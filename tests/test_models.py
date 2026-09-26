"""Tests for admino.models — Pydantic model validation, constraints, and serialization.

Covers every model in models.py:
- API models (ChatMessage, ChatRequest, ChatResponse, ToolCallRecord, ConfirmRequest, SSEEvent)
- Agent/LLM models (ToolCall, LLMMessage, AgentConfig, PendingConfirmation)
- JSON round-trip serialization
- Security: no secret-bearing field names
- Credential redaction (``_strip_credentials``, ``_CONTROL_CHAR_TABLE``) on the models
  that still use it: ChatResponse, ToolCallRecord, PendingConfirmationSummary
- GH-147: the NDJSON audit entry models (ConversationAuditEntry, ToolCallAuditEntry and
  the AuditEntry union) are gone
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
    LLMMessage,
    PendingConfirmation,
    PendingConfirmationSummary,
    SettingsLLM,
    SettingsPatchLLM,
    SSEEvent,
    ToolCall,
    ToolCallRecord,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW: datetime = datetime.now(UTC)
_EXPIRES: datetime = _NOW + timedelta(seconds=30)


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

    def test_permission_accepts_disabled(self) -> None:
        """ToolCallRecord accepts 'disabled' as a valid permission value.

        Needed when a tool call is rejected because the tool is toggled off
        via settings, so the record accurately reflects the reason.
        """
        rec = ToolCallRecord(
            tool="gmail",
            action="read",
            permission="disabled",
            success=False,  # type: ignore[arg-type]
        )
        assert rec.permission == "disabled"


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

    def test_session_id_empty_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ChatResponse(session_id="", response="ok")

    def test_session_id_max_length_exceeded(self) -> None:
        with pytest.raises(ValidationError):
            ChatResponse(session_id="s" * 65, response="ok")

    def test_session_id_rejects_special_chars(self) -> None:
        """session_id with spaces is rejected by pattern constraint."""
        with pytest.raises(ValidationError):
            ChatResponse(session_id="has space", response="ok")

    def test_session_id_rejects_newline(self) -> None:
        """session_id with embedded newline is rejected by pattern constraint."""
        with pytest.raises(ValidationError):
            ChatResponse(session_id="inj\nected", response="ok")

    def test_session_id_accepts_valid(self) -> None:
        """session_id with alphanumeric, hyphens, underscores is accepted."""
        resp = ChatResponse(session_id="abc-123_def", response="ok")
        assert resp.session_id == "abc-123_def"

    def test_session_id_credential_redacted(self) -> None:
        """session_id containing a GitHub token pattern should have it redacted."""
        token = "ghp_" + "A" * 36
        resp = ChatResponse(session_id=token, response="ok")
        assert "ghp_" not in resp.session_id
        assert "[CREDENTIAL_REDACTED]" in resp.session_id


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
            LLMMessage(role="tool", content="r", tool_call_id="x" * 129)


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

    def test_confirmation_id_empty_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PendingConfirmation(
                confirmation_id="",
                session_id="s1",
                tool_call=_make_tool_call(),
                expires_at=_EXPIRES,
            )

    def test_session_id_empty_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PendingConfirmation(
                confirmation_id="c1",
                session_id="",
                tool_call=_make_tool_call(),
                expires_at=_EXPIRES,
            )

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

    def test_confirmation_id_rejects_special_chars(self) -> None:
        """confirmation_id with special characters is rejected by pattern."""
        with pytest.raises(ValidationError):
            PendingConfirmation(
                confirmation_id="c@1",
                session_id="s1",
                tool_call=_make_tool_call(),
                expires_at=_EXPIRES,
            )

    def test_session_id_rejects_special_chars(self) -> None:
        """session_id with special characters is rejected by pattern."""
        with pytest.raises(ValidationError):
            PendingConfirmation(
                confirmation_id="c1",
                session_id="s/1",
                tool_call=_make_tool_call(),
                expires_at=_EXPIRES,
            )


# ===========================================================================
# JSON round-trip serialization
# ===========================================================================


class TestJsonRoundTrip:
    """Every model must survive model_dump_json -> model_validate_json."""

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
    PendingConfirmationSummary,
]


@pytest.mark.parametrize("model_cls", _ALL_MODELS, ids=lambda c: c.__name__)
def test_no_secret_field_names(model_cls: type) -> None:
    """No model should have fields named token, password, secret, key, credential, or api_key."""
    field_names = set(model_cls.model_fields.keys())
    overlap = field_names & _FORBIDDEN_FIELD_NAMES
    assert overlap == set(), f"{model_cls.__name__} has forbidden fields: {overlap}"


# ===========================================================================
# Credential redaction (the helpers outlive the NDJSON audit models, GH-147)
# ===========================================================================

_RLO = chr(0x202E)  # RIGHT-TO-LEFT OVERRIDE
_LRI = chr(0x2066)  # LEFT-TO-RIGHT ISOLATE
_PDI = chr(0x2069)  # POP DIRECTIONAL ISOLATE
_REDACTION_MARKER = "[CREDENTIAL_REDACTED]"


def _chat_response(text: str) -> ChatResponse:
    """A ChatResponse carrying ``text`` as the assistant response."""
    return ChatResponse(session_id="s1", response=text)


def _record_args(args: dict[str, object]) -> dict[str, object]:
    """The args a ToolCallRecord keeps after its sanitizer ran."""
    record = ToolCallRecord(
        tool="gmail", action="read", args=args, permission="allow", success=True
    )
    return record.args


def _summary_args(args: dict[str, object]) -> dict[str, object]:
    """The args a PendingConfirmationSummary keeps after its sanitizer ran."""
    summary = PendingConfirmationSummary(
        confirmation_id="c1", tool="gmail", action="send", args=args, expires_at=_EXPIRES
    )
    return summary.args


class TestCredentialRedaction:
    """_strip_credentials and _CONTROL_CHAR_TABLE still guard the models that use them."""

    def test_google_oauth_token_redacted_in_chat_response(self) -> None:
        fake_token = "ya29." + "a1b2c3d4e5" * 8
        resp = _chat_response(f"token {fake_token}")
        assert "ya29." not in resp.response
        assert _REDACTION_MARKER in resp.response

    def test_jwt_redacted_in_chat_response(self) -> None:
        jwt = (
            "eyJhbGciOiJSUzI1NiJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        resp = _chat_response(f"got {jwt}")
        assert "eyJ" not in resp.response

    def test_bearer_redacted_in_chat_response(self) -> None:
        resp = _chat_response("header: Bearer sk-abc123")
        assert "sk-abc123" not in resp.response

    def test_bearer_redacted_in_tool_call_record_args(self) -> None:
        args = _record_args({"auth": "Bearer secret-token-here"})
        assert "secret-token-here" not in str(args["auth"])

    def test_oauth_token_redacted_in_pending_confirmation_summary_args(self) -> None:
        args = _summary_args({"note": "failed with ya29." + "x1y2z3w4" * 10})
        assert "ya29." not in str(args["note"])

    def test_non_string_arg_values_are_kept(self) -> None:
        """Only string values are scanned; numbers and booleans pass through unchanged."""
        assert _record_args({"count": 5, "flag": True}) == {"count": 5, "flag": True}

    def test_fernet_key_not_false_positive(self) -> None:
        """44-char base64 strings should NOT be redacted (Fernet pattern removed)."""
        safe_hash = "A" * 44
        resp = _chat_response(f"hash: {safe_hash}")
        assert safe_hash in resp.response

    def test_gocspx_client_secret_redacted(self) -> None:
        """Google OAuth client secrets (GOCSPX-...) should be redacted."""
        secret = "GOCSPX-" + "a1b2c3d4e5f6g7h8i9j0k1l2"
        resp = _chat_response(f"secret is {secret}")
        assert "GOCSPX-" not in resp.response

    def test_chat_response_strips_direction_override(self) -> None:
        """The control-character table removes Unicode direction overrides."""
        resp = _chat_response(f"safe{_RLO}evil")
        assert _RLO not in resp.response
        assert "safeevil" in resp.response

    def test_chat_response_strips_bidi_isolate_chars(self) -> None:
        """BiDi Isolate characters (U+2066-U+2069) are stripped."""
        resp = _chat_response(f"safe{_LRI}evil{_PDI}text")
        assert _LRI not in resp.response
        assert _PDI not in resp.response
        assert "safeeviltext" in resp.response

    def test_credential_below_pattern_minimum_is_not_redacted(self) -> None:
        """A credential shorter than its pattern's minimum length is not redacted.

        Accepted behaviour: the regex minimum-length guards prevent partial matches.
        This test documents the boundary explicitly.
        """
        partial_cred = "ya29." + "a" * 19  # below the 20-char minimum after the prefix
        resp = _chat_response("x" * 100 + partial_cred)
        assert partial_cred in resp.response

    def test_model_construct_bypasses_redaction(self) -> None:
        """model_construct() skips validators -- documents the known unsafe path.

        Production code must NEVER use model_construct() on these models.
        """
        fake_token = "ya29." + "a1b2c3d4e5" * 8
        record = ToolCallRecord.model_construct(
            tool="gmail",
            action="read",
            args={"auth": f"token {fake_token}"},
            permission="allow",
            success=True,
        )
        assert "ya29." in str(record.args["auth"])


# ===========================================================================
# SSEEvent newline sanitization
# ===========================================================================


class TestSSEEventNewlineSanitization:
    """SSEEvent.data strips bare newlines to prevent frame injection."""

    def test_newline_escaped(self) -> None:
        ev = SSEEvent(event="msg", data='{"text":"line1\nline2"}')
        assert "\n" not in ev.data
        assert "\\n" in ev.data

    def test_crlf_escaped(self) -> None:
        ev = SSEEvent(event="msg", data="a\r\nb")
        assert "\r" not in ev.data
        assert "\n" not in ev.data

    def test_cr_escaped(self) -> None:
        ev = SSEEvent(event="msg", data="a\rb")
        assert "\r" not in ev.data

    def test_no_newlines_unchanged(self) -> None:
        ev = SSEEvent(event="msg", data='{"ok":true}')
        assert ev.data == '{"ok":true}'

    def test_literal_backslash_n_preserved(self) -> None:
        """Pre-existing literal backslash-n is preserved (not double-escaped)."""
        ev = SSEEvent(event="msg", data=r"already escaped: \n done")
        # The literal \ and n are two separate characters, not a newline
        assert ev.data == r"already escaped: \n done"

    def test_data_strips_bidi_override(self) -> None:
        """BiDi RIGHT-TO-LEFT OVERRIDE (U+202E) is stripped from SSE data."""
        ev = SSEEvent(event="msg", data="safe\u202eevil")
        assert "\u202e" not in ev.data

    def test_data_strips_bidi_isolates(self) -> None:
        """BiDi ISOLATE characters (U+2066, U+2069) are stripped from SSE data."""
        ev = SSEEvent(event="msg", data="test\u2066content\u2069")
        assert "\u2066" not in ev.data
        assert "\u2069" not in ev.data

    def test_data_strips_nel(self) -> None:
        """NEXT LINE (NEL, U+0085) is stripped from SSE data."""
        ev = SSEEvent(event="msg", data="before\x85after")
        assert "\x85" not in ev.data


# ===========================================================================
# Comprehensive credential pattern coverage
# ===========================================================================

_CREDENTIAL_SAMPLES: list[tuple[str, str]] = [
    ("google_refresh", "1//" + "a1b2c3d4e5" * 4),
    ("google_access", "ya29." + "x1y2z3w4p5" * 4),
    (
        "jwt",
        "eyJhbGciOiJSUzI1NiJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ),
    ("bearer", "Bearer sk-proj-abc123def456ghi789"),
    ("gocspx", "GOCSPX-" + "a1b2c3d4e5f6g7h8i9j0k1l2"),
    ("sk_api_key", "sk-" + "a1b2c3d4e5f6g7h8i9j0"),
    ("github_pat", "ghp_" + "A" * 36),
    ("github_server", "ghs_" + "B" * 36),
    ("aws_access_key", "AKIA" + "A" * 16),
    ("slack_bot", "xoxb-" + "a1b2c3d4e5"),
    ("slack_user", "xoxp-" + "a1b2c3d4e5"),
    ("stripe_rk_live", "rk_live_" + "a" * 24),
    ("stripe_rk_test", "rk_test_" + "b" * 24),
]


class TestCredentialRedactionAllPatterns:
    """Every pattern in _CREDENTIAL_PATTERNS is redacted wherever _strip_credentials runs."""

    @pytest.mark.parametrize(("label", "sample"), _CREDENTIAL_SAMPLES)
    def test_pattern_redacted_in_chat_response(self, label: str, sample: str) -> None:
        """Each credential pattern is redacted from ChatResponse.response."""
        resp = _chat_response(f"leaked: {sample}")
        assert sample not in resp.response
        assert _REDACTION_MARKER in resp.response

    @pytest.mark.parametrize(("label", "sample"), _CREDENTIAL_SAMPLES)
    def test_pattern_redacted_in_tool_call_record_args(self, label: str, sample: str) -> None:
        """Each credential pattern is redacted from ToolCallRecord.args string values."""
        value = str(_record_args({"arg": f"arg: {sample}"})["arg"])
        assert sample not in value
        assert _REDACTION_MARKER in value

    @pytest.mark.parametrize(("label", "sample"), _CREDENTIAL_SAMPLES)
    def test_pattern_redacted_in_pending_confirmation_summary_args(
        self, label: str, sample: str
    ) -> None:
        """Each credential pattern is redacted from PendingConfirmationSummary.args."""
        value = str(_summary_args({"arg": f"failed: {sample}"})["arg"])
        assert sample not in value
        assert _REDACTION_MARKER in value


# ===========================================================================
# model_construct enforcement (FINDING 17)
# ===========================================================================


class TestModelConstructEnforcement:
    """Ensure model_construct (which skips redaction validators) is never called in
    production code."""

    def test_no_model_construct_in_production_code(self) -> None:
        """Scan production source files to ensure model_construct is not used on audit models."""
        import ast
        from pathlib import Path

        src_dir = Path(__file__).parent.parent / "src" / "admino"
        for py_file in src_dir.glob("*.py"):
            if py_file.name == "models.py":
                continue
            tree = ast.parse(py_file.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == "model_construct":
                    pytest.fail(f"model_construct() called in {py_file.name}:{node.lineno}")


# ===========================================================================
# GH-147: the NDJSON audit entry models are removed
# ===========================================================================


class TestNdjsonAuditModelsRemoved:
    """ConversationAuditEntry held full message text; ToolCallAuditEntry held argument
    keys and error text. Both went with the NDJSON audit log (GH-147)."""

    @pytest.mark.parametrize("name", ["ConversationAuditEntry", "ToolCallAuditEntry", "AuditEntry"])
    def test_models_ndjson_audit_model_removed(self, name: str) -> None:
        import admino.models as models_module

        assert not hasattr(models_module, name)


# ===========================================================================
# LLMMessage.tool_call_id special characters (FINDING 19)
# ===========================================================================


class TestLLMMessageToolCallId:
    """Tests for tool_call_id pattern validation on LLMMessage."""

    def test_tool_call_id_rejects_newline(self) -> None:
        """tool_call_id with embedded newline is rejected."""
        with pytest.raises(ValidationError):
            LLMMessage(role="tool", content="r", tool_call_id="tc\n1")

    def test_tool_call_id_rejects_spaces(self) -> None:
        """tool_call_id with spaces is rejected."""
        with pytest.raises(ValidationError):
            LLMMessage(role="tool", content="r", tool_call_id="tc 1")

    def test_tool_call_id_accepts_valid(self) -> None:
        """tool_call_id with alphanumeric, hyphens, underscores is accepted."""
        msg = LLMMessage(role="tool", content="r", tool_call_id="tc-123_abc")
        assert msg.tool_call_id == "tc-123_abc"


# ===========================================================================
# PendingConfirmation expires_at validation (FINDING 20)
# ===========================================================================


def _make_pending_confirmation(**overrides: object) -> PendingConfirmation:
    """Build a valid PendingConfirmation with optional overrides."""
    defaults: dict[str, object] = {
        "confirmation_id": "c1",
        "session_id": "s1",
        "tool_call": ToolCall(tool="gmail", action="read", args={}),
        "expires_at": datetime.now(UTC) + timedelta(minutes=5),
    }
    defaults.update(overrides)
    return PendingConfirmation(**defaults)  # type: ignore[arg-type]


class TestPendingConfirmationExpiresAt:
    """Tests for expires_at temporal validation on PendingConfirmation."""

    def test_expires_at_before_created_rejected(self) -> None:
        """expires_at before created_at must raise ValidationError."""
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            PendingConfirmation(
                confirmation_id="c1",
                session_id="s1",
                tool_call=ToolCall(tool="gmail", action="read", args={}),
                created_at=now,
                expires_at=now - timedelta(seconds=10),
            )

    def test_expires_at_equal_created_rejected(self) -> None:
        """expires_at equal to created_at must raise ValidationError."""
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            PendingConfirmation(
                confirmation_id="c1",
                session_id="s1",
                tool_call=ToolCall(tool="gmail", action="read", args={}),
                created_at=now,
                expires_at=now,
            )

    def test_expires_at_naive_datetime_rejected(self) -> None:
        """expires_at with timezone-naive datetime must raise ValidationError."""
        naive_dt = datetime(2026, 1, 1, 12, 0, 0)  # no tzinfo
        with pytest.raises(ValidationError):
            _make_pending_confirmation(expires_at=naive_dt)


# ---------------------------------------------------------------------------
# SettingsLLM — vllm_available_models is untrusted (local /v1/models probe)
# ---------------------------------------------------------------------------


class TestSettingsLLMAvailableModels:
    """vllm_available_models comes from the local vLLM server's /v1/models
    response — outside admino's trust boundary — so SettingsLLM must filter it
    to the model-name allowlist and bound its length (security finding M-2)."""

    @staticmethod
    def _make(available: list[str]) -> SettingsLLM:
        return SettingsLLM(
            provider="vllm",
            anthropic_model="",
            openai_model="",
            vllm_model="mlx-community/gemma-4-12B-it-4bit",
            vllm_available_models=available,
        )

    def test_valid_model_ids_kept(self) -> None:
        """Well-formed HF repo ids pass through unchanged."""
        ids = ["mlx-community/gemma-4-12B-it-4bit", "org/model.name_v2"]
        assert self._make(ids).vllm_available_models == ids

    def test_ids_with_invalid_chars_dropped(self) -> None:
        """Ids from a rogue server with spaces, shell metachars, bidi overrides,
        or over-length are dropped; only allowlisted ids survive."""
        result = self._make(
            ["ok/model", "bad id; rm -rf /", "evil‮model", "x" * 201]
        ).vllm_available_models
        assert result == ["ok/model"]

    def test_list_length_bounded(self) -> None:
        """A flood of ids is capped so a malicious server can't bloat the response."""
        result = self._make([f"org/model{i}" for i in range(100)]).vllm_available_models
        assert len(result) == 64


# ---------------------------------------------------------------------------
# GH-142: Infomaniak in SettingsLLM / SettingsPatchLLM
# ---------------------------------------------------------------------------

_INFOMANIAK_MODEL = "Qwen/Qwen3.5-397B-A17B-FP8"


def _infomaniak_settings(**overrides: object) -> SettingsLLM:
    """A SettingsLLM selecting infomaniak, with optional overrides."""
    values: dict[str, object] = {
        "provider": "infomaniak",
        "anthropic_model": "",
        "openai_model": "",
        "infomaniak_model": _INFOMANIAK_MODEL,
    }
    values.update(overrides)
    return SettingsLLM(**values)  # type: ignore[arg-type]


class TestSettingsLLMInfomaniak:
    """SettingsLLM exposes the Infomaniak provider state (never the token)."""

    def test_settings_llm_accepts_infomaniak_provider(self) -> None:
        """provider='infomaniak' validates and the model round-trips."""
        settings = _infomaniak_settings()
        assert settings.provider == "infomaniak"
        assert settings.infomaniak_model == _INFOMANIAK_MODEL

    def test_settings_llm_infomaniak_defaults(self) -> None:
        """infomaniak_model defaults to "", the list to [], the token flag to False."""
        settings = SettingsLLM(provider="anthropic", anthropic_model="", openai_model="")
        assert settings.infomaniak_model == ""
        assert settings.infomaniak_available_models == []
        assert settings.infomaniak_token_configured is False

    def test_settings_llm_infomaniak_token_flag_is_boolean(self) -> None:
        """infomaniak_token_configured is a plain flag."""
        assert _infomaniak_settings(infomaniak_token_configured=True).infomaniak_token_configured

    @pytest.mark.parametrize("bad_model", ["evil; rm -rf /", "model$(id)", "a b", "-x"])
    def test_settings_llm_infomaniak_model_invalid_chars_rejected(self, bad_model: str) -> None:
        """infomaniak_model uses the shared model-name validator."""
        with pytest.raises(ValidationError, match="invalid characters"):
            _infomaniak_settings(infomaniak_model=bad_model)

    def test_settings_llm_infomaniak_available_models_valid_kept(self) -> None:
        """Well-formed model ids pass through unchanged, in order."""
        ids = [_INFOMANIAK_MODEL, "mistralai/Mistral-Small-3.2"]
        assert (
            _infomaniak_settings(infomaniak_available_models=ids).infomaniak_available_models == ids
        )

    def test_settings_llm_infomaniak_available_models_filtered(self) -> None:
        """Ids with spaces/shell metachars/bidi overrides or over-length are dropped."""
        rlo = chr(0x202E)
        result = _infomaniak_settings(
            infomaniak_available_models=[
                "ok/model",
                "bad id; rm -rf /",
                f"evil{rlo}model",
                "x" * 201,
            ]
        ).infomaniak_available_models
        assert result == ["ok/model"]

    def test_settings_llm_infomaniak_available_models_capped(self) -> None:
        """A flood of ids is capped at 64."""
        result = _infomaniak_settings(
            infomaniak_available_models=[f"org/model{i}" for i in range(100)]
        ).infomaniak_available_models
        assert len(result) == 64


class TestSettingsPatchLLMInfomaniak:
    """SettingsPatchLLM accepts the Infomaniak provider and a validated model."""

    def test_settings_patch_llm_accepts_infomaniak_provider(self) -> None:
        """provider='infomaniak' is a valid PATCH value."""
        assert SettingsPatchLLM(provider="infomaniak").provider == "infomaniak"  # type: ignore[arg-type]

    def test_settings_patch_llm_accepts_infomaniak_model(self) -> None:
        """A well-formed infomaniak_model is accepted."""
        patch_model = SettingsPatchLLM(infomaniak_model="mistralai/Mistral-Small-3.2")  # type: ignore[call-arg]
        assert patch_model.infomaniak_model == "mistralai/Mistral-Small-3.2"

    def test_settings_patch_llm_infomaniak_model_defaults_none(self) -> None:
        """infomaniak_model is optional (None = unchanged)."""
        assert SettingsPatchLLM().infomaniak_model is None

    @pytest.mark.parametrize("bad_model", ["evil; rm -rf /", "model$(id)", "a b", "../x"])
    def test_settings_patch_llm_infomaniak_model_invalid_chars_rejected(
        self, bad_model: str
    ) -> None:
        """infomaniak_model with shell metacharacters is rejected."""
        with pytest.raises(ValidationError, match="invalid characters"):
            SettingsPatchLLM(infomaniak_model=bad_model)  # type: ignore[call-arg]

    def test_settings_patch_llm_infomaniak_model_max_length(self) -> None:
        """infomaniak_model is bounded to 200 characters."""
        with pytest.raises(ValidationError, match="at most 200 characters"):
            SettingsPatchLLM(infomaniak_model="a" * 201)  # type: ignore[call-arg]


# ===========================================================================
# GH-143: the local files tool and the Drive/OneDrive downloads are removed
# ===========================================================================

_REMAINING_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "gmail",
        "google_calendar",
        "google_drive",
        "outlook",
        "outlook_calendar",
        "onedrive",
        "memory",
    }
)


class TestFilesToolModelsRemoved:
    """The files.* and *.download argument models are gone; toggles drop 'files'."""

    @pytest.mark.parametrize(
        "model_name",
        [
            "FileReadArgs",
            "FileListArgs",
            "FileSearchArgs",
            "FileWriteArgs",
            "FileMoveArgs",
            "GoogleDriveDownloadArgs",
            "OneDriveDownloadArgs",
        ],
    )
    def test_removed_args_model_no_longer_exists(self, model_name: str) -> None:
        """The removed tool-argument models are not exported by admino.models."""
        import admino.models as models_module

        assert not hasattr(models_module, model_name)

    @pytest.mark.parametrize(
        "model_name",
        [
            "GoogleDriveReadArgs",
            "GoogleDriveListArgs",
            "GoogleDriveSearchArgs",
            "OneDriveReadArgs",
            "OneDriveListArgs",
            "OneDriveSearchArgs",
        ],
    )
    def test_drive_and_onedrive_read_models_remain(self, model_name: str) -> None:
        """Drive/OneDrive read, list and search argument models are kept."""
        import admino.models as models_module

        assert hasattr(models_module, model_name)

    def test_tools_settings_fields_exclude_files(self) -> None:
        """ToolsSettings toggles cover exactly the remaining tools."""
        from admino.models import ToolsSettings

        assert set(ToolsSettings.model_fields) == _REMAINING_TOOL_NAMES

    def test_tools_settings_default_dump_has_no_files_key(self) -> None:
        """The all-enabled default map has no 'files' entry."""
        from admino.models import ToolsSettings

        assert "files" not in ToolsSettings().model_dump()

    def test_tools_settings_ignores_legacy_files_key(self) -> None:
        """A legacy DB 'tools' value with files still validates, and files is dropped."""
        from admino.models import ToolsSettings

        loaded = ToolsSettings.model_validate({"gmail": False, "files": False})
        dumped = loaded.model_dump()
        assert "files" not in dumped
        assert dumped["gmail"] is False

    def test_settings_patch_tools_fields_exclude_files(self) -> None:
        """SettingsPatchTools accepts toggles for exactly the remaining tools."""
        from admino.models import SettingsPatchTools

        assert set(SettingsPatchTools.model_fields) == _REMAINING_TOOL_NAMES

    def test_settings_patch_tools_ignores_files_key(self) -> None:
        """A PATCH body toggling files validates but carries no update."""
        from admino.models import SettingsPatchTools

        patch_body = SettingsPatchTools.model_validate({"files": False})
        assert patch_body.model_dump(exclude_none=True) == {}
