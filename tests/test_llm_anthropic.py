"""Tests for the Anthropic Claude LLM client module.

Covers message conversion, tool format conversion, tool call parsing,
client construction, chat method, error handling, context manager,
and adversarial/security edge cases.

GH-142: a missing ANTHROPIC_API_KEY or model no longer fails construction;
chat() answers with a friendly, user-facing ``LLMError`` (label "Claude")
instead, and SDK errors map to the fixed user-facing catalogue
(401/403/404/429/5xx incl. 529 overloaded/timeout/connection) while other 4xx
stay internal (``user_facing=False``).

All API calls are mocked — no real Anthropic API is contacted.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import anthropic
import httpx
import pytest

from admino.llm import LLMError, LLMResponse, check_args_depth
from admino.llm_anthropic import (
    AnthropicClient,
    _anthropic_name_to_dot,
    _convert_messages_to_anthropic,
    _convert_tools_to_anthropic,
    _dot_to_anthropic_name,
    _parse_anthropic_tool_calls,
)
from admino.models import LLMMessage

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_llm_config(anthropic_model: str | None = "claude-sonnet-4-6") -> Any:
    """Create a fake LLMConfig for testing."""
    return SimpleNamespace(
        anthropic_model=anthropic_model,
        timeout_s=30,
        max_response_tokens=4096,
    )


_ANTHROPIC_REQUEST = httpx.Request("POST", "https://api.anthropic.com/v1/messages")


def _status_error(cls: type[Any], status: int, marker: str) -> Any:
    """Build an anthropic SDK status error whose body carries a secret marker."""
    body = {"type": "error", "error": {"type": "api_error", "message": f"detail {marker}"}}
    response = httpx.Response(status, request=_ANTHROPIC_REQUEST, json=body)
    return cls(f"Error code: {status} - {body}", response=response, body=body)


def _make_messages(content: str = "Hi") -> list[LLMMessage]:
    """Create a minimal message list for chat calls."""
    return [LLMMessage(role="user", content=content)]


def _make_text_block(text: str = "Hello!") -> SimpleNamespace:
    """Create a mock Anthropic text content block."""
    return SimpleNamespace(type="text", text=text)


def _make_tool_use_block(
    name: str = "memory__store",
    input_data: dict[str, Any] | None = None,
    block_id: str = "toolu_01abc",
) -> SimpleNamespace:
    """Create a mock Anthropic tool_use content block."""
    return SimpleNamespace(
        type="tool_use",
        name=name,
        input=input_data if input_data is not None else {"key": "test"},
        id=block_id,
    )


def _make_response(
    content_blocks: list[Any] | None = None,
    model: str = "claude-sonnet-4-6",
    stop_reason: str = "end_turn",
) -> SimpleNamespace:
    """Create a mock Anthropic Messages API response."""
    if content_blocks is None:
        content_blocks = [_make_text_block()]
    return SimpleNamespace(
        content=content_blocks,
        model=model,
        stop_reason=stop_reason,
    )


# ---------------------------------------------------------------------------
# Message conversion
# ---------------------------------------------------------------------------


class TestConvertMessagesToAnthropic:
    """Tests for _convert_messages_to_anthropic."""

    def test_user_message(self) -> None:
        """User message maps to Anthropic user role."""
        msgs = [LLMMessage(role="user", content="Hello")]
        system, api = _convert_messages_to_anthropic(msgs)
        assert system == ""
        assert len(api) == 1
        assert api[0] == {"role": "user", "content": "Hello"}

    def test_assistant_message(self) -> None:
        """Assistant message maps to Anthropic assistant role."""
        msgs = [LLMMessage(role="assistant", content="Hi")]
        _, api = _convert_messages_to_anthropic(msgs)
        assert api[0] == {"role": "assistant", "content": "Hi"}

    def test_system_message_extracted(self) -> None:
        """System messages are extracted to separate system prompt string."""
        msgs = [
            LLMMessage(role="system", content="You are helpful."),
            LLMMessage(role="user", content="Hi"),
        ]
        system, api = _convert_messages_to_anthropic(msgs)
        assert system == "You are helpful."
        assert len(api) == 1
        assert api[0]["role"] == "user"

    def test_multiple_system_messages_joined(self) -> None:
        """Multiple system messages are joined with newlines."""
        msgs = [
            LLMMessage(role="system", content="Rule 1"),
            LLMMessage(role="system", content="Rule 2"),
            LLMMessage(role="user", content="Hi"),
        ]
        system, _ = _convert_messages_to_anthropic(msgs)
        assert system == "Rule 1\nRule 2"

    def test_tool_result_message(self) -> None:
        """Tool messages become user-role with tool_result content block."""
        msgs = [LLMMessage(role="tool", content="result data", tool_call_id="call-123")]
        _, api = _convert_messages_to_anthropic(msgs)
        assert len(api) == 1
        assert api[0]["role"] == "user"
        content = api[0]["content"]
        assert isinstance(content, list)
        assert content[0]["type"] == "tool_result"
        assert content[0]["tool_use_id"] == "call-123"
        assert content[0]["content"] == "result data"

    def test_tool_result_missing_tool_call_id_skipped(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Tool message without tool_call_id is skipped with a warning."""
        msgs = [LLMMessage(role="tool", content="data")]
        with caplog.at_level(logging.WARNING):
            _, api = _convert_messages_to_anthropic(msgs)
        assert len(api) == 0
        assert "missing tool_call_id" in caplog.text

    def test_consecutive_user_messages_merged_str_str(self) -> None:
        """Two consecutive user messages (both str) are merged with newline."""
        msgs = [
            LLMMessage(role="user", content="First"),
            LLMMessage(role="user", content="Second"),
        ]
        _, api = _convert_messages_to_anthropic(msgs)
        assert len(api) == 1
        assert api[0]["content"] == "First\nSecond"

    def test_consecutive_user_messages_merged_list_list(self) -> None:
        """Consecutive tool results (both lists) are merged."""
        msgs = [
            LLMMessage(role="tool", content="r1", tool_call_id="c1"),
            LLMMessage(role="tool", content="r2", tool_call_id="c2"),
        ]
        _, api = _convert_messages_to_anthropic(msgs)
        assert len(api) == 1
        content = api[0]["content"]
        assert isinstance(content, list)
        assert len(content) == 2

    def test_consecutive_merge_str_then_list(self) -> None:
        """User text followed by tool result merges str + list."""
        msgs = [
            LLMMessage(role="user", content="Hello"),
            LLMMessage(role="tool", content="result", tool_call_id="c1"),
        ]
        _, api = _convert_messages_to_anthropic(msgs)
        assert len(api) == 1
        content = api[0]["content"]
        assert isinstance(content, list)
        assert content[0]["type"] == "text"
        assert content[0]["text"] == "Hello"
        assert content[1]["type"] == "tool_result"

    def test_consecutive_merge_list_then_str(self) -> None:
        """Tool result followed by user text merges list + str."""
        msgs = [
            LLMMessage(role="tool", content="result", tool_call_id="c1"),
            LLMMessage(role="user", content="Thanks"),
        ]
        _, api = _convert_messages_to_anthropic(msgs)
        assert len(api) == 1
        content = api[0]["content"]
        assert isinstance(content, list)
        assert content[-1]["type"] == "text"
        assert content[-1]["text"] == "Thanks"

    def test_assistant_with_tool_use_blocks_produces_structured_content(self) -> None:
        """Assistant message with tool_use_blocks includes tool_use in Anthropic format."""
        msgs = [
            LLMMessage(
                role="assistant",
                content="I'll list your notes.",
                tool_use_blocks=[
                    {
                        "type": "tool_use",
                        "id": "toolu_01abc",
                        "name": "memory.list",  # dot notation; should be encoded to __
                        "input": {"prefix": "work"},
                    }
                ],
            ),
            LLMMessage(role="tool", content="work-note-1", tool_call_id="toolu_01abc"),
        ]
        _, api = _convert_messages_to_anthropic(msgs)
        # Assistant turn should have text + tool_use blocks
        assert api[0]["role"] == "assistant"
        asst_content = api[0]["content"]
        assert isinstance(asst_content, list)
        assert asst_content[0] == {"type": "text", "text": "I'll list your notes."}
        assert asst_content[1]["type"] == "tool_use"
        assert asst_content[1]["id"] == "toolu_01abc"
        assert asst_content[1]["name"] == "memory__list"  # dot encoded to __
        assert asst_content[1]["input"] == {"prefix": "work"}
        # Tool result turn follows
        assert api[1]["role"] == "user"
        assert api[1]["content"][0]["type"] == "tool_result"
        assert api[1]["content"][0]["tool_use_id"] == "toolu_01abc"

    def test_assistant_tool_use_block_missing_id_skipped(self) -> None:
        """tool_use blocks without an id are skipped (Anthropic requires id)."""
        msgs = [
            LLMMessage(
                role="assistant",
                content="Calling tool",
                tool_use_blocks=[{"type": "tool_use", "name": "memory.list", "input": {}}],
            )
        ]
        _, api = _convert_messages_to_anthropic(msgs)
        asst_content = api[0]["content"]
        # Only text block; the tool_use block without id is skipped
        assert isinstance(asst_content, list)
        assert len(asst_content) == 1
        assert asst_content[0]["type"] == "text"

    def test_empty_messages(self) -> None:
        """Empty message list returns empty system and empty list."""
        system, api = _convert_messages_to_anthropic([])
        assert system == ""
        assert api == []

    def test_alternating_roles_not_merged(self) -> None:
        """Alternating user/assistant messages are not merged."""
        msgs = [
            LLMMessage(role="user", content="Q1"),
            LLMMessage(role="assistant", content="A1"),
            LLMMessage(role="user", content="Q2"),
        ]
        _, api = _convert_messages_to_anthropic(msgs)
        assert len(api) == 3


# ---------------------------------------------------------------------------
# Tool format conversion
# ---------------------------------------------------------------------------


class TestConvertToolsToAnthropic:
    """Tests for _convert_tools_to_anthropic."""

    def test_normal_tool(self) -> None:
        """Standard tool definition is converted correctly."""
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "memory.store",
                    "description": "Store a value",
                    "parameters": {"type": "object", "properties": {"key": {"type": "string"}}},
                },
            }
        ]
        result = _convert_tools_to_anthropic(tools)
        assert len(result) == 1
        # Dots are encoded as double-underscores for Anthropic's name constraint
        assert result[0]["name"] == "memory__store"
        assert result[0]["description"] == "Store a value"
        assert "input_schema" in result[0]

    def test_missing_function_key(self) -> None:
        """Tool without 'function' key gets empty dict default and is included."""
        tools = [{"type": "function"}]
        result = _convert_tools_to_anthropic(tools)
        assert len(result) == 1
        assert result[0]["name"] == ""

    def test_function_not_dict(self) -> None:
        """Non-dict function value is skipped."""
        tools = [{"type": "function", "function": "not-a-dict"}]
        result = _convert_tools_to_anthropic(tools)
        assert result == []

    def test_empty_tools_list(self) -> None:
        """Empty tools list returns empty list."""
        assert _convert_tools_to_anthropic([]) == []

    def test_default_parameters(self) -> None:
        """Missing parameters defaults to empty object schema."""
        tools = [{"type": "function", "function": {"name": "test.run"}}]
        result = _convert_tools_to_anthropic(tools)
        assert result[0]["input_schema"] == {"type": "object", "properties": {}}


# ---------------------------------------------------------------------------
# Name encoding helpers
# ---------------------------------------------------------------------------


class TestNameEncoding:
    """Tests for _dot_to_anthropic_name and _anthropic_name_to_dot."""

    def test_dot_to_anthropic_name(self) -> None:
        """Dot notation is encoded as double-underscore."""
        assert _dot_to_anthropic_name("memory.store") == "memory__store"

    def test_dot_to_anthropic_name_no_dot(self) -> None:
        """Name without dot is returned unchanged."""
        assert _dot_to_anthropic_name("nodot") == "nodot"

    def test_anthropic_name_to_dot(self) -> None:
        """Double-underscore is decoded back to dot."""
        assert _anthropic_name_to_dot("memory__store") == "memory.store"

    def test_anthropic_name_to_dot_no_double_underscore(self) -> None:
        """Name without double-underscore is returned unchanged."""
        assert _anthropic_name_to_dot("nodot") == "nodot"

    def test_roundtrip(self) -> None:
        """Encoding then decoding is a no-op."""
        original = "memory.recall"
        assert _anthropic_name_to_dot(_dot_to_anthropic_name(original)) == original

    def test_only_first_double_underscore_replaced(self) -> None:
        """Only the first __ is converted to dot (maxsplit=1 equivalent)."""
        # 'tool__action__extra' → 'tool.action__extra' (first __ only)
        assert _anthropic_name_to_dot("tool__action__extra") == "tool.action__extra"


# ---------------------------------------------------------------------------
# Tool call parsing
# ---------------------------------------------------------------------------


class TestParseAnthropicToolCalls:
    """Tests for _parse_anthropic_tool_calls."""

    def test_valid_tool_call(self) -> None:
        """Valid tool_use block (Anthropic double-underscore encoding) is parsed correctly."""
        blocks = [_make_tool_use_block("memory__store", {"key": "k", "value": "v"}, "toolu_01")]
        result = _parse_anthropic_tool_calls(blocks)
        assert len(result) == 1
        assert result[0].tool == "memory"
        assert result[0].action == "store"
        assert result[0].args == {"key": "k", "value": "v"}
        assert result[0].tool_call_id == "toolu_01"

    def test_text_block_skipped(self) -> None:
        """Text blocks are skipped, only tool_use blocks are parsed."""
        blocks = [_make_text_block("Hello"), _make_tool_use_block()]
        result = _parse_anthropic_tool_calls(blocks)
        assert len(result) == 1

    def test_missing_name(self, caplog: pytest.LogCaptureFixture) -> None:
        """Block with empty name is skipped with warning."""
        block = SimpleNamespace(type="tool_use", name="", input={}, id="x")
        with caplog.at_level(logging.WARNING):
            result = _parse_anthropic_tool_calls([block])
        assert result == []
        assert any("missing name" in r.message for r in caplog.records)

    def test_name_not_string(self, caplog: pytest.LogCaptureFixture) -> None:
        """Block with non-string name is skipped."""
        block = SimpleNamespace(type="tool_use", name=123, input={}, id="x")
        with caplog.at_level(logging.WARNING):
            result = _parse_anthropic_tool_calls([block])
        assert result == []

    def test_no_dot_notation(self, caplog: pytest.LogCaptureFixture) -> None:
        """Name without dot is rejected."""
        blocks = [_make_tool_use_block("nodot", {})]
        with caplog.at_level(logging.WARNING):
            result = _parse_anthropic_tool_calls(blocks)
        assert result == []
        assert any("dot notation" in r.message for r in caplog.records)

    def test_trailing_dot_rejected(self, caplog: pytest.LogCaptureFixture) -> None:
        """Name 'tool.' with empty action is rejected."""
        blocks = [_make_tool_use_block("memory.", {})]
        with caplog.at_level(logging.WARNING):
            result = _parse_anthropic_tool_calls(blocks)
        assert result == []

    def test_leading_dot_rejected(self, caplog: pytest.LogCaptureFixture) -> None:
        """Name '.action' with empty tool is rejected."""
        blocks = [_make_tool_use_block(".store", {})]
        with caplog.at_level(logging.WARNING):
            result = _parse_anthropic_tool_calls(blocks)
        assert result == []

    def test_input_not_dict(self, caplog: pytest.LogCaptureFixture) -> None:
        """Non-dict input is skipped."""
        block = SimpleNamespace(type="tool_use", name="memory.store", input="bad", id="x")
        with caplog.at_level(logging.WARNING):
            result = _parse_anthropic_tool_calls([block])
        assert result == []
        assert any("not a dict" in r.message for r in caplog.records)

    def test_deep_nesting_rejected(self, caplog: pytest.LogCaptureFixture) -> None:
        """Arguments nested beyond depth limit are rejected."""
        deep: dict[str, Any] = {"a": "v"}
        for _ in range(4):
            deep = {"a": deep}
        blocks = [_make_tool_use_block("memory.store", deep)]
        with caplog.at_level(logging.WARNING):
            result = _parse_anthropic_tool_calls(blocks)
        assert result == []
        assert any("nesting depth" in r.message for r in caplog.records)

    def test_too_many_keys_rejected(self, caplog: pytest.LogCaptureFixture) -> None:
        """Arguments with >32 keys are rejected."""
        big = {f"k{i}": "v" for i in range(33)}
        blocks = [_make_tool_use_block("memory.store", big)]
        with caplog.at_level(logging.WARNING):
            result = _parse_anthropic_tool_calls(blocks)
        assert result == []
        assert any("size limits" in r.message for r in caplog.records)

    def test_value_too_long_rejected(self, caplog: pytest.LogCaptureFixture) -> None:
        """String value exceeding 2048 chars is rejected."""
        blocks = [_make_tool_use_block("memory.store", {"big": "x" * 2049})]
        with caplog.at_level(logging.WARNING):
            result = _parse_anthropic_tool_calls(blocks)
        assert result == []

    def test_total_size_exceeded(self, caplog: pytest.LogCaptureFixture) -> None:
        """Total JSON size >16384 bytes is rejected."""
        # Many keys with values just under 2048 chars but total > 16384
        args = {f"k{i}": "x" * 1000 for i in range(20)}
        blocks = [_make_tool_use_block("memory.store", args)]
        with caplog.at_level(logging.WARNING):
            result = _parse_anthropic_tool_calls(blocks)
        assert result == []

    def test_control_chars_in_name_stripped(self) -> None:
        """Control characters in tool name are stripped before parsing."""
        blocks = [_make_tool_use_block("memory\x00.store", {"key": "v"})]
        result = _parse_anthropic_tool_calls(blocks)
        assert len(result) == 1
        assert result[0].tool == "memory"
        assert result[0].action == "store"

    def test_control_chars_in_id_stripped(self) -> None:
        """Control characters in tool_use id are stripped."""
        blocks = [_make_tool_use_block("memory.store", {"key": "v"}, "toolu\x00_01")]
        result = _parse_anthropic_tool_calls(blocks)
        assert len(result) == 1
        assert "\x00" not in (result[0].tool_call_id or "")

    def test_name_truncated_to_64(self) -> None:
        """Name longer than 64 chars is truncated."""
        long_name = "a" * 30 + "." + "b" * 60  # 91 chars
        blocks = [_make_tool_use_block(long_name, {})]
        result = _parse_anthropic_tool_calls(blocks)
        # After truncation to 64, the name may or may not have a dot
        # If it doesn't have a dot, it will be rejected
        # 30 + 1 + 32 = 63 chars... the 64th char is 'b'
        # So truncated = 'a'*30 + '.' + 'b'*33 = 64 chars — still has a dot
        assert len(result) == 1

    def test_id_truncated_to_128(self) -> None:
        """Tool_use id longer than 128 chars is truncated."""
        long_id = "x" * 200
        blocks = [_make_tool_use_block("memory.store", {"key": "v"}, long_id)]
        result = _parse_anthropic_tool_calls(blocks)
        assert len(result) == 1
        assert len(result[0].tool_call_id or "") <= 128

    def test_non_string_id_ignored(self) -> None:
        """Non-string id results in None tool_call_id."""
        block = SimpleNamespace(type="tool_use", name="memory.store", input={}, id=12345)
        result = _parse_anthropic_tool_calls([block])
        assert len(result) == 1
        assert result[0].tool_call_id is None

    def test_missing_id_attribute(self) -> None:
        """Block without id attribute results in None tool_call_id."""
        block = SimpleNamespace(type="tool_use", name="memory.store", input={})
        result = _parse_anthropic_tool_calls([block])
        assert len(result) == 1
        assert result[0].tool_call_id is None

    def test_block_without_type_attribute_skipped(self) -> None:
        """Block without type attribute is skipped."""
        block = SimpleNamespace(name="memory.store", input={})
        result = _parse_anthropic_tool_calls([block])
        assert result == []

    def test_validation_error_skipped(self, caplog: pytest.LogCaptureFixture) -> None:
        """ToolCall that fails Pydantic validation is skipped."""
        # Uppercase tool name fails ^[a-z][a-z0-9_]*$ pattern
        blocks = [_make_tool_use_block("MEMORY.store", {})]
        with caplog.at_level(logging.WARNING):
            result = _parse_anthropic_tool_calls(blocks)
        assert result == []

    def test_unicode_bidi_in_name_stripped(self) -> None:
        """Unicode direction-override chars in name are stripped."""
        blocks = [_make_tool_use_block("memory\u202e__store", {"key": "v"})]
        result = _parse_anthropic_tool_calls(blocks)
        assert len(result) == 1
        assert "\u202e" not in result[0].tool

    def test_multiple_tool_use_blocks(self) -> None:
        """Multiple valid tool_use blocks are all parsed."""
        blocks = [
            _make_tool_use_block("memory__store", {"key": "a"}, "id1"),
            _make_tool_use_block("memory__recall", {"key": "b"}, "id2"),
        ]
        result = _parse_anthropic_tool_calls(blocks)
        assert len(result) == 2
        assert result[0].action == "store"
        assert result[1].action == "recall"


# ---------------------------------------------------------------------------
# Client constructor
# ---------------------------------------------------------------------------


class TestAnthropicClientConstructor:
    """Tests for AnthropicClient.__init__."""

    def test_missing_api_key_does_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A missing ANTHROPIC_API_KEY no longer blocks construction (GH-142)."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        client = AnthropicClient(_make_llm_config())
        assert isinstance(client, AnthropicClient)

    def test_empty_api_key_does_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An empty ANTHROPIC_API_KEY no longer blocks construction (GH-142)."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "")
        client = AnthropicClient(_make_llm_config())
        assert isinstance(client, AnthropicClient)

    @pytest.mark.parametrize("model", [None, ""], ids=["none", "empty"])
    def test_missing_model_does_not_raise(
        self, monkeypatch: pytest.MonkeyPatch, model: str | None
    ) -> None:
        """An unset anthropic_model no longer blocks construction (GH-142)."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test123")
        client = AnthropicClient(_make_llm_config(anthropic_model=model))
        assert isinstance(client, AnthropicClient)

    def test_missing_sdk_raises_import_error(self) -> None:
        """Missing anthropic package raises ImportError with helpful message."""
        config = _make_llm_config()
        with (
            patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}),
            patch.dict("sys.modules", {"anthropic": None}),
            pytest.raises(ImportError, match="pip install anthropic"),
        ):
            AnthropicClient(config)

    def test_successful_construction(self) -> None:
        """Client constructs successfully with valid API key."""
        config = _make_llm_config()
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-ant-test123"}):
            client = AnthropicClient(config)
            assert client._model == "claude-sonnet-4-6"


# ---------------------------------------------------------------------------
# chat() method
# ---------------------------------------------------------------------------


class TestAnthropicClientChat:
    """Tests for AnthropicClient.chat."""

    @pytest.fixture()
    def client(self) -> AnthropicClient:
        """Create an AnthropicClient with a mocked SDK client."""
        config = _make_llm_config()
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-ant-test123"}):
            c = AnthropicClient(config)
        c._client = MagicMock()
        c._client.messages = MagicMock()
        c._client.close = AsyncMock()
        return c

    async def test_successful_text_response(self, client: AnthropicClient) -> None:
        """Successful response with text content."""
        response = _make_response([_make_text_block("Hello!")])
        client._client.messages.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())

        assert isinstance(result, LLMResponse)
        assert result.content == "Hello!"
        assert result.tool_calls == []
        assert result.done is True

    async def test_successful_tool_use_response(self, client: AnthropicClient) -> None:
        """Response with tool_use blocks parses tool calls."""
        blocks = [
            _make_text_block("Let me store that."),
            _make_tool_use_block("memory__store", {"key": "k", "value": "v"}, "toolu_01"),
        ]
        response = _make_response(blocks, stop_reason="tool_use")
        client._client.messages.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())

        assert result.content == "Let me store that."
        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].tool == "memory"
        assert result.tool_calls[0].tool_call_id == "toolu_01"
        assert result.done is False  # stop_reason == "tool_use" → done=False

    async def test_empty_content_blocks(self, client: AnthropicClient) -> None:
        """Response with no content blocks returns empty content."""
        response = _make_response([])
        client._client.messages.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())

        assert result.content == ""
        assert result.tool_calls == []

    async def test_stream_true_raises_value_error(self, client: AnthropicClient) -> None:
        """Passing stream=True raises ValueError."""
        with pytest.raises(ValueError, match="Streaming not yet supported"):
            await client.chat(_make_messages(), stream=True)

    async def test_empty_messages_fallback(self, client: AnthropicClient) -> None:
        """Empty message list gets a fallback user message."""
        response = _make_response()
        client._client.messages.create = AsyncMock(return_value=response)

        await client.chat([])

        # The fallback message should be sent
        call_kwargs = client._client.messages.create.call_args
        messages_sent = call_kwargs.kwargs.get("messages") or call_kwargs[1].get("messages")
        assert len(messages_sent) == 1
        assert messages_sent[0]["content"] == "Hello"

    async def test_tools_converted_and_sent(self, client: AnthropicClient) -> None:
        """Tools are converted to Anthropic format and included in request."""
        response = _make_response()
        client._client.messages.create = AsyncMock(return_value=response)

        tools = [
            {
                "type": "function",
                "function": {
                    "name": "memory.store",
                    "description": "Store",
                    "parameters": {"type": "object"},
                },
            }
        ]
        await client.chat(_make_messages(), tools=tools)

        call_kwargs = client._client.messages.create.call_args
        sent_tools = call_kwargs.kwargs.get("tools") or call_kwargs[1].get("tools")
        assert len(sent_tools) == 1
        assert sent_tools[0]["name"] == "memory__store"  # dots encoded as __
        assert "input_schema" in sent_tools[0]

    async def test_system_prompt_sent(self, client: AnthropicClient) -> None:
        """System messages are sent as the system parameter."""
        response = _make_response()
        client._client.messages.create = AsyncMock(return_value=response)

        msgs = [
            LLMMessage(role="system", content="Be helpful"),
            LLMMessage(role="user", content="Hi"),
        ]
        await client.chat(msgs)

        call_kwargs = client._client.messages.create.call_args
        assert call_kwargs.kwargs.get("system") == "Be helpful"

    async def test_api_timeout_error(self, client: AnthropicClient) -> None:
        """API timeout → user-facing "temporarily unavailable" (GH-142)."""
        client._client.messages.create = AsyncMock(
            side_effect=anthropic.APITimeoutError(request=MagicMock())
        )

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())
        assert "temporarily unavailable" in exc_info.value.message
        assert exc_info.value.status_code is None
        assert exc_info.value.user_facing is True

    async def test_api_connection_error(self, client: AnthropicClient) -> None:
        """Connection error → user-facing "temporarily unavailable" (GH-142)."""
        client._client.messages.create = AsyncMock(
            side_effect=anthropic.APIConnectionError(request=MagicMock())
        )

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())
        assert "temporarily unavailable" in exc_info.value.message
        assert exc_info.value.status_code is None
        assert exc_info.value.user_facing is True

    async def test_rate_limit_error(self, client: AnthropicClient) -> None:
        """Rate limit error raises LLMError with status_code=429."""
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {}
        client._client.messages.create = AsyncMock(
            side_effect=anthropic.RateLimitError(
                message="Rate limited",
                response=mock_response,
                body=None,
            )
        )

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())
        assert exc_info.value.status_code == 429

    async def test_api_status_error(self, client: AnthropicClient) -> None:
        """A 500 → user-facing fixed message; the SDK detail is no longer embedded (GH-142)."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.headers = {}
        client._client.messages.create = AsyncMock(
            side_effect=anthropic.APIStatusError(
                message="Internal error",
                response=mock_response,
                body=None,
            )
        )

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())
        assert exc_info.value.status_code == 500
        assert exc_info.value.user_facing is True
        assert "temporarily unavailable" in exc_info.value.message
        assert "Internal error" not in exc_info.value.message

    async def test_done_true_when_no_tool_use(self, client: AnthropicClient) -> None:
        """done=True when stop_reason is not 'tool_use'."""
        response = _make_response(stop_reason="end_turn")
        client._client.messages.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert result.done is True

    async def test_done_false_when_tool_use(self, client: AnthropicClient) -> None:
        """done=False when stop_reason is 'tool_use'."""
        blocks = [_make_tool_use_block()]
        response = _make_response(blocks, stop_reason="tool_use")
        client._client.messages.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert result.done is False

    async def test_model_name_sanitized(self, client: AnthropicClient) -> None:
        """Control characters in model name are stripped."""
        response = _make_response(model="claude\x00-test\u202e")
        client._client.messages.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert "\x00" not in result.model
        assert "\u202e" not in result.model

    async def test_model_name_truncated(self, client: AnthropicClient) -> None:
        """Model name longer than 200 chars is truncated."""
        response = _make_response(model="x" * 300)
        client._client.messages.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert len(result.model) <= 200

    async def test_content_sanitized(self, client: AnthropicClient) -> None:
        """Control characters in text content are stripped."""
        blocks = [_make_text_block("Hello\x00\u202eWorld")]
        response = _make_response(blocks)
        client._client.messages.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert result.content == "HelloWorld"

    async def test_multiple_text_blocks_joined(self, client: AnthropicClient) -> None:
        """Multiple text blocks are joined with newlines."""
        blocks = [_make_text_block("Part 1"), _make_text_block("Part 2")]
        response = _make_response(blocks)
        client._client.messages.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert result.content == "Part 1\nPart 2"


# ---------------------------------------------------------------------------
# Context manager and close
# ---------------------------------------------------------------------------


class TestAnthropicContextManager:
    """Tests for async context manager and close."""

    async def test_aenter_returns_self(self) -> None:
        """__aenter__ returns the client instance."""
        config = _make_llm_config()
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-ant-test123"}):
            client = AnthropicClient(config)
        client._client = MagicMock()
        client._client.close = AsyncMock()

        result = await client.__aenter__()
        assert result is client

    async def test_aexit_calls_close(self) -> None:
        """__aexit__ calls close() which calls client.close()."""
        config = _make_llm_config()
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-ant-test123"}):
            client = AnthropicClient(config)
        client._client = MagicMock()
        client._client.close = AsyncMock()

        await client.__aexit__(None, None, None)
        client._client.close.assert_awaited_once()

    async def test_async_with(self) -> None:
        """Client works as an async context manager."""
        config = _make_llm_config()
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-ant-test123"}):
            client = AnthropicClient(config)
        client._client = MagicMock()
        client._client.close = AsyncMock()

        async with client as c:
            assert c is client

        client._client.close.assert_awaited_once()


# ---------------------------------------------------------------------------
# Adversarial / security tests
# ---------------------------------------------------------------------------


class TestAnthropicAdversarial:
    """Adversarial security tests for the Anthropic client."""

    def test_zero_width_space_in_tool_name(self) -> None:
        """Zero-width space in tool name is stripped (display spoofing)."""
        blocks = [_make_tool_use_block("memory\u200b.store", {"key": "v"})]
        result = _parse_anthropic_tool_calls(blocks)
        assert len(result) == 1
        assert "\u200b" not in result[0].tool

    def test_rtl_override_in_tool_name(self) -> None:
        """RTL override in tool name is stripped."""
        blocks = [_make_tool_use_block("memory\u202e.store\u202d", {"key": "v"})]
        result = _parse_anthropic_tool_calls(blocks)
        assert len(result) == 1
        assert "\u202e" not in result[0].tool
        assert "\u202d" not in result[0].action

    def test_bom_in_tool_use_id(self) -> None:
        """BOM in tool_use id is stripped."""
        blocks = [_make_tool_use_block("memory.store", {"key": "v"}, "\ufefftoolu_01")]
        result = _parse_anthropic_tool_calls(blocks)
        assert len(result) == 1
        assert "\ufeff" not in (result[0].tool_call_id or "")

    def test_hallucinated_tool_name_rejected(self) -> None:
        """Hallucinated tool name (not matching schema) is rejected by Pydantic."""
        # Tool name with uppercase/special chars fails ToolCall validation
        blocks = [_make_tool_use_block("FAKE-Tool.hack", {})]
        result = _parse_anthropic_tool_calls(blocks)
        assert result == []

    def test_oversized_single_value(self) -> None:
        """Single argument value > 2048 chars is rejected."""
        blocks = [_make_tool_use_block("memory.store", {"payload": "A" * 2049})]
        result = _parse_anthropic_tool_calls(blocks)
        assert result == []

    @pytest.mark.parametrize(
        "depth",
        [5, 6, 10],
        ids=["depth-5", "depth-6", "depth-10"],
    )
    def test_deep_nesting_at_various_depths(self, depth: int) -> None:
        """Arguments with nesting beyond limit=4 are rejected."""
        nested: dict[str, Any] = {"val": "leaf"}
        for _ in range(depth):
            nested = {"nested": nested}
        blocks = [_make_tool_use_block("memory.store", nested)]
        result = _parse_anthropic_tool_calls(blocks)
        assert result == []

    def test_args_at_nesting_limit_accepted(self) -> None:
        """Arguments at exactly depth 3 (within limit 4) are accepted."""
        args: dict[str, Any] = {"a": {"b": {"c": "leaf"}}}
        assert check_args_depth(args, 4) is True
        blocks = [_make_tool_use_block("memory.store", args)]
        result = _parse_anthropic_tool_calls(blocks)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Additional security tests for audit findings
# ---------------------------------------------------------------------------


class TestAnthropicC1ControlChars:
    """Tests that C1 control characters are stripped from LLM content."""

    async def test_c1_nel_stripped_from_content(self) -> None:
        """U+0085 (NEL — Next Line) is stripped from response content."""
        config = _make_llm_config()
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-ant-test123"}):
            client = AnthropicClient(config)
        client._client = MagicMock()
        client._client.close = AsyncMock()

        response = _make_response([_make_text_block("Hello\x85World")])
        client._client.messages.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert "\x85" not in result.content
        assert "HelloWorld" in result.content

    async def test_c1_csi_stripped_from_content(self) -> None:
        """U+009B (CSI — Control Sequence Introducer) is stripped."""
        config = _make_llm_config()
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-ant-test123"}):
            client = AnthropicClient(config)
        client._client = MagicMock()
        client._client.close = AsyncMock()

        response = _make_response([_make_text_block("data\x9b31mred")])
        client._client.messages.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert "\x9b" not in result.content


class TestAnthropicValidateToolsPayload:
    """Tests that validate_tools_payload is enforced."""

    @pytest.fixture()
    def client(self) -> AnthropicClient:
        """Create an AnthropicClient with a mocked SDK client."""
        config = _make_llm_config()
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-ant-test123"}):
            c = AnthropicClient(config)
        c._client = MagicMock()
        c._client.messages = MagicMock()
        c._client.close = AsyncMock()
        return c

    async def test_oversized_tools_list_raises_llm_error(self, client: AnthropicClient) -> None:
        """Tools list exceeding size limits raises LLMError."""
        from admino.llm import LLMError

        # Create 65 tools (limit is 64)
        oversized_tools = [
            {
                "type": "function",
                "function": {
                    "name": f"tool.action{i}",
                    "description": "desc",
                    "parameters": {"type": "object"},
                },
            }
            for i in range(65)
        ]
        with pytest.raises(LLMError, match="tools list exceeds size limits"):
            await client.chat(_make_messages(), tools=oversized_tools)

    async def test_valid_tools_pass_validation(self, client: AnthropicClient) -> None:
        """Normal-sized tools list passes validation and is sent."""
        response = _make_response()
        client._client.messages.create = AsyncMock(return_value=response)

        tools = [
            {
                "type": "function",
                "function": {
                    "name": "memory.store",
                    "description": "Store",
                    "parameters": {"type": "object"},
                },
            }
        ]
        result = await client.chat(_make_messages(), tools=tools)
        assert isinstance(result, LLMResponse)

    async def test_max_tokens_sent_in_request(self, client: AnthropicClient) -> None:
        """max_tokens is included in the API request kwargs."""
        response = _make_response()
        client._client.messages.create = AsyncMock(return_value=response)

        await client.chat(_make_messages())

        call_kwargs = client._client.messages.create.call_args
        assert call_kwargs.kwargs.get("max_tokens") == 4096


# ---------------------------------------------------------------------------
# GH-142: user-facing provider errors
# ---------------------------------------------------------------------------


def _mocked_client(
    model: str | None = "claude-sonnet-4-6",
) -> tuple[AnthropicClient, AsyncMock]:
    """An AnthropicClient whose SDK messages.create() is an AsyncMock text reply."""
    client = AnthropicClient(_make_llm_config(anthropic_model=model))
    create = AsyncMock(return_value=_make_response())
    client._client = MagicMock()
    client._client.messages.create = create
    client._client.close = AsyncMock()
    return client, create


class TestAnthropicUserFacingErrors:
    """Setup/availability problems become friendly chat replies (label "Claude")."""

    @pytest.mark.parametrize("key", [None, ""], ids=["unset", "empty"])
    async def test_claude_missing_key_chat_user_facing(
        self, monkeypatch: pytest.MonkeyPatch, key: str | None
    ) -> None:
        """No key → "Claude isn't configured; set ANTHROPIC_API_KEY", no API call."""
        if key is None:
            monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        else:
            monkeypatch.setenv("ANTHROPIC_API_KEY", key)
        client, create = _mocked_client()

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())

        message = exc_info.value.message
        assert exc_info.value.user_facing is True
        assert exc_info.value.status_code is None
        assert "Claude" in message
        assert "isn't configured" in message
        assert "ANTHROPIC_API_KEY" in message
        create.assert_not_awaited()

    @pytest.mark.parametrize("model", [None, ""], ids=["none", "empty"])
    async def test_claude_missing_model_chat_user_facing(
        self, monkeypatch: pytest.MonkeyPatch, model: str | None
    ) -> None:
        """No model → "No Claude model is set … ask your administrator", no API call."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test123")
        client, create = _mocked_client(model=model)

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())

        message = exc_info.value.message
        assert exc_info.value.user_facing is True
        assert exc_info.value.status_code is None
        assert "No Claude model is set" in message
        assert "ask your administrator" in message
        assert "Settings → Agent" not in message  # GH-159: that section is gone
        create.assert_not_awaited()

    @pytest.mark.parametrize(
        ("cls", "status", "phrases"),
        [
            (
                anthropic.AuthenticationError,
                401,
                ("Claude", "rejected the API", "ANTHROPIC_API_KEY"),
            ),
            (
                anthropic.PermissionDeniedError,
                403,
                ("Claude", "rejected the API", "ANTHROPIC_API_KEY"),
            ),
            (anthropic.NotFoundError, 404, ("Claude", "ask your administrator")),
            (anthropic.RateLimitError, 429, ("Claude", "rate limit")),
            (anthropic.InternalServerError, 500, ("Claude", "temporarily unavailable")),
            (anthropic.InternalServerError, 503, ("Claude", "temporarily unavailable")),
            # 529 "overloaded" is raised as a plain APIStatusError subclass (not
            # InternalServerError) by the SDK — mapping must go by status >= 500.
            (anthropic.APIStatusError, 529, ("Claude", "temporarily unavailable")),
        ],
        ids=["401", "403", "404", "429", "500", "503", "529-overloaded"],
    )
    async def test_claude_status_error_user_facing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        cls: type[Any],
        status: int,
        phrases: tuple[str, ...],
    ) -> None:
        """401/403/404/429/5xx → user-facing fixed message; the body never leaks."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test123")
        client, create = _mocked_client()
        marker = f"CLAUDE-BODY-SECRET-{status}"
        create.side_effect = _status_error(cls, status, marker)

        with caplog.at_level(logging.DEBUG), pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())

        exc = exc_info.value
        assert exc.user_facing is True
        assert exc.status_code == status
        for phrase in phrases:
            if phrase == "rate limit":
                assert phrase in exc.message.lower()
            else:
                assert phrase in exc.message
        assert marker not in exc.message
        assert marker not in str(exc)
        assert marker not in caplog.text

    @pytest.mark.parametrize(
        "make_exc",
        [
            lambda marker: anthropic.APITimeoutError(request=_ANTHROPIC_REQUEST),
            lambda marker: anthropic.APIConnectionError(message=marker, request=_ANTHROPIC_REQUEST),
        ],
        ids=["timeout", "connection"],
    )
    async def test_claude_transport_error_user_facing(
        self, monkeypatch: pytest.MonkeyPatch, make_exc: Any
    ) -> None:
        """Timeout / connection failure → "Claude … temporarily unavailable", no cause detail."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test123")
        client, create = _mocked_client()
        marker = "CLAUDE-TRANSPORT-SECRET"
        create.side_effect = make_exc(marker)

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())

        assert exc_info.value.user_facing is True
        assert exc_info.value.status_code is None
        assert "Claude" in exc_info.value.message
        assert "temporarily unavailable" in exc_info.value.message
        assert marker not in exc_info.value.message

    @pytest.mark.parametrize(
        ("cls", "status"),
        [
            (anthropic.BadRequestError, 400),
            # GH-242: 413 is context_too_long (user-facing), tested in test_llm_error_codes.
            (anthropic.UnprocessableEntityError, 422),
        ],
        ids=["400", "422"],
    )
    async def test_claude_other_4xx_not_user_facing(
        self, monkeypatch: pytest.MonkeyPatch, cls: type[Any], status: int
    ) -> None:
        """Other 4xx stay internal (user_facing False) so the agent shows its generic reply."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test123")
        client, create = _mocked_client()
        create.side_effect = _status_error(cls, status, "detail")

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())

        assert exc_info.value.user_facing is False
        assert exc_info.value.status_code == status

    async def test_claude_oversized_tools_not_user_facing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An oversized tools payload is an internal error."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test123")
        client, _create = _mocked_client()
        tools = [
            {"type": "function", "function": {"name": f"tool.action{i}", "parameters": {}}}
            for i in range(65)
        ]
        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages(), tools=tools)
        assert exc_info.value.user_facing is False
