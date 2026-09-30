"""Tests for the OpenAI LLM client module.

Covers message conversion, tool format conversion, tool call parsing,
client construction, chat method, error handling, context manager,
and adversarial/security edge cases.

GH-142: a missing OPENAI_API_KEY or model no longer fails construction; chat()
answers with a friendly, user-facing ``LLMError`` instead, and SDK errors map to
the fixed user-facing catalogue (401/403/404/429/5xx/timeout/connection) while
other 4xx stay internal (``user_facing=False``).

All API calls are mocked — no real OpenAI API is contacted.
"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import openai
import pytest

from admino.llm import LLMError, LLMResponse, check_args_depth
from admino.llm_openai import (
    OpenAIClient,
    _convert_messages_to_openai,
    _convert_tools_to_openai,
    _parse_openai_tool_calls,
)
from admino.models import LLMMessage

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_llm_config(openai_model: str | None = "gpt-4o") -> Any:
    """Create a fake LLMConfig for testing."""
    return SimpleNamespace(
        openai_model=openai_model,
        timeout_s=30,
        max_response_tokens=4096,
    )


_OPENAI_REQUEST = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")


def _status_error(cls: type[Any], status: int, marker: str) -> Any:
    """Build an openai SDK status error whose body carries a secret marker."""
    body = {"error": {"message": f"upstream detail {marker}", "type": "invalid_request_error"}}
    response = httpx.Response(status, request=_OPENAI_REQUEST, json=body)
    return cls(f"Error code: {status} - {body}", response=response, body=body)


def _make_messages(content: str = "Hi") -> list[LLMMessage]:
    """Create a minimal message list for chat calls."""
    return [LLMMessage(role="user", content=content)]


def _make_openai_tool_call(
    name: str = "memory.store",
    arguments: str = '{"key": "test"}',
    call_id: str = "call_abc123",
) -> SimpleNamespace:
    """Create a mock OpenAI tool call object."""
    return SimpleNamespace(
        id=call_id,
        type="function",
        function=SimpleNamespace(name=name, arguments=arguments),
    )


def _make_choice(
    content: str = "Hello!",
    tool_calls: list[Any] | None = None,
    finish_reason: str = "stop",
) -> SimpleNamespace:
    """Create a mock OpenAI chat completion choice."""
    return SimpleNamespace(
        message=SimpleNamespace(content=content, tool_calls=tool_calls),
        finish_reason=finish_reason,
    )


def _make_completion(
    choices: list[Any] | None = None,
    model: str = "gpt-4o",
) -> SimpleNamespace:
    """Create a mock OpenAI chat completion response."""
    if choices is None:
        choices = [_make_choice()]
    return SimpleNamespace(choices=choices, model=model)


# ---------------------------------------------------------------------------
# Message conversion
# ---------------------------------------------------------------------------


class TestConvertMessagesToOpenAI:
    """Tests for _convert_messages_to_openai."""

    def test_user_message(self) -> None:
        """User message maps correctly."""
        msgs = [LLMMessage(role="user", content="Hello")]
        result = _convert_messages_to_openai(msgs)
        assert result == [{"role": "user", "content": "Hello"}]

    def test_assistant_message(self) -> None:
        """Assistant message maps correctly."""
        msgs = [LLMMessage(role="assistant", content="Hi")]
        result = _convert_messages_to_openai(msgs)
        assert result == [{"role": "assistant", "content": "Hi"}]

    def test_system_message(self) -> None:
        """System message maps correctly (OpenAI supports system natively)."""
        msgs = [LLMMessage(role="system", content="Be helpful")]
        result = _convert_messages_to_openai(msgs)
        assert result == [{"role": "system", "content": "Be helpful"}]

    def test_tool_message_with_id(self) -> None:
        """Tool message includes tool_call_id."""
        msgs = [LLMMessage(role="tool", content="result", tool_call_id="call-123")]
        result = _convert_messages_to_openai(msgs)
        assert result[0]["role"] == "tool"
        assert result[0]["tool_call_id"] == "call-123"

    def test_tool_message_without_id(self) -> None:
        """Tool message without tool_call_id does not include the key."""
        msgs = [LLMMessage(role="tool", content="result")]
        result = _convert_messages_to_openai(msgs)
        assert "tool_call_id" not in result[0]

    def test_assistant_tool_use_blocks_become_tool_calls(self) -> None:
        """An assistant tool-call turn carries OpenAI ``tool_calls`` (JSON-string args).

        OpenAI-compatible servers require every ``tool`` message to answer a
        preceding assistant ``tool_calls`` entry with the same id.
        """
        msgs = [
            LLMMessage(
                role="assistant",
                content="",
                tool_use_blocks=[
                    {
                        "type": "tool_use",
                        "id": "call_1",
                        "name": "memory.store",
                        "input": {"key": "k", "value": "v"},
                    },
                    {"type": "tool_use", "id": "call_2", "name": "memory.list", "input": {}},
                ],
            )
        ]
        result = _convert_messages_to_openai(msgs)
        assert result == [
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "memory.store",
                            "arguments": json.dumps({"key": "k", "value": "v"}),
                        },
                    },
                    {
                        "id": "call_2",
                        "type": "function",
                        "function": {"name": "memory.list", "arguments": "{}"},
                    },
                ],
            }
        ]

    def test_assistant_without_tool_use_blocks_has_no_tool_calls(self) -> None:
        """A plain assistant message gets no ``tool_calls`` key."""
        result = _convert_messages_to_openai([LLMMessage(role="assistant", content="Hi")])
        assert "tool_calls" not in result[0]

    def test_malformed_tool_use_blocks_are_skipped(self) -> None:
        """Blocks without a string id/name or a dict input are dropped."""
        msgs = [
            LLMMessage(
                role="assistant",
                content="",
                tool_use_blocks=[
                    {"type": "tool_use", "id": None, "name": "memory.store", "input": {}},
                    {"type": "tool_use", "id": "call_1", "name": "", "input": {}},
                    {"type": "tool_use", "id": "call_2", "name": "memory.store", "input": "x"},
                ],
            )
        ]
        result = _convert_messages_to_openai(msgs)
        assert "tool_calls" not in result[0]

    def test_empty_messages(self) -> None:
        """Empty message list returns empty list."""
        assert _convert_messages_to_openai([]) == []

    def test_multiple_messages_preserved(self) -> None:
        """Multiple messages are preserved in order."""
        msgs = [
            LLMMessage(role="system", content="System"),
            LLMMessage(role="user", content="Q"),
            LLMMessage(role="assistant", content="A"),
        ]
        result = _convert_messages_to_openai(msgs)
        assert len(result) == 3
        assert [m["role"] for m in result] == ["system", "user", "assistant"]


# ---------------------------------------------------------------------------
# Tool format conversion
# ---------------------------------------------------------------------------


class TestConvertToolsToOpenAI:
    """Tests for _convert_tools_to_openai."""

    def test_normal_tool(self) -> None:
        """Standard tool definition passes through correctly."""
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
        result = _convert_tools_to_openai(tools)
        assert len(result) == 1
        assert result[0]["type"] == "function"
        assert result[0]["function"]["name"] == "memory.store"

    def test_function_not_dict(self) -> None:
        """Non-dict function value is skipped."""
        tools = [{"type": "function", "function": "not-a-dict"}]
        result = _convert_tools_to_openai(tools)
        assert result == []

    def test_missing_function_key(self) -> None:
        """Missing 'function' key gets empty dict default and is included."""
        tools = [{"type": "function"}]
        result = _convert_tools_to_openai(tools)
        assert len(result) == 1
        assert result[0]["function"]["name"] == ""

    def test_empty_tools_list(self) -> None:
        """Empty tools list returns empty list."""
        assert _convert_tools_to_openai([]) == []

    def test_default_parameters(self) -> None:
        """Missing parameters defaults to empty object schema."""
        tools = [{"type": "function", "function": {"name": "test.run"}}]
        result = _convert_tools_to_openai(tools)
        assert result[0]["function"]["parameters"] == {"type": "object", "properties": {}}


# ---------------------------------------------------------------------------
# Tool call parsing
# ---------------------------------------------------------------------------


class TestParseOpenAIToolCalls:
    """Tests for _parse_openai_tool_calls."""

    def test_valid_tool_call(self) -> None:
        """Valid tool call with dot notation is parsed correctly."""
        tc = [_make_openai_tool_call("memory.store", '{"key": "k", "value": "v"}', "call_01")]
        result = _parse_openai_tool_calls(tc)
        assert len(result) == 1
        assert result[0].tool == "memory"
        assert result[0].action == "store"
        assert result[0].args == {"key": "k", "value": "v"}
        assert result[0].tool_call_id == "call_01"

    def test_none_tool_calls(self) -> None:
        """None tool_calls returns empty list."""
        assert _parse_openai_tool_calls(None) == []

    def test_empty_tool_calls(self) -> None:
        """Empty tool_calls list returns empty list."""
        assert _parse_openai_tool_calls([]) == []

    def test_missing_function_attribute(self) -> None:
        """Tool call without function attribute is skipped."""
        tc = [SimpleNamespace(id="call_01")]
        result = _parse_openai_tool_calls(tc)
        assert result == []

    def test_missing_name(self, caplog: pytest.LogCaptureFixture) -> None:
        """Empty name is skipped with warning."""
        tc = [SimpleNamespace(id="x", function=SimpleNamespace(name="", arguments="{}"))]
        with caplog.at_level(logging.WARNING):
            result = _parse_openai_tool_calls(tc)
        assert result == []
        assert any("missing name" in r.message for r in caplog.records)

    def test_non_string_name(self, caplog: pytest.LogCaptureFixture) -> None:
        """Non-string name is skipped."""
        tc = [SimpleNamespace(id="x", function=SimpleNamespace(name=123, arguments="{}"))]
        with caplog.at_level(logging.WARNING):
            result = _parse_openai_tool_calls(tc)
        assert result == []

    def test_malformed_json_arguments(self, caplog: pytest.LogCaptureFixture) -> None:
        """Malformed JSON string in arguments is skipped."""
        tc = [_make_openai_tool_call("memory.store", "not-json{", "call_01")]
        with caplog.at_level(logging.WARNING):
            result = _parse_openai_tool_calls(tc)
        assert result == []
        assert any("malformed JSON" in r.message for r in caplog.records)

    def test_arguments_dict_directly(self) -> None:
        """Arguments as a dict (not JSON string) are accepted."""
        tc = [
            SimpleNamespace(
                id="call_01",
                function=SimpleNamespace(name="memory.store", arguments={"key": "v"}),
            )
        ]
        result = _parse_openai_tool_calls(tc)
        assert len(result) == 1

    def test_arguments_not_string_or_dict(self, caplog: pytest.LogCaptureFixture) -> None:
        """Arguments that are neither string nor dict are skipped."""
        tc = [
            SimpleNamespace(
                id="call_01",
                function=SimpleNamespace(name="memory.store", arguments=42),
            )
        ]
        with caplog.at_level(logging.WARNING):
            result = _parse_openai_tool_calls(tc)
        assert result == []
        assert any("not a string or dict" in r.message for r in caplog.records)

    def test_json_parses_to_non_dict(self, caplog: pytest.LogCaptureFixture) -> None:
        """JSON string that parses to a non-dict (e.g. list) is rejected."""
        tc = [_make_openai_tool_call("memory.store", "[1, 2, 3]", "call_01")]
        with caplog.at_level(logging.WARNING):
            result = _parse_openai_tool_calls(tc)
        assert result == []
        assert any("not a dict" in r.message for r in caplog.records)

    def test_no_dot_notation(self, caplog: pytest.LogCaptureFixture) -> None:
        """Name without dot is rejected."""
        tc = [_make_openai_tool_call("nodot", '{"q": "test"}', "call_01")]
        with caplog.at_level(logging.WARNING):
            result = _parse_openai_tool_calls(tc)
        assert result == []
        assert any("dot notation" in r.message for r in caplog.records)

    def test_trailing_dot_rejected(self, caplog: pytest.LogCaptureFixture) -> None:
        """Name 'tool.' with empty action is rejected."""
        tc = [_make_openai_tool_call("memory.", "{}", "call_01")]
        with caplog.at_level(logging.WARNING):
            result = _parse_openai_tool_calls(tc)
        assert result == []

    def test_leading_dot_rejected(self, caplog: pytest.LogCaptureFixture) -> None:
        """Name '.action' with empty tool is rejected."""
        tc = [_make_openai_tool_call(".store", "{}", "call_01")]
        with caplog.at_level(logging.WARNING):
            result = _parse_openai_tool_calls(tc)
        assert result == []

    def test_deep_nesting_rejected(self, caplog: pytest.LogCaptureFixture) -> None:
        """Arguments nested beyond depth limit are rejected."""
        deep: dict[str, Any] = {"a": "v"}
        for _ in range(4):
            deep = {"a": deep}
        tc = [_make_openai_tool_call("memory.store", json.dumps(deep), "call_01")]
        with caplog.at_level(logging.WARNING):
            result = _parse_openai_tool_calls(tc)
        assert result == []
        assert any("nesting depth" in r.message for r in caplog.records)

    def test_too_many_keys_rejected(self, caplog: pytest.LogCaptureFixture) -> None:
        """Arguments with >32 keys are rejected."""
        big = {f"k{i}": "v" for i in range(33)}
        tc = [_make_openai_tool_call("memory.store", json.dumps(big), "call_01")]
        with caplog.at_level(logging.WARNING):
            result = _parse_openai_tool_calls(tc)
        assert result == []

    def test_value_too_long_rejected(self, caplog: pytest.LogCaptureFixture) -> None:
        """String value >2048 chars is rejected."""
        tc = [_make_openai_tool_call("memory.store", json.dumps({"big": "x" * 2049}), "call_01")]
        with caplog.at_level(logging.WARNING):
            result = _parse_openai_tool_calls(tc)
        assert result == []

    def test_total_size_exceeded(self, caplog: pytest.LogCaptureFixture) -> None:
        """Total JSON size >16384 bytes is rejected."""
        args = {f"k{i}": "x" * 1000 for i in range(20)}
        tc = [_make_openai_tool_call("memory.store", json.dumps(args), "call_01")]
        with caplog.at_level(logging.WARNING):
            result = _parse_openai_tool_calls(tc)
        assert result == []

    def test_control_chars_in_name_stripped(self) -> None:
        """Control characters in tool name are stripped."""
        tc = [_make_openai_tool_call("memory\x00.store", '{"key": "v"}', "call_01")]
        result = _parse_openai_tool_calls(tc)
        assert len(result) == 1
        assert result[0].tool == "memory"

    def test_control_chars_in_id_stripped(self) -> None:
        """Control characters in call id are stripped."""
        tc = [_make_openai_tool_call("memory.store", '{"key": "v"}', "call\x00_01")]
        result = _parse_openai_tool_calls(tc)
        assert len(result) == 1
        assert "\x00" not in (result[0].tool_call_id or "")

    def test_name_truncated_to_64(self) -> None:
        """Name longer than 64 chars is truncated."""
        long_name = "a" * 30 + "." + "b" * 60  # 91 chars, dot at position 30
        tc = [_make_openai_tool_call(long_name, "{}", "call_01")]
        result = _parse_openai_tool_calls(tc)
        # Truncated to 64: 'a'*30 + '.' + 'b'*33 — still has a dot
        assert len(result) == 1

    def test_id_truncated_to_128(self) -> None:
        """Call id longer than 128 chars is truncated."""
        long_id = "x" * 200
        tc = [_make_openai_tool_call("memory.store", '{"key": "v"}', long_id)]
        result = _parse_openai_tool_calls(tc)
        assert len(result) == 1
        assert len(result[0].tool_call_id or "") <= 128

    def test_non_string_id(self) -> None:
        """Non-string id results in None tool_call_id."""
        tc = [
            SimpleNamespace(
                id=12345,
                function=SimpleNamespace(name="memory.store", arguments='{"key": "v"}'),
            )
        ]
        result = _parse_openai_tool_calls(tc)
        assert len(result) == 1
        assert result[0].tool_call_id is None

    def test_validation_error_skipped(self, caplog: pytest.LogCaptureFixture) -> None:
        """ToolCall that fails Pydantic validation is skipped."""
        # Uppercase tool name fails ^[a-z][a-z0-9_]*$ pattern
        tc = [_make_openai_tool_call("MEMORY.store", "{}", "call_01")]
        with caplog.at_level(logging.WARNING):
            result = _parse_openai_tool_calls(tc)
        assert result == []

    def test_multiple_tool_calls(self) -> None:
        """Multiple valid tool calls are all parsed."""
        tc = [
            _make_openai_tool_call("memory.store", '{"key": "a"}', "call_01"),
            _make_openai_tool_call("memory.recall", '{"key": "b"}', "call_02"),
        ]
        result = _parse_openai_tool_calls(tc)
        assert len(result) == 2
        assert result[0].action == "store"
        assert result[1].action == "recall"


# ---------------------------------------------------------------------------
# Client constructor
# ---------------------------------------------------------------------------


class TestOpenAIClientConstructor:
    """Tests for OpenAIClient.__init__."""

    def test_missing_api_key_does_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A missing OPENAI_API_KEY no longer blocks construction (GH-142)."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        client = OpenAIClient(_make_llm_config())
        assert isinstance(client, OpenAIClient)

    def test_empty_api_key_does_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An empty OPENAI_API_KEY no longer blocks construction (GH-142)."""
        monkeypatch.setenv("OPENAI_API_KEY", "")
        client = OpenAIClient(_make_llm_config())
        assert isinstance(client, OpenAIClient)

    @pytest.mark.parametrize("model", [None, ""], ids=["none", "empty"])
    def test_missing_model_does_not_raise(
        self, monkeypatch: pytest.MonkeyPatch, model: str | None
    ) -> None:
        """An unset openai_model no longer blocks construction (GH-142)."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test123")
        client = OpenAIClient(_make_llm_config(openai_model=model))
        assert isinstance(client, OpenAIClient)

    def test_missing_sdk_raises_import_error(self) -> None:
        """Missing openai package raises ImportError with helpful message."""
        config = _make_llm_config()
        with (
            patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}),
            patch.dict("sys.modules", {"openai": None}),
            pytest.raises(ImportError, match="pip install openai"),
        ):
            OpenAIClient(config)

    def test_successful_construction(self) -> None:
        """Client constructs successfully with valid API key."""
        config = _make_llm_config()
        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test123"}):
            client = OpenAIClient(config)
            assert client._model == "gpt-4o"


# ---------------------------------------------------------------------------
# chat() method
# ---------------------------------------------------------------------------


class TestOpenAIClientChat:
    """Tests for OpenAIClient.chat."""

    @pytest.fixture()
    def client(self) -> OpenAIClient:
        """Create an OpenAIClient with a mocked SDK client."""
        config = _make_llm_config()
        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test123"}):
            c = OpenAIClient(config)
        c._client = MagicMock()
        c._client.chat = MagicMock()
        c._client.chat.completions = MagicMock()
        c._client.close = AsyncMock()
        return c

    async def test_successful_text_response(self, client: OpenAIClient) -> None:
        """Successful response with text content."""
        response = _make_completion()
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())

        assert isinstance(result, LLMResponse)
        assert result.content == "Hello!"
        assert result.tool_calls == []
        assert result.done is True

    async def test_successful_tool_call_response(self, client: OpenAIClient) -> None:
        """Response with tool calls parses correctly."""
        tool_calls = [_make_openai_tool_call("memory.store", '{"key": "k"}', "call_01")]
        choice = _make_choice("I'll store that.", tool_calls, "tool_calls")
        response = _make_completion([choice])
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())

        assert result.content == "I'll store that."
        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].tool == "memory"
        assert result.tool_calls[0].tool_call_id == "call_01"
        assert result.done is False  # finish_reason == "tool_calls"

    async def test_empty_choices(self, client: OpenAIClient) -> None:
        """Response with no choices returns empty response."""
        response = _make_completion([])
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())

        assert result.content == ""
        assert result.tool_calls == []
        assert result.done is True

    async def test_none_content(self, client: OpenAIClient) -> None:
        """None message content is handled as empty string."""
        choice = _make_choice(content=None)  # type: ignore[arg-type]
        response = _make_completion([choice])
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert result.content == ""

    async def test_stream_true_raises_value_error(self, client: OpenAIClient) -> None:
        """Passing stream=True raises ValueError."""
        with pytest.raises(ValueError, match="Streaming not yet supported"):
            await client.chat(_make_messages(), stream=True)

    async def test_tools_converted_and_sent(self, client: OpenAIClient) -> None:
        """Tools are converted and included in request."""
        response = _make_completion()
        client._client.chat.completions.create = AsyncMock(return_value=response)

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

        call_kwargs = client._client.chat.completions.create.call_args
        sent_tools = call_kwargs.kwargs.get("tools") or call_kwargs[1].get("tools")
        assert len(sent_tools) == 1
        assert sent_tools[0]["function"]["name"] == "memory.store"

    async def test_no_tools_omitted(self, client: OpenAIClient) -> None:
        """When no tools, the tools key is not sent."""
        response = _make_completion()
        client._client.chat.completions.create = AsyncMock(return_value=response)

        await client.chat(_make_messages())

        call_kwargs = client._client.chat.completions.create.call_args.kwargs
        assert "tools" not in call_kwargs

    async def test_api_timeout_error(self, client: OpenAIClient) -> None:
        """API timeout → user-facing "temporarily unavailable" (GH-142)."""
        client._client.chat.completions.create = AsyncMock(
            side_effect=openai.APITimeoutError(request=MagicMock())
        )

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())
        assert "temporarily unavailable" in exc_info.value.message
        assert exc_info.value.status_code is None
        assert exc_info.value.user_facing is True

    async def test_api_connection_error(self, client: OpenAIClient) -> None:
        """Connection error → user-facing "temporarily unavailable" (GH-142)."""
        client._client.chat.completions.create = AsyncMock(
            side_effect=openai.APIConnectionError(request=MagicMock())
        )

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())
        assert "temporarily unavailable" in exc_info.value.message
        assert exc_info.value.status_code is None
        assert exc_info.value.user_facing is True

    async def test_rate_limit_error(self, client: OpenAIClient) -> None:
        """Rate limit error raises LLMError with status_code=429."""
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {}
        client._client.chat.completions.create = AsyncMock(
            side_effect=openai.RateLimitError(
                message="Rate limited",
                response=mock_response,
                body=None,
            )
        )

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())
        assert exc_info.value.status_code == 429

    async def test_api_status_error(self, client: OpenAIClient) -> None:
        """A 500 → user-facing fixed message; the SDK detail is no longer embedded (GH-142)."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.headers = {}
        client._client.chat.completions.create = AsyncMock(
            side_effect=openai.APIStatusError(
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

    async def test_done_true_when_stop(self, client: OpenAIClient) -> None:
        """done=True when finish_reason is 'stop'."""
        choice = _make_choice(finish_reason="stop")
        response = _make_completion([choice])
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert result.done is True

    async def test_done_false_when_tool_calls(self, client: OpenAIClient) -> None:
        """done=False when finish_reason is 'tool_calls'."""
        tool_calls = [_make_openai_tool_call()]
        choice = _make_choice("", tool_calls, "tool_calls")
        response = _make_completion([choice])
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert result.done is False

    async def test_model_name_sanitized(self, client: OpenAIClient) -> None:
        """Control characters in model name are stripped."""
        response = _make_completion(model="gpt\x00-4o\u202e")
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert "\x00" not in result.model
        assert "\u202e" not in result.model

    async def test_model_name_truncated(self, client: OpenAIClient) -> None:
        """Model name longer than 200 chars is truncated."""
        response = _make_completion(model="x" * 300)
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert len(result.model) <= 200

    async def test_none_model_uses_default(self, client: OpenAIClient) -> None:
        """None model in response falls back to configured model."""
        response = _make_completion(model=None)  # type: ignore[arg-type]
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert result.model == "gpt-4o"

    async def test_content_sanitized(self, client: OpenAIClient) -> None:
        """Control characters in content are stripped."""
        choice = _make_choice("Hello\x00\u202eWorld")
        response = _make_completion([choice])
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert result.content == "HelloWorld"


# ---------------------------------------------------------------------------
# Context manager and close
# ---------------------------------------------------------------------------


class TestOpenAIContextManager:
    """Tests for async context manager and close."""

    async def test_aenter_returns_self(self) -> None:
        """__aenter__ returns the client instance."""
        config = _make_llm_config()
        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test123"}):
            client = OpenAIClient(config)
        client._client = MagicMock()
        client._client.close = AsyncMock()

        result = await client.__aenter__()
        assert result is client

    async def test_aexit_calls_close(self) -> None:
        """__aexit__ calls close() which calls client.close()."""
        config = _make_llm_config()
        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test123"}):
            client = OpenAIClient(config)
        client._client = MagicMock()
        client._client.close = AsyncMock()

        await client.__aexit__(None, None, None)
        client._client.close.assert_awaited_once()

    async def test_async_with(self) -> None:
        """Client works as an async context manager."""
        config = _make_llm_config()
        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test123"}):
            client = OpenAIClient(config)
        client._client = MagicMock()
        client._client.close = AsyncMock()

        async with client as c:
            assert c is client

        client._client.close.assert_awaited_once()


# ---------------------------------------------------------------------------
# Adversarial / security tests
# ---------------------------------------------------------------------------


class TestOpenAIAdversarial:
    """Adversarial security tests for the OpenAI client."""

    def test_zero_width_space_in_tool_name(self) -> None:
        """Zero-width space in tool name is stripped (display spoofing)."""
        tc = [_make_openai_tool_call("memory\u200b.store", '{"key": "v"}', "call_01")]
        result = _parse_openai_tool_calls(tc)
        assert len(result) == 1
        assert "\u200b" not in result[0].tool

    def test_rtl_override_in_tool_name(self) -> None:
        """RTL override in tool name is stripped."""
        tc = [_make_openai_tool_call("memory\u202e.store\u202d", '{"key": "v"}', "call_01")]
        result = _parse_openai_tool_calls(tc)
        assert len(result) == 1
        assert "\u202e" not in result[0].tool
        assert "\u202d" not in result[0].action

    def test_bom_in_call_id(self) -> None:
        """BOM in call id is stripped."""
        tc = [_make_openai_tool_call("memory.store", '{"key": "v"}', "\ufeffcall_01")]
        result = _parse_openai_tool_calls(tc)
        assert len(result) == 1
        assert "\ufeff" not in (result[0].tool_call_id or "")

    def test_hallucinated_tool_name_rejected(self) -> None:
        """Hallucinated tool name with invalid chars is rejected by Pydantic."""
        tc = [_make_openai_tool_call("FAKE-Tool.hack", "{}", "call_01")]
        result = _parse_openai_tool_calls(tc)
        assert result == []

    def test_oversized_single_value(self) -> None:
        """Single argument value > 2048 chars is rejected."""
        tc = [_make_openai_tool_call("memory.store", json.dumps({"payload": "A" * 2049}), "c1")]
        result = _parse_openai_tool_calls(tc)
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
        tc = [_make_openai_tool_call("memory.store", json.dumps(nested), "call_01")]
        result = _parse_openai_tool_calls(tc)
        assert result == []

    def test_args_at_nesting_limit_accepted(self) -> None:
        """Arguments at exactly depth 3 (within limit 4) are accepted."""
        args: dict[str, Any] = {"a": {"b": {"c": "leaf"}}}
        assert check_args_depth(args, 4) is True
        tc = [_make_openai_tool_call("memory.store", json.dumps(args), "call_01")]
        result = _parse_openai_tool_calls(tc)
        assert len(result) == 1

    def test_json_injection_in_arguments(self) -> None:
        """Arguments containing JSON injection patterns are handled safely."""
        # The JSON string has nested quotes / escape sequences
        malicious = '{"key": "value\\", \\"injected\\": \\"true"}'
        tc = [_make_openai_tool_call("memory.store", malicious, "call_01")]
        # This should either parse and validate, or be rejected as malformed JSON
        result = _parse_openai_tool_calls(tc)
        # Either way, no crash — result is deterministic
        assert isinstance(result, list)

    def test_empty_json_string_arguments(self) -> None:
        """Empty JSON string '{}' parses to empty dict."""
        tc = [_make_openai_tool_call("memory.store", "{}", "call_01")]
        result = _parse_openai_tool_calls(tc)
        assert len(result) == 1
        assert result[0].args == {}

    def test_null_byte_in_json_arguments(self) -> None:
        """Null bytes in JSON argument values don't cause crashes."""
        tc = [_make_openai_tool_call("memory.store", '{"key": "te\\u0000st"}', "call_01")]
        result = _parse_openai_tool_calls(tc)
        assert len(result) == 1
        assert result[0].args["key"] == "te\x00st"


# ---------------------------------------------------------------------------
# Additional security tests for audit findings
# ---------------------------------------------------------------------------


class TestOpenAIC1ControlChars:
    """Tests that C1 control characters are stripped from LLM content."""

    async def test_c1_nel_stripped_from_content(self) -> None:
        """U+0085 (NEL — Next Line) is stripped from response content."""
        config = _make_llm_config()
        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test123"}):
            client = OpenAIClient(config)
        client._client = MagicMock()
        client._client.chat = MagicMock()
        client._client.chat.completions = MagicMock()
        client._client.close = AsyncMock()

        response = _make_completion([_make_choice("Hello\x85World")])
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert "\x85" not in result.content
        assert "HelloWorld" in result.content

    async def test_c1_csi_stripped_from_content(self) -> None:
        """U+009B (CSI — Control Sequence Introducer) is stripped."""
        config = _make_llm_config()
        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test123"}):
            client = OpenAIClient(config)
        client._client = MagicMock()
        client._client.chat = MagicMock()
        client._client.chat.completions = MagicMock()
        client._client.close = AsyncMock()

        response = _make_completion([_make_choice("data\x9b31mred")])
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert "\x9b" not in result.content


class TestOpenAIValidateToolsPayload:
    """Tests that validate_tools_payload is enforced."""

    @pytest.fixture()
    def client(self) -> OpenAIClient:
        """Create an OpenAIClient with a mocked SDK client."""
        config = _make_llm_config()
        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test123"}):
            c = OpenAIClient(config)
        c._client = MagicMock()
        c._client.chat = MagicMock()
        c._client.chat.completions = MagicMock()
        c._client.close = AsyncMock()
        return c

    async def test_oversized_tools_list_raises_llm_error(self, client: OpenAIClient) -> None:
        """Tools list exceeding size limits raises LLMError."""
        from admino.llm import LLMError

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

    async def test_valid_tools_pass_validation(self, client: OpenAIClient) -> None:
        """Normal-sized tools list passes validation and is sent."""
        response = _make_completion()
        client._client.chat.completions.create = AsyncMock(return_value=response)

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

    async def test_max_tokens_sent_in_request(self, client: OpenAIClient) -> None:
        """max_tokens is included in the API request kwargs."""
        response = _make_completion()
        client._client.chat.completions.create = AsyncMock(return_value=response)

        await client.chat(_make_messages())

        call_kwargs = client._client.chat.completions.create.call_args
        assert call_kwargs.kwargs.get("max_tokens") == 4096


# ---------------------------------------------------------------------------
# GH-142: user-facing provider errors
# ---------------------------------------------------------------------------


def _mocked_client(model: str | None = "gpt-4o") -> tuple[OpenAIClient, AsyncMock]:
    """An OpenAIClient whose SDK create() is an AsyncMock returning a text reply."""
    client = OpenAIClient(_make_llm_config(openai_model=model))
    create = AsyncMock(return_value=_make_completion())
    client._client = MagicMock()
    client._client.chat.completions.create = create
    client._client.close = AsyncMock()
    return client, create


class TestOpenAIUserFacingErrors:
    """Setup/availability problems become friendly chat replies (label "OpenAI")."""

    @pytest.mark.parametrize("key", [None, ""], ids=["unset", "empty"])
    async def test_openai_missing_key_chat_user_facing(
        self, monkeypatch: pytest.MonkeyPatch, key: str | None
    ) -> None:
        """No key → "OpenAI isn't configured; set OPENAI_API_KEY", no API call."""
        if key is None:
            monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        else:
            monkeypatch.setenv("OPENAI_API_KEY", key)
        client, create = _mocked_client()

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())

        message = exc_info.value.message
        assert exc_info.value.user_facing is True
        assert exc_info.value.status_code is None
        assert "OpenAI" in message
        assert "isn't configured" in message
        assert "OPENAI_API_KEY" in message
        create.assert_not_awaited()

    @pytest.mark.parametrize("model", [None, ""], ids=["none", "empty"])
    async def test_openai_missing_model_chat_user_facing(
        self, monkeypatch: pytest.MonkeyPatch, model: str | None
    ) -> None:
        """No model → "No OpenAI model is set … ask your administrator", no API call."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test123")
        client, create = _mocked_client(model=model)

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())

        message = exc_info.value.message
        assert exc_info.value.user_facing is True
        assert exc_info.value.status_code is None
        assert "No OpenAI model is set" in message
        assert "ask your administrator" in message
        assert "Settings → Agent" not in message  # GH-159: that section is gone
        create.assert_not_awaited()

    @pytest.mark.parametrize(
        ("cls", "status", "phrases"),
        [
            (openai.AuthenticationError, 401, ("OpenAI", "rejected the API", "OPENAI_API_KEY")),
            (openai.PermissionDeniedError, 403, ("OpenAI", "rejected the API", "OPENAI_API_KEY")),
            (openai.NotFoundError, 404, ("OpenAI", "ask your administrator")),
            (openai.RateLimitError, 429, ("OpenAI", "rate limit")),
            (openai.InternalServerError, 500, ("OpenAI", "temporarily unavailable")),
            (openai.InternalServerError, 502, ("OpenAI", "temporarily unavailable")),
            (openai.InternalServerError, 503, ("OpenAI", "temporarily unavailable")),
        ],
        ids=["401", "403", "404", "429", "500", "502", "503"],
    )
    async def test_openai_status_error_user_facing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        cls: type[Any],
        status: int,
        phrases: tuple[str, ...],
    ) -> None:
        """401/403/404/429/5xx → user-facing fixed message; the body never leaks."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test123")
        client, create = _mocked_client()
        marker = f"OPENAI-BODY-SECRET-{status}"
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
            lambda marker: openai.APITimeoutError(request=_OPENAI_REQUEST),
            lambda marker: openai.APIConnectionError(message=marker, request=_OPENAI_REQUEST),
        ],
        ids=["timeout", "connection"],
    )
    async def test_openai_transport_error_user_facing(
        self, monkeypatch: pytest.MonkeyPatch, make_exc: Any
    ) -> None:
        """Timeout / connection failure → "OpenAI … temporarily unavailable", no cause detail."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test123")
        client, create = _mocked_client()
        marker = "OPENAI-TRANSPORT-SECRET"
        create.side_effect = make_exc(marker)

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())

        assert exc_info.value.user_facing is True
        assert exc_info.value.status_code is None
        assert "OpenAI" in exc_info.value.message
        assert "temporarily unavailable" in exc_info.value.message
        assert marker not in exc_info.value.message

    @pytest.mark.parametrize(
        ("cls", "status"),
        [
            (openai.BadRequestError, 400),
            (openai.APIStatusError, 413),
            (openai.UnprocessableEntityError, 422),
        ],
        ids=["400", "413", "422"],
    )
    async def test_openai_other_4xx_not_user_facing(
        self, monkeypatch: pytest.MonkeyPatch, cls: type[Any], status: int
    ) -> None:
        """Other 4xx stay internal (user_facing False) so the agent shows its generic reply."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test123")
        client, create = _mocked_client()
        create.side_effect = _status_error(cls, status, "detail")

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())

        assert exc_info.value.user_facing is False
        assert exc_info.value.status_code == status

    async def test_openai_oversized_tools_not_user_facing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An oversized tools payload is an internal error."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test123")
        client, _create = _mocked_client()
        tools = [
            {"type": "function", "function": {"name": f"tool.action{i}", "parameters": {}}}
            for i in range(65)
        ]
        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages(), tools=tools)
        assert exc_info.value.user_facing is False
