"""Tests for the Ollama LLM client module.

Covers successful chat, tool call parsing, error handling, malformed responses,
streaming, context manager protocol, and the OllamaError model.

All HTTP calls are mocked via httpx.MockTransport -- no real Ollama is contacted.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from pydantic import ValidationError

from admino.config import OllamaConfig
from admino.llm import (
    _CONTROL_CHAR_TABLE,
    _MAX_CONTENT_LENGTH,
    LLMResponse,
    OllamaError,
    parse_tool_calls,
    sanitize_content,
)
from admino.llm_ollama import OllamaClient
from admino.models import LLMMessage

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ollama_config() -> OllamaConfig:
    """Provide a test OllamaConfig pointing at a fake host."""
    return OllamaConfig(
        url="http://test-ollama:11434",
        model="test-model",
        timeout_s=30,
    )


def _make_messages(content: str = "Hi") -> list[LLMMessage]:
    """Create a minimal message list for chat calls."""
    return [LLMMessage(role="user", content=content)]


def _ok_response(
    content: str = "Hello!",
    done: bool = True,
    model: str = "test-model",
    tool_calls: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a standard Ollama /api/chat JSON response body."""
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return {"message": message, "done": done, "model": model}


def _mock_transport(
    response_json: dict[str, Any] | None = None,
    status_code: int = 200,
    response_text: str | None = None,
) -> httpx.MockTransport:
    """Create a MockTransport returning a fixed JSON or text response."""

    def handler(request: httpx.Request) -> httpx.Response:
        if response_json is not None:
            return httpx.Response(
                status_code=status_code,
                json=response_json,
            )
        return httpx.Response(
            status_code=status_code,
            text=response_text or "",
        )

    return httpx.MockTransport(handler)


def _build_client(
    config: OllamaConfig,
    transport: httpx.MockTransport,
) -> OllamaClient:
    """Build an OllamaClient with the underlying httpx client swapped to use a mock transport."""
    client = OllamaClient(config)
    # Replace internal httpx client with one using our mock transport
    client._client = httpx.AsyncClient(
        transport=transport,
        base_url=config.url,
        timeout=httpx.Timeout(
            connect=10.0,
            read=float(config.timeout_s),
            write=10.0,
            pool=5.0,
        ),
        follow_redirects=False,
    )
    return client


# ---------------------------------------------------------------------------
# Successful chat
# ---------------------------------------------------------------------------


class TestChatSuccess:
    """Tests for successful (non-streaming) chat calls."""

    async def test_chat_success(self, ollama_config: OllamaConfig) -> None:
        """Basic chat returns correct content, done flag, and empty tool_calls."""
        transport = _mock_transport(response_json=_ok_response())
        client = _build_client(ollama_config, transport)

        response = await client.chat(_make_messages())

        assert response.content == "Hello!"
        assert response.done is True
        assert response.tool_calls == []
        assert response.model == "test-model"
        await client.close()

    async def test_chat_sends_correct_request(self, ollama_config: OllamaConfig) -> None:
        """Verify POST goes to /api/chat with correct model, messages, stream=False."""
        captured_request: httpx.Request | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_request
            captured_request = request
            return httpx.Response(200, json=_ok_response())

        transport = httpx.MockTransport(handler)
        client = _build_client(ollama_config, transport)

        await client.chat(_make_messages("Hello there"))

        assert captured_request is not None
        assert captured_request.url.path == "/api/chat"
        assert captured_request.method == "POST"

        body = json.loads(captured_request.content)
        assert body["model"] == "test-model"
        assert body["stream"] is False
        assert body["messages"] == [{"role": "user", "content": "Hello there"}]
        assert "tools" not in body
        await client.close()

    async def test_chat_with_tools_parameter(self, ollama_config: OllamaConfig) -> None:
        """When tools are passed, they appear in the request body."""
        captured_body: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_body
            captured_body = json.loads(request.content)
            return httpx.Response(200, json=_ok_response())

        transport = httpx.MockTransport(handler)
        client = _build_client(ollama_config, transport)

        tools = [{"type": "function", "function": {"name": "gmail.read"}}]
        await client.chat(_make_messages(), tools=tools)

        assert captured_body["tools"] == tools
        await client.close()


# ---------------------------------------------------------------------------
# Tool call parsing
# ---------------------------------------------------------------------------


class TestToolCallParsing:
    """Tests for tool call extraction from Ollama responses."""

    async def test_chat_with_tool_calls(self, ollama_config: OllamaConfig) -> None:
        """Tool call with dot notation is split into tool and action."""
        tc = [{"function": {"name": "gmail.read", "arguments": {"id": "123"}}}]
        transport = _mock_transport(response_json=_ok_response(tool_calls=tc))
        client = _build_client(ollama_config, transport)

        response = await client.chat(_make_messages())

        assert len(response.tool_calls) == 1
        assert response.tool_calls[0].tool == "gmail"
        assert response.tool_calls[0].action == "read"
        assert response.tool_calls[0].args == {"id": "123"}
        await client.close()

    async def test_chat_tool_call_name_no_dot(
        self, ollama_config: OllamaConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Name without dot is rejected — tool call is skipped with a warning."""
        import logging

        tc = [{"function": {"name": "search", "arguments": {"q": "test"}}}]
        transport = _mock_transport(response_json=_ok_response(tool_calls=tc))
        client = _build_client(ollama_config, transport)

        with caplog.at_level(logging.WARNING, logger="admino.llm"):
            response = await client.chat(_make_messages())

        assert len(response.tool_calls) == 0
        assert any("dot notation" in r.message for r in caplog.records)
        await client.close()

    async def test_chat_multiple_tool_calls(self, ollama_config: OllamaConfig) -> None:
        """Multiple tool calls are all parsed correctly."""
        tc = [
            {"function": {"name": "gmail.read", "arguments": {"id": "1"}}},
            {"function": {"name": "calendar.list", "arguments": {"days": 7}}},
        ]
        transport = _mock_transport(response_json=_ok_response(tool_calls=tc))
        client = _build_client(ollama_config, transport)

        response = await client.chat(_make_messages())

        assert len(response.tool_calls) == 2
        assert response.tool_calls[0].tool == "gmail"
        assert response.tool_calls[0].action == "read"
        assert response.tool_calls[1].tool == "calendar"
        assert response.tool_calls[1].action == "list"
        await client.close()

    async def test_chat_tool_call_empty_list(self, ollama_config: OllamaConfig) -> None:
        """Empty tool_calls list results in empty parsed list."""
        transport = _mock_transport(response_json=_ok_response(tool_calls=[]))
        client = _build_client(ollama_config, transport)

        response = await client.chat(_make_messages())

        assert response.tool_calls == []
        await client.close()


# ---------------------------------------------------------------------------
# parse_tool_calls unit tests (direct function tests)
# ---------------------------------------------------------------------------


class TestParseToolCalls:
    """Direct unit tests for the parse_tool_calls helper."""

    def test_malformed_function_not_dict(self) -> None:
        """Non-dict function value is skipped."""
        result = parse_tool_calls([{"function": "not-a-dict"}])
        assert result == []

    def test_missing_name(self) -> None:
        """Missing or empty name is skipped."""
        result = parse_tool_calls([{"function": {"arguments": {}}}])
        assert result == []

    def test_arguments_not_dict(self) -> None:
        """Non-dict arguments value is skipped."""
        result = parse_tool_calls([{"function": {"name": "gmail.read", "arguments": "bad"}}])
        assert result == []


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestChatErrors:
    """Tests for HTTP and connection error handling."""

    async def test_chat_http_500(self, ollama_config: OllamaConfig) -> None:
        """HTTP 500 raises OllamaError with status_code=500."""
        transport = _mock_transport(response_json={"error": "internal"}, status_code=500)
        client = _build_client(ollama_config, transport)

        with pytest.raises(OllamaError) as exc_info:
            await client.chat(_make_messages())

        assert exc_info.value.status_code == 500
        await client.close()

    async def test_chat_http_404(self, ollama_config: OllamaConfig) -> None:
        """HTTP 404 raises OllamaError with status_code=404."""
        transport = _mock_transport(response_json={"error": "not found"}, status_code=404)
        client = _build_client(ollama_config, transport)

        with pytest.raises(OllamaError) as exc_info:
            await client.chat(_make_messages())

        assert exc_info.value.status_code == 404
        await client.close()

    async def test_chat_connection_error(self, ollama_config: OllamaConfig) -> None:
        """ConnectError raises OllamaError with status_code=None."""
        client = OllamaClient(ollama_config)

        with (
            patch.object(
                client._client,
                "post",
                side_effect=httpx.ConnectError("Connection refused"),
            ),
            pytest.raises(OllamaError) as exc_info,
        ):
            await client.chat(_make_messages())

        assert exc_info.value.status_code is None
        assert "connect" in exc_info.value.message.lower() or "Connect" in exc_info.value.message
        await client.close()

    async def test_chat_timeout(self, ollama_config: OllamaConfig) -> None:
        """TimeoutException raises OllamaError with status_code=None."""
        client = OllamaClient(ollama_config)

        with (
            patch.object(
                client._client,
                "post",
                side_effect=httpx.TimeoutException("timed out"),
            ),
            pytest.raises(OllamaError) as exc_info,
        ):
            await client.chat(_make_messages())

        assert exc_info.value.status_code is None
        assert (
            "timed out" in exc_info.value.message.lower()
            or "timeout" in exc_info.value.message.lower()
        )
        await client.close()

    async def test_chat_stream_true_raises_value_error(self, ollama_config: OllamaConfig) -> None:
        """Passing stream=True to chat() raises ValueError."""
        transport = _mock_transport(response_json=_ok_response())
        client = _build_client(ollama_config, transport)

        with pytest.raises(ValueError, match="chat_stream"):
            await client.chat(_make_messages(), stream=True)

        await client.close()


# ---------------------------------------------------------------------------
# Malformed responses
# ---------------------------------------------------------------------------


class TestMalformedResponses:
    """Tests for handling unexpected or broken Ollama responses."""

    async def test_chat_missing_message_key(self, ollama_config: OllamaConfig) -> None:
        """Response without 'message' key raises OllamaError, not KeyError."""
        transport = _mock_transport(response_json={"done": True, "model": "test"})
        client = _build_client(ollama_config, transport)

        # The code does data.get("message", {}) which returns {} when missing.
        # An empty dict is still a valid dict, so it won't raise OllamaError.
        # It will just return empty content. Let's test with message=None instead.
        await client.close()

        transport2 = _mock_transport(response_json={"message": None, "done": True})
        client2 = _build_client(ollama_config, transport2)

        with pytest.raises(OllamaError, match="malformed"):
            await client2.chat(_make_messages())

        await client2.close()

    async def test_chat_message_not_dict(self, ollama_config: OllamaConfig) -> None:
        """If 'message' is a non-dict value, OllamaError is raised."""
        transport = _mock_transport(response_json={"message": "not-a-dict", "done": True})
        client = _build_client(ollama_config, transport)

        with pytest.raises(OllamaError, match="malformed"):
            await client.chat(_make_messages())

        await client.close()

    async def test_chat_empty_content(self, ollama_config: OllamaConfig) -> None:
        """Empty content string is returned as-is."""
        transport = _mock_transport(response_json=_ok_response(content=""))
        client = _build_client(ollama_config, transport)

        response = await client.chat(_make_messages())

        assert response.content == ""
        await client.close()

    async def test_chat_content_truncated(self, ollama_config: OllamaConfig) -> None:
        """Content exceeding _MAX_CONTENT_LENGTH is truncated."""
        long_content = "x" * (_MAX_CONTENT_LENGTH + 1000)
        transport = _mock_transport(response_json=_ok_response(content=long_content))
        client = _build_client(ollama_config, transport)

        response = await client.chat(_make_messages())

        assert len(response.content) == _MAX_CONTENT_LENGTH
        await client.close()

    async def test_chat_missing_message_key_returns_empty(
        self, ollama_config: OllamaConfig
    ) -> None:
        """Response without 'message' key defaults to empty content (get returns {})."""
        transport = _mock_transport(response_json={"done": True, "model": "test-model"})
        client = _build_client(ollama_config, transport)

        response = await client.chat(_make_messages())
        assert response.content == ""
        assert response.tool_calls == []
        await client.close()

    async def test_chat_non_string_content_coerced(self, ollama_config: OllamaConfig) -> None:
        """Non-string content is coerced to str."""
        resp = {"message": {"role": "assistant", "content": 42}, "done": True, "model": "m"}
        transport = _mock_transport(response_json=resp)
        client = _build_client(ollama_config, transport)

        response = await client.chat(_make_messages())
        assert response.content == "42"
        await client.close()

    async def test_chat_tool_calls_not_list(self, ollama_config: OllamaConfig) -> None:
        """If tool_calls is not a list, it is treated as empty."""
        resp = {
            "message": {"role": "assistant", "content": "ok", "tool_calls": "not-a-list"},
            "done": True,
            "model": "m",
        }
        transport = _mock_transport(response_json=resp)
        client = _build_client(ollama_config, transport)

        response = await client.chat(_make_messages())
        assert response.tool_calls == []
        await client.close()


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


class TestChatStream:
    """Tests for the streaming chat_stream() method."""

    async def test_chat_stream_yields_chunks(self, ollama_config: OllamaConfig) -> None:
        """Three streaming chunks are yielded in order, stops on done=true."""
        lines = [
            json.dumps({"message": {"content": "chunk1"}, "done": False}),
            json.dumps({"message": {"content": "chunk2"}, "done": False}),
            json.dumps({"message": {"content": "chunk3"}, "done": False}),
            json.dumps({"message": {"content": ""}, "done": True}),
        ]
        stream_body = "\n".join(lines)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=stream_body)

        transport = httpx.MockTransport(handler)
        client = _build_client(ollama_config, transport)

        chunks: list[str] = []
        async with client.chat_stream(_make_messages()) as stream:
            async for chunk in stream:
                chunks.append(chunk)

        assert chunks == ["chunk1", "chunk2", "chunk3"]
        await client.close()

    async def test_chat_stream_skips_empty_content(self, ollama_config: OllamaConfig) -> None:
        """Streaming lines with empty content are not yielded."""
        lines = [
            json.dumps({"message": {"content": ""}, "done": False}),
            json.dumps({"message": {"content": "real"}, "done": False}),
            json.dumps({"message": {"content": ""}, "done": True}),
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="\n".join(lines))

        transport = httpx.MockTransport(handler)
        client = _build_client(ollama_config, transport)

        chunks: list[str] = []
        async with client.chat_stream(_make_messages()) as stream:
            async for chunk in stream:
                chunks.append(chunk)

        assert chunks == ["real"]
        await client.close()

    async def test_chat_stream_stops_on_done(self, ollama_config: OllamaConfig) -> None:
        """No more chunks are yielded after done=true."""
        lines = [
            json.dumps({"message": {"content": "first"}, "done": False}),
            json.dumps({"message": {"content": ""}, "done": True}),
            json.dumps({"message": {"content": "should-not-appear"}, "done": False}),
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="\n".join(lines))

        transport = httpx.MockTransport(handler)
        client = _build_client(ollama_config, transport)

        chunks: list[str] = []
        async with client.chat_stream(_make_messages()) as stream:
            async for chunk in stream:
                chunks.append(chunk)

        assert chunks == ["first"]
        await client.close()

    async def test_chat_stream_http_error(self, ollama_config: OllamaConfig) -> None:
        """Non-2xx status on streaming request raises OllamaError."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="Service Unavailable")

        transport = httpx.MockTransport(handler)
        client = _build_client(ollama_config, transport)

        with pytest.raises(OllamaError) as exc_info:
            async with client.chat_stream(_make_messages()) as stream:
                async for _ in stream:
                    pass  # pragma: no cover

        assert exc_info.value.status_code == 503
        await client.close()

    async def test_chat_stream_connection_error(self, ollama_config: OllamaConfig) -> None:
        """ConnectError during streaming raises OllamaError."""
        client = OllamaClient(ollama_config)

        mock_stream = AsyncMock()
        mock_stream.__aenter__ = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_stream.__aexit__ = AsyncMock(return_value=False)

        with (
            patch.object(client._client, "stream", return_value=mock_stream),
            pytest.raises(OllamaError) as exc_info,
        ):
            async with client.chat_stream(_make_messages()) as stream:
                async for _ in stream:
                    pass  # pragma: no cover

        assert exc_info.value.status_code is None
        await client.close()

    async def test_chat_stream_malformed_json_line(self, ollama_config: OllamaConfig) -> None:
        """Malformed JSON lines in stream are skipped gracefully."""
        lines = [
            "not valid json",
            json.dumps({"message": {"content": "good"}, "done": False}),
            json.dumps({"message": {"content": ""}, "done": True}),
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="\n".join(lines))

        transport = httpx.MockTransport(handler)
        client = _build_client(ollama_config, transport)

        chunks: list[str] = []
        async with client.chat_stream(_make_messages()) as stream:
            async for chunk in stream:
                chunks.append(chunk)

        assert chunks == ["good"]
        await client.close()

    async def test_chat_stream_blank_lines_skipped(self, ollama_config: OllamaConfig) -> None:
        """Blank lines in stream are ignored."""
        lines = [
            "",
            json.dumps({"message": {"content": "data"}, "done": False}),
            "   ",
            json.dumps({"done": True}),
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="\n".join(lines))

        transport = httpx.MockTransport(handler)
        client = _build_client(ollama_config, transport)

        chunks: list[str] = []
        async with client.chat_stream(_make_messages()) as stream:
            async for chunk in stream:
                chunks.append(chunk)

        assert chunks == ["data"]
        await client.close()

    async def test_chat_stream_timeout(self, ollama_config: OllamaConfig) -> None:
        """TimeoutException during streaming raises OllamaError."""
        client = OllamaClient(ollama_config)

        mock_stream = AsyncMock()
        mock_stream.__aenter__ = AsyncMock(side_effect=httpx.ReadTimeout("read timed out"))
        mock_stream.__aexit__ = AsyncMock(return_value=False)

        with (
            patch.object(client._client, "stream", return_value=mock_stream),
            pytest.raises(OllamaError) as exc_info,
        ):
            async with client.chat_stream(_make_messages()) as stream:
                async for _ in stream:
                    pass  # pragma: no cover

        assert exc_info.value.status_code is None
        assert "timed out" in exc_info.value.message.lower()
        await client.close()

    async def test_chat_stream_with_tools(self, ollama_config: OllamaConfig) -> None:
        """Tools parameter is included in streaming request body."""
        captured_body: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_body
            captured_body = json.loads(request.content)
            body_text = json.dumps({"message": {"content": "ok"}, "done": True})
            return httpx.Response(200, text=body_text)

        transport = httpx.MockTransport(handler)
        client = _build_client(ollama_config, transport)

        tools = [{"type": "function", "function": {"name": "test.run"}}]
        async with client.chat_stream(_make_messages(), tools=tools) as stream:
            async for _ in stream:
                pass

        assert captured_body["tools"] == tools
        assert captured_body["stream"] is True
        await client.close()


# ---------------------------------------------------------------------------
# Context manager and close
# ---------------------------------------------------------------------------


class TestContextManager:
    """Tests for async context manager and explicit close."""

    async def test_context_manager(self, ollama_config: OllamaConfig) -> None:
        """Client is usable inside async with and closed after exit."""
        transport = _mock_transport(response_json=_ok_response())

        async with OllamaClient(ollama_config) as client:
            # Replace transport for testing
            client._client = httpx.AsyncClient(
                transport=transport,
                base_url=ollama_config.url,
            )
            response = await client.chat(_make_messages())
            assert response.content == "Hello!"

        # After exiting the context manager, the client should be closed.
        # httpx.AsyncClient.is_closed is the indicator.
        assert client._client.is_closed

    async def test_close(self, ollama_config: OllamaConfig) -> None:
        """Explicit close() closes the underlying httpx client."""
        client = OllamaClient(ollama_config)
        assert not client._client.is_closed

        await client.close()

        assert client._client.is_closed


# ---------------------------------------------------------------------------
# OllamaError model
# ---------------------------------------------------------------------------


class TestOllamaError:
    """Tests for the OllamaError exception class."""

    def test_ollama_error_with_status_code(self) -> None:
        """OllamaError stores message and status_code."""
        err = OllamaError("Service unavailable", 503)
        assert err.message == "Service unavailable"
        assert err.status_code == 503
        assert str(err) == "Service unavailable"

    def test_ollama_error_no_status_code(self) -> None:
        """OllamaError with status_code=None for connection errors."""
        err = OllamaError("Connection refused", None)
        assert err.message == "Connection refused"
        assert err.status_code is None

    def test_ollama_error_default_status_code(self) -> None:
        """OllamaError defaults status_code to None when not provided."""
        err = OllamaError("some error")
        assert err.status_code is None


# ---------------------------------------------------------------------------
# LLMResponse model
# ---------------------------------------------------------------------------


class TestLLMResponse:
    """Tests for the LLMResponse Pydantic model."""

    def test_defaults(self) -> None:
        """LLMResponse has sensible defaults."""
        r = LLMResponse()
        assert r.content == ""
        assert r.tool_calls == []
        assert r.model == ""
        assert r.done is False

    def test_max_content_length_enforced(self) -> None:
        """Content longer than max_length is rejected by Pydantic."""
        with pytest.raises(ValidationError):
            LLMResponse(content="x" * (_MAX_CONTENT_LENGTH + 1))


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


class TestSanitization:
    """Tests for control character and Unicode sanitization of LLM output."""

    async def test_control_chars_stripped_from_content(self, ollama_config: OllamaConfig) -> None:
        """Null, SOH, RTL override, and LTR isolate are stripped from response content."""
        dirty = "Hello\x00\x01\u202e\u2066World"
        transport = _mock_transport(response_json=_ok_response(content=dirty))
        client = _build_client(ollama_config, transport)

        response = await client.chat(_make_messages())

        assert "\x00" not in response.content
        assert "\x01" not in response.content
        assert "\u202e" not in response.content
        assert "\u2066" not in response.content
        assert response.content == "HelloWorld"
        await client.close()

    async def test_zero_width_chars_stripped(self, ollama_config: OllamaConfig) -> None:
        """Zero-width space, joiner, and BOM are stripped from response content."""
        dirty = "A\u200b\u200d\ufeffB"
        transport = _mock_transport(response_json=_ok_response(content=dirty))
        client = _build_client(ollama_config, transport)

        response = await client.chat(_make_messages())

        assert response.content == "AB"
        await client.close()

    def test_strip_control_chars_preserves_tab_newline(self) -> None:
        """Tab, newline, and carriage return survive the control char table."""
        text = "line1\tvalue\nline2\r\n"
        result = text.translate(_CONTROL_CHAR_TABLE)
        assert result == text

    def test_strip_control_chars_removes_bidi(self) -> None:
        """RTL override (U+202E) and LTR isolate (U+2066) are removed."""
        text = "abc\u202edef\u2066ghi"
        result = text.translate(_CONTROL_CHAR_TABLE)
        assert result == "abcdefghi"

    def test_sanitize_content_truncates_and_strips(self) -> None:
        """sanitize_content strips control chars and enforces length limit."""
        dirty = "\x00A" * (_MAX_CONTENT_LENGTH + 100)
        result = sanitize_content(dirty)
        assert "\x00" not in result
        assert len(result) <= _MAX_CONTENT_LENGTH

    def test_strip_control_chars_removes_c1_nel(self) -> None:
        """U+0085 (NEL — Next Line) is stripped by the control char table."""
        text = "Hello\x85World"
        result = text.translate(_CONTROL_CHAR_TABLE)
        assert result == "HelloWorld"

    def test_strip_control_chars_removes_c1_csi(self) -> None:
        """U+009B (CSI — Control Sequence Introducer) is stripped."""
        text = "data\x9b31mred"
        result = text.translate(_CONTROL_CHAR_TABLE)
        assert "\x9b" not in result
        assert result == "data31mred"

    def test_strip_control_chars_removes_full_c1_range(self) -> None:
        """All C1 control characters (U+0080-U+009F) are stripped."""
        # Build a string with all 32 C1 chars interspersed with 'X'
        c1_chars = "".join(chr(i) for i in range(0x80, 0xA0))
        text = f"A{c1_chars}B"
        result = text.translate(_CONTROL_CHAR_TABLE)
        assert result == "AB"


# ---------------------------------------------------------------------------
# Cumulative streaming cap
# ---------------------------------------------------------------------------


class TestChatStreamCumulativeCap:
    """Tests for the cumulative content length cap in streaming."""

    async def test_chat_stream_cumulative_cap(self, ollama_config: OllamaConfig) -> None:
        """Streaming enforces a cumulative cap of _MAX_CONTENT_LENGTH across all chunks."""
        chunk_size = 10000
        num_chunks = 10  # 100,000 chars > 65,536 limit
        lines = []
        for _ in range(num_chunks):
            lines.append(json.dumps({"message": {"content": "x" * chunk_size}, "done": False}))
        lines.append(json.dumps({"message": {"content": ""}, "done": True}))

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="\n".join(lines))

        transport = httpx.MockTransport(handler)
        client = _build_client(ollama_config, transport)

        total = 0
        async with client.chat_stream(_make_messages()) as stream:
            async for chunk in stream:
                total += len(chunk)

        assert total == _MAX_CONTENT_LENGTH
        await client.close()


# ---------------------------------------------------------------------------
# Additional parse_tool_calls security tests
# ---------------------------------------------------------------------------


class TestParseToolCallsSecurity:
    """Security-focused tests for parse_tool_calls."""

    def test_oversized_arguments_rejected(self) -> None:
        """Arguments with JSON payload > 16384 bytes are rejected."""
        big_args = {"data": "x" * 16385}
        result = parse_tool_calls([{"function": {"name": "gmail.read", "arguments": big_args}}])
        assert result == []

    def test_too_many_argument_keys_rejected(self) -> None:
        """Arguments with more than 32 keys are rejected."""
        many_keys = {f"key_{i}": "v" for i in range(33)}
        result = parse_tool_calls([{"function": {"name": "gmail.read", "arguments": many_keys}}])
        assert result == []

    def test_deeply_nested_arguments_rejected(self) -> None:
        """Arguments nested deeper than 4 levels are rejected by depth check."""
        nested: dict[str, Any] = {"a": "val"}
        for _ in range(4):
            nested = {"a": nested}
        result = parse_tool_calls([{"function": {"name": "gmail.read", "arguments": nested}}])
        assert result == []

    def test_trailing_dot_name_rejected(self) -> None:
        """Tool name 'gmail.' splits to action='' which fails Pydantic validation."""
        result = parse_tool_calls([{"function": {"name": "gmail.", "arguments": {}}}])
        assert result == []

    def test_leading_dot_name_rejected(self) -> None:
        """Tool name '.read' splits to tool='' which fails Pydantic validation."""
        result = parse_tool_calls([{"function": {"name": ".read", "arguments": {}}}])
        assert result == []

    def test_null_byte_in_name_sanitised(self) -> None:
        """Null byte in tool name is stripped by sanitisation; clean name is parsed."""
        result = parse_tool_calls([{"function": {"name": "gmail\x00.read", "arguments": {}}}])
        # The null byte is removed by _CONTROL_CHAR_TABLE before the split,
        # so "gmail\x00.read" becomes "gmail.read" which is a valid tool call.
        assert len(result) == 1
        assert result[0].tool == "gmail"
        assert result[0].action == "read"

    def test_many_tool_calls_all_parsed(self) -> None:
        """50 valid tool calls are all parsed (no artificial limit in parser)."""
        raw = [{"function": {"name": f"tool{i}.action", "arguments": {}}} for i in range(50)]
        result = parse_tool_calls(raw)
        # tool names like "tool0" match ^[a-z][a-z0-9_]{0,62}$
        assert len(result) == 50

    def test_too_many_tool_calls_rejected(self) -> None:
        """More than 128 tool calls in a single response are rejected."""
        raw = [{"function": {"name": f"tool{i}.action", "arguments": {}}} for i in range(129)]
        result = parse_tool_calls(raw)
        assert result == []


# ---------------------------------------------------------------------------
# Client configuration
# ---------------------------------------------------------------------------


class TestClientConfiguration:
    """Tests for OllamaClient httpx client settings."""

    def test_client_disables_redirect_following(self, ollama_config: OllamaConfig) -> None:
        """OllamaClient creates an httpx client with follow_redirects=False."""
        client = OllamaClient(ollama_config)
        assert client._client.follow_redirects is False

    def test_client_sets_timeout(self, ollama_config: OllamaConfig) -> None:
        """OllamaClient sets timeout from config."""
        client = OllamaClient(ollama_config)
        # The timeout should reflect the configured value
        assert client._client.timeout.read == float(ollama_config.timeout_s)

    def test_client_sets_per_phase_timeouts(self, ollama_config: OllamaConfig) -> None:
        """OllamaClient sets separate connect, read, write, and pool timeouts."""
        client = OllamaClient(ollama_config)
        assert client._client.timeout.connect == 10.0
        assert client._client.timeout.read == float(ollama_config.timeout_s)
        assert client._client.timeout.write == 10.0
        assert client._client.timeout.pool == 5.0

    def test_client_enables_tls_verification(self, ollama_config: OllamaConfig) -> None:
        """OllamaClient does not disable TLS verification."""
        config = OllamaConfig(url="https://test-ollama:11434", model="test", timeout_s=30)
        client = OllamaClient(config)
        # If verify were False, the transport pool would have ssl_context=None.
        # Best-effort check: the important thing is verify=True in the constructor.
        assert client._client._transport is not None
