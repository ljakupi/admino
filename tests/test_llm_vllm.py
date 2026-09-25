"""Tests for the vLLM LLM client module (issue #134).

The ``VLLMClient`` promotes vLLM from a placeholder to a real, first-class
OpenAI-compatible client. It wraps ``openai.AsyncOpenAI`` pointed at a local
served endpoint (``config.vllm_base_url``), reuses the OpenAI conversion helpers
and the shared ``admino.llm`` sanitizers, and uses ``config.vllm_model`` as the
model. Unlike the OpenAI client it needs no API key (a dummy placeholder is
sent), and connection/timeout failures map to a FRIENDLY ``LLMError`` that
tells the user the local model is starting/unavailable.

Mirrors the mocking style of ``tests/test_llm_openai.py`` exactly:
``SimpleNamespace`` fake completions and an ``AsyncMock`` patched onto
``client._client.chat.completions.create``.

GH-142: a missing/empty ``vllm_model`` no longer fails construction; chat()
answers "No vLLM model is set … Settings → Agent" instead. Connection/timeout
failures become user-facing (still "starting or unavailable", now pointing to
``make start-local``), 404/429/5xx map to the user-facing catalogue, and other
4xx (including 401/403 — vLLM has no key) stay internal.

All API calls are mocked — no real OpenAI SDK network call is contacted.
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
from admino.llm_vllm import (
    VLLMClient,
    _convert_messages_to_openai,
    _convert_tools_to_openai,
    _parse_openai_tool_calls,
)
from admino.models import LLMMessage

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VLLM_MODEL = "mlx-community/gemma-4-12B-it-4bit"


def _make_llm_config(
    *,
    vllm_model: str = _VLLM_MODEL,
    vllm_base_url: str = "http://host.docker.internal:8000/v1",
) -> Any:
    """Create a fake LLMConfig for vLLM client testing.

    Mirrors ``_make_llm_config`` in test_llm_openai.py: a SimpleNamespace
    exposing exactly the attributes the client reads.
    """
    return SimpleNamespace(
        vllm_model=vllm_model,
        vllm_base_url=vllm_base_url,
        timeout_s=30,
        max_response_tokens=4096,
    )


def _make_messages(content: str = "Hi") -> list[LLMMessage]:
    """Create a minimal message list for chat calls."""
    return [LLMMessage(role="user", content=content)]


def _make_openai_tool_call(
    name: str = "memory.store",
    arguments: str = '{"key": "test"}',
    call_id: str = "call_abc123",
) -> SimpleNamespace:
    """Create a mock OpenAI-compatible tool call object."""
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
    """Create a mock chat completion choice."""
    return SimpleNamespace(
        message=SimpleNamespace(content=content, tool_calls=tool_calls),
        finish_reason=finish_reason,
    )


def _make_completion(
    choices: list[Any] | None = None,
    model: str = _VLLM_MODEL,
) -> SimpleNamespace:
    """Create a mock chat completion response."""
    if choices is None:
        choices = [_make_choice()]
    return SimpleNamespace(choices=choices, model=model)


def _make_client(config: Any = None) -> VLLMClient:
    """Construct a VLLMClient with a mocked SDK client.

    No API key env var is set — the vLLM client must construct without one.
    """
    if config is None:
        config = _make_llm_config()
    client = VLLMClient(config)
    client._client = MagicMock()
    client._client.chat = MagicMock()
    client._client.chat.completions = MagicMock()
    client._client.close = AsyncMock()
    return client


# ---------------------------------------------------------------------------
# Shared helper reuse (from admino.llm_openai)
# ---------------------------------------------------------------------------


class TestVLLMReusesOpenAIHelpers:
    """The vLLM module re-exports the OpenAI conversion/parse helpers.

    The intended design reuses ``admino.llm_openai``'s helpers verbatim, so
    importing them from ``admino.llm_vllm`` must resolve to the same callables.
    """

    def test_convert_messages_helper_is_openai_helper(self) -> None:
        """_convert_messages_to_openai is the OpenAI helper (same object)."""
        from admino import llm_openai

        assert _convert_messages_to_openai is llm_openai._convert_messages_to_openai

    def test_convert_tools_helper_is_openai_helper(self) -> None:
        """_convert_tools_to_openai is the OpenAI helper (same object)."""
        from admino import llm_openai

        assert _convert_tools_to_openai is llm_openai._convert_tools_to_openai

    def test_parse_tool_calls_helper_is_openai_helper(self) -> None:
        """_parse_openai_tool_calls is the OpenAI helper (same object)."""
        from admino import llm_openai

        assert _parse_openai_tool_calls is llm_openai._parse_openai_tool_calls


# ---------------------------------------------------------------------------
# Client constructor
# ---------------------------------------------------------------------------


class TestVLLMClientConstructor:
    """Tests for VLLMClient.__init__."""

    def test_construction_needs_no_api_key(self) -> None:
        """Client constructs with NO OpenAI/Anthropic API key env var set.

        Unlike OpenAIClient, the vLLM client points at a local endpoint and
        sends a dummy placeholder key, so a cleared environment must still work.
        """
        config = _make_llm_config()
        with patch.dict("os.environ", {}, clear=True):
            client = VLLMClient(config)
        assert client._model == _VLLM_MODEL

    def test_missing_sdk_raises_import_error(self) -> None:
        """Missing openai package raises ImportError with helpful message."""
        config = _make_llm_config()
        with (
            patch.dict("os.environ", {}, clear=True),
            patch.dict("sys.modules", {"openai": None}),
            pytest.raises(ImportError, match="pip install openai"),
        ):
            VLLMClient(config)

    @pytest.mark.parametrize("model", [None, ""], ids=["none", "empty"])
    def test_missing_model_does_not_raise(self, model: str | None) -> None:
        """An unset vllm_model no longer blocks construction (GH-142); chat() explains."""
        config = _make_llm_config(vllm_model=model)  # type: ignore[arg-type]
        client = VLLMClient(config)
        assert isinstance(client, VLLMClient)

    def test_base_url_passed_to_sdk_client(self) -> None:
        """The configured vllm_base_url is passed to AsyncOpenAI(base_url=...)."""
        config = _make_llm_config(vllm_base_url="http://localhost:9001/v1")
        fake_async_openai = MagicMock()
        with (
            patch.dict("os.environ", {}, clear=True),
            patch("openai.AsyncOpenAI", fake_async_openai),
        ):
            VLLMClient(config)
        _, kwargs = fake_async_openai.call_args
        assert kwargs.get("base_url") == "http://localhost:9001/v1"


# ---------------------------------------------------------------------------
# chat() method
# ---------------------------------------------------------------------------


class TestVLLMClientChat:
    """Tests for VLLMClient.chat."""

    @pytest.fixture()
    def client(self) -> VLLMClient:
        """Create a VLLMClient with a mocked SDK client (no API key)."""
        with patch.dict("os.environ", {}, clear=True):
            return _make_client()

    async def test_successful_text_response(self, client: VLLMClient) -> None:
        """Successful response with text content parses to LLMResponse."""
        response = _make_completion()
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())

        assert isinstance(result, LLMResponse)
        assert result.content == "Hello!"
        assert result.tool_calls == []
        assert result.done is True

    async def test_successful_tool_call_response(self, client: VLLMClient) -> None:
        """Response with tool calls parses correctly and done=False."""
        tool_calls = [_make_openai_tool_call("memory.store", '{"key": "k"}', "call_01")]
        choice = _make_choice("I'll store that.", tool_calls, "tool_calls")
        response = _make_completion([choice])
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())

        assert result.content == "I'll store that."
        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].tool == "memory"
        assert result.tool_calls[0].action == "store"
        assert result.tool_calls[0].tool_call_id == "call_01"
        assert result.done is False

    async def test_done_true_when_stop(self, client: VLLMClient) -> None:
        """done=True when finish_reason is 'stop'."""
        choice = _make_choice(finish_reason="stop")
        response = _make_completion([choice])
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert result.done is True

    async def test_done_false_when_tool_calls(self, client: VLLMClient) -> None:
        """done=False when finish_reason is 'tool_calls'."""
        tool_calls = [_make_openai_tool_call()]
        choice = _make_choice("", tool_calls, "tool_calls")
        response = _make_completion([choice])
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert result.done is False

    async def test_empty_choices(self, client: VLLMClient) -> None:
        """Response with no choices returns an empty, done response."""
        response = _make_completion([])
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())

        assert result.content == ""
        assert result.tool_calls == []
        assert result.done is True

    async def test_content_sanitized(self, client: VLLMClient) -> None:
        """Control chars and RTL override in content are stripped."""
        choice = _make_choice("Hello\x00‮World")
        response = _make_completion([choice])
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert result.content == "HelloWorld"

    async def test_c1_nel_stripped_from_content(self, client: VLLMClient) -> None:
        """U+0085 (NEL — Next Line) is stripped from response content."""
        response = _make_completion([_make_choice("Hello\x85World")])
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert "\x85" not in result.content
        assert "HelloWorld" in result.content

    async def test_c1_csi_stripped_from_content(self, client: VLLMClient) -> None:
        """U+009B (CSI — Control Sequence Introducer) is stripped."""
        response = _make_completion([_make_choice("data\x9b31mred")])
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert "\x9b" not in result.content

    async def test_rtl_override_stripped_from_content(self, client: VLLMClient) -> None:
        """RTL override (U+202E) is stripped from response content."""
        response = _make_completion([_make_choice("abc‮def")])
        client._client.chat.completions.create = AsyncMock(return_value=response)

        result = await client.chat(_make_messages())
        assert "‮" not in result.content

    async def test_stream_true_raises_value_error(self, client: VLLMClient) -> None:
        """Passing stream=True raises ValueError (streaming unsupported)."""
        with pytest.raises(ValueError, match=r"[Ss]tream"):
            await client.chat(_make_messages(), stream=True)

    async def test_tools_converted_and_sent(self, client: VLLMClient) -> None:
        """Tools are converted and included in the request."""
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

    async def test_uses_configured_vllm_model(self, client: VLLMClient) -> None:
        """The request model is config.vllm_model, not an OpenAI model id."""
        response = _make_completion()
        client._client.chat.completions.create = AsyncMock(return_value=response)

        await client.chat(_make_messages())

        call_kwargs = client._client.chat.completions.create.call_args.kwargs
        assert call_kwargs.get("model") == _VLLM_MODEL

    async def test_max_tokens_sent_in_request(self, client: VLLMClient) -> None:
        """max_tokens (from config.max_response_tokens) is included in the request."""
        response = _make_completion()
        client._client.chat.completions.create = AsyncMock(return_value=response)

        await client.chat(_make_messages())

        call_kwargs = client._client.chat.completions.create.call_args.kwargs
        assert call_kwargs.get("max_tokens") == 4096


# ---------------------------------------------------------------------------
# Tools payload validation
# ---------------------------------------------------------------------------


class TestVLLMValidateToolsPayload:
    """The shared validate_tools_payload guard is enforced."""

    @pytest.fixture()
    def client(self) -> VLLMClient:
        with patch.dict("os.environ", {}, clear=True):
            return _make_client()

    async def test_oversized_tools_list_raises_llm_error(self, client: VLLMClient) -> None:
        """Tools list exceeding size limits raises LLMError."""
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

    async def test_valid_tools_pass_validation(self, client: VLLMClient) -> None:
        """A normal-sized tools list passes validation and returns a response."""
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


# ---------------------------------------------------------------------------
# Error mapping — the local-serving friendly failure contract
# ---------------------------------------------------------------------------


class TestVLLMErrorMapping:
    """Connection/timeout failures map to a friendly, leak-free LLMError.

    Because the served model is local and may still be starting, an
    unreachable endpoint must surface a friendly message (mentioning the model
    is starting/unavailable), NOT a raw SDK error body. status_code stays None.
    """

    @pytest.fixture()
    def client(self) -> VLLMClient:
        with patch.dict("os.environ", {}, clear=True):
            return _make_client()

    async def test_connection_error_maps_to_friendly_llm_error(self, client: VLLMClient) -> None:
        """openai.APIConnectionError → friendly LLMError, no raw detail leaked."""
        import openai

        client._client.chat.completions.create = AsyncMock(
            side_effect=openai.APIConnectionError(request=MagicMock())
        )

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())

        msg = exc_info.value.message
        assert "unavailable" in msg.lower() or "starting" in msg.lower()
        assert exc_info.value.status_code is None

    async def test_timeout_error_maps_to_friendly_llm_error(self, client: VLLMClient) -> None:
        """openai.APITimeoutError → friendly LLMError, no raw detail leaked."""
        import openai

        client._client.chat.completions.create = AsyncMock(
            side_effect=openai.APITimeoutError(request=MagicMock())
        )

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())

        msg = exc_info.value.message
        assert "unavailable" in msg.lower() or "starting" in msg.lower()
        assert exc_info.value.status_code is None

    async def test_connection_error_does_not_leak_cause_detail(self, client: VLLMClient) -> None:
        """The friendly message must not embed a raw SDK cause/body string."""
        import openai

        secret_marker = "raw-sdk-internal-endpoint-detail"
        client._client.chat.completions.create = AsyncMock(
            side_effect=openai.APIConnectionError(message=secret_marker, request=MagicMock())
        )

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())

        assert secret_marker not in exc_info.value.message


# ---------------------------------------------------------------------------
# Context manager and close
# ---------------------------------------------------------------------------


class TestVLLMContextManager:
    """Tests for async context manager and close (mirrors OpenAI)."""

    async def test_aenter_returns_self(self) -> None:
        """__aenter__ returns the client instance."""
        with patch.dict("os.environ", {}, clear=True):
            client = _make_client()
        result = await client.__aenter__()
        assert result is client

    async def test_aexit_calls_close(self) -> None:
        """__aexit__ calls close() which awaits the SDK client's close()."""
        with patch.dict("os.environ", {}, clear=True):
            client = _make_client()
        await client.__aexit__(None, None, None)
        client._client.close.assert_awaited_once()

    async def test_async_with(self) -> None:
        """Client works as an async context manager and closes on exit."""
        with patch.dict("os.environ", {}, clear=True):
            client = _make_client()
        async with client as c:
            assert c is client
        client._client.close.assert_awaited_once()


# ---------------------------------------------------------------------------
# Adversarial content / tool parsing (reuses shared parser, but assert here)
# ---------------------------------------------------------------------------


class TestVLLMAdversarial:
    """Adversarial parsing checks routed through the vLLM client's parser."""

    def test_hallucinated_tool_name_rejected(self) -> None:
        """Hallucinated tool name with invalid chars is rejected by Pydantic."""
        tc = [_make_openai_tool_call("FAKE-Tool.hack", "{}", "call_01")]
        result = _parse_openai_tool_calls(tc)
        assert result == []

    def test_malformed_json_arguments_rejected(self, caplog: pytest.LogCaptureFixture) -> None:
        """Malformed JSON string in arguments is skipped."""
        tc = [_make_openai_tool_call("memory.store", "not-json{", "call_01")]
        with caplog.at_level(logging.WARNING):
            result = _parse_openai_tool_calls(tc)
        assert result == []

    def test_deep_nesting_rejected(self) -> None:
        """Arguments nested beyond the depth limit are rejected."""
        deep: dict[str, Any] = {"a": "v"}
        for _ in range(6):
            deep = {"a": deep}
        tc = [_make_openai_tool_call("memory.store", json.dumps(deep), "call_01")]
        result = _parse_openai_tool_calls(tc)
        assert result == []

    def test_args_at_nesting_limit_accepted(self) -> None:
        """Arguments at exactly depth 3 (within limit 4) are accepted."""
        args: dict[str, Any] = {"a": {"b": {"c": "leaf"}}}
        assert check_args_depth(args, 4) is True
        tc = [_make_openai_tool_call("memory.store", json.dumps(args), "call_01")]
        result = _parse_openai_tool_calls(tc)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# GH-142: user-facing provider errors
# ---------------------------------------------------------------------------

_VLLM_REQUEST = httpx.Request("POST", "http://vllm:8000/v1/chat/completions")


def _status_error(cls: type[Any], status: int, marker: str) -> Any:
    """Build an openai SDK status error whose body carries a secret marker."""
    body = {"error": {"message": f"upstream detail {marker}", "type": "BadRequestError"}}
    response = httpx.Response(status, request=_VLLM_REQUEST, json=body)
    return cls(f"Error code: {status} - {body}", response=response, body=body)


class TestVLLMUserFacingErrors:
    """Setup/availability problems become friendly chat replies (label "vLLM")."""

    @pytest.fixture()
    def client(self) -> VLLMClient:
        with patch.dict("os.environ", {}, clear=True):
            return _make_client()

    @pytest.mark.parametrize("model", [None, ""], ids=["none", "empty"])
    async def test_vllm_missing_model_chat_user_facing(self, model: str | None) -> None:
        """No model → "No vLLM model is set … Settings → Agent", no API call."""
        client = _make_client(_make_llm_config(vllm_model=model))  # type: ignore[arg-type]
        create = AsyncMock(return_value=_make_completion())
        client._client.chat.completions.create = create

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())

        message = exc_info.value.message
        assert exc_info.value.user_facing is True
        assert exc_info.value.status_code is None
        assert "No vLLM model is set" in message
        assert "Settings → Agent" in message
        create.assert_not_awaited()

    @pytest.mark.parametrize(
        "make_exc",
        [
            lambda marker: openai.APITimeoutError(request=_VLLM_REQUEST),
            lambda marker: openai.APIConnectionError(message=marker, request=_VLLM_REQUEST),
        ],
        ids=["timeout", "connection"],
    )
    async def test_vllm_unreachable_user_facing_points_to_start_local(
        self, client: VLLMClient, make_exc: Any
    ) -> None:
        """Unreachable/starting vLLM → user-facing, "starting"/"unavailable", make start-local."""
        marker = "VLLM-TRANSPORT-SECRET"
        client._client.chat.completions.create = AsyncMock(side_effect=make_exc(marker))

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())

        message = exc_info.value.message
        assert exc_info.value.user_facing is True
        assert exc_info.value.status_code is None
        assert "starting" in message.lower() or "unavailable" in message.lower()
        assert "make start-local" in message
        assert marker not in message

    @pytest.mark.parametrize(
        ("cls", "status", "phrases"),
        [
            (openai.NotFoundError, 404, ("vLLM", "Settings → Agent")),
            (openai.RateLimitError, 429, ("vLLM", "rate limit")),
            (openai.InternalServerError, 500, ("vLLM", "unavailable")),
            (openai.InternalServerError, 503, ("vLLM", "unavailable")),
        ],
        ids=["404", "429", "500", "503"],
    )
    async def test_vllm_status_error_user_facing(
        self,
        client: VLLMClient,
        caplog: pytest.LogCaptureFixture,
        cls: type[Any],
        status: int,
        phrases: tuple[str, ...],
    ) -> None:
        """404/429/5xx → user-facing fixed message; the body never leaks."""
        marker = f"VLLM-BODY-SECRET-{status}"
        client._client.chat.completions.create = AsyncMock(
            side_effect=_status_error(cls, status, marker)
        )

        with caplog.at_level(logging.DEBUG), pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())

        exc = exc_info.value
        assert exc.user_facing is True
        assert exc.status_code == status
        for phrase in phrases:
            if phrase in ("rate limit", "unavailable"):
                assert phrase in exc.message.lower()
            else:
                assert phrase in exc.message
        assert marker not in exc.message
        assert marker not in caplog.text

    @pytest.mark.parametrize(
        ("cls", "status"),
        [
            (openai.BadRequestError, 400),
            (openai.AuthenticationError, 401),
            (openai.PermissionDeniedError, 403),
            (openai.UnprocessableEntityError, 422),
        ],
        ids=["400", "401", "403", "422"],
    )
    async def test_vllm_other_4xx_not_user_facing(
        self, client: VLLMClient, cls: type[Any], status: int
    ) -> None:
        """vLLM has no key, so 401/403 are "other 4xx" too: internal, generic reply."""
        client._client.chat.completions.create = AsyncMock(
            side_effect=_status_error(cls, status, "detail")
        )

        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages())

        assert exc_info.value.user_facing is False
        assert exc_info.value.status_code == status

    async def test_vllm_oversized_tools_not_user_facing(self, client: VLLMClient) -> None:
        """An oversized tools payload is an internal error."""
        tools = [
            {"type": "function", "function": {"name": f"tool.action{i}", "parameters": {}}}
            for i in range(65)
        ]
        with pytest.raises(LLMError) as exc_info:
            await client.chat(_make_messages(), tools=tools)
        assert exc_info.value.user_facing is False
