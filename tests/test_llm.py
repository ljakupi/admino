"""Tests for the shared llm.py utilities and the provider factory.

Covers tool-call parsing, content sanitization, argument-depth and tools-payload
guards, the LLMResponse / LLMUsage / LLMStreamDelta models, LLMError (including
the GH-142 ``user_facing`` flag), and create_llm_client provider selection —
including the default ``infomaniak`` provider, which must build without any
network I/O or credentials. Provider-specific client behaviour lives in
test_llm_infomaniak.py, test_llm_anthropic.py, test_llm_openai.py and
test_llm_vllm.py.

The GH-142 symbols (``LLMUsage``, ``LLMStreamDelta``, ``admino.llm_infomaniak``)
are reached through module attributes / local imports so this module keeps
collecting before they exist (each such test fails on its own).
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from pydantic import ValidationError

import admino.llm as llm_mod
from admino.config import LLMConfig
from admino.llm import (
    _MAX_CONTENT_LENGTH,
    _MAX_TOOLS_COUNT,
    _MAX_TOOLS_PAYLOAD,
    LLMError,
    LLMResponse,
    check_args_depth,
    create_llm_client,
    parse_tool_calls,
    sanitize_content,
    strip_control_chars,
    validate_tools_payload,
)
from admino.llm_anthropic import AnthropicClient
from admino.llm_openai import OpenAIClient
from admino.llm_vllm import VLLMClient

# ---------------------------------------------------------------------------
# parse_tool_calls
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
        # The null byte is removed before the split, so "gmail\x00.read"
        # becomes "gmail.read" which is a valid tool call.
        assert len(result) == 1
        assert result[0].tool == "gmail"
        assert result[0].action == "read"

    def test_many_tool_calls_all_parsed(self) -> None:
        """50 valid tool calls are all parsed (no artificial limit in parser)."""
        raw = [{"function": {"name": f"tool{i}.action", "arguments": {}}} for i in range(50)]
        result = parse_tool_calls(raw)
        assert len(result) == 50

    def test_too_many_tool_calls_rejected(self) -> None:
        """More than 128 tool calls in a single response are rejected."""
        raw = [{"function": {"name": f"tool{i}.action", "arguments": {}}} for i in range(129)]
        result = parse_tool_calls(raw)
        assert result == []


# ---------------------------------------------------------------------------
# check_args_depth
# ---------------------------------------------------------------------------


class TestCheckArgsDepth:
    """Tests for the recursive argument nesting-depth guard."""

    def test_within_limit(self) -> None:
        """A structure within the depth limit passes."""
        assert check_args_depth({"a": {"b": {"c": 1}}}, limit=4) is True

    def test_exceeds_limit_via_dict(self) -> None:
        """Dict nesting deeper than the limit fails."""
        assert check_args_depth({"a": {"b": {"c": {"d": 1}}}}, limit=2) is False

    def test_exceeds_limit_via_list(self) -> None:
        """List nesting deeper than the limit fails."""
        assert check_args_depth([[[1]]], limit=2) is False

    def test_list_within_limit(self) -> None:
        """A flat list within the limit passes."""
        assert check_args_depth([1, 2, 3], limit=2) is True

    def test_zero_limit_is_false(self) -> None:
        """A non-positive limit always fails."""
        assert check_args_depth("x", limit=0) is False


# ---------------------------------------------------------------------------
# validate_tools_payload
# ---------------------------------------------------------------------------


class TestValidateToolsPayload:
    """Tests for the tools-payload size guard."""

    def test_valid_payload_passes(self) -> None:
        """A small tools list does not raise."""
        validate_tools_payload([{"type": "function", "function": {"name": "gmail.read"}}])

    def test_too_many_tools_rejected(self) -> None:
        """More tools than the count limit raises ValueError."""
        tools = [{"type": "function"} for _ in range(_MAX_TOOLS_COUNT + 1)]
        with pytest.raises(ValueError, match="exceeds size limits"):
            validate_tools_payload(tools)

    def test_oversized_payload_rejected(self) -> None:
        """A tools payload larger than the byte limit raises ValueError."""
        tools = [{"blob": "a" * (_MAX_TOOLS_PAYLOAD + 1)}]
        with pytest.raises(ValueError, match="exceeds size limits"):
            validate_tools_payload(tools)


# ---------------------------------------------------------------------------
# Content sanitization
# ---------------------------------------------------------------------------


class TestSanitization:
    """Tests for control character and Unicode sanitization of LLM output."""

    def test_control_chars_stripped(self) -> None:
        """Null, SOH, RTL override, and LTR isolate are stripped from content."""
        assert sanitize_content("Hello\x00\x01‮⁦World") == "HelloWorld"

    def test_zero_width_chars_stripped(self) -> None:
        """Zero-width space, joiner, and BOM are stripped from content."""
        assert sanitize_content("A​‍﻿B") == "AB"

    def test_strip_control_chars_preserves_tab_newline(self) -> None:
        """Tab, newline, and carriage return survive sanitisation."""
        text = "line1\tvalue\nline2\r\n"
        assert strip_control_chars(text) == text

    def test_strip_control_chars_removes_bidi(self) -> None:
        """RTL override (U+202E) and LTR isolate (U+2066) are removed."""
        assert strip_control_chars("abc‮def⁦ghi") == "abcdefghi"

    def test_sanitize_content_truncates_and_strips(self) -> None:
        """sanitize_content strips control chars and enforces the length limit."""
        dirty = "\x00A" * (_MAX_CONTENT_LENGTH + 100)
        result = sanitize_content(dirty)
        assert "\x00" not in result
        assert len(result) <= _MAX_CONTENT_LENGTH

    def test_strip_control_chars_removes_c1_nel(self) -> None:
        """U+0085 (NEL — Next Line) is stripped."""
        assert strip_control_chars("Hello\x85World") == "HelloWorld"

    def test_strip_control_chars_removes_c1_csi(self) -> None:
        """U+009B (CSI — Control Sequence Introducer) is stripped."""
        assert strip_control_chars("data\x9b31mred") == "data31mred"

    def test_strip_control_chars_removes_full_c1_range(self) -> None:
        """All C1 control characters (U+0080-U+009F) are stripped."""
        c1_chars = "".join(chr(i) for i in range(0x80, 0xA0))
        assert strip_control_chars(f"A{c1_chars}B") == "AB"


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

    def test_llm_response_usage_defaults_to_none(self) -> None:
        """LLMResponse().usage is None when the provider reports no usage (GH-142)."""
        assert LLMResponse().usage is None

    def test_llm_response_accepts_usage(self) -> None:
        """LLMResponse carries an LLMUsage with prompt/completion token counts."""
        usage = llm_mod.LLMUsage(prompt_tokens=12, completion_tokens=34)
        response = LLMResponse(content="hi", usage=usage)
        assert response.usage is not None
        assert (response.usage.prompt_tokens, response.usage.completion_tokens) == (12, 34)


# ---------------------------------------------------------------------------
# LLMUsage / LLMStreamDelta models (GH-142)
# ---------------------------------------------------------------------------


class TestLLMUsage:
    """Token usage parsed from provider responses (ready for #178)."""

    def test_llm_usage_valid_counts(self) -> None:
        """Non-negative token counts are accepted."""
        usage = llm_mod.LLMUsage(prompt_tokens=0, completion_tokens=7)
        assert usage.prompt_tokens == 0
        assert usage.completion_tokens == 7

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"prompt_tokens": -1, "completion_tokens": 0},
            {"prompt_tokens": 0, "completion_tokens": -1},
        ],
        ids=["negative-prompt", "negative-completion"],
    )
    def test_llm_usage_negative_counts_rejected(self, kwargs: dict[str, int]) -> None:
        """Token counts are bounded below by zero (ge=0)."""
        with pytest.raises(ValidationError):
            llm_mod.LLMUsage(**kwargs)

    def test_llm_usage_requires_both_counts(self) -> None:
        """Both counts are required fields."""
        with pytest.raises(ValidationError):
            llm_mod.LLMUsage(prompt_tokens=1)


class TestLLMStreamDelta:
    """One sanitized streamed text delta (reasoning excluded)."""

    def test_llm_stream_delta_holds_content(self) -> None:
        """LLMStreamDelta stores its content string."""
        assert llm_mod.LLMStreamDelta(content="x").content == "x"

    def test_llm_stream_delta_requires_content(self) -> None:
        """content is a required field."""
        with pytest.raises(ValidationError):
            llm_mod.LLMStreamDelta()


# ---------------------------------------------------------------------------
# LLMError model
# ---------------------------------------------------------------------------


class TestLLMError:
    """Tests for the LLMError exception class."""

    def test_error_with_status_code(self) -> None:
        """LLMError stores message and status_code."""
        err = LLMError("Service unavailable", 503)
        assert err.message == "Service unavailable"
        assert err.status_code == 503
        assert str(err) == "Service unavailable"

    def test_error_no_status_code(self) -> None:
        """LLMError with status_code=None for connection errors."""
        err = LLMError("Connection refused", None)
        assert err.message == "Connection refused"
        assert err.status_code is None

    def test_error_default_status_code(self) -> None:
        """LLMError defaults status_code to None when not provided."""
        err = LLMError("some error")
        assert err.status_code is None

    def test_llm_error_user_facing_flag_set(self) -> None:
        """LLMError(..., user_facing=True) marks a friendly, show-verbatim message (GH-142)."""
        err = LLMError(
            "Infomaniak isn't configured; set INFOMANIAK_API_TOKEN", None, user_facing=True
        )
        assert err.user_facing is True

    def test_llm_error_user_facing_defaults_false(self) -> None:
        """Without the flag an LLMError is internal (the agent shows its generic reply)."""
        assert LLMError("boom").user_facing is False

    def test_llm_error_existing_positional_args_still_work(self) -> None:
        """The positional (message, status_code) form keeps working alongside the flag."""
        err = LLMError("Service unavailable", 503)
        assert (err.message, err.status_code, err.user_facing) == (
            "Service unavailable",
            503,
            False,
        )

    def test_llm_error_user_facing_with_status_code(self) -> None:
        """status_code and user_facing coexist (e.g. a 429 rate limit reply)."""
        err = LLMError("Infomaniak rate limit reached", status_code=429, user_facing=True)
        assert (err.status_code, err.user_facing) == (429, True)


# ---------------------------------------------------------------------------
# create_llm_client factory
# ---------------------------------------------------------------------------


class TestCreateLLMClient:
    """Tests for provider selection in the client factory."""

    def test_anthropic_provider_builds_anthropic_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """provider='anthropic' returns an AnthropicClient."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        config = LLMConfig(provider="anthropic", anthropic_model="claude-sonnet-4-6")
        client = create_llm_client(config)
        assert isinstance(client, AnthropicClient)

    def test_openai_provider_builds_openai_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """provider='openai' returns an OpenAIClient."""
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        config = LLMConfig(provider="openai", openai_model="gpt-4o")
        client = create_llm_client(config)
        assert isinstance(client, OpenAIClient)

    def test_unknown_provider_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An unrecognised provider raises ValueError.

        anthropic/openai/vllm are all valid provider values now, so the only
        way to reach the factory's fallthrough is to force a genuinely unknown
        value via model_copy — this guards the defensive ``raise`` at the end
        of create_llm_client.
        """
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        config = LLMConfig(provider="anthropic", anthropic_model="claude-sonnet-4-6")
        forced = config.model_copy(update={"provider": "does-not-exist"})
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            create_llm_client(forced)

    def test_vllm_provider_builds_vllm_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """provider='vllm' returns a real VLLMClient, constructed with no API key.

        Issue #134 promotes vllm from a placeholder to a first-class client: the
        factory now builds a ``VLLMClient`` (an OpenAI-compatible wrapper) rather
        than the removed ``VLLMPlaceholderClient``, and must do so without any
        ANTHROPIC_API_KEY/OPENAI_API_KEY set.
        """
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = LLMConfig(provider="vllm")
        client = create_llm_client(config)
        assert isinstance(client, VLLMClient)

    # -- GH-142: Infomaniak (default) + no raise for missing keys/models --

    @staticmethod
    def _forbid_network(monkeypatch: pytest.MonkeyPatch) -> Any:
        """Patch the Infomaniak HTTP seam with a transport that fails on any request."""
        from admino import llm_infomaniak

        def _handler(request: httpx.Request) -> httpx.Response:
            pytest.fail(f"unexpected network request to {request.url.host}")

        def _factory(*_args: Any, **_kwargs: Any) -> httpx.AsyncClient:
            return httpx.AsyncClient(transport=httpx.MockTransport(_handler))

        monkeypatch.setattr(llm_infomaniak, "_new_http_client", _factory)
        return llm_infomaniak

    def test_infomaniak_provider_builds_infomaniak_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """provider='infomaniak' returns an InfomaniakClient — no env vars, no network."""
        monkeypatch.delenv("INFOMANIAK_API_TOKEN", raising=False)
        monkeypatch.delenv("INFOMANIAK_PRODUCT_ID", raising=False)
        module = self._forbid_network(monkeypatch)
        client = create_llm_client(LLMConfig(provider="infomaniak"))
        assert isinstance(client, module.InfomaniakClient)

    def test_default_config_builds_infomaniak_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The default LLMConfig selects Infomaniak and the factory builds it offline."""
        monkeypatch.delenv("INFOMANIAK_API_TOKEN", raising=False)
        monkeypatch.delenv("INFOMANIAK_PRODUCT_ID", raising=False)
        module = self._forbid_network(monkeypatch)
        client = create_llm_client(LLMConfig())
        assert isinstance(client, module.InfomaniakClient)

    def test_infomaniak_client_is_llm_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The factory's Infomaniak client satisfies the LLMClient protocol."""
        monkeypatch.setenv("INFOMANIAK_API_TOKEN", "ik-test-token")
        self._forbid_network(monkeypatch)
        client = create_llm_client(LLMConfig(provider="infomaniak"))
        assert isinstance(client, llm_mod.LLMClient)

    def test_openai_provider_without_key_builds_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A missing OPENAI_API_KEY no longer stops the factory (chat explains instead)."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        client = create_llm_client(LLMConfig(provider="openai", openai_model="gpt-4o"))
        assert isinstance(client, OpenAIClient)

    def test_anthropic_provider_without_key_builds_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A missing ANTHROPIC_API_KEY no longer stops the factory (chat explains instead)."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        client = create_llm_client(
            LLMConfig(provider="anthropic", anthropic_model="claude-sonnet-4-6")
        )
        assert isinstance(client, AnthropicClient)

    @pytest.mark.parametrize(
        ("provider", "field", "client_type"),
        [
            ("openai", "openai_model", OpenAIClient),
            ("anthropic", "anthropic_model", AnthropicClient),
            ("vllm", "vllm_model", VLLMClient),
        ],
    )
    def test_provider_without_model_builds_client(
        self,
        monkeypatch: pytest.MonkeyPatch,
        provider: str,
        field: str,
        client_type: type[Any],
    ) -> None:
        """An unset model no longer stops the factory for any provider."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        config = LLMConfig(provider=provider, **{field: ""})  # type: ignore[arg-type]
        assert isinstance(create_llm_client(config), client_type)
