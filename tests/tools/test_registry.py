"""Tests for the tool registry and dispatch (admino.tools.registry).

Covers tool registration, dispatch with permission checks, argument validation,
handler execution, error handling, and security properties (no input leakage,
no raw exception details).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from collections.abc import Generator

from admino.models import PendingConfirmation, ToolCall
from admino.permissions import PermissionsConfig, ToolPermissions
from admino.tools.registry import (
    ToolCallResult,
    ToolDescription,
    clear_registry,
    dispatch_tool_call,
    get_registered_tools,
    get_tool_entry,
    register_tool,
)

# ---------------------------------------------------------------------------
# Sample tool for testing
# ---------------------------------------------------------------------------


class SampleArgs(BaseModel):
    """Args model for the sample test tool."""

    query: str = Field(min_length=1, max_length=100)


class StrictArgs(BaseModel):
    """Args model with multiple constraints for validation testing."""

    count: int = Field(ge=1, le=100)
    label: str = Field(min_length=1, max_length=50)


async def sample_handler(args: SampleArgs, *, session_id: str) -> str:
    """Sample handler that returns a predictable result."""
    return f"result for {args.query}"


async def failing_handler(args: SampleArgs, *, session_id: str) -> str:
    """Handler that always raises an exception."""
    msg = "secret internal error: /home/user/.config/secrets.json"
    raise RuntimeError(msg)


async def strict_handler(args: StrictArgs, *, session_id: str) -> str:
    """Handler for StrictArgs."""
    return f"{args.label}: {args.count}"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry() -> Generator[None, None, None]:
    """Ensure the registry is clean before and after every test."""
    clear_registry()
    yield
    clear_registry()


@pytest.fixture()
def registered_tool() -> None:
    """Register sample gmail.read tool."""
    register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)


@pytest.fixture()
def allow_config() -> PermissionsConfig:
    """PermissionsConfig that allows gmail.read."""
    return PermissionsConfig(tools={"gmail": ToolPermissions(actions={"read": "allow"})})


@pytest.fixture()
def deny_config() -> PermissionsConfig:
    """PermissionsConfig that denies gmail.read."""
    return PermissionsConfig(tools={"gmail": ToolPermissions(actions={"read": "deny"})})


@pytest.fixture()
def confirm_config() -> PermissionsConfig:
    """PermissionsConfig that requires confirmation for gmail.read."""
    return PermissionsConfig(tools={"gmail": ToolPermissions(actions={"read": "confirm"})})


@pytest.fixture()
def empty_config() -> PermissionsConfig:
    """Empty PermissionsConfig -- everything defaults to deny."""
    return PermissionsConfig()


def _make_tool_call(**overrides: object) -> ToolCall:
    """Create a ToolCall with sensible defaults."""
    defaults: dict[str, object] = {
        "tool": "gmail",
        "action": "read",
        "args": {"query": "test"},
    }
    defaults.update(overrides)
    return ToolCall(**defaults)  # type: ignore[arg-type]


def _make_pending_confirmation(tool_call: ToolCall | None = None) -> PendingConfirmation:
    """Create a valid PendingConfirmation."""
    tc = tool_call or _make_tool_call()
    now = datetime.now(UTC)
    return PendingConfirmation(
        confirmation_id="confirm-123",
        session_id="sess-1",
        tool_call=tc,
        created_at=now,
        expires_at=now + timedelta(seconds=300),
    )


# ---------------------------------------------------------------------------
# 1. Registration Tests (TestRegisterTool)
# ---------------------------------------------------------------------------


class TestRegisterTool:
    """Tests for the register_tool decorator."""

    def test_register_tool_valid_registration(self) -> None:
        """Register a tool and verify it appears in the registry."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)
        entry = get_tool_entry("gmail", "read")
        assert entry is not None
        assert entry.tool == "gmail"
        assert entry.action == "read"

    def test_register_tool_duplicate_raises_value_error(self) -> None:
        """Registering the same (tool, action) twice raises ValueError."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)
        with pytest.raises(ValueError, match="already registered"):
            register_tool("gmail", "read", "Read emails again", SampleArgs)(sample_handler)

    @pytest.mark.parametrize(
        "tool_name",
        [
            "Gmail",  # uppercase
            "GMAIL",  # all uppercase
            "gmail send",  # space
            "1gmail",  # starts with digit
            "",  # empty
            "g" * 64,  # too long (64 chars, max is 63)
            "gmail.read",  # dot
            "gmail\x00",  # null byte
        ],
        ids=[
            "mixed-case",
            "all-upper",
            "space",
            "starts-digit",
            "empty",
            "too-long",
            "dot",
            "null-byte",
        ],
    )
    def test_register_tool_invalid_tool_name_raises(self, tool_name: str) -> None:
        """Invalid tool names raise ValueError at registration time."""
        with pytest.raises(ValueError, match="Invalid tool name"):
            register_tool(tool_name, "read", "desc", SampleArgs)

    @pytest.mark.parametrize(
        "action_name",
        [
            "Read",  # uppercase
            "read send",  # space
            "1read",  # starts with digit
            "",  # empty
            "r" * 64,  # too long
            "read.all",  # dot
        ],
        ids=[
            "mixed-case",
            "space",
            "starts-digit",
            "empty",
            "too-long",
            "dot",
        ],
    )
    def test_register_tool_invalid_action_name_raises(self, action_name: str) -> None:
        """Invalid action names raise ValueError at registration time."""
        with pytest.raises(ValueError, match="Invalid action name"):
            register_tool("gmail", action_name, "desc", SampleArgs)

    def test_register_tool_returns_original_function(self) -> None:
        """The decorator returns the handler function unchanged."""
        result = register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)
        assert result is sample_handler


# ---------------------------------------------------------------------------
# 2. Get Registered Tools (TestGetRegisteredTools)
# ---------------------------------------------------------------------------


class TestGetRegisteredTools:
    """Tests for get_registered_tools."""

    def test_get_registered_tools_empty_registry(self) -> None:
        """Returns empty list when nothing is registered."""
        assert get_registered_tools() == []

    def test_get_registered_tools_returns_sorted(self) -> None:
        """Multiple tools registered are returned sorted by (tool, action)."""
        register_tool("weather", "fetch", "Fetch weather", SampleArgs)(sample_handler)
        register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)
        register_tool("gmail", "list", "List emails", SampleArgs)(sample_handler)
        register_tool("calendar", "list", "List events", SampleArgs)(sample_handler)

        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert keys == sorted(keys)
        assert keys == [
            ("calendar", "list"),
            ("gmail", "list"),
            ("gmail", "read"),
            ("weather", "fetch"),
        ]

    def test_get_registered_tools_includes_json_schema(self) -> None:
        """Each ToolDescription has a parameters_schema from the Pydantic model."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)
        tools = get_registered_tools()
        assert len(tools) == 1
        schema = tools[0].parameters_schema
        assert "properties" in schema
        assert "query" in schema["properties"]

    def test_get_registered_tools_returns_tool_description_instances(self) -> None:
        """Returned items are ToolDescription model instances."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)
        tools = get_registered_tools()
        assert all(isinstance(t, ToolDescription) for t in tools)


# ---------------------------------------------------------------------------
# 3. Dispatch -- Permission Denied (TestDispatchPermissionDenied)
# ---------------------------------------------------------------------------


class TestDispatchPermissionDenied:
    """Tests for dispatch when permission is denied."""

    async def test_dispatch_denied_tool_returns_failure(
        self, registered_tool: None, deny_config: PermissionsConfig
    ) -> None:
        """Tool denied by config returns success=False."""
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, deny_config, session_id="sess-1")
        assert result.success is False

    async def test_dispatch_denied_tool_handler_never_called(
        self, deny_config: PermissionsConfig
    ) -> None:
        """When denied, the handler function is never invoked."""
        call_count = 0

        async def counting_handler(args: SampleArgs, *, session_id: str) -> str:
            nonlocal call_count
            call_count += 1
            return "should not happen"

        register_tool("gmail", "read", "Read emails", SampleArgs)(counting_handler)
        tc = _make_tool_call()
        await dispatch_tool_call(tc, deny_config, session_id="sess-1")
        assert call_count == 0

    async def test_dispatch_denied_returns_permission_result(
        self, registered_tool: None, deny_config: PermissionsConfig
    ) -> None:
        """Result includes the deny permission decision."""
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, deny_config, session_id="sess-1")
        assert result.permission.allowed == "deny"

    async def test_dispatch_hardcoded_denial_returns_failure(self, registered_tool: None) -> None:
        """Hardcoded denials (e.g. gmail.send) return failure even if config says allow."""
        config_says_allow = PermissionsConfig(
            tools={"gmail": ToolPermissions(actions={"send": "allow"})}
        )
        tc = _make_tool_call(tool="gmail", action="send", args={})
        result = await dispatch_tool_call(tc, config_says_allow, session_id="sess-1")
        assert result.success is False
        assert result.permission.allowed == "deny"


# ---------------------------------------------------------------------------
# 4. Dispatch -- Confirm Required (TestDispatchConfirmRequired)
# ---------------------------------------------------------------------------


class TestDispatchConfirmRequired:
    """Tests for dispatch when confirmation is required."""

    async def test_dispatch_confirm_no_pending_returns_failure(
        self, registered_tool: None, confirm_config: PermissionsConfig
    ) -> None:
        """When confirm needed and no pending_confirmation, returns success=False."""
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, confirm_config, session_id="sess-1")
        assert result.success is False

    async def test_dispatch_confirm_with_pending_proceeds(
        self, registered_tool: None, confirm_config: PermissionsConfig
    ) -> None:
        """When pending_confirmation is provided, tool executes successfully."""
        tc = _make_tool_call()
        pending = _make_pending_confirmation(tc)
        result = await dispatch_tool_call(
            tc, confirm_config, session_id="sess-1", pending_confirmation=pending
        )
        assert result.success is True
        assert "result for test" in result.result

    async def test_dispatch_confirm_result_message_mentions_action(
        self, registered_tool: None, confirm_config: PermissionsConfig
    ) -> None:
        """Result message includes tool.action when confirmation is needed."""
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, confirm_config, session_id="sess-1")
        assert "gmail.read" in result.result


# ---------------------------------------------------------------------------
# 5. Dispatch -- Tool Not Found (TestDispatchUnknownTool)
# ---------------------------------------------------------------------------


class TestDispatchUnknownTool:
    """Tests for dispatch of tools not in the registry."""

    async def test_dispatch_unknown_tool_returns_failure(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Tool allowed by permissions but not registered returns failure."""
        # gmail.read is allowed but NOT registered (no registered_tool fixture)
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is False
        assert "unknown" in result.result.lower()

    async def test_dispatch_unknown_tool_logs_warning(
        self,
        allow_config: PermissionsConfig,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A warning is logged when an unknown tool is dispatched."""
        tc = _make_tool_call()
        with caplog.at_level(logging.WARNING, logger="admino.tools.registry"):
            await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert any(
            "unknown tool" in r.message.lower() or "not in registry" in r.message.lower()
            for r in caplog.records
        )


# ---------------------------------------------------------------------------
# 6. Dispatch -- Argument Validation (TestDispatchArgValidation)
# ---------------------------------------------------------------------------


class TestDispatchArgValidation:
    """Tests for argument validation during dispatch."""

    async def test_dispatch_invalid_args_returns_failure(
        self, registered_tool: None, allow_config: PermissionsConfig
    ) -> None:
        """Wrong args for schema produce a validation error result."""
        tc = _make_tool_call(args={"query": ""})  # min_length=1 violation
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is False
        assert "validation failed" in result.result.lower()

    async def test_dispatch_invalid_args_no_input_leak(
        self, registered_tool: None, allow_config: PermissionsConfig
    ) -> None:
        """Error message does NOT contain raw argument values."""
        secret = "super_secret_api_key_ghp_1234567890"
        tc = _make_tool_call(args={"query": secret * 10})  # exceeds max_length=100
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is False
        assert secret not in result.result

    async def test_dispatch_missing_required_arg_returns_failure(
        self, registered_tool: None, allow_config: PermissionsConfig
    ) -> None:
        """Missing required args produce a validation failure."""
        tc = _make_tool_call(args={})  # 'query' is required
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is False
        assert "validation failed" in result.result.lower()

    async def test_dispatch_wrong_type_arg_returns_failure(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Wrong type for an arg field causes validation failure."""
        register_tool("gmail", "read", "Read emails", StrictArgs)(strict_handler)
        tc = _make_tool_call(args={"count": "not_a_number", "label": "test"})
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is False

    async def test_dispatch_valid_args_passes_validated_model(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Handler receives a Pydantic model instance, not a raw dict."""
        received_args: list[object] = []

        async def capturing_handler(args: SampleArgs, *, session_id: str) -> str:
            received_args.append(args)
            return "ok"

        register_tool("gmail", "read", "Read emails", SampleArgs)(capturing_handler)
        tc = _make_tool_call()
        await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert len(received_args) == 1
        assert isinstance(received_args[0], SampleArgs)
        assert received_args[0].query == "test"  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# 7. Dispatch -- Handler Execution (TestDispatchExecution)
# ---------------------------------------------------------------------------


class TestDispatchExecution:
    """Tests for successful and failed handler execution."""

    async def test_dispatch_success_returns_result(
        self, registered_tool: None, allow_config: PermissionsConfig
    ) -> None:
        """Handler returns a string, dispatch returns success=True with that string."""
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is True
        assert result.result == "result for test"

    async def test_dispatch_handler_exception_returns_failure(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Handler raising an exception results in success=False."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(failing_handler)
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is False
        assert "RuntimeError" in result.result

    async def test_dispatch_handler_exception_no_raw_details(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Error result does NOT contain the exception message details."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(failing_handler)
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        # The handler's message contains a path -- it must not leak
        assert "secrets.json" not in result.result
        assert "secret internal error" not in result.result
        # Only the type name should appear
        assert result.result == "Tool execution failed: RuntimeError"

    async def test_dispatch_success_includes_permission(
        self, registered_tool: None, allow_config: PermissionsConfig
    ) -> None:
        """Successful dispatch includes the allow permission."""
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.permission.allowed == "allow"

    async def test_dispatch_returns_tool_call_result(
        self, registered_tool: None, allow_config: PermissionsConfig
    ) -> None:
        """Dispatch returns a ToolCallResult model instance."""
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert isinstance(result, ToolCallResult)


# ---------------------------------------------------------------------------
# 8. Clear Registry (TestClearRegistry)
# ---------------------------------------------------------------------------


class TestClearRegistry:
    """Tests for clear_registry."""

    def test_clear_registry_empties_all(self) -> None:
        """After clear, get_registered_tools returns empty list."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)
        register_tool("weather", "fetch", "Fetch weather", SampleArgs)(sample_handler)
        assert len(get_registered_tools()) == 2
        clear_registry()
        assert get_registered_tools() == []


# ---------------------------------------------------------------------------
# 9. Get Tool Entry (TestGetToolEntry)
# ---------------------------------------------------------------------------


class TestGetToolEntry:
    """Tests for get_tool_entry."""

    def test_get_tool_entry_found(self, registered_tool: None) -> None:
        """Returns entry for a registered tool."""
        entry = get_tool_entry("gmail", "read")
        assert entry is not None
        assert entry.tool == "gmail"
        assert entry.action == "read"

    def test_get_tool_entry_not_found(self) -> None:
        """Returns None for an unregistered tool."""
        assert get_tool_entry("nonexistent", "action") is None

    def test_get_tool_entry_no_handler_exposed(self, registered_tool: None) -> None:
        """get_tool_entry returns ToolDescription, not _ToolEntry with handler."""
        entry = get_tool_entry("gmail", "read")
        assert entry is not None
        assert type(entry) is ToolDescription  # exact type check
        assert not hasattr(entry, "handler")


# ---------------------------------------------------------------------------
# 10. Dispatch ordering -- permission check before arg validation
# ---------------------------------------------------------------------------


class TestDispatchOrdering:
    """Permission check must happen BEFORE argument validation."""

    async def test_denied_tool_skips_arg_validation(self, deny_config: PermissionsConfig) -> None:
        """A denied tool returns failure even with completely invalid args."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)
        # Args that would fail validation -- but permission check comes first
        tc = _make_tool_call(args={"nonexistent_field": 999})
        result = await dispatch_tool_call(tc, deny_config, session_id="sess-1")
        assert result.success is False
        assert result.permission.allowed == "deny"
        # If arg validation ran first, error would mention validation, not permission
        assert "validation" not in result.result.lower()

    async def test_unlisted_tool_denied_before_arg_check(
        self, empty_config: PermissionsConfig
    ) -> None:
        """An unlisted tool is denied before any arg validation."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)
        tc = _make_tool_call(args={"bad": True})
        result = await dispatch_tool_call(tc, empty_config, session_id="sess-1")
        assert result.success is False
        assert result.permission.allowed == "deny"


# ---------------------------------------------------------------------------
# 11. Adversarial tests
# ---------------------------------------------------------------------------


class TestAdversarialRegistry:
    """Adversarial tests for the registry and dispatch."""

    async def test_hallucinated_tool_name_rejected(self, allow_config: PermissionsConfig) -> None:
        """A tool name that exists in permissions but not in registry is rejected."""
        register_tool("gmail", "list", "List emails", SampleArgs)(sample_handler)
        # gmail.read is allowed but only gmail.list is registered
        tc = _make_tool_call(tool="gmail", action="read")
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is False
        assert "unknown" in result.result.lower()

    async def test_oversized_tool_args_rejected(
        self, registered_tool: None, allow_config: PermissionsConfig
    ) -> None:
        """Oversized query arg is caught by Pydantic validation."""
        tc = _make_tool_call(args={"query": "x" * 200})  # max_length=100
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is False
        assert "validation failed" in result.result.lower()

    async def test_hardcoded_deny_in_yaml_set_to_allow_still_denied(self) -> None:
        """Even if YAML says allow, hardcoded denials are still denied."""
        config = PermissionsConfig(tools={"gmail": ToolPermissions(actions={"send": "allow"})})
        register_tool("gmail", "send", "Send email", SampleArgs)(sample_handler)
        tc = _make_tool_call(tool="gmail", action="send")
        result = await dispatch_tool_call(tc, config, session_id="sess-1")
        assert result.success is False
        assert result.permission.allowed == "deny"

    async def test_handler_exception_does_not_leak_internals(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Handler exceptions only expose the error type name."""

        async def leaky_handler(args: SampleArgs, *, session_id: str) -> str:
            msg = "Database connection failed: postgres://user:password@host:5432/db"
            raise ConnectionError(msg)

        register_tool("gmail", "read", "Read emails", SampleArgs)(leaky_handler)
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is False
        assert "password" not in result.result
        assert "postgres" not in result.result
        assert "ConnectionError" in result.result


# ---------------------------------------------------------------------------
# 12. Additional Registration Tests
# ---------------------------------------------------------------------------


class TestRegisterToolAdditional:
    """Additional registration edge cases."""

    def test_register_after_clear_registry_allows_reregistration(self) -> None:
        """After clear_registry, the same (tool, action) can be registered again."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)
        assert get_tool_entry("gmail", "read") is not None
        clear_registry()
        # Re-register same key -- should not raise
        register_tool("gmail", "read", "Read emails v2", SampleArgs)(sample_handler)
        entry = get_tool_entry("gmail", "read")
        assert entry is not None
        assert entry.description == "Read emails v2"

    def test_register_multiple_tools_no_conflict(self) -> None:
        """Multiple distinct tools coexist without interfering."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)
        register_tool("gmail", "list", "List emails", SampleArgs)(sample_handler)
        register_tool("calendar", "list", "List events", SampleArgs)(sample_handler)
        register_tool("weather", "fetch", "Fetch weather", SampleArgs)(sample_handler)

        assert get_tool_entry("gmail", "read") is not None
        assert get_tool_entry("gmail", "list") is not None
        assert get_tool_entry("calendar", "list") is not None
        assert get_tool_entry("weather", "fetch") is not None
        assert len(get_registered_tools()) == 4

    def test_register_tool_preserves_function_name(self) -> None:
        """Decorator preserves the original function's __name__ attribute."""
        result = register_tool("gmail", "read", "Read", SampleArgs)(sample_handler)
        assert result.__name__ == "sample_handler"

    def test_register_tool_stores_description_and_schema(self) -> None:
        """Registration stores description and parameters_schema on the entry."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)
        entry = get_tool_entry("gmail", "read")
        assert entry is not None
        assert isinstance(entry, ToolDescription)
        assert entry.description == "Read emails"
        assert "properties" in entry.parameters_schema
        assert "query" in entry.parameters_schema["properties"]


# ---------------------------------------------------------------------------
# 13. Additional Dispatch Tests -- Handler Receives Correct Arguments
# ---------------------------------------------------------------------------


class TestDispatchHandlerArgPassing:
    """Verify handlers receive validated Pydantic models and session_id."""

    async def test_handler_receives_session_id_value(self, allow_config: PermissionsConfig) -> None:
        """Handler receives the exact session_id passed to dispatch."""
        received_session_ids: list[str] = []

        async def capturing_handler(args: SampleArgs, *, session_id: str) -> str:
            received_session_ids.append(session_id)
            return "ok"

        register_tool("gmail", "read", "Read emails", SampleArgs)(capturing_handler)
        tc = _make_tool_call()
        await dispatch_tool_call(tc, allow_config, session_id="my-unique-session-42")
        assert received_session_ids == ["my-unique-session-42"]

    async def test_handler_result_string_passed_through(
        self, allow_config: PermissionsConfig
    ) -> None:
        """The exact string returned by the handler appears in ToolCallResult.result."""

        async def custom_handler(args: SampleArgs, *, session_id: str) -> str:
            return "custom output: 42"

        register_tool("gmail", "read", "Read emails", SampleArgs)(custom_handler)
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.result == "custom output: 42"

    async def test_handler_returns_empty_string(self, allow_config: PermissionsConfig) -> None:
        """Handler returning an empty string is valid and passed through."""

        async def empty_handler(args: SampleArgs, *, session_id: str) -> str:
            return ""

        register_tool("gmail", "read", "Read emails", SampleArgs)(empty_handler)
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is True
        assert result.result == ""

    async def test_handler_returns_max_length_string(self, allow_config: PermissionsConfig) -> None:
        """Handler returning a string at the ToolCallResult max_length (65536) succeeds."""
        max_result = "x" * 65536

        async def big_handler(args: SampleArgs, *, session_id: str) -> str:
            return max_result

        register_tool("gmail", "read", "Read emails", SampleArgs)(big_handler)
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is True
        assert len(result.result) == 65536


# ---------------------------------------------------------------------------
# 14. Additional Dispatch Tests -- No-Args Tools
# ---------------------------------------------------------------------------


class NoArgs(BaseModel):
    """Tool args model with no required fields."""

    pass


class TestDispatchNoArgsTools:
    """Dispatch for tools that require no arguments."""

    async def test_dispatch_empty_args_for_no_arg_tool(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Tool with no required fields succeeds with empty args dict."""

        async def no_arg_handler(args: NoArgs, *, session_id: str) -> str:
            return "no args needed"

        register_tool("gmail", "read", "Read emails", NoArgs)(no_arg_handler)
        tc = _make_tool_call(args={})
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is True
        assert result.result == "no args needed"


# ---------------------------------------------------------------------------
# 15. Additional Arg Validation Tests
# ---------------------------------------------------------------------------


class TestDispatchArgValidationAdditional:
    """Additional argument validation edge cases."""

    async def test_dispatch_field_constraint_ge_le_violation(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Value exceeding ge/le Field constraint returns validation error."""
        register_tool("gmail", "read", "Read emails", StrictArgs)(strict_handler)
        tc = _make_tool_call(args={"count": 999, "label": "test"})  # le=100
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is False
        assert "validation failed" in result.result.lower()

    async def test_dispatch_field_constraint_below_minimum(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Value below ge constraint returns validation error."""
        register_tool("gmail", "read", "Read emails", StrictArgs)(strict_handler)
        tc = _make_tool_call(args={"count": 0, "label": "test"})  # ge=1
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is False
        assert "validation failed" in result.result.lower()

    async def test_dispatch_extra_fields_rejected(
        self, registered_tool: None, allow_config: PermissionsConfig
    ) -> None:
        """Extra unexpected fields are rejected — no covert smuggling channel.

        Pydantic's default ``extra='ignore'`` would silently drop unknown
        keys. Dispatch enforces ``extra='forbid'`` semantics explicitly so
        the LLM cannot sneak fields past the schema.
        """
        tc = _make_tool_call(args={"query": "test", "extra_field": "sneaky"})
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is False
        assert "unexpected fields" in result.result.lower()

    async def test_dispatch_extra_field_value_not_leaked(
        self, registered_tool: None, allow_config: PermissionsConfig
    ) -> None:
        """The rejection message does not echo the extra field's value."""
        secret = "ghp_verysensitivetokenvalue1234567890abcd"
        tc = _make_tool_call(args={"query": "test", "sneaky_token": secret})
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is False
        assert secret not in result.result

    async def test_dispatch_validation_error_does_not_leak_raw_value(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Validation error message does NOT contain the raw input value."""
        register_tool("gmail", "read", "Read emails", StrictArgs)(strict_handler)
        secret_value = "super_secret_password_12345"
        tc = _make_tool_call(args={"count": secret_value, "label": "test"})
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is False
        assert secret_value not in result.result

    async def test_dispatch_confirm_with_pending_but_invalid_args_fails_validation(
        self, confirm_config: PermissionsConfig
    ) -> None:
        """Confirm with pending_confirmation but invalid args still fails validation."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)
        tc = _make_tool_call(args={"query": ""})  # min_length=1 violation
        pending = _make_pending_confirmation(tc)
        result = await dispatch_tool_call(
            tc, confirm_config, session_id="sess-1", pending_confirmation=pending
        )
        assert result.success is False
        assert "validation failed" in result.result.lower()


# ---------------------------------------------------------------------------
# 16. Additional Permission Tests
# ---------------------------------------------------------------------------


class TestDispatchPermissionAdditional:
    """Additional permission-related dispatch tests."""

    async def test_denied_result_includes_reason_text(
        self, registered_tool: None, deny_config: PermissionsConfig
    ) -> None:
        """Denied result includes a non-empty reason from the permission engine."""
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, deny_config, session_id="sess-1")
        assert result.permission.reason
        assert len(result.permission.reason) > 0

    async def test_config_deny_blocks_handler_execution(
        self, deny_config: PermissionsConfig
    ) -> None:
        """Config-based denial (not hardcoded) blocks handler from executing."""
        call_count = 0

        async def counting_handler(args: SampleArgs, *, session_id: str) -> str:
            nonlocal call_count
            call_count += 1
            return "should not run"

        register_tool("gmail", "read", "Read emails", SampleArgs)(counting_handler)
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, deny_config, session_id="sess-1")
        assert result.success is False
        assert result.permission.allowed == "deny"
        assert call_count == 0

    async def test_default_deny_for_unlisted_tool(self, empty_config: PermissionsConfig) -> None:
        """Tool not listed in config at all is denied (default-deny)."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, empty_config, session_id="sess-1")
        assert result.success is False
        assert result.permission.allowed == "deny"

    @pytest.mark.parametrize(
        ("tool", "action"),
        [
            ("gmail", "send"),
            ("gmail", "delete"),
            ("google_calendar", "delete"),
            ("google_calendar", "update"),
            ("google_drive", "delete"),
            ("outlook", "send"),
            ("outlook", "delete"),
            ("outlook_calendar", "delete"),
            ("outlook_calendar", "update"),
            ("onedrive", "delete"),
            ("documents", "delete"),
            ("files", "delete"),
            ("memory", "delete"),
        ],
        ids=[
            "gmail.send",
            "gmail.delete",
            "google_calendar.delete",
            "google_calendar.update",
            "google_drive.delete",
            "outlook.send",
            "outlook.delete",
            "outlook_calendar.delete",
            "outlook_calendar.update",
            "onedrive.delete",
            "documents.delete",
            "files.delete",
            "memory.delete",
        ],
    )
    async def test_all_hardcoded_denials_blocked(self, tool: str, action: str) -> None:
        """Every hardcoded denial is enforced even when config says allow."""
        config = PermissionsConfig(tools={tool: ToolPermissions(actions={action: "allow"})})
        register_tool(tool, action, f"{tool} {action}", SampleArgs)(sample_handler)
        tc = _make_tool_call(tool=tool, action=action)
        result = await dispatch_tool_call(tc, config, session_id="sess-1")
        assert result.success is False
        assert result.permission.allowed == "deny"


# ---------------------------------------------------------------------------
# 17. Additional Unknown Tool Tests
# ---------------------------------------------------------------------------


class TestDispatchUnknownToolAdditional:
    """Additional tests for unknown/hallucinated tools."""

    async def test_unknown_tool_handler_never_called(self, allow_config: PermissionsConfig) -> None:
        """Handler for a different tool.action is never called for an unknown one."""
        call_count = 0

        async def counting_handler(args: SampleArgs, *, session_id: str) -> str:
            nonlocal call_count
            call_count += 1
            return "ok"

        # Register gmail.list, but dispatch gmail.read (allowed but not registered)
        register_tool("gmail", "list", "List emails", SampleArgs)(counting_handler)
        tc = _make_tool_call(tool="gmail", action="read")
        await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert call_count == 0

    async def test_unknown_tool_result_mentions_unknown(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Result message for unknown tool contains 'unknown'."""
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert "unknown" in result.result.lower()

    async def test_unknown_tool_includes_tool_action_in_message(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Result message for unknown tool includes the tool.action pair."""
        tc = _make_tool_call(tool="gmail", action="read")
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert "gmail.read" in result.result


# ---------------------------------------------------------------------------
# 18. ToolCallResult Model Tests
# ---------------------------------------------------------------------------


class TestToolCallResultModel:
    """Tests for the ToolCallResult Pydantic model itself."""

    def test_result_default_empty_string(self) -> None:
        """ToolCallResult.result defaults to empty string."""
        from admino.permissions import PermissionResult

        r = ToolCallResult(
            success=True,
            permission=PermissionResult(allowed="allow", reason="ok"),
        )
        assert r.result == ""

    def test_result_max_length_enforced(self) -> None:
        """ToolCallResult.result rejects strings exceeding max_length."""
        from pydantic import ValidationError as PydanticValidationError

        from admino.permissions import PermissionResult

        with pytest.raises(PydanticValidationError):
            ToolCallResult(
                success=True,
                result="x" * 65537,
                permission=PermissionResult(allowed="allow", reason="ok"),
            )


# ---------------------------------------------------------------------------
# 19. ToolDescription Model Tests
# ---------------------------------------------------------------------------


class TestToolDescriptionModel:
    """Tests for the ToolDescription Pydantic model."""

    def test_tool_description_valid(self) -> None:
        """Valid ToolDescription instantiation succeeds."""
        td = ToolDescription(
            tool="gmail",
            action="read",
            description="Read emails",
            parameters_schema={"type": "object"},
        )
        assert td.tool == "gmail"
        assert td.action == "read"

    @pytest.mark.parametrize(
        "field,value",
        [
            ("tool", "INVALID"),
            ("tool", ""),
            ("action", "INVALID"),
            ("action", ""),
            ("description", ""),
            ("description", "x" * 1025),
        ],
        ids=[
            "tool-uppercase",
            "tool-empty",
            "action-uppercase",
            "action-empty",
            "description-empty",
            "description-too-long",
        ],
    )
    def test_tool_description_invalid_fields(self, field: str, value: str) -> None:
        """Invalid field values on ToolDescription raise ValidationError."""
        from pydantic import ValidationError as PydanticValidationError

        defaults = {
            "tool": "gmail",
            "action": "read",
            "description": "Read emails",
            "parameters_schema": {"type": "object"},
        }
        defaults[field] = value
        with pytest.raises(PydanticValidationError):
            ToolDescription(**defaults)


# ---------------------------------------------------------------------------
# 20. Dispatch Logging Tests
# ---------------------------------------------------------------------------


class TestDispatchLogging:
    """Verify that dispatch logs appropriate messages."""

    async def test_handler_exception_logs_error(
        self, allow_config: PermissionsConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Handler exception is logged at ERROR level with exception type."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(failing_handler)
        tc = _make_tool_call()
        with caplog.at_level(logging.ERROR, logger="admino.tools.registry"):
            await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert any("RuntimeError" in r.message for r in caplog.records)

    async def test_handler_exception_log_does_not_leak_secrets(
        self, allow_config: PermissionsConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Logged exception message does not include raw exception details from handler."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(failing_handler)
        tc = _make_tool_call()
        with caplog.at_level(logging.ERROR, logger="admino.tools.registry"):
            await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        # Check both the message template and the full formatted output (inc. exc_info)
        formatter = logging.Formatter()
        for record in caplog.records:
            assert "secrets.json" not in record.message
            formatted = formatter.format(record)
            assert "secrets.json" not in formatted


# ---------------------------------------------------------------------------
# 21. Adversarial -- model_construct bypass and identifier validation
# ---------------------------------------------------------------------------


class TestAdversarialModelConstructBypass:
    """Tests that dispatch rejects ToolCalls constructed via model_construct."""

    async def test_dispatch_rejects_model_construct_bypass(
        self, allow_config: PermissionsConfig
    ) -> None:
        """model_construct bypasses validators; dispatch must still reject."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)
        tc = ToolCall.model_construct(tool="x" * 200, action="../../etc", args={})
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is False

    async def test_dispatch_rejects_invalid_identifier_in_tool_call(
        self, allow_config: PermissionsConfig
    ) -> None:
        """dispatch_tool_call rejects tool_call with malformed identifiers."""
        register_tool("gmail", "read", "Read emails", SampleArgs)(sample_handler)
        tc = ToolCall.model_construct(tool="GMAIL", action="read", args={"query": "test"})
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        assert result.success is False


# ---------------------------------------------------------------------------
# 22. Handler result sanitization
# ---------------------------------------------------------------------------


class TestHandlerResultSanitization:
    """Tests that handler results are sanitized before returning."""

    async def test_null_bytes_stripped_from_handler_result(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Null bytes in handler result are stripped or rejected."""

        async def null_handler(args: SampleArgs, *, session_id: str) -> str:
            return "result\x00with\x00nulls"

        register_tool("gmail", "read", "Read", SampleArgs)(null_handler)
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, allow_config, session_id="sess-1")
        # Either success with nulls stripped, or failure — but never nulls in result
        assert "\x00" not in result.result


# ---------------------------------------------------------------------------
# 23. No model_construct in production tools code
# ---------------------------------------------------------------------------


class TestNoModelConstructInToolsCode:
    """Ensure production code in src/admino/tools/ never uses model_construct."""

    def test_no_model_construct_in_tools_production_code(self) -> None:
        """Scan src/admino/tools/*.py for model_construct() calls."""
        import ast
        from pathlib import Path

        src_dir = Path(__file__).resolve().parent.parent.parent / "src" / "admino" / "tools"
        for py_file in src_dir.glob("*.py"):
            tree = ast.parse(py_file.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == "model_construct":
                    pytest.fail(f"model_construct() called in {py_file.name}:{node.lineno}")


# ---------------------------------------------------------------------------
# 24. Handler non-string return
# ---------------------------------------------------------------------------


class TestHandlerNonStringReturn:
    """Tests that non-string handler returns produce failure, not crashes."""

    async def test_handler_returning_none_returns_failure(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Handler returning None results in success=False with descriptive message."""

        async def none_handler(args: SampleArgs, *, session_id: str) -> str:
            return None  # type: ignore[return-value]

        register_tool("gmail", "read", "Read", SampleArgs)(none_handler)
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, allow_config, session_id="s1")
        assert result.success is False
        assert "non-string" in result.result.lower()

    async def test_handler_returning_int_returns_failure(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Handler returning an int results in success=False with descriptive message."""

        async def int_handler(args: SampleArgs, *, session_id: str) -> str:
            return 42  # type: ignore[return-value]

        register_tool("gmail", "read", "Read", SampleArgs)(int_handler)
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, allow_config, session_id="s1")
        assert result.success is False
        assert "non-string" in result.result.lower()


# ---------------------------------------------------------------------------
# 25. Handler result truncation
# ---------------------------------------------------------------------------


class TestHandlerResultTruncation:
    """Tests that oversized handler results are truncated, not rejected."""

    async def test_oversized_result_truncated_not_error(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Handler returning >65536 chars is truncated to 65536, still success."""

        async def big_handler(args: SampleArgs, *, session_id: str) -> str:
            return "x" * 100_000

        register_tool("gmail", "read", "Read", SampleArgs)(big_handler)
        tc = _make_tool_call()
        result = await dispatch_tool_call(tc, allow_config, session_id="s1")
        assert result.success is True
        assert len(result.result) == 65536


# ---------------------------------------------------------------------------
# 26. Resource exhaustion re-raise
# ---------------------------------------------------------------------------


class TestNoClearRegistryInProduction:
    """Verify no production code calls clear_registry()."""

    def test_no_production_clear_registry_calls(self) -> None:
        """AST-scan src/admino/ for clear_registry references (excluding registry.py)."""
        import ast
        from pathlib import Path

        src_dir = Path(__file__).resolve().parent.parent.parent / "src" / "admino"
        for py_file in src_dir.rglob("*.py"):
            if py_file.name == "registry.py":
                continue
            tree = ast.parse(py_file.read_text())
            for node in ast.walk(tree):
                name: str | None = None
                if isinstance(node, ast.Name):
                    name = node.id
                elif isinstance(node, ast.Attribute):
                    name = node.attr
                if name == "clear_registry":
                    pytest.fail(
                        f"clear_registry referenced in {py_file.relative_to(src_dir)}:{node.lineno}"
                    )


class TestResourceExhaustionReRaise:
    """Tests that MemoryError and RecursionError are re-raised, not swallowed."""

    async def test_memory_error_is_reraised(self, allow_config: PermissionsConfig) -> None:
        """MemoryError from handler propagates instead of being caught."""

        async def oom_handler(args: SampleArgs, *, session_id: str) -> str:
            raise MemoryError("out of memory")

        register_tool("gmail", "read", "Read", SampleArgs)(oom_handler)
        tc = _make_tool_call()
        with pytest.raises(MemoryError):
            await dispatch_tool_call(tc, allow_config, session_id="s1")

    async def test_recursion_error_is_reraised(self, allow_config: PermissionsConfig) -> None:
        """RecursionError from handler propagates instead of being caught."""

        async def recurse_handler(args: SampleArgs, *, session_id: str) -> str:
            raise RecursionError("max depth")

        register_tool("gmail", "read", "Read", SampleArgs)(recurse_handler)
        tc = _make_tool_call()
        with pytest.raises(RecursionError):
            await dispatch_tool_call(tc, allow_config, session_id="s1")


# ---------------------------------------------------------------------------
# 27. Pending confirmation identity / expiry enforcement
# ---------------------------------------------------------------------------


class TestPendingConfirmationEnforcement:
    """Dispatch must verify pending_confirmation identity and expiry itself.

    Callers are no longer the sole line of defence: a stale or mismatched
    confirmation object must not unlock a different write action.
    """

    async def test_mismatched_tool_rejected(self, confirm_config: PermissionsConfig) -> None:
        """pending_confirmation for a different tool is rejected as deny."""
        register_tool("gmail", "read", "Read", SampleArgs)(sample_handler)
        # Confirmation was issued for a DIFFERENT tool.action
        other_tc = ToolCall(tool="files", action="write", args={"query": "test"})
        pending = _make_pending_confirmation(other_tc)
        # Now dispatch gmail.read with that stale/wrong confirmation
        tc = _make_tool_call()
        result = await dispatch_tool_call(
            tc, confirm_config, session_id="sess-1", pending_confirmation=pending
        )
        assert result.success is False
        assert result.permission.allowed == "deny"
        assert "does not match" in result.result.lower()

    async def test_mismatched_action_rejected(self, confirm_config: PermissionsConfig) -> None:
        """pending_confirmation for the same tool but different action is rejected."""
        register_tool("gmail", "read", "Read", SampleArgs)(sample_handler)
        other_tc = ToolCall(tool="gmail", action="list", args={"query": "test"})
        pending = _make_pending_confirmation(other_tc)
        tc = _make_tool_call()
        result = await dispatch_tool_call(
            tc, confirm_config, session_id="sess-1", pending_confirmation=pending
        )
        assert result.success is False
        assert result.permission.allowed == "deny"

    async def test_mismatched_confirmation_handler_not_called(
        self, confirm_config: PermissionsConfig
    ) -> None:
        """Handler must not execute when pending_confirmation identity mismatches."""
        called = False

        async def spy_handler(args: SampleArgs, *, session_id: str) -> str:
            nonlocal called
            called = True
            return "run"

        register_tool("gmail", "read", "Read", SampleArgs)(spy_handler)
        other_tc = ToolCall(tool="files", action="write", args={"query": "test"})
        pending = _make_pending_confirmation(other_tc)
        tc = _make_tool_call()
        await dispatch_tool_call(
            tc, confirm_config, session_id="sess-1", pending_confirmation=pending
        )
        assert called is False

    async def test_expired_pending_confirmation_rejected(
        self, confirm_config: PermissionsConfig
    ) -> None:
        """A pending_confirmation past expires_at is rejected as deny."""
        register_tool("gmail", "read", "Read", SampleArgs)(sample_handler)
        tc = _make_tool_call()
        # Build an expired confirmation: created 10 minutes ago, expired 5 minutes ago
        now = datetime.now(UTC)
        pending = PendingConfirmation(
            confirmation_id="confirm-expired",
            session_id="sess-1",
            tool_call=tc,
            created_at=now - timedelta(minutes=10),
            expires_at=now - timedelta(minutes=5),
        )
        result = await dispatch_tool_call(
            tc, confirm_config, session_id="sess-1", pending_confirmation=pending
        )
        assert result.success is False
        assert result.permission.allowed == "deny"
        assert "expired" in result.result.lower()

    async def test_expired_confirmation_handler_not_called(
        self, confirm_config: PermissionsConfig
    ) -> None:
        """Handler must not execute when pending_confirmation has expired."""
        called = False

        async def spy_handler(args: SampleArgs, *, session_id: str) -> str:
            nonlocal called
            called = True
            return "run"

        register_tool("gmail", "read", "Read", SampleArgs)(spy_handler)
        tc = _make_tool_call()
        now = datetime.now(UTC)
        pending = PendingConfirmation(
            confirmation_id="confirm-expired",
            session_id="sess-1",
            tool_call=tc,
            created_at=now - timedelta(minutes=10),
            expires_at=now - timedelta(minutes=5),
        )
        await dispatch_tool_call(
            tc, confirm_config, session_id="sess-1", pending_confirmation=pending
        )
        assert called is False


# ---------------------------------------------------------------------------
# 28. check_permission isolation spy
# ---------------------------------------------------------------------------


class TestCheckPermissionIsolation:
    """check_permission must be called with ONLY (tool, action, config).

    The permission engine must never see LLM args, session state, or
    conversation history. This spy test enforces the invariant.
    """

    async def test_check_permission_called_with_tool_action_config_only(
        self,
        allow_config: PermissionsConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Assert check_permission receives exactly (str, str, PermissionsConfig)."""
        from admino.permissions import PermissionResult
        from admino.permissions import check_permission as real_check
        from admino.tools import registry as reg

        captured: list[tuple[object, ...]] = []
        captured_kwargs: list[dict[str, object]] = []

        def spy(*args: object, **kwargs: object) -> PermissionResult:
            captured.append(args)
            captured_kwargs.append(kwargs)
            return real_check(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(reg, "check_permission", spy)
        register_tool("gmail", "read", "Read", SampleArgs)(sample_handler)
        tc = _make_tool_call(args={"query": "sensitive-value-should-not-reach-engine"})
        await dispatch_tool_call(tc, allow_config, session_id="sess-1")

        assert len(captured) == 1
        positional = captured[0]
        # Exactly three positional args
        assert len(positional) == 3
        assert positional[0] == "gmail"
        assert positional[1] == "read"
        assert positional[2] is allow_config
        # No kwargs snuck in
        assert captured_kwargs[0] == {}
        # Defence-in-depth: no arg value passed
        for value in positional:
            assert "sensitive-value-should-not-reach-engine" not in repr(value)


# ---------------------------------------------------------------------------
# 29. Handler exception logging must not pass exc_info
# ---------------------------------------------------------------------------


class TestHandlerExceptionLogHasNoExcInfo:
    """logger.error for handler exceptions must NOT include exc_info.

    An exception traceback could embed credentials or filesystem paths from
    arbitrary tool handlers. Only the exception type name is safe to log.
    """

    async def test_logger_error_not_called_with_exc_info(
        self,
        allow_config: PermissionsConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Spy logger.error and assert no call used exc_info."""
        from admino.tools import registry as reg

        calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

        def spy(*args: object, **kwargs: object) -> None:
            calls.append((args, kwargs))

        monkeypatch.setattr(reg.logger, "error", spy)
        register_tool("gmail", "read", "Read", SampleArgs)(failing_handler)
        tc = _make_tool_call()
        await dispatch_tool_call(tc, allow_config, session_id="sess-1")

        assert len(calls) >= 1
        for _args, kwargs in calls:
            # exc_info=True would embed the raw exception message in logs
            assert kwargs.get("exc_info") in (None, False)


# ---------------------------------------------------------------------------
# 30. Registry freeze
# ---------------------------------------------------------------------------


class TestFreezeRegistry:
    """freeze_registry() blocks further registrations."""

    def test_freeze_blocks_new_registration(self) -> None:
        """After freeze, register_tool raises RuntimeError."""
        from admino.tools.registry import freeze_registry

        register_tool("gmail", "read", "Read", SampleArgs)(sample_handler)
        freeze_registry()
        with pytest.raises(RuntimeError, match="frozen"):
            register_tool("weather", "fetch", "Fetch", SampleArgs)(sample_handler)
        # autouse clear_registry fixture resets the frozen flag after the test

    def test_clear_registry_unfreezes(self) -> None:
        """clear_registry() resets the frozen flag so tests can continue."""
        from admino.tools.registry import freeze_registry

        freeze_registry()
        clear_registry()
        # Should no longer raise
        register_tool("gmail", "read", "Read", SampleArgs)(sample_handler)
        assert get_tool_entry("gmail", "read") is not None


# ---------------------------------------------------------------------------
# 31. Audit log entries from dispatch
# ---------------------------------------------------------------------------


class _SpyAuditLogger:
    """In-memory audit logger spy for dispatch tests.

    Structurally compatible with admino.audit.AuditLogger — exposes only
    log_tool_call() since that is all dispatch uses. No disk I/O.
    """

    def __init__(self) -> None:
        from admino.models import ToolCallAuditEntry

        self.entries: list[ToolCallAuditEntry] = []

    def log_tool_call(self, entry: object) -> None:
        self.entries.append(entry)  # type: ignore[arg-type]


class TestDispatchAuditLogging:
    """Every dispatch path writes a ToolCallAuditEntry when audit_logger is set."""

    async def test_audit_entry_on_success(
        self, registered_tool: None, allow_config: PermissionsConfig
    ) -> None:
        """Successful dispatch writes an audit entry with success=True."""
        spy = _SpyAuditLogger()
        tc = _make_tool_call()
        await dispatch_tool_call(
            tc,
            allow_config,
            session_id="sess-1",
            audit_logger=spy,  # type: ignore[arg-type]
        )
        assert len(spy.entries) == 1
        e = spy.entries[0]
        assert e.tool == "gmail"
        assert e.action == "read"
        assert e.permission == "allow"
        assert e.success is True
        assert e.error is None

    async def test_audit_entry_on_permission_deny(
        self, registered_tool: None, deny_config: PermissionsConfig
    ) -> None:
        """Permission-denied dispatch writes an audit entry with success=False."""
        spy = _SpyAuditLogger()
        tc = _make_tool_call()
        await dispatch_tool_call(
            tc,
            deny_config,
            session_id="sess-1",
            audit_logger=spy,  # type: ignore[arg-type]
        )
        assert len(spy.entries) == 1
        assert spy.entries[0].permission == "deny"
        assert spy.entries[0].success is False

    async def test_audit_entry_on_confirm_required(
        self, registered_tool: None, confirm_config: PermissionsConfig
    ) -> None:
        """Confirmation-required dispatch writes an audit entry."""
        spy = _SpyAuditLogger()
        tc = _make_tool_call()
        await dispatch_tool_call(
            tc,
            confirm_config,
            session_id="sess-1",
            audit_logger=spy,  # type: ignore[arg-type]
        )
        assert len(spy.entries) == 1
        assert spy.entries[0].permission == "confirm"
        assert spy.entries[0].success is False

    async def test_audit_entry_on_unknown_tool(self, allow_config: PermissionsConfig) -> None:
        """Unknown tool dispatch writes an audit entry."""
        spy = _SpyAuditLogger()
        tc = _make_tool_call()
        await dispatch_tool_call(
            tc,
            allow_config,
            session_id="sess-1",
            audit_logger=spy,  # type: ignore[arg-type]
        )
        assert len(spy.entries) == 1
        assert spy.entries[0].success is False
        assert spy.entries[0].error is not None
        assert "unknown" in spy.entries[0].error.lower()

    async def test_audit_entry_on_validation_failure(
        self, registered_tool: None, allow_config: PermissionsConfig
    ) -> None:
        """Arg-validation failure writes an audit entry."""
        spy = _SpyAuditLogger()
        tc = _make_tool_call(args={"query": ""})  # violates min_length
        await dispatch_tool_call(
            tc,
            allow_config,
            session_id="sess-1",
            audit_logger=spy,  # type: ignore[arg-type]
        )
        assert len(spy.entries) == 1
        assert spy.entries[0].success is False

    async def test_audit_entry_on_handler_exception(self, allow_config: PermissionsConfig) -> None:
        """Handler exception writes an audit entry (no raw exception details)."""
        spy = _SpyAuditLogger()
        register_tool("gmail", "read", "Read", SampleArgs)(failing_handler)
        tc = _make_tool_call()
        await dispatch_tool_call(
            tc,
            allow_config,
            session_id="sess-1",
            audit_logger=spy,  # type: ignore[arg-type]
        )
        assert len(spy.entries) == 1
        entry = spy.entries[0]
        assert entry.success is False
        assert entry.error is not None
        assert "secrets.json" not in entry.error
        assert "RuntimeError" in entry.error

    async def test_audit_entry_on_malformed_identifier(
        self, allow_config: PermissionsConfig
    ) -> None:
        """Malformed tool identifier writes an audit entry with placeholder values."""
        spy = _SpyAuditLogger()
        tc = ToolCall.model_construct(tool="GMAIL", action="read", args={})
        await dispatch_tool_call(
            tc,
            allow_config,
            session_id="sess-1",
            audit_logger=spy,  # type: ignore[arg-type]
        )
        assert len(spy.entries) == 1
        # Placeholder values because original identifier is not pattern-valid
        assert spy.entries[0].tool == "invalid"
        assert spy.entries[0].success is False

    async def test_audit_entry_args_summary_contains_only_key_names(
        self, registered_tool: None, allow_config: PermissionsConfig
    ) -> None:
        """args_summary records key names only — never raw values."""
        spy = _SpyAuditLogger()
        secret_value = "ghp_1234567890abcdefghijklmnop"
        tc = _make_tool_call(args={"query": secret_value})
        await dispatch_tool_call(
            tc,
            allow_config,
            session_id="sess-1",
            audit_logger=spy,  # type: ignore[arg-type]
        )
        assert len(spy.entries) == 1
        assert "query" in spy.entries[0].args_summary
        assert secret_value not in spy.entries[0].args_summary

    async def test_audit_entry_on_pending_confirmation_mismatch(
        self, confirm_config: PermissionsConfig
    ) -> None:
        """Mismatched pending_confirmation writes a deny audit entry."""
        spy = _SpyAuditLogger()
        register_tool("gmail", "read", "Read", SampleArgs)(sample_handler)
        other_tc = ToolCall(tool="files", action="write", args={"query": "x"})
        pending = _make_pending_confirmation(other_tc)
        tc = _make_tool_call()
        await dispatch_tool_call(
            tc,
            confirm_config,
            session_id="sess-1",
            pending_confirmation=pending,
            audit_logger=spy,  # type: ignore[arg-type]
        )
        assert len(spy.entries) == 1
        assert spy.entries[0].permission == "deny"

    async def test_no_audit_entry_when_logger_is_none(
        self, registered_tool: None, allow_config: PermissionsConfig
    ) -> None:
        """audit_logger=None is allowed in dev/tests and writes nothing."""
        # Sanity check — this is the default behaviour that all other tests rely on.
        result = await dispatch_tool_call(
            _make_tool_call(), allow_config, session_id="sess-1", audit_logger=None
        )
        assert result.success is True


# ---------------------------------------------------------------------------
# 32. Production enforcement: audit_logger required when ADMINO_ENV=production
# ---------------------------------------------------------------------------


class TestProductionAuditEnforcement:
    """In production mode, dispatch must reject audit_logger=None."""

    async def test_production_requires_audit_logger(
        self,
        registered_tool: None,
        allow_config: PermissionsConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """audit_logger=None in production raises ValueError.

        ``_IS_PRODUCTION`` is cached at import time; monkey-patching the
        module attribute simulates production without reloading.
        """
        from admino.tools import registry as reg

        monkeypatch.setattr(reg, "_IS_PRODUCTION", True)
        tc = _make_tool_call()
        with pytest.raises(ValueError, match="audit_logger is required"):
            await dispatch_tool_call(tc, allow_config, session_id="sess-1", audit_logger=None)

    async def test_production_accepts_audit_logger(
        self,
        registered_tool: None,
        allow_config: PermissionsConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """In production, dispatch proceeds normally when audit_logger is supplied."""
        from admino.tools import registry as reg

        monkeypatch.setattr(reg, "_IS_PRODUCTION", True)
        spy = _SpyAuditLogger()
        tc = _make_tool_call()
        result = await dispatch_tool_call(
            tc,
            allow_config,
            session_id="sess-1",
            audit_logger=spy,  # type: ignore[arg-type]
        )
        assert result.success is True
        assert len(spy.entries) == 1
