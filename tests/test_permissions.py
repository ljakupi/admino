"""Tests for the permission engine (admino.permissions).

Covers hardcoded denials, config-based decisions, default-deny behavior,
config validation with warning detection, architectural isolation,
pure-function properties, and model validation.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from admino.permissions import (
    HARDCODED_DENIALS,
    PermissionResult,
    PermissionsConfig,
    ToolPermissions,
    check_permission,
    validate_permissions_config,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def empty_config() -> PermissionsConfig:
    """An empty permissions config — no tools configured at all."""
    return PermissionsConfig()


@pytest.fixture()
def sample_config() -> PermissionsConfig:
    """A config with one allow, one confirm, and one deny action."""
    return PermissionsConfig(
        tools={
            "gmail": ToolPermissions(actions={"read": "allow", "list": "confirm"}),
            "calendar": ToolPermissions(actions={"list": "allow", "create": "confirm"}),
            "news": ToolPermissions(actions={"fetch": "allow"}),
            "documents": ToolPermissions(actions={"search": "deny"}),
        }
    )


def _build_config_with_hardcoded_allow(tool: str, action: str) -> PermissionsConfig:
    """Helper: build a config that sets a hardcoded-denial pair to 'allow'."""
    return PermissionsConfig(
        tools={
            tool: ToolPermissions(actions={action: "allow"}),
        }
    )


# ---------------------------------------------------------------------------
# 1. Hardcoded denials — parametrized
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "action"),
    [
        ("gmail", "send"),
        ("gmail", "delete"),
        ("calendar", "delete"),
        ("calendar", "update"),
        ("documents", "delete"),
    ],
    ids=[
        "gmail.send",
        "gmail.delete",
        "calendar.delete",
        "calendar.update",
        "documents.delete",
    ],
)
class TestHardcodedDenials:
    """All five hardcoded denial pairs must return 'deny' no matter what."""

    def test_denied_with_empty_config(
        self, tool: str, action: str, empty_config: PermissionsConfig
    ) -> None:
        """Hardcoded denials return deny even with an empty config."""
        result = check_permission(tool, action, empty_config)
        assert result.allowed == "deny"
        assert "hardcoded" in result.reason.lower()

    def test_denied_even_when_config_says_allow(self, tool: str, action: str) -> None:
        """Hardcoded denials return deny even when config explicitly sets allow."""
        config = _build_config_with_hardcoded_allow(tool, action)
        result = check_permission(tool, action, config)
        assert result.allowed == "deny"
        assert "hardcoded" in result.reason.lower()

    def test_denied_even_when_config_says_confirm(self, tool: str, action: str) -> None:
        """Hardcoded denials return deny even when config explicitly sets confirm."""
        config = PermissionsConfig(tools={tool: ToolPermissions(actions={action: "confirm"})})
        result = check_permission(tool, action, config)
        assert result.allowed == "deny"
        assert "hardcoded" in result.reason.lower()


# ---------------------------------------------------------------------------
# 2-4. Config allow / confirm / deny
# ---------------------------------------------------------------------------


class TestConfigAllow:
    """A configured 'allow' action returns allow."""

    def test_allow_returns_allow(self, sample_config: PermissionsConfig) -> None:
        """gmail.read configured as allow should return allow."""
        result = check_permission("gmail", "read", sample_config)
        assert result.allowed == "allow"
        assert "allow" in result.reason

    def test_allow_reason_mentions_action(self, sample_config: PermissionsConfig) -> None:
        """The reason string should reference the tool.action pair."""
        result = check_permission("gmail", "read", sample_config)
        assert "gmail.read" in result.reason


class TestConfigConfirm:
    """A configured 'confirm' action returns confirm."""

    def test_confirm_returns_confirm(self, sample_config: PermissionsConfig) -> None:
        """gmail.list configured as confirm should return confirm."""
        result = check_permission("gmail", "list", sample_config)
        assert result.allowed == "confirm"
        assert "confirm" in result.reason


class TestConfigDeny:
    """A configured 'deny' action returns deny."""

    def test_deny_returns_deny(self, sample_config: PermissionsConfig) -> None:
        """documents.search configured as deny should return deny."""
        result = check_permission("documents", "search", sample_config)
        assert result.allowed == "deny"
        assert "deny" in result.reason


# ---------------------------------------------------------------------------
# 5. Unlisted tool
# ---------------------------------------------------------------------------


class TestUnlistedTool:
    """A tool not in config returns deny (default deny)."""

    def test_unlisted_tool_is_denied(self, sample_config: PermissionsConfig) -> None:
        """A completely unknown tool should be denied."""
        result = check_permission("unknown_tool", "anything", sample_config)
        assert result.allowed == "deny"
        assert "not listed" in result.reason.lower()

    def test_unlisted_tool_reason_mentions_tool_name(
        self, sample_config: PermissionsConfig
    ) -> None:
        """The denial reason should mention the tool name."""
        result = check_permission("phantom", "read", sample_config)
        assert "phantom" in result.reason


# ---------------------------------------------------------------------------
# 6. Unlisted action (tool exists but action does not)
# ---------------------------------------------------------------------------


class TestUnlistedAction:
    """A tool exists in config but action is not listed returns deny."""

    def test_unlisted_action_is_denied(self, sample_config: PermissionsConfig) -> None:
        """gmail exists but 'forward' is not listed — should deny."""
        result = check_permission("gmail", "forward", sample_config)
        assert result.allowed == "deny"
        assert "not listed" in result.reason.lower()

    def test_unlisted_action_reason_mentions_action(self, sample_config: PermissionsConfig) -> None:
        """The denial reason should reference the tool.action pair."""
        result = check_permission("gmail", "forward", sample_config)
        assert "gmail.forward" in result.reason


# ---------------------------------------------------------------------------
# 7. Empty config — everything defaults to deny
# ---------------------------------------------------------------------------


class TestEmptyConfig:
    """Empty PermissionsConfig defaults everything to deny."""

    def test_any_tool_denied(self, empty_config: PermissionsConfig) -> None:
        """With no tools configured, any request is denied."""
        result = check_permission("gmail", "read", empty_config)
        assert result.allowed == "deny"

    def test_empty_config_has_no_tools(self, empty_config: PermissionsConfig) -> None:
        """The tools dict should be empty by default."""
        assert empty_config.tools == {}


# ---------------------------------------------------------------------------
# 8. validate_permissions_config warns on hardcoded override
# ---------------------------------------------------------------------------


class TestValidateWarnsOnOverride:
    """validate_permissions_config logs a warning when YAML overrides a hardcoded denial."""

    @pytest.mark.parametrize(
        ("tool", "action"),
        [
            ("gmail", "send"),
            ("gmail", "delete"),
            ("calendar", "delete"),
            ("calendar", "update"),
            ("documents", "delete"),
        ],
    )
    def test_warning_logged_when_override_attempted(
        self,
        caplog: pytest.LogCaptureFixture,
        tool: str,
        action: str,
    ) -> None:
        """Setting a hardcoded denial to 'allow' in YAML logs a warning."""
        raw: dict[str, dict[str, str]] = {tool: {action: "allow"}}
        with caplog.at_level(logging.WARNING, logger="admino.permissions"):
            config = validate_permissions_config(raw)

        assert any("hardcoded denial" in record.message for record in caplog.records)
        # The stored value must be 'deny' despite the YAML saying 'allow'
        assert config.tools[tool].actions[action] == "deny"

    def test_warning_includes_tool_and_action(self, caplog: pytest.LogCaptureFixture) -> None:
        """The warning message should mention which tool.action was overridden."""
        raw: dict[str, dict[str, str]] = {"gmail": {"send": "allow"}}
        with caplog.at_level(logging.WARNING, logger="admino.permissions"):
            validate_permissions_config(raw)

        warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warning_messages) >= 1
        assert "gmail" in warning_messages[0]
        assert "send" in warning_messages[0]


# ---------------------------------------------------------------------------
# 9. validate_permissions_config passes clean config
# ---------------------------------------------------------------------------


class TestValidateCleanConfig:
    """No warnings when hardcoded denials are set to 'deny' or not present."""

    def test_no_warnings_on_clean_config(self, caplog: pytest.LogCaptureFixture) -> None:
        """A config with no overridden hardcoded denials produces no warnings."""
        raw: dict[str, dict[str, str]] = {
            "gmail": {"read": "allow", "list": "confirm", "send": "deny"},
            "news": {"fetch": "allow"},
        }
        with caplog.at_level(logging.WARNING, logger="admino.permissions"):
            config = validate_permissions_config(raw)

        warning_records = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert len(warning_records) == 0
        assert config.tools["gmail"].actions["read"] == "allow"

    def test_clean_config_preserves_states(self) -> None:
        """validate_permissions_config preserves allow/confirm/deny states correctly."""
        raw: dict[str, dict[str, str]] = {
            "gmail": {"read": "allow", "list": "confirm"},
            "calendar": {"list": "allow"},
        }
        config = validate_permissions_config(raw)
        assert config.tools["gmail"].actions["read"] == "allow"
        assert config.tools["gmail"].actions["list"] == "confirm"
        assert config.tools["calendar"].actions["list"] == "allow"


# ---------------------------------------------------------------------------
# 10. No forbidden imports (architectural isolation)
# ---------------------------------------------------------------------------


class TestNoForbiddenImports:
    """permissions.py must not import from agent, llm, or server modules."""

    def test_no_imports_from_agent_llm_server(self) -> None:
        """Parse permissions.py AST and verify no imports from forbidden modules."""
        source_path = Path(__file__).resolve().parent.parent / "src" / "admino" / "permissions.py"
        source = source_path.read_text()
        tree = ast.parse(source)

        forbidden = {"agent", "llm", "server", "admino.agent", "admino.llm", "admino.server"}
        imported_modules: list[str] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.append(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_modules.append(node.module)

        violations = [m for m in imported_modules if m in forbidden]
        assert violations == [], f"Forbidden imports found: {violations}"


# ---------------------------------------------------------------------------
# 11. Pure function property
# ---------------------------------------------------------------------------


class TestPureFunctionProperty:
    """check_permission is a pure function — same inputs always produce same output."""

    def test_same_inputs_same_result(self, sample_config: PermissionsConfig) -> None:
        """Calling check_permission twice with identical args returns identical results."""
        result_a = check_permission("gmail", "read", sample_config)
        result_b = check_permission("gmail", "read", sample_config)
        assert result_a.allowed == result_b.allowed
        assert result_a.reason == result_b.reason

    def test_pure_for_deny_path(self, empty_config: PermissionsConfig) -> None:
        """Pure function property holds for the deny path too."""
        result_a = check_permission("unknown", "action", empty_config)
        result_b = check_permission("unknown", "action", empty_config)
        assert result_a == result_b

    def test_pure_for_hardcoded_denial(self, sample_config: PermissionsConfig) -> None:
        """Pure function property holds for hardcoded denials."""
        result_a = check_permission("gmail", "send", sample_config)
        result_b = check_permission("gmail", "send", sample_config)
        assert result_a == result_b


# ---------------------------------------------------------------------------
# 12. PermissionResult model validation
# ---------------------------------------------------------------------------


class TestPermissionResultValidation:
    """PermissionResult rejects invalid values for the 'allowed' field."""

    def test_valid_allow(self) -> None:
        """'allow' is accepted as a valid PermissionState."""
        result = PermissionResult(allowed="allow", reason="test")
        assert result.allowed == "allow"

    def test_valid_confirm(self) -> None:
        """'confirm' is accepted as a valid PermissionState."""
        result = PermissionResult(allowed="confirm", reason="test")
        assert result.allowed == "confirm"

    def test_valid_deny(self) -> None:
        """'deny' is accepted as a valid PermissionState."""
        result = PermissionResult(allowed="deny", reason="test")
        assert result.allowed == "deny"

    def test_invalid_allowed_value_raises(self) -> None:
        """An invalid string for 'allowed' raises ValidationError."""
        with pytest.raises(ValidationError, match="allowed"):
            PermissionResult(allowed="maybe", reason="test")  # type: ignore[arg-type]

    def test_empty_string_raises(self) -> None:
        """Empty string for 'allowed' raises ValidationError."""
        with pytest.raises(ValidationError):
            PermissionResult(allowed="", reason="test")  # type: ignore[arg-type]

    def test_reason_too_long_raises(self) -> None:
        """A reason exceeding max_length raises ValidationError."""
        with pytest.raises(ValidationError, match="reason"):
            PermissionResult(allowed="allow", reason="x" * 501)


# ---------------------------------------------------------------------------
# 13. validate_permissions_config with invalid state
# ---------------------------------------------------------------------------


class TestValidateInvalidState:
    """Passing an unknown permission state string raises ValidationError."""

    def test_invalid_state_raises_validation_error(self) -> None:
        """An unrecognized state like 'maybe' should raise ValueError."""
        raw: dict[str, dict[str, str]] = {"news": {"fetch": "maybe"}}
        with pytest.raises(ValueError):
            validate_permissions_config(raw)

    def test_empty_state_raises_validation_error(self) -> None:
        """An empty string state should raise ValueError."""
        raw: dict[str, dict[str, str]] = {"news": {"fetch": ""}}
        with pytest.raises(ValueError):
            validate_permissions_config(raw)


# ---------------------------------------------------------------------------
# Additional edge cases
# ---------------------------------------------------------------------------


class TestHardcodedDenialsConstant:
    """The HARDCODED_DENIALS constant is a frozenset with exactly 5 entries."""

    def test_count(self) -> None:
        """There should be exactly 5 hardcoded denial pairs."""
        assert len(HARDCODED_DENIALS) == 7

    def test_is_frozenset(self) -> None:
        """HARDCODED_DENIALS must be immutable (frozenset)."""
        assert isinstance(HARDCODED_DENIALS, frozenset)


class TestToolPermissionsDefaults:
    """ToolPermissions defaults to empty actions dict."""

    def test_default_actions_empty(self) -> None:
        """A ToolPermissions with no args has an empty actions dict."""
        tp = ToolPermissions()
        assert tp.actions == {}
