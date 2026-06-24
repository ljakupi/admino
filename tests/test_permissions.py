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
    _CONFIRM_ONLY_ACTIONS,
    HARDCODED_DENIALS,
    IMMUTABLE_DENIALS,
    PROMOTABLE_DENIALS,
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
            "google_calendar": ToolPermissions(actions={"list": "allow", "create": "confirm"}),
            "files": ToolPermissions(actions={"read": "allow"}),
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
    sorted(HARDCODED_DENIALS),
    ids=[f"{t}.{a}" for t, a in sorted(HARDCODED_DENIALS)],
)
class TestHardcodedDenials:
    """All hardcoded denial pairs must return 'deny' no matter what."""

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
        sorted(HARDCODED_DENIALS),
        ids=[f"{t}-{a}" for t, a in sorted(HARDCODED_DENIALS)],
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
        assert any("gmail" in m and "send" in m for m in warning_messages)


# ---------------------------------------------------------------------------
# 9. validate_permissions_config passes clean config
# ---------------------------------------------------------------------------


class TestValidateCleanConfig:
    """No warnings when hardcoded denials are set to 'deny' or not present."""

    def test_no_warnings_on_clean_config(self, caplog: pytest.LogCaptureFixture) -> None:
        """A config with no overridden hardcoded denials produces no warnings."""
        raw: dict[str, dict[str, str]] = {
            "gmail": {"read": "allow", "list": "confirm", "send": "deny"},
            "files": {"read": "allow"},
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
            "google_calendar": {"list": "allow"},
        }
        config = validate_permissions_config(raw)
        assert config.tools["gmail"].actions["read"] == "allow"
        assert config.tools["gmail"].actions["list"] == "confirm"
        assert config.tools["google_calendar"].actions["list"] == "allow"


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

        forbidden_exact = {
            "agent",
            "llm",
            "server",
            "admino.agent",
            "admino.llm",
            "admino.server",
            "tools",
            "admino.tools",
            "importlib",
        }
        forbidden_prefixes = ("admino.tools.", "tools.")
        imported_modules: list[str] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.append(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_modules.append(node.module)

        violations = [
            m for m in imported_modules if m in forbidden_exact or m.startswith(forbidden_prefixes)
        ]

        # Also check for __import__() calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id == "__import__":
                    violations.append("__import__() call")

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
        raw: dict[str, dict[str, str]] = {"files": {"read": "maybe"}}
        with pytest.raises(ValueError):
            validate_permissions_config(raw)

    def test_empty_state_raises_validation_error(self) -> None:
        """An empty string state should raise ValueError."""
        raw: dict[str, dict[str, str]] = {"files": {"read": ""}}
        with pytest.raises(ValueError):
            validate_permissions_config(raw)


# ---------------------------------------------------------------------------
# Additional edge cases
# ---------------------------------------------------------------------------


class TestHardcodedDenialsConstant:
    """The HARDCODED_DENIALS constant contains the exact expected set."""

    def test_count(self) -> None:
        """HARDCODED_DENIALS contains the exact expected set."""
        expected = frozenset(
            {
                # Google
                ("gmail", "send"),
                ("gmail", "delete"),
                ("google_calendar", "delete"),
                ("google_calendar", "update"),
                ("google_drive", "delete"),
                # Microsoft
                ("outlook", "send"),
                ("outlook", "delete"),
                ("outlook_calendar", "delete"),
                ("outlook_calendar", "update"),
                ("onedrive", "delete"),
                # Local
                ("documents", "delete"),
                ("files", "delete"),
                # files.overwrite is modelled as a first-class denied action
                # so any LLM attempt is rejected at the permission layer with
                # a clear audit trail — see permissions.py.
                ("files", "overwrite"),
                ("memory", "delete"),
            }
        )
        assert expected == HARDCODED_DENIALS

    def test_files_overwrite_is_hardcoded_denied(self) -> None:
        """files.overwrite must be permanently denied, like files.delete.

        Regression guard: overwriting a file is semantically a delete-then-
        create, and since files.delete is hardcoded-denied, permitting
        overwrite would be a bypass of that invariant. This test exists to
        fail loudly if a future refactor removes the denial.
        """
        assert ("files", "overwrite") in HARDCODED_DENIALS

    def test_is_frozenset(self) -> None:
        """HARDCODED_DENIALS must be immutable (frozenset)."""
        assert isinstance(HARDCODED_DENIALS, frozenset)


class TestToolPermissionsDefaults:
    """ToolPermissions defaults to empty actions dict."""

    def test_default_actions_empty(self) -> None:
        """A ToolPermissions with no args has an empty actions dict."""
        tp = ToolPermissions()
        assert tp.actions == {}


# ---------------------------------------------------------------------------
# Confirm-only actions: write-mutating actions downgraded from allow to confirm
# ---------------------------------------------------------------------------


class TestConfirmOnlyActions:
    """Write-mutating actions cannot be set to 'allow' via YAML config."""

    @pytest.mark.parametrize(
        "tool,action",
        sorted(_CONFIRM_ONLY_ACTIONS - HARDCODED_DENIALS),
        ids=[f"{t}.{a}" for t, a in sorted(_CONFIRM_ONLY_ACTIONS - HARDCODED_DENIALS)],
    )
    def test_allow_downgraded_to_confirm(
        self, tool: str, action: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Setting a confirm-only action to 'allow' should be downgraded to 'confirm'."""
        raw = {tool: {action: "allow"}}
        with caplog.at_level(logging.WARNING):
            config = validate_permissions_config(raw)
        assert config.tools[tool].actions[action] == "confirm"
        assert "downgrading to 'confirm'" in caplog.text

    @pytest.mark.parametrize(
        "tool,action",
        sorted(_CONFIRM_ONLY_ACTIONS - HARDCODED_DENIALS),
        ids=[f"{t}.{a}" for t, a in sorted(_CONFIRM_ONLY_ACTIONS - HARDCODED_DENIALS)],
    )
    def test_confirm_stays_confirm(self, tool: str, action: str) -> None:
        """Setting a confirm-only action to 'confirm' is accepted as-is."""
        raw = {tool: {action: "confirm"}}
        config = validate_permissions_config(raw)
        assert config.tools[tool].actions[action] == "confirm"

    @pytest.mark.parametrize(
        "tool,action",
        sorted(_CONFIRM_ONLY_ACTIONS - HARDCODED_DENIALS),
        ids=[f"{t}.{a}" for t, a in sorted(_CONFIRM_ONLY_ACTIONS - HARDCODED_DENIALS)],
    )
    def test_deny_stays_deny(self, tool: str, action: str) -> None:
        """Setting a confirm-only action to 'deny' is accepted as-is."""
        raw = {tool: {action: "deny"}}
        config = validate_permissions_config(raw)
        assert config.tools[tool].actions[action] == "deny"

    def test_non_mutating_action_allows_allow(self) -> None:
        """A non-mutating action like gmail.read can be set to 'allow'."""
        raw = {"gmail": {"read": "allow"}}
        config = validate_permissions_config(raw)
        assert config.tools["gmail"].actions["read"] == "allow"

    def test_confirm_only_is_frozenset(self) -> None:
        """_CONFIRM_ONLY_ACTIONS is immutable."""
        assert isinstance(_CONFIRM_ONLY_ACTIONS, frozenset)


# ---------------------------------------------------------------------------
# Adversarial input tests
# ---------------------------------------------------------------------------


class TestAdversarialInputs:
    """Verify check_permission denies all malformed tool/action identifiers."""

    @pytest.mark.parametrize(
        ("tool", "action"),
        [
            ("", "delete"),  # empty tool
            ("gmail", ""),  # empty action
            ("gmail ", "send"),  # trailing space
            (" gmail", "send"),  # leading space
            ("GMAIL", "send"),  # uppercase
            ("gmail\x00", "send"),  # null byte
            ("g" * 300, "send"),  # overlength
            ("gmail\nsend", "read"),  # newline in tool
            ("gmail", "send\r"),  # carriage return in action
            ("1gmail", "send"),  # starts with digit
            ("gmail.evil", "send"),  # dot in tool name
        ],
    )
    def test_adversarial_inputs_denied(
        self, tool: str, action: str, empty_config: PermissionsConfig
    ) -> None:
        """Malformed tool/action identifiers must be denied."""
        result = check_permission(tool, action, empty_config)
        assert result.allowed == "deny"
        assert "invalid" in result.reason.lower()


# ---------------------------------------------------------------------------
# Hardcoded denials subset of confirm-only
# ---------------------------------------------------------------------------


class TestHardcodedDenialsSubsetOfConfirmOnly:
    """Every hardcoded denial must also be a confirm-only action."""

    def test_hardcoded_denials_subset_of_confirm_only(self) -> None:
        """HARDCODED_DENIALS must be a subset of _CONFIRM_ONLY_ACTIONS."""
        assert HARDCODED_DENIALS <= _CONFIRM_ONLY_ACTIONS


# ---------------------------------------------------------------------------
# End-to-end permission pipeline
# ---------------------------------------------------------------------------


class TestPermissionPipeline:
    """End-to-end: validate_permissions_config -> check_permission."""

    def test_hardcoded_denial_survives_pipeline(self) -> None:
        """A hardcoded denial set to 'allow' in raw config is still denied."""
        raw: dict[str, dict[str, str]] = {"gmail": {"send": "allow", "read": "allow"}}
        config = validate_permissions_config(raw)
        result = check_permission("gmail", "send", config)
        assert result.allowed == "deny"

    def test_allowed_action_survives_pipeline(self) -> None:
        """A normal 'allow' action passes through the full pipeline."""
        raw: dict[str, dict[str, str]] = {"gmail": {"read": "allow"}}
        config = validate_permissions_config(raw)
        result = check_permission("gmail", "read", config)
        assert result.allowed == "allow"

    def test_confirm_only_downgrade_in_pipeline(self) -> None:
        """A confirm-only action set to 'allow' is downgraded to 'confirm'."""
        raw: dict[str, dict[str, str]] = {"files": {"write": "allow"}}
        config = validate_permissions_config(raw)
        result = check_permission("files", "write", config)
        assert result.allowed == "confirm"


# ---------------------------------------------------------------------------
# Non-string YAML values
# ---------------------------------------------------------------------------


class TestValidateNonStringValues:
    """validate_permissions_config rejects non-string permission state values.

    Note: config.py pre-validates types via Pydantic before calling
    validate_permissions_config in production. These tests cover the
    function's standalone defensive behavior when called directly with
    raw dicts (e.g. from tests or non-YAML callers).
    """

    def test_boolean_state_raises(self) -> None:
        """A boolean value for permission state raises ValueError."""
        with pytest.raises((ValueError, ValidationError)):
            validate_permissions_config({"gmail": {"read": True}})  # type: ignore[dict-item]

    def test_integer_state_raises(self) -> None:
        """An integer value for permission state raises ValueError."""
        with pytest.raises((ValueError, ValidationError)):
            validate_permissions_config({"gmail": {"read": 123}})  # type: ignore[dict-item]

    def test_none_state_raises(self) -> None:
        """A None value for permission state raises ValueError."""
        with pytest.raises((ValueError, ValidationError)):
            validate_permissions_config({"gmail": {"read": None}})  # type: ignore[dict-item]


# ---------------------------------------------------------------------------
# Empty actions dict warning
# ---------------------------------------------------------------------------


class TestEmptyActionsWarning:
    """validate_permissions_config warns when a tool has an empty actions dict."""

    def test_empty_actions_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """A tool with no actions should log a warning."""
        with caplog.at_level(logging.WARNING):
            validate_permissions_config({"gmail": {}})
        assert any("no actions" in r.message.lower() for r in caplog.records)


# ---------------------------------------------------------------------------
# Invalid identifier rejection
# ---------------------------------------------------------------------------


class TestValidateRejectsInvalidIdentifiers:
    """validate_permissions_config rejects invalid tool/action names early."""

    def test_invalid_tool_name_rejected(self) -> None:
        """Uppercase tool name should be rejected."""
        with pytest.raises(ValueError, match="Invalid tool name"):
            validate_permissions_config({"GMAIL": {"read": "allow"}})

    def test_invalid_action_name_rejected(self) -> None:
        """Uppercase action name should be rejected."""
        with pytest.raises(ValueError, match="Invalid action name"):
            validate_permissions_config({"gmail": {"READ": "allow"}})

    def test_empty_tool_name_rejected(self) -> None:
        """Empty string tool name should be rejected."""
        with pytest.raises(ValueError, match="Invalid tool name"):
            validate_permissions_config({"": {"read": "allow"}})

    def test_tool_name_with_newline_rejected(self) -> None:
        """Tool name containing a newline should be rejected."""
        with pytest.raises(ValueError, match="Invalid tool name"):
            validate_permissions_config({"gmail\nfake": {"read": "allow"}})


# ---------------------------------------------------------------------------
# Promoted parameter (tier-2 promotable denials)
# ---------------------------------------------------------------------------


class TestPromotedParameter:
    """Tests for the `promoted` kwarg on check_permission — tier-2 promotable denials."""

    def test_promotable_denial_denied_by_default(self, empty_config: PermissionsConfig) -> None:
        """Promotable denial without promoted set returns deny."""
        result = check_permission("gmail", "send", empty_config)
        assert result.allowed == "deny"

    def test_promotable_denial_promoted_returns_confirm(
        self, empty_config: PermissionsConfig
    ) -> None:
        """Promotable denial with matching promoted entry returns confirm."""
        result = check_permission(
            "gmail", "send", empty_config, promoted=frozenset({("gmail", "send")})
        )
        assert result.allowed == "confirm"

    @pytest.mark.parametrize(
        ("tool", "action"),
        sorted(PROMOTABLE_DENIALS),
        ids=[f"{t}.{a}" for t, a in sorted(PROMOTABLE_DENIALS)],
    )
    def test_all_promotable_denials_can_be_promoted(
        self, tool: str, action: str, empty_config: PermissionsConfig
    ) -> None:
        """Each of the 4 promotable denials returns confirm when promoted."""
        result = check_permission(tool, action, empty_config, promoted=frozenset({(tool, action)}))
        assert result.allowed == "confirm"

    @pytest.mark.parametrize(
        ("tool", "action"),
        sorted(IMMUTABLE_DENIALS),
        ids=[f"{t}.{a}" for t, a in sorted(IMMUTABLE_DENIALS)],
    )
    def test_immutable_denial_cannot_be_promoted(
        self, tool: str, action: str, empty_config: PermissionsConfig
    ) -> None:
        """Immutable denials stay denied even if they appear in promoted set."""
        result = check_permission(tool, action, empty_config, promoted=frozenset({(tool, action)}))
        assert result.allowed == "deny"

    def test_promoted_set_does_not_affect_non_denial(
        self, sample_config: PermissionsConfig
    ) -> None:
        """Promoted set has no effect on actions that aren't in HARDCODED_DENIALS."""
        result = check_permission(
            "gmail", "read", sample_config, promoted=frozenset({("gmail", "read")})
        )
        assert result.allowed == "allow"

    def test_hardcoded_denials_is_union_of_immutable_and_promotable(self) -> None:
        """HARDCODED_DENIALS == IMMUTABLE_DENIALS | PROMOTABLE_DENIALS."""
        assert HARDCODED_DENIALS == IMMUTABLE_DENIALS | PROMOTABLE_DENIALS

    def test_immutable_and_promotable_are_disjoint(self) -> None:
        """IMMUTABLE_DENIALS and PROMOTABLE_DENIALS share no entries."""
        assert frozenset() == IMMUTABLE_DENIALS & PROMOTABLE_DENIALS

    def test_promotable_denials_has_exactly_4_entries(self) -> None:
        """There are exactly 4 promotable denials."""
        assert len(PROMOTABLE_DENIALS) == 4

    def test_immutable_denials_has_exactly_10_entries(self) -> None:
        """There are exactly 10 immutable denials."""
        assert len(IMMUTABLE_DENIALS) == 10

    def test_promoted_empty_frozenset_is_default(self, empty_config: PermissionsConfig) -> None:
        """Calling without promoted kwarg behaves same as promoted=frozenset()."""
        r1 = check_permission("gmail", "send", empty_config)
        r2 = check_permission("gmail", "send", empty_config, promoted=frozenset())
        assert r1.allowed == r2.allowed
