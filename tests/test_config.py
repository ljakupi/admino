"""Tests for admino.config — YAML loading, validation, env overrides, and permissions loading.

Covers valid config loading, defaults, env var overrides, invalid YAML,
invalid field values, path resolution, permissions loading, missing permissions,
hardcoded denial overrides, invalid permission states, egress host validation,
and sub-model presence.
"""

from __future__ import annotations

import logging
import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from admino.config import (
    AuthConfig,
    EgressConfig,
    LimitsConfig,
    OcrConfig,
    OllamaConfig,
    PathsConfig,
    ServerConfig,
    load_app_config,
    load_permissions_config,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_yaml(path: Path, content: str) -> Path:
    """Write a YAML string to a file and return its path."""
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# 1. Valid config loading
# ---------------------------------------------------------------------------


class TestValidConfigLoading:
    """A well-formed config.yaml is parsed into the correct AppConfig fields."""

    def test_all_fields_parsed(self, tmp_path: Path) -> None:
        """All explicitly set fields in YAML should be reflected in AppConfig."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            server:
              host: "127.0.0.1"
              port: 9090
            ollama:
              url: "http://localhost:11434"
              model: "llama3"
              timeout_s: 60
            auth:
              mode: "token"
            paths:
              database: "/data/db.sqlite"
              audit_log: "/data/audit.jsonl"
              images: "/data/images"
              tokens_dir: "/data/tokens"
            limits:
              max_tool_calls_per_message: 5
              max_pending_confirmations: 2
              confirmation_timeout_s: 120
              max_message_length: 2000
              max_context_messages: 10
            egress:
              allowed_hosts:
                - "example.com"
            ocr:
              binary: "/usr/local/bin/tesseract"
              languages:
                - "eng"
                - "deu"
            log_level: "DEBUG"
            """,
        )
        config = load_app_config(yaml_path)

        assert config.server.host == "127.0.0.1"
        assert config.server.port == 9090
        assert config.ollama.url == "http://localhost:11434"
        assert config.ollama.model == "llama3"
        assert config.ollama.timeout_s == 60
        assert config.auth.mode == "token"
        assert config.paths.database == Path("/data/db.sqlite")
        assert config.paths.audit_log == Path("/data/audit.jsonl")
        assert config.limits.max_tool_calls_per_message == 5
        assert config.limits.max_pending_confirmations == 2
        assert config.limits.confirmation_timeout_s == 120
        assert config.limits.max_message_length == 2000
        assert config.limits.max_context_messages == 10
        assert config.egress.allowed_hosts == ["example.com"]
        assert config.ocr.languages == ["eng", "deu"]
        assert config.log_level == "DEBUG"


# ---------------------------------------------------------------------------
# 2. Defaults when file is missing
# ---------------------------------------------------------------------------


class TestDefaults:
    """When config file does not exist, AppConfig uses defaults."""

    def test_defaults_with_missing_file(self, tmp_path: Path) -> None:
        """load_app_config with a nonexistent path returns defaults."""
        config = load_app_config(tmp_path / "nonexistent.yaml")

        assert config.server.host == "0.0.0.0"  # noqa: S104
        assert config.server.port == 8000
        assert config.ollama.url == "http://ollama:11434"
        assert config.ollama.model == "qwen2.5-coder:14b"
        assert config.ollama.timeout_s == 120
        assert config.auth.mode == "vpn"
        assert config.limits.max_tool_calls_per_message == 10
        assert config.limits.confirmation_timeout_s == 300
        assert config.log_level == "INFO"

    def test_defaults_with_empty_yaml(self, tmp_path: Path) -> None:
        """An empty YAML file (parses as None) uses defaults."""
        yaml_path = _write_yaml(tmp_path / "config.yaml", "")
        config = load_app_config(yaml_path)
        assert config.server.port == 8000
        assert config.log_level == "INFO"


# ---------------------------------------------------------------------------
# 3. Env var overrides
# ---------------------------------------------------------------------------


class TestEnvVarOverrides:
    """Environment variables override YAML values for supported fields."""

    def test_ollama_base_url_override(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """OLLAMA_BASE_URL env var overrides ollama.url from YAML."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            ollama:
              url: "http://yaml-value:11434"
            """,
        )
        monkeypatch.setenv("OLLAMA_BASE_URL", "http://env-value:11434")
        config = load_app_config(yaml_path)
        assert config.ollama.url == "http://env-value:11434"

    def test_ollama_model_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """OLLAMA_MODEL env var overrides ollama.model from YAML."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            ollama:
              model: "yaml-model"
            """,
        )
        monkeypatch.setenv("OLLAMA_MODEL", "env-model")
        config = load_app_config(yaml_path)
        assert config.ollama.model == "env-model"

    def test_log_level_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """LOG_LEVEL env var overrides log_level from YAML."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            log_level: "INFO"
            """,
        )
        monkeypatch.setenv("LOG_LEVEL", "debug")
        config = load_app_config(yaml_path)
        assert config.log_level == "DEBUG"

    def test_audit_log_path_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """AUDIT_LOG_PATH env var overrides paths.audit_log from YAML."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            paths:
              audit_log: "/yaml/audit.jsonl"
            """,
        )
        monkeypatch.setenv("AUDIT_LOG_PATH", "/env/audit.jsonl")
        config = load_app_config(yaml_path)
        assert config.paths.audit_log == Path("/env/audit.jsonl")

    def test_env_overrides_on_missing_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Env vars work even when config file is missing (defaults + env)."""
        monkeypatch.setenv("OLLAMA_BASE_URL", "http://env-only:11434")
        monkeypatch.setenv("LOG_LEVEL", "WARNING")
        config = load_app_config(tmp_path / "nonexistent.yaml")
        assert config.ollama.url == "http://env-only:11434"
        assert config.log_level == "WARNING"


# ---------------------------------------------------------------------------
# 4. Invalid YAML
# ---------------------------------------------------------------------------


class TestInvalidYaml:
    """Non-mapping or malformed YAML raises ValueError."""

    def test_non_mapping_root_list(self, tmp_path: Path) -> None:
        """A YAML list at root level raises ValueError."""
        yaml_path = _write_yaml(tmp_path / "config.yaml", "- item1\n- item2\n")
        with pytest.raises(ValueError, match="YAML mapping"):
            load_app_config(yaml_path)

    def test_non_mapping_root_string(self, tmp_path: Path) -> None:
        """A plain string YAML raises ValueError."""
        yaml_path = _write_yaml(tmp_path / "config.yaml", "just a string\n")
        with pytest.raises(ValueError, match="YAML mapping"):
            load_app_config(yaml_path)

    def test_non_mapping_root_integer(self, tmp_path: Path) -> None:
        """A bare integer YAML raises ValueError."""
        yaml_path = _write_yaml(tmp_path / "config.yaml", "42\n")
        with pytest.raises(ValueError, match="YAML mapping"):
            load_app_config(yaml_path)


# ---------------------------------------------------------------------------
# 5. Invalid field values
# ---------------------------------------------------------------------------


class TestInvalidFieldValues:
    """Out-of-range or wrong-type values trigger ValidationError (wrapped in ValueError)."""

    @pytest.mark.parametrize(
        ("field_path", "value", "match"),
        [
            ("server:\n  port: 0", "port below minimum", "Invalid application config"),
            ("server:\n  port: 70000", "port above maximum", "Invalid application config"),
            ("ollama:\n  url: 'ftp://bad'", "bad URL scheme", "Invalid application config"),
            ("log_level: 'TRACE'", "invalid log level", "Invalid application config"),
            ("limits:\n  max_tool_calls_per_message: 0", "below min", "Invalid application config"),
            (
                "limits:\n  confirmation_timeout_s: 5",
                "below min timeout",
                "Invalid application config",
            ),
        ],
        ids=[
            "port_too_low",
            "port_too_high",
            "bad_url_scheme",
            "invalid_log_level",
            "tool_calls_below_min",
            "timeout_below_min",
        ],
    )
    def test_invalid_value_raises(
        self, tmp_path: Path, field_path: str, value: str, match: str
    ) -> None:
        """Various invalid field values raise ValueError wrapping validation errors."""
        yaml_path = _write_yaml(tmp_path / "config.yaml", field_path + "\n")
        with pytest.raises(ValueError, match=match):
            load_app_config(yaml_path)


# ---------------------------------------------------------------------------
# 6. Path resolution — relative paths become absolute
# ---------------------------------------------------------------------------


class TestPathResolution:
    """Relative paths in YAML are resolved to absolute paths after loading."""

    def test_relative_paths_resolved(self, tmp_path: Path) -> None:
        """Relative path values become absolute after model validation."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            paths:
              database: "relative/db.sqlite"
              audit_log: "relative/audit.jsonl"
              images: "relative/images"
              tokens_dir: "relative/tokens"
            ocr:
              binary: "relative/tesseract"
            """,
        )
        config = load_app_config(yaml_path)

        assert config.paths.database.is_absolute()
        assert config.paths.audit_log.is_absolute()
        assert config.paths.images.is_absolute()
        assert config.paths.tokens_dir.is_absolute()
        assert config.ocr.binary.is_absolute()

    def test_absolute_paths_stay_absolute(self, tmp_path: Path) -> None:
        """Absolute paths remain unchanged after resolution."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            paths:
              database: "/absolute/db.sqlite"
            """,
        )
        config = load_app_config(yaml_path)
        assert config.paths.database == Path("/absolute/db.sqlite")


# ---------------------------------------------------------------------------
# 7. Permissions loading — valid file
# ---------------------------------------------------------------------------


class TestPermissionsLoading:
    """A valid permissions.yaml is loaded and parsed correctly."""

    def test_valid_permissions_loaded(self, tmp_path: Path) -> None:
        """Valid permissions.yaml results in correct PermissionsConfig."""
        yaml_path = _write_yaml(
            tmp_path / "permissions.yaml",
            """\
            tools:
              gmail:
                read: allow
                list: confirm
              calendar:
                list: allow
                create: confirm
              news:
                fetch: allow
            """,
        )
        config = load_permissions_config(yaml_path)

        assert config.tools["gmail"].actions["read"] == "allow"
        assert config.tools["gmail"].actions["list"] == "confirm"
        assert config.tools["calendar"].actions["list"] == "allow"
        assert config.tools["calendar"].actions["create"] == "confirm"
        assert config.tools["news"].actions["fetch"] == "allow"

    def test_permissions_with_deny(self, tmp_path: Path) -> None:
        """Explicit deny in permissions.yaml is preserved."""
        yaml_path = _write_yaml(
            tmp_path / "permissions.yaml",
            """\
            tools:
              documents:
                search: deny
            """,
        )
        config = load_permissions_config(yaml_path)
        assert config.tools["documents"].actions["search"] == "deny"


# ---------------------------------------------------------------------------
# 8. Missing permissions file
# ---------------------------------------------------------------------------


class TestMissingPermissionsFile:
    """load_permissions_config raises FileNotFoundError for missing file."""

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        """A nonexistent permissions.yaml raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="Permissions config not found"):
            load_permissions_config(tmp_path / "nonexistent.yaml")


# ---------------------------------------------------------------------------
# 9. Hardcoded denial override in permissions
# ---------------------------------------------------------------------------


class TestHardcodedDenialOverride:
    """Attempting to set a hardcoded denial to allow logs a warning and stores deny."""

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
    def test_hardcoded_denial_overridden_to_deny(
        self,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
        tool: str,
        action: str,
    ) -> None:
        """Setting a hardcoded denial pair to 'allow' in YAML -> warning + stored as deny."""
        yaml_path = _write_yaml(
            tmp_path / "permissions.yaml",
            f"""\
            tools:
              {tool}:
                {action}: allow
            """,
        )
        with caplog.at_level(logging.WARNING, logger="admino.permissions"):
            config = load_permissions_config(yaml_path)

        assert config.tools[tool].actions[action] == "deny"
        assert any("hardcoded denial" in r.message for r in caplog.records)

    def test_warning_mentions_tool_and_action(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The warning message includes the tool and action names."""
        yaml_path = _write_yaml(
            tmp_path / "permissions.yaml",
            """\
            tools:
              gmail:
                send: allow
            """,
        )
        with caplog.at_level(logging.WARNING, logger="admino.permissions"):
            load_permissions_config(yaml_path)

        warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) >= 1
        assert "gmail" in warnings[0]
        assert "send" in warnings[0]


# ---------------------------------------------------------------------------
# 10. Invalid permission states
# ---------------------------------------------------------------------------


class TestInvalidPermissionStates:
    """Permission state not in allow/confirm/deny raises ValueError."""

    @pytest.mark.parametrize(
        "state",
        ["maybe", "block", "ALLOW", "Allow", ""],
        ids=["maybe", "block", "ALLOW_uppercase", "Allow_mixed", "empty"],
    )
    def test_invalid_state_raises(self, tmp_path: Path, state: str) -> None:
        """An unrecognized permission state raises ValueError."""
        yaml_path = _write_yaml(
            tmp_path / "permissions.yaml",
            f"""\
            tools:
              news:
                fetch: {state if state else '""'}
            """,
        )
        with pytest.raises(ValueError, match=r"Invalid permission state|must be"):
            load_permissions_config(yaml_path)


# ---------------------------------------------------------------------------
# 11. Egress host validation
# ---------------------------------------------------------------------------


class TestEgressHostValidation:
    """Empty string or too-long hostname in egress.allowed_hosts raises ValidationError."""

    def test_empty_host_raises(self) -> None:
        """An empty string in allowed_hosts raises ValidationError."""
        with pytest.raises(ValidationError, match="Invalid host entry"):
            EgressConfig(allowed_hosts=["valid.com", ""])

    def test_too_long_host_raises(self) -> None:
        """A hostname exceeding 253 characters raises ValidationError."""
        with pytest.raises(ValidationError, match="Invalid host entry"):
            EgressConfig(allowed_hosts=["x" * 254])

    def test_valid_hosts_accepted(self) -> None:
        """Valid hostnames pass validation without error."""
        config = EgressConfig(allowed_hosts=["example.com", "*.googleapis.com"])
        assert len(config.allowed_hosts) == 2

    def test_max_length_host_accepted(self) -> None:
        """A hostname at exactly 253 characters is accepted."""
        config = EgressConfig(allowed_hosts=["x" * 253])
        assert len(config.allowed_hosts) == 1

    def test_unsafe_characters_rejected(self) -> None:
        """Hostnames with shell-unsafe characters raise ValidationError."""
        with pytest.raises(ValidationError, match="Only alphanumeric"):
            EgressConfig(allowed_hosts=["valid.com", "; rm -rf /"])

    def test_semicolon_in_host_rejected(self) -> None:
        """A semicolon in a host entry is rejected to prevent shell injection."""
        with pytest.raises(ValidationError, match="Only alphanumeric"):
            EgressConfig(allowed_hosts=["evil.com;bad.com"])


# ---------------------------------------------------------------------------
# 12. All AppConfig sub-models present
# ---------------------------------------------------------------------------


class TestSubModelsPresent:
    """A loaded AppConfig has all expected sub-model attributes."""

    def test_all_submodels_present(self, tmp_path: Path) -> None:
        """Default AppConfig contains all sub-model instances."""
        config = load_app_config(tmp_path / "nonexistent.yaml")

        assert isinstance(config.server, ServerConfig)
        assert isinstance(config.ollama, OllamaConfig)
        assert isinstance(config.auth, AuthConfig)
        assert isinstance(config.paths, PathsConfig)
        assert isinstance(config.limits, LimitsConfig)
        assert isinstance(config.egress, EgressConfig)
        assert isinstance(config.ocr, OcrConfig)


# ---------------------------------------------------------------------------
# Additional edge cases
# ---------------------------------------------------------------------------


class TestPermissionsYamlEdgeCases:
    """Edge cases in permissions.yaml parsing."""

    def test_non_mapping_root_raises(self, tmp_path: Path) -> None:
        """A permissions.yaml with a list root raises ValueError."""
        yaml_path = _write_yaml(tmp_path / "permissions.yaml", "- item\n")
        with pytest.raises(ValueError, match="YAML mapping"):
            load_permissions_config(yaml_path)

    def test_missing_tools_key_raises(self, tmp_path: Path) -> None:
        """A permissions.yaml without a 'tools' key raises ValueError."""
        yaml_path = _write_yaml(
            tmp_path / "permissions.yaml",
            """\
            other_key:
              foo: bar
            """,
        )
        with pytest.raises(ValueError, match="tools"):
            load_permissions_config(yaml_path)

    def test_tools_not_mapping_raises(self, tmp_path: Path) -> None:
        """A permissions.yaml with 'tools' as a list raises ValueError."""
        yaml_path = _write_yaml(
            tmp_path / "permissions.yaml",
            """\
            tools:
              - gmail
              - calendar
            """,
        )
        with pytest.raises(ValueError, match="mapping"):
            load_permissions_config(yaml_path)

    def test_tool_actions_not_mapping_raises(self, tmp_path: Path) -> None:
        """A tool with a non-mapping value for actions raises ValueError."""
        yaml_path = _write_yaml(
            tmp_path / "permissions.yaml",
            """\
            tools:
              gmail: "not_a_mapping"
            """,
        )
        with pytest.raises(ValueError, match="mapping"):
            load_permissions_config(yaml_path)


class TestOcrConfigValidation:
    """OcrConfig language validation edge cases."""

    def test_empty_language_code_raises(self) -> None:
        """An empty language code string raises ValidationError."""
        with pytest.raises(ValidationError, match="Invalid language code"):
            OcrConfig(languages=[""])

    def test_too_long_language_code_raises(self) -> None:
        """A language code exceeding 10 characters raises ValidationError."""
        with pytest.raises(ValidationError, match="Invalid language code"):
            OcrConfig(languages=["x" * 11])

    def test_valid_languages_accepted(self) -> None:
        """Valid language codes pass validation."""
        config = OcrConfig(languages=["eng", "deu", "fra"])
        assert config.languages == ["eng", "deu", "fra"]


class TestServerConfigValidation:
    """ServerConfig field boundary validation."""

    def test_port_boundary_low(self) -> None:
        """Port 1 is the minimum valid value."""
        config = ServerConfig(port=1)
        assert config.port == 1

    def test_port_boundary_high(self) -> None:
        """Port 65535 is the maximum valid value."""
        config = ServerConfig(port=65535)
        assert config.port == 65535

    def test_port_zero_raises(self) -> None:
        """Port 0 is below minimum and raises ValidationError."""
        with pytest.raises(ValidationError):
            ServerConfig(port=0)

    def test_port_above_max_raises(self) -> None:
        """Port 65536 is above maximum and raises ValidationError."""
        with pytest.raises(ValidationError):
            ServerConfig(port=65536)


class TestOllamaConfigValidation:
    """OllamaConfig URL pattern and timeout validation."""

    def test_ftp_url_rejected(self) -> None:
        """A URL not starting with http(s):// is rejected."""
        with pytest.raises(ValidationError, match="url"):
            OllamaConfig(url="ftp://bad:11434")

    def test_timeout_below_min_raises(self) -> None:
        """Timeout below 1 raises ValidationError."""
        with pytest.raises(ValidationError):
            OllamaConfig(timeout_s=0)

    def test_timeout_above_max_raises(self) -> None:
        """Timeout above 600 raises ValidationError."""
        with pytest.raises(ValidationError):
            OllamaConfig(timeout_s=601)


# ---------------------------------------------------------------------------
# 13. Non-string tool name in permissions (covers lines 354-355)
# ---------------------------------------------------------------------------


class TestNonStringToolName:
    """YAML allows non-string keys; the loader must reject them."""

    def test_integer_tool_name_raises_valueerror(self, tmp_path: Path) -> None:
        """An integer tool key in permissions.yaml raises ValueError mentioning the type."""
        yaml_path = _write_yaml(
            tmp_path / "permissions.yaml",
            """\
            tools:
              123:
                read: allow
            """,
        )
        with pytest.raises(ValueError, match="Tool name must be a string, got int"):
            load_permissions_config(yaml_path)

    def test_boolean_tool_name_raises_valueerror(self, tmp_path: Path) -> None:
        """A boolean tool key (YAML `true`) raises ValueError mentioning 'bool'."""
        yaml_path = _write_yaml(
            tmp_path / "permissions.yaml",
            """\
            tools:
              true:
                read: allow
            """,
        )
        with pytest.raises(ValueError, match="Tool name must be a string, got bool"):
            load_permissions_config(yaml_path)

    def test_float_tool_name_raises_valueerror(self, tmp_path: Path) -> None:
        """A float tool key raises ValueError mentioning 'float'."""
        yaml_path = _write_yaml(
            tmp_path / "permissions.yaml",
            """\
            tools:
              3.14:
                read: allow
            """,
        )
        with pytest.raises(ValueError, match="Tool name must be a string, got float"):
            load_permissions_config(yaml_path)
