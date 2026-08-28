"""Tests for admino.config — YAML loading, validation, env overrides, and permissions loading.

Covers valid config loading, defaults, env var overrides, invalid YAML,
invalid field values, path resolution, permissions loading, missing permissions,
hardcoded denial overrides, invalid permission states, egress host validation,
and sub-model presence.
"""

from __future__ import annotations

import logging
import secrets
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from admino.config import (
    AppConfig,
    AuthConfig,
    DatabaseConfig,
    EgressConfig,
    LimitsConfig,
    LLMConfig,
    PathsConfig,
    ServerConfig,
    load_app_config,
    load_app_config_from_db,
    load_permissions_config_from_db,
)


@pytest.fixture()
def auth_token() -> str:
    """Generate a fresh high-entropy auth token for each test (min 48 chars, base64url)."""
    return secrets.token_urlsafe(48)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# A minimal valid llm section. The anthropic default provider requires a model
# (and ANTHROPIC_API_KEY, provided by the autouse conftest fixture), so configs
# that omit an llm section would otherwise fail validation.
_DEFAULT_TEST_LLM = 'llm:\n  provider: "anthropic"\n  anthropic_model: "claude-sonnet-4-6"\n'


def _write_yaml(path: Path, content: str) -> Path:
    """Write a YAML string to a file and return its path.

    Prepends a valid default llm section when the content omits one, so tests
    that don't care about the LLM provider still produce a loadable config.
    """
    text = textwrap.dedent(content)
    if "llm:" not in text:
        text = _DEFAULT_TEST_LLM + text
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# 1. Valid config loading
# ---------------------------------------------------------------------------


class TestValidConfigLoading:
    """A well-formed config.yaml is parsed into the correct AppConfig fields."""

    def test_all_fields_parsed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, auth_token: str
    ) -> None:
        """All explicitly set fields in YAML should be reflected in AppConfig."""
        # AUTH_TOKEN must be set when mode=token to pass the startup validator
        monkeypatch.setenv("AUTH_TOKEN", auth_token)
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            server:
              host: "127.0.0.1"
              port: 9090
            llm:
              provider: "anthropic"
              anthropic_model: "claude-sonnet-4-6"
              timeout_s: 60
            auth:
              mode: "token"
            paths:
              audit_log: "/data/audit.jsonl"
            limits:
              max_tool_calls_per_message: 5
              max_pending_confirmations: 2
              confirmation_timeout_s: 120
              max_message_length: 2000
              max_context_messages: 10
            egress:
              allowed_hosts:
                - "example.com"
            log_level: "DEBUG"
            """,
        )
        config = load_app_config(yaml_path)

        assert config.server.host == "127.0.0.1"
        assert config.server.port == 9090
        assert config.llm.anthropic_model == "claude-sonnet-4-6"
        assert config.llm.timeout_s == 60
        assert config.llm.provider == "anthropic"
        assert config.auth.mode == "token"
        assert config.paths.audit_log.is_absolute()
        assert str(config.paths.audit_log).endswith("audit.jsonl")
        assert config.limits.max_tool_calls_per_message == 5
        assert config.limits.max_pending_confirmations == 2
        assert config.limits.confirmation_timeout_s == 120
        assert config.limits.max_message_length == 2000
        assert config.limits.max_context_messages == 10
        assert config.egress.allowed_hosts == ["example.com"]
        assert config.log_level == "DEBUG"


# ---------------------------------------------------------------------------
# 2. Defaults when file is missing
# ---------------------------------------------------------------------------


class TestDefaults:
    """Defaults are applied to unset sections; an incomplete llm section fails."""

    def test_defaults_applied_for_unset_sections(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With a valid llm section, all other sections fall back to defaults."""
        monkeypatch.setenv("AUTH_MODE", "vpn")
        # _write_yaml injects a valid llm section for the empty body.
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))

        assert config.server.host == "0.0.0.0"  # noqa: S104
        assert config.server.port == 8000
        assert config.llm.provider == "anthropic"
        assert config.llm.timeout_s == 120
        assert config.auth.mode == "vpn"  # explicitly set via AUTH_MODE env
        assert config.limits.max_tool_calls_per_message == 10
        assert config.limits.confirmation_timeout_s == 300
        assert config.log_level == "INFO"

    def test_missing_file_without_llm_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A missing file yields defaults with an incomplete anthropic llm — invalid."""
        monkeypatch.setenv("AUTH_MODE", "vpn")
        with pytest.raises(ValueError, match="Invalid application config"):
            load_app_config(tmp_path / "nonexistent.yaml")

    def test_empty_yaml_without_llm_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty YAML file (parses as None) has no llm section — invalid."""
        monkeypatch.setenv("AUTH_MODE", "vpn")
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text("", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid application config"):
            load_app_config(yaml_path)

    def test_comment_only_yaml_without_llm_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A comment-only YAML file (parses as None) has no llm section — invalid."""
        monkeypatch.setenv("AUTH_MODE", "vpn")
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text("# just a comment\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid application config"):
            load_app_config(yaml_path)


# ---------------------------------------------------------------------------
# 3. Env var overrides
# ---------------------------------------------------------------------------


class TestEnvVarOverrides:
    """Environment variables override YAML values for supported fields."""

    def test_llm_provider_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """LLM_PROVIDER env var overrides llm.provider from YAML."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            llm:
              provider: "anthropic"
              anthropic_model: "claude-sonnet-4-6"
              openai_model: "gpt-4o"
            """,
        )
        monkeypatch.setenv("AUTH_MODE", "vpn")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
        monkeypatch.setenv("LLM_PROVIDER", "openai")
        config = load_app_config(yaml_path)
        assert config.llm.provider == "openai"

    def test_log_level_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """LOG_LEVEL env var overrides log_level from YAML."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            log_level: "INFO"
            """,
        )
        monkeypatch.setenv("AUTH_MODE", "vpn")
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
        monkeypatch.setenv("AUTH_MODE", "vpn")
        monkeypatch.setenv("AUDIT_LOG_PATH", "/env/audit.jsonl")
        config = load_app_config(yaml_path)
        assert config.paths.audit_log == Path("/env/audit.jsonl")

    def test_env_overrides_on_minimal_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Env vars apply on top of a minimal (llm-only) config."""
        monkeypatch.setenv("AUTH_MODE", "vpn")
        monkeypatch.setenv("LOG_LEVEL", "WARNING")
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert config.llm.provider == "anthropic"
        assert config.log_level == "WARNING"


# ---------------------------------------------------------------------------
# 4. Invalid YAML
# ---------------------------------------------------------------------------


class TestInvalidYaml:
    """Non-mapping or malformed YAML raises ValueError."""

    def test_non_mapping_root_list(self, tmp_path: Path) -> None:
        """A YAML list at root level raises ValueError."""
        # Written raw (no llm injection) — this tests parse-level rejection.
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text("- item1\n- item2\n", encoding="utf-8")
        with pytest.raises(ValueError, match="YAML mapping"):
            load_app_config(yaml_path)

    def test_non_mapping_root_string(self, tmp_path: Path) -> None:
        """A plain string YAML raises ValueError."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text("just a string\n", encoding="utf-8")
        with pytest.raises(ValueError, match="YAML mapping"):
            load_app_config(yaml_path)

    def test_non_mapping_root_integer(self, tmp_path: Path) -> None:
        """A bare integer YAML raises ValueError."""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text("42\n", encoding="utf-8")
        with pytest.raises(ValueError, match="YAML mapping"):
            load_app_config(yaml_path)

    def test_malformed_yaml_syntax_raises(self, tmp_path: Path) -> None:
        """Genuinely malformed YAML (syntax error) raises ValueError."""
        yaml_path = _write_yaml(tmp_path / "config.yaml", "key: [unclosed\n")
        with pytest.raises(ValueError, match="invalid YAML syntax"):
            load_app_config(yaml_path)


# ---------------------------------------------------------------------------
# 5. Invalid field values
# ---------------------------------------------------------------------------


class TestInvalidFieldValues:
    """Out-of-range or wrong-type values trigger ValidationError (wrapped in ValueError)."""

    @pytest.mark.parametrize(
        ("field_path", "value"),
        [
            ("server:\n  port: 0", "port below minimum"),
            ("server:\n  port: 70000", "port above maximum"),
            ("llm:\n  timeout_s: 0", "llm timeout below minimum"),
            ("log_level: 'TRACE'", "invalid log level"),
            ("limits:\n  max_tool_calls_per_message: 0", "below min"),
            ("limits:\n  confirmation_timeout_s: 5", "below min timeout"),
        ],
        ids=[
            "port_too_low",
            "port_too_high",
            "llm_timeout_too_low",
            "invalid_log_level",
            "tool_calls_below_min",
            "timeout_below_min",
        ],
    )
    def test_invalid_value_raises(self, tmp_path: Path, field_path: str, value: str) -> None:
        """Various invalid field values raise ValueError wrapping validation errors."""
        yaml_path = _write_yaml(tmp_path / "config.yaml", field_path + "\n")
        with pytest.raises(ValueError, match=r"Invalid application config.*field\(s\)"):
            load_app_config(yaml_path)


# ---------------------------------------------------------------------------
# 6. Path resolution — relative paths become absolute
# ---------------------------------------------------------------------------


class TestPathResolution:
    """Relative paths in YAML are resolved to absolute paths after loading."""

    def test_relative_paths_resolved(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Relative path values become absolute after model validation."""
        monkeypatch.setenv("AUTH_MODE", "vpn")
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            paths:
              audit_log: "relative/audit.jsonl"
            """,
        )
        config = load_app_config(yaml_path)

        assert config.paths.audit_log.is_absolute()

    def test_absolute_paths_stay_absolute(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Absolute paths remain unchanged after resolution."""
        monkeypatch.setenv("AUTH_MODE", "vpn")
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            paths:
              audit_log: "/absolute/audit.jsonl"
            """,
        )
        config = load_app_config(yaml_path)
        assert config.paths.audit_log == Path("/absolute/audit.jsonl")


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
        """A hostname at exactly 253 characters is accepted.

        Note: single-label hostnames (no dots) are technically accepted by
        the regex but are unlikely to resolve. The validator focuses on
        shell-safety, not DNS validity.
        """
        config = EgressConfig(allowed_hosts=["x" * 253])
        assert len(config.allowed_hosts) == 1

    def test_valid_dns_boundary_hostname(self) -> None:
        """A realistic multi-label hostname at exactly 253 chars is accepted."""
        # "a." * 126 + "a" = 253 chars with dots separating labels
        hostname = "a." * 126 + "a"
        assert len(hostname) == 253
        config = EgressConfig(allowed_hosts=[hostname])
        assert len(config.allowed_hosts) == 1

    def test_unsafe_characters_rejected(self) -> None:
        """Hostnames with shell-unsafe characters raise ValidationError."""
        with pytest.raises(ValidationError, match="Only alphanumeric"):
            EgressConfig(allowed_hosts=["valid.com", "; rm -rf /"])

    def test_semicolon_in_host_rejected(self) -> None:
        """A semicolon in a host entry is rejected to prevent shell injection."""
        with pytest.raises(ValidationError, match="Only alphanumeric"):
            EgressConfig(allowed_hosts=["evil.com;bad.com"])

    def test_invalid_egress_host_in_yaml_raises(self, tmp_path: Path) -> None:
        """An invalid egress host in config.yaml raises ValueError end-to-end."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            'egress:\n  allowed_hosts:\n    - "valid.com"\n    - ""',
        )
        with pytest.raises(ValueError, match=r"Invalid application config.*field\(s\)"):
            load_app_config(yaml_path)

    def test_consecutive_dots_rejected(self) -> None:
        """Hostnames with consecutive dots are rejected."""
        with pytest.raises(ValidationError, match="consecutive dots"):
            EgressConfig(allowed_hosts=["a..b.com"])


# ---------------------------------------------------------------------------
# 12. All AppConfig sub-models present
# ---------------------------------------------------------------------------


class TestSubModelsPresent:
    """A loaded AppConfig has all expected sub-model attributes."""

    def test_all_submodels_present(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Default AppConfig contains all sub-model instances."""
        monkeypatch.setenv("AUTH_MODE", "vpn")
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))

        assert isinstance(config.server, ServerConfig)
        assert isinstance(config.llm, LLMConfig)
        assert isinstance(config.auth, AuthConfig)
        assert isinstance(config.paths, PathsConfig)
        assert isinstance(config.limits, LimitsConfig)
        assert isinstance(config.egress, EgressConfig)


class TestUnimplementedToolScaffoldingRemoved:
    """The OCR/documents config scaffolding for unimplemented tools is gone (GH-84)."""

    def test_ocrconfig_symbol_removed(self) -> None:
        """OcrConfig no longer exists in admino.config."""
        import admino.config as config_module

        assert not hasattr(config_module, "OcrConfig")

    def test_appconfig_has_no_ocr_field(self) -> None:
        """AppConfig no longer carries an ocr section."""
        assert "ocr" not in AppConfig.model_fields

    def test_pathsconfig_has_no_images_field(self) -> None:
        """PathsConfig no longer carries the document-images path."""
        assert "images" not in PathsConfig.model_fields

    def test_leftover_ocr_and_images_db_settings_are_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A DB seeded before GH-84 (stale ocr row + paths.images) still loads.

        Pydantic ignores unknown keys, so an existing deployment with leftover
        ``ocr``/``images`` settings must not fail config validation.
        """
        monkeypatch.setenv("AUTH_MODE", "vpn")
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            paths:
              audit_log: "/data/audit.jsonl"
              images: "/data/images"
            ocr:
              binary: "/usr/bin/tesseract"
              languages: ["eng"]
            """,
        )
        config = load_app_config(yaml_path)
        assert not hasattr(config, "ocr")
        assert not hasattr(config.paths, "images")


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


class TestServerHostValidation:
    """ServerConfig.host validates IP addresses properly."""

    def test_valid_ipv4(self) -> None:
        config = ServerConfig(host="127.0.0.1")
        assert config.host == "127.0.0.1"

    def test_valid_ipv6(self) -> None:
        config = ServerConfig(host="::1")
        assert config.host == "::1"

    def test_localhost_accepted(self) -> None:
        config = ServerConfig(host="localhost")
        assert config.host == "localhost"

    def test_invalid_octet_rejected(self) -> None:
        """IP with octets > 255 should be rejected."""
        with pytest.raises(ValidationError):
            ServerConfig(host="999.999.999.999")

    def test_hostname_rejected(self) -> None:
        """Non-IP hostnames should be rejected."""
        with pytest.raises(ValidationError):
            ServerConfig(host="myserver.example.com")


class TestAuthConfigValidation:
    """AuthConfig token-mode startup validation."""

    def test_token_mode_requires_auth_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """mode=token fails if AUTH_TOKEN is absent."""
        monkeypatch.delenv("AUTH_TOKEN", raising=False)
        yaml_path = _write_yaml(tmp_path / "config.yaml", 'auth:\n  mode: "token"')
        with pytest.raises(ValueError):
            load_app_config(yaml_path)

    def test_token_mode_requires_min_48_chars(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """mode=token fails if AUTH_TOKEN is shorter than 48 chars."""
        monkeypatch.setenv("AUTH_TOKEN", "tooshort")
        yaml_path = _write_yaml(tmp_path / "config.yaml", 'auth:\n  mode: "token"')
        with pytest.raises(ValueError):
            load_app_config(yaml_path)

    def test_token_mode_accepts_strong_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, auth_token: str
    ) -> None:
        """mode=token succeeds when AUTH_TOKEN is at least 48 chars with sufficient entropy."""
        monkeypatch.setenv("AUTH_TOKEN", auth_token)
        yaml_path = _write_yaml(tmp_path / "config.yaml", 'auth:\n  mode: "token"')
        config = load_app_config(yaml_path)
        assert config.auth.mode == "token"

    def test_token_mode_rejects_low_entropy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """mode=token fails if AUTH_TOKEN has fewer than 20 unique chars.

        Uses a 48+ char token to isolate the entropy check from the length check.
        """
        # 19 unique chars repeated to reach 57 chars — passes length but fails entropy
        token = "abcdefghijklmnopqrs" * 3
        assert len(token) >= 48
        assert len(set(token)) == 19
        monkeypatch.setenv("AUTH_TOKEN", token)
        yaml_path = _write_yaml(tmp_path / "config.yaml", 'auth:\n  mode: "token"')
        with pytest.raises(ValueError, match="Invalid application config"):
            load_app_config(yaml_path)

    def test_token_with_exactly_19_unique_chars_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A 48+ char token with only 19 unique characters should fail entropy check."""
        # Build a token from exactly 19 distinct base64url chars, repeated to reach 48
        chars_19 = "abcdefghijklmnopqrs"
        assert len(set(chars_19)) == 19
        token = (chars_19 * 3)[:48]  # 48 chars, 19 unique
        assert len(token) >= 48
        assert len(set(token)) == 19
        monkeypatch.setenv("AUTH_TOKEN", token)
        yaml_path = _write_yaml(tmp_path / "config.yaml", 'auth:\n  mode: "token"')
        with pytest.raises(ValueError):
            load_app_config(yaml_path)

    def test_token_with_exactly_20_unique_chars_accepted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A 48+ char token with exactly 20 unique characters should pass."""
        chars_20 = "abcdefghijklmnopqrst"
        assert len(set(chars_20)) == 20
        token = (chars_20 * 3)[:48]  # 48 chars, 20 unique
        assert len(token) >= 48
        assert len(set(token)) == 20
        monkeypatch.setenv("AUTH_TOKEN", token)
        yaml_path = _write_yaml(tmp_path / "config.yaml", 'auth:\n  mode: "token"')
        config = load_app_config(yaml_path)
        assert config.auth.mode == "token"

    def test_token_length_47_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A 47-char token with high entropy should fail due to length."""
        # Use a high-entropy token but truncate to 47 chars
        token = secrets.token_urlsafe(48)[:47]
        monkeypatch.setenv("AUTH_TOKEN", token)
        yaml_path = _write_yaml(tmp_path / "config.yaml", 'auth:\n  mode: "token"')
        with pytest.raises(ValueError):
            load_app_config(yaml_path)

    def test_token_with_non_base64url_chars_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A 48+ char token containing non-base64url characters should fail."""
        # Start with a valid token and inject invalid chars
        token = secrets.token_urlsafe(48)
        bad_token = token[:46] + "!@"
        assert len(bad_token) >= 48
        monkeypatch.setenv("AUTH_TOKEN", bad_token)
        yaml_path = _write_yaml(tmp_path / "config.yaml", 'auth:\n  mode: "token"')
        with pytest.raises(ValueError):
            load_app_config(yaml_path)

    def test_vpn_mode_does_not_require_auth_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """mode=vpn succeeds even when AUTH_TOKEN is absent."""
        monkeypatch.delenv("AUTH_TOKEN", raising=False)
        yaml_path = _write_yaml(tmp_path / "config.yaml", 'auth:\n  mode: "vpn"')
        config = load_app_config(yaml_path)
        assert config.auth.mode == "vpn"

    def test_auth_token_not_leaked_in_exception(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The AUTH_TOKEN value must not appear in exception messages."""
        token = secrets.token_urlsafe(48)
        monkeypatch.setenv("AUTH_TOKEN", token)
        # Use an invalid port to trigger a validation error
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            "server:\n  port: 0\nauth:\n  mode: token",
        )
        with pytest.raises(ValueError) as exc_info:
            load_app_config(yaml_path)
        assert token not in str(exc_info.value)
        assert token not in str(exc_info.value.__cause__)

    def test_model_construct_bypasses_auth_validator(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Documents that model_construct bypasses security validators.

        Production code must NEVER use model_construct for AppConfig.
        """
        monkeypatch.delenv("AUTH_TOKEN", raising=False)
        # model_construct skips all validators, including validate_auth_token_present.
        # A valid llm is supplied so the llm default_factory (which does validate)
        # is not invoked.
        config = AppConfig.model_construct(
            auth=AuthConfig(mode="token"),
            llm=LLMConfig(provider="anthropic", anthropic_model="claude-sonnet-4-6"),
        )
        assert config.auth.mode == "token"


class TestLLMConfigValidation:
    """LLMConfig URL pattern, timeout, and provider validation."""

    def test_timeout_below_min_raises(self) -> None:
        """Timeout below 1 raises ValidationError."""
        with pytest.raises(ValidationError):
            LLMConfig(timeout_s=0)

    def test_timeout_above_max_raises(self) -> None:
        """Timeout above 600 raises ValidationError."""
        with pytest.raises(ValidationError):
            LLMConfig(timeout_s=601)

    def test_model_name_shell_chars_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Model name with shell metacharacters is rejected."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
        with pytest.raises(ValidationError, match="invalid characters"):
            LLMConfig(provider="anthropic", anthropic_model="evil; rm -rf /")

    def test_anthropic_requires_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Anthropic provider requires ANTHROPIC_API_KEY env var."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ValidationError, match="ANTHROPIC_API_KEY"):
            LLMConfig(provider="anthropic")

    def test_openai_requires_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """OpenAI provider requires OPENAI_API_KEY env var."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(ValidationError, match="OPENAI_API_KEY"):
            LLMConfig(provider="openai")

    def test_anthropic_with_api_key_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Anthropic provider with ANTHROPIC_API_KEY + model set passes validation."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
        config = LLMConfig(provider="anthropic", anthropic_model="claude-sonnet-4-6")
        assert config.provider == "anthropic"
        assert config.active_model_name == "claude-sonnet-4-6"

    def test_openai_with_api_key_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """OpenAI provider with OPENAI_API_KEY + model set passes validation."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
        config = LLMConfig(provider="openai", openai_model="gpt-4o")
        assert config.provider == "openai"
        assert config.active_model_name == "gpt-4o"

    # -- No hardcoded model defaults: the model must come from config --

    def test_model_fields_have_no_hardcoded_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The inactive-provider model field defaults to None, not a baked-in ID."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
        config = LLMConfig(provider="anthropic", anthropic_model="claude-sonnet-4-6")
        assert config.openai_model is None

    def test_anthropic_missing_model_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Anthropic provider without anthropic_model fails validation."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
        with pytest.raises(ValidationError, match="anthropic_model"):
            LLMConfig(provider="anthropic")

    def test_anthropic_empty_model_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Anthropic provider with an empty model string fails validation."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
        with pytest.raises(ValidationError, match="anthropic_model"):
            LLMConfig(provider="anthropic", anthropic_model="")

    def test_openai_missing_model_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """OpenAI provider without openai_model fails validation."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
        with pytest.raises(ValidationError, match="openai_model"):
            LLMConfig(provider="openai")

    def test_active_model_name_missing_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """active_model_name raises defensively if the active model is unset.

        Validation normally guarantees a model, so the guard is only reachable
        by bypassing it via model_copy.
        """
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
        config = LLMConfig(provider="anthropic", anthropic_model="claude-sonnet-4-6")
        forced = config.model_copy(update={"anthropic_model": None})
        with pytest.raises(ValueError, match="No model configured"):
            _ = forced.active_model_name


# ---------------------------------------------------------------------------
# VPN mode + 0.0.0.0 warning
# ---------------------------------------------------------------------------


class TestVpnModeWarning:
    """Warn when binding to all interfaces with vpn auth (no app-layer auth)."""

    def test_vpn_on_all_interfaces_warns(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """vpn mode + 0.0.0.0 should produce a warning."""
        monkeypatch.delenv("AUTH_TOKEN", raising=False)
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            'server:\n  host: "0.0.0.0"\nauth:\n  mode: vpn',
        )
        with caplog.at_level(logging.WARNING):
            load_app_config(yaml_path)
        assert "unauthenticated on ALL network interfaces" in caplog.text

    def test_token_mode_no_warning(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        auth_token: str,
    ) -> None:
        """token mode + 0.0.0.0 should NOT produce the vpn warning."""
        monkeypatch.setenv("AUTH_TOKEN", auth_token)
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            'server:\n  host: "0.0.0.0"\nauth:\n  mode: token',
        )
        with caplog.at_level(logging.WARNING):
            load_app_config(yaml_path)
        assert "unauthenticated on ALL" not in caplog.text

    def test_localhost_vpn_no_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """vpn mode + localhost should NOT produce the warning."""
        monkeypatch.delenv("AUTH_TOKEN", raising=False)
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            'server:\n  host: "localhost"\nauth:\n  mode: vpn',
        )
        with caplog.at_level(logging.WARNING):
            load_app_config(yaml_path)
        assert "unauthenticated on ALL" not in caplog.text


# ---------------------------------------------------------------------------
# DatabaseConfig validation
# ---------------------------------------------------------------------------


class TestDatabaseConfig:
    """DatabaseConfig defaults and validation."""

    def test_database_config_defaults(self) -> None:
        """DatabaseConfig has correct default pool sizes."""
        config = DatabaseConfig()
        assert config.min_pool_size == 2
        assert config.max_pool_size == 5

    def test_database_config_in_app_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """AppConfig includes DatabaseConfig with defaults."""
        monkeypatch.setenv("AUTH_MODE", "vpn")
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert isinstance(config.database, DatabaseConfig)
        assert config.database.min_pool_size == 2
        assert config.database.max_pool_size == 5

    def test_paths_config_no_database_field(self) -> None:
        """PathsConfig no longer has a 'database' field."""
        paths = PathsConfig()
        assert not hasattr(paths, "database")


# ---------------------------------------------------------------------------
# Database-backed config loaders
# ---------------------------------------------------------------------------


class TestLoadAppConfigFromDb:
    """Tests for load_app_config_from_db()."""

    async def test_calls_load_settings_from_db(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """load_app_config_from_db calls load_settings_from_db and returns AppConfig."""
        mock_pool = MagicMock()
        mock_data: dict[str, object] = {
            "server": {"host": "127.0.0.1", "port": 8000},
            "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
            "auth": {"mode": "vpn"},
            "paths": {},
            "files": {},
            "limits": {},
            "egress": {},
            "database": {},
            "log_level": "INFO",
        }
        mock_load = AsyncMock(return_value=mock_data)
        monkeypatch.setenv("AUTH_MODE", "vpn")

        with patch("admino.database.load_settings_from_db", new=mock_load):
            result = await load_app_config_from_db(mock_pool)

        mock_load.assert_awaited_once_with(mock_pool)
        assert isinstance(result, AppConfig)
        assert result.server.host == "127.0.0.1"

    async def test_applies_env_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """load_app_config_from_db applies environment variable overrides."""
        mock_pool = MagicMock()
        mock_data: dict[str, object] = {
            "server": {},
            "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
            "auth": {"mode": "vpn"},
            "paths": {},
            "files": {},
            "limits": {},
            "egress": {},
            "database": {},
            "log_level": "INFO",
        }
        mock_load = AsyncMock(return_value=mock_data)
        monkeypatch.setenv("AUTH_MODE", "vpn")
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")

        with patch("admino.database.load_settings_from_db", new=mock_load):
            result = await load_app_config_from_db(mock_pool)

        assert result.log_level == "DEBUG"


class TestLoadPermissionsConfigFromDb:
    """Tests for load_permissions_config_from_db()."""

    async def test_calls_load_permissions_from_db(self) -> None:
        """load_permissions_config_from_db calls load_permissions_from_db and returns config."""
        mock_pool = MagicMock()
        mock_data = {
            "gmail": {"read": "allow", "list": "allow"},
            "memory": {"store": "allow", "recall": "allow", "list": "allow"},
        }
        mock_load = AsyncMock(return_value=mock_data)

        with patch("admino.database.load_permissions_from_db", new=mock_load):
            result = await load_permissions_config_from_db(mock_pool)

        mock_load.assert_awaited_once_with(mock_pool)
        assert result.tools["gmail"].actions["read"] == "allow"
        assert result.tools["memory"].actions["store"] == "allow"

    async def test_empty_permissions_returns_empty_config(self) -> None:
        """load_permissions_config_from_db handles empty permissions dict."""
        mock_pool = MagicMock()
        mock_load = AsyncMock(return_value={})

        with patch("admino.database.load_permissions_from_db", new=mock_load):
            result = await load_permissions_config_from_db(mock_pool)

        assert result.tools == {}


class TestProviderCleanup:
    """GH-111: Ollama removed; anthropic default; vLLM guarded 'coming soon'."""

    def test_default_provider_is_anthropic(self) -> None:
        """The shipped LLMConfig.provider default flips from ollama to anthropic."""
        assert LLMConfig.model_fields["provider"].default == "anthropic"

    def test_provider_ollama_is_rejected(self) -> None:
        """'ollama' is no longer a valid provider value."""
        with pytest.raises(ValidationError):
            LLMConfig(provider="ollama")

    def test_provider_vllm_raises_coming_soon(self) -> None:
        """'vllm' is accepted by the enum but guarded with a clear coming-soon error."""
        with pytest.raises(ValidationError, match="coming soon"):
            LLMConfig(provider="vllm")

    def test_no_ollama_url_field(self) -> None:
        """The ollama_url field is gone from LLMConfig."""
        assert "ollama_url" not in LLMConfig.model_fields

    def test_no_to_ollama_config_method(self) -> None:
        """The to_ollama_config helper is gone from LLMConfig."""
        assert not hasattr(LLMConfig, "to_ollama_config")
