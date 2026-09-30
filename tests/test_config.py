"""Tests for admino.config — YAML loading, validation, env overrides, and permissions loading.

Covers valid config loading, defaults, env var overrides, invalid YAML,
invalid field values, path resolution, permissions loading, missing permissions,
hardcoded denial overrides, invalid permission states, egress host validation,
and sub-model presence.

GH-142: ``infomaniak`` is a provider and the default. A missing API key/token or
model never fails validation for any provider any more — it logs a WARNING that
names the env var / model field (never a value) and chat explains what to set.
``active_model_name`` returns ``""`` when the active provider's model is unset.

GH-149: the old auth is gone. ``AuthConfig`` / ``AppConfig.auth``, the
``AUTH_MODE`` override, the ``AUTH_TOKEN`` startup validation and the vpn
warning no longer exist; an old ``auth:`` section (YAML or DB row) is ignored
without error and the ``AUTH_TOKEN`` / ``AUTH_MODE`` env vars have no effect.
``ServerConfig.cookie_secure`` (default True) controls the session cookie's
``Secure`` flag; the ``COOKIE_SECURE`` env var overrides it
(true/1/yes/on -> True, false/0/no/off -> False, case-insensitive; any other
value logs a warning and is ignored).

GH-151: ``ServerConfig.public_url`` is the base of password reset (and later
invitation) links, never the request's Host header. Default
``http://localhost:8000``, stored without a trailing slash. It must be an
origin: https with a host and an optional port (plain http only for localhost,
127.0.0.1 and [::1]), no user info, no path other than "/", no query or
fragment, no whitespace or control characters, at most 2048 characters; the
error never repeats the value. ``ADMINO_PUBLIC_URL`` (set and non-empty)
overrides it, and an invalid value makes config loading fail.

GH-156: ``ServerConfig.trusted_proxies`` (default ``[]``: trust nobody) lists
the reverse proxy's addresses or networks. Each entry is an IPv4/IPv6 address
or a CIDR network, stored as a network string (``172.31.0.10`` becomes
``172.31.0.10/32``); anything else, a network with host bits set, a prefix
length of 0 (every address) or more than 16 entries fails validation, and the
error never repeats the value. ``ADMINO_TRUSTED_PROXIES`` (a comma-separated
list; blank items ignored) replaces the YAML list; unset or blank changes
nothing; an invalid value makes config loading fail without the value reaching
the error or the log. A non-Secure session cookie (``cookie_secure=False``) is
dev-only: it is refused with an https public URL.

GH-158: ``AppConfig.log_format`` is ``"text"`` (default) or ``"json"``
(structured JSON lines with a per-request ID). YAML ``log_format: json`` works;
any other YAML value fails validation without the value reaching the error.
``LOG_FORMAT`` overrides it case-insensitively (``JSON`` -> ``"json"``); an
invalid value logs a WARNING naming the variable (never the value) and the
YAML/default value stays.
"""

from __future__ import annotations

import logging
import textwrap
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from admino.config import (
    AppConfig,
    DatabaseConfig,
    EgressConfig,
    LimitsConfig,
    LLMConfig,
    ServerConfig,
    load_app_config,
    load_app_config_from_db,
    load_permissions_config_from_db,
)

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _no_cookie_secure_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test without a COOKIE_SECURE override from the developer's shell."""
    monkeypatch.delenv("COOKIE_SECURE", raising=False)


@pytest.fixture(autouse=True)
def _no_public_url_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test without an ADMINO_PUBLIC_URL override from the developer's shell."""
    monkeypatch.delenv("ADMINO_PUBLIC_URL", raising=False)


@pytest.fixture(autouse=True)
def _no_trusted_proxies_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test without an ADMINO_TRUSTED_PROXIES override from the developer's shell."""
    monkeypatch.delenv("ADMINO_TRUSTED_PROXIES", raising=False)


@pytest.fixture(autouse=True)
def _no_log_format_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test without a LOG_FORMAT override from the developer's shell."""
    monkeypatch.delenv("LOG_FORMAT", raising=False)


# A strong value of the removed AUTH_TOKEN env var (it must have no effect now).
_OLD_AUTH_TOKEN = "a" * 48 + "BcDeFgHiJkLmNoPqRsTuVwXyZ"


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

    def test_all_fields_parsed(self, tmp_path: Path) -> None:
        """All explicitly set fields in YAML should be reflected in AppConfig."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            server:
              host: "127.0.0.1"
              port: 9090
              cookie_secure: false
            llm:
              provider: "anthropic"
              anthropic_model: "claude-sonnet-4-6"
              timeout_s: 60
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
        assert config.server.cookie_secure is False
        assert config.llm.anthropic_model == "claude-sonnet-4-6"
        assert config.llm.timeout_s == 60
        assert config.llm.provider == "anthropic"
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
    """Defaults are applied to unset sections; a missing llm section defaults to infomaniak.

    Under GH-142 the default provider is ``infomaniak``, which boots gracefully
    with no INFOMANIAK_API_TOKEN (warning + friendly chat reply) — so a config
    that omits the llm section loads successfully instead of failing.
    """

    def test_defaults_applied_for_unset_sections(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With a valid llm section, all other sections fall back to defaults."""
        # _write_yaml injects a valid llm section for the empty body.
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))

        assert config.server.host == "0.0.0.0"  # noqa: S104
        assert config.server.port == 8000
        assert config.llm.provider == "anthropic"
        assert config.llm.timeout_s == 120
        assert config.server.cookie_secure is True
        assert config.limits.max_tool_calls_per_message == 10
        assert config.limits.confirmation_timeout_s == 300
        assert config.log_level == "INFO"

    def test_missing_file_defaults_to_infomaniak(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A missing file yields defaults with the infomaniak provider, which boots tokenless."""
        monkeypatch.delenv("INFOMANIAK_API_TOKEN", raising=False)
        config = load_app_config(tmp_path / "nonexistent.yaml")
        assert config.llm.provider == "infomaniak"

    def test_empty_yaml_defaults_to_infomaniak(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty YAML file (parses as None) has no llm section — defaults to infomaniak."""
        monkeypatch.delenv("INFOMANIAK_API_TOKEN", raising=False)
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text("", encoding="utf-8")
        config = load_app_config(yaml_path)
        assert config.llm.provider == "infomaniak"

    def test_comment_only_yaml_defaults_to_infomaniak(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A comment-only YAML file (parses as None) has no llm section — defaults to infomaniak."""
        monkeypatch.delenv("INFOMANIAK_API_TOKEN", raising=False)
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text("# just a comment\n", encoding="utf-8")
        config = load_app_config(yaml_path)
        assert config.llm.provider == "infomaniak"


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
        monkeypatch.setenv("LOG_LEVEL", "debug")
        config = load_app_config(yaml_path)
        assert config.log_level == "DEBUG"

    def test_audit_log_path_env_is_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GH-147: AUDIT_LOG_PATH is no longer read; setting it changes nothing."""
        yaml_path = _write_yaml(tmp_path / "config.yaml", "")
        monkeypatch.setenv("AUDIT_LOG_PATH", "/env/audit.ndjson")
        config = load_app_config(yaml_path)
        assert not hasattr(config, "paths")
        assert "/env/audit.ndjson" not in config.model_dump_json()

    def test_env_overrides_on_minimal_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Env vars apply on top of a minimal (llm-only) config."""
        monkeypatch.setenv("LOG_LEVEL", "WARNING")
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert config.llm.provider == "anthropic"
        assert config.log_level == "WARNING"

    def test_vllm_model_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """VLLM_MODEL env var overrides llm.vllm_model from YAML."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            llm:
              provider: "vllm"
              vllm_model: "org/from-yaml"
            """,
        )
        monkeypatch.setenv("VLLM_MODEL", "org/from-env")
        config = load_app_config(yaml_path)
        assert config.llm.vllm_model == "org/from-env"

    def test_vllm_base_url_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """VLLM_BASE_URL env var overrides llm.vllm_base_url from YAML."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            llm:
              provider: "vllm"
              vllm_base_url: "http://from-yaml:8000/v1"
            """,
        )
        monkeypatch.setenv("VLLM_BASE_URL", "http://from-env:9000/v1")
        config = load_app_config(yaml_path)
        assert config.llm.vllm_base_url == "http://from-env:9000/v1"

    def test_vllm_max_model_len_override(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """VLLM_MAX_MODEL_LEN env var (string) overrides llm.vllm_max_model_len as int."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            llm:
              provider: "vllm"
              vllm_max_model_len: 8192
            """,
        )
        monkeypatch.setenv("VLLM_MAX_MODEL_LEN", "16384")
        config = load_app_config(yaml_path)
        assert config.llm.vllm_max_model_len == 16384


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


class TestAuditLogPathRemoved:
    """GH-147: the NDJSON audit log path is gone from the config."""

    def test_paths_config_is_removed(self) -> None:
        """PathsConfig (its last field was the audit log path) no longer exists."""
        import admino.config as config_module

        assert not hasattr(config_module, "PathsConfig")

    def test_app_config_has_no_paths_field(self) -> None:
        assert "paths" not in AppConfig.model_fields

    def test_legacy_paths_section_still_loads(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An existing config.yaml or settings row with a paths section is ignored."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            paths:
              audit_log: "data/logs/audit.ndjson"
            """,
        )
        config = load_app_config(yaml_path)
        assert not hasattr(config, "paths")


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
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))

        assert isinstance(config.server, ServerConfig)
        assert isinstance(config.llm, LLMConfig)
        assert not hasattr(config, "auth")
        assert not hasattr(config, "paths")
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

    def test_leftover_ocr_and_images_db_settings_are_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A DB seeded before GH-84 (stale ocr row + paths.images) still loads.

        Pydantic ignores unknown keys, so an existing deployment with leftover
        ``ocr``/``images`` settings must not fail config validation.
        """
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            paths:
              images: "/data/images"
            ocr:
              binary: "/usr/bin/tesseract"
              languages: ["eng"]
            """,
        )
        config = load_app_config(yaml_path)
        assert not hasattr(config, "ocr")
        assert not hasattr(config, "paths")


class TestFilesToolConfigRemoved:
    """The local files tool's config is gone; legacy sections are ignored (GH-143)."""

    @pytest.mark.parametrize("symbol", ["FilesConfig", "FilePathEntry"])
    def test_files_config_symbols_removed(self, symbol: str) -> None:
        """FilesConfig / FilePathEntry no longer exist in admino.config."""
        import admino.config as config_module

        assert not hasattr(config_module, symbol)

    def test_appconfig_has_no_files_field(self) -> None:
        """AppConfig no longer carries a files section."""
        assert "files" not in AppConfig.model_fields

    def test_appconfig_dict_with_legacy_files_section_validates(self) -> None:
        """A dict still carrying a files section validates and drops it."""
        config = AppConfig.model_validate(
            {
                "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
                "files": {
                    "allowed_paths": [
                        {"path": "/app/documents", "label": "Docs", "access": "readwrite"}
                    ],
                    "max_read_chars": 10000,
                },
            }
        )
        assert not hasattr(config, "files")
        assert "files" not in config.model_dump()

    def test_legacy_files_section_in_yaml_is_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An existing config.yaml with a files section still loads."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            files:
              allowed_paths:
                - path: "/app/documents"
                  label: "Documents (~/Downloads/admino)"
                  access: "readwrite"
              max_read_chars: 10000
            """,
        )
        config = load_app_config(yaml_path)
        assert not hasattr(config, "files")

    async def test_legacy_files_row_in_db_settings_is_ignored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A DB seeded before GH-143 (stale files row) still boots."""
        mock_data: dict[str, object] = {
            "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
            "files": {
                "allowed_paths": [{"path": "/app/documents", "label": "", "access": "read"}],
                "max_read_chars": 10000,
            },
        }
        with patch("admino.database.load_settings_from_db", new=AsyncMock(return_value=mock_data)):
            config = await load_app_config_from_db(MagicMock())
        assert not hasattr(config, "files")


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


class TestAuthConfigRemoved:
    """GH-149: auth.mode / AUTH_TOKEN / AUTH_MODE are gone; old sections are ignored."""

    def test_auth_config_symbol_removed(self) -> None:
        import admino.config as config_module

        assert not hasattr(config_module, "AuthConfig")

    def test_app_config_has_no_auth_field(self) -> None:
        assert "auth" not in AppConfig.model_fields

    @pytest.mark.parametrize(
        "removed", ["validate_auth_token_present", "warn_vpn_mode_on_all_interfaces"]
    )
    def test_app_config_auth_validators_removed(self, removed: str) -> None:
        assert not hasattr(AppConfig, removed)

    def test_app_config_builds_without_auth_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """AppConfig() no longer needs AUTH_TOKEN (the old default mode was 'token')."""
        monkeypatch.delenv("AUTH_TOKEN", raising=False)
        monkeypatch.delenv("AUTH_MODE", raising=False)
        config = AppConfig(
            llm=LLMConfig(provider="anthropic", anthropic_model="claude-sonnet-4-6"),
        )
        assert not hasattr(config, "auth")

    @pytest.mark.parametrize("mode", ["token", "vpn"])
    def test_legacy_auth_section_in_yaml_is_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
    ) -> None:
        """An existing config.yaml with an auth section still loads (and drops it)."""
        monkeypatch.delenv("AUTH_TOKEN", raising=False)
        monkeypatch.delenv("AUTH_MODE", raising=False)
        yaml_path = _write_yaml(tmp_path / "config.yaml", f'auth:\n  mode: "{mode}"')
        config = load_app_config(yaml_path)
        assert not hasattr(config, "auth")
        assert "auth" not in config.model_dump()

    def test_legacy_auth_section_in_dict_is_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AUTH_TOKEN", raising=False)
        config = AppConfig.model_validate(
            {
                "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
                "auth": {"mode": "token", "token": "should-not-matter"},
            }
        )
        assert "auth" not in config.model_dump()

    async def test_legacy_auth_row_in_db_settings_is_ignored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A DB seeded before GH-149 (auth row, until migration 0007 deletes it) still boots."""
        monkeypatch.delenv("AUTH_TOKEN", raising=False)
        monkeypatch.delenv("AUTH_MODE", raising=False)
        mock_data: dict[str, object] = {
            "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
            "auth": {"mode": "token"},
        }
        with patch("admino.database.load_settings_from_db", new=AsyncMock(return_value=mock_data)):
            config = await load_app_config_from_db(MagicMock())
        assert not hasattr(config, "auth")

    @pytest.mark.parametrize("value", ["tooshort", _OLD_AUTH_TOKEN, "not base64!@#" * 5])
    def test_auth_token_env_has_no_effect(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        """AUTH_TOKEN is not read: any value (weak, strong, invalid) loads the same config."""
        monkeypatch.setenv("AUTH_TOKEN", value)
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert not hasattr(config, "auth")
        assert value not in config.model_dump_json()

    @pytest.mark.parametrize("value", ["token", "vpn", "garbage"])
    def test_auth_mode_env_has_no_effect(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        """AUTH_MODE is not read: even 'token' with no AUTH_TOKEN loads fine."""
        monkeypatch.delenv("AUTH_TOKEN", raising=False)
        monkeypatch.setenv("AUTH_MODE", value)
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert not hasattr(config, "auth")

    async def test_auth_mode_env_has_no_effect_on_db_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The DB loader applies no AUTH_MODE override either (no token demanded)."""
        monkeypatch.delenv("AUTH_TOKEN", raising=False)
        monkeypatch.setenv("AUTH_MODE", "token")
        mock_data: dict[str, object] = {
            "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
        }
        with patch("admino.database.load_settings_from_db", new=AsyncMock(return_value=mock_data)):
            config = await load_app_config_from_db(MagicMock())
        assert not hasattr(config, "auth")

    def test_config_module_never_reads_auth_env_vars(self) -> None:
        """No AUTH_TOKEN / AUTH_MODE string is left in admino.config's source."""
        import inspect

        import admino.config as config_module

        source = inspect.getsource(config_module)
        assert "AUTH_TOKEN" not in source
        assert "AUTH_MODE" not in source


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

    @pytest.mark.parametrize(
        ("provider", "model_field", "env_var"),
        [
            ("anthropic", "anthropic_model", "ANTHROPIC_API_KEY"),
            ("openai", "openai_model", "OPENAI_API_KEY"),
        ],
    )
    def test_missing_api_key_warns_without_raising(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        provider: str,
        model_field: str,
        env_var: str,
    ) -> None:
        """A missing cloud API key no longer fails validation — it logs a WARNING (GH-142)."""
        monkeypatch.delenv(env_var, raising=False)
        with caplog.at_level(logging.DEBUG):
            config = LLMConfig(provider=provider, **{model_field: "some-model"})  # type: ignore[arg-type]
        assert config.provider == provider
        assert any(
            env_var in record.getMessage()
            for record in caplog.records
            if record.levelno >= logging.WARNING
        )

    @pytest.mark.parametrize(
        ("provider", "model_field", "env_var"),
        [
            ("anthropic", "anthropic_model", "ANTHROPIC_API_KEY"),
            ("openai", "openai_model", "OPENAI_API_KEY"),
            ("infomaniak", "infomaniak_model", "INFOMANIAK_API_TOKEN"),
        ],
    )
    def test_provider_credential_value_never_logged(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        provider: str,
        model_field: str,
        env_var: str,
    ) -> None:
        """Validation never logs a credential value, whether it is set or not."""
        secret = f"CREDENTIAL-VALUE-MARKER-{provider}"
        monkeypatch.setenv(env_var, secret)
        with caplog.at_level(logging.DEBUG):
            LLMConfig(provider=provider, **{model_field: "some-model"})  # type: ignore[arg-type]
            LLMConfig(provider=provider, **{model_field: ""})  # type: ignore[arg-type]
        assert secret not in caplog.text

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

    @pytest.mark.parametrize(
        ("provider", "model_field", "model_value"),
        [
            ("anthropic", "anthropic_model", None),
            ("anthropic", "anthropic_model", ""),
            ("openai", "openai_model", None),
            ("openai", "openai_model", ""),
            ("vllm", "vllm_model", None),
            ("vllm", "vllm_model", ""),
            ("infomaniak", "infomaniak_model", None),
            ("infomaniak", "infomaniak_model", ""),
        ],
    )
    def test_missing_model_warns_without_raising(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        provider: str,
        model_field: str,
        model_value: str | None,
    ) -> None:
        """An unset model no longer fails validation — it logs a WARNING naming the field."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
        monkeypatch.setenv("INFOMANIAK_API_TOKEN", "ik-test-token")
        with caplog.at_level(logging.DEBUG):
            config = LLMConfig(provider=provider, **{model_field: model_value})  # type: ignore[arg-type]
        assert config.provider == provider
        assert any(
            model_field in record.getMessage()
            for record in caplog.records
            if record.levelno >= logging.WARNING
        )

    @pytest.mark.parametrize(
        ("provider", "model_field"),
        [
            ("anthropic", "anthropic_model"),
            ("openai", "openai_model"),
            ("vllm", "vllm_model"),
            ("infomaniak", "infomaniak_model"),
        ],
    )
    def test_active_model_name_empty_when_model_unset(
        self, monkeypatch: pytest.MonkeyPatch, provider: str, model_field: str
    ) -> None:
        """active_model_name returns "" (never raises) when the active model is unset."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
        config = LLMConfig(provider=provider, **{model_field: None})  # type: ignore[arg-type]
        assert config.active_model_name == ""

    def test_active_model_name_empty_after_model_copy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Even when validation is bypassed via model_copy, the property returns ""."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
        config = LLMConfig(provider="anthropic", anthropic_model="claude-sonnet-4-6")
        forced = config.model_copy(update={"anthropic_model": None})
        assert forced.active_model_name == ""

    # -- vLLM as a first-class local provider (issue #134) --

    def test_vllm_active_model_name_is_vllm_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """active_model_name for vllm returns vllm_model, NOT the 'vllm' sentinel.

        Issue #134: vllm is now a real provider whose served model is
        ``vllm_model`` (default Qwen/Qwen3-4B-Instruct-2507).
        """
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = LLMConfig(provider="vllm")
        assert config.active_model_name == "Qwen/Qwen3-4B-Instruct-2507"

    def test_vllm_boots_without_not_yet_implemented_warning(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Constructing a vllm config succeeds and no longer logs 'not yet implemented'.

        Issue #134 removes the placeholder warning: vllm is a working local
        provider now, so the old "not yet implemented" WARNING must be gone.
        """
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with caplog.at_level(logging.WARNING):
            config = LLMConfig(provider="vllm")
        assert config.provider == "vllm"
        assert not any("not yet implemented" in record.message for record in caplog.records)
        assert not any("not implemented" in record.message for record in caplog.records)

    def test_vllm_model_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """vllm_model defaults to the shipped Qwen model id."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = LLMConfig(provider="vllm")
        assert config.vllm_model == "Qwen/Qwen3-4B-Instruct-2507"

    def test_vllm_empty_model_boots(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An explicitly empty vllm_model while provider=vllm no longer fails (GH-142)."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = LLMConfig(provider="vllm", vllm_model="")
        assert config.provider == "vllm"
        assert config.active_model_name == ""

    def test_vllm_model_accepts_slashes_and_uppercase(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """vllm_model reuses the model-name validator, which accepts slashes/uppercase."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = LLMConfig(provider="vllm", vllm_model="Org/Some-Model_v2:latest")
        assert config.vllm_model == "Org/Some-Model_v2:latest"

    def test_vllm_model_shell_chars_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """vllm_model with shell metacharacters is rejected by the shared validator."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(ValidationError, match="invalid characters"):
            LLMConfig(provider="vllm", vllm_model="evil; rm -rf /")

    def test_vllm_base_url_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """vllm_base_url defaults to the internal Docker vllm service endpoint."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = LLMConfig(provider="vllm")
        assert config.vllm_base_url == "http://vllm:8000/v1"

    def test_vllm_base_url_accepts_https(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An https vllm_base_url is accepted."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = LLMConfig(provider="vllm", vllm_base_url="https://gpu.local:8443/v1")
        assert config.vllm_base_url == "https://gpu.local:8443/v1"

    def test_vllm_base_url_non_url_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-URL vllm_base_url raises ValidationError."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(ValidationError):
            LLMConfig(provider="vllm", vllm_base_url="not a url")

    def test_vllm_base_url_rejects_control_chars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A vllm_base_url containing whitespace/control chars is rejected."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(ValidationError):
            LLMConfig(provider="vllm", vllm_base_url="http://ok\x00/v1")

    def test_vllm_base_url_rejects_oversized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A vllm_base_url longer than 2048 chars is rejected."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        oversized = "http://example.com/" + "a" * 2048
        with pytest.raises(ValidationError):
            LLMConfig(provider="vllm", vllm_base_url=oversized)

    def test_vllm_max_model_len_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """vllm_max_model_len defaults to 32768."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = LLMConfig(provider="vllm")
        assert config.vllm_max_model_len == 32768

    def test_vllm_max_model_len_below_min_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """vllm_max_model_len below 512 raises ValidationError."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(ValidationError):
            LLMConfig(provider="vllm", vllm_max_model_len=511)

    def test_vllm_max_model_len_above_max_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """vllm_max_model_len above 262144 raises ValidationError."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(ValidationError):
            LLMConfig(provider="vllm", vllm_max_model_len=262145)


# ---------------------------------------------------------------------------
# GH-142: Infomaniak provider (the default)
# ---------------------------------------------------------------------------


_INFOMANIAK_DEFAULT_MODEL = "Qwen/Qwen3.5-397B-A17B-FP8"


class TestInfomaniakConfig:
    """``infomaniak`` is accepted, is the default, and boots without a token."""

    @pytest.fixture(autouse=True)
    def _no_infomaniak_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("INFOMANIAK_API_TOKEN", raising=False)
        monkeypatch.delenv("INFOMANIAK_PRODUCT_ID", raising=False)

    def test_infomaniak_provider_accepted(self) -> None:
        """provider='infomaniak' validates."""
        assert LLMConfig(provider="infomaniak").provider == "infomaniak"

    def test_llm_config_default_provider_is_infomaniak(self) -> None:
        """LLMConfig() defaults to the infomaniak provider."""
        assert LLMConfig().provider == "infomaniak"

    def test_app_config_default_provider_is_infomaniak(self) -> None:
        """AppConfig() (and therefore the settings seed) defaults to infomaniak."""
        config = AppConfig()
        assert config.llm.provider == "infomaniak"

    def test_infomaniak_model_default(self) -> None:
        """infomaniak_model defaults to Qwen/Qwen3.5-397B-A17B-FP8."""
        assert LLMConfig().infomaniak_model == _INFOMANIAK_DEFAULT_MODEL

    def test_infomaniak_active_model_name(self) -> None:
        """active_model_name for infomaniak is infomaniak_model."""
        config = LLMConfig(provider="infomaniak", infomaniak_model="org/Other-Model_v2:1")
        assert config.active_model_name == "org/Other-Model_v2:1"

    @pytest.mark.parametrize(
        "bad_model",
        ["evil; rm -rf /", "model$(id)", "a b", "../../etc/passwd", "-leading-dash", "x|y"],
    )
    def test_infomaniak_model_shell_chars_rejected(self, bad_model: str) -> None:
        """infomaniak_model uses the shared model-name validator."""
        with pytest.raises(ValidationError, match="invalid characters"):
            LLMConfig(provider="infomaniak", infomaniak_model=bad_model)

    def test_infomaniak_model_max_length_enforced(self) -> None:
        """infomaniak_model is bounded to 200 characters."""
        with pytest.raises(ValidationError, match="at most 200 characters"):
            LLMConfig(provider="infomaniak", infomaniak_model="a" * 201)

    def test_infomaniak_missing_token_warns_without_raising(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No INFOMANIAK_API_TOKEN → config still loads and a WARNING names the variable."""
        with caplog.at_level(logging.DEBUG):
            config = LLMConfig(provider="infomaniak")
        assert config.provider == "infomaniak"
        assert any(
            "INFOMANIAK_API_TOKEN" in record.getMessage()
            for record in caplog.records
            if record.levelno >= logging.WARNING
        )

    def test_infomaniak_logs_swiss_processing_notice(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Selecting infomaniak logs that messages are processed by Infomaniak in Switzerland."""
        monkeypatch.setenv("INFOMANIAK_API_TOKEN", "ik-test-token")
        with caplog.at_level(logging.DEBUG):
            LLMConfig(provider="infomaniak")
        assert any(
            "Switzerland" in record.getMessage()
            for record in caplog.records
            if record.levelno >= logging.INFO
        )

    def test_infomaniak_llm_provider_env_override(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """LLM_PROVIDER=infomaniak overrides the YAML provider."""
        monkeypatch.setenv("LLM_PROVIDER", "infomaniak")
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert config.llm.provider == "infomaniak"

    def test_infomaniak_yaml_model_loaded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """infomaniak_model is read from config.yaml."""
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            """\
            llm:
              provider: "infomaniak"
              infomaniak_model: "mistralai/Mistral-Small-3.2"
            """,
        )
        config = load_app_config(yaml_path)
        assert config.llm.infomaniak_model == "mistralai/Mistral-Small-3.2"


# ---------------------------------------------------------------------------
# GH-149: no vpn warning any more (every route needs a session)
# ---------------------------------------------------------------------------


class TestNoVpnModeWarning:
    """Binding to all interfaces no longer warns about an unauthenticated API."""

    @pytest.mark.parametrize(
        "yaml_text",
        [
            'server:\n  host: "0.0.0.0"',
            'server:\n  host: "0.0.0.0"\nauth:\n  mode: vpn',
        ],
        ids=["plain", "legacy-vpn-section"],
    )
    def test_all_interfaces_logs_no_unauthenticated_warning(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        yaml_text: str,
    ) -> None:
        monkeypatch.delenv("AUTH_TOKEN", raising=False)
        yaml_path = _write_yaml(tmp_path / "config.yaml", yaml_text)
        with caplog.at_level(logging.WARNING):
            load_app_config(yaml_path)
        assert "unauthenticated on ALL" not in caplog.text


# ---------------------------------------------------------------------------
# GH-149: ServerConfig.cookie_secure + COOKIE_SECURE env override
# ---------------------------------------------------------------------------

_COOKIE_SECURE_FALSE = ["false", "0", "no", "off", "FALSE", "False", "Off", "NO"]
_COOKIE_SECURE_TRUE = ["true", "1", "yes", "on", "TRUE", "True", "On", "YES"]
_COOKIE_SECURE_JUNK = ["maybe", "2", "enabled", "-1", "yes please"]


class TestCookieSecure:
    """The session cookie's Secure flag: on by default, COOKIE_SECURE overrides it."""

    def test_server_config_cookie_secure_defaults_true(self) -> None:
        assert ServerConfig().cookie_secure is True

    def test_server_config_cookie_secure_can_be_disabled(self) -> None:
        assert ServerConfig(cookie_secure=False).cookie_secure is False

    def test_loaded_config_cookie_secure_defaults_true(self, tmp_path: Path) -> None:
        """No YAML value and no env var: the secure default applies."""
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert config.server.cookie_secure is True

    def test_yaml_cookie_secure_false_is_read(self, tmp_path: Path) -> None:
        yaml_path = _write_yaml(tmp_path / "config.yaml", "server:\n  cookie_secure: false")
        assert load_app_config(yaml_path).server.cookie_secure is False

    @pytest.mark.parametrize("value", _COOKIE_SECURE_FALSE)
    def test_cookie_secure_env_false_values(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        """false/0/no/off (any case) turn the Secure flag off."""
        monkeypatch.setenv("COOKIE_SECURE", value)
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert config.server.cookie_secure is False

    @pytest.mark.parametrize("value", _COOKIE_SECURE_TRUE)
    def test_cookie_secure_env_true_values_override_yaml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        """true/1/yes/on (any case) turn it on, even over a YAML ``false``."""
        monkeypatch.setenv("COOKIE_SECURE", value)
        yaml_path = _write_yaml(tmp_path / "config.yaml", "server:\n  cookie_secure: false")
        assert load_app_config(yaml_path).server.cookie_secure is True

    @pytest.mark.parametrize("value", _COOKIE_SECURE_JUNK)
    def test_cookie_secure_env_junk_keeps_secure_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        """Any other value is ignored, so the Secure default stays on."""
        monkeypatch.setenv("COOKIE_SECURE", value)
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert config.server.cookie_secure is True

    @pytest.mark.parametrize("value", _COOKIE_SECURE_JUNK)
    def test_cookie_secure_env_junk_logs_warning(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        value: str,
    ) -> None:
        """An unrecognised COOKIE_SECURE value logs a WARNING that names the variable."""
        monkeypatch.setenv("COOKIE_SECURE", value)
        with caplog.at_level(logging.WARNING):
            load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert any(
            "COOKIE_SECURE" in record.getMessage()
            for record in caplog.records
            if record.levelno >= logging.WARNING
        )

    async def test_cookie_secure_env_applies_to_db_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The DB-backed loader applies the same COOKIE_SECURE override."""
        monkeypatch.setenv("COOKIE_SECURE", "false")
        mock_data: dict[str, object] = {
            "server": {"host": "127.0.0.1", "port": 8000},
            "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
        }
        with patch("admino.database.load_settings_from_db", new=AsyncMock(return_value=mock_data)):
            config = await load_app_config_from_db(MagicMock())
        assert config.server.cookie_secure is False


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
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert isinstance(config.database, DatabaseConfig)
        assert config.database.min_pool_size == 2
        assert config.database.max_pool_size == 5


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
            # A legacy row (migration 0007 deletes it); the loader ignores it.
            "auth": {"mode": "vpn"},
            "paths": {},
            "limits": {},
            "egress": {},
            "database": {},
            "log_level": "INFO",
        }
        mock_load = AsyncMock(return_value=mock_data)

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
            # A legacy row (migration 0007 deletes it); the loader ignores it.
            "auth": {"mode": "vpn"},
            "paths": {},
            "limits": {},
            "egress": {},
            "database": {},
            "log_level": "INFO",
        }
        mock_load = AsyncMock(return_value=mock_data)
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
    """Infomaniak is the default provider; vLLM stays a keyless opt-in.

    GH-142 makes 'infomaniak' the default. vLLM remains a real local provider:
    constructing it must NOT require an API key, and its model comes from the
    ``vllm_model`` default (no explicit model needed to boot).
    """

    def test_default_provider_is_infomaniak(self) -> None:
        """The LLMConfig.provider field default is infomaniak (GH-142)."""
        assert LLMConfig.model_fields["provider"].default == "infomaniak"

    def test_provider_vllm_boots_without_key_or_model(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """'vllm' validates with no API key set — vllm_model has a default, so it boots.

        Issue #134: no explicit model is required because ``vllm_model`` defaults
        to the shipped Qwen id; only a cloud API key is unnecessary.
        """
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = LLMConfig(provider="vllm")
        assert config.provider == "vllm"
        assert config.vllm_model == "Qwen/Qwen3-4B-Instruct-2507"


# ---------------------------------------------------------------------------
# GH-151: ServerConfig.public_url + ADMINO_PUBLIC_URL env override
# ---------------------------------------------------------------------------

_PUBLIC_URL_DEFAULT = "http://localhost:8000"

# (value, stored value): origins, stored without a trailing slash.
_PUBLIC_URLS_ACCEPTED: list[object] = [
    pytest.param("https://admino.example.ch", "https://admino.example.ch", id="https"),
    pytest.param("https://admino.example.ch/", "https://admino.example.ch", id="trailing-slash"),
    pytest.param("https://admino.example.ch:8443", "https://admino.example.ch:8443", id="port"),
    pytest.param(
        "https://admino.example.ch:8443/", "https://admino.example.ch:8443", id="port-slash"
    ),
    pytest.param("https://127.0.0.1", "https://127.0.0.1", id="https-ip"),
    pytest.param("http://localhost:8000", "http://localhost:8000", id="http-localhost"),
    pytest.param("http://localhost", "http://localhost", id="http-localhost-no-port"),
    pytest.param("http://localhost:8000/", "http://localhost:8000", id="http-localhost-slash"),
    pytest.param("http://127.0.0.1:8000", "http://127.0.0.1:8000", id="http-127"),
    pytest.param("http://[::1]:8000", "http://[::1]:8000", id="http-ipv6-loopback"),
]

_PUBLIC_URLS_REFUSED: list[object] = [
    pytest.param("javascript:alert(1)", id="javascript"),
    pytest.param("ftp://admino.example.ch", id="ftp"),
    pytest.param("file:///etc/passwd", id="file"),
    pytest.param("data:text/html,hi", id="data"),
    pytest.param("http://admino.example.ch", id="http-public-host"),
    pytest.param("http://192.168.1.10:8000", id="http-lan"),
    pytest.param("http://localhost.evil.example", id="http-localhost-lookalike"),
    pytest.param("http://127.0.0.1.nip.io", id="http-loopback-lookalike"),
    pytest.param("https://", id="no-host"),
    pytest.param("https:///reset", id="no-host-path"),
    pytest.param("https://:8443", id="port-only"),
    pytest.param("admino.example.ch", id="no-scheme"),
    pytest.param("//admino.example.ch", id="scheme-relative"),
    pytest.param("", id="empty"),
    pytest.param("https://user@admino.example.ch", id="userinfo"),
    pytest.param("https://user:secret@admino.example.ch", id="userinfo-password"),
    pytest.param("https://admino.example.ch\\@evil.example", id="backslash-userinfo"),
    pytest.param("https://admino.example.ch/app", id="path"),
    pytest.param("https://admino.example.ch/app/", id="path-slash"),
    pytest.param("https://admino.example.ch//", id="double-slash"),
    pytest.param("https://admino.example.ch?next=1", id="query"),
    pytest.param("https://admino.example.ch/?next=1", id="slash-query"),
    pytest.param("https://admino.example.ch#top", id="fragment"),
    pytest.param("https://admino.example.ch:99999", id="port-out-of-range"),
    pytest.param("https://admino.example.ch:port", id="port-not-a-number"),
    pytest.param(" https://admino.example.ch", id="leading-space"),
    pytest.param("https://admino.example.ch ", id="trailing-space"),
    pytest.param("https://admino.example.ch\n", id="trailing-newline"),
    pytest.param("https://admino.exa mple.ch", id="inner-space"),
    pytest.param("https://admino.example.ch\t", id="tab"),
    pytest.param("https://admino.example.ch" + chr(0), id="nul"),
    pytest.param("https://admino.example" + chr(0x7F) + "ch", id="del"),
    pytest.param("https://admino.example.ch" + chr(0x2028), id="line-separator"),
    pytest.param("https://" + "a" * 2041, id="2049-chars"),
]

# (value, distinctive parts that must not appear in the error).
_PUBLIC_URL_ECHO_CASES: list[object] = [
    pytest.param("https://echomarkerq7.example.ch/secretpathq7", ["echomarkerq7", "secretpathq7"]),
    pytest.param("http://echomarkerq7.example.ch", ["echomarkerq7"]),
    pytest.param("https://userq7secret@echomarkerq7.example.ch", ["userq7secret", "echomarkerq7"]),
    pytest.param("https://echomarkerq7.example.ch:portmarkerq7", ["portmarkerq7", "echomarkerq7"]),
    pytest.param("https://echomarkerq7.example.ch?tokenq7=1", ["tokenq7", "echomarkerq7"]),
    pytest.param("javascript:echomarkerq7()", ["echomarkerq7"]),
]


class TestPublicUrl:
    """server.public_url: the configured origin reset links are built from."""

    def test_server_config_public_url_default(self) -> None:
        assert ServerConfig().public_url == _PUBLIC_URL_DEFAULT  # type: ignore[attr-defined]

    @pytest.mark.parametrize(("value", "stored"), _PUBLIC_URLS_ACCEPTED)
    def test_server_config_public_url_accepts_origins(self, value: str, stored: str) -> None:
        """https origins (http for loopback), stored without a trailing slash."""
        assert ServerConfig(public_url=value).public_url == stored  # type: ignore[call-arg]

    @pytest.mark.parametrize("value", _PUBLIC_URLS_REFUSED)
    def test_server_config_public_url_refuses_non_origins(self, value: str) -> None:
        """Other schemes, http off loopback, no host, user info, a path, a query, a
        fragment, a bad port, whitespace or control characters, over 2048 characters."""
        with pytest.raises(ValidationError):
            ServerConfig(public_url=value)  # type: ignore[call-arg]

    @pytest.mark.parametrize(("value", "parts"), _PUBLIC_URL_ECHO_CASES)
    def test_server_config_public_url_error_does_not_echo_the_value(
        self, value: str, parts: list[str]
    ) -> None:
        with pytest.raises(ValidationError) as exc_info:
            ServerConfig(public_url=value)  # type: ignore[call-arg]

        errors = exc_info.value.errors(include_url=False, include_input=False)
        rendered = f"{exc_info.value!s} {errors!r}"
        for part in parts:
            assert part not in rendered

    def test_loaded_config_public_url_defaults_to_localhost(self, tmp_path: Path) -> None:
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert config.server.public_url == _PUBLIC_URL_DEFAULT  # type: ignore[attr-defined]

    def test_yaml_public_url_is_read_and_normalized(self, tmp_path: Path) -> None:
        yaml_path = _write_yaml(
            tmp_path / "config.yaml", 'server:\n  public_url: "https://admino.example.ch/"'
        )
        assert load_app_config(yaml_path).server.public_url == "https://admino.example.ch"  # type: ignore[attr-defined]

    def test_yaml_invalid_public_url_fails_loading(self, tmp_path: Path) -> None:
        yaml_path = _write_yaml(
            tmp_path / "config.yaml", 'server:\n  public_url: "http://admino.example.ch"'
        )
        with pytest.raises(ValueError, match=r"Invalid application config"):
            load_app_config(yaml_path)

    def test_public_url_env_sets_it(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ADMINO_PUBLIC_URL", "https://admino.example.ch")
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert config.server.public_url == "https://admino.example.ch"  # type: ignore[attr-defined]

    def test_public_url_env_overrides_yaml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ADMINO_PUBLIC_URL", "https://from-env.example.ch/")
        yaml_path = _write_yaml(
            tmp_path / "config.yaml", 'server:\n  public_url: "https://from-yaml.example.ch"'
        )
        assert load_app_config(yaml_path).server.public_url == "https://from-env.example.ch"  # type: ignore[attr-defined]

    def test_public_url_env_keeps_other_server_settings(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The override only replaces public_url inside the server section."""
        monkeypatch.setenv("ADMINO_PUBLIC_URL", "https://admino.example.ch")
        yaml_path = _write_yaml(
            tmp_path / "config.yaml", 'server:\n  host: "127.0.0.1"\n  port: 9090'
        )
        config = load_app_config(yaml_path)
        assert (config.server.host, config.server.port) == ("127.0.0.1", 9090)
        assert config.server.public_url == "https://admino.example.ch"  # type: ignore[attr-defined]

    def test_public_url_empty_env_is_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ADMINO_PUBLIC_URL= (empty) leaves the YAML value in place."""
        monkeypatch.setenv("ADMINO_PUBLIC_URL", "")
        yaml_path = _write_yaml(
            tmp_path / "config.yaml", 'server:\n  public_url: "https://from-yaml.example.ch"'
        )
        assert load_app_config(yaml_path).server.public_url == "https://from-yaml.example.ch"  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        "value",
        [
            "http://envmarkerq9.example.ch",
            "javascript:envmarkerq9()",
            "https://envmarkerq9.example.ch/path",
        ],
    )
    def test_public_url_invalid_env_fails_loading_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        value: str,
    ) -> None:
        """An invalid override isn't silently ignored: loading fails, and neither the error
        nor the log repeats the value."""
        caplog.set_level(logging.DEBUG)
        monkeypatch.setenv("ADMINO_PUBLIC_URL", value)

        with pytest.raises(ValueError, match=r"Invalid application config") as exc_info:
            load_app_config(_write_yaml(tmp_path / "config.yaml", ""))

        assert "envmarkerq9" not in str(exc_info.value)
        assert "envmarkerq9" not in caplog.text

    @pytest.mark.parametrize(("value", "parts"), _PUBLIC_URL_ECHO_CASES)
    def test_app_config_public_url_error_does_not_echo_the_value(
        self, value: str, parts: list[str]
    ) -> None:
        """Validated through AppConfig (the DB loader's path), the error still hides the value."""
        with pytest.raises(ValidationError) as exc_info:
            AppConfig.model_validate({"server": {"public_url": value}})

        rendered = f"{exc_info.value!s} {exc_info.value!r}"
        for part in parts:
            assert part not in rendered

    async def test_public_url_invalid_value_fails_db_loading_without_echo(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An invalid override fails the DB-backed loader too, and the error (which startup
        logs with %s) doesn't repeat the value."""
        monkeypatch.setenv("ADMINO_PUBLIC_URL", "http://dbmarkerq8.example.ch/pathq8")
        mock_data: dict[str, object] = {"server": {"host": "127.0.0.1", "port": 8000}}
        with (
            patch("admino.database.load_settings_from_db", new=AsyncMock(return_value=mock_data)),
            pytest.raises(ValueError) as exc_info,
        ):
            await load_app_config_from_db(MagicMock())

        assert "dbmarkerq8" not in str(exc_info.value)
        assert "pathq8" not in str(exc_info.value)

    async def test_public_url_env_applies_to_db_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The DB-backed loader applies the same override."""
        monkeypatch.setenv("ADMINO_PUBLIC_URL", "https://admino.example.ch")
        mock_data: dict[str, object] = {
            "server": {"host": "127.0.0.1", "port": 8000},
            "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
        }
        with patch("admino.database.load_settings_from_db", new=AsyncMock(return_value=mock_data)):
            config = await load_app_config_from_db(MagicMock())
        assert config.server.public_url == "https://admino.example.ch"  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# GH-156: ServerConfig.trusted_proxies + ADMINO_TRUSTED_PROXIES env override
# ---------------------------------------------------------------------------

# (entry, stored network string): addresses become single-host networks.
_TRUSTED_PROXIES_ACCEPTED: list[object] = [
    pytest.param("172.31.0.10", "172.31.0.10/32", id="ipv4-address"),
    pytest.param("172.31.0.10/32", "172.31.0.10/32", id="ipv4-single-host-network"),
    pytest.param("172.31.0.0/24", "172.31.0.0/24", id="ipv4-network"),
    pytest.param("10.0.0.0/8", "10.0.0.0/8", id="ipv4-wide-network"),
    pytest.param("127.0.0.1", "127.0.0.1/32", id="ipv4-loopback"),
    pytest.param("2001:db8::1", "2001:db8::1/128", id="ipv6-address"),
    pytest.param("2001:db8::/64", "2001:db8::/64", id="ipv6-network"),
    pytest.param("::1", "::1/128", id="ipv6-loopback"),
]

_TRUSTED_PROXIES_REFUSED: list[object] = [
    pytest.param("not-an-ip", id="not-an-ip"),
    pytest.param("localhost", id="hostname-localhost"),
    pytest.param("caddy", id="hostname-service"),
    pytest.param("*", id="wildcard"),
    pytest.param("", id="empty"),
    pytest.param("300.1.1.1", id="octet-out-of-range"),
    pytest.param("172.31.0.10/24", id="host-bits-set"),
    pytest.param("2001:db8::1/64", id="ipv6-host-bits-set"),
    pytest.param("0.0.0.0/0", id="ipv4-every-address"),
    pytest.param("::/0", id="ipv6-every-address"),
    pytest.param("10.0.0.0/33", id="prefix-too-long"),
    pytest.param("10.0.0.0/abc", id="prefix-not-a-number"),
    pytest.param("172.31.0.10, 10.0.0.0/8", id="comma-list-in-one-entry"),
    # An IPv6 scope ID is meaningless for a proxy network, and ipaddress would
    # keep any text after '%' in the stored entry.
    pytest.param("fe80::%eth0/64", id="ipv6-network-scope-id"),
    pytest.param("fe80::1%anything-goes", id="ipv6-address-scope-id"),
]

# (value, distinctive parts that must not appear in the error). The ipaddress
# module's own messages repeat the value, so re-raising them would leak it.
_TRUSTED_PROXY_ECHO_CASES: list[object] = [
    pytest.param("evil-proxy-value", ["evil-proxy-value"], id="not-an-ip"),
    pytest.param("10.123.45.67/24", ["10.123.45.67"], id="host-bits-set"),
    pytest.param("2001:db8:77::1/64", ["2001:db8:77::1"], id="ipv6-host-bits-set"),
    pytest.param("310.20.30.40", ["310.20.30.40"], id="octet-out-of-range"),
    pytest.param("10.20.30.0/99", ["10.20.30.0"], id="prefix-too-long"),
]

# ADMINO_TRUSTED_PROXIES values that must fail config loading.
_TRUSTED_PROXIES_ENV_REFUSED: list[object] = [
    pytest.param("not-an-ip", id="not-an-ip"),
    pytest.param("localhost", id="hostname"),
    pytest.param("*", id="wildcard"),
    pytest.param("0.0.0.0/0", id="ipv4-every-address"),
    pytest.param("::/0", id="ipv6-every-address"),
    pytest.param("172.31.0.10/24", id="host-bits-set"),
    pytest.param("172.31.0.10, not-an-ip", id="one-bad-item"),
    pytest.param("172.31.0.10;10.0.0.0/8", id="wrong-separator"),
    pytest.param(",".join(f"10.0.{i}.0/24" for i in range(17)), id="17-items"),
]

# (ADMINO_TRUSTED_PROXIES value, marker that must reach neither the error nor the log).
_TRUSTED_PROXIES_ENV_ECHO_CASES: list[object] = [
    pytest.param("proxymarkerq3", "proxymarkerq3", id="not-an-ip"),
    pytest.param("172.31.0.10, proxymarkerq3", "proxymarkerq3", id="one-bad-item"),
    pytest.param("10.77.66.55/24", "10.77.66.55", id="host-bits-set"),
    pytest.param("fd00:77::1/64", "fd00:77::1", id="ipv6-host-bits-set"),
]


class TestTrustedProxies:
    """server.trusted_proxies: the reverse proxy addresses whose X-Forwarded-* headers count."""

    def test_server_config_trusted_proxies_default_is_empty(self) -> None:
        """Default: trust nobody (forwarded headers are ignored from every peer)."""
        assert ServerConfig().trusted_proxies == []

    @pytest.mark.parametrize(("value", "stored"), _TRUSTED_PROXIES_ACCEPTED)
    def test_server_config_trusted_proxies_accepts_addresses_and_networks(
        self, value: str, stored: str
    ) -> None:
        """Addresses and CIDR networks are stored as network strings."""
        assert ServerConfig(trusted_proxies=[value]).trusted_proxies == [stored]

    def test_server_config_trusted_proxies_keeps_the_order(self) -> None:
        config = ServerConfig(trusted_proxies=["10.0.0.0/8", "172.31.0.10", "2001:db8::/64"])
        assert config.trusted_proxies == ["10.0.0.0/8", "172.31.0.10/32", "2001:db8::/64"]

    @pytest.mark.parametrize("value", _TRUSTED_PROXIES_REFUSED)
    def test_server_config_trusted_proxies_refuses_invalid_entries(self, value: str) -> None:
        """Not an IP, host bits set (strict), a /0 prefix (every address), a bad prefix."""
        with pytest.raises(ValidationError):
            ServerConfig(trusted_proxies=[value])

    def test_server_config_trusted_proxies_refuses_a_bad_entry_among_good_ones(self) -> None:
        """One invalid entry fails the whole list (it is never silently dropped)."""
        with pytest.raises(ValidationError):
            ServerConfig(trusted_proxies=["172.31.0.10", "not-an-ip", "10.0.0.0/8"])

    def test_server_config_trusted_proxies_refuses_non_string_entries(self) -> None:
        """An integer entry is refused (ipaddress would read 167772161 as 10.0.0.1)."""
        with pytest.raises(ValidationError):
            ServerConfig.model_validate({"trusted_proxies": [167772161]})

    def test_server_config_trusted_proxies_accepts_16_entries(self) -> None:
        entries = [f"10.0.{i}.0/24" for i in range(16)]
        assert len(ServerConfig(trusted_proxies=entries).trusted_proxies) == 16

    def test_server_config_trusted_proxies_refuses_17_entries(self) -> None:
        entries = [f"10.0.{i}.0/24" for i in range(17)]
        with pytest.raises(ValidationError):
            ServerConfig(trusted_proxies=entries)

    @pytest.mark.parametrize(("value", "parts"), _TRUSTED_PROXY_ECHO_CASES)
    def test_server_config_trusted_proxies_error_does_not_echo_the_value(
        self, value: str, parts: list[str]
    ) -> None:
        with pytest.raises(ValidationError) as exc_info:
            ServerConfig(trusted_proxies=[value])

        errors = exc_info.value.errors(include_url=False, include_input=False)
        rendered = f"{exc_info.value!s} {errors!r}"
        for part in parts:
            assert part not in rendered

    @pytest.mark.parametrize(("value", "parts"), _TRUSTED_PROXY_ECHO_CASES)
    def test_app_config_trusted_proxies_error_does_not_echo_the_value(
        self, value: str, parts: list[str]
    ) -> None:
        """Validated through AppConfig (the DB loader's path), the error still hides the value."""
        with pytest.raises(ValidationError) as exc_info:
            AppConfig.model_validate({"server": {"trusted_proxies": [value]}})

        rendered = f"{exc_info.value!s} {exc_info.value!r}"
        for part in parts:
            assert part not in rendered

    def test_loaded_config_trusted_proxies_defaults_to_empty(self, tmp_path: Path) -> None:
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert config.server.trusted_proxies == []

    def test_yaml_trusted_proxies_is_read_and_normalized(self, tmp_path: Path) -> None:
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            'server:\n  trusted_proxies:\n    - "172.31.0.10"\n    - "fd00:31::/64"',
        )
        config = load_app_config(yaml_path)
        assert config.server.trusted_proxies == ["172.31.0.10/32", "fd00:31::/64"]

    def test_yaml_invalid_trusted_proxies_fails_loading(self, tmp_path: Path) -> None:
        yaml_path = _write_yaml(
            tmp_path / "config.yaml", 'server:\n  trusted_proxies:\n    - "0.0.0.0/0"'
        )
        with pytest.raises(ValueError, match=r"Invalid application config"):
            load_app_config(yaml_path)

    def test_trusted_proxies_env_sets_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ADMINO_TRUSTED_PROXIES", "172.31.0.10")
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert config.server.trusted_proxies == ["172.31.0.10/32"]

    def test_trusted_proxies_env_is_a_comma_separated_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Whitespace around items is stripped and empty items are ignored."""
        monkeypatch.setenv("ADMINO_TRUSTED_PROXIES", " 172.31.0.10 , 10.0.0.0/8 ,")
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert config.server.trusted_proxies == ["172.31.0.10/32", "10.0.0.0/8"]

    def test_trusted_proxies_env_replaces_the_yaml_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ADMINO_TRUSTED_PROXIES", "172.31.0.10")
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            'server:\n  trusted_proxies:\n    - "10.0.0.0/8"\n    - "192.168.0.0/16"',
        )
        assert load_app_config(yaml_path).server.trusted_proxies == ["172.31.0.10/32"]

    @pytest.mark.parametrize("value", ["", "   ", "\t"], ids=["empty", "spaces", "tab"])
    def test_trusted_proxies_blank_env_keeps_the_yaml_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        """A blank ADMINO_TRUSTED_PROXIES changes nothing."""
        monkeypatch.setenv("ADMINO_TRUSTED_PROXIES", value)
        yaml_path = _write_yaml(
            tmp_path / "config.yaml", 'server:\n  trusted_proxies:\n    - "10.0.0.0/8"'
        )
        assert load_app_config(yaml_path).server.trusted_proxies == ["10.0.0.0/8"]

    @pytest.mark.parametrize("value", ["", "   "], ids=["empty", "spaces"])
    def test_trusted_proxies_blank_env_keeps_the_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("ADMINO_TRUSTED_PROXIES", value)
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert config.server.trusted_proxies == []

    def test_trusted_proxies_env_keeps_other_server_settings(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The override only replaces trusted_proxies inside the server section."""
        monkeypatch.setenv("ADMINO_TRUSTED_PROXIES", "172.31.0.10")
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            'server:\n  host: "127.0.0.1"\n  port: 9090\n  public_url: "https://admino.example.ch"',
        )
        config = load_app_config(yaml_path)
        assert (config.server.host, config.server.port) == ("127.0.0.1", 9090)
        assert config.server.public_url == "https://admino.example.ch"
        assert config.server.trusted_proxies == ["172.31.0.10/32"]

    @pytest.mark.parametrize("value", _TRUSTED_PROXIES_ENV_REFUSED)
    def test_trusted_proxies_invalid_env_fails_loading(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        """An invalid override is never silently ignored: loading fails."""
        monkeypatch.setenv("ADMINO_TRUSTED_PROXIES", value)
        with pytest.raises(ValueError):
            load_app_config(_write_yaml(tmp_path / "config.yaml", ""))

    @pytest.mark.parametrize(("value", "marker"), _TRUSTED_PROXIES_ENV_ECHO_CASES)
    def test_trusted_proxies_invalid_env_is_never_echoed_or_logged(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        value: str,
        marker: str,
    ) -> None:
        """Neither the error nor any log line (DEBUG included) repeats the value."""
        caplog.set_level(logging.DEBUG)
        monkeypatch.setenv("ADMINO_TRUSTED_PROXIES", value)

        with pytest.raises(ValueError) as exc_info:
            load_app_config(_write_yaml(tmp_path / "config.yaml", ""))

        assert marker not in str(exc_info.value)
        assert marker not in caplog.text

    def test_trusted_proxies_invalid_env_names_the_setting(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The operator learns which setting to fix (the error or the log names it)."""
        caplog.set_level(logging.DEBUG)
        monkeypatch.setenv("ADMINO_TRUSTED_PROXIES", "proxymarkerq3")

        with pytest.raises(ValueError) as exc_info:
            load_app_config(_write_yaml(tmp_path / "config.yaml", ""))

        assert "trusted_proxies" in f"{exc_info.value} {caplog.text}".lower()

    async def test_trusted_proxies_env_applies_to_db_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The DB-backed loader applies the same override (replacing the stored list)."""
        monkeypatch.setenv("ADMINO_TRUSTED_PROXIES", " 172.31.0.10 , 10.0.0.0/8")
        mock_data: dict[str, object] = {
            "server": {"host": "127.0.0.1", "port": 8000, "trusted_proxies": ["192.168.0.0/16"]},
            "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
        }
        with patch("admino.database.load_settings_from_db", new=AsyncMock(return_value=mock_data)):
            config = await load_app_config_from_db(MagicMock())
        assert config.server.trusted_proxies == ["172.31.0.10/32", "10.0.0.0/8"]

    async def test_trusted_proxies_db_row_is_normalized(self) -> None:
        """Without the env var, a stored server row's list is validated like YAML."""
        mock_data: dict[str, object] = {
            "server": {"host": "127.0.0.1", "port": 8000, "trusted_proxies": ["172.31.0.10"]},
            "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
        }
        with patch("admino.database.load_settings_from_db", new=AsyncMock(return_value=mock_data)):
            config = await load_app_config_from_db(MagicMock())
        assert config.server.trusted_proxies == ["172.31.0.10/32"]

    async def test_trusted_proxies_invalid_env_fails_db_loading_without_echo(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An invalid override fails the DB-backed loader too, and the error (which startup
        logs with %s) doesn't repeat the value."""
        monkeypatch.setenv("ADMINO_TRUSTED_PROXIES", "172.31.0.10, proxymarkerq4")
        mock_data: dict[str, object] = {"server": {"host": "127.0.0.1", "port": 8000}}
        with (
            patch("admino.database.load_settings_from_db", new=AsyncMock(return_value=mock_data)),
            pytest.raises(ValueError) as exc_info,
        ):
            await load_app_config_from_db(MagicMock())

        assert "proxymarkerq4" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# GH-156: a non-Secure session cookie is dev-only (plain-http loopback URL)
# ---------------------------------------------------------------------------

_HTTPS_PUBLIC_URLS: list[object] = [
    pytest.param("https://admino.example.ch", id="https"),
    pytest.param("https://admino.example.ch:8443", id="https-port"),
    pytest.param("https://127.0.0.1", id="https-loopback-ip"),
    pytest.param("https://localhost:8443", id="https-localhost"),
]

_LOOPBACK_HTTP_PUBLIC_URLS: list[object] = [
    pytest.param("http://localhost:8000", id="localhost"),
    pytest.param("http://localhost", id="localhost-no-port"),
    pytest.param("http://127.0.0.1:8000", id="ipv4-loopback"),
    pytest.param("http://[::1]:8000", id="ipv6-loopback"),
]


class TestInsecureCookieIsDevOnly:
    """cookie_secure=False is only allowed with a plain-http (loopback) public URL."""

    @pytest.mark.parametrize("url", _HTTPS_PUBLIC_URLS)
    def test_server_config_insecure_cookie_refused_with_https_public_url(self, url: str) -> None:
        with pytest.raises(ValidationError):
            ServerConfig(cookie_secure=False, public_url=url)

    def test_server_config_insecure_cookie_error_names_the_field_not_the_url(self) -> None:
        """The error tells the operator what to fix (cookie_secure) without the URL."""
        with pytest.raises(ValidationError) as exc_info:
            ServerConfig(cookie_secure=False, public_url="https://cookiemarkerq5.example.ch")

        errors = exc_info.value.errors(include_url=False, include_input=False)
        rendered = f"{exc_info.value!s} {errors!r}"
        assert "cookiemarkerq5" not in rendered
        assert "cookie_secure" in rendered.lower()

    def test_server_config_insecure_cookie_allowed_with_default_public_url(self) -> None:
        """The dev profile (http://localhost:8000) keeps working without Secure."""
        assert ServerConfig(cookie_secure=False).cookie_secure is False

    @pytest.mark.parametrize("url", _LOOPBACK_HTTP_PUBLIC_URLS)
    def test_server_config_insecure_cookie_allowed_with_loopback_http_url(self, url: str) -> None:
        assert ServerConfig(cookie_secure=False, public_url=url).cookie_secure is False

    @pytest.mark.parametrize("url", _HTTPS_PUBLIC_URLS)
    def test_server_config_secure_cookie_allowed_with_https_public_url(self, url: str) -> None:
        assert ServerConfig(cookie_secure=True, public_url=url).cookie_secure is True

    def test_yaml_insecure_cookie_with_https_public_url_fails_loading(self, tmp_path: Path) -> None:
        yaml_path = _write_yaml(
            tmp_path / "config.yaml",
            'server:\n  cookie_secure: false\n  public_url: "https://admino.example.ch"',
        )
        with pytest.raises(ValueError, match=r"Invalid application config"):
            load_app_config(yaml_path)

    def test_cookie_secure_env_false_with_https_public_url_fails_loading_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """COOKIE_SECURE=false in production fails startup; the URL is never repeated."""
        caplog.set_level(logging.DEBUG)
        monkeypatch.setenv("COOKIE_SECURE", "false")
        monkeypatch.setenv("ADMINO_PUBLIC_URL", "https://cookiemarkerq5.example.ch")

        with pytest.raises(ValueError) as exc_info:
            load_app_config(_write_yaml(tmp_path / "config.yaml", ""))

        assert "cookiemarkerq5" not in str(exc_info.value)
        assert "cookiemarkerq5" not in caplog.text

    def test_cookie_secure_env_false_over_yaml_https_public_url_fails_loading(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("COOKIE_SECURE", "false")
        yaml_path = _write_yaml(
            tmp_path / "config.yaml", 'server:\n  public_url: "https://admino.example.ch"'
        )
        with pytest.raises(ValueError):
            load_app_config(yaml_path)

    def test_cookie_secure_env_true_with_https_public_url_loads(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("COOKIE_SECURE", "true")
        monkeypatch.setenv("ADMINO_PUBLIC_URL", "https://admino.example.ch")
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert config.server.cookie_secure is True
        assert config.server.public_url == "https://admino.example.ch"

    def test_cookie_secure_env_false_keeps_working_on_localhost(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The dev-only flag still loads with the local http public URL."""
        monkeypatch.setenv("COOKIE_SECURE", "false")
        monkeypatch.setenv("ADMINO_PUBLIC_URL", "http://localhost:8000")
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert config.server.cookie_secure is False

    async def test_insecure_cookie_with_https_public_url_fails_db_loading(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The DB-backed loader refuses it too, and the error doesn't repeat the URL."""
        monkeypatch.setenv("COOKIE_SECURE", "false")
        monkeypatch.setenv("ADMINO_PUBLIC_URL", "https://cookiemarkerq5.example.ch")
        mock_data: dict[str, object] = {
            "server": {"host": "127.0.0.1", "port": 8000},
            "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
        }
        with (
            patch("admino.database.load_settings_from_db", new=AsyncMock(return_value=mock_data)),
            pytest.raises(ValueError) as exc_info,
        ):
            await load_app_config_from_db(MagicMock())

        assert "cookiemarkerq5" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# GH-158: log_format (text or structured JSON lines)
# ---------------------------------------------------------------------------

# A distinctive invalid LOG_FORMAT value: it must never reach the log.
_JUNK_LOG_FORMAT = "zebrafmt7731"


class TestLogFormat:
    """``log_format``: "text" by default, "json" from YAML or LOG_FORMAT."""

    def test_config_log_format_defaults_to_text(self) -> None:
        assert AppConfig().log_format == "text"

    def test_config_loaded_log_format_defaults_to_text(self, tmp_path: Path) -> None:
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert config.log_format == "text"

    @pytest.mark.parametrize("value", ["json", "text"])
    def test_config_log_format_from_yaml(self, tmp_path: Path, value: str) -> None:
        yaml_path = _write_yaml(tmp_path / "config.yaml", f"log_format: {value}\n")
        assert load_app_config(yaml_path).log_format == value

    def test_config_invalid_yaml_log_format_fails_validation(self, tmp_path: Path) -> None:
        yaml_path = _write_yaml(tmp_path / "config.yaml", f"log_format: {_JUNK_LOG_FORMAT}\n")
        with pytest.raises(ValueError, match=r"Invalid application config.*field\(s\)") as info:
            load_app_config(yaml_path)
        assert _JUNK_LOG_FORMAT not in str(info.value)

    def test_config_invalid_log_format_is_a_validation_error_without_the_value(self) -> None:
        with pytest.raises(ValidationError) as info:
            AppConfig.model_validate({"log_format": _JUNK_LOG_FORMAT})
        assert _JUNK_LOG_FORMAT not in str(info.value)

    @pytest.mark.parametrize(
        ("value", "expected"), [("JSON", "json"), ("Json", "json"), ("json", "json")]
    )
    def test_config_log_format_env_is_case_insensitive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str, expected: str
    ) -> None:
        monkeypatch.setenv("LOG_FORMAT", value)
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert config.log_format == expected

    def test_config_log_format_env_overrides_yaml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LOG_FORMAT", "TEXT")
        yaml_path = _write_yaml(tmp_path / "config.yaml", "log_format: json\n")
        assert load_app_config(yaml_path).log_format == "text"

    @pytest.mark.parametrize(
        ("yaml_text", "expected"), [("", "text"), ("log_format: json\n", "json")]
    )
    def test_config_invalid_log_format_env_keeps_yaml_or_default(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        yaml_text: str,
        expected: str,
    ) -> None:
        """An invalid LOG_FORMAT is ignored: loading succeeds with the YAML/default value."""
        monkeypatch.setenv("LOG_FORMAT", _JUNK_LOG_FORMAT)
        config = load_app_config(_write_yaml(tmp_path / "config.yaml", yaml_text))
        assert config.log_format == expected

    def test_config_invalid_log_format_env_warns_without_the_value(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The WARNING names LOG_FORMAT; the value itself reaches no log record."""
        monkeypatch.setenv("LOG_FORMAT", _JUNK_LOG_FORMAT)
        with caplog.at_level(logging.DEBUG):
            load_app_config(_write_yaml(tmp_path / "config.yaml", ""))
        assert any(
            "LOG_FORMAT" in record.getMessage()
            for record in caplog.records
            if record.levelno == logging.WARNING
        )
        assert _JUNK_LOG_FORMAT not in caplog.text
