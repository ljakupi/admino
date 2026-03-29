"""Configuration loading and validation for admino.

Reads and validates two YAML configuration files at startup:
- config.yaml  -- main application config (server, Ollama, paths, limits, etc.)
- permissions.yaml -- tool permission rules (delegated to permissions.py)

Environment variable overrides are supported for deployment flexibility.
Secrets (FERNET_KEY, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, AUTH_TOKEN)
are NEVER read from YAML -- they come exclusively from environment variables.

Security notes:
- No secrets in config.yaml. Credentials come from env vars only.
- Path fields are resolved to absolute paths relative to the config file location.
- Invalid config causes the agent to refuse to start with a clear error message.
- YAML parsing uses safe_load only (no arbitrary Python object deserialization).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from admino.permissions import PermissionsConfig, validate_permissions_config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic config models
# ---------------------------------------------------------------------------


class ServerConfig(BaseModel):
    """HTTP server settings."""

    host: str = Field(
        default="0.0.0.0",  # noqa: S104
        max_length=255,
        description="Bind address for the ASGI server.",
    )
    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="Listen port for the ASGI server.",
    )


class OllamaConfig(BaseModel):
    """Ollama LLM inference settings."""

    url: str = Field(
        default="http://ollama:11434",
        max_length=500,
        pattern=r"^https?://",
        description="Base URL for the Ollama API.",
    )
    model: str = Field(
        default="qwen2.5-coder:14b",
        max_length=200,
        description="Model name to request from Ollama.",
    )
    timeout_s: int = Field(
        default=120,
        ge=1,
        le=600,
        description="Request timeout in seconds for Ollama API calls.",
    )


class AuthConfig(BaseModel):
    """Authentication configuration.

    The actual token value is read from the AUTH_TOKEN env var, never from YAML.
    """

    mode: Literal["vpn", "token"] = Field(
        default="vpn",
        description="Auth mode: 'vpn' trusts all connections, 'token' requires Bearer token.",
    )


class PathsConfig(BaseModel):
    """Filesystem path configuration.

    All paths are resolved to absolute paths during validation.
    """

    database: Path = Field(
        default=Path("/app/data/db/admino.db"),
        description="Path to the SQLite database file.",
    )
    audit_log: Path = Field(
        default=Path("/app/data/logs/audit.jsonl"),
        description="Path to the append-only NDJSON audit log.",
    )
    images: Path = Field(
        default=Path("/app/data/images"),
        description="Directory for uploaded document images.",
    )
    tokens: Path = Field(
        default=Path("/app/data/tokens"),
        description="Directory for encrypted OAuth refresh tokens.",
    )


class LimitsConfig(BaseModel):
    """Rate and size limits for the agent."""

    max_tool_calls_per_message: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum tool calls the agent may make per user message.",
    )
    max_pending_confirmations: int = Field(
        default=3,
        ge=1,
        le=50,
        description="Maximum pending confirmation prompts at any time.",
    )
    confirmation_timeout_s: int = Field(
        default=300,
        ge=10,
        le=3600,
        description="Seconds before an unconfirmed action is automatically denied.",
    )
    max_message_length: int = Field(
        default=4000,
        ge=1,
        le=100_000,
        description="Maximum length of a user message in characters.",
    )
    max_context_messages: int = Field(
        default=20,
        ge=1,
        le=200,
        description="Maximum conversation messages sent as context to the LLM.",
    )


class EgressConfig(BaseModel):
    """Network egress whitelist configuration."""

    allowed_hosts: list[str] = Field(
        default_factory=lambda: [
            "*.googleapis.com",
            "oauth2.googleapis.com",
            "accounts.google.com",
        ],
        description="Hostnames/patterns allowed for outbound connections.",
    )

    @field_validator("allowed_hosts")
    @classmethod
    def validate_allowed_hosts(cls, v: list[str]) -> list[str]:
        """Ensure all host entries are non-empty strings."""
        for host in v:
            if not host or len(host) > 253:
                msg = f"Invalid host entry: '{host}'. Must be 1-253 characters."
                raise ValueError(msg)
        return v


class OcrConfig(BaseModel):
    """OCR (Tesseract) configuration."""

    binary: Path = Field(
        default=Path("/usr/bin/tesseract"),
        description="Path to the Tesseract binary.",
    )
    languages: list[str] = Field(
        default_factory=lambda: ["eng"],
        description="Language codes for Tesseract OCR.",
    )

    @field_validator("languages")
    @classmethod
    def validate_languages(cls, v: list[str]) -> list[str]:
        """Ensure language codes are reasonable."""
        for lang in v:
            if not lang or len(lang) > 10:
                msg = f"Invalid language code: '{lang}'. Must be 1-10 characters."
                raise ValueError(msg)
        return v


class AppConfig(BaseModel):
    """Top-level application configuration validated from config.yaml.

    Environment variable overrides are applied after YAML loading:
    - OLLAMA_BASE_URL -> ollama.url
    - OLLAMA_MODEL -> ollama.model
    - LOG_LEVEL -> log_level
    - AUDIT_LOG_PATH -> paths.audit_log
    """

    server: ServerConfig = Field(default_factory=ServerConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    egress: EgressConfig = Field(default_factory=EgressConfig)
    ocr: OcrConfig = Field(default_factory=OcrConfig)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Python logging level for the application.",
    )

    @model_validator(mode="after")
    def resolve_paths(self) -> AppConfig:
        """Ensure all path fields are absolute."""
        self.paths.database = self.paths.database.resolve()
        self.paths.audit_log = self.paths.audit_log.resolve()
        self.paths.images = self.paths.images.resolve()
        self.paths.tokens = self.paths.tokens.resolve()
        self.ocr.binary = self.ocr.binary.resolve()
        return self


# ---------------------------------------------------------------------------
# Config loading functions
# ---------------------------------------------------------------------------


def _apply_env_overrides(data: dict[str, object]) -> dict[str, object]:
    """Apply environment variable overrides to raw config data.

    Supported env vars:
    - OLLAMA_BASE_URL  -> ollama.url
    - OLLAMA_MODEL     -> ollama.model
    - LOG_LEVEL        -> log_level
    - AUDIT_LOG_PATH   -> paths.audit_log

    Args:
        data: Raw config dict parsed from YAML.

    Returns:
        The config dict with env overrides applied in-place.
    """
    ollama_url = os.environ.get("OLLAMA_BASE_URL")
    if ollama_url:
        ollama_section = data.setdefault("ollama", {})
        if isinstance(ollama_section, dict):
            ollama_section["url"] = ollama_url

    ollama_model = os.environ.get("OLLAMA_MODEL")
    if ollama_model:
        ollama_section = data.setdefault("ollama", {})
        if isinstance(ollama_section, dict):
            ollama_section["model"] = ollama_model

    log_level = os.environ.get("LOG_LEVEL")
    if log_level:
        data["log_level"] = log_level.upper()

    audit_log_path = os.environ.get("AUDIT_LOG_PATH")
    if audit_log_path:
        paths_section = data.setdefault("paths", {})
        if isinstance(paths_section, dict):
            paths_section["audit_log"] = audit_log_path

    return data


def load_app_config(config_path: Path) -> AppConfig:
    """Load and validate the main application config from a YAML file.

    Reads config.yaml, applies environment variable overrides, validates
    with Pydantic, and returns the config. Falls back to defaults if the
    config file does not exist.

    Args:
        config_path: Path to config.yaml.

    Returns:
        A validated AppConfig instance.

    Raises:
        ValueError: If the YAML is malformed or config validation fails.
        OSError: If the file cannot be read (permissions, etc.).
    """
    data: dict[str, object] = {}

    if config_path.exists():
        logger.info("Loading config from %s", config_path)
        raw_text = config_path.read_text(encoding="utf-8")
        parsed = yaml.safe_load(raw_text)
        if parsed is not None:
            if not isinstance(parsed, dict):
                msg = f"config.yaml must contain a YAML mapping, got {type(parsed).__name__}"
                raise ValueError(msg)
            data = parsed
    else:
        logger.warning(
            "Config file %s not found, using defaults with env overrides.",
            config_path,
        )

    data = _apply_env_overrides(data)

    try:
        return AppConfig.model_validate(data)
    except Exception as exc:
        msg = f"Invalid application config: {exc}"
        raise ValueError(msg) from exc


def load_permissions_config(permissions_path: Path) -> PermissionsConfig:
    """Load and validate the permissions config from a YAML file.

    Reads permissions.yaml, extracts the 'tools' block, and delegates
    validation to permissions.validate_permissions_config().

    Args:
        permissions_path: Path to permissions.yaml.

    Returns:
        A validated PermissionsConfig instance.

    Raises:
        ValueError: If the YAML is malformed or validation fails.
        FileNotFoundError: If the permissions file does not exist.
    """
    if not permissions_path.exists():
        msg = f"Permissions config not found: {permissions_path}"
        raise FileNotFoundError(msg)

    logger.info("Loading permissions config from %s", permissions_path)
    raw_text = permissions_path.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw_text)

    if not isinstance(parsed, dict):
        msg = f"permissions.yaml must contain a YAML mapping, got {type(parsed).__name__}"
        raise ValueError(msg)

    tools_raw = parsed.get("tools")
    if tools_raw is None:
        msg = "permissions.yaml must contain a 'tools' key."
        raise ValueError(msg)

    if not isinstance(tools_raw, dict):
        msg = f"permissions.yaml 'tools' must be a mapping, got {type(tools_raw).__name__}"
        raise ValueError(msg)

    # Ensure values are dicts of str->str
    tools_typed: dict[str, dict[str, str]] = {}
    for tool_name, actions in tools_raw.items():
        if not isinstance(tool_name, str):
            msg = f"Tool name must be a string, got {type(tool_name).__name__}"
            raise ValueError(msg)
        if not isinstance(actions, dict):
            msg = f"Actions for tool '{tool_name}' must be a mapping, got {type(actions).__name__}"
            raise ValueError(msg)
        tools_typed[tool_name] = {str(k): str(v) for k, v in actions.items()}

    return validate_permissions_config(tools_typed)
