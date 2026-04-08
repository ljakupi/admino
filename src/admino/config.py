"""Configuration loading and validation for admino.

Reads and validates two YAML configuration files at startup:
- config.yaml  -- main application config (server, Ollama, paths, limits, etc.)
- permissions.yaml -- tool permission rules (delegated to permissions.py)

Environment variable overrides are supported for deployment flexibility.
Secrets (OAUTH_ENCRYPTION_KEY, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, AUTH_TOKEN)
are NEVER read from YAML -- they come exclusively from environment variables.

Security notes:
- No secrets in config.yaml. Credentials come from env vars only.
- Path fields are resolved to absolute paths relative to the config file location.
- Invalid config causes the agent to refuse to start with a clear error message.
- YAML parsing uses safe_load only (no arbitrary Python object deserialization).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, SecretStr, ValidationError, field_validator, model_validator

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
        description="Bind address for the ASGI server (IPv4, IPv6, or 'localhost').",
    )
    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="Listen port for the ASGI server.",
    )

    @field_validator("host")
    @classmethod
    def validate_host_address(cls, v: str) -> str:
        """Validate host is a proper IP address or 'localhost'."""
        if v == "localhost":
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError:
            msg = f"ServerConfig.host {v[:64]!r} is not a valid IP address or 'localhost'."
            raise ValueError(msg) from None
        return v


class OllamaConfig(BaseModel):
    """Ollama LLM inference settings.

    Security note: use http:// only for local/Docker networking (ollama, localhost,
    127.0.0.1). For remote Ollama instances, use https:// to prevent cleartext
    transmission of conversation history.
    """

    url: str = Field(
        default="http://ollama:11434",
        max_length=500,
        pattern=r"^https?://",
        description="Base URL for the Ollama API.",
    )

    @field_validator("url")
    @classmethod
    def warn_on_insecure_remote_url(cls, v: str) -> str:
        """Warn when http:// is used with a non-local host.

        Uses ipaddress to detect loopback and link-local addresses so that
        non-standard loopback IPs (e.g. 127.0.0.2) and IPv6 link-local
        addresses (fe80::) are correctly treated as local.
        """
        # Reject control characters (CRLF injection, null bytes).
        if any(c in v for c in "\r\n\x00"):
            msg = "OllamaConfig.url must not contain control characters."
            raise ValueError(msg)

        if v.startswith("http://"):
            host_match = re.match(r"^http://([^/:]+)", v)
            host = host_match.group(1) if host_match else ""
            if not host:
                msg = "OllamaConfig.url must include a hostname."
                raise ValueError(msg)
            # Named local hosts and Docker service names
            local_names = frozenset({"localhost", "ollama"})
            is_local = host in local_names
            if not is_local:
                try:
                    addr = ipaddress.ip_address(host)
                    is_local = addr.is_loopback or addr.is_link_local
                except ValueError:
                    pass  # Not an IP address — treat as remote
            if not is_local:
                logger.warning(
                    "OllamaConfig.url uses http:// with non-local host '%s'. "
                    "Conversation history will be transmitted in cleartext. "
                    "Use https:// for remote Ollama instances.",
                    host,
                )
        return v

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

    @field_validator("model")
    @classmethod
    def validate_model_name(cls, v: str) -> str:
        """Reject model names containing shell metacharacters."""
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.:\-/]*$", v):
            msg = "OllamaConfig.model contains invalid characters."
            raise ValueError(msg)
        return v


class AuthConfig(BaseModel):
    """Authentication configuration.

    The actual token value is read from the AUTH_TOKEN env var, never from YAML.
    """

    mode: Literal["vpn", "token"] = Field(
        default="vpn",
        description="Auth mode: 'vpn' trusts all connections, 'token' requires Bearer token.",
    )
    token: SecretStr | None = Field(
        default=None,
        description="Bearer token for 'token' auth mode. Populated from AUTH_TOKEN env var.",
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
    tokens_dir: Path = Field(
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
            "oauth2.googleapis.com",
            "accounts.google.com",
            "www.googleapis.com",
        ],
        description=(
            "Hostnames allowed for outbound connections. "
            "Wildcards (*.example.com) resolve only the apex domain, "
            "NOT subdomains — list each subdomain explicitly."
        ),
    )

    @field_validator("allowed_hosts")
    @classmethod
    def validate_allowed_hosts(cls, v: list[str]) -> list[str]:
        """Ensure all host entries are non-empty, valid hostname patterns.

        Only allows characters safe for shell use and iptables: alphanumeric,
        dots, hyphens, and leading wildcards (e.g. *.googleapis.com).
        """
        # Requires at least 2 characters (matching the shell regex in entrypoint.sh).
        # Single-char hostnames are not valid DNS labels and are rejected by both validators.
        safe_host_re = re.compile(r"(\*\.)?[a-zA-Z0-9][a-zA-Z0-9.\-]*[a-zA-Z0-9]")
        for host in v:
            if not host or len(host) > 253:
                msg = f"Invalid host entry: '{host}'. Must be 2-253 characters."
                raise ValueError(msg)
            if ".." in host:
                msg = "Invalid host entry: consecutive dots are not allowed."
                raise ValueError(msg)
            if not safe_host_re.fullmatch(host):
                msg = (
                    f"Invalid host entry: '{host}'. "
                    "Only alphanumeric characters, dots, hyphens, and a leading '*.' are allowed."
                )
                raise ValueError(msg)
            # Reject raw IP addresses — require DNS hostnames.
            bare_host = host.removeprefix("*.")
            try:
                ipaddress.ip_address(bare_host)
            except ValueError:
                pass  # Not an IP — this is the expected (good) case.
            else:
                msg = "Raw IP addresses are not allowed in egress whitelist; use DNS hostnames."
                raise ValueError(msg)
        return v


# SECURITY: Do not add entries without a security review. Each prefix expands
# the set of directories from which the OCR binary may be loaded. An overly
# broad prefix (e.g. "/tmp/") would allow binary substitution attacks.
_SAFE_BINARY_PREFIXES: tuple[str, ...] = (
    "/usr/bin/",
    "/usr/local/bin/",
    "/opt/homebrew/bin/",
)


class OcrConfig(BaseModel):
    """OCR (Tesseract) configuration."""

    binary: Path = Field(
        default=Path("/usr/bin/tesseract"),
        description="Path to the Tesseract binary. Must reside under a known-safe prefix.",
    )
    languages: list[str] = Field(
        default_factory=lambda: ["eng"],
        description="Language codes for Tesseract OCR.",
    )

    @field_validator("binary")
    @classmethod
    def validate_binary_path(cls, v: Path) -> Path:
        """Restrict the Tesseract binary to known-safe directory prefixes.

        Prevents an operator-supplied config from redirecting the OCR binary
        to an arbitrary executable (e.g. /tmp/evil-tesseract).

        Both the unresolved and resolved paths must reside under a safe prefix
        to prevent symlink laundering (e.g. /tmp/tess -> /usr/bin/tesseract).
        """
        # Check unresolved path is also under a safe prefix (prevents symlink laundering)
        if not any(str(v).startswith(prefix) for prefix in _SAFE_BINARY_PREFIXES):
            msg = "OcrConfig.binary must reside under a safe prefix before and after resolution."
            raise ValueError(msg)
        resolved = v.resolve()
        if not any(str(resolved).startswith(prefix) for prefix in _SAFE_BINARY_PREFIXES):
            msg = "OcrConfig.binary resolves outside safe prefixes."
            raise ValueError(msg)
        # Warn if the binary does not exist yet (may not be installed on every dev machine).
        # In production, a missing binary is a hard error.
        if not resolved.is_file():
            if os.environ.get("ADMINO_ENV", "").lower() == "production":
                msg = (
                    "OCR binary does not exist at the resolved path and "
                    "ADMINO_ENV=production. Tesseract must be installed."
                )
                raise ValueError(msg)
            logger.warning(
                "OCR binary does not exist at the resolved path. "
                "Tesseract may not be installed on this machine."
            )
        return resolved

    @field_validator("languages")
    @classmethod
    def validate_languages(cls, v: list[str]) -> list[str]:
        """Ensure language codes are reasonable and contain no shell metacharacters."""
        for lang in v:
            if not lang or len(lang) > 10:
                msg = f"Invalid language code: '{lang}'. Must be 1-10 characters."
                raise ValueError(msg)
            if not re.match(r"^[a-zA-Z0-9_-]+$", lang):
                msg = (
                    "Invalid language code: must contain only"
                    " letters, digits, underscores, and hyphens."
                )
                raise ValueError(msg)
        return v


class FilePathEntry(BaseModel):
    """A single allowed file path entry from config.yaml files.allowed_paths."""

    path: str = Field(
        min_length=1,
        max_length=500,
        description="Absolute path to an allowed directory.",
    )
    label: str = Field(
        default="",
        max_length=100,
        description="Human-readable label for this path.",
    )
    access: Literal["read", "readwrite"] = Field(
        default="read",
        description="Access mode: 'read' for read-only, 'readwrite' for read-write.",
    )


class FilesConfig(BaseModel):
    """Configuration for the files tool — allowed paths and read limits."""

    allowed_paths: list[FilePathEntry] = Field(
        default_factory=list,
        description="List of allowed file system paths the agent can access.",
    )
    max_read_chars: int = Field(
        default=10000,
        ge=100,
        le=1_000_000,
        description="Maximum characters to return when reading a file.",
    )


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
    files: FilesConfig = Field(default_factory=FilesConfig)
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
        self.paths.tokens_dir = self.paths.tokens_dir.resolve()
        # ocr.binary is already resolved in OcrConfig.validate_binary_path
        return self

    @model_validator(mode="after")
    def warn_vpn_mode_on_all_interfaces(self) -> AppConfig:
        """Warn when binding to all interfaces with no application-layer auth.

        If server.host is 0.0.0.0 (all interfaces) and auth.mode is 'vpn'
        (trust-the-network), the API is unauthenticated on every interface.
        This is dangerous on a VPS with a public IP.
        """
        if self.server.host == "0.0.0.0" and self.auth.mode == "vpn":  # noqa: S104
            logger.warning(
                "server.host is '0.0.0.0' with auth.mode='vpn' — the API is "
                "unauthenticated on ALL network interfaces. Ensure VPN/firewall "
                "controls are in place, or switch to auth.mode='token'."
            )
        return self

    @model_validator(mode="after")
    def validate_auth_token_present(self) -> AppConfig:
        """Fail fast if token auth is configured but AUTH_TOKEN is unset or weak.

        Prevents an empty-string AUTH_TOKEN from creating an authentication
        bypass where any request without an Authorization header would match.
        """
        if self.auth.mode == "token":
            token = os.environ.get("AUTH_TOKEN", "")
            if len(token) < 48:
                msg = (
                    "auth.mode is 'token' but AUTH_TOKEN env var is missing or "
                    "shorter than 48 characters. Set a strong AUTH_TOKEN or use "
                    "auth.mode: vpn."
                )
                raise ValueError(msg)
            if not re.fullmatch(r"[A-Za-z0-9_-]+", token):
                msg = (
                    "AUTH_TOKEN contains invalid characters. "
                    "Only base64-URL-safe characters [A-Za-z0-9_-] are allowed."
                )
                raise ValueError(msg)
            # Floor check only — not a substitute for cryptographically random generation.
            # Recommended: python -c "import secrets; print(secrets.token_urlsafe(48))"
            if len(set(token)) < 20:
                msg = (
                    "AUTH_TOKEN has insufficient entropy (fewer than 20 unique "
                    "characters). Generate with: "
                    'python -c "import secrets; print(secrets.token_urlsafe(48))"'
                )
                raise ValueError(msg)
            self.auth.token = SecretStr(token)
        return self


# ---------------------------------------------------------------------------
# Config loading functions
# ---------------------------------------------------------------------------

_VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


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
        else:
            logger.warning(
                "Cannot apply OLLAMA_BASE_URL override: 'ollama' config section is not a mapping."
            )

    ollama_model = os.environ.get("OLLAMA_MODEL")
    if ollama_model:
        ollama_section = data.setdefault("ollama", {})
        if isinstance(ollama_section, dict):
            ollama_section["model"] = ollama_model
        else:
            logger.warning(
                "Cannot apply OLLAMA_MODEL override: 'ollama' config section is not a mapping."
            )

    log_level = os.environ.get("LOG_LEVEL")
    if log_level:
        upper = log_level.upper()
        if upper in _VALID_LOG_LEVELS:
            data["log_level"] = upper
        else:
            logger.warning(
                "Ignoring invalid LOG_LEVEL value %r. Valid: %s",
                log_level,
                ", ".join(sorted(_VALID_LOG_LEVELS)),
            )

    audit_log_path = os.environ.get("AUDIT_LOG_PATH")
    if audit_log_path:
        paths_section = data.setdefault("paths", {})
        if isinstance(paths_section, dict):
            paths_section["audit_log"] = audit_log_path
        else:
            logger.warning(
                "Cannot apply AUDIT_LOG_PATH override: 'paths' config section is not a mapping."
            )

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

    _max_config_bytes = 1_048_577  # 1 MB + 1 byte to detect oversize
    try:
        logger.info("Loading config from %s", config_path)
        with open(config_path, encoding="utf-8") as f:
            raw_text = f.read(_max_config_bytes)
        if len(raw_text) >= _max_config_bytes:
            msg = "Config file exceeds 1MB size limit."
            raise ValueError(msg)
    except FileNotFoundError:
        logger.warning(
            "Config file %s not found, using defaults with env overrides.",
            config_path,
        )
        raw_text = None

    if raw_text is not None:
        try:
            parsed = yaml.safe_load(raw_text)
        except yaml.YAMLError as exc:
            msg = "config.yaml contains invalid YAML syntax."
            raise ValueError(msg) from exc
        if parsed is not None:
            if not isinstance(parsed, dict):
                msg = f"config.yaml must contain a YAML mapping, got {type(parsed).__name__}"
                raise ValueError(msg)
            data = parsed

    data = _apply_env_overrides(data)

    try:
        return AppConfig.model_validate(data)
    except ValidationError as exc:
        error_count = exc.error_count()
        # Log field paths for operator debugging but do not include in the
        # exception message — adversarial YAML keys could leak through loc tuples.
        for err in exc.errors(include_input=False):
            # Sanitize loc elements — adversarial YAML keys could inject non-printable
            # characters or overly long strings into the log.
            safe_loc = tuple(repr(part)[:64] for part in err["loc"])
            logger.error("Config validation error at %s: %s", safe_loc, err["msg"])
        msg = (
            f"Invalid application config: validation failed on "
            f"{error_count} field(s) — check server logs for details"
        )
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
    try:
        raw_text = permissions_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        msg = f"Permissions config not found: {permissions_path}"
        raise FileNotFoundError(msg) from None

    logger.info("Loading permissions config from %s", permissions_path)
    try:
        parsed = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        msg = "permissions.yaml contains invalid YAML syntax."
        raise ValueError(msg) from exc

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
        for k, v in actions.items():
            if not isinstance(v, str):
                msg = (
                    f"Action value for '{tool_name}.{k}' must be a string, got {type(v).__name__}."
                )
                raise ValueError(msg)
        tools_typed[tool_name] = {str(k): str(v) for k, v in actions.items()}

    return validate_permissions_config(tools_typed)
