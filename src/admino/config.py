"""Configuration loading and validation for admino.

Reads and validates the main application config (config.yaml) at startup, and
provides the database-backed loaders that become the runtime source of truth
once the DB is seeded. Tool permission rules live in permissions.py; their
in-code defaults (DEFAULT_PERMISSIONS) seed an empty DB on first run.

Environment variable overrides are supported for deployment flexibility.
Secrets (OAUTH_ENCRYPTION_KEY, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, AUTH_TOKEN)
are NEVER read from YAML -- they come exclusively from environment variables.

Security notes:
- No secrets in config.yaml. Credentials come from env vars only.
- Invalid config causes the agent to refuse to start with a clear error message.
- YAML parsing uses safe_load only (no arbitrary Python object deserialization).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from typing import TYPE_CHECKING, Final, Literal

import yaml
from pydantic import BaseModel, Field, SecretStr, ValidationError, field_validator, model_validator

from admino.permissions import PermissionsConfig, validate_permissions_config

if TYPE_CHECKING:
    from pathlib import Path

    import asyncpg

logger = logging.getLogger(__name__)

# Env var holding each provider's credential (vLLM is local and needs none).
# Only the NAME is ever logged, never the value.
_PROVIDER_KEY_ENV: Final[dict[str, str]] = {
    "infomaniak": "INFOMANIAK_API_TOKEN",
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
}

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


class LLMConfig(BaseModel):
    """LLM provider configuration.

    Supported providers:
    - "infomaniak" (default): Infomaniak AI Services, an OpenAI-compatible API
      hosted in Switzerland (queries are not recorded or used for training).
      Needs the INFOMANIAK_API_TOKEN env var; INFOMANIAK_PRODUCT_ID is optional
      (auto-discovered). Serves ``infomaniak_model``.
    - "vllm" (opt-in, local): a first-class local, OpenAI-compatible provider
      that serves the configured ``vllm_model`` from a local endpoint
      (``vllm_base_url``). It needs no API key. The server may still be starting
      (loading a large model), so validation does NOT probe the network.
    - "anthropic" (opt-in): Anthropic Claude API. Messages sent to Anthropic servers.
    - "openai" (opt-in): OpenAI API. Messages sent to OpenAI servers.

    A missing API key/token or model never fails validation for any provider:
    admino boots, logs a WARNING naming the env var or model field (never a
    credential value), and chat replies explain what to set. Cloud providers
    also log where messages are processed, because they leave the machine.
    """

    provider: Literal["infomaniak", "anthropic", "openai", "vllm"] = Field(
        default="infomaniak",
        description=(
            "LLM provider: 'infomaniak' (default, Swiss-hosted), 'vllm' (opt-in, "
            "local OpenAI-compatible serving), 'anthropic' (opt-in, cloud), "
            "'openai' (opt-in, cloud)."
        ),
    )

    timeout_s: int = Field(
        default=120,
        ge=1,
        le=600,
        description="Request timeout in seconds for LLM API calls.",
    )

    # -- Infomaniak settings (used when provider=infomaniak, the default) --
    # Credentials come from env vars only (INFOMANIAK_API_TOKEN,
    # INFOMANIAK_PRODUCT_ID), never from this config.
    infomaniak_model: str | None = Field(
        default="Qwen/Qwen3.5-397B-A17B-FP8",
        max_length=200,
        description="Infomaniak AI Services model ID (used when provider=infomaniak).",
    )

    # -- vLLM settings (used when provider=vllm) --
    # vLLM is a first-class local provider serving an OpenAI-compatible API.
    # The model default lets the provider boot without a config edit. base_url
    # points at the local endpoint (no API key needed).
    vllm_model: str | None = Field(
        default="Qwen/Qwen3-4B-Instruct-2507",
        max_length=200,
        description="Served vLLM model ID (used when provider=vllm).",
    )
    vllm_base_url: str = Field(
        default="http://vllm:8000/v1",
        max_length=2048,
        description="Base URL of the local OpenAI-compatible vLLM endpoint.",
    )
    vllm_max_model_len: int = Field(
        default=32768,
        ge=512,
        le=262144,
        description="Maximum context length (tokens) the served vLLM model supports.",
    )

    # -- Anthropic settings (used when provider=anthropic) --
    # No hardcoded default: the model ID must come from config.yaml (or
    # Settings → Agent) so that a stale or retired ID can never be silently
    # substituted. A missing value for the active provider logs a warning and
    # chat asks the user to choose a model (see below).
    anthropic_model: str | None = Field(
        default=None,
        max_length=200,
        description="Anthropic model ID, e.g. claude-sonnet-4-6 (used when provider=anthropic).",
    )

    # -- OpenAI settings (used when provider=openai) --
    openai_model: str | None = Field(
        default=None,
        max_length=200,
        description="OpenAI model ID, e.g. gpt-4o (used when provider=openai).",
    )

    # -- Shared settings for every provider --
    max_response_tokens: int = Field(
        default=4096,
        ge=1,
        le=65536,
        description="Maximum tokens in LLM response (sent as max_tokens to every provider).",
    )

    @field_validator("infomaniak_model", "anthropic_model", "openai_model", "vllm_model")
    @classmethod
    def validate_model_name(cls, v: str | None) -> str | None:
        """Reject model names containing shell metacharacters or control chars.

        ``None``/empty are allowed (the field is unset); a missing model for the
        active provider only logs a warning in ``validate_provider_requirements``.
        """
        if not v:
            return v
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.:\-/]*$", v):
            msg = "LLMConfig model field contains invalid characters."
            raise ValueError(msg)
        return v

    @field_validator("vllm_base_url")
    @classmethod
    def validate_vllm_base_url(cls, v: str) -> str:
        """Require an http(s) URL free of whitespace and control characters.

        A malformed base URL would send the local-serving requests to an
        unexpected host, so reject anything that is not a plain http(s) URL.
        """
        if any(ord(ch) < 0x20 or ch.isspace() for ch in v):
            msg = "LLMConfig.vllm_base_url must not contain whitespace or control characters."
            raise ValueError(msg)
        if not v.startswith(("http://", "https://")):
            msg = "LLMConfig.vllm_base_url must start with 'http://' or 'https://'."
            raise ValueError(msg)
        return v

    @model_validator(mode="after")
    def validate_provider_requirements(self) -> LLMConfig:
        """Log provider-specific setup problems and privacy notices at load time.

        Never raises for a missing API key/token or model on any provider: admino
        boots, a WARNING names the env var or the model field (never a credential
        value), and chat replies explain what to set. Validation does NOT probe
        the network. Cloud providers also log where messages are processed.
        """
        key_env = _PROVIDER_KEY_ENV.get(self.provider)
        if key_env and not os.environ.get(key_env, "").strip():
            logger.warning(
                "llm.provider is '%s' but the %s env var is not set. admino starts "
                "anyway; chat replies will ask for it until it is set on the server.",
                self.provider,
                key_env,
            )
        if not self.active_model_name:
            logger.warning(
                "llm.provider is '%s' but llm.%s_model is not set. admino starts "
                "anyway; chat replies will ask to choose a model in Settings → Agent.",
                self.provider,
                self.provider,
            )

        if self.provider == "infomaniak":
            logger.info(
                "LLM provider is 'infomaniak' — user messages and tool results are "
                "processed by Infomaniak in Switzerland (queries are not recorded or "
                "used for training)."
            )
        elif self.provider == "vllm":
            logger.info(
                "LLM provider is 'vllm' (local) — serving '%s' from %s. "
                "If the endpoint is still starting, chat replies will report it "
                "as unavailable until the model finishes loading.",
                self.vllm_model,
                self.vllm_base_url,
            )
        elif self.provider == "anthropic":
            logger.warning(
                "LLM provider is 'anthropic' — user messages and tool results "
                "will be sent to Anthropic's servers. Ensure you accept this trade-off."
            )
        else:
            logger.warning(
                "LLM provider is 'openai' — user messages and tool results "
                "will be sent to OpenAI's servers. Ensure you accept this trade-off."
            )
        return self

    @property
    def active_model_name(self) -> str:
        """Return the model name for the currently configured provider.

        Returns ``""`` (never raises) when the active provider's model is unset;
        the provider client then answers chat with a "choose a model" message.
        """
        if self.provider == "infomaniak":
            name = self.infomaniak_model
        elif self.provider == "vllm":
            name = self.vllm_model
        elif self.provider == "anthropic":
            name = self.anthropic_model
        else:
            name = self.openai_model
        return name or ""


class AuthConfig(BaseModel):
    """Authentication configuration.

    The actual token value is read from the AUTH_TOKEN env var, never from YAML.
    """

    mode: Literal["vpn", "token"] = Field(
        default="token",
        description="Auth mode: 'vpn' trusts all connections, 'token' requires Bearer token.",
    )
    token: SecretStr | None = Field(
        default=None,
        description="Bearer token for 'token' auth mode. Populated from AUTH_TOKEN env var.",
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
        description=(
            "Maximum conversation messages sent as context to the LLM. The"
            " system prompt and the current user message are always sent."
        ),
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


class DatabaseConfig(BaseModel):
    """PostgreSQL connection pool settings."""

    min_pool_size: int = Field(default=2, ge=1, le=20)
    max_pool_size: int = Field(default=5, ge=1, le=50)


class AppConfig(BaseModel):
    """Top-level application configuration validated from config.yaml.

    Unknown top-level sections are ignored (Pydantic's default ``extra``
    behaviour), so a legacy ``files`` section (from before GH-143) or
    ``paths`` section (the removed NDJSON audit log path, GH-147) left in an
    existing config.yaml or settings table still validates and is dropped.

    Environment variable overrides are applied after YAML loading:
    - LLM_PROVIDER      -> llm.provider
    - VLLM_MODEL        -> llm.vllm_model
    - VLLM_BASE_URL     -> llm.vllm_base_url
    - VLLM_MAX_MODEL_LEN -> llm.vllm_max_model_len
    - LOG_LEVEL         -> log_level
    """

    server: ServerConfig = Field(default_factory=ServerConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    egress: EgressConfig = Field(default_factory=EgressConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Python logging level for the application.",
    )

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


def _apply_vllm_env_overrides(data: dict[str, object]) -> None:
    """Apply the VLLM_* env overrides to the ``llm`` config section in-place.

    Handles VLLM_MODEL, VLLM_BASE_URL, and VLLM_MAX_MODEL_LEN. A non-integer
    VLLM_MAX_MODEL_LEN is logged and skipped (mirrors the LOG_LEVEL pattern) so
    a bad value never crashes config loading.

    Args:
        data: Raw config dict parsed from YAML (mutated in place).
    """
    vllm_model = os.environ.get("VLLM_MODEL")
    vllm_base_url = os.environ.get("VLLM_BASE_URL")
    vllm_max_model_len = os.environ.get("VLLM_MAX_MODEL_LEN")
    if not (vllm_model or vllm_base_url or vllm_max_model_len):
        return

    llm_section = data.setdefault("llm", {})
    if not isinstance(llm_section, dict):
        logger.warning("Cannot apply VLLM_* overrides: 'llm' config section is not a mapping.")
        return

    if vllm_model:
        llm_section["vllm_model"] = vllm_model
    if vllm_base_url:
        llm_section["vllm_base_url"] = vllm_base_url
    if vllm_max_model_len:
        try:
            llm_section["vllm_max_model_len"] = int(vllm_max_model_len)
        except ValueError:
            logger.warning(
                "Ignoring invalid VLLM_MAX_MODEL_LEN value %r (not an integer).",
                vllm_max_model_len,
            )


def _apply_env_overrides(data: dict[str, object]) -> dict[str, object]:
    """Apply environment variable overrides to raw config data.

    Supported env vars:
    - LLM_PROVIDER       -> llm.provider
    - VLLM_MODEL         -> llm.vllm_model
    - VLLM_BASE_URL      -> llm.vllm_base_url
    - VLLM_MAX_MODEL_LEN -> llm.vllm_max_model_len (parsed to int)
    - LOG_LEVEL          -> log_level

    Args:
        data: Raw config dict parsed from YAML.

    Returns:
        The config dict with env overrides applied in-place.
    """
    llm_provider = os.environ.get("LLM_PROVIDER")
    if llm_provider:
        llm_section = data.setdefault("llm", {})
        if isinstance(llm_section, dict):
            llm_section["provider"] = llm_provider
        else:
            logger.warning(
                "Cannot apply LLM_PROVIDER override: 'llm' config section is not a mapping."
            )

    _apply_vllm_env_overrides(data)

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

    auth_mode = os.environ.get("AUTH_MODE")
    if auth_mode:
        auth_section = data.setdefault("auth", {})
        if isinstance(auth_section, dict):
            auth_section["mode"] = auth_mode
        else:
            logger.warning(
                "Cannot apply AUTH_MODE override: 'auth' config section is not a mapping."
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


# ---------------------------------------------------------------------------
# Database-backed config loaders
# ---------------------------------------------------------------------------


async def load_app_config_from_db(pool: asyncpg.Pool) -> AppConfig:
    """Load application config from the database.

    Fetches settings rows, reconstructs the config dict, applies env
    overrides, and validates via Pydantic.

    Args:
        pool: The asyncpg connection pool.

    Returns:
        A validated AppConfig instance loaded from the database.
    """
    from admino.database import load_settings_from_db

    data = await load_settings_from_db(pool)
    data = _apply_env_overrides(data)
    return AppConfig.model_validate(data)


async def load_permissions_config_from_db(
    pool: asyncpg.Pool,
) -> PermissionsConfig:
    """Load permissions config from the database.

    Fetches permission rows and validates via validate_permissions_config().

    Args:
        pool: The asyncpg connection pool.

    Returns:
        A validated PermissionsConfig instance loaded from the database.
    """
    from admino.database import load_permissions_from_db

    tools_dict = await load_permissions_from_db(pool)
    return validate_permissions_config(tools_dict)
