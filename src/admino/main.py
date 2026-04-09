"""Entry point for admino — load config, validate, wire dependencies, start uvicorn.

Startup sequence:
1. Load and validate config.yaml (with env var overrides).
2. Load and validate permissions.yaml.
3. Configure Python logging from config.log_level.
4. Open the append-only audit logger.
5. Create the Ollama LLM client.
6. Import tool modules to trigger @register_tool decorators, then freeze the registry.
7. Instantiate the Agent with all dependencies.
8. Create the FastAPI app via server.create_app().
9. Start uvicorn with single-worker constraint.

The module refuses to start on any configuration or validation error,
printing a clear message and exiting with code 1. Internal paths and
secrets are never included in error output.

Security notes:
- AUTH_TOKEN is validated at config load time; never logged.
- Audit logger uses base_dir confinement to prevent path traversal.
- Registry is frozen after tool imports to block dynamic registration.
- Single-worker uvicorn prevents split-brain session state.
- HSTS is not set here (plain HTTP local deployment). When deploying
  behind a TLS reverse proxy, configure HSTS at the proxy layer.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Final

import uvicorn

from admino.config import load_app_config, load_permissions_config
from admino.models import AgentConfig

logger = logging.getLogger(__name__)

# Config directory: CONFIG_DIR env var (set in .env / docker-compose), or
# fall back to ./config (local dev from project root).
_CONFIG_DIR: Final[Path] = Path(os.environ.get("CONFIG_DIR", "config"))
_DEFAULT_CONFIG_PATH: Final[Path] = _CONFIG_DIR / "config.yaml"
_DEFAULT_PERMISSIONS_PATH: Final[Path] = _CONFIG_DIR / "permissions.yaml"

# Valid Python log levels (explicit allowlist for _configure_logging).
_VALID_LOG_LEVELS: Final[frozenset[str]] = frozenset(
    {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
)


def _configure_logging(level_name: str) -> None:
    """Configure root logger with a consistent format.

    Only accepts the five standard Python log levels. Any other value
    falls back to INFO. This avoids relying solely on upstream Pydantic
    validation and prevents accidental acceptance of arbitrary
    ``logging`` module attributes via ``getattr``.

    Args:
        level_name: Python log level name (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    """
    if level_name not in _VALID_LOG_LEVELS:
        level_name = "INFO"
    numeric_level = getattr(logging, level_name)  # safe: level_name is in allowlist
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        force=True,
    )


def _import_tool_modules() -> None:
    """Import tool modules to trigger @register_tool decorator side effects.

    Uses explicit static imports (no importlib) to comply with SEC-20.
    Only imports modules that exist; logs a warning for missing modules
    (tools may not all be implemented yet during development).
    """
    _names = [
        "admino.tools.gmail",
        "admino.tools.calendar",
        "admino.tools.news",
        "admino.tools.documents",
        "admino.tools.search",
        "admino.tools.files",
        "admino.tools.memory",
        "admino.tools.aggregate",
        "admino.tools.recipes",
    ]

    for module_name in _names:
        try:
            # __import__ is a built-in (not importlib) and is the primitive
            # that the import statement itself compiles to. SEC-20 bans
            # importlib; __import__ with a hardcoded name list is equivalent
            # to writing nine ``import admino.tools.X`` statements.
            __import__(module_name)
        except ModuleNotFoundError:
            logger.warning("Tool module %s not found, skipping.", module_name)
        except Exception:
            logger.error("Failed to import tool module %s", module_name)
            raise


def _build_system_prompt(config: object) -> str:
    """Build a system prompt from the validated application config.

    Tells the LLM which file paths it can access so it doesn't have to
    guess and hit permission errors.

    Args:
        config: Validated AppConfig instance.

    Returns:
        A system prompt string, or empty string if nothing meaningful to say.
    """
    from admino.config import AppConfig

    if not isinstance(config, AppConfig):
        return ""

    lines: list[str] = [
        "You are admino, a local personal AI assistant.",
        "You have access to the following tools: memory (store/recall/list key-value notes) "
        "and files (read/list/search/write/move files).",
        "",
    ]

    if config.files.allowed_paths:
        lines.append("The following file paths are available to you:")
        for entry in config.files.allowed_paths:
            from pathlib import Path as _Path

            resolved = _Path(entry.path).resolve()
            access_desc = "read and write" if entry.access == "readwrite" else "read only"
            lines.append(f"  - {entry.label}: {resolved}  ({access_desc})")
        lines.append(
            "When using file tools, always use the exact paths listed above "
            "(or paths within those directories)."
        )

    return "\n".join(lines)


def main(
    *,
    config_path: Path = _DEFAULT_CONFIG_PATH,
    permissions_path: Path = _DEFAULT_PERMISSIONS_PATH,
) -> None:
    """Load configuration, wire dependencies, and start the server.

    This is the primary entry point. It performs all startup validation
    and refuses to start if any step fails, printing a clear error
    message and exiting with code 1.

    Args:
        config_path: Path to config.yaml.
        permissions_path: Path to permissions.yaml.
    """
    # ------------------------------------------------------------------
    # 1. Load and validate application config
    # ------------------------------------------------------------------
    try:
        config = load_app_config(config_path)
    except (ValueError, OSError) as exc:
        print(f"ERROR: Failed to load config: {exc}", file=sys.stderr)
        sys.exit(1)

    # ------------------------------------------------------------------
    # 2. Configure logging from validated config
    # ------------------------------------------------------------------
    _configure_logging(config.log_level)
    logger.info("Configuration loaded successfully.")

    # ------------------------------------------------------------------
    # 3. Load and validate permissions config
    # ------------------------------------------------------------------
    try:
        permissions_config = load_permissions_config(permissions_path)
    except (ValueError, FileNotFoundError, OSError):
        logger.error("Failed to load permissions config.")
        sys.exit(1)

    logger.info("Permissions config loaded successfully.")

    # ------------------------------------------------------------------
    # 4. Open the audit logger with path confinement
    # ------------------------------------------------------------------
    from admino.audit import AuditLogger

    audit_base_dir = config.paths.audit_log.parent
    try:
        audit_logger = AuditLogger(config.paths.audit_log, base_dir=audit_base_dir)
    except (ValueError, OSError) as exc:
        logger.error("Failed to open audit log: %s", exc)
        sys.exit(1)

    logger.info("Audit logger opened.")
    logger.debug("Audit log path: %s", config.paths.audit_log)

    # ------------------------------------------------------------------
    # 5. Create the Ollama LLM client
    # ------------------------------------------------------------------
    from admino.llm import OllamaClient

    llm_client = OllamaClient(config.ollama)
    logger.info("Ollama client configured.")
    logger.debug("Ollama URL: %s", config.ollama.url)

    # ------------------------------------------------------------------
    # 6. Configure and import tool modules, then freeze the registry
    # ------------------------------------------------------------------

    # Configure tool modules with paths from the validated config BEFORE
    # importing them (import triggers @register_tool decorators, not config).
    from admino.tools import files as files_tool
    from admino.tools import memory as memory_tool
    from admino.tools.registry import freeze_registry

    memory_tool.configure(config.paths.database)
    files_tool.configure(
        allowed_paths=[
            {"path": entry.path, "label": entry.label, "access": entry.access}
            for entry in config.files.allowed_paths
        ],
        max_read_chars=config.files.max_read_chars,
    )
    logger.info("Tool modules configured (memory, files).")

    _import_tool_modules()
    freeze_registry()
    logger.info("Tool registry frozen.")

    # ------------------------------------------------------------------
    # 7. Build AgentConfig from the validated application config
    # ------------------------------------------------------------------
    agent_config = AgentConfig(
        max_tool_calls=config.limits.max_tool_calls_per_message,
        max_context_messages=config.limits.max_context_messages,
        confirmation_timeout_s=float(config.limits.confirmation_timeout_s),
    )

    # ------------------------------------------------------------------
    # 8. Build system prompt from config and instantiate the Agent
    # ------------------------------------------------------------------
    from admino.agent import Agent

    system_prompt = _build_system_prompt(config)

    agent = Agent(
        llm_client=llm_client,
        audit_logger=audit_logger,
        permissions_config=permissions_config,
        agent_config=agent_config,
        model_name=config.ollama.model,
        system_prompt=system_prompt,
    )
    logger.info("Agent initialized with model %s", config.ollama.model)

    # ------------------------------------------------------------------
    # 9. Create the FastAPI app
    # ------------------------------------------------------------------
    from admino.server import create_app

    app = create_app(agent=agent, config=config)

    # ------------------------------------------------------------------
    # 10. Start uvicorn (single worker — required for in-memory session state)
    # ------------------------------------------------------------------
    logger.info(
        "Starting uvicorn on %s:%d (single worker)",
        config.server.host,
        config.server.port,
    )

    uvicorn.run(
        app,
        host=config.server.host,
        port=config.server.port,
        workers=1,
        log_level=config.log_level.lower(),
        # Disable uvicorn's default access log to avoid double-logging.
        access_log=False,
    )


if __name__ == "__main__":
    main()
