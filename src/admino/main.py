"""Entry point for admino — load config, validate, wire dependencies, start uvicorn.

Startup sequence:
1. Load and validate config.yaml (with env var overrides).
2. Configure Python logging from config.log_level and config.log_format
   (text, or structured JSON lines with a per-request ID).
3. Load the bundled common-password list (the password policy's list check).
4. Build the default permissions ruleset (seeds an empty DB on first run).
5. Initialise the database: run migrations, seed, then load config,
   permissions and per-tool enabled state from the DB. No organization is
   created: a fresh install starts with none.
6. Create the LLM client, warn if the provider's API host is not in the egress
   whitelist, and (Infomaniak only) check the token and resolve the product ID.
   These checks only log: a missing key, model or product ID never stops startup
   — chat replies explain what to set.
7. Import tool modules to trigger @register_tool decorators, then freeze the registry.
8. Build the AgentConfig from the validated limits.
9. Instantiate the Agent with all dependencies, including the tool-call
   recorder that writes one ``tool.call`` audit event per dispatch.
10. Create the FastAPI app via server.create_app().
11. Start uvicorn with single-worker constraint.

The module refuses to start on any configuration or validation error,
printing a clear message and exiting with code 1. Internal paths and
secrets are never included in error output.

Security notes:
- A missing or unreadable common-password list stops startup, so the password
  policy's list check can't be silently disabled.
- Provider credentials (e.g. INFOMANIAK_API_TOKEN) are never logged; only the
  env var name appears in startup warnings.
- Tool calls are audited as content-free ``tool.call`` rows in
  ``audit_events`` (tool, action, decision, success, duration — never
  arguments or output) through the recorder injected into the Agent, in the
  acting member's organization. A principal without one (a Super Admin) or a
  failed write raises, so the agent aborts the run (H-1).
- Registry is frozen after tool imports to block dynamic registration.
- Single-worker uvicorn prevents split-brain session state.
- HSTS is not set here: the Caddy proxy of the production profile
  (docker-compose.prod.yml) terminates TLS and sends it.
- uvicorn runs with ``proxy_headers=False``: X-Forwarded-For/Proto are
  believed only from ``server.trusted_proxies`` (the app's middleware), never
  from uvicorn's own default trust of 127.0.0.1 or FORWARDED_ALLOW_IPS.
- Logging (GH-158): one root handler with ``admino.logs``' formatters, which
  never write a traceback (an exception is named by its type only) and cut
  query strings off URLs. uvicorn runs with ``log_config=None`` (its loggers
  go through that handler) and ``access_log=False`` (request paths and query
  strings are never logged). The httpx, httpcore, openai, anthropic,
  googleapiclient and urllib3 loggers are pinned at WARNING: they log request
  URLs with query strings at INFO and whole request payloads at DEBUG.
- Startup failures are logged by exception type with a fixed hint, never the
  exception's message (a DSN carries the database password).
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Final, TextIO

import uvicorn
from pydantic import ValidationError

from admino import passwords
from admino.config import load_app_config
from admino.llm import LLMError
from admino.logs import JsonFormatter, RequestIdFilter, TextFormatter, safe_log
from admino.models import AgentConfig, ToolsSettings
from admino.permissions import build_default_permissions_config

if TYPE_CHECKING:
    from admino.access import Principal
    from admino.agent import ToolCallRecorder
    from admino.config import AppConfig
    from admino.llm_infomaniak import InfomaniakClient
    from admino.permissions import PermissionsConfig, PermissionState

logger = logging.getLogger(__name__)

# Namespace of the per-session chat id that tool.call audit events target until
# #176 gives chats server-generated UUIDs. Fixed, so a session maps to the same
# chat id across restarts.
_SESSION_CHAT_NAMESPACE: Final[uuid.UUID] = uuid.UUID("3b8f6e2a-9c4d-4e71-8a5f-0d2c7b9e1f43")

# Config directory: CONFIG_DIR env var (set in .env / docker-compose), or
# fall back to ./config (local dev from project root).
_CONFIG_DIR: Final[Path] = Path(os.environ.get("CONFIG_DIR", "config"))
_DEFAULT_CONFIG_PATH: Final[Path] = _CONFIG_DIR / "config.yaml"

# Valid Python log levels (explicit allowlist for _configure_logging).
_VALID_LOG_LEVELS: Final[frozenset[str]] = frozenset(
    {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
)

# Third-party loggers pinned at WARNING: httpx/httpcore/urllib3/googleapiclient
# log request URLs (query strings included) at INFO, and the openai/anthropic
# SDKs log whole request payloads (conversation content) at DEBUG.
_PINNED_THIRD_PARTY_LOGGERS: Final[tuple[str, ...]] = (
    "httpx",
    "httpcore",
    "openai",
    "anthropic",
    "googleapiclient",
    "urllib3",
)

# API host each cloud LLM provider must reach through the egress whitelist.
# vLLM is served locally (no egress needed), so it has no entry.
_PROVIDER_EGRESS_HOSTS: Final[dict[str, str]] = {
    "infomaniak": "api.infomaniak.com",
    "anthropic": "api.anthropic.com",
    "openai": "api.openai.com",
}


def _configure_logging(
    level_name: str,
    log_format: str = "text",
    *,
    stream: TextIO | None = None,
) -> None:
    """Replace the root logger's handlers with one admino StreamHandler.

    The handler carries a ``RequestIdFilter`` and the ``JsonFormatter`` for
    ``"json"`` or the ``TextFormatter`` for anything else; neither writes a
    traceback. Only the five standard Python log levels are accepted; any
    other value falls back to INFO (no ``getattr`` on arbitrary ``logging``
    attributes). The chatty third-party loggers are pinned at WARNING, so
    they log no URLs or payloads even at DEBUG.

    Args:
        level_name: Python log level name (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_format: ``"json"`` for JSON lines, otherwise text.
        stream: Where the handler writes (stderr by default).
    """
    if level_name not in _VALID_LOG_LEVELS:
        level_name = "INFO"
    numeric_level = getattr(logging, level_name)  # safe: level_name is in allowlist
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.addFilter(RequestIdFilter())
    handler.setFormatter(JsonFormatter() if log_format == "json" else TextFormatter())
    logging.basicConfig(level=numeric_level, handlers=[handler], force=True)
    for name in _PINNED_THIRD_PARTY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def _warn_missing_provider_egress(config: AppConfig) -> None:
    """Warn when the active LLM provider's API host is not egress-whitelisted.

    Outbound connections to a host missing from ``egress.allowed_hosts`` are
    blocked by iptables in the Docker deployment, so every chat request would
    fail. Local providers (vLLM) need no egress and never warn.

    Args:
        config: Validated application config.
    """
    required_host = _PROVIDER_EGRESS_HOSTS.get(config.llm.provider)
    if required_host and required_host not in config.egress.allowed_hosts:
        logger.warning(
            "LLM provider '%s' requires egress to '%s', but it is not in "
            "egress.allowed_hosts. Outbound connections will be blocked by "
            "iptables. Add '%s' to egress.allowed_hosts in config.yaml.",
            config.llm.provider,
            required_host,
            required_host,
        )


async def _check_infomaniak_startup(client: InfomaniakClient) -> None:
    """Report Infomaniak setup problems at startup without blocking it.

    A missing INFOMANIAK_API_TOKEN logs a WARNING (no product discovery is
    attempted). Otherwise the product ID is resolved (INFOMANIAK_PRODUCT_ID or
    discovery via the Infomaniak API) and any failure — e.g. several products
    and no INFOMANIAK_PRODUCT_ID — is logged as an ERROR with its type and a
    fixed hint (never the error's message). Never raises and never exits: chat
    replies explain the same problem to the user. The token value is never
    logged.

    Args:
        client: The Infomaniak client created for the active provider.
    """
    if not os.environ.get("INFOMANIAK_API_TOKEN", "").strip():
        logger.warning(
            "INFOMANIAK_API_TOKEN is not set. admino starts anyway; chat replies "
            "will ask for it. Create a token with the 'ai-tools' scope in the "
            "Infomaniak Manager and set it on the server."
        )
        return
    try:
        await client.resolve_product_id()
    except LLMError as exc:
        logger.error(
            "Infomaniak startup check failed (%s): check INFOMANIAK_API_TOKEN, and set "
            "INFOMANIAK_PRODUCT_ID when the token sees several AI products.",
            type(exc).__name__,
        )
        return
    logger.info("Infomaniak AI product resolved.")


def _import_tool_modules() -> None:
    """Import tool modules to trigger @register_tool decorator side effects.

    Uses explicit static imports (no importlib) to comply with SEC-20.
    Only imports modules that exist; logs a warning for missing modules
    (tools may not all be implemented yet during development).
    """
    _names = [
        # Google API tools
        "admino.tools.gmail",
        "admino.tools.google_calendar",
        "admino.tools.google_drive",
        # Microsoft Graph API tools
        "admino.tools.outlook",
        "admino.tools.outlook_calendar",
        "admino.tools.onedrive",
        # Other tools
        "admino.tools.memory",
    ]

    for module_name in _names:
        try:
            # __import__ is a built-in (not importlib) and is the primitive
            # that the import statement itself compiles to. SEC-20 bans
            # importlib; __import__ with a hardcoded name list is equivalent
            # to writing seven ``import admino.tools.X`` statements.
            __import__(module_name)
        except ModuleNotFoundError:
            logger.warning("Tool module %s not found, skipping.", module_name)
        except Exception:
            logger.error("Failed to import tool module %s", module_name)
            raise


def _build_system_prompt(
    config: object,
    permissions_config: PermissionsConfig | None = None,
) -> str:
    """Build a system prompt from the validated application config.

    Tells the LLM which tools and actions it can use, that some actions need
    user confirmation, and that it must never substitute a different action
    for the one the user asked for.

    Args:
        config: Validated AppConfig instance.
        permissions_config: When provided, the advertised tool summary is
            filtered through the permission engine so it lists only actions
            the agent can actually take (GH-77).  This keeps the summary
            consistent with the permission-aware tool payload sent each turn
            and avoids presenting hardcoded-denied or un-promoted actions as
            available — which could otherwise invite tool substitution.

    Returns:
        A system prompt string, or empty string if nothing meaningful to say.
    """
    from admino.config import AppConfig

    if not isinstance(config, AppConfig):
        return ""

    from admino.tools.registry import get_registered_tools

    # Build a dynamic tool summary from the registry so the LLM knows which
    # tools are available, grouped by name with their actions listed. When a
    # permissions config is supplied the list is permission-aware: denied and
    # un-promoted actions are excluded so it matches the per-turn tool payload.
    tool_actions: dict[str, list[str]] = {}
    for desc in get_registered_tools(permissions_config=permissions_config):
        tool_actions.setdefault(desc.tool, []).append(desc.action)
    tool_summary = ", ".join(
        f"{name} ({'/'.join(sorted(actions))})" for name, actions in sorted(tool_actions.items())
    )

    lines: list[str] = [
        "You are admino, a local personal AI assistant.",
        f"You have access to the following tools: {tool_summary}.",
        "Some actions may require user confirmation before execution.",
        "",
        "IMPORTANT: Tool permissions can change during a conversation. If a tool "
        "call was previously denied, the user may have since promoted it. Always "
        "attempt the tool call when the user asks — never refuse based on earlier "
        "denials in the conversation. The permission engine will re-evaluate each "
        "call independently.",
        "",
        "CRITICAL — never substitute a different tool or action for the one the "
        "user actually requested. If the exact capability the user asked for is "
        "not available to you (not in your tool list, disabled, or not permitted), "
        "STOP and tell the user that action is not available and why — for example, "
        "that it needs to be enabled or promoted in Critical Permissions. Do NOT "
        "approximate the request with a different tool. This is absolute for "
        "mutating actions: never turn an update into a create, or send to a "
        "different recipient/channel. A duplicate or wrong write is worse than "
        "doing nothing.",
        "",
    ]

    return "\n".join(lines)


def _session_chat_id(session_id: str) -> uuid.UUID:
    """Return the chat id a session's ``tool.call`` audit events target.

    ``uuid5(_SESSION_CHAT_NAMESPACE, session_id)``: deterministic per session,
    and a UUID, so no session text reaches the audit store. The bridge until
    persisted chats (#176) carry server-generated UUIDs.
    """
    return uuid.uuid5(_SESSION_CHAT_NAMESPACE, session_id)


def _build_tool_call_recorder() -> ToolCallRecorder:
    """Build the recorder the Agent awaits after every tool dispatch.

    Each call writes one ``tool.call`` row through
    ``audit_events.record_tool_call`` naming the acting member (their org and
    user id, from ``TenantContext.from_principal``) and targeting the
    session's chat. A principal without an organization (a Super Admin, or a
    malformed principal) raises ``NoTenantContextError`` before anything is
    written. The runtime pool is resolved at call time: it only exists once
    the server lifespan has run, after this recorder was built. Errors
    propagate so the agent aborts the run (H-1).
    """

    async def record(
        *,
        principal: Principal,
        session_id: str,
        tool: str,
        action: str,
        decision: PermissionState,
        success: bool,
        duration_ms: int,
    ) -> None:
        from admino import audit_events, database
        from admino.tenancy import TenantContext

        tenant = TenantContext.from_principal(principal)
        await audit_events.record_tool_call(
            database.get_pool(),
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            chat_id=_session_chat_id(session_id),
            tool=tool,
            action=action,
            decision=decision,
            success=success,
            duration_ms=duration_ms,
        )

    return record


async def _async_startup(
    config: AppConfig,
    permissions_config: PermissionsConfig,
) -> tuple[AppConfig, PermissionsConfig, dict[str, bool]]:
    """Initialise database, run migrations, seed data, and load config from DB.

    Creates no organization: a fresh install starts with none.

    Returns the DB-loaded config and permissions (which become the runtime
    source of truth) plus the persisted per-tool enabled state.

    The tools-enabled map is loaded here, while the startup pool is still
    open, so it can be passed into the ``Agent`` at construction time. This
    is the security-critical fix for GH-80: a service the user toggled
    **off** must stay off across a server restart — the gate has to be
    active on the very first dispatch, before any PATCH arrives. Missing or
    corrupt ``tools`` settings fall back to ``ToolsSettings`` defaults
    (all enabled).

    Args:
        config: The YAML-loaded application config (used for seeding).
        permissions_config: The YAML-loaded permissions config (used for seeding).

    Returns:
        A tuple of ``(db_config, db_permissions, tools_enabled)`` loaded from
        the database. ``tools_enabled`` is a full ``ToolsSettings`` dump
        (every tool name mapped to a bool).

    Raises:
        ValueError: If PG_PASSWORD is not set.
        RuntimeError: If the database health check fails.
    """
    from admino.config import load_app_config_from_db, load_permissions_config_from_db
    from admino.database import (
        check_health,
        close_pool,
        database_url_from_env,
        init_pool,
        load_settings_from_db,
        run_migrations,
        seed_permissions,
        seed_settings,
        update_setting,
    )

    database_url = database_url_from_env()
    if not database_url:
        msg = "PG_PASSWORD environment variable is required but not set."
        raise ValueError(msg)

    pool = await init_pool(
        database_url,
        min_size=config.database.min_pool_size,
        max_size=config.database.max_pool_size,
    )

    if not await check_health():
        await close_pool()
        msg = "PostgreSQL health check failed — database is unreachable."
        raise RuntimeError(msg)

    await run_migrations(pool)
    await seed_settings(pool, config)
    await seed_permissions(pool, permissions_config)

    # config.yaml is authoritative for the LLM section on every boot. The
    # settings table is only seeded once (when empty), so without this the DB
    # would keep a stale provider/model after config.yaml is edited. Re-apply
    # the validated llm section from config.yaml so edits always take effect.
    await update_setting(pool, "llm", config.llm.model_dump(mode="json"))

    db_config = await load_app_config_from_db(pool)
    db_permissions = await load_permissions_config_from_db(pool)

    # GH-80: Load the persisted per-tool enabled state while the pool is open
    # so the gate can be active at Agent construction time. A service the user
    # toggled off must remain off across a restart — not silently re-enabled
    # until the first PATCH. Corrupt/missing tools data falls back to defaults
    # (all enabled) rather than failing startup.
    db_settings = await load_settings_from_db(pool)
    tools_data = db_settings.get("tools", {})
    try:
        tools_enabled = ToolsSettings.model_validate(tools_data).model_dump()
    except ValidationError:
        logger.warning("Corrupt tools settings in DB — defaulting to all enabled.")
        tools_enabled = ToolsSettings().model_dump()

    # Close the pool — it was created on asyncio.run()'s event loop which
    # will be destroyed when asyncio.run() returns.  The server lifespan
    # creates a fresh pool on uvicorn's event loop for runtime use.
    await close_pool()

    return db_config, db_permissions, tools_enabled


def main(
    *,
    config_path: Path = _DEFAULT_CONFIG_PATH,
) -> None:
    """Load configuration, wire dependencies, and start the server.

    This is the primary entry point. It performs all startup validation
    and refuses to start if any step fails, printing a clear error
    message and exiting with code 1.

    Args:
        config_path: Path to config.yaml.
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
    _configure_logging(config.log_level, config.log_format)
    logger.info("Configuration loaded successfully.")

    # ------------------------------------------------------------------
    # 3. Load the bundled common-password list (once, cached)
    # ------------------------------------------------------------------
    # A missing or unreadable list stops startup instead of silently
    # disabling the password policy's list check. The error names no path.
    try:
        passwords.common_passwords()
    except (OSError, ValueError) as exc:
        print(
            f"ERROR: Failed to load the common-password list ({type(exc).__name__}).",
            file=sys.stderr,
        )
        sys.exit(1)

    # ------------------------------------------------------------------
    # 4. Build the default permissions ruleset (seeds an empty DB only)
    # ------------------------------------------------------------------
    # The database is the source of truth for permissions; this in-code default
    # (GH-85) is used solely to seed an empty ``permissions`` table on first run.
    permissions_config = build_default_permissions_config()
    logger.info("Default permissions ruleset built for DB seeding.")

    # ------------------------------------------------------------------
    # 5. Initialize database, run migrations, seed and load from DB
    # ------------------------------------------------------------------
    try:
        config, permissions_config, tools_enabled = asyncio.run(
            _async_startup(config, permissions_config)
        )
    except (ValueError, RuntimeError, OSError) as exc:
        # The type only: the message can carry the DSN (the database password).
        logger.error(
            "Database startup failed (%s): check PG_PASSWORD, PG_HOST, PG_PORT, PG_USER "
            "and PG_DATABASE, and that PostgreSQL is reachable.",
            type(exc).__name__,
        )
        sys.exit(1)

    logger.info("Database initialized, config loaded from DB.")

    # ------------------------------------------------------------------
    # 6. Create the LLM client, then run the provider setup checks
    # ------------------------------------------------------------------
    # The factory never raises for a missing key or model; these checks only
    # log (warnings/errors) so the app always boots and chat explains the fix.
    from admino.llm import create_llm_client

    llm_client = create_llm_client(config.llm)
    logger.info("LLM client configured (provider=%s).", config.llm.provider)

    _warn_missing_provider_egress(config)

    if config.llm.provider == "infomaniak":
        from admino.llm_infomaniak import InfomaniakClient

        if isinstance(llm_client, InfomaniakClient):
            asyncio.run(_check_infomaniak_startup(llm_client))

    # ------------------------------------------------------------------
    # 7. Import tool modules, then freeze the registry
    # ------------------------------------------------------------------
    # Importing a tool module runs its @register_tool decorators; freezing
    # afterwards blocks any late or dynamic registration.
    from admino.tools.registry import freeze_registry

    _import_tool_modules()
    freeze_registry()
    logger.info("Tool registry frozen.")

    # ------------------------------------------------------------------
    # 8. Build AgentConfig from the validated application config
    # ------------------------------------------------------------------
    agent_config = AgentConfig(
        max_tool_calls=config.limits.max_tool_calls_per_message,
        max_context_messages=config.limits.max_context_messages,
        confirmation_timeout_s=float(config.limits.confirmation_timeout_s),
    )

    # ------------------------------------------------------------------
    # 9. Build system prompt from config and instantiate the Agent
    # ------------------------------------------------------------------
    from admino.agent import Agent

    system_prompt = _build_system_prompt(config, permissions_config)
    # Logged below; fall back to the provider name when no model is set (chat
    # then asks the user to choose one).
    model_name = config.llm.active_model_name or config.llm.provider

    agent = Agent(
        llm_client=llm_client,
        # GH-147: every dispatch is recorded as a tool.call audit event.
        tool_call_recorder=_build_tool_call_recorder(),
        permissions_config=permissions_config,
        agent_config=agent_config,
        system_prompt=system_prompt,
        # GH-80: seed the per-tool gate from persisted DB state so services
        # the user toggled off stay off immediately on boot.
        tools_enabled=tools_enabled,
    )
    logger.info(
        "Agent initialized with model %s (provider=%s)",
        safe_log(model_name, max_len=200),
        config.llm.provider,
    )

    # ------------------------------------------------------------------
    # 10. Create the FastAPI app
    # ------------------------------------------------------------------
    from admino.server import create_app

    app = create_app(agent=agent, config=config)

    # ------------------------------------------------------------------
    # 11. Start uvicorn (single worker — required for in-memory session state)
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
        # uvicorn's access log stays off: request paths (invitation tokens) and
        # query strings (the OAuth code and state) are never logged.
        access_log=False,
        # No uvicorn LOGGING_CONFIG: its loggers install no handlers and go
        # through the root handler configured above (no tracebacks).
        log_config=None,
        # uvicorn's own X-Forwarded-* handling (it trusts 127.0.0.1, or
        # FORWARDED_ALLOW_IPS, by default) must never run: the app's
        # server.trusted_proxies is the only source of truth.
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
