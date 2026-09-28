"""PostgreSQL connection pool, migration runner, health check, and seed logic.

Owns the asyncpg pool lifecycle. All database access in admino goes through
the pool returned by get_pool(). Migrations are plain numbered SQL files
executed in order on startup. ``database_url_from_env()`` builds the DSN that
both the server startup and the admin CLI open the pool with.

Security notes:
- The DSN is built from the PG_* env vars only, never from YAML or config
  files. The password is percent-encoded into it and never logged.
- All SQL uses parameterized queries ($1, $2). No string interpolation.
- Org-content repository functions take a TenantContext (admino.tenancy) as
  their first argument and filter by its org_id; there is no unscoped path.
- Does not import from agent.py, llm.py, or server.py.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote_plus

import asyncpg

if TYPE_CHECKING:
    from admino.config import AppConfig
    from admino.permissions import PermissionsConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level pool
# ---------------------------------------------------------------------------

_pool: asyncpg.Pool | None = None


def database_url_from_env() -> str | None:
    """Build a PostgreSQL DSN from the PG_* env vars, URL-encoding the password.

    PG_HOST defaults to localhost, PG_PORT to 5432, PG_USER and PG_DATABASE to
    admino. PG_PASSWORD is required and percent-encoded (quote_plus), so
    characters like "/" and "@" can't break the DSN.

    Returns:
        A ``postgresql://`` connection string, or None when PG_PASSWORD is
        unset or empty (the caller reports the missing variable).
    """
    password = os.environ.get("PG_PASSWORD")
    if not password:
        return None

    host = os.environ.get("PG_HOST", "localhost")
    port = os.environ.get("PG_PORT", "5432")
    user = os.environ.get("PG_USER", "admino")
    database = os.environ.get("PG_DATABASE", "admino")

    return f"postgresql://{user}:{quote_plus(password)}@{host}:{port}/{database}"


async def init_pool(
    database_url: str,
    *,
    min_size: int = 2,
    max_size: int = 5,
) -> asyncpg.Pool:
    """Create the asyncpg connection pool and store it module-level.

    Args:
        database_url: PostgreSQL connection string (e.g. postgres://user:pass@host/db).
        min_size: Minimum number of connections in the pool.
        max_size: Maximum number of connections in the pool.

    Returns:
        The created connection pool.
    """
    global _pool
    _pool = await asyncpg.create_pool(
        database_url,
        min_size=min_size,
        max_size=max_size,
    )
    logger.info("Database pool created (min=%d, max=%d).", min_size, max_size)
    return _pool


def get_pool() -> asyncpg.Pool:
    """Return the module-level connection pool.

    Raises:
        RuntimeError: If init_pool() has not been called yet.
    """
    if _pool is None:
        msg = "Database pool not initialised — call init_pool() first."
        raise RuntimeError(msg)
    return _pool


async def close_pool() -> None:
    """Close the connection pool and clear the module-level reference."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("Database pool closed.")


async def check_health() -> bool:
    """Run a trivial query to verify database connectivity.

    Returns:
        True if the database responded, False otherwise.
    """
    if _pool is None:
        return False
    try:
        await _pool.fetchval("SELECT 1")
    except (asyncpg.PostgresError, OSError, TimeoutError):
        return False
    return True


# ---------------------------------------------------------------------------
# Migrations
# ---------------------------------------------------------------------------

_MIGRATION_FILE_RE: re.Pattern[str] = re.compile(r"^(\d{4})_.+\.sql$")
_MIGRATIONS_DIR: Path = Path(__file__).parent / "migrations"


async def run_migrations(pool: asyncpg.Pool) -> None:
    """Execute pending SQL migrations in order.

    Creates the ``_migrations`` tracking table if it does not exist, then
    scans the migrations directory for numbered SQL files. Files whose
    version has not been recorded are executed inside a transaction.

    Args:
        pool: The asyncpg connection pool.
    """
    async with pool.acquire() as conn:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS _migrations (
                version     INTEGER     PRIMARY KEY,
                name        TEXT        NOT NULL,
                applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )

    # Discover migration files sorted by version number.
    migration_files: list[tuple[int, Path]] = []
    if _MIGRATIONS_DIR.is_dir():
        for path in sorted(_MIGRATIONS_DIR.iterdir()):
            match = _MIGRATION_FILE_RE.match(path.name)
            if match:
                version = int(match.group(1))
                migration_files.append((version, path))

    if not migration_files:
        logger.info("No migration files found.")
        return

    # Determine which versions have already been applied.
    applied: set[int] = set()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT version FROM _migrations")
        for row in rows:
            applied.add(int(row["version"]))

    for version, path in migration_files:
        if version in applied:
            continue
        sql = path.read_text(encoding="utf-8")
        logger.info("Applying migration %04d: %s", version, path.name)
        async with pool.acquire() as conn, conn.transaction():
            await conn.execute(sql)
            await conn.execute(
                "INSERT INTO _migrations (version, name) VALUES ($1, $2)",
                version,
                path.name,
            )
        logger.info("Migration %04d applied successfully.", version)


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


async def seed_settings(pool: asyncpg.Pool, config: AppConfig) -> None:
    """Seed the settings table from AppConfig if the table is empty.

    Each config section (server, llm, limits, egress, database)
    becomes a row with key=section_name and value=JSONB of the model dict.
    The log_level string is stored as ``{"value": "INFO"}``. No ``files`` row
    is seeded (the local files tool was removed in GH-143), no ``paths`` row
    (the NDJSON audit log path was removed in GH-147), and no ``auth`` row
    (the auth modes were removed in GH-149).

    Args:
        pool: The asyncpg connection pool.
        config: The validated application config to seed from.
    """
    async with pool.acquire() as conn:
        count = await conn.fetchval("SELECT count(*) FROM settings")
        if count and int(count) > 0:
            logger.info("Settings table already has %d rows, skipping seed.", count)
            return

    sections: dict[str, object] = {
        "server": config.server.model_dump(mode="json"),
        "llm": config.llm.model_dump(mode="json"),
        "limits": config.limits.model_dump(mode="json"),
        "egress": config.egress.model_dump(mode="json"),
        "database": config.database.model_dump(mode="json"),
        "log_level": {"value": config.log_level},
    }

    async with pool.acquire() as conn:
        for key, value in sections.items():
            await conn.execute(
                "INSERT INTO settings (key, value) VALUES ($1, $2::jsonb)",
                key,
                json.dumps(value),
            )
    logger.info("Seeded %d settings rows from AppConfig.", len(sections))


async def seed_permissions(
    pool: asyncpg.Pool,
    permissions: PermissionsConfig,
) -> None:
    """Seed the permissions table from PermissionsConfig if the table is empty.

    Iterates through all tools and their configured actions, inserting
    one row per (tool, action, permission) tuple.

    Args:
        pool: The asyncpg connection pool.
        permissions: The validated permissions config to seed from.
    """
    async with pool.acquire() as conn:
        count = await conn.fetchval("SELECT count(*) FROM permissions")
        if count and int(count) > 0:
            logger.info("Permissions table already has %d rows, skipping seed.", count)
            return

    rows_inserted = 0
    async with pool.acquire() as conn:
        for tool_name, tool_perms in permissions.tools.items():
            for action_name, state in tool_perms.actions.items():
                await conn.execute(
                    "INSERT INTO permissions (tool, action, permission) VALUES ($1, $2, $3)",
                    tool_name,
                    action_name,
                    state,
                )
                rows_inserted += 1
    logger.info("Seeded %d permission rows from PermissionsConfig.", rows_inserted)


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


async def update_setting(pool: asyncpg.Pool, key: str, value: dict[str, Any]) -> None:
    """Upsert a single settings row by key.

    Inserts the row if it does not exist, updates it otherwise.
    Uses parameterized query — no string interpolation.

    Args:
        pool: The asyncpg connection pool.
        key: The settings section key (e.g. "llm", "appearance").
        value: The new JSONB value for the settings row.
    """
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO settings (key, value) VALUES ($1, $2::jsonb) "
            "ON CONFLICT (key) DO UPDATE SET value = $2::jsonb, updated_at = now()",
            key,
            json.dumps(value),
        )


async def update_permission(
    pool: asyncpg.Pool,
    tool: str,
    action: str,
    permission: str,
) -> None:
    """Upsert a single permission row.

    Inserts the row if it does not exist, updates it otherwise.
    Uses parameterized query — no string interpolation.

    Args:
        pool: The asyncpg connection pool.
        tool: Tool identifier (e.g. "gmail").
        action: Action identifier (e.g. "search").
        permission: One of "allow", "confirm", "deny".
    """
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO permissions (tool, action, permission) VALUES ($1, $2, $3) "
            "ON CONFLICT (tool, action) DO UPDATE SET permission = $3, updated_at = now()",
            tool,
            action,
            permission,
        )


async def load_settings_from_db(
    pool: asyncpg.Pool,
) -> dict[str, Any]:
    """Load all settings rows and return a dict suitable for AppConfig.model_validate().

    Each row has key (section name) and value (JSONB). The log_level
    section stores ``{"value": "INFO"}`` and is unwrapped to a plain string.

    Args:
        pool: The asyncpg connection pool.

    Returns:
        A dict like ``{"server": {...}, "llm": {...}, ...}``.
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT key, value FROM settings")

    result: dict[str, Any] = {}
    for row in rows:
        key: str = row["key"]
        value: Any = row["value"]
        # asyncpg returns JSONB as str when the default codec is not active
        # (e.g. certain pool configurations). Parse if needed.
        if isinstance(value, str):
            value = json.loads(value)
        # A persisted NULL means "not set" — drop the whole section so the
        # config model's section default applies.
        if value is None:
            continue
        if key == "log_level" and isinstance(value, dict):
            result[key] = value.get("value", "INFO")
        elif isinstance(value, dict):
            # Drop NULL-valued fields within a section. Pydantic only applies a
            # field default when the key is ABSENT, not when it is explicitly
            # None, so a persisted null would otherwise fail validation for
            # non-optional fields (e.g. llm.openai_model). See test_database.
            result[key] = {k: v for k, v in value.items() if v is not None}
        else:
            result[key] = value
    return result


async def load_permissions_from_db(
    pool: asyncpg.Pool,
) -> dict[str, dict[str, str]]:
    """Load all permission rows grouped by tool.

    Args:
        pool: The asyncpg connection pool.

    Returns:
        A dict like ``{"gmail": {"list": "allow", "read": "confirm"}, ...}``.
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT tool, action, permission FROM permissions")

    result: dict[str, dict[str, str]] = {}
    for row in rows:
        tool: str = row["tool"]
        action: str = row["action"]
        permission: str = row["permission"]
        if tool not in result:
            result[tool] = {}
        result[tool][action] = permission
    return result
