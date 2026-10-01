"""PostgreSQL connection pool, migration runner and health check.

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
  The org-scoped permission matrix is seeded and read by
  ``admino.org_permissions`` (GH-161), not here.
- Does not import from agent.py, llm.py, or server.py.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from urllib.parse import quote_plus

import asyncpg

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
