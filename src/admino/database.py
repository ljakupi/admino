"""PostgreSQL connection pool, migration runner, schema check and health check.

Owns the asyncpg pool lifecycle. All database access in admino goes through
the pool returned by get_pool(): a ``TimedPool`` (GH-244) around the asyncpg
pool, which times every statement for the request's timing line
(``admino.request_timing``). Migrations are plain numbered SQL files in
``migrations/``, applied in order by ``run_migrations()``; only the one-shot
migrate step (``admino.migrate``, connected as the owner) calls it.

The running app (the server, its startup and the admin CLI) connects as the
least-privilege runtime role ``RUNTIME_ROLE`` (``admino_app``, created by
migration 0018) through ``database_url_from_env()``, and never migrates:
``pending_migration_versions()`` tells it whether the schema is up to date.

Inputs: the PG_APP_PASSWORD, PG_HOST, PG_PORT and PG_DATABASE env vars (the
runtime DSN) and the shipped migration files.
Outputs: the module-level pool, the runtime DSN, the pending migration
versions, and each statement's count and duration on the current request's
timing record.

Security notes:
- The runtime DSN is built from env vars only, never from YAML or config
  files. Its user is always ``admino_app`` and its password PG_APP_PASSWORD;
  the owner's role name and password are never read here, so the app can't
  fall back to the superuser. The password is percent-encoded into the DSN
  and never logged.
- ``pending_migration_versions()`` is read-only: one SELECT, no DDL.
- Two shipped migration files with one version number are refused before
  any statement (``DuplicateMigrationVersionError``, GH-302): its message
  names the version and the files, never their contents.
- ``TimedPool`` sees statements, never logs: only their count and duration
  reach ``admino.request_timing`` (never SQL, arguments or results).
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
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast
from urllib.parse import quote

import asyncpg

from admino import request_timing

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)

# The least-privilege role the app connects as (migration 0018 creates it).
RUNTIME_ROLE: Final[str] = "admino_app"

# ---------------------------------------------------------------------------
# Module-level pool
# ---------------------------------------------------------------------------

_pool: asyncpg.Pool | None = None


class _TimedStatements:
    """Times the statement methods of a pool or connection; the rest passes through.

    ``fetch``, ``fetchrow``, ``fetchval``, ``execute`` and ``executemany`` each
    run inside ``request_timing.db_statement()`` (one statement, its duration)
    and return the inner result unchanged; an exception propagates unchanged.
    Every other attribute (``transaction``, ``close``, ...) is the inner
    object's, untimed: BEGIN/COMMIT and a connection's reset aren't statements.
    """

    # Any: the wrapper delegates by shape to an asyncpg pool, an acquired
    # connection or a test stand-in, with their own signatures; init_pool's
    # cast gives every caller back the asyncpg.Pool type.
    def __init__(self, inner: Any) -> None:
        self._inner = inner

    async def fetch(self, *args: Any, **kwargs: Any) -> Any:
        """The inner ``fetch``, timed as one statement."""
        with request_timing.db_statement():
            return await self._inner.fetch(*args, **kwargs)

    async def fetchrow(self, *args: Any, **kwargs: Any) -> Any:
        """The inner ``fetchrow``, timed as one statement."""
        with request_timing.db_statement():
            return await self._inner.fetchrow(*args, **kwargs)

    async def fetchval(self, *args: Any, **kwargs: Any) -> Any:
        """The inner ``fetchval``, timed as one statement."""
        with request_timing.db_statement():
            return await self._inner.fetchval(*args, **kwargs)

    async def execute(self, *args: Any, **kwargs: Any) -> Any:
        """The inner ``execute``, timed as one statement."""
        with request_timing.db_statement():
            return await self._inner.execute(*args, **kwargs)

    async def executemany(self, *args: Any, **kwargs: Any) -> Any:
        """The inner ``executemany``, timed as one statement."""
        with request_timing.db_statement():
            return await self._inner.executemany(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        """Every other attribute is the inner object's (untimed)."""
        return getattr(self._inner, name)


class TimedPool(_TimedStatements):
    """A connection pool whose statements are timed, on itself and on acquired connections."""

    @asynccontextmanager
    async def acquire(self, *, timeout: float | None = None) -> AsyncIterator[_TimedStatements]:
        """Acquire an inner connection (and release it), yielding it with timed statements.

        Used as ``async with pool.acquire(...) as conn`` only (asyncpg's
        await/release form isn't supported). The wait for a free connection and
        the release aren't statements.

        Args:
            timeout: Passed to the inner pool's ``acquire`` as ``timeout=``, like
                asyncpg's ``Pool.acquire`` (None, its default, waits without a bound).
                A ``TimeoutError`` of the wait reaches the caller unchanged.
        """
        async with self._inner.acquire(timeout=timeout) as conn:
            yield _TimedStatements(conn)


def database_url_from_env() -> str | None:
    """Build the runtime role's PostgreSQL DSN from the env vars.

    The user is always ``RUNTIME_ROLE`` (``admino_app``) and the password
    PG_APP_PASSWORD, percent-encoded with ``quote(..., safe="")`` (asyncpg
    decodes the DSN password with ``unquote``, so a space must be %20, never
    '+'), so characters like "/" and "@" can't break the DSN. PG_HOST defaults
    to localhost, PG_PORT to 5432 and PG_DATABASE to admino. The owner's
    credential is never read: there is no fallback to it.

    Returns:
        A ``postgresql://`` connection string, or None when PG_APP_PASSWORD
        is unset or empty (the caller reports the missing variable).
    """
    password = os.environ.get("PG_APP_PASSWORD")
    if not password:
        return None

    host = os.environ.get("PG_HOST") or "localhost"
    port = os.environ.get("PG_PORT") or "5432"
    database = os.environ.get("PG_DATABASE") or "admino"

    return f"postgresql://{RUNTIME_ROLE}:{quote(password, safe='')}@{host}:{port}/{database}"


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
        The created connection pool, wrapped in a ``TimedPool`` (GH-244).
    """
    global _pool
    pool = await asyncpg.create_pool(
        database_url,
        min_size=min_size,
        max_size=max_size,
    )
    # The cast keeps asyncpg.Pool as the type every caller sees: TimedPool
    # offers the same methods (the statement ones timed, the rest delegated).
    _pool = cast("asyncpg.Pool", TimedPool(pool))
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


class DuplicateMigrationVersionError(RuntimeError):
    """Two or more shipped migration files share one version number (GH-302)."""


def _migration_files() -> list[tuple[int, Path]]:
    """The shipped migration files as (version, path), sorted by version.

    Only ``NNNN_<name>.sql`` files in ``_MIGRATIONS_DIR`` count. Two files
    with one version would each be applied under it: a fresh database fails
    midway on the second ``_migrations`` row, an upgraded one skips the
    second file. So a shared version is refused here, before any caller
    runs a statement (GH-302, Decision 3). Only the names are listed; no
    file is read.

    Raises:
        DuplicateMigrationVersionError: Two or more files share a version;
            the message names the lowest such version and its files (names
            only, never their contents).
    """
    migration_files: list[tuple[int, Path]] = []
    if _MIGRATIONS_DIR.is_dir():
        for path in sorted(_MIGRATIONS_DIR.iterdir()):
            match = _MIGRATION_FILE_RE.match(path.name)
            if match:
                migration_files.append((int(match.group(1)), path))
    # The names sort by their four-digit version first, so the dict's first shared
    # version is the lowest one and each version's names are already sorted.
    names_by_version: dict[int, list[str]] = {}
    for version, path in migration_files:
        names_by_version.setdefault(version, []).append(path.name)
    for version, names in names_by_version.items():
        if len(names) > 1:
            msg = (
                f"Migration version {version:04d} is used by more than one file: "
                f"{', '.join(names)}."
            )
            raise DuplicateMigrationVersionError(msg)
    return migration_files


async def run_migrations(pool: asyncpg.Pool) -> None:
    """Execute pending SQL migrations in order.

    Lists the shipped migration files first (GH-302: two files with one
    version stop it there, before any statement, so nothing is created or
    applied), then creates the ``_migrations`` tracking table if it does not
    exist. Files whose version has not been recorded are executed inside a
    transaction each. Only ``admino.migrate`` calls it, connected as the
    owner: the runtime role can't run DDL.

    Args:
        pool: The asyncpg connection pool.

    Raises:
        DuplicateMigrationVersionError: Two or more files share a version
            (nothing acquired or executed).
    """
    migration_files = _migration_files()
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


async def pending_migration_versions(pool: asyncpg.Pool) -> list[int]:
    """Return the versions of the shipped migrations the database hasn't applied.

    Read-only: runs exactly one ``SELECT version FROM _migrations``, creates
    nothing and executes no DDL, so the runtime role can call it. The app
    refuses to start on a non-empty result instead of migrating, and on two
    shipped files with one version (raised before the SELECT, GH-302).

    Args:
        pool: The asyncpg connection pool.

    Returns:
        The unapplied versions, sorted; every shipped version when the
        ``_migrations`` table doesn't exist yet.

    Raises:
        DuplicateMigrationVersionError: Two or more shipped files share a
            version (before any statement).
        asyncpg.PostgresError: Any database error other than the missing
            ``_migrations`` table (e.g. a missing privilege).
    """
    shipped = [version for version, _ in _migration_files()]
    try:
        rows = await pool.fetch("SELECT version FROM _migrations")
    except asyncpg.UndefinedTableError:
        return shipped
    applied = {int(row["version"]) for row in rows}
    return [version for version in shipped if version not in applied]
