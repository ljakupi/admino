"""One-shot migrate step: apply the migrations as the owner, then set the runtime role's password.

Usage::

    python -m admino.migrate
    make migrate

The compose ``migrate`` service runs it before the agent starts (GH-220). It is
the only code path that knows the database owner's credential: the postgres
image's superuser (PG_USER, default ``admino``, password PG_PASSWORD), which
owns every table and function. In order it:

1. Validates the configuration before connecting: PG_PASSWORD set, PG_USER not
   the runtime role, PG_APP_PASSWORD set, printable ASCII and different from
   PG_PASSWORD.
2. Opens a one-connection pool as the owner and applies the pending migrations
   (``database.run_migrations``; migration 0018 creates the runtime role
   ``admino_app``). Two shipped migration files with one version number stop
   it before any statement (GH-302): nothing is applied, and the log names
   the version and the files.
3. Sets ``admino_app``'s password from PG_APP_PASSWORD, as a SCRAM-SHA-256
   verifier computed here, then closes the pool.

The app (server, startup, admin CLI) connects as ``admino_app`` only and never
migrates.

Inputs: the env vars PG_USER, PG_PASSWORD (the owner), PG_APP_PASSWORD (the
runtime role), PG_HOST, PG_PORT, PG_DATABASE, LOG_LEVEL and LOG_FORMAT.
Outputs: log lines on stderr (``admino.logs``' text or JSON formatter) and the
exit code: 0 when migrated, 1 on an unsafe configuration or a failure.

Security notes:
- The runtime password never reaches the database in plaintext: only its
  verifier is sent, and the server's ``format()`` quotes the role name (%I) and
  the verifier (%L). No SQL is built in Python.
- The runtime password must differ from the owner's (else the app would know
  the owner's password) and be printable ASCII (SCRAM's SASLprep is the
  identity only for ASCII, so the verifier matches what a client sends).
- No log line, exception message or return value carries a password, the DSN
  or the verifier: failures are logged by exception type with a fixed hint,
  never a message or a traceback. The one exception is
  ``database.DuplicateMigrationVersionError``, whose fixed message (a version
  number and file names only) is logged as it is, without the hint.
- No eval, exec, importlib, subprocess or shell.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import os
import secrets
import sys
from typing import TYPE_CHECKING, Final
from urllib.parse import quote

import asyncpg

from admino import database
from admino.logs import JsonFormatter, RequestIdFilter, TextFormatter

if TYPE_CHECKING:
    from asyncpg.pool import PoolConnectionProxy

logger = logging.getLogger(__name__)

_DEFAULT_OWNER: Final = "admino"
_SALT_BYTES: Final = 16
_VALID_LOG_LEVELS: Final[frozenset[str]] = frozenset(
    {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
)

# The server builds the statement: %I quotes the role name, %L the verifier.
_ALTER_ROLE_SQL: Final = (
    "SELECT format('ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
    "NOREPLICATION NOBYPASSRLS PASSWORD %L', $1::text, $2::text)"
)

# Fixed messages: none of them carries a password, the DSN or the verifier.
_OWNER_CREDENTIAL_MISSING: Final = (
    "PG_PASSWORD is not set: the migrations run as the database owner. Nothing was migrated."
)
_OWNER_IS_RUNTIME_ROLE: Final = (
    "PG_USER names the runtime role admino_app; it must name the database owner. "
    "Nothing was migrated."
)
_RUNTIME_CREDENTIAL_MISSING: Final = (
    "PG_APP_PASSWORD is not set: the runtime role admino_app needs a password. "
    "Nothing was migrated."
)
_RUNTIME_CREDENTIAL_NOT_ASCII: Final = (
    "PG_APP_PASSWORD must contain printable ASCII characters only (space to '~'). "
    "Nothing was migrated."
)
_RUNTIME_CREDENTIAL_IS_OWNERS: Final = (
    "PG_APP_PASSWORD must differ from PG_PASSWORD: the app must never know the owner's "
    "password. Nothing was migrated."
)
_MIGRATE_FAILED: Final = (
    "Migration failed (%s): check PG_USER, PG_PASSWORD, PG_HOST, PG_PORT and PG_DATABASE, "
    "and that PostgreSQL is reachable."
)
_MIGRATED: Final = "Migrations applied; runtime role admino_app is ready."

# What a failed run can raise: the database refuses (PostgresError), the driver
# fails (InterfaceError), it can't be reached (OSError) or times out.
_MIGRATE_ERRORS: Final = (
    asyncpg.PostgresError,
    asyncpg.InterfaceError,
    OSError,
    TimeoutError,
    ValueError,
    RuntimeError,
)


def owner_database_url_from_env() -> str | None:
    """Build the owner's PostgreSQL DSN from the env vars.

    PG_USER defaults to admino, PG_HOST to localhost, PG_PORT to 5432 and
    PG_DATABASE to admino. PG_PASSWORD is percent-encoded with
    ``quote(..., safe="")`` (asyncpg decodes it with ``unquote``, so a space is
    %20, never '+'). PG_APP_PASSWORD is never used.

    Returns:
        A ``postgresql://`` connection string, or None when PG_PASSWORD is
        unset or empty.
    """
    password = os.environ.get("PG_PASSWORD")
    if not password:
        return None
    user = os.environ.get("PG_USER") or _DEFAULT_OWNER
    host = os.environ.get("PG_HOST") or "localhost"
    port = os.environ.get("PG_PORT") or "5432"
    name = os.environ.get("PG_DATABASE") or "admino"
    return f"postgresql://{user}:{quote(password, safe='')}@{host}:{port}/{name}"


def _b64(raw: bytes) -> str:
    """Standard base64 with padding, as text."""
    return base64.b64encode(raw).decode("ascii")


def scram_sha256_verifier(
    password: str, *, salt: bytes | None = None, iterations: int = 4096
) -> str:
    """Compute PostgreSQL's SCRAM-SHA-256 verifier of a password (RFC 5802/7677).

    Args:
        password: The plaintext password (printable ASCII, see
            ``check_runtime_password``).
        salt: The salt; a fresh random 16-byte salt when None.
        iterations: The PBKDF2 iteration count.

    Returns:
        ``SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>``, each part
        standard base64. The plaintext can't be recovered from it.
    """
    if salt is None:
        salt = secrets.token_bytes(_SALT_BYTES)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    client_key = hmac.digest(salted, b"Client Key", "sha256")
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.digest(salted, b"Server Key", "sha256")
    return f"SCRAM-SHA-256${iterations}:{_b64(salt)}${_b64(stored_key)}:{_b64(server_key)}"


def check_runtime_password(password: str | None, *, owner_password: str) -> str:
    """Validate the runtime role's password.

    Args:
        password: PG_APP_PASSWORD's value (None when unset).
        owner_password: The owner's password, which it must differ from.

    Returns:
        The password, unchanged.

    Raises:
        ValueError: With a fixed message (never the password) when it is unset
            or empty, has a character outside printable ASCII 0x20..0x7E, or
            equals the owner's password.
    """
    if not password:
        raise ValueError(_RUNTIME_CREDENTIAL_MISSING)
    if any(not " " <= char <= "~" for char in password):
        raise ValueError(_RUNTIME_CREDENTIAL_NOT_ASCII)
    if hmac.compare_digest(password.encode("utf-8"), owner_password.encode("utf-8")):
        raise ValueError(_RUNTIME_CREDENTIAL_IS_OWNERS)
    return password


async def set_runtime_role_password(
    conn: asyncpg.Connection | PoolConnectionProxy, password: str
) -> None:
    """Set the runtime role's password, sending only its SCRAM-SHA-256 verifier.

    The server builds the ``ALTER ROLE`` statement with ``format()`` from the
    role name and the verifier (bound parameters), so Python interpolates
    nothing into SQL; the statement also pins the role's attributes.

    Args:
        conn: A connection as the owner.
        password: The validated runtime password.
    """
    verifier = scram_sha256_verifier(password)
    statement = await conn.fetchval(_ALTER_ROLE_SQL, database.RUNTIME_ROLE, verifier)
    await conn.execute(statement)


async def migrate(owner_dsn: str, runtime_password: str) -> None:
    """Apply the pending migrations as the owner, then set the runtime role's password.

    Migrations first: migration 0018 creates the role. The pool is closed on
    success and on every failure.

    Args:
        owner_dsn: The owner's DSN (``owner_database_url_from_env``).
        runtime_password: The validated runtime password.
    """
    try:
        pool = await database.init_pool(owner_dsn, min_size=1, max_size=1)
        await database.run_migrations(pool)
        async with pool.acquire() as conn:
            await set_runtime_role_password(conn, runtime_password)
    finally:
        await database.close_pool()


def _configure_logging() -> None:
    """One root stderr handler with admino's formatter (JSON when LOG_FORMAT=json).

    The level comes from LOG_LEVEL (one of the five standard levels, else
    INFO). Neither formatter writes a traceback or an exception message.
    """
    level_name = os.environ.get("LOG_LEVEL", "INFO").strip().upper()
    if level_name not in _VALID_LOG_LEVELS:
        level_name = "INFO"
    log_format = os.environ.get("LOG_FORMAT", "text").strip().lower()
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RequestIdFilter())
    handler.setFormatter(JsonFormatter() if log_format == "json" else TextFormatter())
    logging.basicConfig(
        level=logging.getLevelNamesMapping()[level_name], handlers=[handler], force=True
    )


def main() -> int:
    """Validate the configuration, migrate, and set the runtime role's password.

    Returns:
        0 when migrated, 1 on an unsafe configuration (nothing connects), two
        migration files sharing a version (their fixed message logged, nothing
        applied) or another failure (logged by exception type only).
    """
    _configure_logging()
    owner_dsn = owner_database_url_from_env()
    owner_password = os.environ.get("PG_PASSWORD")
    if owner_dsn is None or not owner_password:
        logger.error(_OWNER_CREDENTIAL_MISSING)
        return 1
    if (os.environ.get("PG_USER") or _DEFAULT_OWNER) == database.RUNTIME_ROLE:
        logger.error(_OWNER_IS_RUNTIME_ROLE)
        return 1
    try:
        runtime_password = check_runtime_password(
            os.environ.get("PG_APP_PASSWORD"), owner_password=owner_password
        )
    except ValueError as exc:
        # The check's messages are fixed text that never carries the password.
        logger.error("%s", exc)
        return 1
    try:
        asyncio.run(migrate(owner_dsn, runtime_password))
    except database.DuplicateMigrationVersionError as exc:
        # Before _MIGRATE_ERRORS (it is a RuntimeError): its message is fixed text, the
        # version and the file names, never SQL, the DSN or a password, and the
        # connection hint would point the operator at the wrong cause.
        logger.error("%s", exc)
        return 1
    except _MIGRATE_ERRORS as exc:
        # The type only: the message can carry the DSN or the verifier.
        logger.error(_MIGRATE_FAILED, type(exc).__name__)
        return 1
    logger.info(_MIGRATED)
    return 0


if __name__ == "__main__":
    sys.exit(main())
