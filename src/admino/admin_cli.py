"""Platform admin CLI: create the first Super Admin (GH-150) and organizations (GH-154).

Usage::

    python -m admino.admin_cli create-superadmin --email you@example.ch --name 'Your Name'
    make create-superadmin EMAIL=you@example.ch NAME='Your Name'

    python -m admino.admin_cli create-org --name 'Acme AG' --admin-email ada@acme.ch \
        [--seats 10] [--budget-chf 100] [--storage-quota-gib 10] [--language en]
    make create-org ...

The make targets run the same commands inside the agent container, as the
unprivileged admino user (``docker compose exec -u admino agent``). Commands
are argparse subcommands.

``create-superadmin``, in order:

1. Validates the email (3 to 254 characters, no whitespace, an '@' after a
   non-empty local part, like the users table CHECKs; never trimmed) and the
   name (1 to 120 characters after trimming, no control characters).
2. Refuses to run without an interactive terminal, or without PG_PASSWORD.
3. Opens a small pool from the PG_* env vars and applies pending migrations,
   so it also works on a fresh database before the agent's first start.
4. Refuses an email that's already taken, in any capitalization, before any
   password prompt.
5. Asks for the password and its confirmation with getpass, under the
   password policy of ``admino.passwords``; three failed attempts end it.
6. Hashes the password with Argon2id in a worker thread, then inserts the
   active Super Admin and its ``user.activate`` audit event in one
   transaction (``admino.accounts.create_super_admin``).

``create-org`` creates an active organization and invites its first Org
Admin through the Super Admin route's service
(``admino.organizations.create_org``), acting as the platform operator
(``access.Operator``: no account, events audited as actor 'operator'). In
order:

1. Validates the input through ``models.OrgCreateRequest`` (the budget as an
   exact decimal, the quota as GiB x 1024**3 bytes); each invalid field gets
   one fixed message naming its option.
2. Refuses to run without PG_PASSWORD.
3. Picks the delivery: with SMTP configured (``mailer.load_smtp_config``)
   the invitation email is queued; without it nothing is queued and the
   one-time link is shown on stdout, so stdout must be a terminal.
4. Opens a small pool, applies pending migrations, reads ``server.public_url``
   (``$CONFIG_DIR/config.yaml`` plus ADMINO_PUBLIC_URL, like the server's
   startup) as the link base, and creates the org, its ``org.create`` event
   and the invitation in one transaction.
5. Prints the new org's id and either that the email is queued or the link
   and its expiry date.

Inputs: argv (the subcommand and its options), the PG_* and SMTP_* env vars,
and, for create-superadmin, the password typed at the terminal.
Outputs: a confirmation on stdout and exit code 0; a message on stderr and
exit code 1 when the command is refused, cancelled or fails; exit code 2 for
a usage error.

Security notes:
- The password is only read from the terminal (getpass, no echo). There is
  no option for it, so it never reaches argv, the process list or the shell
  history; without a TTY the command refuses to run instead of reading
  piped input.
- The password must pass the policy (12 to 128 characters, not a common
  password, not the email) and match its confirmation.
- The invitation link is a one-time secret: it is shown on stdout only, only
  without SMTP, and only when stdout is a terminal (checked before the
  database is touched), so it can't end up in a file or a log collector. It
  is never logged or written to stderr.
- No secrets or content in output or logs: the password, its hash, the
  emails, the names and the link (except as above) are never printed or
  logged. Messages are fixed text that never repeats the input; a driver's
  or a config error (which can repeat the failing row or value) is never
  shown.
- Only this module builds an ``access.Operator`` (tests/test_access.py
  enforces it): being at the server's terminal is what authorizes
  ``create-org``.
- Parameterized SQL only (in ``admino.accounts`` and ``admino.organizations``).
- Fail closed: every change and its audit event share one transaction, so a
  failed audit write creates nothing. Every refusal or failure exits 1
  without a traceback, and the pool is closed.
- No shell, subprocess, eval or exec.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import signal
import sys
import unicodedata
from datetime import UTC
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Final

import asyncpg
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
)

from admino import accounts, organizations, passwords
from admino.access import Operator
from admino.audit_events import AuditRecordError
from admino.config import load_app_config
from admino.database import close_pool, database_url_from_env, init_pool, run_migrations
from admino.mailer import load_smtp_config
from admino.models import OrgCreateRequest

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from admino.email_templates import EmailLanguage

_MAX_ATTEMPTS: Final = 3
_FIRST_PROMPT: Final = "Password: "
_REPEAT_PROMPT: Final = "Repeat password: "
_GIB: Final = 1024**3
# config.yaml, found like the server's startup does (main.py): $CONFIG_DIR, default "config".
_CONFIG_PATH: Final[Path] = Path(os.environ.get("CONFIG_DIR", "config")) / "config.yaml"

# The users_email_format_check (migration 0004): no whitespace, and an '@'
# after a non-empty local part.
_EMAIL_PATTERN: Final = r"^[^\s@][^\s@]*@\S*$"

# The database can't be reached (OSError covers refused connections and
# timeouts), the driver fails, or the server refuses the statement.
_DATABASE_ERRORS: Final = (OSError, asyncpg.InterfaceError, asyncpg.PostgresError)

# Fixed messages: none of them repeats the input or a driver's error text.
_INVALID_INPUT: Final[dict[str, str]] = {
    "email": (
        "Error: --email must be 3 to 254 characters, with no whitespace and an '@' "
        "that isn't the first character."
    ),
    "name": "Error: --name must be 1 to 120 characters, without control characters.",
}
# create-org: one message per OrgCreateRequest field, naming only its option.
_INVALID_ORG_INPUT: Final[dict[str, str]] = {
    "name": (
        "Error: --name must be 1 to 120 characters, without control, invisible or "
        "line separator characters."
    ),
    "primary_admin_email": (
        "Error: --admin-email must be one email address like name@example.com, without "
        "spaces or invisible characters."
    ),
    "seats": "Error: --seats must be a whole number from 1 to 100000.",
    "monthly_budget_chf": (
        "Error: --budget-chf must be an amount in CHF of at least 0, with at most 10 digits "
        "before the decimal point and 2 after it."
    ),
    "storage_quota": "Error: --storage-quota-gib must be a whole number from 0 to 8388607.",
}
_NO_TTY: Final = (
    "Error: an interactive terminal is required to type the password; it can't be piped in."
)
_NO_TTY_FOR_LINK: Final = (
    "Error: SMTP isn't configured, so the one-time invitation link would be shown on "
    "stdout; run this command in an interactive terminal, without redirecting its output."
)
_NO_DSN: Final = "Error: the PG_PASSWORD environment variable is not set."
_DATABASE_UNAVAILABLE: Final = "Error: the database is unavailable; nothing was created."
_INVALID_CONFIG: Final = "Error: the configuration is invalid; nothing was created."
_CONFIG_UNREADABLE: Final = "Error: the configuration can't be read; nothing was created."
_DUPLICATE: Final = "Error: a user with this email already exists."
_MISMATCH: Final = "Error: the passwords don't match."
_TOO_MANY_ATTEMPTS: Final = "Error: too many failed attempts; nothing was created."
_CANCELLED: Final = "\nCancelled."
_NOT_CREATED: Final = "Error: the Super Admin could not be created."
_ORG_NOT_CREATED: Final = "Error: the organization could not be created."
_CREATED: Final = "Super Admin created."
_EMAIL_QUEUED: Final = "The invitation email to the first Org Admin is queued."
_LINK_FOLLOWS: Final = (
    "SMTP isn't configured, so no invitation email was sent. Give the first Org Admin "
    "this one-time invitation link:"
)


class _NewSuperAdmin(BaseModel):
    """The validated --email and --name of create-superadmin."""

    model_config = ConfigDict(frozen=True, hide_input_in_errors=True)

    # Never trimmed: validated exactly as it is stored.
    email: str = Field(min_length=3, max_length=254, pattern=_EMAIL_PATTERN)
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]

    @field_validator("name")
    @classmethod
    def _no_control_characters(cls, value: str) -> str:
        """Refuse control characters (Unicode category Cc): newlines, tabs, escapes."""
        if any(unicodedata.category(char) == "Cc" for char in value):
            msg = "The name must not contain control characters."
            raise ValueError(msg)
        return value


def _error(message: str) -> None:
    """Print a fixed message on stderr."""
    print(message, file=sys.stderr)


def _getpass(prompt: str) -> str:
    """Read a password without echo; Ctrl-C raises KeyboardInterrupt at once.

    The prompt blocks the event loop's thread, where asyncio.run's SIGINT
    handler would only cancel the task at its next await: the prompt would
    swallow the first Ctrl-C. Python's default handler applies while it waits.
    """
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        return getpass.getpass(prompt)
    finally:
        signal.signal(signal.SIGINT, previous)


def _read_password(email: str) -> str | None:
    """Ask for the password and its confirmation, up to three attempts.

    A password that breaks the policy isn't confirmed; a mismatch starts the
    attempt over.

    Args:
        email: The account's email (the policy refuses it as the password).

    Returns:
        The confirmed password, or None when cancelled (Ctrl-C, EOF) or after
        three failed attempts; the reason is on stderr.
    """
    try:
        for _ in range(_MAX_ATTEMPTS):
            password = _getpass(_FIRST_PROMPT)
            try:
                passwords.check_password_policy(password, email=email)
            except passwords.PasswordPolicyError as exc:
                _error(f"Error: {exc}")
                continue
            if _getpass(_REPEAT_PROMPT) == password:
                return password
            _error(_MISMATCH)
    except (KeyboardInterrupt, EOFError):
        _error(_CANCELLED)
        return None
    _error(_TOO_MANY_ATTEMPTS)
    return None


async def _with_pool(dsn: str, command: Callable[[asyncpg.Pool], Awaitable[int]]) -> int:
    """Open a small pool, run the command on it and close the pool.

    Returns:
        The command's exit code, or 1 when the database can't be reached.
    """
    try:
        pool = await init_pool(dsn, min_size=1, max_size=2)
    except _DATABASE_ERRORS:
        _error(_DATABASE_UNAVAILABLE)
        return 1
    try:
        return await command(pool)
    finally:
        await close_pool()


def _run_on_database(dsn: str, command: Callable[[asyncpg.Pool], Awaitable[int]]) -> int:
    """Run a command on a small pool in a new event loop; Ctrl-C cancels it.

    Returns:
        The command's exit code; 1 when the database can't be reached or the
        command is cancelled.
    """
    try:
        return asyncio.run(_with_pool(dsn, command))
    except KeyboardInterrupt:
        # Ctrl-C outside a prompt: asyncio.run cancelled the task (rolling
        # back an open transaction, closing the pool) and re-raised it.
        _error(_CANCELLED)
        return 1


async def _create_with_pool(pool: asyncpg.Pool, account: _NewSuperAdmin) -> int:
    """Migrate, check the email, ask for the password, hash it and create the account.

    Returns:
        The exit code: 0 when created, 1 otherwise.
    """
    try:
        await run_migrations(pool)
        taken = await accounts.email_exists(pool, account.email)
    except _DATABASE_ERRORS:
        _error(_DATABASE_UNAVAILABLE)
        return 1
    if taken:
        _error(_DUPLICATE)
        return 1

    password = _read_password(account.email)
    if password is None:
        return 1
    password_hash = await asyncio.to_thread(passwords.hash_password, password)

    try:
        async with pool.acquire() as conn, conn.transaction():
            await accounts.create_super_admin(
                conn, email=account.email, name=account.name, password_hash=password_hash
            )
    except accounts.DuplicateEmailError:
        _error(_DUPLICATE)
        return 1
    except (AuditRecordError, *_DATABASE_ERRORS):
        _error(_NOT_CREATED)
        return 1
    print(_CREATED)
    return 0


def _create_superadmin(*, email: str, name: str) -> int:
    """Run create-superadmin: validate, check the terminal and PG_PASSWORD, then create.

    Returns:
        The exit code: 0 when created, 1 otherwise.
    """
    try:
        account = _NewSuperAdmin(email=email, name=name)
    except ValidationError as exc:
        for field in sorted({str(error["loc"][0]) for error in exc.errors()}):
            _error(_INVALID_INPUT[field])
        return 1
    if not sys.stdin.isatty():
        _error(_NO_TTY)
        return 1
    dsn = database_url_from_env()
    if dsn is None:
        _error(_NO_DSN)
        return 1
    return _run_on_database(dsn, lambda pool: _create_with_pool(pool, account))


async def _create_org_with_pool(
    pool: asyncpg.Pool,
    request: OrgCreateRequest,
    *,
    language: EmailLanguage,
    queue_email: bool,
) -> int:
    """Migrate, read the link base, create the org and print the outcome.

    Returns:
        The exit code: 0 when created, 1 otherwise.
    """
    try:
        await run_migrations(pool)
    except _DATABASE_ERRORS:
        _error(_DATABASE_UNAVAILABLE)
        return 1
    try:
        app_config = load_app_config(_CONFIG_PATH)
    except OSError:
        _error(_CONFIG_UNREADABLE)
        return 1
    except ValueError:
        # Includes pydantic's ValidationError, whose text repeats the value.
        _error(_INVALID_CONFIG)
        return 1
    try:
        created = await organizations.create_org(
            pool,
            actor=Operator(),
            request=request,
            language=language,
            public_url=app_config.server.public_url,
            ip=None,
            queue_email=queue_email,
        )
    except accounts.DuplicateEmailError:
        _error(_DUPLICATE)
        return 1
    except (AuditRecordError, *_DATABASE_ERRORS):
        _error(_ORG_NOT_CREATED)
        return 1
    print(f"Organization created: {created.organization.id}")
    if queue_email:
        print(_EMAIL_QUEUED)
    else:
        expiry = created.invitation.expires_at.astimezone(UTC).date().isoformat()
        print(_LINK_FOLLOWS)
        print(created.accept_link)
        print(f"The link works once and expires on {expiry} (UTC).")
    return 0


def _create_org(args: argparse.Namespace) -> int:
    """Run create-org: validate, check PG_PASSWORD and the delivery, then create.

    Returns:
        The exit code: 0 when created, 1 otherwise.
    """
    try:
        request = OrgCreateRequest.model_validate(
            {
                "name": args.name,
                "primary_admin_email": args.admin_email,
                "seats": args.seats,
                # The raw text: Decimal parses it exactly (no float round trip).
                "monthly_budget_chf": args.budget_chf,
                "storage_quota": args.storage_quota_gib * _GIB,
                "status": "active",
            }
        )
    except ValidationError as exc:
        invalid = {str(error["loc"][0]) for error in exc.errors(include_input=False)}
        for field, message in _INVALID_ORG_INPUT.items():
            if field in invalid:
                _error(message)
        return 1
    dsn = database_url_from_env()
    if dsn is None:
        _error(_NO_DSN)
        return 1
    queue_email = load_smtp_config() is not None
    # Without SMTP the link is shown on stdout: never into a file or a pipe.
    if not queue_email and not sys.stdout.isatty():
        _error(_NO_TTY_FOR_LINK)
        return 1
    language: EmailLanguage = args.language
    return _run_on_database(
        dsn,
        lambda pool: _create_org_with_pool(
            pool, request, language=language, queue_email=queue_email
        ),
    )


def _parser() -> argparse.ArgumentParser:
    """Build the argument parser: one subcommand per platform task."""
    parser = argparse.ArgumentParser(
        prog="python -m admino.admin_cli", description="admino platform administration."
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    create = commands.add_parser(
        "create-superadmin",
        help="create a Super Admin (the password is asked for on the terminal)",
        description=(
            "Create an active Super Admin. The password is asked for twice on the "
            "terminal; it can't be passed as an option."
        ),
    )
    create.add_argument("--email", required=True, help="the Super Admin's email address")
    create.add_argument("--name", required=True, help="the Super Admin's display name")
    org = commands.add_parser(
        "create-org",
        help="create an organization and invite its first Org Admin",
        description=(
            "Create an active organization and invite its first Org Admin. With SMTP "
            "configured the invitation email is queued; without it the one-time link "
            "is shown on this terminal."
        ),
    )
    org.add_argument("--name", required=True, help="the organization's display name")
    org.add_argument("--admin-email", required=True, help="the first Org Admin's email address")
    org.add_argument("--seats", type=int, default=10, help="the number of seats (default: 10)")
    org.add_argument("--budget-chf", default="100", help="the monthly budget in CHF (default: 100)")
    org.add_argument(
        "--storage-quota-gib",
        type=int,
        default=10,
        help="the storage quota in GiB (default: 10)",
    )
    org.add_argument(
        "--language",
        choices=("de", "fr", "en"),
        default="en",
        help="the Org Admin's language, for the email too (default: en)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run a platform admin command and return its exit code.

    Args:
        argv: The arguments without the program name; None reads sys.argv.

    Returns:
        0 when the command succeeded, 1 when it was refused, cancelled or failed.

    Raises:
        SystemExit: With code 2 on a usage error (argparse).
    """
    args = _parser().parse_args(argv)
    if args.command == "create-org":
        return _create_org(args)
    return _create_superadmin(email=args.email, name=args.name)


if __name__ == "__main__":
    sys.exit(main())
