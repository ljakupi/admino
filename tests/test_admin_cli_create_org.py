"""Tests for ``admin_cli create-org``: the operator's organization bootstrap command (GH-154).

``python -m admino.admin_cli create-org --name NAME --admin-email EMAIL [--seats N]
[--budget-chf AMOUNT] [--storage-quota-gib N] [--language {de,fr,en}]`` creates an
organization and invites its first Org Admin. It goes through the same service as the
Super Admin route (``admino.organizations.create_org``) and acts as the platform
operator (``access.Operator()``: no account, no session).

What these tests pin (the GH-154 "CLI" decisions and spec):

- argparse: the subcommand and its options, with the defaults 10 seats, 100 CHF,
  10 GiB and ``en``. Status is always ``active``, so there's no option for it. A missing
  required option, a non-integer ``--seats`` or ``--storage-quota-gib`` and a
  ``--language`` outside de/fr/en are usage errors (exit 2) before anything runs.
- The order of the steps:
  1. The input is validated through ``models.OrgCreateRequest``: one fixed message per
     invalid field, naming its option and never repeating the input, then exit 1. A
     ``--budget-chf`` that isn't a number is such a validation error, not a usage error.
  2. PG_APP_PASSWORD is checked (GH-220: the runtime role's password; the owner's
     PG_PASSWORD is never a fallback).
  3. ``load_smtp_config()`` picks the delivery. Without SMTP, stdout must be a terminal.
  4. Only then the database: ``init_pool(dsn, min_size=1, max_size=2)`` with the
     runtime DSN (user ``admino_app``), ``load_app_config`` (config.yaml plus its env
     overrides: ``server.public_url``, the link base; GH-159 dropped the settings
     table the CLI used to read it from), ``organizations.create_org`` and
     ``close_pool``. GH-220: no migrations; the one-shot migrate service applied
     them before the agent (where the CLI runs) started.
- The service call gets the pool, an ``Operator`` actor and the validated request:
  the stripped name and email, the seats, a Decimal budget, GiB x 1024**3 bytes and the
  status ``active``. It also gets the language, the stored public URL, ``ip=None`` and
  ``queue_email``, which is whether SMTP is configured.
- The output: the new org id on stdout.
  - With SMTP: a line saying the invitation email is queued, and no link anywhere.
  - Without SMTP: an explanation, then the one-time link on its own line and its
    expiry date (YYYY-MM-DD), on stdout only.
- Failures: a taken email, an audit or database failure during creation, an
  unreachable database and an invalid stored config each exit 1 with a fixed
  message and no traceback, and the pool is closed.
- ``create-superadmin`` still dispatches as before.

Inputs: argv and the PG_* env vars (PG_APP_PASSWORD, and the owner's
PG_USER/PG_PASSWORD, which the CLI must ignore). These are patched:
``load_smtp_config``, ``load_app_config``, ``init_pool``, ``close_pool`` (all
looked up on ``admino.admin_cli``; ``load_app_config`` is admino.config's config.yaml
loader, called with ``$CONFIG_DIR/config.yaml`` like main.py) and
``admino.organizations.create_org`` (called through the module attribute). The
migrations runner is a spy that must never be awaited. stdout and stderr are
stand-in streams whose ``isatty()`` answers what the test says.
Outputs: the exit code, the recorded calls and their order, stdout/stderr and log
records.

Everything new (the subcommand, ``admino.organizations``, ``CreatedOrg``,
``OrgSummary``, ``OrgCreateRequest`` and ``access.Operator``) is looked up lazily in
fixtures or tests. Before it exists, every test errors on its own and the file still
collects.

Security notes:
- All database access is mocked, so no PostgreSQL connection is made. The subprocess
  tests stop before the database by design.
- The one-time link (and its token) reaches stdout only, and only without SMTP. It
  never reaches stderr or a log record at any level. The admin email, the org name
  and the SMTP password never reach stderr or a log record either.
- Error messages are fixed text: they never repeat the input or a driver's error.
- Without SMTP the command refuses to run unless stdout is a terminal, so the link
  can't end up in a file or a log collector.
- create-org never prompts: getpass and reading stdin are test failures.
"""

from __future__ import annotations

import getpass
import io
import logging
import os
import re
import subprocess
import sys
from contextlib import ExitStack, asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import DEFAULT, AsyncMock, MagicMock, patch
from uuid import UUID

import asyncpg
import pytest
from pydantic import BaseModel, ValidationError

from admino import accounts
from admino.audit_events import AuditRecordError
from admino.config import AppConfig
from admino.mailer import SmtpConfig

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator
    from types import ModuleType

# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

_ORG_NAME = "Helvetia Robotics AG"
_NAME_ARG = f"  {_ORG_NAME}  "  # surrounding whitespace the model strips
_ADMIN_EMAIL = "Primary.Admin@Helvetia-Robotics.ch"
_PUBLIC_URL = "https://orgs.admino.example.ch"
_ENV_PUBLIC_URL = "https://env-only.admino.example.ch"
# 43 characters, like secrets.token_urlsafe(32).
_TOKEN = "Xk3Tq9Lm2Vb7Rw4Zc8Nd1Fh6Jg5Sy0Pa-Ue_Oi7Kt2W"
_LINK = f"{_PUBLIC_URL}/accept-invitation#token={_TOKEN}"
_ORG_ID = UUID("5d2c7a1e-8f3b-4c6d-9a0e-1b2f3c4d5e6f")
_INVITATION_ID = UUID("a7e3c9b1-2d4f-4e8a-b6c0-9f1e2d3c4b5a")
# Noon UTC: the expiry keeps its date in any timezone from UTC-12 to UTC+11.
_CREATED_AT = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
_EXPIRES_AT = _CREATED_AT + timedelta(hours=72)
_EXPIRY_DATE = "2026-10-01"
_GIB = 1024**3
_MAX_QUOTA_GIB = (2**53 - 1) // _GIB  # 8388607: the largest GiB count within 2**53 - 1 bytes
_SMTP_PASSWORD = "smtp-Pa55word/For-Tests"
_PG_APP_PASSWORD = "pg-S3cret/p@ss"
_OWNER_PASSWORD = "owner-secret"
# GH-220: the runtime role admino_app with PG_APP_PASSWORD (percent-encoded).
_EXPECTED_DSN = "postgresql://admino_app:pg-S3cret%2Fp%40ss@localhost:5432/admino"
_PG_ENV: dict[str, str] = {
    "PG_HOST": "localhost",
    "PG_PORT": "5432",
    "PG_DATABASE": "admino",
    "PG_APP_PASSWORD": _PG_APP_PASSWORD,
}
# The owner's credentials, for the migrate service only. The fixture sets them too,
# as a shell that sourced .env would: the CLI must ignore them.
_OWNER_ENV: dict[str, str] = {"PG_USER": "admino", "PG_PASSWORD": _OWNER_PASSWORD}
_SUPERADMIN_EMAIL = "Ops.Admin@Example.ch"
_SUPERADMIN_NAME = "Ada Lovelace-Operator"
_SUPERADMIN_PASSWORD = "Correct-Horse-Battery-9!"
_SUPERADMIN_ID = UUID("3c9e1f4a-7b2d-4e8f-a1c6-5d0b9e2f7a14")
_FAKE_HASH = (
    "$argon2id$v=19$m=19456,t=2,p=1$ZmFrZXNhbHRmYWtlc2FsdA"
    "$ZmFrZWRpZ2VzdGZha2VkaWdlc3RmYWtlZGlnZXN0MDE"
)
# Marks text that only a driver's error or a config error carries.
_DRIVER_MARKER = "driver-detail-7f3a"
_CONFIG_MARKER = "stored-config-detail-9c1e"

_OPTIONS: tuple[str, ...] = (
    "--name",
    "--admin-email",
    "--seats",
    "--budget-chf",
    "--storage-quota-gib",
    "--language",
)
# The options a validation message can name (--language is argparse's).
_VALIDATED_OPTIONS: tuple[str, ...] = _OPTIONS[:-1]

# The service-call steps, in order, without the stdout.isatty/stderr.isatty probes.
# GH-220: no "run_migrations" step.
_DB_STEPS: list[str] = [
    "load_smtp_config",
    "init_pool",
    "load_app_config",
    "create_org",
    "close_pool",
]


def _argv(*extra: str, name: str = _NAME_ARG, email: str = _ADMIN_EMAIL) -> list[str]:
    """``create-org --name <name> --admin-email <email> <extra...>``."""
    return ["create-org", "--name", name, "--admin-email", email, *extra]


# ---------------------------------------------------------------------------
# Fakes: stdin, stdout/stderr and a pool
# ---------------------------------------------------------------------------


class _Stdin:
    """A stand-in for sys.stdin that isn't a terminal. create-org never reads it."""

    def __init__(self, *, tty: bool) -> None:
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty

    def read(self, *_args: Any) -> str:
        msg = "the CLI read sys.stdin; create-org takes no input from it"
        raise AssertionError(msg)

    def readline(self, *_args: Any) -> str:
        msg = "the CLI read sys.stdin; create-org takes no input from it"
        raise AssertionError(msg)


class _Stream(io.StringIO):
    """A captured stdout/stderr. isatty() answers ``tty`` and logs the probe as an event."""

    def __init__(self, label: str, events: list[str], *, tty: bool) -> None:
        super().__init__()
        self._label = label
        self._events = events
        self.tty = tty

    def isatty(self) -> bool:
        self._events.append(f"{self._label}.isatty")
        return self.tty


class _FakeConn:
    """A pooled connection (only create-superadmin uses one): neutral answers, a transaction."""

    async def fetchval(self, sql: str, *args: Any) -> Any:
        return None

    async def fetchrow(self, sql: str, *args: Any) -> Any:
        return None

    async def fetch(self, sql: str, *args: Any) -> list[Any]:
        return []

    async def execute(self, sql: str, *args: Any) -> str:
        return "OK"

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        yield


class _FakePool:
    """The pool init_pool returns. create_org is patched, so it only has to exist."""

    def __init__(self) -> None:
        self.conn = _FakeConn()

    async def fetchval(self, sql: str, *args: Any) -> Any:
        return None

    async def fetchrow(self, sql: str, *args: Any) -> Any:
        return None

    async def fetch(self, sql: str, *args: Any) -> list[Any]:
        return []

    async def execute(self, sql: str, *args: Any) -> str:
        return "OK"

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[_FakeConn]:
        yield self.conn


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@dataclass
class _Deps:
    """Every patched dependency of create-org, plus the shared ordered event log."""

    cli: ModuleType
    events: list[str]
    pool: _FakePool
    stdout: _Stream
    stderr: _Stream
    created: Any
    load_smtp_config: MagicMock
    init_pool: AsyncMock
    run_migrations_spy: AsyncMock
    load_app_config: MagicMock
    create_org: AsyncMock
    close_pool: AsyncMock

    def out(self) -> str:
        """Everything written to stdout so far."""
        return self.stdout.getvalue()

    def err(self) -> str:
        """Everything written to stderr so far."""
        return self.stderr.getvalue()

    def steps(self) -> list[str]:
        """The recorded steps, without the isatty probes."""
        return [event for event in self.events if not event.endswith(".isatty")]

    @contextmanager
    def streams(self) -> Iterator[None]:
        """Install the stand-in stdout/stderr for one main() call.

        Done per call, not in the fixture: pytest puts its own capture streams back
        on sys.stdout/sys.stderr between the setup and the call phase.
        """
        with patch.object(sys, "stdout", self.stdout), patch.object(sys, "stderr", self.stderr):
            yield


def _logging(events: list[str], name: str) -> Callable[..., Any]:
    """A mock side effect that logs its name and then lets the mock return its return_value."""

    def _log(*_args: Any, **_kwargs: Any) -> Any:
        events.append(name)
        return DEFAULT

    return _log


def _no_prompt(prompt: str = "", stream: Any = None) -> str:
    """getpass stand-in: create-org must never prompt."""
    msg = "create-org prompted with getpass; it takes no interactive input"
    raise AssertionError(msg)


@pytest.fixture()
def cli() -> ModuleType:
    """Import admino.admin_cli (lazily, like the create-superadmin tests)."""
    from admino import admin_cli

    return admin_cli


@pytest.fixture()
def created_org() -> Any:
    """What create_org returns: CreatedOrg(organization, invitation, accept_link).

    Built lazily: before ``admino.organizations`` and ``models.OrgSummary`` exist,
    this fixture fails and so does every test that uses it (RED).
    """
    from admino.models import InvitationSummary, OrgSummary
    from admino.organizations import CreatedOrg

    organization = OrgSummary(
        id=_ORG_ID,
        name=_ORG_NAME,
        status="active",
        seats=10,
        monthly_budget_chf=Decimal("100"),
        storage_quota=10 * _GIB,
        data_residency=True,
        deletion_requested_at=None,
        purge_after=None,
        created_at=_CREATED_AT,
        updated_at=_CREATED_AT,
    )
    invitation = InvitationSummary(
        id=_INVITATION_ID,
        email=_ADMIN_EMAIL,
        role="org_admin",
        sent_at=_CREATED_AT,
        expires_at=_EXPIRES_AT,
        expired=False,
    )
    return CreatedOrg(organization=organization, invitation=invitation, accept_link=_LINK)


@pytest.fixture()
def deps(cli: ModuleType, created_org: Any, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Deps]:
    """PG_* env set, SMTP configured, no terminal anywhere and every dependency patched.

    Defaults: load_smtp_config returns a valid SmtpConfig, the stored config's
    public_url is _PUBLIC_URL and create_org returns ``created_org``. stdin, stdout
    and stderr aren't terminals (stdout/stderr are installed by ``_run``), and
    getpass fails the test. PG_APP_PASSWORD and the owner's PG_USER/PG_PASSWORD
    are all set (the CLI must use only the first).

    GH-220: the migrations runner is replaced by ``run_migrations_spy``, which
    records a "run_migrations" step and must never be awaited. It replaces
    ``admino.database.run_migrations`` and, while admin_cli still has a name of
    its own for it, that name too, so the real migrations never run against the
    fake pool.
    """
    for name, value in {**_PG_ENV, **_OWNER_ENV}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("ADMINO_PUBLIC_URL", raising=False)

    events: list[str] = []
    stdout = _Stream("stdout", events, tty=False)
    stderr = _Stream("stderr", events, tty=False)
    monkeypatch.setattr(sys, "stdin", _Stdin(tty=False))
    monkeypatch.setattr(getpass, "getpass", _no_prompt)

    pool = _FakePool()
    smtp_config = SmtpConfig.model_validate(
        {
            "host": "mail.infomaniak.com",
            "port": 587,
            "username": "admino@example.ch",
            "password": _SMTP_PASSWORD,
            "from_address": "admino@example.ch",
        }
    )
    app_config = AppConfig.model_validate({"server": {"public_url": _PUBLIC_URL}})

    load_smtp_config = MagicMock(
        return_value=smtp_config, side_effect=_logging(events, "load_smtp_config")
    )
    init_pool = AsyncMock(return_value=pool, side_effect=_logging(events, "init_pool"))
    run_migrations_spy = AsyncMock(side_effect=_logging(events, "run_migrations"))
    load_app_config = MagicMock(
        return_value=app_config, side_effect=_logging(events, "load_app_config")
    )
    create_org = AsyncMock(return_value=created_org, side_effect=_logging(events, "create_org"))
    close_pool = AsyncMock(side_effect=_logging(events, "close_pool"))

    with ExitStack() as stack:
        stack.enter_context(patch("admino.admin_cli.load_smtp_config", new=load_smtp_config))
        # GH-159: config.yaml's loader. create=True keeps the tests that never reach the
        # config step running before the CLI imports it; the removed DB-backed loader
        # must not be called (test_admin_cli_create_org_uses_the_config_yaml_loader
        # pins the import).
        stack.enter_context(
            patch("admino.admin_cli.load_app_config", new=load_app_config, create=True)
        )
        if hasattr(cli, "load_app_config_from_db"):
            stack.enter_context(
                patch(
                    "admino.admin_cli.load_app_config_from_db",
                    new=AsyncMock(side_effect=AssertionError("the settings table is gone")),
                )
            )
        stack.enter_context(patch("admino.admin_cli.init_pool", new=init_pool))
        stack.enter_context(patch("admino.database.run_migrations", new=run_migrations_spy))
        if hasattr(cli, "run_migrations"):
            stack.enter_context(patch("admino.admin_cli.run_migrations", new=run_migrations_spy))
        stack.enter_context(patch("admino.admin_cli.close_pool", new=close_pool))
        stack.enter_context(patch("admino.organizations.create_org", new=create_org))
        yield _Deps(
            cli=cli,
            events=events,
            pool=pool,
            stdout=stdout,
            stderr=stderr,
            created=created_org,
            load_smtp_config=load_smtp_config,
            init_pool=init_pool,
            run_migrations_spy=run_migrations_spy,
            load_app_config=load_app_config,
            create_org=create_org,
            close_pool=close_pool,
        )


@pytest.fixture()
def no_smtp_terminal(deps: _Deps) -> _Deps:
    """SMTP isn't configured and stdout is a terminal: the link is shown there."""
    deps.load_smtp_config.return_value = None
    deps.stdout.tty = True
    return deps


@pytest.fixture()
def no_smtp_pipe(deps: _Deps) -> _Deps:
    """SMTP isn't configured and stdout isn't a terminal (a pipe or a file)."""
    deps.load_smtp_config.return_value = None
    deps.stdout.tty = False
    return deps


def _run(deps: _Deps, argv: list[str]) -> int:
    """Run ``main(argv)`` with the stand-in stdout/stderr and return its exit code.

    A SystemExit (a usage error, e.g. while create-org isn't a subcommand) or a
    KeyboardInterrupt escaping main() becomes a clear test failure.
    """
    try:
        with deps.streams():
            result = deps.cli.main(argv)
    except SystemExit as exc:
        pytest.fail(f"main() raised SystemExit({exc.code!r}); create-org must return 0 or 1")
    except KeyboardInterrupt:
        pytest.fail("KeyboardInterrupt escaped main()")
    assert isinstance(result, int)
    return result


def _usage_error(deps: _Deps, argv: list[str]) -> int | str | None:
    """Run ``main(argv)``, expecting argparse's SystemExit, and return its code."""
    with deps.streams(), pytest.raises(SystemExit) as exc_info:
        deps.cli.main(argv)
    return exc_info.value.code


def _service_call(deps: _Deps) -> tuple[Any, dict[str, Any]]:
    """The pool and the keyword arguments of the one create_org call.

    Everything after the pool is keyword-only in ``create_org``'s signature.
    """
    deps.create_org.assert_awaited_once()
    awaited = deps.create_org.await_args
    assert awaited is not None
    kwargs = dict(awaited.kwargs)
    assert len(awaited.args) <= 1, "only the pool may be passed positionally"
    pool = awaited.args[0] if awaited.args else kwargs.pop("pool", None)
    return pool, kwargs


def _request(deps: _Deps) -> Any:
    """The OrgCreateRequest create_org was called with."""
    return _service_call(deps)[1]["request"]


def _err_of(deps: _Deps, argv: list[str]) -> str:
    """Run ``main(argv)`` and return only what this run wrote to stderr."""
    start = len(deps.err())
    _run(deps, argv)
    return deps.err()[start:]


def _log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Everything the log records carry: formatted output, messages, args and exception text."""
    parts = [caplog.text]
    for record in caplog.records:
        parts.extend([record.getMessage(), repr(record.args), record.exc_text or ""])
    return "\n".join(parts)


def _set_env(monkeypatch: pytest.MonkeyPatch, env: dict[str, str | None]) -> None:
    """Set each variable, or remove it when its value is None."""
    for name, value in env.items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


# GH-220: the runtime DSN is the same whatever the owner's variables say.
_OWNER_ENV_VARIANTS: list[Any] = [
    pytest.param({}, id="owner-vars-set"),
    pytest.param({"PG_USER": None, "PG_PASSWORD": None}, id="owner-vars-unset"),
    pytest.param({"PG_USER": "postgres"}, id="other-pg-user"),
]


def _duplicate_error() -> Exception:
    """accounts.DuplicateEmailError()."""
    error: Exception = accounts.DuplicateEmailError()
    return error


def _driver_error() -> asyncpg.PostgresError:
    """A driver error whose text repeats the row, as PostgreSQL's DETAIL lines do."""
    return asyncpg.PostgresError(
        f"{_DRIVER_MARKER}: failing row contains ({_ADMIN_EMAIL}, {_ORG_NAME}, {_TOKEN})"
    )


class _ConfigProbe(BaseModel):
    """A model whose ValidationError text repeats its input (no hide_input_in_errors)."""

    public_url: int


def _config_validation_error() -> ValidationError:
    """A pydantic ValidationError whose text carries _CONFIG_MARKER."""
    try:
        _ConfigProbe.model_validate({"public_url": _CONFIG_MARKER})
    except ValidationError as exc:
        return exc
    msg = "the probe model accepted a non-integer"
    raise AssertionError(msg)


# ---------------------------------------------------------------------------
# 1. Command line: the subcommand, its options and usage errors
# ---------------------------------------------------------------------------

_USAGE_ERRORS: list[Any] = [
    pytest.param(["create-org"], "--name", id="no-options"),
    pytest.param(["create-org", "--admin-email", _ADMIN_EMAIL], "--name", id="missing-name"),
    pytest.param(["create-org", "--name", _ORG_NAME], "--admin-email", id="missing-admin-email"),
    pytest.param(_argv("--seats", "ten"), "--seats", id="seats-not-a-number"),
    pytest.param(_argv("--seats", "1.5"), "--seats", id="seats-fraction"),
    pytest.param(_argv("--seats", ""), "--seats", id="seats-empty"),
    pytest.param(
        _argv("--storage-quota-gib", "ten"), "--storage-quota-gib", id="quota-not-a-number"
    ),
    pytest.param(_argv("--storage-quota-gib", "0.5"), "--storage-quota-gib", id="quota-fraction"),
    pytest.param(_argv("--language", "it"), "--language", id="language-italian"),
    pytest.param(_argv("--language", "EN"), "--language", id="language-uppercase"),
    pytest.param(_argv("--language", ""), "--language", id="language-empty"),
    pytest.param(_argv("--status", "deactivated"), "--status", id="status-is-not-an-option"),
]


class TestCreateOrgCommandLine:
    """``create-org`` is an argparse subcommand; usage errors exit 2 before anything runs."""

    def test_admin_cli_create_org_help_lists_every_option(self, deps: _Deps) -> None:
        """``create-org --help`` exits 0 and documents all six options."""
        assert _usage_error(deps, ["create-org", "--help"]) == 0

        out = deps.out()
        assert [option for option in _OPTIONS if option not in out] == []

    def test_admin_cli_create_org_help_touches_nothing(self, deps: _Deps) -> None:
        """--help looks up no SMTP config and opens no pool."""
        _usage_error(deps, ["create-org", "--help"])

        assert deps.steps() == []

    @pytest.mark.parametrize(("argv", "option"), _USAGE_ERRORS)
    def test_admin_cli_create_org_usage_error_exits_two(
        self, deps: _Deps, argv: list[str], option: str
    ) -> None:
        """SystemExit(2), and argparse's message on stderr names the offending option."""
        assert _usage_error(deps, argv) == 2

        assert option in deps.err()

    @pytest.mark.parametrize(("argv", "option"), _USAGE_ERRORS)
    def test_admin_cli_create_org_usage_error_touches_nothing(
        self, deps: _Deps, argv: list[str], option: str
    ) -> None:
        """No SMTP lookup, no pool, no service call."""
        _usage_error(deps, argv)

        assert deps.steps() == []
        deps.create_org.assert_not_awaited()


# ---------------------------------------------------------------------------
# 2. The service call: pool, actor, request, language, link base, ip
# ---------------------------------------------------------------------------


class TestCreateOrgServiceCall:
    """create-org calls ``organizations.create_org`` once, as the operator, with the request."""

    def test_admin_cli_create_org_success_returns_zero(self, deps: _Deps) -> None:
        """Exit code 0 when the organization is created."""
        assert _run(deps, _argv()) == 0

    @pytest.mark.parametrize("owner_env", _OWNER_ENV_VARIANTS)
    def test_admin_cli_create_org_opens_a_small_pool_as_the_runtime_role(
        self, deps: _Deps, monkeypatch: pytest.MonkeyPatch, owner_env: dict[str, str | None]
    ) -> None:
        """GH-220: init_pool(runtime DSN, min_size=1, max_size=2), once: user admino_app and
        PG_APP_PASSWORD, whether the owner's PG_USER/PG_PASSWORD are set, unset or name
        another user.
        """
        _set_env(monkeypatch, owner_env)

        assert _run(deps, _argv()) == 0

        deps.init_pool.assert_awaited_once_with(_EXPECTED_DSN, min_size=1, max_size=2)

    def test_admin_cli_create_org_never_runs_migrations(self, deps: _Deps) -> None:
        """GH-220: no migrations on the opened pool; the migrate service applied them."""
        _run(deps, _argv())

        deps.run_migrations_spy.assert_not_awaited()

    def test_admin_cli_create_org_loads_config_yaml(self, deps: _Deps) -> None:
        """load_app_config($CONFIG_DIR/config.yaml) provides server.public_url (GH-159:
        the settings table it used to come from is dropped)."""
        _run(deps, _argv())

        deps.load_app_config.assert_called_once_with(
            Path(os.environ.get("CONFIG_DIR", "config")) / "config.yaml"
        )

    def test_admin_cli_create_org_uses_the_config_yaml_loader(self, cli: ModuleType) -> None:
        """The CLI imports admino.config.load_app_config; the DB-backed loader is gone."""
        from admino import config

        assert getattr(cli, "load_app_config", None) is config.load_app_config
        assert not hasattr(cli, "load_app_config_from_db")

    def test_admin_cli_create_org_calls_the_service_with_the_pool(self, deps: _Deps) -> None:
        """create_org gets the pool init_pool returned, and nothing else positionally."""
        _run(deps, _argv())

        pool, _ = _service_call(deps)
        assert pool is deps.pool

    def test_admin_cli_create_org_passes_exactly_the_service_keywords(self, deps: _Deps) -> None:
        """actor, request, language, public_url, ip and queue_email, all explicit."""
        _run(deps, _argv())

        _, kwargs = _service_call(deps)
        assert set(kwargs) == {"actor", "request", "language", "public_url", "ip", "queue_email"}

    def test_admin_cli_create_org_acts_as_the_operator(self, deps: _Deps) -> None:
        """The actor is an ``access.Operator``: no account, no session."""
        from admino import access

        _run(deps, _argv())

        _, kwargs = _service_call(deps)
        assert isinstance(kwargs["actor"], access.Operator)

    def test_admin_cli_create_org_passes_a_validated_org_create_request(self, deps: _Deps) -> None:
        """The request is a ``models.OrgCreateRequest``."""
        from admino.models import OrgCreateRequest

        _run(deps, _argv())

        assert isinstance(_request(deps), OrgCreateRequest)

    def test_admin_cli_create_org_request_has_the_stripped_name_and_the_email(
        self, deps: _Deps
    ) -> None:
        """name is stripped; primary_admin_email is as given (capitalization kept)."""
        _run(deps, _argv())

        request = _request(deps)
        assert request.name == _ORG_NAME
        assert request.primary_admin_email == _ADMIN_EMAIL

    def test_admin_cli_create_org_defaults_are_ten_seats_100_chf_10_gib_active(
        self, deps: _Deps
    ) -> None:
        """Without options: 10 seats, 100 CHF, 10 GiB in bytes, status active."""
        _run(deps, _argv())

        request = _request(deps)
        assert (request.seats, request.storage_quota, request.status) == (
            10,
            10 * _GIB,
            "active",
        )
        assert isinstance(request.monthly_budget_chf, Decimal)
        assert request.monthly_budget_chf == Decimal("100")

    def test_admin_cli_create_org_default_language_is_english(self, deps: _Deps) -> None:
        """Without --language the invited account's language is ``en``."""
        _run(deps, _argv())

        assert _service_call(deps)[1]["language"] == "en"

    def test_admin_cli_create_org_options_reach_the_request(self, deps: _Deps) -> None:
        """--seats, --budget-chf (a Decimal) and --storage-quota-gib (x 1024**3 bytes)."""
        _run(
            deps,
            _argv("--seats", "25", "--budget-chf", "249.50", "--storage-quota-gib", "3"),
        )

        request = _request(deps)
        assert request.seats == 25
        assert request.monthly_budget_chf == Decimal("249.50")
        assert request.storage_quota == 3 * _GIB
        assert request.status == "active"

    @pytest.mark.parametrize("language", ["de", "fr", "en"])
    def test_admin_cli_create_org_language_option_reaches_the_service(
        self, deps: _Deps, language: str
    ) -> None:
        """--language de/fr/en is passed through as ``language``."""
        _run(deps, _argv("--language", language))

        assert _service_call(deps)[1]["language"] == language

    def test_admin_cli_create_org_link_base_is_the_stored_public_url(
        self, deps: _Deps, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """public_url is the loaded config's server.public_url (which already applies
        ADMINO_PUBLIC_URL); the CLI never reads the env var or builds its own base.
        """
        monkeypatch.setenv("ADMINO_PUBLIC_URL", _ENV_PUBLIC_URL)

        _run(deps, _argv())

        assert _service_call(deps)[1]["public_url"] == _PUBLIC_URL

    def test_admin_cli_create_org_has_no_client_ip(self, deps: _Deps) -> None:
        """The terminal has no client address: ip=None."""
        _run(deps, _argv())

        assert _service_call(deps)[1]["ip"] is None

    def test_admin_cli_create_org_steps_run_in_order(self, deps: _Deps) -> None:
        """SMTP lookup, pool, stored config, create_org, close: each once (no migrations)."""
        _run(deps, _argv())

        assert deps.steps() == _DB_STEPS

    def test_admin_cli_create_org_closes_the_pool(self, deps: _Deps) -> None:
        """close_pool is awaited once at the end."""
        _run(deps, _argv())

        deps.close_pool.assert_awaited_once()


_VALID_BOUNDARIES: list[Any] = [
    pytest.param(_argv("--seats", "1"), "seats", 1, id="seats-1"),
    pytest.param(_argv("--seats", "100000"), "seats", 100000, id="seats-100000"),
    pytest.param(_argv("--budget-chf", "0"), "monthly_budget_chf", Decimal(0), id="budget-0"),
    pytest.param(
        _argv("--budget-chf", "9999999999.99"),
        "monthly_budget_chf",
        Decimal("9999999999.99"),
        id="budget-12-digits",
    ),
    # A float round trip would turn this into 1234567.889999999897... and fail.
    pytest.param(
        _argv("--budget-chf", "1234567.89"),
        "monthly_budget_chf",
        Decimal("1234567.89"),
        id="budget-exact-decimal",
    ),
    pytest.param(_argv("--storage-quota-gib", "0"), "storage_quota", 0, id="quota-0"),
    pytest.param(
        _argv("--storage-quota-gib", str(_MAX_QUOTA_GIB)),
        "storage_quota",
        _MAX_QUOTA_GIB * _GIB,
        id="quota-max-gib",
    ),
    pytest.param(_argv(name="X"), "name", "X", id="name-1-char"),
    pytest.param(_argv(name="n" * 120), "name", "n" * 120, id="name-120-chars"),
    pytest.param(_argv(name="  " + "n" * 120 + "  "), "name", "n" * 120, id="name-120-after-strip"),
    pytest.param(
        _argv(name="Zürich Präzision SA"), "name", "Zürich Präzision SA", id="name-unicode"
    ),
    pytest.param(
        _argv(email=f"  {_ADMIN_EMAIL}  "),
        "primary_admin_email",
        _ADMIN_EMAIL,
        id="email-stripped",
    ),
    pytest.param(
        _argv(email="a" * 243 + "@example.ch"),
        "primary_admin_email",
        "a" * 243 + "@example.ch",
        id="email-254-chars",
    ),
]


class TestCreateOrgValidBoundaries:
    """Inputs at the edges of the OrgCreateRequest rules are accepted and passed on."""

    @pytest.mark.parametrize(("argv", "field_name", "expected"), _VALID_BOUNDARIES)
    def test_admin_cli_create_org_boundary_input_is_accepted(
        self, deps: _Deps, argv: list[str], field_name: str, expected: object
    ) -> None:
        """Exit 0, and the request carries the (normalized) value."""
        assert _run(deps, argv) == 0

        assert getattr(_request(deps), field_name) == expected


# ---------------------------------------------------------------------------
# 3. Validation: before PG_APP_PASSWORD, SMTP, the terminal and the database
# ---------------------------------------------------------------------------

_INVALID_INPUTS: list[Any] = [
    pytest.param(_argv(name=""), "--name", id="name-empty"),
    pytest.param(_argv(name="   "), "--name", id="name-whitespace-only"),
    pytest.param(_argv(name="n" * 121), "--name", id="name-121-chars"),
    pytest.param(_argv(name="Helvetia\nRobotics"), "--name", id="name-newline"),
    pytest.param(_argv(name="Helvetia\tRobotics"), "--name", id="name-tab"),
    pytest.param(_argv(name="Helvetia\x00Robotics"), "--name", id="name-nul"),
    pytest.param(_argv(name="Helvetia\x1b[31mRobotics"), "--name", id="name-ansi-escape"),
    pytest.param(_argv(name="Helvetia" + chr(0x9B) + "Robotics"), "--name", id="name-c1-csi"),
    pytest.param(_argv(name="Helvetia" + chr(0x202E) + "Robotics"), "--name", id="name-bidi-cf"),
    pytest.param(_argv(name="Helvetia" + chr(0x200B) + "Robotics"), "--name", id="name-zwsp-cf"),
    pytest.param(_argv(name="Helvetia" + chr(0xAD) + "Robotics"), "--name", id="name-soft-hyphen"),
    pytest.param(_argv(name="Helvetia" + chr(0x2028) + "Robotics"), "--name", id="name-zl"),
    pytest.param(_argv(name="Helvetia" + chr(0x2029) + "Robotics"), "--name", id="name-zp"),
    pytest.param(_argv(name="Helvetia" + chr(0xD800) + "Robotics"), "--name", id="name-cs"),
    pytest.param(_argv(email=""), "--admin-email", id="email-empty"),
    pytest.param(_argv(email="a@"), "--admin-email", id="email-2-chars"),
    pytest.param(
        _argv(email="primary.admin.helvetia-robotics.ch"), "--admin-email", id="email-no-at"
    ),
    pytest.param(_argv(email="@helvetia-robotics.ch"), "--admin-email", id="email-empty-local"),
    pytest.param(_argv(email="primary.admin@helvetia"), "--admin-email", id="email-no-dot"),
    pytest.param(
        _argv(email="primary.admin@helvetia-robotics."), "--admin-email", id="email-dot-last"
    ),
    pytest.param(
        _argv(email="primary@admin@helvetia-robotics.ch"), "--admin-email", id="email-two-ats"
    ),
    pytest.param(
        _argv(email="primary admin@helvetia-robotics.ch"), "--admin-email", id="email-space"
    ),
    pytest.param(
        _argv(email="primary.admin@helvetia\trobotics.ch"), "--admin-email", id="email-tab"
    ),
    pytest.param(
        _argv(email="primary" + chr(0x200B) + "admin@helvetia-robotics.ch"),
        "--admin-email",
        id="email-zwsp",
    ),
    pytest.param(
        _argv(email="primary.admin@helvetia" + chr(0x2028) + "robotics.ch"),
        "--admin-email",
        id="email-line-separator",
    ),
    pytest.param(_argv(email="a" * 244 + "@example.ch"), "--admin-email", id="email-255-chars"),
    pytest.param(_argv("--seats", "0"), "--seats", id="seats-0"),
    pytest.param(_argv("--seats", "100001"), "--seats", id="seats-100001"),
    pytest.param(_argv("--seats", "-5"), "--seats", id="seats-negative"),
    pytest.param(_argv("--budget-chf", "-1"), "--budget-chf", id="budget-negative"),
    pytest.param(_argv("--budget-chf", "-0.01"), "--budget-chf", id="budget-minus-a-cent"),
    pytest.param(_argv("--budget-chf", "100.005"), "--budget-chf", id="budget-3-decimals"),
    pytest.param(_argv("--budget-chf", "10000000000.00"), "--budget-chf", id="budget-13-digits"),
    pytest.param(_argv("--budget-chf", "NaN"), "--budget-chf", id="budget-nan"),
    pytest.param(_argv("--budget-chf", "sNaN"), "--budget-chf", id="budget-snan"),
    pytest.param(_argv("--budget-chf", "Infinity"), "--budget-chf", id="budget-infinity"),
    pytest.param(_argv("--budget-chf", "abc"), "--budget-chf", id="budget-not-a-number"),
    pytest.param(_argv("--budget-chf", ""), "--budget-chf", id="budget-empty"),
    pytest.param(_argv("--budget-chf", "12,50"), "--budget-chf", id="budget-decimal-comma"),
    pytest.param(_argv("--storage-quota-gib", "-1"), "--storage-quota-gib", id="quota-negative"),
    pytest.param(
        _argv("--storage-quota-gib", str(_MAX_QUOTA_GIB + 1)),
        "--storage-quota-gib",
        id="quota-over-2-pow-53-bytes",
    ),
]


# Distinctive inputs: a fixed hint (e.g. "like name@example.com") can't contain them.
_ECHO_CHECKED: list[Any] = [
    pytest.param(_argv(name="Helvetia\nRobotics"), ["Helvetia", "Robotics"], id="name-newline"),
    pytest.param(
        _argv(name="Helvetia" + chr(0x202E) + "Robotics"),
        ["Helvetia", "Robotics"],
        id="name-bidi",
    ),
    pytest.param(_argv(name="Quokka" * 21), ["Quokka"], id="name-too-long"),
    pytest.param(
        _argv(email="primary.admin.helvetia-robotics.ch"),
        ["primary.admin", "helvetia"],
        id="email-no-at",
    ),
    pytest.param(_argv(email="primary.admin@helvetia"), ["primary.admin", "helvetia"], id="no-dot"),
    pytest.param(
        _argv(email="primary admin@helvetia-robotics.ch"),
        ["primary admin", "helvetia"],
        id="email-space",
    ),
    pytest.param(_argv(email="q" * 244 + "@example.ch"), ["qqqqqqqq"], id="email-too-long"),
    pytest.param(_argv("--seats", "987654"), ["987654"], id="seats-987654"),
    pytest.param(_argv("--seats", "-4242"), ["4242"], id="seats-negative"),
    pytest.param(_argv("--budget-chf", "123.456"), ["123.456"], id="budget-3-decimals"),
    pytest.param(_argv("--budget-chf", "-777.77"), ["777.77"], id="budget-negative"),
    pytest.param(_argv("--budget-chf", "twelve-francs"), ["twelve", "francs"], id="budget-text"),
    pytest.param(
        _argv("--budget-chf", "98765432109876.5"), ["98765432109876"], id="budget-too-many-digits"
    ),
    pytest.param(_argv("--storage-quota-gib", "99999999"), ["99999999"], id="quota-too-big"),
    pytest.param(_argv("--storage-quota-gib", "-4242"), ["4242"], id="quota-negative"),
]

# Characters an error message can only carry if it repeats the input.
_UNSAFE_CHARACTERS: tuple[str, ...] = (
    "\x00",
    "\t",
    "\x1b",
    chr(0x7F),
    chr(0x9B),
    chr(0xAD),
    chr(0x200B),
    chr(0x202E),
    chr(0x2028),
    chr(0x2029),
    chr(0xD800),
)

# Two different invalid values of one field must produce the same fixed message.
_SAME_MESSAGE_PAIRS: list[Any] = [
    pytest.param(_argv(name=""), _argv(name="Quokka" * 21), id="name"),
    pytest.param(
        _argv(email="primary.admin.helvetia-robotics.ch"),
        _argv(email="primary admin@helvetia-robotics.ch"),
        id="admin-email",
    ),
    pytest.param(_argv("--seats", "0"), _argv("--seats", "987654"), id="seats"),
    pytest.param(
        _argv("--budget-chf", "-1"), _argv("--budget-chf", "123.456"), id="budget-range-vs-decimals"
    ),
    pytest.param(
        _argv("--budget-chf", "abc"), _argv("--budget-chf", "-1"), id="budget-text-vs-negative"
    ),
    pytest.param(
        _argv("--storage-quota-gib", "-1"),
        _argv("--storage-quota-gib", "99999999"),
        id="storage-quota",
    ),
]


class TestCreateOrgInvalidInput:
    """An invalid field is refused with a fixed message naming its option, exit 1, nothing run."""

    @pytest.mark.parametrize(("argv", "option"), _INVALID_INPUTS)
    def test_admin_cli_create_org_invalid_input_returns_one(
        self, deps: _Deps, argv: list[str], option: str
    ) -> None:
        """Exit code 1 (a validation error, not argparse's 2, and no traceback)."""
        assert _run(deps, argv) == 1

    @pytest.mark.parametrize(("argv", "option"), _INVALID_INPUTS)
    def test_admin_cli_create_org_invalid_input_names_only_its_option(
        self, deps: _Deps, argv: list[str], option: str
    ) -> None:
        """stderr names the invalid field's option and none of the valid ones."""
        _run(deps, argv)

        err = deps.err()
        assert option in err
        assert [other for other in _VALIDATED_OPTIONS if other != option and other in err] == []

    @pytest.mark.parametrize(("argv", "option"), _INVALID_INPUTS)
    def test_admin_cli_create_org_invalid_input_touches_nothing(
        self, deps: _Deps, argv: list[str], option: str
    ) -> None:
        """No SMTP lookup, no pool, no migrations, no stored config, no service call."""
        _run(deps, argv)

        assert deps.steps() == []
        deps.create_org.assert_not_awaited()

    @pytest.mark.parametrize(("argv", "option"), _INVALID_INPUTS)
    def test_admin_cli_create_org_invalid_input_error_is_clean(
        self, deps: _Deps, argv: list[str], option: str
    ) -> None:
        """stderr has no traceback and none of the input's control or invisible characters."""
        _run(deps, argv)

        err = deps.err()
        assert "Traceback" not in err
        assert [hex(ord(char)) for char in _UNSAFE_CHARACTERS if char in err] == []

    @pytest.mark.parametrize(("argv", "fragments"), _ECHO_CHECKED)
    def test_admin_cli_create_org_invalid_input_is_not_echoed(
        self, deps: _Deps, argv: list[str], fragments: list[str]
    ) -> None:
        """The error never repeats the rejected value or a distinctive part of it."""
        assert _run(deps, argv) == 1

        err = deps.err().lower()
        assert [fragment for fragment in fragments if fragment.lower() in err] == []

    @pytest.mark.parametrize(("first", "second"), _SAME_MESSAGE_PAIRS)
    def test_admin_cli_create_org_invalid_field_message_is_fixed(
        self, deps: _Deps, first: list[str], second: list[str]
    ) -> None:
        """Two different invalid values of one field produce the identical stderr text."""
        first_err = _err_of(deps, first)
        second_err = _err_of(deps, second)

        assert first_err.strip()
        assert first_err == second_err

    def test_admin_cli_create_org_every_invalid_field_is_reported(self, deps: _Deps) -> None:
        """All five fields invalid: exit 1, and stderr names each of their options."""
        argv = _argv(
            "--seats",
            "0",
            "--budget-chf",
            "-1",
            "--storage-quota-gib",
            "-1",
            name="",
            email="primary.admin.helvetia-robotics.ch",
        )

        assert _run(deps, argv) == 1

        err = deps.err()
        assert [option for option in _VALIDATED_OPTIONS if option not in err] == []

    def test_admin_cli_create_org_validation_precedes_the_pg_app_password_check(
        self, deps: _Deps, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Invalid input and no PG_APP_PASSWORD: the input is what gets reported."""
        monkeypatch.delenv("PG_APP_PASSWORD")

        assert _run(deps, _argv(name="")) == 1

        err = deps.err()
        assert "--name" in err
        assert "PG_APP_PASSWORD" not in err

    def test_admin_cli_create_org_validation_precedes_the_terminal_check(
        self, no_smtp_pipe: _Deps
    ) -> None:
        """Invalid input, no SMTP, no terminal: the input is reported; SMTP isn't looked up."""
        assert _run(no_smtp_pipe, _argv(email="primary.admin@helvetia")) == 1

        err = no_smtp_pipe.err()
        assert "--admin-email" in err
        assert "terminal" not in err.lower()
        no_smtp_pipe.load_smtp_config.assert_not_called()


# ---------------------------------------------------------------------------
# 4. PG_APP_PASSWORD (GH-220: the runtime role's password, never the owner's)
# ---------------------------------------------------------------------------

_NO_DSN_MESSAGE = "Error: the PG_APP_PASSWORD environment variable is not set."

_MISSING_APP_PASSWORD: list[Any] = [
    pytest.param({"PG_APP_PASSWORD": None}, id="unset-owner-vars-set"),
    pytest.param({"PG_APP_PASSWORD": ""}, id="empty-owner-vars-set"),
    pytest.param(
        {"PG_APP_PASSWORD": None, "PG_USER": None, "PG_PASSWORD": None},
        id="unset-owner-vars-unset",
    ),
    pytest.param(
        {"PG_APP_PASSWORD": "", "PG_USER": None, "PG_PASSWORD": None},
        id="empty-owner-vars-unset",
    ),
]


class TestCreateOrgRequiresPgAppPassword:
    """Without PG_APP_PASSWORD there is no runtime DSN: refuse before SMTP and the database.

    The owner's PG_PASSWORD is never a fallback, so setting it changes nothing.
    """

    @pytest.mark.parametrize("env", _MISSING_APP_PASSWORD)
    def test_admin_cli_create_org_without_pg_app_password_returns_one(
        self, deps: _Deps, monkeypatch: pytest.MonkeyPatch, env: dict[str, str | None]
    ) -> None:
        """Exit 1, stderr is exactly the fixed message naming PG_APP_PASSWORD; nothing
        looked up or opened.
        """
        _set_env(monkeypatch, env)

        assert _run(deps, _argv()) == 1

        assert deps.err() == _NO_DSN_MESSAGE + "\n"
        assert deps.steps() == []
        deps.create_org.assert_not_awaited()

    def test_admin_cli_create_org_pg_app_password_check_precedes_the_terminal_check(
        self, no_smtp_pipe: _Deps, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No PG_APP_PASSWORD (the owner's PG_PASSWORD set), no SMTP, no terminal:
        PG_APP_PASSWORD is what gets reported.
        """
        monkeypatch.delenv("PG_APP_PASSWORD")

        assert _run(no_smtp_pipe, _argv()) == 1

        err = no_smtp_pipe.err()
        assert _NO_DSN_MESSAGE in err
        assert "terminal" not in err.lower()


# ---------------------------------------------------------------------------
# 5. Delivery with SMTP: the email is queued, no link anywhere
# ---------------------------------------------------------------------------


class TestCreateOrgWithSmtp:
    """SMTP configured: no terminal needed, the email is queued and the link never shown."""

    def test_admin_cli_create_org_with_smtp_needs_no_terminal(self, deps: _Deps) -> None:
        """stdin and stdout aren't terminals, and the command still succeeds."""
        assert _run(deps, _argv()) == 0

        deps.create_org.assert_awaited_once()

    def test_admin_cli_create_org_with_smtp_queues_the_email(self, deps: _Deps) -> None:
        """create_org(..., queue_email=True)."""
        _run(deps, _argv())

        assert _service_call(deps)[1]["queue_email"] is True

    def test_admin_cli_create_org_with_smtp_prints_the_org_id(self, deps: _Deps) -> None:
        """stdout carries the new org's id (from the service's result)."""
        _run(deps, _argv())

        assert str(_ORG_ID) in deps.out()

    def test_admin_cli_create_org_with_smtp_says_the_email_is_queued(self, deps: _Deps) -> None:
        """stdout says the invitation email is queued."""
        _run(deps, _argv())

        assert "queued" in deps.out().lower()

    @pytest.mark.parametrize("tty", [False, True], ids=["pipe", "terminal"])
    def test_admin_cli_create_org_with_smtp_never_shows_the_link(
        self, deps: _Deps, tty: bool
    ) -> None:
        """Neither the link nor its token appears on stdout or stderr, terminal or not."""
        deps.stdout.tty = tty

        assert _run(deps, _argv()) == 0

        output = deps.out() + deps.err()
        assert _TOKEN not in output
        assert "accept-invitation" not in output


# ---------------------------------------------------------------------------
# 6. Delivery without SMTP: stdout must be a terminal; the link goes there only
# ---------------------------------------------------------------------------


class TestCreateOrgWithoutSmtpNoTerminal:
    """No SMTP and stdout isn't a terminal: refuse before the database (exit 1)."""

    def test_admin_cli_create_org_without_smtp_or_terminal_returns_one(
        self, no_smtp_pipe: _Deps
    ) -> None:
        """Exit code 1, no traceback."""
        assert _run(no_smtp_pipe, _argv()) == 1

        assert "Traceback" not in no_smtp_pipe.err()

    def test_admin_cli_create_org_without_smtp_or_terminal_asks_for_a_terminal(
        self, no_smtp_pipe: _Deps
    ) -> None:
        """stderr explains that a terminal is required, without echoing the input."""
        _run(no_smtp_pipe, _argv())

        err = no_smtp_pipe.err().lower()
        assert "terminal" in err
        assert _ADMIN_EMAIL.lower() not in err
        assert _ORG_NAME.lower() not in err

    def test_admin_cli_create_org_without_smtp_or_terminal_touches_no_database(
        self, no_smtp_pipe: _Deps
    ) -> None:
        """No pool, no migrations, no stored config, no service call."""
        _run(no_smtp_pipe, _argv())

        assert no_smtp_pipe.steps() == ["load_smtp_config"]
        no_smtp_pipe.create_org.assert_not_awaited()

    def test_admin_cli_create_org_without_smtp_or_terminal_prints_no_link(
        self, no_smtp_pipe: _Deps
    ) -> None:
        """Nothing link-like reaches the pipe."""
        _run(no_smtp_pipe, _argv())

        assert "accept-invitation" not in no_smtp_pipe.out()


class TestCreateOrgWithoutSmtpOnTerminal:
    """No SMTP and stdout is a terminal: nothing queued; the link is shown on stdout only."""

    def test_admin_cli_create_org_without_smtp_on_terminal_returns_zero(
        self, no_smtp_terminal: _Deps
    ) -> None:
        """Exit code 0."""
        assert _run(no_smtp_terminal, _argv()) == 0

    def test_admin_cli_create_org_without_smtp_queues_nothing(
        self, no_smtp_terminal: _Deps
    ) -> None:
        """create_org(..., queue_email=False)."""
        _run(no_smtp_terminal, _argv())

        assert _service_call(no_smtp_terminal)[1]["queue_email"] is False

    def test_admin_cli_create_org_without_smtp_prints_the_org_id(
        self, no_smtp_terminal: _Deps
    ) -> None:
        """stdout carries the new org's id."""
        _run(no_smtp_terminal, _argv())

        assert str(_ORG_ID) in no_smtp_terminal.out()

    def test_admin_cli_create_org_without_smtp_prints_the_link_on_its_own_line(
        self, no_smtp_terminal: _Deps
    ) -> None:
        """The service's accept_link, unchanged, is a line of its own on stdout."""
        _run(no_smtp_terminal, _argv())

        lines = [line.strip() for line in no_smtp_terminal.out().splitlines()]
        assert _LINK in lines

    def test_admin_cli_create_org_without_smtp_explains_before_the_link(
        self, no_smtp_terminal: _Deps
    ) -> None:
        """A line mentioning SMTP (not configured) comes before the link's line."""
        _run(no_smtp_terminal, _argv())

        lines = [line.strip() for line in no_smtp_terminal.out().splitlines()]
        smtp_lines = [index for index, line in enumerate(lines) if "smtp" in line.lower()]
        assert smtp_lines, "stdout doesn't explain that SMTP isn't configured"
        assert _LINK in lines
        assert smtp_lines[0] < lines.index(_LINK)

    def test_admin_cli_create_org_without_smtp_prints_the_expiry_date(
        self, no_smtp_terminal: _Deps
    ) -> None:
        """stdout shows when the link expires (the invitation's expires_at, YYYY-MM-DD)."""
        _run(no_smtp_terminal, _argv())

        assert _EXPIRY_DATE in no_smtp_terminal.out()

    def test_admin_cli_create_org_without_smtp_link_never_reaches_stderr(
        self, no_smtp_terminal: _Deps
    ) -> None:
        """stderr carries neither the link nor its token."""
        _run(no_smtp_terminal, _argv())

        err = no_smtp_terminal.err()
        assert _TOKEN not in err
        assert "accept-invitation" not in err

    def test_admin_cli_create_org_without_smtp_checks_the_terminal_before_the_database(
        self, no_smtp_terminal: _Deps
    ) -> None:
        """stdout.isatty() is asked before init_pool; then the usual steps, in order."""
        _run(no_smtp_terminal, _argv())

        events = no_smtp_terminal.events
        assert "init_pool" in events
        assert "stdout.isatty" in events[: events.index("init_pool")]
        assert no_smtp_terminal.steps() == _DB_STEPS


# ---------------------------------------------------------------------------
# 7. Refusals and failures: exit 1, fixed message, pool closed, no traceback
# ---------------------------------------------------------------------------

_CREATE_FAILURES: list[Any] = [
    pytest.param(_duplicate_error, "already exists", id="email-taken"),
    pytest.param(AuditRecordError, "could not be created", id="audit-write-failed"),
    pytest.param(_driver_error, "could not be created", id="postgres-error"),
    pytest.param(
        lambda: asyncpg.InterfaceError(f"{_DRIVER_MARKER}: connection closed"),
        "could not be created",
        id="interface-error",
    ),
    pytest.param(
        lambda: ConnectionResetError(f"{_DRIVER_MARKER}: connection reset"),
        "could not be created",
        id="os-error",
    ),
]


class TestCreateOrgCreateFailures:
    """create_org refuses or fails: a fixed message, exit 1, the pool closed."""

    @pytest.mark.parametrize(("make_error", "phrase"), _CREATE_FAILURES)
    def test_admin_cli_create_org_create_failure_returns_one_with_fixed_message(
        self, deps: _Deps, make_error: Callable[[], Exception], phrase: str
    ) -> None:
        """Exit 1; stderr carries the fixed message and no traceback."""
        deps.create_org.side_effect = make_error()

        assert _run(deps, _argv()) == 1

        err = deps.err()
        assert phrase in err.lower()
        assert "Traceback" not in err

    @pytest.mark.parametrize(("make_error", "phrase"), _CREATE_FAILURES)
    def test_admin_cli_create_org_create_failure_closes_the_pool(
        self, deps: _Deps, make_error: Callable[[], Exception], phrase: str
    ) -> None:
        """close_pool is awaited once."""
        deps.create_org.side_effect = make_error()

        _run(deps, _argv())

        deps.close_pool.assert_awaited_once()

    @pytest.mark.parametrize(("make_error", "phrase"), _CREATE_FAILURES)
    def test_admin_cli_create_org_create_failure_echoes_nothing(
        self, deps: _Deps, make_error: Callable[[], Exception], phrase: str
    ) -> None:
        """stderr repeats neither the driver's text nor the email, the name or the token."""
        deps.create_org.side_effect = make_error()

        _run(deps, _argv())

        err = deps.err().lower()
        for fragment in (_DRIVER_MARKER, _ADMIN_EMAIL, _ORG_NAME, _TOKEN):
            assert fragment.lower() not in err, fragment

    def test_admin_cli_create_org_create_failure_prints_no_org_id_or_link(
        self, no_smtp_terminal: _Deps
    ) -> None:
        """A failure without SMTP on a terminal shows no org id and no link."""
        no_smtp_terminal.create_org.side_effect = AuditRecordError()

        assert _run(no_smtp_terminal, _argv()) == 1

        out = no_smtp_terminal.out()
        assert str(_ORG_ID) not in out
        assert "accept-invitation" not in out


_UNREACHABLE: list[Any] = [
    pytest.param(ConnectionRefusedError("connection refused"), id="connection-refused"),
    pytest.param(TimeoutError("timed out"), id="timeout"),
    pytest.param(asyncpg.InterfaceError("interface"), id="interface-error"),
    pytest.param(asyncpg.PostgresError("auth failed"), id="postgres-error"),
]

_DATABASE_UNAVAILABLE = "database is unavailable"


class TestCreateOrgSetupFailures:
    """The pool or the stored config fail: exit 1 before create_org."""

    @pytest.mark.parametrize("error", _UNREACHABLE)
    def test_admin_cli_create_org_unreachable_database_returns_one(
        self, deps: _Deps, error: Exception
    ) -> None:
        """init_pool fails → exit 1, 'database is unavailable', nothing else runs."""
        deps.init_pool.side_effect = error

        assert _run(deps, _argv()) == 1

        err = deps.err()
        assert _DATABASE_UNAVAILABLE in err.lower()
        assert "Traceback" not in err
        deps.run_migrations_spy.assert_not_awaited()
        deps.create_org.assert_not_awaited()

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(
                asyncpg.UndefinedTableError(f'{_DRIVER_MARKER}: relation "organizations"'),
                id="schema-not-migrated",
            ),
            pytest.param(
                asyncpg.InsufficientPrivilegeError(f"{_DRIVER_MARKER}: permission denied"),
                id="missing-grant",
            ),
        ],
    )
    def test_admin_cli_create_org_first_query_failure_runs_no_migrations(
        self, deps: _Deps, error: asyncpg.PostgresError
    ) -> None:
        """GH-220: the first query (create_org) fails as the runtime role → exit 1, the
        fixed 'could not be created' message without the driver's text, the pool
        closed, and no migrations are run to make up for a missing table.
        """
        deps.create_org.side_effect = error

        assert _run(deps, _argv()) == 1

        err = deps.err()
        assert "could not be created" in err.lower()
        assert _DRIVER_MARKER not in err
        deps.close_pool.assert_awaited_once()
        deps.run_migrations_spy.assert_not_awaited()

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(
                lambda: ValueError(f"Invalid application config: {_CONFIG_MARKER}"),
                id="value-error",
            ),
            pytest.param(_config_validation_error, id="validation-error"),
        ],
    )
    def test_admin_cli_create_org_invalid_stored_config_returns_one(
        self, deps: _Deps, make_error: Callable[[], Exception]
    ) -> None:
        """load_app_config raises → exit 1, a fixed 'configuration is invalid'
        message without the error's text, no service call, the pool closed.
        """
        deps.load_app_config.side_effect = make_error()

        assert _run(deps, _argv()) == 1

        err = deps.err()
        assert "configuration is invalid" in err.lower()
        assert _CONFIG_MARKER not in err
        assert "Traceback" not in err
        deps.create_org.assert_not_awaited()
        deps.close_pool.assert_awaited_once()

    def test_admin_cli_create_org_config_read_failure_returns_one(self, deps: _Deps) -> None:
        """config.yaml can't be read (OSError) → exit 1, fixed text, pool closed."""
        deps.load_app_config.side_effect = PermissionError(f"{_DRIVER_MARKER}: config.yaml")

        assert _run(deps, _argv()) == 1

        err = deps.err()
        assert err.strip()
        assert _DRIVER_MARKER not in err
        assert "Traceback" not in err
        deps.create_org.assert_not_awaited()
        deps.close_pool.assert_awaited_once()


# ---------------------------------------------------------------------------
# 8. No link, token, email, name or SMTP secret in logs (or on stderr), on every path
# ---------------------------------------------------------------------------


def _scenario_smtp_success(deps: _Deps, monkeypatch: pytest.MonkeyPatch) -> None:
    """Defaults: SMTP configured, created."""


def _scenario_no_smtp_terminal(deps: _Deps, monkeypatch: pytest.MonkeyPatch) -> None:
    deps.load_smtp_config.return_value = None
    deps.stdout.tty = True


def _scenario_no_smtp_pipe(deps: _Deps, monkeypatch: pytest.MonkeyPatch) -> None:
    deps.load_smtp_config.return_value = None


def _scenario_no_pg_app_password(deps: _Deps, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PG_APP_PASSWORD")


def _scenario_email_taken(deps: _Deps, monkeypatch: pytest.MonkeyPatch) -> None:
    deps.create_org.side_effect = _duplicate_error()


def _scenario_audit_failure(deps: _Deps, monkeypatch: pytest.MonkeyPatch) -> None:
    deps.create_org.side_effect = AuditRecordError()


def _scenario_db_failure(deps: _Deps, monkeypatch: pytest.MonkeyPatch) -> None:
    deps.create_org.side_effect = _driver_error()


def _scenario_unreachable(deps: _Deps, monkeypatch: pytest.MonkeyPatch) -> None:
    deps.init_pool.side_effect = ConnectionRefusedError("connection refused")


def _scenario_invalid_config(deps: _Deps, monkeypatch: pytest.MonkeyPatch) -> None:
    deps.load_app_config.side_effect = _config_validation_error()


# (scenario, whether the link may appear on stdout)
_SCENARIOS: list[Any] = [
    pytest.param(_scenario_smtp_success, False, id="smtp-success"),
    pytest.param(_scenario_no_smtp_terminal, True, id="no-smtp-terminal"),
    pytest.param(_scenario_no_smtp_pipe, False, id="no-smtp-pipe"),
    pytest.param(_scenario_no_pg_app_password, False, id="no-pg-app-password"),
    pytest.param(_scenario_email_taken, False, id="email-taken"),
    pytest.param(_scenario_audit_failure, False, id="audit-failure"),
    pytest.param(_scenario_db_failure, False, id="db-failure"),
    pytest.param(_scenario_unreachable, False, id="unreachable"),
    pytest.param(_scenario_invalid_config, False, id="invalid-config"),
]


class TestCreateOrgNoLeaks:
    """The link reaches stdout only (without SMTP); logs never carry any secret or content."""

    @pytest.mark.parametrize(("scenario", "link_on_stdout"), _SCENARIOS)
    def test_admin_cli_create_org_logs_carry_no_link_email_name_or_secret(
        self,
        deps: _Deps,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
        scenario: Callable[[_Deps, pytest.MonkeyPatch], None],
        link_on_stdout: bool,
    ) -> None:
        """At DEBUG on every logger: no link, token, admin email, org name or SMTP password."""
        caplog.set_level(logging.DEBUG)
        caplog.set_level(logging.DEBUG, logger="admino")
        scenario(deps, monkeypatch)

        _run(deps, _argv())

        logged = _log_text(caplog).lower()
        for secret in (_LINK, _TOKEN, _ADMIN_EMAIL, _ORG_NAME, _SMTP_PASSWORD):
            assert secret.lower() not in logged, secret

    @pytest.mark.parametrize(("scenario", "link_on_stdout"), _SCENARIOS)
    def test_admin_cli_create_org_stderr_carries_no_link_email_name_or_secret(
        self,
        deps: _Deps,
        monkeypatch: pytest.MonkeyPatch,
        scenario: Callable[[_Deps, pytest.MonkeyPatch], None],
        link_on_stdout: bool,
    ) -> None:
        """stderr never carries the link, the token, the email, the name or the SMTP password."""
        scenario(deps, monkeypatch)

        _run(deps, _argv())

        err = deps.err().lower()
        for secret in (_LINK, _TOKEN, _ADMIN_EMAIL, _ORG_NAME, _SMTP_PASSWORD):
            assert secret.lower() not in err, secret

    @pytest.mark.parametrize(("scenario", "link_on_stdout"), _SCENARIOS)
    def test_admin_cli_create_org_link_on_stdout_only_without_smtp_on_a_terminal(
        self,
        deps: _Deps,
        monkeypatch: pytest.MonkeyPatch,
        scenario: Callable[[_Deps, pytest.MonkeyPatch], None],
        link_on_stdout: bool,
    ) -> None:
        """The token is on stdout exactly when SMTP is off and stdout is a terminal."""
        scenario(deps, monkeypatch)

        _run(deps, _argv())

        out = deps.out()
        assert (_TOKEN in out) is link_on_stdout
        assert _SMTP_PASSWORD not in out


# ---------------------------------------------------------------------------
# 9. create-superadmin still dispatches as before
# ---------------------------------------------------------------------------


class TestCreateSuperAdminStillDispatches:
    """Adding create-org leaves create-superadmin working and separate."""

    def test_admin_cli_create_superadmin_still_creates_and_never_creates_an_org(
        self, deps: _Deps, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """create-superadmin prompts, creates the Super Admin, exits 0; create_org never runs."""
        monkeypatch.setattr(sys, "stdin", _Stdin(tty=True))
        answers = [_SUPERADMIN_PASSWORD, _SUPERADMIN_PASSWORD]

        def _scripted(prompt: str = "", stream: Any = None) -> str:
            return answers.pop(0)

        monkeypatch.setattr(getpass, "getpass", _scripted)
        email_exists = AsyncMock(return_value=False)
        create_super_admin = AsyncMock(return_value=_SUPERADMIN_ID)
        with (
            patch("admino.accounts.email_exists", new=email_exists),
            patch("admino.accounts.create_super_admin", new=create_super_admin),
            patch("admino.passwords.hash_password", new=MagicMock(return_value=_FAKE_HASH)),
        ):
            code = _run(
                deps,
                ["create-superadmin", "--email", _SUPERADMIN_EMAIL, "--name", _SUPERADMIN_NAME],
            )

        assert code == 0
        create_super_admin.assert_awaited_once_with(
            deps.pool.conn,
            email=_SUPERADMIN_EMAIL,
            name=_SUPERADMIN_NAME,
            password_hash=_FAKE_HASH,
        )
        deps.create_org.assert_not_awaited()
        assert "super admin created" in deps.out().lower()


# ---------------------------------------------------------------------------
# 10. The module entry point (what ``make create-org`` runs)
# ---------------------------------------------------------------------------


def _run_module(*args: str, env_extra: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run ``python -m admino.admin_cli <args>`` with stdin, stdout and stderr not terminals.

    No PG_*, SMTP_* or ADMINO_* variable is inherited; ``env_extra`` adds some back.
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("PG_", "SMTP_", "ADMINO_"))
    }
    env.update(env_extra)
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "admino.admin_cli", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        stdin=subprocess.DEVNULL,
        env=env,
    )


class TestCreateOrgEntryPoint:
    """``python -m admino.admin_cli create-org`` refuses before the database when it must."""

    @pytest.mark.parametrize(
        "env_extra",
        [
            pytest.param({}, id="no-pg-vars"),
            pytest.param(_OWNER_ENV, id="owner-vars-only"),
        ],
    )
    def test_admin_cli_module_create_org_without_pg_app_password_exits_one(
        self, env_extra: dict[str, str]
    ) -> None:
        """No PG_APP_PASSWORD (no PG_* at all, or only the owner's PG_USER/PG_PASSWORD)
        → exit 1 with the PG_APP_PASSWORD message, and the owner's password not shown.
        """
        result = _run_module(
            "create-org", "--name", _ORG_NAME, "--admin-email", _ADMIN_EMAIL, env_extra=env_extra
        )

        assert result.returncode == 1, result.stderr
        assert _NO_DSN_MESSAGE in result.stderr
        assert _OWNER_PASSWORD not in result.stdout + result.stderr

    def test_admin_cli_module_create_org_without_smtp_refuses_piped_stdout(self) -> None:
        """PG_APP_PASSWORD set (an unreachable port), no SMTP_*, stdout piped → exit 1
        asking for a terminal, before any database connection, with no link anywhere.
        """
        result = _run_module(
            "create-org",
            "--name",
            _ORG_NAME,
            "--admin-email",
            _ADMIN_EMAIL,
            env_extra={
                "PG_HOST": "127.0.0.1",
                "PG_PORT": "9",
                "PG_DATABASE": "admino",
                "PG_APP_PASSWORD": _PG_APP_PASSWORD,
            },
        )

        assert result.returncode == 1, result.stderr
        assert "terminal" in result.stderr.lower()
        assert _DATABASE_UNAVAILABLE not in result.stderr.lower()
        assert "accept-invitation" not in result.stdout + result.stderr
        assert re.search(r"token=", result.stdout + result.stderr) is None
