"""Tests for admino.admin_cli — the create-superadmin bootstrap CLI (GH-150).

``python -m admino.admin_cli create-superadmin --email ... --name ...`` creates
the platform's first Super Admin. It validates the email (3 to 254 characters,
no whitespace, an '@' after a non-empty local part) and the name (1 to 120
characters after trimming, no control characters), refuses to run without an
interactive terminal, opens the pool from the PG_* env vars and applies pending
migrations. It then refuses a duplicate email (before any prompt), reads the
password twice with getpass under the #149 policy (3 attempts), hashes it off
the event loop and creates the account and its user.activate audit event in
one transaction. The module is argparse-based with subcommands, so #154 can
add ``create-org``.

Inputs: argv, the PG_* env vars, a scripted getpass and a stubbed sys.stdin.
Outputs: the exit code (0 created, 1 refused or failed, 2 usage error), the
calls to the patched pool/migrations/accounts functions, stdout/stderr and log
records.

The module is imported lazily through the ``cli`` fixture, so before it exists
every test errors on its own instead of the whole file failing to collect.

Security notes:
- All database access is mocked (init_pool, run_migrations, close_pool and a
  recording fake pool). No real PostgreSQL connection is made.
- Argon2 is replaced by a fast fake, except in one test that checks that the
  stored hash verifies.
- The password never appears in stdout, stderr or any log record. The email
  and the name never appear in a log record. Error messages never echo input.
"""

from __future__ import annotations

import getpass
import logging
import os
import re
import subprocess
import sys
import threading
from contextlib import ExitStack, asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from unittest.mock import DEFAULT, AsyncMock, MagicMock, call, patch
from uuid import UUID

import asyncpg
import pytest

from admino import accounts, passwords
from admino.audit_events import AuditRecordError
from admino.passwords import PasswordPolicyError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator
    from types import ModuleType

# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

_EMAIL = "Ops.Admin@Example.ch"
_NAME = "Ada Lovelace-Operator"
_NAME_ARG = f"  {_NAME}  "  # surrounding whitespace the CLI trims
_PASSWORD = "Correct-Horse-Battery-9!"
_OTHER_PASSWORD = "Correct-Horse-Battery-8!"
_TOO_SHORT = "Tiny-9!"
_COMMON = "password1234"
_EMAIL_AS_PASSWORD = _EMAIL.upper()  # 20 characters, uncommon: only equals_email catches it
_FAKE_HASH = (
    "$argon2id$v=19$m=19456,t=2,p=1$ZmFrZXNhbHRmYWtlc2FsdA"
    "$ZmFrZWRpZ2VzdGZha2VkaWdlc3RmYWtlZGlnZXN0MDE"
)
_NEW_USER_ID = UUID("3c9e1f4a-7b2d-4e8f-a1c6-5d0b9e2f7a14")
_PG_PASSWORD = "pg-S3cret/p@ss"
_EXPECTED_DSN = "postgresql://admino:pg-S3cret%2Fp%40ss@localhost:5432/admino"
_PG_ENV: dict[str, str] = {
    "PG_HOST": "localhost",
    "PG_PORT": "5432",
    "PG_USER": "admino",
    "PG_DATABASE": "admino",
    "PG_PASSWORD": _PG_PASSWORD,
}
_PASSWORD_PROMPT = "Password: "
_REPEAT_PROMPT = "Repeat password: "
_TYPED_PASSWORDS: tuple[str, ...] = (
    _PASSWORD,
    _OTHER_PASSWORD,
    _TOO_SHORT,
    _COMMON,
    _EMAIL_AS_PASSWORD,
)
# Captured before any test patches them.
_REAL_HASH_PASSWORD = passwords.hash_password
_REAL_CHECK_PASSWORD_POLICY = passwords.check_password_policy


def _norm(sql: str) -> str:
    """Collapse whitespace and lowercase, for formatting-tolerant SQL matching."""
    return re.sub(r"\s+", " ", sql).strip().lower()


# ---------------------------------------------------------------------------
# Fakes: stdin, getpass, and a recording pool
# ---------------------------------------------------------------------------


class _Stdin:
    """A stand-in for sys.stdin: only isatty() answers; reading it is a test failure.

    The password must come from getpass, never from input() or sys.stdin.
    """

    def __init__(self, *, tty: bool) -> None:
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty

    def read(self, *_args: Any) -> str:
        msg = "the CLI read sys.stdin; the password must be read with getpass"
        raise AssertionError(msg)

    def readline(self, *_args: Any) -> str:
        msg = "the CLI read sys.stdin; the password must be read with getpass"
        raise AssertionError(msg)


class _Prompts:
    """A scripted getpass.getpass: pops the next answer (or raises it) and records the prompt."""

    def __init__(self, events: list[str], answers: list[str | BaseException]) -> None:
        self._events = events
        self.answers: list[str | BaseException] = list(answers)
        self.prompts: list[str] = []

    def script(self, *answers: str | BaseException) -> None:
        """Replace the scripted answers."""
        self.answers = list(answers)

    def __call__(self, prompt: str = _PASSWORD_PROMPT, stream: Any = None) -> str:
        self._events.append("getpass")
        self.prompts.append(prompt)
        if not self.answers:
            msg = "getpass was called more often than the test scripted"
            raise AssertionError(msg)
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


@dataclass
class _Call:
    """One statement the fake pool saw."""

    method: str
    sql: str
    args: tuple[Any, ...]
    in_transaction: bool


class _FakeConn:
    """A pooled connection: records statements, tracks its transaction, answers inserts."""

    def __init__(self, pool: _FakePool) -> None:
        self._pool = pool
        self._in_transaction = False
        self.rollbacks: list[type[BaseException]] = []
        self.commits = 0

    def _record(self, method: str, sql: str, args: tuple[Any, ...]) -> None:
        self._pool.calls.append(_Call(f"conn.{method}", sql, args, self._in_transaction))

    async def fetchval(self, sql: str, *args: Any) -> Any:
        self._record("fetchval", sql, args)
        if _norm(sql).startswith("insert"):
            return _NEW_USER_ID
        return self._pool.existing

    async def execute(self, sql: str, *args: Any) -> str:
        self._record("execute", sql, args)
        return "INSERT 0 1"

    async def fetch(self, sql: str, *args: Any) -> list[Any]:
        self._record("fetch", sql, args)
        return []

    async def fetchrow(self, sql: str, *args: Any) -> Any:
        self._record("fetchrow", sql, args)
        return None

    def is_in_transaction(self) -> bool:
        return self._in_transaction

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        self._pool.events.append("transaction.begin")
        self._in_transaction = True
        try:
            yield
        except BaseException as exc:
            self.rollbacks.append(type(exc))
            self._pool.events.append("transaction.rollback")
            raise
        else:
            self.commits += 1
            self._pool.events.append("transaction.commit")
        finally:
            self._in_transaction = False


class _FakePool:
    """The pool init_pool returns: one reusable connection; records every statement."""

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.calls: list[_Call] = []
        self.existing: object = False
        self.conn = _FakeConn(self)

    async def fetchval(self, sql: str, *args: Any) -> Any:
        self.calls.append(_Call("pool.fetchval", sql, args, False))
        return self.existing

    async def fetchrow(self, sql: str, *args: Any) -> Any:
        self.calls.append(_Call("pool.fetchrow", sql, args, False))
        return None

    async def fetch(self, sql: str, *args: Any) -> list[Any]:
        self.calls.append(_Call("pool.fetch", sql, args, False))
        return []

    async def execute(self, sql: str, *args: Any) -> str:
        self.calls.append(_Call("pool.execute", sql, args, False))
        return "OK"

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[_FakeConn]:
        yield self.conn


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@dataclass
class _Deps:
    """Every patched dependency of the CLI, plus the shared ordered event log."""

    events: list[str]
    pool: _FakePool
    prompts: _Prompts
    init_pool: AsyncMock
    run_migrations: AsyncMock
    close_pool: AsyncMock
    email_exists: AsyncMock
    create_super_admin: AsyncMock
    hash_password: MagicMock
    policy: MagicMock
    real_email_exists: Callable[..., Any]
    real_create_super_admin: Callable[..., Any]
    create_in_transaction: list[bool] = field(default_factory=list)
    hash_threads: list[int] = field(default_factory=list)


def _logging(events: list[str], name: str) -> Callable[..., Any]:
    """A mock side effect that logs its name and then lets the mock return its return_value."""

    def _log(*_args: Any, **_kwargs: Any) -> Any:
        events.append(name)
        return DEFAULT

    return _log


@pytest.fixture()
def cli() -> ModuleType:
    """Import admino.admin_cli (lazily, so each test fails on its own before it exists)."""
    from admino import admin_cli

    return admin_cli


@pytest.fixture()
def deps(cli: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Deps]:
    """PG_* env set, a TTY on stdin, a scripted getpass and every DB/hash dependency patched.

    Defaults: the email is free, the password is typed twice correctly, the
    insert returns _NEW_USER_ID and hash_password returns _FAKE_HASH. The
    password policy is the real one, wrapped in a spy.
    """
    for name, value in _PG_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "stdin", _Stdin(tty=True))

    events: list[str] = []
    pool = _FakePool(events)
    prompts = _Prompts(events, [_PASSWORD, _PASSWORD])
    monkeypatch.setattr(getpass, "getpass", prompts)

    create_in_transaction: list[bool] = []
    hash_threads: list[int] = []

    def _log_create(*args: Any, **kwargs: Any) -> Any:
        conn = args[0] if args else kwargs.get("conn")
        events.append("create_super_admin")
        create_in_transaction.append(bool(conn is not None and conn.is_in_transaction()))
        return DEFAULT

    def _log_hash(*_args: Any, **_kwargs: Any) -> Any:
        events.append("hash_password")
        hash_threads.append(threading.get_ident())
        return DEFAULT

    init_pool = AsyncMock(return_value=pool, side_effect=_logging(events, "init_pool"))
    run_migrations = AsyncMock(side_effect=_logging(events, "run_migrations"))
    close_pool = AsyncMock(side_effect=_logging(events, "close_pool"))
    email_exists = AsyncMock(return_value=False, side_effect=_logging(events, "email_exists"))
    create_super_admin = AsyncMock(return_value=_NEW_USER_ID, side_effect=_log_create)
    hash_password = MagicMock(return_value=_FAKE_HASH, side_effect=_log_hash)
    policy = MagicMock(wraps=_REAL_CHECK_PASSWORD_POLICY)

    # Looked up before patching: after GH-150 both exist on admino.accounts.
    real_email_exists = accounts.email_exists  # type: ignore[attr-defined]
    real_create_super_admin = accounts.create_super_admin  # type: ignore[attr-defined]

    with ExitStack() as stack:
        stack.enter_context(patch("admino.admin_cli.init_pool", new=init_pool))
        stack.enter_context(patch("admino.admin_cli.run_migrations", new=run_migrations))
        stack.enter_context(patch("admino.admin_cli.close_pool", new=close_pool))
        stack.enter_context(patch("admino.accounts.email_exists", new=email_exists))
        stack.enter_context(patch("admino.accounts.create_super_admin", new=create_super_admin))
        stack.enter_context(patch("admino.passwords.hash_password", new=hash_password))
        stack.enter_context(patch("admino.passwords.check_password_policy", new=policy))
        yield _Deps(
            events=events,
            pool=pool,
            prompts=prompts,
            init_pool=init_pool,
            run_migrations=run_migrations,
            close_pool=close_pool,
            email_exists=email_exists,
            create_super_admin=create_super_admin,
            hash_password=hash_password,
            policy=policy,
            real_email_exists=real_email_exists,
            real_create_super_admin=real_create_super_admin,
            create_in_transaction=create_in_transaction,
            hash_threads=hash_threads,
        )


def _run(cli: ModuleType, *, email: str = _EMAIL, name: str = _NAME_ARG) -> int:
    """Run ``create-superadmin --email <email> --name <name>`` and return the exit code.

    A KeyboardInterrupt escaping main() becomes a test failure instead of
    stopping the whole pytest session.
    """
    try:
        result = cli.main(["create-superadmin", "--email", email, "--name", name])
    except KeyboardInterrupt:
        pytest.fail("KeyboardInterrupt escaped main(): Ctrl-C must end as 'Cancelled', exit 1")
    assert isinstance(result, int)
    return result


def _duplicate_error() -> Exception:
    """accounts.DuplicateEmailError(), looked up lazily."""
    error: Exception = accounts.DuplicateEmailError()  # type: ignore[attr-defined]
    return error


def _log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Everything the log records carry: formatted output, messages, args and exception text."""
    parts = [caplog.text]
    for record in caplog.records:
        parts.extend([record.getMessage(), repr(record.args), record.exc_text or ""])
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# 1. Happy path
# ---------------------------------------------------------------------------


class TestCreateSuperAdminHappyPath:
    """A valid email, name and password (typed twice) create an active Super Admin."""

    def test_admin_cli_create_superadmin_success_returns_zero(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """Exit code 0 when the Super Admin is created."""
        assert _run(cli) == 0

    def test_admin_cli_create_superadmin_success_prints_confirmation(
        self, cli: ModuleType, deps: _Deps, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """stdout confirms 'Super Admin created'."""
        _run(cli)

        assert "super admin created" in capsys.readouterr().out.lower()

    def test_admin_cli_create_superadmin_creates_account_with_email_trimmed_name_and_hash(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """create_super_admin(conn, email=as given, name=trimmed, password_hash=the hash)."""
        _run(cli)

        deps.create_super_admin.assert_awaited_once_with(
            deps.pool.conn, email=_EMAIL, name=_NAME, password_hash=_FAKE_HASH
        )

    def test_admin_cli_create_superadmin_creates_inside_a_committed_transaction(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """The create runs on the pooled connection inside its transaction, which commits."""
        _run(cli)

        assert deps.create_in_transaction == [True]
        assert deps.pool.conn.commits == 1
        assert deps.pool.conn.rollbacks == []

    def test_admin_cli_create_superadmin_hashes_the_typed_password(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """hash_password receives the password typed at the prompt, once."""
        _run(cli)

        deps.hash_password.assert_called_once_with(_PASSWORD)

    def test_admin_cli_create_superadmin_hashes_off_the_event_loop_thread(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """Argon2 runs through asyncio.to_thread, not on the thread running the event loop."""
        _run(cli)

        assert len(deps.hash_threads) == 1
        assert deps.hash_threads[0] != threading.main_thread().ident

    def test_admin_cli_create_superadmin_checks_policy_against_the_email(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """check_password_policy(password, email=the email) runs once for the typed password."""
        _run(cli)

        assert deps.policy.call_args_list == [call(_PASSWORD, email=_EMAIL)]

    def test_admin_cli_create_superadmin_prompts_password_then_repeat(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """getpass asks for the password, then for it again to confirm."""
        _run(cli)

        assert deps.prompts.prompts == [_PASSWORD_PROMPT, _REPEAT_PROMPT]

    def test_admin_cli_create_superadmin_opens_the_pool_from_pg_env(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """init_pool gets the DSN built from PG_* (password URL-encoded)."""
        _run(cli)

        deps.init_pool.assert_awaited_once()
        assert deps.init_pool.await_args is not None
        assert deps.init_pool.await_args.args[0] == _EXPECTED_DSN

    def test_admin_cli_create_superadmin_runs_migrations_on_the_pool(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """Pending migrations are applied to the opened pool (works on a fresh database)."""
        _run(cli)

        deps.run_migrations.assert_awaited_once_with(deps.pool)

    def test_admin_cli_create_superadmin_checks_duplicate_on_the_pool(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """email_exists(pool, email) is asked with the email as given."""
        _run(cli)

        deps.email_exists.assert_awaited_once_with(deps.pool, _EMAIL)

    def test_admin_cli_create_superadmin_steps_run_in_order(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """Pool, migrations, duplicate check, prompts, hash, transaction + create, close."""
        _run(cli)

        assert deps.events == [
            "init_pool",
            "run_migrations",
            "email_exists",
            "getpass",
            "getpass",
            "hash_password",
            "transaction.begin",
            "create_super_admin",
            "transaction.commit",
            "close_pool",
        ]

    def test_admin_cli_create_superadmin_closes_the_pool(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """close_pool is awaited once at the end."""
        _run(cli)

        deps.close_pool.assert_awaited_once()

    def test_admin_cli_create_superadmin_stored_hash_verifies(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """With real Argon2: the stored hash verifies the typed password and nothing else."""
        deps.hash_password.side_effect = _REAL_HASH_PASSWORD

        assert _run(cli) == 0

        assert deps.create_super_admin.await_args is not None
        stored = deps.create_super_admin.await_args.kwargs["password_hash"]
        assert _PASSWORD not in stored
        assert passwords.verify_password(_PASSWORD, stored)
        assert not passwords.verify_password(_OTHER_PASSWORD, stored)


_VALID_INPUTS: list[Any] = [
    pytest.param("a@b", _NAME_ARG, _NAME, id="email-3-chars"),
    pytest.param("a" * 243 + "@example.ch", _NAME_ARG, _NAME, id="email-254-chars"),
    pytest.param(_EMAIL, "X", "X", id="name-1-char"),
    pytest.param(_EMAIL, "n" * 120, "n" * 120, id="name-120-chars"),
    pytest.param(_EMAIL, "  " + "n" * 120 + "  ", "n" * 120, id="name-120-after-trim"),
    pytest.param(_EMAIL, "é" * 120, "é" * 120, id="name-120-non-ascii-chars"),
    pytest.param(_EMAIL, "Zoë Müller-Łukasiewicz", "Zoë Müller-Łukasiewicz", id="name-unicode"),
]


class TestCreateSuperAdminValidBoundaries:
    """Inputs at the edges of the rules are accepted (lengths count characters, not bytes)."""

    @pytest.mark.parametrize(("email", "name_arg", "stored_name"), _VALID_INPUTS)
    def test_admin_cli_create_superadmin_boundary_input_is_accepted(
        self, cli: ModuleType, deps: _Deps, email: str, name_arg: str, stored_name: str
    ) -> None:
        """The account is created with the email as given and the trimmed name."""
        assert _run(cli, email=email, name=name_arg) == 0

        deps.create_super_admin.assert_awaited_once_with(
            deps.pool.conn, email=email, name=stored_name, password_hash=_FAKE_HASH
        )


# ---------------------------------------------------------------------------
# 2. Duplicate email
# ---------------------------------------------------------------------------


class TestCreateSuperAdminDuplicateEmail:
    """A taken email (case-insensitively, via email_exists) is refused before any prompt."""

    def test_admin_cli_create_superadmin_duplicate_returns_one(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """email_exists is True → exit code 1."""
        deps.email_exists.return_value = True

        assert _run(cli) == 1

    def test_admin_cli_create_superadmin_duplicate_says_already_exists(
        self, cli: ModuleType, deps: _Deps, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """stderr says a user with this email 'already exists', without echoing the email."""
        deps.email_exists.return_value = True

        _run(cli)

        err = capsys.readouterr().err
        assert "already exists" in err.lower()
        assert _EMAIL.lower() not in err.lower()

    def test_admin_cli_create_superadmin_duplicate_never_prompts(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """The duplicate check runs before the password prompt: getpass is never called."""
        deps.email_exists.return_value = True

        _run(cli)

        assert deps.prompts.prompts == []
        deps.hash_password.assert_not_called()

    def test_admin_cli_create_superadmin_duplicate_creates_nothing(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """No account is created for a taken email."""
        deps.email_exists.return_value = True

        _run(cli)

        deps.create_super_admin.assert_not_awaited()

    def test_admin_cli_create_superadmin_duplicate_closes_the_pool(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """The pool is closed on the refusal path too."""
        deps.email_exists.return_value = True

        _run(cli)

        deps.close_pool.assert_awaited_once()

    def test_admin_cli_create_superadmin_concurrent_duplicate_returns_one(
        self, cli: ModuleType, deps: _Deps, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A unique violation on insert (DuplicateEmailError) → the same refusal, exit 1."""
        deps.create_super_admin.side_effect = _duplicate_error()

        assert _run(cli) == 1

        captured = capsys.readouterr()
        assert "already exists" in captured.err.lower()
        assert "super admin created" not in captured.out.lower()

    def test_admin_cli_create_superadmin_concurrent_duplicate_rolls_back_and_closes(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """The error leaves the transaction block (rollback), and the pool is closed."""
        deps.create_super_admin.side_effect = _duplicate_error()

        _run(cli)

        assert deps.pool.conn.commits == 0
        assert deps.pool.conn.rollbacks == [type(_duplicate_error())]
        deps.close_pool.assert_awaited_once()


# ---------------------------------------------------------------------------
# 3. Password prompt: policy, confirmation, attempts, cancel
# ---------------------------------------------------------------------------

_WEAK_PASSWORDS: list[Any] = [
    pytest.param(_TOO_SHORT, "too_short", id="too-short"),
    pytest.param(_COMMON, "common", id="common"),
    pytest.param(_EMAIL_AS_PASSWORD, "equals_email", id="equals-email"),
]


class TestCreateSuperAdminPasswordPolicy:
    """A password that breaks the #149 policy is refused and the prompt starts over."""

    @pytest.mark.parametrize(("weak", "reason"), _WEAK_PASSWORDS)
    def test_admin_cli_create_superadmin_weak_then_valid_creates(
        self, cli: ModuleType, deps: _Deps, weak: str, reason: str
    ) -> None:
        """Attempt 1 is weak, attempt 2 valid → exit 0, hashed and created with the valid one."""
        deps.prompts.script(weak, _PASSWORD, _PASSWORD)

        assert _run(cli) == 0

        deps.hash_password.assert_called_once_with(_PASSWORD)
        deps.create_super_admin.assert_awaited_once()

    @pytest.mark.parametrize(("weak", "reason"), _WEAK_PASSWORDS)
    def test_admin_cli_create_superadmin_weak_password_names_the_broken_rule(
        self,
        cli: ModuleType,
        deps: _Deps,
        capsys: pytest.CaptureFixture[str],
        weak: str,
        reason: str,
    ) -> None:
        """stderr carries the PasswordPolicyError message of the broken rule."""
        deps.prompts.script(weak, _PASSWORD, _PASSWORD)

        _run(cli)

        assert str(PasswordPolicyError(reason)) in capsys.readouterr().err  # type: ignore[arg-type]

    @pytest.mark.parametrize(("weak", "reason"), _WEAK_PASSWORDS)
    def test_admin_cli_create_superadmin_weak_password_skips_the_repeat_prompt(
        self, cli: ModuleType, deps: _Deps, weak: str, reason: str
    ) -> None:
        """A refused password isn't confirmed: the next prompt asks for a new password."""
        deps.prompts.script(weak, _PASSWORD, _PASSWORD)

        _run(cli)

        assert deps.prompts.prompts == [_PASSWORD_PROMPT, _PASSWORD_PROMPT, _REPEAT_PROMPT]

    @pytest.mark.parametrize(("weak", "reason"), _WEAK_PASSWORDS)
    def test_admin_cli_create_superadmin_weak_password_is_never_printed(
        self,
        cli: ModuleType,
        deps: _Deps,
        capsys: pytest.CaptureFixture[str],
        weak: str,
        reason: str,
    ) -> None:
        """The refused password appears neither on stdout nor on stderr."""
        deps.prompts.script(weak, _PASSWORD, _PASSWORD)

        _run(cli)

        captured = capsys.readouterr()
        assert weak not in captured.out
        assert weak not in captured.err


class TestCreateSuperAdminPasswordConfirmation:
    """The password is typed twice; a mismatch starts the attempt over."""

    def test_admin_cli_create_superadmin_mismatch_then_match_creates(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """Attempt 1 mismatches, attempt 2 matches → exit 0 with the matching password."""
        deps.prompts.script(_PASSWORD, _OTHER_PASSWORD, _PASSWORD, _PASSWORD)

        assert _run(cli) == 0

        deps.hash_password.assert_called_once_with(_PASSWORD)
        deps.create_super_admin.assert_awaited_once()

    def test_admin_cli_create_superadmin_mismatch_says_dont_match(
        self, cli: ModuleType, deps: _Deps, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """stderr says the passwords "don't match"."""
        deps.prompts.script(_PASSWORD, _OTHER_PASSWORD, _PASSWORD, _PASSWORD)

        _run(cli)

        assert "don't match" in capsys.readouterr().err.lower()

    def test_admin_cli_create_superadmin_mismatch_prompts_the_full_attempt_again(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """After a mismatch, the next attempt asks for the password and its repeat again."""
        deps.prompts.script(_PASSWORD, _OTHER_PASSWORD, _PASSWORD, _PASSWORD)

        _run(cli)

        assert deps.prompts.prompts == [
            _PASSWORD_PROMPT,
            _REPEAT_PROMPT,
            _PASSWORD_PROMPT,
            _REPEAT_PROMPT,
        ]


_THREE_FAILURES: list[Any] = [
    pytest.param(
        [_TOO_SHORT, _COMMON, _EMAIL_AS_PASSWORD, _PASSWORD, _PASSWORD], 3, id="three-weak"
    ),
    pytest.param(
        [_PASSWORD, _OTHER_PASSWORD] * 3 + [_PASSWORD, _PASSWORD], 6, id="three-mismatches"
    ),
    pytest.param(
        [_TOO_SHORT, _PASSWORD, _OTHER_PASSWORD, _COMMON, _PASSWORD, _PASSWORD],
        4,
        id="weak-mismatch-weak",
    ),
]


class TestCreateSuperAdminAttemptLimit:
    """Three failed attempts end the command with exit 1; a fourth is never offered."""

    @pytest.mark.parametrize(("answers", "prompts_used"), _THREE_FAILURES)
    def test_admin_cli_create_superadmin_three_failures_return_one(
        self, cli: ModuleType, deps: _Deps, answers: list[str], prompts_used: int
    ) -> None:
        """Exit code 1 after the third failed attempt."""
        deps.prompts.script(*answers)

        assert _run(cli) == 1

    @pytest.mark.parametrize(("answers", "prompts_used"), _THREE_FAILURES)
    def test_admin_cli_create_superadmin_three_failures_stop_prompting(
        self, cli: ModuleType, deps: _Deps, answers: list[str], prompts_used: int
    ) -> None:
        """No fourth attempt: the valid answers scripted after the third failure stay unused."""
        deps.prompts.script(*answers)

        _run(cli)

        assert len(deps.prompts.prompts) == prompts_used

    @pytest.mark.parametrize(("answers", "prompts_used"), _THREE_FAILURES)
    def test_admin_cli_create_superadmin_three_failures_create_nothing(
        self, cli: ModuleType, deps: _Deps, answers: list[str], prompts_used: int
    ) -> None:
        """Nothing is hashed or created, and the pool is closed."""
        deps.prompts.script(*answers)

        _run(cli)

        deps.hash_password.assert_not_called()
        deps.create_super_admin.assert_not_awaited()
        deps.close_pool.assert_awaited_once()

    @pytest.mark.parametrize(("answers", "prompts_used"), _THREE_FAILURES)
    def test_admin_cli_create_superadmin_three_failures_report_on_stderr(
        self,
        cli: ModuleType,
        deps: _Deps,
        capsys: pytest.CaptureFixture[str],
        answers: list[str],
        prompts_used: int,
    ) -> None:
        """The operator is told why on stderr; stdout never claims success."""
        deps.prompts.script(*answers)

        _run(cli)

        captured = capsys.readouterr()
        assert captured.err.strip()
        assert "super admin created" not in captured.out.lower()


_CANCELS: list[Any] = [
    pytest.param([KeyboardInterrupt()], id="ctrl-c-at-password"),
    pytest.param([EOFError()], id="eof-at-password"),
    pytest.param([_PASSWORD, KeyboardInterrupt()], id="ctrl-c-at-repeat"),
    pytest.param([_PASSWORD, EOFError()], id="eof-at-repeat"),
]


class TestCreateSuperAdminCancel:
    """Ctrl-C or EOF at a prompt cancels cleanly: exit 1, nothing created, pool closed."""

    @pytest.mark.parametrize("answers", _CANCELS)
    def test_admin_cli_create_superadmin_cancel_returns_one(
        self, cli: ModuleType, deps: _Deps, answers: list[str | BaseException]
    ) -> None:
        """KeyboardInterrupt/EOFError from getpass → exit code 1 (no traceback)."""
        deps.prompts.script(*answers)

        assert _run(cli) == 1

    @pytest.mark.parametrize("answers", _CANCELS)
    def test_admin_cli_create_superadmin_cancel_says_cancelled(
        self,
        cli: ModuleType,
        deps: _Deps,
        capsys: pytest.CaptureFixture[str],
        answers: list[str | BaseException],
    ) -> None:
        """stderr says 'Cancelled'."""
        deps.prompts.script(*answers)

        _run(cli)

        assert "cancelled" in capsys.readouterr().err.lower()

    @pytest.mark.parametrize("answers", _CANCELS)
    def test_admin_cli_create_superadmin_cancel_creates_nothing_and_closes(
        self, cli: ModuleType, deps: _Deps, answers: list[str | BaseException]
    ) -> None:
        """Nothing is hashed or created; the pool is still closed."""
        deps.prompts.script(*answers)

        _run(cli)

        deps.hash_password.assert_not_called()
        deps.create_super_admin.assert_not_awaited()
        deps.close_pool.assert_awaited_once()


class TestCreateSuperAdminInterruptOutsidePrompt:
    """Ctrl-C outside a prompt (connecting, hashing) also ends as 'Cancelled', exit 1."""

    def test_admin_cli_create_superadmin_interrupt_while_connecting_cancels(
        self, cli: ModuleType, deps: _Deps, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Ctrl-C while the pool opens → exit 1, 'Cancelled', no prompt."""
        deps.init_pool.side_effect = KeyboardInterrupt()

        assert _run(cli) == 1
        assert "cancelled" in capsys.readouterr().err.lower()
        assert "getpass" not in deps.events

    def test_admin_cli_create_superadmin_interrupt_while_hashing_creates_nothing(
        self, cli: ModuleType, deps: _Deps, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Ctrl-C while hashing → exit 1, 'Cancelled', nothing created, pool closed."""
        deps.hash_password.side_effect = KeyboardInterrupt()

        assert _run(cli) == 1
        assert "cancelled" in capsys.readouterr().err.lower()
        deps.create_super_admin.assert_not_awaited()
        deps.close_pool.assert_awaited_once()


# ---------------------------------------------------------------------------
# 4. Preconditions: interactive terminal and PG_PASSWORD
# ---------------------------------------------------------------------------


class TestCreateSuperAdminRequiresTty:
    """The password can't be piped in: without an interactive stdin the command refuses."""

    def test_admin_cli_create_superadmin_without_tty_returns_one(
        self, cli: ModuleType, deps: _Deps, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """stdin is not a TTY → exit code 1."""
        monkeypatch.setattr(sys, "stdin", _Stdin(tty=False))

        assert _run(cli) == 1

    def test_admin_cli_create_superadmin_without_tty_explains(
        self,
        cli: ModuleType,
        deps: _Deps,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """stderr says an 'interactive terminal' is required."""
        monkeypatch.setattr(sys, "stdin", _Stdin(tty=False))

        _run(cli)

        assert "interactive terminal" in capsys.readouterr().err.lower()

    def test_admin_cli_create_superadmin_without_tty_touches_nothing(
        self, cli: ModuleType, deps: _Deps, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No prompt, no pool, no database access."""
        monkeypatch.setattr(sys, "stdin", _Stdin(tty=False))

        _run(cli)

        assert deps.prompts.prompts == []
        deps.init_pool.assert_not_awaited()
        deps.email_exists.assert_not_awaited()
        deps.create_super_admin.assert_not_awaited()

    def test_admin_cli_create_superadmin_tty_check_precedes_pg_check(
        self,
        cli: ModuleType,
        deps: _Deps,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Without a TTY and without PG_PASSWORD, the terminal is what gets reported."""
        monkeypatch.setattr(sys, "stdin", _Stdin(tty=False))
        monkeypatch.delenv("PG_PASSWORD")

        assert _run(cli) == 1

        err = capsys.readouterr().err
        assert "interactive terminal" in err.lower()
        assert "PG_PASSWORD" not in err


class TestCreateSuperAdminRequiresPgPassword:
    """Without PG_PASSWORD there is no DSN: refuse before opening a pool."""

    @pytest.mark.parametrize("unset", [True, False], ids=["unset", "empty"])
    def test_admin_cli_create_superadmin_without_pg_password_returns_one(
        self,
        cli: ModuleType,
        deps: _Deps,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        unset: bool,
    ) -> None:
        """PG_PASSWORD unset or empty → exit 1, stderr names PG_PASSWORD, no pool, no prompt."""
        if unset:
            monkeypatch.delenv("PG_PASSWORD")
        else:
            monkeypatch.setenv("PG_PASSWORD", "")

        assert _run(cli) == 1

        assert "PG_PASSWORD" in capsys.readouterr().err
        deps.init_pool.assert_not_awaited()
        assert deps.prompts.prompts == []


# ---------------------------------------------------------------------------
# 5. Input validation (before any terminal, database or prompt work)
# ---------------------------------------------------------------------------

_NO_BREAK_SPACE = chr(0xA0)

_INVALID_EMAILS: list[Any] = [
    pytest.param("", id="empty"),
    pytest.param("a@", id="too-short-2-chars"),
    pytest.param("a" * 244 + "@example.ch", id="too-long-255-chars"),
    pytest.param("ops.admin.example.ch", id="no-at-sign"),
    pytest.param("@example.ch", id="empty-local-part"),
    pytest.param("ops admin@example.ch", id="inner-space"),
    pytest.param("ops.admin@exa\tmple.ch", id="inner-tab"),
    pytest.param(" ops.admin@example.ch", id="leading-space"),
    pytest.param("ops.admin@example.ch\n", id="trailing-newline"),
    pytest.param("ops" + _NO_BREAK_SPACE + "admin@example.ch", id="no-break-space"),
]

# Distinctive enough that a generic hint (e.g. "like you@example.ch") can't contain them.
_ECHO_CHECKED_EMAILS: list[Any] = [
    pytest.param("a" * 244 + "@example.ch", id="too-long-255-chars"),
    pytest.param("ops.admin.example.ch", id="no-at-sign"),
    pytest.param("ops admin@example.ch", id="inner-space"),
    pytest.param("ops.admin@exa\tmple.ch", id="inner-tab"),
    pytest.param("ops" + _NO_BREAK_SPACE + "admin@example.ch", id="no-break-space"),
]

_INVALID_NAMES: list[Any] = [
    pytest.param("", id="empty"),
    pytest.param("   ", id="whitespace-only"),
    pytest.param("n" * 121, id="too-long-121-chars"),
    pytest.param("  " + "n" * 121 + "  ", id="too-long-after-trim"),
    pytest.param("Ada\nLovelace", id="newline"),
    pytest.param("Ada\x00Lovelace", id="nul"),
    pytest.param("Ada\x1b[31mLovelace", id="ansi-escape"),
    pytest.param("Ada\tLovelace", id="tab"),
    pytest.param("Ada" + chr(0x7F) + "Lovelace", id="del"),
    pytest.param("Ada" + chr(0x9B) + "31mLovelace", id="c1-csi"),
]

# Characters an error message must never carry (they could only come from the input).
_CONTROL_CHARACTERS: tuple[str, ...] = ("\x00", "\x1b", chr(0x7F), chr(0x9B))


class TestCreateSuperAdminInvalidEmail:
    """The email follows the users table rules; a bad one is refused before anything else."""

    @pytest.mark.parametrize("email", _INVALID_EMAILS)
    def test_admin_cli_create_superadmin_invalid_email_returns_one(
        self, cli: ModuleType, deps: _Deps, email: str
    ) -> None:
        """Exit code 1."""
        assert _run(cli, email=email) == 1

    @pytest.mark.parametrize("email", _INVALID_EMAILS)
    def test_admin_cli_create_superadmin_invalid_email_touches_nothing(
        self, cli: ModuleType, deps: _Deps, capsys: pytest.CaptureFixture[str], email: str
    ) -> None:
        """An explanation on stderr; no pool, no migrations, no prompt, nothing created."""
        _run(cli, email=email)

        assert capsys.readouterr().err.strip()
        deps.init_pool.assert_not_awaited()
        deps.run_migrations.assert_not_awaited()
        assert deps.prompts.prompts == []
        deps.create_super_admin.assert_not_awaited()

    @pytest.mark.parametrize("email", _ECHO_CHECKED_EMAILS)
    def test_admin_cli_create_superadmin_invalid_email_is_not_echoed(
        self, cli: ModuleType, deps: _Deps, capsys: pytest.CaptureFixture[str], email: str
    ) -> None:
        """The error message never repeats the rejected email."""
        _run(cli, email=email)

        assert email not in capsys.readouterr().err

    def test_admin_cli_create_superadmin_validation_precedes_tty_check(
        self,
        cli: ModuleType,
        deps: _Deps,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """An invalid email is reported even without a TTY: validation runs first."""
        monkeypatch.setattr(sys, "stdin", _Stdin(tty=False))

        assert _run(cli, email="ops.admin.example.ch") == 1

        assert "interactive terminal" not in capsys.readouterr().err.lower()


class TestCreateSuperAdminInvalidName:
    """The name is 1 to 120 characters after trimming, with no control characters."""

    @pytest.mark.parametrize("name", _INVALID_NAMES)
    def test_admin_cli_create_superadmin_invalid_name_returns_one(
        self, cli: ModuleType, deps: _Deps, name: str
    ) -> None:
        """Exit code 1."""
        assert _run(cli, name=name) == 1

    @pytest.mark.parametrize("name", _INVALID_NAMES)
    def test_admin_cli_create_superadmin_invalid_name_touches_nothing(
        self, cli: ModuleType, deps: _Deps, capsys: pytest.CaptureFixture[str], name: str
    ) -> None:
        """An explanation on stderr; no pool, no migrations, no prompt, nothing created."""
        _run(cli, name=name)

        assert capsys.readouterr().err.strip()
        deps.init_pool.assert_not_awaited()
        deps.run_migrations.assert_not_awaited()
        assert deps.prompts.prompts == []
        deps.create_super_admin.assert_not_awaited()

    @pytest.mark.parametrize("name", _INVALID_NAMES)
    def test_admin_cli_create_superadmin_invalid_name_is_not_echoed(
        self, cli: ModuleType, deps: _Deps, capsys: pytest.CaptureFixture[str], name: str
    ) -> None:
        """stderr repeats neither the name nor its words, and carries no control characters."""
        _run(cli, name=name)

        err = capsys.readouterr().err
        for word in re.findall(r"[A-Za-z]{5,}", name):
            assert word not in err
        assert [char for char in _CONTROL_CHARACTERS if char in err] == []


# ---------------------------------------------------------------------------
# 6. Database and audit failures
# ---------------------------------------------------------------------------


def _db_error_with_content() -> asyncpg.PostgresError:
    """A driver error whose text repeats the row (as PostgreSQL's DETAIL lines do)."""
    return asyncpg.PostgresError(f"failing row contains ({_EMAIL}, {_NAME}, {_FAKE_HASH})")


_CREATE_FAILURES: list[Any] = [
    pytest.param(AuditRecordError(), id="audit-write-failed"),
    pytest.param(_db_error_with_content(), id="postgres-error"),
]


class TestCreateSuperAdminCreateFailures:
    """A failed insert or audit write creates no account and reports a generic error."""

    @pytest.mark.parametrize("error", _CREATE_FAILURES)
    def test_admin_cli_create_superadmin_create_failure_returns_one(
        self,
        cli: ModuleType,
        deps: _Deps,
        capsys: pytest.CaptureFixture[str],
        error: Exception,
    ) -> None:
        """Exit code 1, an error on stderr, no success message."""
        deps.create_super_admin.side_effect = error

        assert _run(cli) == 1

        captured = capsys.readouterr()
        assert captured.err.strip()
        assert "super admin created" not in captured.out.lower()

    @pytest.mark.parametrize("error", _CREATE_FAILURES)
    def test_admin_cli_create_superadmin_create_failure_rolls_back(
        self, cli: ModuleType, deps: _Deps, error: Exception
    ) -> None:
        """The error leaves the transaction block, so the insert rolls back with the audit."""
        deps.create_super_admin.side_effect = error

        _run(cli)

        assert deps.pool.conn.commits == 0
        assert deps.pool.conn.rollbacks == [type(error)]
        deps.close_pool.assert_awaited_once()

    def test_admin_cli_create_superadmin_db_error_text_is_not_echoed(
        self, cli: ModuleType, deps: _Deps, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The driver's message (email, name, hash) never reaches stdout or stderr."""
        deps.create_super_admin.side_effect = _db_error_with_content()

        _run(cli)

        captured = capsys.readouterr()
        output = (captured.out + captured.err).lower()
        assert _EMAIL.lower() not in output
        assert _NAME.lower() not in output
        assert _FAKE_HASH.lower() not in output
        assert _PASSWORD.lower() not in output


class TestCreateSuperAdminSetupFailures:
    """Failures before the prompt end the command with exit 1, never a traceback."""

    def test_admin_cli_create_superadmin_unreachable_database_returns_one(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """init_pool fails (connection refused) → exit 1, no prompt, nothing created."""
        deps.init_pool.side_effect = ConnectionRefusedError("connection refused")

        assert _run(cli) == 1

        assert deps.prompts.prompts == []
        deps.create_super_admin.assert_not_awaited()

    def test_admin_cli_create_superadmin_migration_failure_returns_one_and_closes(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """run_migrations fails → exit 1, no duplicate check, no prompt, pool closed."""
        deps.run_migrations.side_effect = asyncpg.PostgresError("migration failed")

        assert _run(cli) == 1

        deps.email_exists.assert_not_awaited()
        assert deps.prompts.prompts == []
        deps.close_pool.assert_awaited_once()

    def test_admin_cli_create_superadmin_duplicate_check_failure_returns_one_and_closes(
        self, cli: ModuleType, deps: _Deps
    ) -> None:
        """email_exists fails → exit 1, no prompt, nothing created, pool closed."""
        deps.email_exists.side_effect = _db_error_with_content()

        assert _run(cli) == 1

        assert deps.prompts.prompts == []
        deps.create_super_admin.assert_not_awaited()
        deps.close_pool.assert_awaited_once()


# ---------------------------------------------------------------------------
# 7. No secrets or content in output and logs, on every path
# ---------------------------------------------------------------------------


def _scenario_success(deps: _Deps) -> None:
    """Defaults: created."""


def _scenario_weak_then_valid(deps: _Deps) -> None:
    deps.prompts.script(_TOO_SHORT, _PASSWORD, _PASSWORD)


def _scenario_mismatch_then_valid(deps: _Deps) -> None:
    deps.prompts.script(_PASSWORD, _OTHER_PASSWORD, _PASSWORD, _PASSWORD)


def _scenario_three_failures(deps: _Deps) -> None:
    deps.prompts.script(_TOO_SHORT, _PASSWORD, _OTHER_PASSWORD, _EMAIL_AS_PASSWORD)


def _scenario_cancelled(deps: _Deps) -> None:
    deps.prompts.script(_PASSWORD, KeyboardInterrupt())


def _scenario_duplicate_check(deps: _Deps) -> None:
    deps.email_exists.return_value = True


def _scenario_duplicate_on_insert(deps: _Deps) -> None:
    deps.create_super_admin.side_effect = _duplicate_error()


def _scenario_audit_failure(deps: _Deps) -> None:
    deps.create_super_admin.side_effect = AuditRecordError()


def _scenario_db_failure(deps: _Deps) -> None:
    deps.create_super_admin.side_effect = _db_error_with_content()


def _scenario_duplicate_check_failure(deps: _Deps) -> None:
    deps.email_exists.side_effect = _db_error_with_content()


_ERROR_SCENARIOS: list[Any] = [
    pytest.param(_scenario_three_failures, id="three-failures"),
    pytest.param(_scenario_cancelled, id="cancelled"),
    pytest.param(_scenario_duplicate_check, id="duplicate-check"),
    pytest.param(_scenario_duplicate_on_insert, id="duplicate-on-insert"),
    pytest.param(_scenario_audit_failure, id="audit-failure"),
    pytest.param(_scenario_db_failure, id="db-failure"),
    pytest.param(_scenario_duplicate_check_failure, id="duplicate-check-failure"),
]
_ALL_SCENARIOS: list[Any] = [
    pytest.param(_scenario_success, id="success"),
    pytest.param(_scenario_weak_then_valid, id="weak-then-valid"),
    pytest.param(_scenario_mismatch_then_valid, id="mismatch-then-valid"),
    *_ERROR_SCENARIOS,
]


class TestCreateSuperAdminNoLeaks:
    """The password never leaves the prompt; logs never carry the password, email or name."""

    @pytest.mark.parametrize("scenario", _ALL_SCENARIOS)
    def test_admin_cli_create_superadmin_password_never_printed(
        self,
        cli: ModuleType,
        deps: _Deps,
        capsys: pytest.CaptureFixture[str],
        scenario: Callable[[_Deps], None],
    ) -> None:
        """No typed password (valid, mismatched or weak) and no hash on stdout or stderr."""
        scenario(deps)

        _run(cli)

        captured = capsys.readouterr()
        for secret in (*_TYPED_PASSWORDS, _FAKE_HASH):
            assert secret not in captured.out, secret
            assert secret not in captured.err, secret

    @pytest.mark.parametrize("scenario", _ALL_SCENARIOS)
    def test_admin_cli_create_superadmin_logs_carry_no_password_or_hash(
        self,
        cli: ModuleType,
        deps: _Deps,
        caplog: pytest.LogCaptureFixture,
        scenario: Callable[[_Deps], None],
    ) -> None:
        """At DEBUG, no log record carries a typed password or the hash."""
        caplog.set_level(logging.DEBUG)
        scenario(deps)

        _run(cli)

        logged = _log_text(caplog)
        for secret in (*_TYPED_PASSWORDS, _FAKE_HASH):
            assert secret not in logged, secret

    @pytest.mark.parametrize("scenario", _ALL_SCENARIOS)
    def test_admin_cli_create_superadmin_logs_carry_no_email_or_name(
        self,
        cli: ModuleType,
        deps: _Deps,
        caplog: pytest.LogCaptureFixture,
        scenario: Callable[[_Deps], None],
    ) -> None:
        """At DEBUG, no log record carries the email (any case) or the name."""
        caplog.set_level(logging.DEBUG)
        scenario(deps)

        _run(cli)

        logged = _log_text(caplog).lower()
        assert _EMAIL.lower() not in logged
        assert _NAME.lower() not in logged

    @pytest.mark.parametrize("scenario", _ERROR_SCENARIOS)
    def test_admin_cli_create_superadmin_errors_never_echo_email_or_name(
        self,
        cli: ModuleType,
        deps: _Deps,
        capsys: pytest.CaptureFixture[str],
        scenario: Callable[[_Deps], None],
    ) -> None:
        """On every refusal or failure (exit 1), stderr repeats neither the email nor the name."""
        scenario(deps)

        assert _run(cli) == 1

        err = capsys.readouterr().err.lower()
        assert _EMAIL.lower() not in err
        assert _NAME.lower() not in err


# ---------------------------------------------------------------------------
# 8. End to end through the real accounts functions and audit record()
# ---------------------------------------------------------------------------


def _users_inserts(deps: _Deps) -> list[_Call]:
    """Every INSERT INTO users the fake pool saw."""
    return [c for c in deps.pool.calls if re.match(r"insert\s+into\s+users\b", _norm(c.sql))]


def _audit_inserts(deps: _Deps) -> list[_Call]:
    """Every INSERT INTO audit_events the fake pool saw."""
    return [c for c in deps.pool.calls if re.match(r"insert\s+into\s+audit_events\b", _norm(c.sql))]


class TestCreateSuperAdminEndToEnd:
    """The real email_exists/create_super_admin/record() against the recording fake pool."""

    @pytest.fixture()
    def real_deps(self, deps: _Deps) -> _Deps:
        """Route the accounts mocks to the real functions (the audit record() stays real)."""
        deps.email_exists.side_effect = deps.real_email_exists
        deps.create_super_admin.side_effect = deps.real_create_super_admin
        return deps

    def test_admin_cli_create_superadmin_e2e_inserts_the_super_admin_in_a_transaction(
        self, cli: ModuleType, real_deps: _Deps
    ) -> None:
        """One users INSERT on the pooled connection, in its transaction, with the three binds."""
        assert _run(cli) == 0

        inserts = _users_inserts(real_deps)
        assert len(inserts) == 1
        assert inserts[0].method == "conn.fetchval"
        assert inserts[0].in_transaction is True
        assert inserts[0].args == (_EMAIL, _NAME, _FAKE_HASH)

    def test_admin_cli_create_superadmin_e2e_audits_in_the_same_transaction(
        self, cli: ModuleType, real_deps: _Deps
    ) -> None:
        """One audit_events INSERT on the same connection, in the transaction, as user.activate."""
        _run(cli)

        audits = _audit_inserts(real_deps)
        assert len(audits) == 1
        assert audits[0].method.startswith("conn.")
        assert audits[0].in_transaction is True
        assert "user.activate" in audits[0].args
        assert "operator" in audits[0].args
        assert real_deps.pool.conn.commits == 1

    def test_admin_cli_create_superadmin_e2e_duplicate_check_binds_the_email(
        self, cli: ModuleType, real_deps: _Deps
    ) -> None:
        """The duplicate check is one parameterized pool query with the email as its bind."""
        _run(cli)

        checks = [c for c in real_deps.pool.calls if c.method.startswith("pool.")]
        assert len(checks) == 1
        assert checks[0].args == (_EMAIL,)
        assert _EMAIL.lower() not in checks[0].sql.lower()

    def test_admin_cli_create_superadmin_e2e_existing_email_writes_nothing(
        self, cli: ModuleType, real_deps: _Deps
    ) -> None:
        """The pool says the email exists → exit 1, no prompt, no INSERT of any kind."""
        real_deps.pool.existing = True

        assert _run(cli) == 1

        assert real_deps.prompts.prompts == []
        assert _users_inserts(real_deps) == []
        assert _audit_inserts(real_deps) == []


# ---------------------------------------------------------------------------
# 9. Command line: usage errors and the module entry point
# ---------------------------------------------------------------------------

_USAGE_ERRORS: list[Any] = [
    pytest.param([], id="no-subcommand"),
    pytest.param(["create-superadmin"], id="no-options"),
    pytest.param(["create-superadmin", "--email", _EMAIL], id="missing-name"),
    pytest.param(["create-superadmin", "--name", _NAME], id="missing-email"),
    pytest.param(["delete-everything"], id="unknown-subcommand"),
    pytest.param(
        ["create-superadmin", "--email", _EMAIL, "--name", _NAME, "--password", _PASSWORD],
        id="password-is-not-an-option",
    ),
]


class TestAdminCliUsage:
    """argparse usage errors exit with code 2 before anything runs."""

    @pytest.mark.parametrize("argv", _USAGE_ERRORS)
    def test_admin_cli_usage_error_exits_two(
        self, cli: ModuleType, deps: _Deps, argv: list[str]
    ) -> None:
        """SystemExit(2), no pool, no prompt. A password can't be passed in argv."""
        with pytest.raises(SystemExit) as exc_info:
            cli.main(argv)

        assert exc_info.value.code == 2
        deps.init_pool.assert_not_awaited()
        assert deps.prompts.prompts == []

    def test_admin_cli_module_has_a_docstring(self, cli: ModuleType) -> None:
        """The module documents its purpose (all modules have docstrings)."""
        assert (cli.__doc__ or "").strip()


def _run_module(*args: str) -> subprocess.CompletedProcess[str]:
    """Run ``python -m admino.admin_cli <args>`` without a TTY and without any PG_* variable."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("PG_")}
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "admino.admin_cli", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        stdin=subprocess.DEVNULL,
        env=env,
    )


class TestAdminCliEntryPoint:
    """``python -m admino.admin_cli`` is runnable (what ``make create-superadmin`` execs)."""

    def test_admin_cli_module_without_arguments_exits_two(self) -> None:
        """No subcommand → usage error, exit status 2."""
        result = _run_module()

        assert result.returncode == 2, result.stderr

    def test_admin_cli_module_refuses_piped_stdin(self) -> None:
        """stdin from /dev/null (no TTY) → exit 1 with 'interactive terminal' on stderr."""
        result = _run_module("create-superadmin", "--email", _EMAIL, "--name", _NAME)

        assert result.returncode == 1, result.stderr
        assert "interactive terminal" in result.stderr.lower()
