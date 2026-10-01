"""Tests for admino.auth.reauthenticate — the password re-authentication of a critical
permission promotion (GH-161).

An Org Admin promoting a tier-2 denial (gmail.send, ...) confirms their own
password first. The issue's Decision 3: a wrong password counts in the login
throttle (account and IP) exactly like a failed login, and a locked account or
IP can't re-authenticate.

What these tests pin down (the GH-161 contract):
- ``reauthenticate(pool, *, principal, password, ip) -> bool`` is a coroutine
  with keyword-only principal, password and ip.
- It reads the principal's OWN users row by id (the email and stored hash come
  from there, never from the caller). A missing or deleted account is False.
- The throttle: ``login_throttle.begin`` with the stored email (account subject
  ``sha256(lower(email))``) and the IP; a locked account or IP is False without
  checking the password; a mismatch keeps the reservation (one failure counted
  on the account and the IP), and the Nth failure locks the account and records
  one ``login.lockout`` row (the member actor, their org); a match resets the
  account counter and releases the IP's own reservation (``succeed``).
- No session is created and no ``login.success`` / ``login.failure`` row is
  written. The password check runs off the event loop (``asyncio.to_thread``).
- Neither the password nor the email reaches a log record.

All database calls go to tests/db_fakes.FakeDb; ``passwords.verify_password`` is
a fast recording stand-in (never a real Argon2 hash) and the throttle's delays
are recorded instead of slept (``login_delays``). ``auth.reauthenticate`` is
looked up per test, so each test fails on its own until it exists.

Security notes:
- Fail closed: an unknown, deleted or locked account never re-authenticates; a
  wrong password costs a counted failure, so re-auth can't be used to guess a
  password faster than the login form.
- No content in logs: the password and the email are never logged.
"""

from __future__ import annotations

import inspect
import logging
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from admino import auth, login_throttle, passwords
from admino.access import Principal
from tests.db_fakes import ORG_ID, FakeDb, account_subject, fake_hash, plain

if TYPE_CHECKING:
    from collections.abc import Callable

# ---------------------------------------------------------------------------
# Constants and helpers
# ---------------------------------------------------------------------------

_PASSWORD = "Reauth-Marker-Quartz-58"
_WRONG = "Reauth-Marker-Quartz-59"
_OTHER_PASSWORD = "Reauth-Marker-Other-60"
_EMAIL = "Reauth.Admin.Marker@Example.test"
_IP = "203.0.113.9"
# The default lockout_after_failures / lockout_minutes (tests/conftest.py's platform row).
_LIMIT = 10
_ACCOUNT_LOCK = {"per_ip": False, "lockout_minutes": 15}


class _Verifier:
    """Fast stand-in for passwords.verify_password; records each check and its thread."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.threads: list[int] = []

    def __call__(self, password: str, encoded: str) -> bool:
        self.calls.append((password, encoded))
        self.threads.append(threading.get_ident())
        return encoded == fake_hash(password)

    @property
    def passwords(self) -> list[str]:
        return [password for password, _ in self.calls]


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database with one active org."""
    fake = FakeDb()
    fake.add_org(ORG_ID)
    return fake


@pytest.fixture(autouse=True)
def verifier(monkeypatch: pytest.MonkeyPatch, login_delays: list[float]) -> _Verifier:
    """Replace Argon2 with the fast recording stand-in; record the throttle's delays."""
    spy = _Verifier()
    monkeypatch.setattr(passwords, "verify_password", spy)
    monkeypatch.setattr(passwords, "needs_rehash", lambda _encoded: False)
    monkeypatch.setattr(passwords, "hash_password", fake_hash)
    return spy


def _reauthenticate() -> Callable[..., Any]:
    """auth.reauthenticate, looked up per test (new in GH-161)."""
    return auth.reauthenticate


def _admin(
    db: FakeDb, *, email: str = _EMAIL, password: str = _PASSWORD, **fields: Any
) -> Principal:
    """An active Org Admin whose password is ``password``, and their Principal."""
    user_id = db.add_account(
        role="org_admin", email=email, password_hash=fake_hash(password), **fields
    )
    return Principal(user_id=user_id, kind="member", org_id=ORG_ID, role="org_admin")


async def _reauth(db: FakeDb, principal: Principal, password: str, ip: str | None = _IP) -> Any:
    return await _reauthenticate()(db.pool, principal=principal, password=password, ip=ip)


def _account_row(db: FakeDb, email: str = _EMAIL) -> dict[str, Any] | None:
    return db.throttle_row("account", account_subject(email))


def _ip_row(db: FakeDb, ip: str = _IP) -> dict[str, Any] | None:
    return db.throttle_row("ip", login_throttle.ip_subject(ip))


def _locked(row: dict[str, Any] | None) -> bool:
    return (
        row is not None
        and row["locked_until"] is not None
        and row["locked_until"] > datetime.now(UTC)
    )


def _login_rows(db: FakeDb) -> list[dict[str, Any]]:
    return db.audit_rows("login.success") + db.audit_rows("login.failure")


# ---------------------------------------------------------------------------
# 1. Surface
# ---------------------------------------------------------------------------


class TestSurface:
    def test_reauth_is_a_coroutine(self) -> None:
        assert inspect.iscoroutinefunction(_reauthenticate())

    def test_reauth_principal_password_and_ip_are_keyword_only(self) -> None:
        parameters = inspect.signature(_reauthenticate()).parameters
        found = {key for key, p in parameters.items() if p.kind is inspect.Parameter.KEYWORD_ONLY}
        assert found == {"principal", "password", "ip"}


# ---------------------------------------------------------------------------
# 2. The password
# ---------------------------------------------------------------------------


class TestPassword:
    """The principal's own stored hash decides; the outcome is a plain bool."""

    async def test_reauth_right_password_is_true(self, db: FakeDb) -> None:
        admin = _admin(db)

        assert await _reauth(db, admin, _PASSWORD) is True

    async def test_reauth_wrong_password_is_false(self, db: FakeDb) -> None:
        admin = _admin(db)

        assert await _reauth(db, admin, _WRONG) is False

    async def test_reauth_checks_the_typed_password_against_the_stored_hash_once(
        self, db: FakeDb, verifier: _Verifier
    ) -> None:
        admin = _admin(db)

        await _reauth(db, admin, _WRONG)

        assert verifier.calls == [(_WRONG, fake_hash(_PASSWORD))]

    async def test_reauth_uses_the_principals_own_account(self, db: FakeDb) -> None:
        """Another user's password never re-authenticates this principal."""
        admin = _admin(db)
        _admin(db, email="other.marker@example.test", password=_OTHER_PASSWORD)

        assert await _reauth(db, admin, _OTHER_PASSWORD) is False

    async def test_reauth_reads_the_users_row_by_the_principals_id(self, db: FakeDb) -> None:
        admin = _admin(db)

        await _reauth(db, admin, _PASSWORD)

        lookups = db.matching(r"\bfrom users\b")
        assert lookups
        assert any(
            isinstance(arg, uuid.UUID) and plain(arg) == admin.user_id
            for call in lookups
            for arg in call.args
        )
        assert all(_EMAIL.lower() not in str(arg).lower() for call in lookups for arg in call.args)

    async def test_reauth_unknown_user_is_false(self, db: FakeDb, verifier: _Verifier) -> None:
        """A principal whose users row is gone: False (after a dummy check, like a login)."""
        ghost = Principal(user_id=uuid.uuid4(), kind="member", org_id=ORG_ID, role="org_admin")

        assert await _reauth(db, ghost, _PASSWORD) is False
        assert len(verifier.calls) == 1

    async def test_reauth_deleted_user_is_false(self, db: FakeDb) -> None:
        admin = _admin(db, deleted_at=datetime.now(UTC) - timedelta(minutes=5))

        assert await _reauth(db, admin, _PASSWORD) is False

    async def test_reauth_password_check_runs_off_the_event_loop(
        self, db: FakeDb, verifier: _Verifier
    ) -> None:
        admin = _admin(db)

        await _reauth(db, admin, _PASSWORD)

        assert verifier.threads
        assert threading.get_ident() not in verifier.threads


# ---------------------------------------------------------------------------
# 3. The login throttle (Decision 3)
# ---------------------------------------------------------------------------


class TestThrottle:
    """A wrong password is a counted failure; a locked account or IP can't re-auth."""

    async def test_reauth_wrong_password_counts_one_failure_on_the_account_and_ip(
        self, db: FakeDb
    ) -> None:
        admin = _admin(db)

        await _reauth(db, admin, _WRONG)

        account = _account_row(db)
        ip = _ip_row(db)
        assert account is not None and account["failures"] == 1
        assert ip is not None and ip["failures"] == 1

    async def test_reauth_account_subject_is_the_stored_email(self, db: FakeDb) -> None:
        """Counted on sha256(lower(stored email)), the same counter as the login form."""
        admin = _admin(db, email="MiXeD.Case.Reauth@Example.test")

        await _reauth(db, admin, _WRONG, ip=None)

        row = _account_row(db, "mixed.case.reauth@example.test")
        assert row is not None and row["failures"] == 1

    async def test_reauth_right_password_resets_the_account_counter(self, db: FakeDb) -> None:
        """login_throttle.succeed: the account count goes to 0, the IP keeps its other
        failures (only this attempt's reservation is released)."""
        admin = _admin(db)
        db.add_throttle("account", account_subject(_EMAIL), failures=4)
        db.add_throttle("ip", login_throttle.ip_subject(_IP), failures=2)

        assert await _reauth(db, admin, _PASSWORD) is True

        account = _account_row(db)
        ip = _ip_row(db)
        assert account is not None and account["failures"] == 0
        assert ip is not None and ip["failures"] == 2

    @pytest.mark.parametrize("password", [_PASSWORD, _WRONG])
    async def test_reauth_locked_account_is_false_without_a_password_check(
        self, db: FakeDb, verifier: _Verifier, password: str
    ) -> None:
        admin = _admin(db)
        db.add_throttle(
            "account",
            account_subject(_EMAIL),
            locked_until=datetime.now(UTC) + timedelta(minutes=10),
        )

        assert await _reauth(db, admin, password) is False
        assert verifier.calls == []

    async def test_reauth_account_at_the_limit_is_false_without_a_password_check(
        self, db: FakeDb, verifier: _Verifier
    ) -> None:
        """N failures in the window and no lock yet: refused like a login."""
        admin = _admin(db)
        db.add_throttle("account", account_subject(_EMAIL), failures=_LIMIT)

        assert await _reauth(db, admin, _PASSWORD) is False
        assert verifier.calls == []

    async def test_reauth_locked_ip_is_false_without_a_password_check(
        self, db: FakeDb, verifier: _Verifier
    ) -> None:
        admin = _admin(db)
        db.add_throttle(
            "ip",
            login_throttle.ip_subject(_IP),
            locked_until=datetime.now(UTC) + timedelta(minutes=10),
        )

        assert await _reauth(db, admin, _PASSWORD) is False
        assert verifier.calls == []

    async def test_reauth_failures_reaching_the_limit_lock_the_account(
        self, db: FakeDb, verifier: _Verifier
    ) -> None:
        """The Nth wrong password locks the account; the right one is refused afterwards
        (without a check) and exactly one account login.lockout row names the member."""
        admin = _admin(db)
        for _ in range(_LIMIT):
            assert await _reauth(db, admin, _WRONG, ip=None) is False

        assert _locked(_account_row(db))
        checks = len(verifier.calls)
        assert await _reauth(db, admin, _PASSWORD, ip=None) is False
        assert len(verifier.calls) == checks
        row = db.audit_rows("login.lockout")
        assert len(row) == 1
        lockout = row[0]
        assert (lockout["actor_kind"], plain(lockout["actor_user_id"])) == ("member", admin.user_id)
        assert plain(lockout["org_id"]) == ORG_ID
        assert lockout["metadata"] == _ACCOUNT_LOCK

    async def test_reauth_failures_share_the_login_forms_counter(self, db: FakeDb) -> None:
        """Failed logins and failed re-auths add up on the one account counter."""
        admin = _admin(db)
        for _ in range(3):
            with pytest.raises(auth.LoginFailedError):
                await auth.login(
                    db.pool, email=_EMAIL, password=_WRONG, ip=None, user_agent="pytest"
                )

        await _reauth(db, admin, _WRONG, ip=None)

        row = _account_row(db)
        assert row is not None and row["failures"] == 4


# ---------------------------------------------------------------------------
# 4. No login side effects
# ---------------------------------------------------------------------------


class TestNoLoginSideEffects:
    """Re-auth is not a login: no session, no login.success / login.failure row."""

    @pytest.mark.parametrize("password", [_PASSWORD, _WRONG])
    async def test_reauth_creates_no_session_and_no_login_audit_row(
        self, db: FakeDb, password: str
    ) -> None:
        admin = _admin(db)

        await _reauth(db, admin, password)

        assert db.sessions == {}
        assert _login_rows(db) == []
        assert db.matching(r"^insert into sessions\b") == []

    async def test_reauth_locked_records_no_login_failure_row(self, db: FakeDb) -> None:
        admin = _admin(db)
        db.add_throttle(
            "account",
            account_subject(_EMAIL),
            locked_until=datetime.now(UTC) + timedelta(minutes=10),
        )

        await _reauth(db, admin, _PASSWORD)

        assert _login_rows(db) == []

    async def test_reauth_success_doesnt_stamp_last_login(self, db: FakeDb) -> None:
        admin = _admin(db)

        await _reauth(db, admin, _PASSWORD)

        assert db.users[admin.user_id]["last_login_at"] is None


# ---------------------------------------------------------------------------
# 5. No content in logs
# ---------------------------------------------------------------------------


class TestNoContentInLogs:
    async def test_reauth_logs_neither_password_nor_email(
        self, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        admin = _admin(db)
        ghost = Principal(user_id=uuid.uuid4(), kind="member", org_id=ORG_ID, role="org_admin")

        await _reauth(db, admin, _PASSWORD)
        await _reauth(db, ghost, _PASSWORD)
        for _ in range(_LIMIT + 1):
            await _reauth(db, admin, _WRONG)

        text = "\n".join(
            f"{record.name} {record.getMessage()} {record.exc_text or ''}"
            for record in caplog.records
        ).lower()
        for marker in (_PASSWORD, _WRONG, _EMAIL):
            assert marker.lower() not in text
