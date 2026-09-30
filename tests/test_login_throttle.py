"""Tests for admino.login_throttle and the throttled login (GH-157).

``admino.login_throttle`` counts failed attempts per account and per client IP
in the ``login_throttle`` table (migration 0012), so the counters survive a
restart. ``admino.auth.login`` runs every attempt through it; these tests drive
the real ``auth.login`` against the shared in-memory database of
tests/db_fakes.py, with Argon2 replaced by a fast recording stand-in and the
progressive delay recorded through the ``login_delays`` fixture (no test ever
really sleeps).

What these tests pin down:
- Constants: a 15-minute failure window, a delay from 3 failures, a lockout of
  15 minutes after 10 failures, delays doubling from 1 s up to 8 s, an hourly
  purge and the message "Too many attempts. Try again later."
  ``delay_seconds(failures)``: 0.0 below 3, then 1, 2, 4, 8, 8, ... (never an
  overflow). ``sleep`` is ``asyncio.sleep``.
- ``ip_subject(ip)``: a 32-byte digest, the same in every process; IPv4 keys
  by its address, an IPv4-mapped IPv6 address like the IPv4 address, any other
  IPv6 address by its /64; equivalent spellings key the same; None or a string
  that isn't an IP address gives None (no IP dimension). The digest never
  contains the address.
- Counters: an attempt adds one row per dimension (scope 'account' keyed by
  ``sha256(convert_to(lower(<email>), 'UTF8'))``, computed by the database, and
  scope 'ip' keyed by ``ip_subject``); every spelling of an email shares one
  counter; the rows hold digests and counts only; ``expires_at`` is
  ``max(window_started_at + 15 minutes, locked_until)``.
- The reservation: in one transaction the rows are locked FOR UPDATE (account
  first, then IP) and every subject's failures go up by one before the
  password is checked; the delay (the max of the prior counts, in-flight
  reservations included) is awaited after the commit and before the
  verification. A failure keeps the reservation, an exception keeps it too; a
  success resets the account counter and only releases its own IP reservation
  (floor 0).
- Lockout: the 10th failure within the window locks each subject that reached
  10 for 15 minutes (failures reset to 0) and records one ``login.lockout``
  per subject (account first, then IP) after the attempt's ``login.failure``,
  in the lock's transaction. A locked attempt (an active lock, or 10 failures
  in the window without one) is refused with the generic error, verifies
  nothing, reserves nothing and records ``login.failure`` with ``{"locked":
  true}``. A failed lockout record fails closed.
- Expiry: a lock ends on its own and the counter starts fresh; failures from
  a window that ended no longer count.
- No enumeration: a known and an unknown email behave identically.
- Audit: exact rows (actor, org, IP, metadata); a member's account lockout
  lands in their org's log, an unknown email's and every IP lockout in the
  platform log; never the email.
- Persistence: the state lives in the table only.
- ``purge_expired`` deletes only the rows past ``expires_at`` (never a live
  lock); ``run_purge_job`` purges now and then hourly, surviving failures.

Security notes:
- No real PostgreSQL, no network, no real sleeping.
- The throttle table stores no email and no IP text.
"""

from __future__ import annotations

import asyncio
import copy
import inspect
import json
import logging
import re
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

import asyncpg
import pytest

from admino import auth, passwords
from admino.audit_events import AuditRecordError
from admino.auth import LOGIN_FAILED_MESSAGE, LoginFailedError
from tests.db_fakes import ORG_ID, FakeDb, account_subject, fake_hash, plain

if TYPE_CHECKING:
    import uuid
    from collections.abc import Callable
    from types import ModuleType

# ---------------------------------------------------------------------------
# Constants and helpers
# ---------------------------------------------------------------------------

_PASSWORD = "violet-Anchor-93-quartz"
_WRONG = "violet-Anchor-93-quartzz"
_EMAIL = "Throttle.Marker@Example.test"
_UNKNOWN = "Nobody.Marker@Example.test"
_IP = "203.0.113.5"
_OTHER_IP = "198.51.100.23"
_UA = "pytest-throttle/1.0"
_WINDOW = timedelta(minutes=15)
_LOCKOUT = timedelta(minutes=15)
_ACCOUNT_LOCK = {"per_ip": False, "lockout_minutes": 15}
_IP_LOCK = {"per_ip": True, "lockout_minutes": 15}
_SEQUENCE_TO_NINE = [1.0, 2.0, 4.0, 8.0, 8.0, 8.0]
_SEQUENCE_TO_TEN = [1.0, 2.0, 4.0, 8.0, 8.0, 8.0, 8.0]
# sha256(convert_to(lower($n), 'UTF8')), formatting-tolerant (normalized SQL).
_DIGEST_RE = re.compile(
    r"sha256 ?\( ?convert_to ?\( ?lower ?\( ?\$(\d+)(?: ?:: ?\w+)? ?\) ?, ?'utf-?8' ?\) ?\)"
)
_LOOKUP_RE = re.compile(r"lower ?\( ?(?:\w+\.)?email ?\) ?= ?lower ?\( ?\$(\d+)")
_FAILURE_MARKER = "row-marker-7c1d 203.0.113.5 throttle.marker@example.test"

# The real asyncio.sleep, kept before any test patches it.
_REAL_SLEEP = asyncio.sleep


class _Verifier:
    """Fast stand-in for passwords.verify_password.

    Records every password it checks and runs an optional hook first (in the
    worker thread, like the real check).
    """

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.hook: Callable[[], None] | None = None

    def __call__(self, password: str, encoded: str) -> bool:
        self.calls.append(password)
        if self.hook is not None:
            self.hook()
        return encoded == fake_hash(password)


@pytest.fixture()
def throttle() -> ModuleType:
    """admino.login_throttle, imported per test (so each test fails on its own)."""
    import admino.login_throttle as module

    return module


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database."""
    return FakeDb()


@pytest.fixture(autouse=True)
def verifier(monkeypatch: pytest.MonkeyPatch) -> _Verifier:
    """Replace Argon2 with the fast recording stand-in (never a real hash here)."""
    spy = _Verifier()
    monkeypatch.setattr(passwords, "verify_password", spy)
    monkeypatch.setattr(passwords, "needs_rehash", lambda _encoded: False)
    monkeypatch.setattr(passwords, "hash_password", fake_hash)
    return spy


def _now() -> datetime:
    return datetime.now(UTC)


def _account(db: FakeDb, email: str = _EMAIL, **fields: Any) -> uuid.UUID:
    """An active member (by default) who logs in with _PASSWORD."""
    return db.add_account(email=email, password_hash=fake_hash(_PASSWORD), **fields)


async def _attempt(
    db: FakeDb, *, email: str = _EMAIL, password: str = _WRONG, ip: str | None = _IP
) -> bool:
    """One login attempt: True when it opened a session, False on LoginFailedError."""
    try:
        await auth.login(db.pool, email=email, password=password, ip=ip, user_agent=_UA)
    except LoginFailedError:
        return False
    return True


async def _fail(db: FakeDb, count: int, **kwargs: Any) -> None:
    """``count`` failed attempts with the same arguments."""
    for _ in range(count):
        assert await _attempt(db, **kwargs) is False


def _ips(count: int, prefix: str = "198.51.100") -> list[str]:
    return [f"{prefix}.{index}" for index in range(1, count + 1)]


def _emails(count: int) -> list[str]:
    return [f"ghost{index}.marker@example.test" for index in range(1, count + 1)]


def _account_row(db: FakeDb, email: str = _EMAIL) -> dict[str, Any] | None:
    return db.throttle_row("account", account_subject(email))


def _ip_row(db: FakeDb, throttle: ModuleType, ip: str = _IP) -> dict[str, Any] | None:
    return db.throttle_row("ip", throttle.ip_subject(ip))


def _seed_account(db: FakeDb, email: str = _EMAIL, **fields: Any) -> dict[str, Any]:
    return db.add_throttle("account", account_subject(email), **fields)


def _seed_ip(db: FakeDb, throttle: ModuleType, ip: str = _IP, **fields: Any) -> dict[str, Any]:
    return db.add_throttle("ip", throttle.ip_subject(ip), **fields)


def _locked(row: dict[str, Any] | None) -> bool:
    """True when the row holds an active lock."""
    return row is not None and row["locked_until"] is not None and row["locked_until"] > _now()


def _event(row: dict[str, Any]) -> tuple[Any, ...]:
    """An audit row as (action, actor kind, user, org, ip, target type, targets, metadata)."""
    return (
        row["action"],
        row["actor_kind"],
        None if row["actor_user_id"] is None else plain(row["actor_user_id"]),
        None if row["org_id"] is None else plain(row["org_id"]),
        row["ip"],
        row["target_type"],
        row["target_ids"],
        row["metadata"],
    )


def _scope_of(call: Any) -> str | None:
    """The scope a login_throttle statement names (a literal or a bound value)."""
    for scope in ("account", "ip"):
        if f"'{scope}'" in call.normalized or scope in call.args:
            return scope
    return None


# ---------------------------------------------------------------------------
# 1. Constants, delay_seconds and sleep
# ---------------------------------------------------------------------------


class TestConstants:
    """The issue's defaults, as module constants (#160 makes them configurable)."""

    def test_login_throttle_window_and_lockout_constants(self, throttle: ModuleType) -> None:
        assert timedelta(minutes=15) == throttle.FAILURE_WINDOW
        assert throttle.DELAY_AFTER_FAILURES == 3
        assert throttle.LOCKOUT_AFTER_FAILURES == 10
        assert timedelta(minutes=15) == throttle.LOCKOUT_DURATION

    def test_login_throttle_delay_constants(self, throttle: ModuleType) -> None:
        assert throttle.DELAY_BASE_SECONDS == 1.0
        assert throttle.DELAY_MAX_SECONDS == 8.0

    def test_login_throttle_purge_interval_is_an_hour(self, throttle: ModuleType) -> None:
        assert throttle.PURGE_INTERVAL_SECONDS == 3600

    def test_login_throttle_too_many_attempts_message(self, throttle: ModuleType) -> None:
        assert throttle.TOO_MANY_ATTEMPTS_MESSAGE == "Too many attempts. Try again later."

    def test_login_throttle_sleep_is_asyncio_sleep(self, throttle: ModuleType) -> None:
        """The delay is awaited through this module attribute (the tests replace it)."""
        assert throttle.sleep is asyncio.sleep


class TestDelaySeconds:
    """No delay below 3 failures, then doubling from 1 s, capped at 8 s."""

    @pytest.mark.parametrize(
        ("failures", "expected"),
        [
            (-1, 0.0),
            (0, 0.0),
            (1, 0.0),
            (2, 0.0),
            (3, 1.0),
            (4, 2.0),
            (5, 4.0),
            (6, 8.0),
            (7, 8.0),
            (9, 8.0),
            (10, 8.0),
            (50, 8.0),
            (10_000, 8.0),
            (10**6, 8.0),
        ],
    )
    def test_login_throttle_delay_seconds(
        self, throttle: ModuleType, failures: int, expected: float
    ) -> None:
        result = throttle.delay_seconds(failures)

        assert result == expected
        assert type(result) is float


# ---------------------------------------------------------------------------
# 2. ip_subject
# ---------------------------------------------------------------------------


class TestIpSubject:
    """What keys the IP counter: a digest of the address or of its /64."""

    @pytest.mark.parametrize("ip", ["203.0.113.5", "2001:db8:1:2::1", "::ffff:203.0.113.5"])
    def test_login_throttle_ip_subject_is_a_32_byte_digest(
        self, throttle: ModuleType, ip: str
    ) -> None:
        subject = throttle.ip_subject(ip)

        assert type(subject) is bytes
        assert len(subject) == 32

    def test_login_throttle_ipv4_keys_by_its_address(self, throttle: ModuleType) -> None:
        subjects = {throttle.ip_subject(ip) for ip in ("203.0.113.5", "203.0.113.6", "10.0.0.5")}

        assert len(subjects) == 3
        assert throttle.ip_subject("203.0.113.5") == throttle.ip_subject("203.0.113.5")

    def test_login_throttle_mapped_ipv4_keys_like_the_ipv4_address(
        self, throttle: ModuleType
    ) -> None:
        assert throttle.ip_subject("::ffff:203.0.113.5") == throttle.ip_subject("203.0.113.5")
        assert throttle.ip_subject("::ffff:203.0.113.5") != throttle.ip_subject(
            "::ffff:203.0.113.6"
        )

    @pytest.mark.parametrize(
        "ip", ["2001:db8:1:2::2", "2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::"]
    )
    def test_login_throttle_ipv6_keys_by_its_64(self, throttle: ModuleType, ip: str) -> None:
        """Every address of 2001:db8:1:2::/64 shares one counter."""
        assert throttle.ip_subject(ip) == throttle.ip_subject("2001:db8:1:2::1")

    @pytest.mark.parametrize("ip", ["2001:db8:1:3::1", "2001:db8:1:1:ffff:ffff:ffff:ffff"])
    def test_login_throttle_another_64_is_another_counter(
        self, throttle: ModuleType, ip: str
    ) -> None:
        assert throttle.ip_subject(ip) != throttle.ip_subject("2001:db8:1:2::1")

    def test_login_throttle_equivalent_spellings_key_the_same(self, throttle: ModuleType) -> None:
        spellings = ["2001:DB8::1", "2001:db8:0::1", "2001:0db8:0000:0000:0000:0000:0000:0001"]

        assert len({throttle.ip_subject(ip) for ip in spellings}) == 1

    def test_login_throttle_ipv4_and_ipv6_never_share_a_key(self, throttle: ModuleType) -> None:
        assert throttle.ip_subject("0.0.0.1") != throttle.ip_subject("::1")
        assert throttle.ip_subject("32.1.13.184") != throttle.ip_subject("2001:db8::1")

    @pytest.mark.parametrize(
        "ip",
        [
            None,
            "testclient",
            "",
            "unknown",
            "203.0.113",
            "203.0.113.5:8080",
            "not an ip",
            "2001:db8::g",
        ],
    )
    def test_login_throttle_no_ip_dimension_without_an_ip_address(
        self, throttle: ModuleType, ip: str | None
    ) -> None:
        assert throttle.ip_subject(ip) is None

    @pytest.mark.parametrize("ip", ["203.0.113.5", "2001:db8:1:2::1", "::ffff:203.0.113.5"])
    def test_login_throttle_ip_subject_never_contains_the_address(
        self, throttle: ModuleType, ip: str
    ) -> None:
        subject = throttle.ip_subject(ip)
        address = ip_address(ip)
        network = ip_network(f"{ip}/64", strict=False) if address.version == 6 else None

        assert ip.encode() not in subject
        assert address.packed not in subject
        if network is not None:
            assert network.network_address.packed[:8] not in subject
            assert str(network).encode() not in subject

    def test_login_throttle_ip_subject_is_the_same_in_a_new_process(
        self, throttle: ModuleType
    ) -> None:
        """Deterministic across processes (no per-process key): the counters survive a
        restart."""
        code = (
            "from admino.login_throttle import ip_subject;"
            "print(ip_subject('203.0.113.5').hex());"
            "print(ip_subject('2001:db8:1:2::9').hex())"
        )
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            stdin=subprocess.DEVNULL,
        )

        assert result.returncode == 0, result.stderr
        assert result.stdout.split() == [
            throttle.ip_subject("203.0.113.5").hex(),
            throttle.ip_subject("2001:db8:1:2::9").hex(),
        ]


# ---------------------------------------------------------------------------
# 3. Counters
# ---------------------------------------------------------------------------


class TestCounters:
    """One login_throttle row per dimension, counting failed attempts."""

    async def test_login_throttle_first_failure_adds_one_row_per_dimension(
        self, db: FakeDb, throttle: ModuleType
    ) -> None:
        assert await _attempt(db, email=_UNKNOWN) is False

        assert len(db.throttle) == 2
        account = _account_row(db, _UNKNOWN)
        ip = _ip_row(db, throttle)
        assert account is not None
        assert ip is not None
        assert (account["failures"], ip["failures"]) == (1, 1)

    async def test_login_throttle_failures_count_up(self, db: FakeDb, throttle: ModuleType) -> None:
        _account(db)

        await _fail(db, 3)

        account = _account_row(db)
        ip = _ip_row(db, throttle)
        assert account is not None
        assert ip is not None
        assert (account["failures"], ip["failures"]) == (3, 3)
        assert len(db.throttle) == 2

    async def test_login_throttle_rows_hold_only_digests_and_counts(self, db: FakeDb) -> None:
        """32-byte subjects; no email and no IP text anywhere in a row."""
        _account(db)

        await _attempt(db)

        assert len(db.throttle) == 2
        for row in db.throttle:
            assert type(row["subject"]) is bytes
            assert len(row["subject"]) == 32
            assert _EMAIL.lower().encode() not in row["subject"]
            assert _IP.encode() not in row["subject"]
            assert ip_address(_IP).packed not in row["subject"]
            assert [value for value in row.values() if isinstance(value, str)] == [row["scope"]]
        assert {row["scope"] for row in db.throttle} == {"account", "ip"}

    async def test_login_throttle_row_expires_at_the_end_of_its_window(self, db: FakeDb) -> None:
        before = _now()

        await _attempt(db, email=_UNKNOWN)

        after = _now()
        assert len(db.throttle) == 2
        for row in db.throttle:
            assert before <= row["window_started_at"] <= after
            assert row["locked_until"] is None
            assert row["expires_at"] == row["window_started_at"] + _WINDOW

    @pytest.mark.parametrize("known", [True, False], ids=["known", "unknown"])
    async def test_login_throttle_email_spellings_share_one_counter(
        self, db: FakeDb, known: bool
    ) -> None:
        """The same lower() as the login lookup: every spelling reaches one counter."""
        if known:
            _account(db)
        spellings = [_EMAIL, _EMAIL.lower(), _EMAIL.upper()]

        for email in spellings:
            assert await _attempt(db, email=email, ip=None) is False

        assert len(db.throttle) == 1
        row = _account_row(db)
        assert row is not None
        assert row["failures"] == 3

    async def test_login_throttle_account_subject_is_computed_by_the_database(
        self, db: FakeDb
    ) -> None:
        """A statement applies sha256(convert_to(lower($n), 'UTF8')) to the typed email;
        the email is bound only there and in the users lookup, never in SQL text."""
        typed = "Throttle.MARKER@example.test"

        await _attempt(db, email=typed, ip=None)

        digests = [
            call
            for call in db.calls
            if any(call.args[int(n) - 1] == typed for n in _DIGEST_RE.findall(call.normalized))
        ]
        assert digests != []
        for call in db.calls:
            assert typed.lower() not in call.normalized
            lookup = _LOOKUP_RE.search(call.normalized)
            for position in [i + 1 for i, arg in enumerate(call.args) if arg == typed]:
                uses = len(re.findall(rf"\${position}(?!\d)", call.normalized))
                digested = [int(n) for n in _DIGEST_RE.findall(call.normalized)].count(position)
                looked_up = int(lookup is not None and int(lookup.group(1)) == position)
                assert uses == digested + looked_up, call.normalized

    async def test_login_throttle_ipv6_addresses_of_one_64_share_one_counter(
        self, db: FakeDb, throttle: ModuleType, login_delays: list[float]
    ) -> None:
        addresses = ["2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:2::3"]
        for ip, email in zip(addresses, _emails(3), strict=True):
            assert await _attempt(db, email=email, ip=ip) is False

        row = _ip_row(db, throttle, "2001:db8:1:2::ffff")
        assert row is not None
        assert row["failures"] == 3
        await _attempt(db, email="fourth.marker@example.test", ip="2001:db8:1:2::ffff")
        await _attempt(db, email="fifth.marker@example.test", ip="2001:db8:1:3::1")
        assert login_delays == [1.0]
        other = _ip_row(db, throttle, "2001:db8:1:3::1")
        assert other is not None
        assert other["failures"] == 1

    async def test_login_throttle_mapped_ipv4_shares_the_ipv4_counter(
        self, db: FakeDb, throttle: ModuleType
    ) -> None:
        await _attempt(db, email=_UNKNOWN, ip="::ffff:203.0.113.5")
        await _attempt(db, email=_UNKNOWN, ip="203.0.113.5")

        row = _ip_row(db, throttle)
        assert row is not None
        assert row["failures"] == 2

    @pytest.mark.parametrize("ip", [None, "testclient"])
    async def test_login_throttle_counts_the_account_only_without_an_ip(
        self, db: FakeDb, ip: str | None
    ) -> None:
        await _attempt(db, email=_UNKNOWN, ip=ip)

        assert [row["scope"] for row in db.throttle] == ["account"]


# ---------------------------------------------------------------------------
# 4. The progressive delay
# ---------------------------------------------------------------------------


class TestProgressiveDelay:
    """1, 2, 4, 8, 8, ... seconds from the 4th attempt, before the verification."""

    async def test_login_throttle_no_delay_for_the_first_three_failures(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        await _fail(db, 3, ip=None)

        assert login_delays == []
        row = _account_row(db)
        assert row is not None
        assert row["failures"] == 3

    async def test_login_throttle_account_delay_sequence(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        _account(db)

        await _fail(db, 9, ip=None)

        assert login_delays == _SEQUENCE_TO_NINE

    async def test_login_throttle_tenth_attempt_is_delayed_too(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        await _fail(db, 10, email=_UNKNOWN, ip=None)

        assert login_delays == _SEQUENCE_TO_TEN

    async def test_login_throttle_ip_delay_sequence(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        """Nine different emails from one IP: the IP's counter drives the delay."""
        for email in _emails(9):
            assert await _attempt(db, email=email) is False

        assert login_delays == _SEQUENCE_TO_NINE

    @pytest.mark.parametrize(
        ("account_failures", "ip_failures", "expected"),
        [
            pytest.param(5, 3, [4.0], id="account-5-ip-3"),
            pytest.param(3, 6, [8.0], id="account-3-ip-6"),
            pytest.param(4, 4, [2.0], id="both-4"),
            pytest.param(2, 0, [], id="account-2"),
            pytest.param(0, 2, [], id="ip-2"),
        ],
    )
    async def test_login_throttle_delay_is_the_max_of_both_counts(
        self,
        db: FakeDb,
        throttle: ModuleType,
        login_delays: list[float],
        account_failures: int,
        ip_failures: int,
        expected: list[float],
    ) -> None:
        _seed_account(db, failures=account_failures)
        _seed_ip(db, throttle, failures=ip_failures)

        await _attempt(db)

        assert login_delays == expected
        account = _account_row(db)
        assert account is not None
        assert account["failures"] == account_failures + 1

    @pytest.mark.parametrize("password", [_WRONG, _PASSWORD], ids=["failure", "success"])
    async def test_login_throttle_delay_is_awaited_before_the_verification(
        self,
        db: FakeDb,
        throttle: ModuleType,
        verifier: _Verifier,
        monkeypatch: pytest.MonkeyPatch,
        password: str,
    ) -> None:
        """Even a correct password waits: the delay comes before the check."""
        _account(db)
        _seed_account(db, failures=3)
        events: list[str] = []

        async def sleep(delay: float, *_args: Any, **_kwargs: Any) -> None:
            events.append(f"sleep:{delay}")

        monkeypatch.setattr(throttle, "sleep", sleep)
        verifier.hook = lambda: events.append("verify")

        opened = await _attempt(db, password=password, ip=None)

        assert opened is (password == _PASSWORD)
        assert events == ["sleep:1.0", "verify"]

    async def test_login_throttle_delay_is_awaited_after_the_reservation_commits(
        self, db: FakeDb, throttle: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No transaction is open while the attempt sleeps, and its reservation shows."""
        _seed_account(db, failures=3)
        seen: list[tuple[int, int | None]] = []

        async def sleep(_delay: float, *_args: Any, **_kwargs: Any) -> None:
            row = _account_row(db)
            seen.append((db.open_transactions, None if row is None else row["failures"]))

        monkeypatch.setattr(throttle, "sleep", sleep)

        await _attempt(db, ip=None)

        assert seen == [(0, 4)]
        assert any(outcome == "commit" for _, outcome in db.transactions)

    async def test_login_throttle_delay_counts_in_flight_reservations(
        self, db: FakeDb, verifier: _Verifier, login_delays: list[float]
    ) -> None:
        """Attempt A (2 prior failures) is still verifying when attempt B starts: B's
        delay counts A's reservation (3 prior failures, so 1 s)."""
        _seed_account(db, failures=2)
        gate = threading.Event()
        entered = threading.Event()

        def hook() -> None:
            if len(verifier.calls) == 1:
                entered.set()
                gate.wait(timeout=5)

        verifier.hook = hook
        first = asyncio.create_task(_attempt(db, ip=None))
        try:
            async with asyncio.timeout(5):
                while not entered.is_set():
                    await _REAL_SLEEP(0.01)
            second = await _attempt(db, ip=None)
        finally:
            gate.set()
        assert await first is False
        assert second is False
        assert login_delays == [1.0]


# ---------------------------------------------------------------------------
# 5. The reservation and the outcomes
# ---------------------------------------------------------------------------


class TestReservation:
    """The attempt counts as a failure from the moment it starts."""

    async def test_login_throttle_reservation_is_visible_during_verification(
        self, db: FakeDb, throttle: ModuleType, verifier: _Verifier
    ) -> None:
        _account(db)
        seen: list[tuple[int | None, int | None, int]] = []

        def hook() -> None:
            account = _account_row(db)
            ip = _ip_row(db, throttle)
            seen.append(
                (
                    None if account is None else account["failures"],
                    None if ip is None else ip["failures"],
                    db.open_transactions,
                )
            )

        verifier.hook = hook

        await _attempt(db, password=_PASSWORD)

        assert seen == [(1, 1, 0)]

    async def test_login_throttle_rows_are_locked_account_first_in_one_transaction(
        self, db: FakeDb
    ) -> None:
        await _attempt(db, email=_UNKNOWN)

        locks = [
            call
            for call in db.calls
            if re.search(r"\bfrom login_throttle\b", call.normalized)
            and re.search(r"\bfor update\b", call.normalized)
        ]
        assert len(locks) >= 2
        assert [_scope_of(call) for call in locks[:2]] == ["account", "ip"]
        assert locks[0].tx is not None
        assert locks[0].tx == locks[1].tx
        writes = [
            call
            for call in db.calls
            if call.tx == locks[0].tx
            and re.match(r"(?:insert into|update) login_throttle\b", call.normalized)
        ]
        assert writes != []

    async def test_login_throttle_concurrent_attempts_cannot_outrun_the_lockout(
        self, db: FakeDb, verifier: _Verifier, login_delays: list[float]
    ) -> None:
        """9 failures so far; attempt A (wrong password) is verifying, so its reservation
        makes 10: attempt B is refused even with the correct password, unverified."""
        _account(db)
        _seed_account(db, failures=9)
        gate = threading.Event()
        entered = threading.Event()

        def hook() -> None:
            if len(verifier.calls) == 1:
                entered.set()
                gate.wait(timeout=5)

        verifier.hook = hook
        first = asyncio.create_task(_attempt(db, ip=None))
        try:
            async with asyncio.timeout(5):
                while not entered.is_set():
                    await _REAL_SLEEP(0.01)
            second = await _attempt(db, password=_PASSWORD, ip=None)
            calls_during = list(verifier.calls)
        finally:
            gate.set()
        assert await first is False
        assert second is False
        assert calls_during == [_WRONG]
        assert _locked(_account_row(db))
        assert db.sessions == {}

    async def test_login_throttle_success_resets_the_account_counter(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        _account(db)
        _seed_account(db, failures=5)

        assert await _attempt(db, password=_PASSWORD, ip=None) is True

        row = _account_row(db)
        assert row is not None
        assert (row["failures"], row["locked_until"]) == (0, None)
        assert login_delays == [4.0]
        await _attempt(db, ip=None)
        assert login_delays == [4.0]

    async def test_login_throttle_success_releases_only_its_own_ip_reservation(
        self, db: FakeDb, throttle: ModuleType, login_delays: list[float]
    ) -> None:
        _account(db)
        _seed_ip(db, throttle, failures=6)

        assert await _attempt(db, password=_PASSWORD) is True

        row = _ip_row(db, throttle)
        assert row is not None
        assert row["failures"] == 6
        assert login_delays == [8.0]

    async def test_login_throttle_success_never_clears_the_ips_earlier_failures(
        self, db: FakeDb, throttle: ModuleType, login_delays: list[float]
    ) -> None:
        """9 failures from an IP, a success from it with a valid account, then one more
        failure: the IP locks (an attacker's own account can't reset the IP)."""
        _account(db)
        for email in _emails(9):
            assert await _attempt(db, email=email) is False
        assert await _attempt(db, password=_PASSWORD) is True

        assert await _attempt(db, email="tenth.marker@example.test") is False

        assert _locked(_ip_row(db, throttle))
        assert [row["metadata"] for row in db.audit_rows("login.lockout")] == [_IP_LOCK]
        assert await _attempt(db, password=_PASSWORD) is False
        assert await _attempt(db, password=_PASSWORD, ip=_OTHER_IP) is True

    async def test_login_throttle_release_never_goes_below_zero(
        self, db: FakeDb, throttle: ModuleType, verifier: _Verifier
    ) -> None:
        """A success whose IP counter was reset meanwhile (a concurrent lockout) still
        succeeds and leaves 0."""
        _account(db)

        def reset_ip() -> None:
            row = _ip_row(db, throttle)
            assert row is not None
            row["failures"] = 0

        verifier.hook = reset_ip

        assert await _attempt(db, password=_PASSWORD) is True
        row = _ip_row(db, throttle)
        assert row is not None
        assert row["failures"] == 0

    async def test_login_throttle_exception_during_verification_keeps_the_reservation(
        self, db: FakeDb, throttle: ModuleType, verifier: _Verifier
    ) -> None:
        _account(db)

        def boom() -> None:
            raise RuntimeError(_FAILURE_MARKER)

        verifier.hook = boom

        with pytest.raises((RuntimeError, LoginFailedError)):
            await auth.login(db.pool, email=_EMAIL, password=_PASSWORD, ip=_IP, user_agent=_UA)

        account = _account_row(db)
        ip = _ip_row(db, throttle)
        assert account is not None
        assert ip is not None
        assert (account["failures"], ip["failures"]) == (1, 1)
        assert db.sessions == {}

    async def test_login_throttle_store_failure_fails_closed(
        self, db: FakeDb, verifier: _Verifier
    ) -> None:
        """If the counter can't be written, the password is never checked and no session
        opens."""
        _account(db)
        db.fail_sql = r"\blogin_throttle\b"

        with pytest.raises((asyncpg.PostgresError, LoginFailedError)):
            await auth.login(db.pool, email=_EMAIL, password=_PASSWORD, ip=_IP, user_agent=_UA)

        assert db.matching(r"\blogin_throttle\b") != []
        assert verifier.calls == []
        assert db.sessions == {}


# ---------------------------------------------------------------------------
# 6. Lockout
# ---------------------------------------------------------------------------


class TestLockout:
    """10 failures in 15 minutes lock a subject for 15 minutes."""

    async def test_login_throttle_tenth_failure_locks_the_account(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        _account(db)
        before = _now()

        await _fail(db, 10, ip=None)

        after = _now()
        row = _account_row(db)
        assert row is not None
        assert row["locked_until"] is not None
        assert before + _LOCKOUT <= row["locked_until"] <= after + _LOCKOUT
        assert row["failures"] == 0
        assert row["expires_at"] >= row["locked_until"]
        assert row["expires_at"] == max(row["window_started_at"] + _WINDOW, row["locked_until"])

    async def test_login_throttle_ninth_failure_does_not_lock(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        _account(db)
        await _fail(db, 9, ip=None)

        row = _account_row(db)
        assert row is not None
        assert (row["failures"], row["locked_until"]) == (9, None)
        assert await _attempt(db, password=_PASSWORD, ip=None) is True

    async def test_login_throttle_locked_account_refuses_the_correct_password(
        self, db: FakeDb, verifier: _Verifier, login_delays: list[float]
    ) -> None:
        _account(db)
        await _fail(db, 10, ip=None)
        verifications = len(verifier.calls)

        with pytest.raises(LoginFailedError) as exc_info:
            await auth.login(db.pool, email=_EMAIL, password=_PASSWORD, ip=None, user_agent=_UA)

        assert str(exc_info.value) == LOGIN_FAILED_MESSAGE
        assert len(verifier.calls) == verifications
        assert db.sessions == {}

    async def test_login_throttle_account_lock_holds_for_every_ip(
        self, db: FakeDb, throttle: ModuleType, verifier: _Verifier, login_delays: list[float]
    ) -> None:
        """10 failures from 10 IPs lock the account; each IP saw only one failure."""
        _account(db)
        for ip in _ips(10):
            assert await _attempt(db, ip=ip) is False
        verifications = len(verifier.calls)

        assert await _attempt(db, password=_PASSWORD, ip="192.0.2.200") is False

        assert len(verifier.calls) == verifications
        for ip in _ips(10):
            row = _ip_row(db, throttle, ip)
            assert row is not None
            assert (row["failures"], row["locked_until"]) == (1, None)

    async def test_login_throttle_account_lock_leaves_other_accounts_alone(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        _account(db)
        _account(db, "other.person@example.test")
        for ip in _ips(10):
            await _attempt(db, ip=ip)

        assert await _attempt(db, email="other.person@example.test", password=_PASSWORD) is True
        assert await _attempt(db, password=_PASSWORD, ip=_ips(1)[0]) is False

    async def test_login_throttle_ten_emails_from_one_ip_lock_the_ip(
        self, db: FakeDb, throttle: ModuleType, login_delays: list[float]
    ) -> None:
        _account(db)
        emails = _emails(10)
        for email in emails:
            assert await _attempt(db, email=email) is False

        assert _locked(_ip_row(db, throttle))
        for email in emails:
            row = _account_row(db, email)
            assert row is not None
            assert (row["failures"], row["locked_until"]) == (1, None)
        assert await _attempt(db, password=_PASSWORD) is False
        assert await _attempt(db, password=_PASSWORD, ip=_OTHER_IP) is True

    async def test_login_throttle_seeded_ip_lock_refuses_every_email(
        self, db: FakeDb, throttle: ModuleType, verifier: _Verifier
    ) -> None:
        _account(db)
        _seed_ip(db, throttle, locked_until=_now() + timedelta(minutes=10))

        assert await _attempt(db, password=_PASSWORD) is False
        assert verifier.calls == []
        assert await _attempt(db, password=_PASSWORD, ip=_OTHER_IP) is True

    async def test_login_throttle_locked_attempt_writes_nothing(
        self, db: FakeDb, throttle: ModuleType, verifier: _Verifier
    ) -> None:
        """No verification and no reservation on any subject."""
        _account(db)
        _seed_account(
            db,
            failures=0,
            window_started_at=_now() - timedelta(minutes=5),
            locked_until=_now() + timedelta(minutes=10),
        )
        _seed_ip(db, throttle, failures=2)
        before = copy.deepcopy(db.throttle)

        assert await _attempt(db, password=_PASSWORD) is False

        assert verifier.calls == []
        assert db.throttle == before
        assert db.sessions == {}

    async def test_login_throttle_ten_failures_without_a_lock_refuse_unverified(
        self, db: FakeDb, verifier: _Verifier
    ) -> None:
        """failures >= 10 in the window without a lock (in-flight attempts, or a failed
        lockout record) is locked too: fail closed."""
        _account(db)
        _seed_account(db, failures=10, window_started_at=_now() - timedelta(minutes=1))
        before = copy.deepcopy(db.throttle)

        assert await _attempt(db, password=_PASSWORD, ip=None) is False

        assert verifier.calls == []
        assert db.throttle == before
        assert db.audit_rows("login.lockout") == []

    async def test_login_throttle_active_lock_near_its_end_still_refuses(
        self, db: FakeDb, verifier: _Verifier
    ) -> None:
        _account(db)
        _seed_account(db, locked_until=_now() + timedelta(seconds=5))

        assert await _attempt(db, password=_PASSWORD, ip=None) is False
        assert verifier.calls == []

    async def test_login_throttle_lockout_is_recorded_once(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        _account(db)
        await _fail(db, 10, ip=None)

        await _fail(db, 3, ip=None)
        await _attempt(db, password=_PASSWORD, ip=None)

        assert len(db.audit_rows("login.lockout")) == 1


# ---------------------------------------------------------------------------
# 7. Expiry and the window
# ---------------------------------------------------------------------------


def _expired_lock(db: FakeDb, email: str = _EMAIL) -> None:
    """The row a lockout leaves behind, once its lock has run out."""
    _seed_account(
        db,
        email,
        failures=0,
        window_started_at=_now() - timedelta(minutes=20),
        locked_until=_now() - timedelta(seconds=1),
    )


class TestExpiry:
    """A lock ends on its own; failures from an ended window no longer count."""

    async def test_login_throttle_expired_lock_lets_the_correct_password_in(
        self, db: FakeDb, verifier: _Verifier
    ) -> None:
        _account(db)
        _expired_lock(db)
        before = _now()

        assert await _attempt(db, password=_PASSWORD, ip=None) is True
        assert verifier.calls == [_PASSWORD]
        row = _account_row(db)
        assert row is not None
        assert (row["failures"], row["window_started_at"] >= before) == (0, True)

    async def test_login_throttle_counter_starts_fresh_after_expiry(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        _account(db)
        _expired_lock(db)

        await _fail(db, 3, ip=None)

        assert login_delays == []
        row = _account_row(db)
        assert row is not None
        assert row["failures"] == 3
        assert not _locked(row)
        await _attempt(db, ip=None)
        assert login_delays == [1.0]
        assert db.audit_rows("login.lockout") == []

    async def test_login_throttle_one_failure_after_expiry_does_not_relock(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        _account(db)
        _expired_lock(db)

        assert await _attempt(db, ip=None) is False

        row = _account_row(db)
        assert row is not None
        assert row["failures"] == 1
        assert not _locked(row)
        assert await _attempt(db, password=_PASSWORD, ip=None) is True

    async def test_login_throttle_ended_window_no_longer_counts(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        _account(db)
        _seed_account(db, failures=9, window_started_at=_now() - _WINDOW - timedelta(seconds=1))
        before = _now()

        assert await _attempt(db, ip=None) is False

        row = _account_row(db)
        assert row is not None
        assert login_delays == []
        assert (row["failures"], row["locked_until"]) == (1, None)
        assert row["window_started_at"] >= before
        assert row["expires_at"] == row["window_started_at"] + _WINDOW

    async def test_login_throttle_failures_inside_the_window_still_count(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        _account(db)
        _seed_account(db, failures=9, window_started_at=_now() - timedelta(minutes=14))

        assert await _attempt(db, ip=None) is False

        assert login_delays == [8.0]
        assert _locked(_account_row(db))

    async def test_login_throttle_limit_from_an_ended_window_is_no_lock(
        self, db: FakeDb, verifier: _Verifier
    ) -> None:
        _account(db)
        _seed_account(db, failures=10, window_started_at=_now() - timedelta(minutes=16))
        before = _now()

        assert await _attempt(db, password=_PASSWORD, ip=None) is True
        assert verifier.calls == [_PASSWORD]
        row = _account_row(db)
        assert row is not None
        assert (row["failures"], row["window_started_at"] >= before) == (0, True)


# ---------------------------------------------------------------------------
# 8. No enumeration
# ---------------------------------------------------------------------------


class TestNoEnumeration:
    """A known and an unknown email can't be told apart by the throttle."""

    async def _scenario(self, db: FakeDb, email: str, verifier: _Verifier) -> list[tuple[Any, ...]]:
        """10 wrong passwords, then the right one; per attempt: the outcome, the number
        of verifications and the account row's (failures, locked, columns)."""
        outcomes: list[tuple[Any, ...]] = []
        for attempt in range(1, 12):
            password = _PASSWORD if attempt == 11 else _WRONG
            checked = len(verifier.calls)
            try:
                await auth.login(db.pool, email=email, password=password, ip=None, user_agent=_UA)
                outcome = "session"
            except LoginFailedError as exc:
                outcome = f"{type(exc).__name__}: {exc}"
            row = _account_row(db, email)
            shape = None if row is None else (row["failures"], _locked(row), sorted(row))
            outcomes.append((outcome, len(verifier.calls) - checked, shape))
        return outcomes

    async def test_login_throttle_known_and_unknown_emails_are_indistinguishable(
        self, verifier: _Verifier, login_delays: list[float]
    ) -> None:
        known_db = FakeDb()
        _account(known_db)
        known = await self._scenario(known_db, _EMAIL, verifier)
        known_delays = list(login_delays)
        login_delays.clear()

        unknown = await self._scenario(FakeDb(), _UNKNOWN, verifier)

        assert known == unknown
        assert known_delays == login_delays
        assert login_delays[:7] == _SEQUENCE_TO_TEN
        assert next(index for index, (_, _, shape) in enumerate(known, 1) if shape[1]) == 10
        assert known[-1][:2] == (f"LoginFailedError: {LOGIN_FAILED_MESSAGE}", 0)


# ---------------------------------------------------------------------------
# 9. Audit
# ---------------------------------------------------------------------------


class TestAudit:
    """Exact, content-free rows; the member's org log or the platform log."""

    async def test_login_throttle_ordinary_failure_is_audited_as_before(self, db: FakeDb) -> None:
        user_id = _account(db)

        await _attempt(db)

        assert [_event(row) for row in db.audit] == [
            ("login.failure", "member", user_id, ORG_ID, _IP, None, [], {})
        ]
        assert len(db.throttle) == 2

    async def test_login_throttle_member_account_lockout_event(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        user_id = _account(db)
        ips = _ips(10)

        for ip in ips:
            await _attempt(db, ip=ip)

        assert [_event(row) for row in db.audit_rows("login.lockout")] == [
            ("login.lockout", "member", user_id, ORG_ID, ips[-1], None, [], _ACCOUNT_LOCK)
        ]

    async def test_login_throttle_super_admin_account_lockout_event(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        user_id = _account(db, kind="super_admin", role=None)
        ips = _ips(10)

        for ip in ips:
            await _attempt(db, ip=ip)

        assert [_event(row) for row in db.audit_rows("login.lockout")] == [
            ("login.lockout", "super_admin", user_id, None, ips[-1], None, [], _ACCOUNT_LOCK)
        ]

    async def test_login_throttle_unknown_email_lockout_is_a_platform_event(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        ips = _ips(10)

        for ip in ips:
            await _attempt(db, email=_UNKNOWN, ip=ip)

        assert [_event(row) for row in db.audit_rows("login.lockout")] == [
            ("login.lockout", "system", None, None, ips[-1], None, [], _ACCOUNT_LOCK)
        ]

    async def test_login_throttle_ip_lockout_is_a_platform_event(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        """Even when every email belongs to a member, the IP lockout has no actor account
        and no org."""
        emails = _emails(10)
        for email in emails:
            _account(db, email)

        for email in emails:
            await _attempt(db, email=email)

        assert [_event(row) for row in db.audit_rows("login.lockout")] == [
            ("login.lockout", "system", None, None, _IP, None, [], _IP_LOCK)
        ]

    async def test_login_throttle_lockout_follows_the_failure_event(
        self, db: FakeDb, throttle: ModuleType
    ) -> None:
        """Both dimensions lock on one attempt: login.failure, then the account lockout,
        then the IP lockout."""
        user_id = _account(db)
        _seed_account(db, failures=9)
        _seed_ip(db, throttle, failures=9)

        with patch.object(throttle, "sleep", AsyncMock()):
            await _attempt(db)

        assert [_event(row) for row in db.audit] == [
            ("login.failure", "member", user_id, ORG_ID, _IP, None, [], {}),
            ("login.lockout", "member", user_id, ORG_ID, _IP, None, [], _ACCOUNT_LOCK),
            ("login.lockout", "system", None, None, _IP, None, [], _IP_LOCK),
        ]

    async def test_login_throttle_locked_attempt_records_a_locked_failure(self, db: FakeDb) -> None:
        user_id = _account(db)
        _seed_account(db, locked_until=_now() + timedelta(minutes=10))

        await _attempt(db, password=_PASSWORD)

        assert [_event(row) for row in db.audit] == [
            ("login.failure", "member", user_id, ORG_ID, _IP, None, [], {"locked": True})
        ]

    async def test_login_throttle_locked_unknown_email_is_a_system_failure(
        self, db: FakeDb
    ) -> None:
        _seed_account(db, _UNKNOWN, locked_until=_now() + timedelta(minutes=10))

        await _attempt(db, email=_UNKNOWN)

        assert [_event(row) for row in db.audit] == [
            ("login.failure", "system", None, None, _IP, None, [], {"locked": True})
        ]

    async def test_login_throttle_ip_locked_attempt_names_the_account(
        self, db: FakeDb, throttle: ModuleType
    ) -> None:
        user_id = _account(db)
        _seed_ip(db, throttle, locked_until=_now() + timedelta(minutes=10))

        await _attempt(db, password=_PASSWORD)

        assert [_event(row) for row in db.audit] == [
            ("login.failure", "member", user_id, ORG_ID, _IP, None, [], {"locked": True})
        ]

    async def test_login_throttle_lockout_is_recorded_in_the_locks_transaction(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        await _fail(db, 10, email=_UNKNOWN, ip=None)

        records = [
            call
            for call in db.matching(r"^insert into audit_events\b")
            if "login.lockout" in call.args
        ]
        assert len(records) == 1
        assert records[0].tx is not None
        assert any(
            call.tx == records[0].tx and re.match(r"update login_throttle\b", call.normalized)
            for call in db.calls
        )

    async def test_login_throttle_failed_lockout_record_fails_closed(
        self, db: FakeDb, verifier: _Verifier, login_delays: list[float]
    ) -> None:
        """The lock rolls back with its audit row, but the 10 reserved failures stay: the
        next attempt is refused unverified."""
        _account(db)
        db.fail_audit_when = lambda row: row["action"] == "login.lockout"
        await _fail(db, 9, ip=None)

        with pytest.raises((LoginFailedError, AuditRecordError)):
            await auth.login(db.pool, email=_EMAIL, password=_WRONG, ip=None, user_agent=_UA)

        row = _account_row(db)
        assert row is not None
        assert row["failures"] >= 10
        assert row["locked_until"] is None
        verifications = len(verifier.calls)
        assert await _attempt(db, password=_PASSWORD, ip=None) is False
        assert len(verifier.calls) == verifications
        assert db.audit_rows("login.lockout") == []
        assert db.audit_rows("login.failure")[-1]["metadata"] == {"locked": True}

    async def test_login_throttle_audit_rows_never_carry_the_email(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        _account(db)
        await _fail(db, 10)
        await _attempt(db, password=_PASSWORD)

        rendered = json.dumps(db.audit, default=str).casefold()
        assert "throttle.marker" not in rendered
        assert "example.test" not in rendered
        assert _WRONG.casefold() not in rendered

    async def test_login_throttle_logs_no_email_or_password(
        self, db: FakeDb, caplog: pytest.LogCaptureFixture, login_delays: list[float]
    ) -> None:
        caplog.set_level(logging.DEBUG)
        _account(db)

        await _fail(db, 10)
        await _attempt(db, password=_PASSWORD)

        text = caplog.text.casefold()
        assert "throttle.marker" not in text
        assert _WRONG.casefold() not in text
        assert _PASSWORD.casefold() not in text

    async def test_login_throttle_statements_bind_their_values(
        self, db: FakeDb, throttle: ModuleType, login_delays: list[float]
    ) -> None:
        """No subject, IP or count is interpolated into login_throttle SQL."""
        await _fail(db, 10, email=_UNKNOWN)

        statements = db.matching(r"\blogin_throttle\b")
        assert statements != []
        subjects = {account_subject(_UNKNOWN).hex(), throttle.ip_subject(_IP).hex()}
        for call in statements:
            assert _IP not in call.normalized
            assert "nobody.marker" not in call.normalized
            assert not any(subject in call.normalized for subject in subjects)


# ---------------------------------------------------------------------------
# 10. Persistence
# ---------------------------------------------------------------------------


class TestPersistence:
    """The state lives in the login_throttle table, not in process memory."""

    async def test_login_throttle_lock_is_read_from_the_table(
        self, db: FakeDb, verifier: _Verifier
    ) -> None:
        _account(db)
        _seed_account(db, locked_until=_now() + timedelta(minutes=10))

        assert await _attempt(db, password=_PASSWORD, ip=None) is False
        assert verifier.calls == []

    async def test_login_throttle_state_lives_only_in_the_table(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        """After a lockout, a database without the rows lets the account in; the same
        rows in another database lock it again."""
        _account(db)
        await _fail(db, 10)
        assert await _attempt(db, password=_PASSWORD) is False

        fresh = FakeDb()
        _account(fresh)
        restored = FakeDb()
        _account(restored)
        restored.throttle = copy.deepcopy(db.throttle)

        assert await _attempt(fresh, password=_PASSWORD) is True
        assert await _attempt(restored, password=_PASSWORD) is False


# ---------------------------------------------------------------------------
# 11. purge_expired and run_purge_job
# ---------------------------------------------------------------------------


class TestPurgeExpired:
    """Only rows past expires_at go; a live lock never does."""

    def _seed(self, db: FakeDb) -> dict[str, bytes]:
        now = _now()
        subjects = {name: bytes([index]) * 32 for index, name in enumerate("abcde", start=1)}
        db.add_throttle("account", subjects["a"], window_started_at=now - timedelta(minutes=20))
        db.add_throttle("ip", subjects["b"], failures=4, window_started_at=now)
        db.add_throttle(
            "account",
            subjects["c"],
            window_started_at=now - timedelta(minutes=30),
            locked_until=now + timedelta(minutes=10),
        )
        db.add_throttle(
            "ip",
            subjects["d"],
            window_started_at=now - timedelta(minutes=40),
            locked_until=now - timedelta(minutes=1),
        )
        db.add_throttle("ip", subjects["e"], window_started_at=now - timedelta(minutes=14))
        return subjects

    async def test_login_throttle_purge_removes_only_expired_rows(
        self, db: FakeDb, throttle: ModuleType
    ) -> None:
        subjects = self._seed(db)

        purged = await throttle.purge_expired(db.pool)

        assert purged == 2
        assert {row["subject"] for row in db.throttle} == {
            subjects["b"],
            subjects["c"],
            subjects["e"],
        }

    async def test_login_throttle_purge_never_removes_a_live_lock(
        self, db: FakeDb, throttle: ModuleType
    ) -> None:
        now = _now()
        db.add_throttle(
            "account",
            b"\x07" * 32,
            window_started_at=now - timedelta(hours=1),
            locked_until=now + timedelta(seconds=30),
        )

        assert await throttle.purge_expired(db.pool) == 0
        assert len(db.throttle) == 1

    async def test_login_throttle_purge_runs_on_a_connection(
        self, db: FakeDb, throttle: ModuleType
    ) -> None:
        self._seed(db)

        async with db.pool.acquire() as conn:
            assert await throttle.purge_expired(conn) == 2

    async def test_login_throttle_purge_of_an_empty_table_is_zero(
        self, db: FakeDb, throttle: ModuleType
    ) -> None:
        assert await throttle.purge_expired(db.pool) == 0
        assert db.matching(r"^delete from login_throttle\b") != []


def _cancelling_sleep(after: int, events: list[str] | None = None) -> AsyncMock:
    """A fake sleep that returns at once and raises CancelledError on call ``after``."""
    calls = {"count": 0}

    async def fake_sleep(delay: float, *_args: Any, **_kwargs: Any) -> None:
        calls["count"] += 1
        if events is not None:
            events.append("sleep")
        if calls["count"] >= after:
            raise asyncio.CancelledError

    return AsyncMock(side_effect=fake_sleep)


def _delay(call: Any) -> Any:
    return call.args[0] if call.args else call.kwargs["delay"]


def _executor(call: Any) -> Any:
    return call.args[0] if call.args else call.kwargs["executor"]


@pytest.fixture()
def patched_job(throttle: ModuleType) -> Callable[[AsyncMock, AsyncMock], _Patched]:
    """Patch purge_expired and the job's sleep (the module's sleep and asyncio.sleep)."""

    def apply(purge: AsyncMock, sleep: AsyncMock) -> _Patched:
        return _Patched(throttle, purge, sleep)

    return apply


class _Patched:
    """Context manager patching purge_expired, login_throttle.sleep and asyncio.sleep."""

    def __init__(self, throttle: ModuleType, purge: AsyncMock, sleep: AsyncMock) -> None:
        self._patches = [
            patch.object(throttle, "purge_expired", purge),
            patch.object(throttle, "sleep", sleep),
            patch("asyncio.sleep", sleep),
        ]

    def __enter__(self) -> None:
        for item in self._patches:
            item.start()

    def __exit__(self, *_exc: object) -> None:
        for item in reversed(self._patches):
            item.stop()


class TestPurgeJob:
    """run_purge_job purges now, then once per interval, and survives failures."""

    async def test_login_throttle_job_purges_then_sleeps_in_a_loop(
        self, throttle: ModuleType, patched_job: Callable[..., _Patched]
    ) -> None:
        events: list[str] = []

        async def fake_purge(*_args: Any, **_kwargs: Any) -> int:
            events.append("purge")
            return 0

        with (
            patched_job(AsyncMock(side_effect=fake_purge), _cancelling_sleep(3, events)),
            pytest.raises(asyncio.CancelledError),
        ):
            await throttle.run_purge_job(MagicMock())

        assert events == ["purge", "sleep", "purge", "sleep", "purge", "sleep"]

    async def test_login_throttle_job_defaults_to_the_purge_interval(
        self, throttle: ModuleType, patched_job: Callable[..., _Patched]
    ) -> None:
        pool = MagicMock(name="pool")
        purge = AsyncMock(return_value=0)
        sleep = _cancelling_sleep(2)

        with patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await throttle.run_purge_job(pool)

        interval = throttle.PURGE_INTERVAL_SECONDS
        assert [_executor(call) for call in purge.await_args_list] == [pool, pool]
        assert [_delay(call) for call in sleep.await_args_list] == [interval, interval]

    async def test_login_throttle_job_passes_a_custom_interval(
        self, throttle: ModuleType, patched_job: Callable[..., _Patched]
    ) -> None:
        sleep = _cancelling_sleep(1)

        with patched_job(AsyncMock(return_value=0), sleep), pytest.raises(asyncio.CancelledError):
            await throttle.run_purge_job(MagicMock(), interval_seconds=5)

        assert _delay(sleep.await_args_list[0]) == 5

    def test_login_throttle_job_signature(self, throttle: ModuleType) -> None:
        """run_purge_job(pool, *, interval_seconds=PURGE_INTERVAL_SECONDS)."""
        params = list(inspect.signature(throttle.run_purge_job).parameters.values())

        assert [p.name for p in params] == ["pool", "interval_seconds"]
        assert params[1].kind is inspect.Parameter.KEYWORD_ONLY
        assert params[1].default == throttle.PURGE_INTERVAL_SECONDS

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(lambda: RuntimeError(_FAILURE_MARKER), id="runtime-error"),
            pytest.param(lambda: OSError(_FAILURE_MARKER), id="os-error"),
            pytest.param(
                lambda: asyncpg.exceptions.RaiseError(_FAILURE_MARKER), id="postgres-error"
            ),
            pytest.param(lambda: TimeoutError(_FAILURE_MARKER), id="timeout"),
        ],
    )
    async def test_login_throttle_job_retries_a_failed_run(
        self,
        throttle: ModuleType,
        patched_job: Callable[..., _Patched],
        make_error: Callable[[], Exception],
    ) -> None:
        purge = AsyncMock(side_effect=[make_error(), 3])
        sleep = _cancelling_sleep(2)

        with patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await throttle.run_purge_job(MagicMock())

        interval = throttle.PURGE_INTERVAL_SECONDS
        assert purge.await_count == 2
        assert [_delay(call) for call in sleep.await_args_list] == [interval, interval]

    async def test_login_throttle_job_logs_a_failure_by_class_name_only(
        self,
        throttle: ModuleType,
        patched_job: Callable[..., _Patched],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        purge = AsyncMock(side_effect=ConnectionResetError(_FAILURE_MARKER))

        with patched_job(purge, _cancelling_sleep(1)), pytest.raises(asyncio.CancelledError):
            await throttle.run_purge_job(MagicMock())

        failures = [
            entry
            for entry in caplog.records
            if entry.levelno >= logging.WARNING and entry.name.startswith("admino")
        ]
        assert len(failures) == 1
        assert "ConnectionResetError" in failures[0].getMessage()
        assert "row-marker" not in caplog.text
        assert "throttle.marker" not in caplog.text
        assert all(entry.exc_info is None and entry.exc_text is None for entry in caplog.records)

    async def test_login_throttle_job_cancelled_purge_propagates(
        self, throttle: ModuleType, patched_job: Callable[..., _Patched]
    ) -> None:
        purge = AsyncMock(side_effect=asyncio.CancelledError)
        sleep = _cancelling_sleep(5)

        with patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await throttle.run_purge_job(MagicMock())

        assert purge.await_count == 1
        sleep.assert_not_awaited()

    async def test_login_throttle_job_task_cancel_stops_it(
        self, throttle: ModuleType, patched_job: Callable[..., _Patched]
    ) -> None:
        sleeping = asyncio.Event()

        async def blocking_sleep(_delay: float, *_args: Any, **_kwargs: Any) -> None:
            sleeping.set()
            await asyncio.Event().wait()

        with patched_job(AsyncMock(return_value=0), AsyncMock(side_effect=blocking_sleep)):
            task = asyncio.create_task(throttle.run_purge_job(MagicMock()))
            async with asyncio.timeout(5):
                await sleeping.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        assert task.cancelled()
