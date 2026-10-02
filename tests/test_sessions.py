"""Tests for admino.sessions — server-side sessions, session policies and the one
Principal builder (GH-149, GH-152, GH-162).

A login creates a ``sessions`` row holding the SHA-256 hash of a random 256-bit
token; the raw token only ever lives in the ``admino_session`` cookie. Every
request resolves the cookie back to its session, re-reading the user's row, and
builds the ``Principal`` from that row (never from request data). GH-152 adds
session policies: each row stores its own idle timeout and expiry, set at login
from the member's org policy or the platform policy of a Super Admin, and
revoking a session deletes its row.

What these tests pin down:
- Tokens: ``secrets.token_urlsafe(32)`` values (43 URL-safe characters, 256 bits),
  unique; ``hash_session_token`` is the raw SHA-256 digest.
- Policy constants: idle timeout 15 to 480 minutes (default 60), lifetime 1 to 72
  hours (default 12), ``last_seen_at`` touched at most once a minute, the purge
  running at least hourly. ``SESSION_LIFETIME`` is gone.
- ``SessionPolicy``: a SealedModel with strict int fields inside those bounds and
  ``idle_timeout`` / ``max_lifetime`` timedelta properties.
  ``DEFAULT_ORG_SESSION_POLICY`` (members, until #169) is 60 min / 12 h. GH-160
  retires ``PLATFORM_SESSION_POLICY`` and ``session_policy_for`` from this module:
  the Super Admin policy is stored in ``platform_settings`` and
  ``scoped_settings.session_policy_for`` picks a kind's policy (tested in
  tests/test_scoped_settings.py).
- ``apply_super_admin_policy(executor, policy)`` (GH-160): a coroutine issuing one
  ``UPDATE sessions SET idle_timeout_minutes = $1, expires_at = created_at +
  make_interval(hours => $2) WHERE user_id IN (SELECT id FROM users WHERE kind =
  'super_admin')`` with the policy's two ints bound (never inlined); it returns the
  updated row count. Only Super Admin sessions change; one older than the new
  lifetime, or idle past the new timeout, no longer resolves; members' sessions are
  untouched.
- ``create_session(executor, *, user_id, policy, ip, user_agent)``: one INSERT of
  token_hash, user_id, expires_at (``now() + $n::interval`` on the database clock,
  bound to the policy's lifetime), idle_timeout_minutes (the policy's), the client
  IP (NULL when it isn't an IP address) and the user agent truncated to 256
  characters. No revoked_at, created_at or last_seen_at column is written.
- ``resolve_session``: a token that isn't a plausible ``token_urlsafe(32)`` value
  returns None without a query; otherwise one ``fetchrow`` by token hash, joining
  users and (LEFT JOIN) organizations, never naming revoked_at. The decision is
  made in Python on every call: no row, expired, idle past the row's own timeout
  (``last_seen_at + idle_timeout_minutes <= now``), malformed timestamps or
  timeout, a user that isn't active or is deleted, or a member of an org that
  isn't active → None. An accepted session last seen at least a minute ago gets
  exactly one ``UPDATE sessions SET last_seen_at = now() WHERE id = $n`` (bound to
  the session id); a fresher one gets no write, and a rejected one never does.
- ``resolve_session_by_id(executor, session_id)`` (GH-162, the OAuth callback): the
  same checks and the same AuthenticatedSession as ``resolve_session``, but one
  ``fetchrow`` keyed by the session row id (``... WHERE s.id = $1``, the id bound,
  no token hash) with the same joins; an unknown, revoked, expired or idle session,
  an inactive or deleted user and an org that isn't active → None. It never writes:
  no ``UPDATE sessions`` (last_seen_at untouched), even for a session seen long ago.
- Revocation deletes rows: ``revoke_session`` by token hash, ``revoke_user_sessions``
  by user, ``revoke_org_sessions`` by the users of an org (the deactivation
  services of #164 and #154/#167), each returning the "DELETE <n>" count.
- ``purge_expired_sessions`` deletes the rows past ``expires_at`` or idle past
  their own timeout (the same ``<=`` boundary resolve_session applies) with no
  bind values; ``run_session_purge_job`` runs it now and then every interval,
  logging a failed run by exception class name only and retrying next interval.

All asyncpg calls are mocked or go to the in-memory fake of tests/db_fakes.py.
No real PostgreSQL connections are made.

Security notes:
- The raw token appears in no SQL text, no bind parameter and no log line; the
  touch is bound to the session id, never the token or its hash.
- Values travel as bind parameters, never inside the SQL text.
- A row that fails Principal validation fails closed (None), never raises.
- Logs carry no token, hash, IP, user agent or IDs (a failed purge: class name).
"""

from __future__ import annotations

import ast
import asyncio
import base64
import contextlib
import hashlib
import inspect
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from ipaddress import ip_address
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

import asyncpg
import pytest
from asyncpg.pgproto.pgproto import UUID as PgUUID  # noqa: N811
from pydantic import ValidationError

import admino.sessions as sessions_mod
from admino.access import Capability, Principal, SealedModel, can
from admino.sessions import (
    SESSION_COOKIE_NAME,
    USER_AGENT_MAX_LENGTH,
    AuthenticatedSession,
    create_session,
    hash_session_token,
    new_session_token,
    resolve_session,
    revoke_session,
)
from tests.db_fakes import (
    EXPIRED_RE,
    ID_PARAM_RE,
    IDLE_GONE_RE,
    NOW_SQL,
    ORG_ID,
    OTHER_ORG_ID,
    FakeDb,
    NowPlus,
    insert_values,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

# ---------------------------------------------------------------------------
# Constants and helpers
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_USER_ID = uuid.UUID("5f0e8a3c-1d2b-4c6e-9a7f-0b1c2d3e4f50")
_ORG_ID = uuid.UUID("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")
_SESSION_ID = uuid.UUID("0c9b8a7d-6e5f-4a3b-9c2d-1e0f9a8b7c6d")
_VALID_TOKEN = "Q" * 21 + "-" + "z" * 20 + "_"  # 43 URL-safe characters
_IP = "203.0.113.9"
_USER_AGENT = "Mozilla/5.0 (UA-marker-7731)"

# The real asyncio.sleep, kept before any test patches the module attribute.
_REAL_SLEEP = asyncio.sleep

_SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "admino"


def _norm(sql: str) -> str:
    """Collapse whitespace and lowercase, for formatting-tolerant SQL matching."""
    return re.sub(r"\s+", " ", sql).strip().lower()


def _ago(**kwargs: float) -> datetime:
    """A timezone-aware timestamp that long before now."""
    return datetime.now(UTC) - timedelta(**kwargs)


class _Executor:
    """A stand-in asyncpg executor that records every call.

    Each call is recorded as (method, sql, args). ``fetchrow`` returns the queued
    rows in order (None once exhausted); the other methods return fixed values.
    """

    def __init__(self, rows: list[dict[str, Any] | None] | None = None) -> None:
        self.calls: list[tuple[str, str, tuple[Any, ...]]] = []
        self._rows = list(rows or [])

    async def execute(self, sql: str, *args: Any) -> str:
        self.calls.append(("execute", sql, args))
        return "OK"

    async def fetchrow(self, sql: str, *args: Any) -> dict[str, Any] | None:
        self.calls.append(("fetchrow", sql, args))
        return self._rows.pop(0) if self._rows else None

    async def fetchval(self, sql: str, *args: Any) -> Any:
        self.calls.append(("fetchval", sql, args))
        return _SESSION_ID

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        self.calls.append(("fetch", sql, args))
        return []


class _StatusExecutor(_Executor):
    """An executor whose execute() answers a fixed asyncpg status string."""

    def __init__(self, status: str) -> None:
        super().__init__()
        self._status = status

    async def execute(self, sql: str, *args: Any) -> str:
        self.calls.append(("execute", sql, args))
        return self._status


def _insert_row(executor: _Executor) -> dict[str, Any]:
    """Map each column of the one INSERT INTO sessions to its bound value.

    A plain bind parameter maps to its argument; ``now() + $n::interval`` maps to
    ``NowPlus(<the bound interval>)``. Any other VALUES expression fails the test.
    """
    inserts = [c for c in executor.calls if "insert into sessions" in _norm(c[1])]
    assert len(inserts) == 1, executor.calls
    _, sql, args = inserts[0]
    return insert_values(sql, args)


def _row(**overrides: Any) -> dict[str, Any]:
    """A session row as resolve_session's query returns it: an active editor, asyncpg
    UUIDs, seen 10 seconds ago with the default 60-minute idle timeout. No revoked_at:
    migration 0009 dropped the column."""
    now = datetime.now(UTC)
    row: dict[str, Any] = {
        "session_id": PgUUID(str(_SESSION_ID)),
        "expires_at": now + timedelta(hours=11),
        "last_seen_at": now - timedelta(seconds=10),
        "idle_timeout_minutes": 60,
        "user_id": PgUUID(str(_USER_ID)),
        "kind": "member",
        "org_id": PgUUID(str(_ORG_ID)),
        "role": "editor",
        "status": "active",
        "deleted_at": None,
        "org_status": "active",
        "ui_language": "de",
        "response_language": "fr",
    }
    row.update(overrides)
    return row


def _super_admin_row(**overrides: Any) -> dict[str, Any]:
    """An active Super Admin's session row: no org, no role, no org status."""
    fields: dict[str, Any] = {
        "kind": "super_admin",
        "org_id": None,
        "role": None,
        "org_status": None,
        "ui_language": "en",
        "response_language": None,
    }
    fields.update(overrides)
    return _row(**fields)


def _all_args(executor: _Executor) -> list[Any]:
    """Every bind argument of every call."""
    return [arg for _, _, args in executor.calls for arg in args]


def _updates(executor: _Executor) -> list[tuple[str, str, tuple[Any, ...]]]:
    """Every call whose SQL is an UPDATE of the sessions table."""
    return [call for call in executor.calls if _norm(call[1]).startswith("update sessions")]


def _policy(idle: int = 60, lifetime: int = 12) -> Any:
    """A SessionPolicy, looked up at call time so this file collects before GH-152."""
    return sessions_mod.SessionPolicy(idle_timeout_minutes=idle, max_lifetime_hours=lifetime)


_SNAP = timedelta(seconds=5)


def _exactly_ago(delta: timedelta) -> datetime:
    """A timestamp exactly ``delta`` before whatever "now" the code under test reads.

    The code's own ``datetime.now(UTC)`` runs a moment after this helper, so a plain
    boundary timestamp would always be a little older than intended. The returned
    value is a datetime subclass: any plain datetime within 5 seconds of the helper's
    now counts as exactly that now when it is compared with, or subtracted from, this
    value or a value derived from it (``value + timedelta``). ``value + delta <= now``
    and ``now - value >= delta`` are therefore decided at the exact boundary, which
    catches a ``<`` written for ``<=`` (and a ``>`` written for ``>=``).
    """
    anchor = datetime.now(UTC)

    def snap(other: datetime) -> datetime:
        if isinstance(other, _Instant):
            return other.real()
        return anchor if abs(other - anchor) <= _SNAP else other

    class _Instant(datetime):
        def real(self) -> datetime:
            return datetime(
                self.year,
                self.month,
                self.day,
                self.hour,
                self.minute,
                self.second,
                self.microsecond,
                tzinfo=self.tzinfo,
            )

        @classmethod
        def of(cls, value: datetime) -> _Instant:
            return cls(
                value.year,
                value.month,
                value.day,
                value.hour,
                value.minute,
                value.second,
                value.microsecond,
                tzinfo=value.tzinfo,
            )

        def __add__(self, other: object) -> Any:
            if isinstance(other, timedelta):
                return _Instant.of(self.real() + other)
            return NotImplemented

        __radd__ = __add__

        def __sub__(self, other: object) -> Any:
            if isinstance(other, timedelta):
                return _Instant.of(self.real() - other)
            if isinstance(other, datetime):
                return self.real() - snap(other)
            return NotImplemented

        def __rsub__(self, other: object) -> Any:
            if isinstance(other, datetime):
                return snap(other) - self.real()
            return NotImplemented

        def __eq__(self, other: object) -> bool:
            return isinstance(other, datetime) and self.real() == snap(other)

        def __ne__(self, other: object) -> bool:
            return not self.__eq__(other)

        def __lt__(self, other: object) -> bool:
            assert isinstance(other, datetime)
            return self.real() < snap(other)

        def __le__(self, other: object) -> bool:
            assert isinstance(other, datetime)
            return self.real() <= snap(other)

        def __gt__(self, other: object) -> bool:
            assert isinstance(other, datetime)
            return self.real() > snap(other)

        def __ge__(self, other: object) -> bool:
            assert isinstance(other, datetime)
            return self.real() >= snap(other)

        def __hash__(self) -> int:
            return hash(self.real())

    return _Instant.of(anchor - delta)


# ---------------------------------------------------------------------------
# 1. Constants and tokens
# ---------------------------------------------------------------------------


class TestSessionConstants:
    """The cookie name, the user-agent bound and the GH-152 policy constants."""

    def test_sessions_cookie_name(self) -> None:
        """The cookie is called admino_session."""
        assert SESSION_COOKIE_NAME == "admino_session"

    def test_sessions_user_agent_bound(self) -> None:
        """User agents are stored truncated to 256 characters."""
        assert USER_AGENT_MAX_LENGTH == 256

    def test_sessions_fixed_session_lifetime_is_gone(self) -> None:
        """SESSION_LIFETIME is removed: the lifetime comes from the session's policy."""
        assert not hasattr(sessions_mod, "SESSION_LIFETIME")

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("MIN_IDLE_TIMEOUT_MINUTES", 15),
            ("MAX_IDLE_TIMEOUT_MINUTES", 480),
            ("DEFAULT_IDLE_TIMEOUT_MINUTES", 60),
            ("MIN_LIFETIME_HOURS", 1),
            ("MAX_LIFETIME_HOURS", 72),
            ("DEFAULT_LIFETIME_HOURS", 12),
        ],
    )
    def test_sessions_policy_bound_constants(self, name: str, value: int) -> None:
        """Idle 15 to 480 minutes (default 60), lifetime 1 to 72 hours (default 12)."""
        constant = getattr(sessions_mod, name)

        assert constant == value
        assert type(constant) is int

    def test_sessions_last_seen_update_interval_is_one_minute(self) -> None:
        """last_seen_at is written at most once a minute per session (throttled)."""
        assert timedelta(minutes=1) == sessions_mod.LAST_SEEN_UPDATE_INTERVAL

    def test_sessions_purge_interval_is_at_most_hourly(self) -> None:
        """The purge job runs at least hourly: an int number of seconds, 1 to 3600."""
        interval = sessions_mod.PURGE_INTERVAL_SECONDS

        assert type(interval) is int
        assert 0 < interval <= 3600


class TestSessionTokens:
    """Tokens are 256-bit, URL-safe and unique; their hash is SHA-256."""

    def test_sessions_token_is_43_url_safe_characters(self) -> None:
        """token_urlsafe(32): 43 characters from [A-Za-z0-9_-]."""
        assert _TOKEN_RE.fullmatch(new_session_token()) is not None

    def test_sessions_token_carries_256_bits(self) -> None:
        """The token decodes to 32 random bytes."""
        token = new_session_token()

        assert len(base64.urlsafe_b64decode(token + "=")) == 32

    def test_sessions_tokens_are_unique(self) -> None:
        """1000 tokens, 1000 distinct values."""
        assert len({new_session_token() for _ in range(1000)}) == 1000

    def test_sessions_token_hash_is_sha256_digest(self) -> None:
        """hash_session_token is the raw 32-byte SHA-256 of the UTF-8 token."""
        token = new_session_token()

        assert hash_session_token(token) == hashlib.sha256(token.encode()).digest()

    def test_sessions_token_hash_is_32_bytes(self) -> None:
        """bytes, 32 long (the BYTEA CHECK in migration 0007)."""
        digest = hash_session_token(_VALID_TOKEN)

        assert isinstance(digest, bytes)
        assert len(digest) == 32

    def test_sessions_token_hash_differs_per_token(self) -> None:
        """Different tokens, different hashes; the same token, the same hash."""
        assert hash_session_token("a" * 43) != hash_session_token("b" * 43)
        assert hash_session_token(_VALID_TOKEN) == hash_session_token(_VALID_TOKEN)


# ---------------------------------------------------------------------------
# 2. SessionPolicy (GH-152)
# ---------------------------------------------------------------------------


class TestSessionPolicy:
    """A validated, sealed policy: idle 15 to 480 minutes, lifetime 1 to 72 hours."""

    def test_sessions_policy_is_a_sealed_model(self) -> None:
        """SessionPolicy is a SealedModel (frozen, extra=forbid, no unvalidated build)."""
        assert issubclass(sessions_mod.SessionPolicy, SealedModel)

    def test_sessions_policy_defaults_are_60_minutes_and_12_hours(self) -> None:
        """SessionPolicy() is the documented default: 60 minutes idle, 12 hours lifetime."""
        policy = sessions_mod.SessionPolicy()

        assert (policy.idle_timeout_minutes, policy.max_lifetime_hours) == (60, 12)

    @pytest.mark.parametrize("idle", [15, 16, 60, 479, 480])
    def test_sessions_policy_accepts_idle_timeout_in_bounds(self, idle: int) -> None:
        """15 and 480 are inclusive bounds."""
        assert _policy(idle=idle).idle_timeout_minutes == idle

    @pytest.mark.parametrize("idle", [14, 481, 0, -1, -60, 10_000])
    def test_sessions_policy_refuses_idle_timeout_out_of_bounds(self, idle: int) -> None:
        """14 minutes and 481 minutes are refused."""
        with pytest.raises(ValidationError):
            _policy(idle=idle)

    @pytest.mark.parametrize("lifetime", [1, 2, 12, 71, 72])
    def test_sessions_policy_accepts_lifetime_in_bounds(self, lifetime: int) -> None:
        """1 and 72 hours are inclusive bounds."""
        assert _policy(lifetime=lifetime).max_lifetime_hours == lifetime

    @pytest.mark.parametrize("lifetime", [0, 73, -1, 1000])
    def test_sessions_policy_refuses_lifetime_out_of_bounds(self, lifetime: int) -> None:
        """0 hours and 73 hours are refused."""
        with pytest.raises(ValidationError):
            _policy(lifetime=lifetime)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            pytest.param("max_lifetime_hours", True, id="lifetime-bool"),
            pytest.param("max_lifetime_hours", 12.0, id="lifetime-float"),
            pytest.param("max_lifetime_hours", "12", id="lifetime-str"),
            pytest.param("max_lifetime_hours", b"12", id="lifetime-bytes"),
            pytest.param("max_lifetime_hours", Decimal(12), id="lifetime-decimal"),
            pytest.param("max_lifetime_hours", None, id="lifetime-none"),
            pytest.param("idle_timeout_minutes", 60.0, id="idle-float"),
            pytest.param("idle_timeout_minutes", "60", id="idle-str"),
            pytest.param("idle_timeout_minutes", b"60", id="idle-bytes"),
            pytest.param("idle_timeout_minutes", Decimal(60), id="idle-decimal"),
            pytest.param("idle_timeout_minutes", None, id="idle-none"),
        ],
    )
    def test_sessions_policy_fields_are_strict_ints(self, field: str, value: Any) -> None:
        """No lax coercion: a bool, float, string, bytes or Decimal is refused even when
        its value would be in range."""
        with pytest.raises(ValidationError):
            sessions_mod.SessionPolicy(**{field: value})

    def test_sessions_policy_refuses_unknown_fields(self) -> None:
        """extra=forbid: no smuggled settings."""
        with pytest.raises(ValidationError):
            sessions_mod.SessionPolicy(
                idle_timeout_minutes=60, max_lifetime_hours=12, absolute_timeout=True
            )

    def test_sessions_policy_is_frozen(self) -> None:
        """A policy can't be changed after validation."""
        policy = _policy()

        with pytest.raises(ValidationError):
            policy.idle_timeout_minutes = 480

    def test_sessions_policy_model_construct_is_refused(self) -> None:
        """model_construct() would skip the bounds: it raises TypeError."""
        with pytest.raises(TypeError):
            sessions_mod.SessionPolicy.model_construct(
                idle_timeout_minutes=100_000, max_lifetime_hours=10_000
            )

    def test_sessions_policy_model_copy_update_is_refused(self) -> None:
        """model_copy(update=...) would skip the bounds: it raises TypeError."""
        with pytest.raises(TypeError):
            _policy().model_copy(update={"max_lifetime_hours": 10_000})

    @pytest.mark.parametrize(("idle", "lifetime"), [(15, 1), (60, 12), (480, 72), (30, 8)])
    def test_sessions_policy_timedelta_properties(self, idle: int, lifetime: int) -> None:
        """idle_timeout = timedelta(minutes=...), max_lifetime = timedelta(hours=...)."""
        policy = _policy(idle=idle, lifetime=lifetime)

        assert policy.idle_timeout == timedelta(minutes=idle)
        assert policy.max_lifetime == timedelta(hours=lifetime)
        assert type(policy.idle_timeout) is timedelta
        assert type(policy.max_lifetime) is timedelta


# ---------------------------------------------------------------------------
# 3. The org default policy; the platform policy moved out (GH-152, GH-160)
# ---------------------------------------------------------------------------


class TestDefaultPolicies:
    """Members get the org default (until #169 stores org policies). Since GH-160 the
    Super Admin policy is a stored platform default, picked by
    scoped_settings.session_policy_for, so this module holds neither a platform policy
    nor the per-kind lookup."""

    def test_sessions_default_org_policy_is_60_minutes_and_12_hours(self) -> None:
        """DEFAULT_ORG_SESSION_POLICY is a SessionPolicy of 60 minutes idle, 12 hours."""
        policy = sessions_mod.DEFAULT_ORG_SESSION_POLICY

        assert type(policy) is sessions_mod.SessionPolicy
        assert (policy.idle_timeout_minutes, policy.max_lifetime_hours) == (60, 12)

    @pytest.mark.parametrize("name", ["PLATFORM_SESSION_POLICY", "session_policy_for"])
    def test_sessions_platform_policy_lookup_is_gone(self, name: str) -> None:
        """GH-160: both moved to the stored platform settings (scoped_settings)."""
        assert not hasattr(sessions_mod, name)


# ---------------------------------------------------------------------------
# 3b. apply_super_admin_policy: open Super Admin sessions follow a change (GH-160)
# ---------------------------------------------------------------------------

# The one statement, normalized: $1 the idle timeout, $2 the lifetime in hours
# (an int cast on either is fine).
_SUPER_ADMIN_POLICY_SQL = re.compile(
    r"update sessions set idle_timeout_minutes = \$1(?:::int(?:eger|4)?)?, "
    r"expires_at = created_at \+ make_interval\(hours => \$2(?:::int(?:eger|4)?)?\) "
    r"where user_id in \(select id from users where kind = 'super_admin'\)"
)


def _super_admin(db: FakeDb) -> uuid.UUID:
    """An active Super Admin account."""
    return db.add_account(kind="super_admin", role=None)


class TestApplySuperAdminPolicy:
    """One parameterized UPDATE gives every open Super Admin session the new idle timeout
    and ``expires_at = created_at + <lifetime>``; members' sessions are never touched."""

    def test_sessions_apply_super_admin_policy_is_a_coroutine(self) -> None:
        assert inspect.iscoroutinefunction(sessions_mod.apply_super_admin_policy)

    async def test_sessions_apply_super_admin_policy_issues_the_exact_update(self) -> None:
        """One execute(): the UPDATE of the issue, the policy's two ints bound as $1, $2."""
        executor = _StatusExecutor("UPDATE 2")

        await sessions_mod.apply_super_admin_policy(executor, _policy(idle=30, lifetime=4))

        assert len(executor.calls) == 1, executor.calls
        method, sql, args = executor.calls[0]
        assert method == "execute"
        assert _SUPER_ADMIN_POLICY_SQL.fullmatch(_norm(sql)), sql
        assert args == (30, 4)
        assert [type(arg) for arg in args] == [int, int]

    @pytest.mark.parametrize(
        ("status", "count"), [("UPDATE 0", 0), ("UPDATE 1", 1), ("UPDATE 17", 17)]
    )
    async def test_sessions_apply_super_admin_policy_returns_the_updated_count(
        self, status: str, count: int
    ) -> None:
        executor = _StatusExecutor(status)

        result = await sessions_mod.apply_super_admin_policy(executor, _policy())

        assert result == count
        assert type(result) is int

    async def test_sessions_apply_super_admin_policy_never_inlines_the_values(self) -> None:
        executor = _StatusExecutor("UPDATE 1")

        await sessions_mod.apply_super_admin_policy(executor, _policy(idle=437, lifetime=61))

        _, sql, args = executor.calls[0]
        assert "437" not in sql
        assert "61" not in sql
        assert args == (437, 61)

    async def test_sessions_apply_super_admin_policy_retimes_only_super_admin_sessions(
        self,
    ) -> None:
        db = FakeDb()
        admin = _super_admin(db)
        other = _super_admin(db)
        member = db.add_account(role="org_admin")
        tokens = [db.open_session(admin), db.open_session(other), db.open_session(other)]
        member_token = db.open_session(member)
        member_before = dict(db.session(member_token))

        count = await sessions_mod.apply_super_admin_policy(db.pool, _policy(idle=30, lifetime=4))

        assert count == 3
        for token in tokens:
            row = db.session(token)
            assert row["idle_timeout_minutes"] == 30
            assert row["expires_at"] == row["created_at"] + timedelta(hours=4)
        assert db.session(member_token) == member_before

    async def test_sessions_apply_super_admin_policy_without_super_admin_sessions_is_zero(
        self,
    ) -> None:
        db = FakeDb()
        _super_admin(db)
        member_token = db.open_session(db.add_account(role="editor"))
        member_before = dict(db.session(member_token))

        count = await sessions_mod.apply_super_admin_policy(db.pool, _policy(idle=30, lifetime=4))

        assert count == 0
        assert db.session(member_token) == member_before

    async def test_sessions_apply_super_admin_policy_ends_a_session_older_than_the_lifetime(
        self,
    ) -> None:
        """Opened 5 hours ago: live under 12 hours, its expiry in the past under 4."""
        db = FakeDb()
        token = db.open_session(_super_admin(db))
        row = db.session(token)
        row["created_at"] = _ago(hours=5)
        row["expires_at"] = row["created_at"] + timedelta(hours=12)
        assert await resolve_session(db.pool, token) is not None

        await sessions_mod.apply_super_admin_policy(db.pool, _policy(idle=60, lifetime=4))

        assert db.session(token)["expires_at"] <= datetime.now(UTC)
        assert await resolve_session(db.pool, token) is None

    async def test_sessions_apply_super_admin_policy_ends_a_session_idle_past_the_timeout(
        self,
    ) -> None:
        """Seen 40 minutes ago: gone under a 30-minute idle timeout; a member seen as long
        ago keeps their session."""
        db = FakeDb()
        token = db.open_session(_super_admin(db), last_seen_ago=timedelta(minutes=40))
        member_token = db.open_session(
            db.add_account(role="editor"), last_seen_ago=timedelta(minutes=40)
        )

        await sessions_mod.apply_super_admin_policy(db.pool, _policy(idle=30, lifetime=12))

        assert await resolve_session(db.pool, token) is None
        assert await resolve_session(db.pool, member_token) is not None

    async def test_sessions_apply_super_admin_policy_keeps_a_session_inside_the_policy(
        self,
    ) -> None:
        db = FakeDb()
        admin = _super_admin(db)
        token = db.open_session(admin)

        await sessions_mod.apply_super_admin_policy(db.pool, _policy(idle=30, lifetime=4))

        resolved = await resolve_session(db.pool, token)
        assert resolved is not None
        assert resolved.principal.user_id == admin


# ---------------------------------------------------------------------------
# 4. create_session
# ---------------------------------------------------------------------------


async def _create(**overrides: Any) -> tuple[str, _Executor]:
    """Run create_session with defaults (the default policy); return the token and the
    executor."""
    executor = _Executor()
    kwargs: dict[str, Any] = {
        "user_id": _USER_ID,
        "policy": sessions_mod.SessionPolicy(),
        "ip": _IP,
        "user_agent": "Mozilla/5.0 (test)",
    }
    kwargs.update(overrides)
    token = await create_session(executor, **kwargs)
    return token, executor


class TestCreateSession:
    """create_session issues one parameterized INSERT and returns the raw token."""

    async def test_sessions_create_returns_a_url_safe_token(self) -> None:
        """The returned token is a token_urlsafe(32) value."""
        token, _ = await _create()

        assert _TOKEN_RE.fullmatch(token) is not None

    async def test_sessions_create_issues_exactly_one_insert(self) -> None:
        """One statement, and it is the INSERT INTO sessions."""
        _, executor = await _create()

        assert len(executor.calls) == 1
        assert "insert into sessions" in _norm(executor.calls[0][1])

    async def test_sessions_create_inserts_exactly_the_session_columns(self) -> None:
        """token_hash, user_id, expires_at, idle_timeout_minutes, ip and user_agent: no
        revoked_at (dropped), and created_at / last_seen_at keep their DB defaults."""
        _, executor = await _create()

        assert set(_insert_row(executor)) == {
            "token_hash",
            "user_id",
            "expires_at",
            "idle_timeout_minutes",
            "ip",
            "user_agent",
        }

    async def test_sessions_create_stores_the_token_hash(self) -> None:
        """token_hash is sha256(token), bound as a parameter."""
        token, executor = await _create()

        assert _insert_row(executor)["token_hash"] == hash_session_token(token)

    async def test_sessions_create_never_stores_the_raw_token(self) -> None:
        """The raw token is in no bind parameter and not in the SQL text."""
        token, executor = await _create()

        assert all(token not in str(arg) for arg in _all_args(executor))
        assert token not in executor.calls[0][1]

    async def test_sessions_create_binds_values_never_inlines_them(self) -> None:
        """The user id and the hash travel as bind parameters, not inside the SQL."""
        token, executor = await _create()
        sql = executor.calls[0][1]

        assert str(_USER_ID) not in sql
        assert hash_session_token(token).hex() not in sql
        assert "$1" in sql

    async def test_sessions_create_stores_the_user_id(self) -> None:
        """user_id is the account the session belongs to."""
        _, executor = await _create()

        assert _insert_row(executor)["user_id"] == _USER_ID

    async def test_sessions_create_default_policy_is_12_hours_and_60_minutes(self) -> None:
        """With SessionPolicy(): expires_at = now() + 12 hours, idle_timeout_minutes = 60."""
        _, executor = await _create()

        row = _insert_row(executor)
        assert row["expires_at"] == NowPlus(timedelta(hours=12))
        assert row["idle_timeout_minutes"] == 60

    @pytest.mark.parametrize("lifetime", [1, 8, 12, 72])
    async def test_sessions_create_expiry_is_the_policy_lifetime_on_the_db_clock(
        self, lifetime: int
    ) -> None:
        """expires_at is ``now() + $n::interval`` (the database clock, so the 72-hour
        CHECK against created_at holds under clock skew), bound to policy.max_lifetime as
        a timedelta."""
        _, executor = await _create(policy=_policy(lifetime=lifetime))

        expires_at = _insert_row(executor)["expires_at"]
        assert expires_at == NowPlus(timedelta(hours=lifetime))
        assert type(expires_at.interval) is timedelta

    @pytest.mark.parametrize("idle", [15, 30, 60, 480])
    async def test_sessions_create_stores_the_policy_idle_timeout(self, idle: int) -> None:
        """idle_timeout_minutes is bound to policy.idle_timeout_minutes (an int)."""
        _, executor = await _create(policy=_policy(idle=idle))

        stored = _insert_row(executor)["idle_timeout_minutes"]
        assert stored == idle
        assert type(stored) is int

    async def test_sessions_create_binds_no_python_timestamp(self) -> None:
        """No datetime computed in Python is bound: the expiry comes from now()."""
        _, executor = await _create()

        assert [arg for arg in _all_args(executor) if isinstance(arg, datetime)] == []

    @pytest.mark.parametrize("ip", ["203.0.113.9", "2001:db8::1", "10.0.0.1"])
    async def test_sessions_create_keeps_a_valid_ip(self, ip: str) -> None:
        """An IPv4 or IPv6 client address is stored."""
        _, executor = await _create(ip=ip)

        stored = _insert_row(executor)["ip"]
        assert stored is not None
        assert ip_address(str(stored)) == ip_address(ip)

    @pytest.mark.parametrize("ip", ["testclient", "not-an-ip", "", "999.1.1.1", None])
    async def test_sessions_create_stores_null_for_a_non_ip(self, ip: str | None) -> None:
        """A peer that isn't an IP address (e.g. TestClient's 'testclient') is NULL."""
        _, executor = await _create(ip=ip)

        assert _insert_row(executor)["ip"] is None

    async def test_sessions_create_truncates_the_user_agent(self) -> None:
        """A 300-character user agent is stored as its first 256 characters."""
        user_agent = "".join(chr(ord("a") + i % 26) for i in range(300))
        _, executor = await _create(user_agent=user_agent)

        assert _insert_row(executor)["user_agent"] == user_agent[:256]

    async def test_sessions_create_truncates_by_characters(self) -> None:
        """Truncation counts characters (the CHECK uses char_length), not bytes."""
        _, executor = await _create(user_agent="é" * 300)

        assert _insert_row(executor)["user_agent"] == "é" * 256

    @pytest.mark.parametrize("length", [0, 1, 255, 256])
    async def test_sessions_create_keeps_a_short_user_agent(self, length: int) -> None:
        """Up to 256 characters are stored unchanged."""
        user_agent = "u" * length
        _, executor = await _create(user_agent=user_agent)

        assert _insert_row(executor)["user_agent"] == user_agent

    async def test_sessions_create_keeps_a_missing_user_agent_null(self) -> None:
        """No user agent → NULL."""
        _, executor = await _create(user_agent=None)

        assert _insert_row(executor)["user_agent"] is None

    async def test_sessions_create_returns_a_new_token_each_call(self) -> None:
        """Two sessions for the same user get different tokens and hashes."""
        first, first_executor = await _create()
        second, second_executor = await _create()

        assert first != second
        assert (
            _insert_row(first_executor)["token_hash"] != _insert_row(second_executor)["token_hash"]
        )

    async def test_sessions_create_never_logs_the_token(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No log line (at any level) carries the raw token."""
        caplog.set_level(logging.DEBUG)

        token, _ = await _create()

        assert token not in caplog.text

    def test_sessions_create_takes_keyword_only_values_and_requires_a_policy(self) -> None:
        """create_session(executor, *, user_id, policy, ip, user_agent): the policy is a
        required keyword (no default, so no session is opened without one)."""
        params = list(inspect.signature(create_session).parameters.values())

        assert params[0].name == "executor"
        assert {p.name for p in params[1:]} == {"user_id", "policy", "ip", "user_agent"}
        assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in params[1:])
        policy = next(p for p in params if p.name == "policy")
        assert policy.default is inspect.Parameter.empty

    async def test_sessions_create_without_a_policy_raises_before_any_statement(self) -> None:
        """Omitting the policy is a TypeError and nothing is written."""
        executor = _Executor()

        with pytest.raises(TypeError):
            await create_session(executor, user_id=_USER_ID, ip=_IP, user_agent=None)

        assert executor.calls == []


# ---------------------------------------------------------------------------
# 5. resolve_session — shape of the lookup
# ---------------------------------------------------------------------------

_MALFORMED_TOKENS: list[Any] = [
    pytest.param("", id="empty"),
    pytest.param("short", id="short"),
    pytest.param("a" * 42, id="42-chars"),
    pytest.param("a" * 44, id="44-chars"),
    pytest.param("a" * 42 + "=", id="padding"),
    pytest.param("a" * 42 + "+", id="plus"),
    pytest.param("a" * 42 + "/", id="slash"),
    pytest.param("a" * 42 + ".", id="dot"),
    pytest.param("a" * 43 + "\n", id="trailing-newline"),
    pytest.param(" " + "a" * 42, id="leading-space"),
    pytest.param("a" * 42 + " ", id="trailing-space"),
    pytest.param("é" * 43, id="non-ascii"),
    pytest.param("a" * 20 + "'" + "a" * 22, id="quote"),
    pytest.param("a" * 10_000, id="huge"),
]


class TestResolveSessionLookup:
    """One parameterized fetchrow by token hash; malformed tokens never reach the DB."""

    @pytest.mark.parametrize("token", _MALFORMED_TOKENS)
    async def test_sessions_resolve_malformed_token_returns_none_without_query(
        self, token: str
    ) -> None:
        """Anything that isn't ^[A-Za-z0-9_-]{43}$ returns None and issues no query."""
        executor = _Executor([_row()])

        assert await resolve_session(executor, token) is None
        assert executor.calls == []

    async def test_sessions_resolve_issues_one_fetchrow(self) -> None:
        """A well-formed token of a session seen seconds ago costs exactly one fetchrow."""
        executor = _Executor([_row()])

        await resolve_session(executor, _VALID_TOKEN)

        assert [method for method, _, _ in executor.calls] == ["fetchrow"]

    async def test_sessions_resolve_looks_up_by_token_hash(self) -> None:
        """The token's SHA-256 digest is a bind parameter; the raw token is not."""
        executor = _Executor([_row()])

        await resolve_session(executor, _VALID_TOKEN)

        _, sql, args = executor.calls[0]
        assert hash_session_token(_VALID_TOKEN) in args
        assert all(_VALID_TOKEN not in str(arg) for arg in args)
        assert _VALID_TOKEN not in sql
        assert hash_session_token(_VALID_TOKEN).hex() not in sql

    async def test_sessions_resolve_joins_users_and_left_joins_organizations(self) -> None:
        """The session, its users row and (LEFT JOIN: Super Admins have none) its org."""
        executor = _Executor([_row()])

        await resolve_session(executor, _VALID_TOKEN)

        sql = _norm(executor.calls[0][1])
        assert re.search(r"\bfrom sessions\b", sql) is not None
        assert re.search(r"\bjoin users\b", sql) is not None
        assert re.search(r"\bleft (?:outer )?join organizations\b", sql) is not None

    async def test_sessions_resolve_reads_last_seen_and_idle_timeout(self) -> None:
        """The row's own last_seen_at and idle_timeout_minutes are selected (GH-152)."""
        executor = _Executor([_row()])

        await resolve_session(executor, _VALID_TOKEN)

        sql = _norm(executor.calls[0][1])
        assert re.search(r"\blast_seen_at\b", sql) is not None
        assert re.search(r"\bidle_timeout_minutes\b", sql) is not None

    async def test_sessions_resolve_never_names_revoked_at(self) -> None:
        """Migration 0009 dropped revoked_at: revoking deletes the row, so the lookup
        can't read it."""
        executor = _Executor([_row()])

        await resolve_session(executor, _VALID_TOKEN)

        assert "revoked_at" not in _norm(executor.calls[0][1])

    async def test_sessions_resolve_unknown_token_returns_none(self) -> None:
        """No row (never existed, revoked or purged) → None."""
        assert await resolve_session(_Executor([None]), _VALID_TOKEN) is None

    def test_sessions_resolve_takes_only_the_executor_and_token(self) -> None:
        """Nothing from the request (body, headers, claimed role) can reach the Principal."""
        assert list(inspect.signature(resolve_session).parameters) == ["executor", "token"]

    async def test_sessions_resolve_never_logs_the_token(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No log line carries the raw token, found or not."""
        caplog.set_level(logging.DEBUG)

        await resolve_session(_Executor([_row()]), _VALID_TOKEN)
        await resolve_session(_Executor([None]), _VALID_TOKEN)

        assert _VALID_TOKEN not in caplog.text


# ---------------------------------------------------------------------------
# 6. resolve_session — the decision (re-made in Python on every call)
# ---------------------------------------------------------------------------


# Each case builds its row when the test runs (never at collection), so the
# timestamps are relative to the moment of the call. A case takes the row's
# last_seen_at (``seen``) unless it sets its own: the touch tests pass 5 minutes
# ago, so a usable session would be touched and a rejected one must not be.
def _naive(value: datetime) -> datetime:
    """The same wall time without a timezone (a malformed row value)."""
    return value.replace(tzinfo=None)


_REJECTED_ROWS: list[Any] = [
    pytest.param(lambda seen: _row(last_seen_at=seen, expires_at=_ago(seconds=1)), id="expired"),
    pytest.param(lambda seen: _row(last_seen_at=seen, expires_at=_ago(days=30)), id="long-expired"),
    pytest.param(lambda seen: _row(last_seen_at=seen, expires_at=None), id="expires-at-missing"),
    pytest.param(
        lambda seen: _row(last_seen_at=seen, expires_at=_naive(_ago(hours=-1))),
        id="expires-at-naive",
    ),
    pytest.param(
        lambda seen: _row(last_seen_at=seen, expires_at="2999-01-01T00:00:00+00:00"),
        id="expires-at-string",
    ),
    pytest.param(
        lambda _seen: _row(idle_timeout_minutes=60, last_seen_at=_ago(minutes=61)), id="idle-60"
    ),
    pytest.param(
        lambda _seen: _row(idle_timeout_minutes=15, last_seen_at=_ago(minutes=16)), id="idle-15"
    ),
    pytest.param(
        lambda _seen: _row(idle_timeout_minutes=480, last_seen_at=_ago(hours=8, minutes=1)),
        id="idle-480",
    ),
    pytest.param(
        lambda _seen: _row(idle_timeout_minutes=60, last_seen_at=_ago(days=1)),
        id="idle-for-a-day",
    ),
    pytest.param(lambda _seen: _row(last_seen_at=None), id="last-seen-missing"),
    pytest.param(lambda seen: _row(last_seen_at=_naive(seen)), id="last-seen-naive"),
    pytest.param(
        lambda _seen: _row(last_seen_at="2026-01-01T00:00:00+00:00"), id="last-seen-string"
    ),
    pytest.param(
        lambda seen: _row(last_seen_at=seen, idle_timeout_minutes=None),
        id="idle-timeout-missing",
    ),
    pytest.param(
        lambda seen: _row(last_seen_at=seen, idle_timeout_minutes="60"), id="idle-timeout-string"
    ),
    pytest.param(
        lambda seen: _row(last_seen_at=seen, idle_timeout_minutes=60.0), id="idle-timeout-float"
    ),
    pytest.param(
        lambda seen: _row(last_seen_at=seen, idle_timeout_minutes=True), id="idle-timeout-bool"
    ),
    pytest.param(lambda seen: _row(last_seen_at=seen, status="deactivated"), id="user-deactivated"),
    pytest.param(lambda seen: _row(last_seen_at=seen, status="invited"), id="user-invited"),
    pytest.param(lambda seen: _row(last_seen_at=seen, status="unknown"), id="user-status-unknown"),
    pytest.param(lambda seen: _row(last_seen_at=seen, deleted_at=_ago(days=1)), id="user-deleted"),
    pytest.param(
        lambda seen: _row(last_seen_at=seen, org_status="deactivated"), id="org-deactivated"
    ),
    pytest.param(
        lambda seen: _row(last_seen_at=seen, org_status="pending_deletion"),
        id="org-pending-deletion",
    ),
    pytest.param(lambda seen: _row(last_seen_at=seen, org_status=None), id="member-org-missing"),
    pytest.param(
        lambda seen: _super_admin_row(last_seen_at=seen, status="deactivated"),
        id="super-admin-deactivated",
    ),
    pytest.param(
        lambda seen: _super_admin_row(last_seen_at=seen, deleted_at=_ago(days=1)),
        id="super-admin-deleted",
    ),
]

# Rows whose account fields can't form a valid Principal: fail closed.
_INVALID_PRINCIPAL_ROWS: list[Any] = [
    pytest.param(lambda seen: _row(last_seen_at=seen, org_id=None), id="member-without-org"),
    pytest.param(lambda seen: _row(last_seen_at=seen, role=None), id="member-without-role"),
    pytest.param(lambda seen: _row(last_seen_at=seen, role="owner"), id="member-unknown-role"),
    pytest.param(lambda seen: _row(last_seen_at=seen, kind="root"), id="unknown-kind"),
    pytest.param(
        lambda seen: _super_admin_row(last_seen_at=seen, role="org_admin"),
        id="super-admin-with-role",
    ),
    pytest.param(
        lambda seen: _super_admin_row(
            last_seen_at=seen, org_id=PgUUID(str(_ORG_ID)), org_status="active"
        ),
        id="super-admin-with-org",
    ),
]


class TestResolveSessionRejects:
    """Every non-usable session resolves to None."""

    @pytest.mark.parametrize("make_row", _REJECTED_ROWS)
    async def test_sessions_resolve_rejects(
        self, make_row: Callable[[datetime], dict[str, Any]]
    ) -> None:
        """Expired, idle past its own timeout, malformed timestamps or timeout, an inactive
        or deleted user, an inactive org → None."""
        row = make_row(_ago(seconds=10))

        assert await resolve_session(_Executor([row]), _VALID_TOKEN) is None

    @pytest.mark.parametrize("make_row", _INVALID_PRINCIPAL_ROWS)
    async def test_sessions_resolve_invalid_principal_row_fails_closed(
        self, make_row: Callable[[datetime], dict[str, Any]]
    ) -> None:
        """A row that fails Principal validation returns None instead of raising."""
        row = make_row(_ago(seconds=10))

        assert await resolve_session(_Executor([row]), _VALID_TOKEN) is None

    @pytest.mark.parametrize("idle", [15, 60, 480])
    async def test_sessions_resolve_idle_boundary_is_refused(self, idle: int) -> None:
        """Exactly idle_timeout_minutes after last_seen_at the session is gone:
        ``last_seen_at + idle <= now`` means idle (the same boundary as the purge)."""
        row = _row(idle_timeout_minutes=idle, last_seen_at=_exactly_ago(timedelta(minutes=idle)))

        assert await resolve_session(_Executor([row]), _VALID_TOKEN) is None

    async def test_sessions_resolve_uses_the_rows_idle_timeout_not_the_default(self) -> None:
        """A 15-minute session last seen 16 minutes ago is idle although 16 minutes is well
        inside the 60-minute default."""
        row = _row(idle_timeout_minutes=15, last_seen_at=_ago(minutes=16))

        assert await resolve_session(_Executor([row]), _VALID_TOKEN) is None


# Accepted at the edge of the row's own idle timeout (idle, last seen this long ago).
_IDLE_ACCEPTED: list[Any] = [
    pytest.param(15, timedelta(minutes=14), id="idle-15-seen-14-min-ago"),
    pytest.param(60, timedelta(minutes=59), id="idle-60-seen-59-min-ago"),
    pytest.param(480, timedelta(hours=7, minutes=59), id="idle-480-seen-7h59-ago"),
    pytest.param(480, timedelta(hours=2), id="idle-480-seen-2h-ago"),
    pytest.param(60, timedelta(0), id="seen-just-now"),
]


class TestResolveSessionAccepts:
    """An active member or Super Admin gets an AuthenticatedSession built from the row."""

    @pytest.mark.parametrize("role", ["org_admin", "editor", "viewer"])
    async def test_sessions_resolve_active_member(self, role: str) -> None:
        """The Principal is the row's user, kind, org and role."""
        session = await resolve_session(_Executor([_row(role=role)]), _VALID_TOKEN)

        assert session is not None
        assert session.principal == Principal(
            user_id=_USER_ID, kind="member", org_id=_ORG_ID, role=role
        )

    @pytest.mark.parametrize(("idle", "seen_ago"), _IDLE_ACCEPTED)
    async def test_sessions_resolve_accepts_inside_the_rows_idle_timeout(
        self, idle: int, seen_ago: timedelta
    ) -> None:
        """Inside the row's own timeout the session is usable (480 minutes allows a
        session last seen almost 8 hours ago)."""
        row = _row(idle_timeout_minutes=idle, last_seen_at=datetime.now(UTC) - seen_ago)

        session = await resolve_session(_Executor([row]), _VALID_TOKEN)

        assert session is not None
        assert session.session_id == _SESSION_ID

    async def test_sessions_resolve_carries_session_id_and_languages(self) -> None:
        """session_id, ui_language and response_language come from the row."""
        session = await resolve_session(_Executor([_row()]), _VALID_TOKEN)

        assert session is not None
        assert session.session_id == _SESSION_ID
        assert (session.ui_language, session.response_language) == ("de", "fr")

    async def test_sessions_resolve_active_super_admin(self) -> None:
        """A Super Admin (no org, LEFT JOIN gives no org status) resolves: no org, no role."""
        session = await resolve_session(_Executor([_super_admin_row()]), _VALID_TOKEN)

        assert session is not None
        assert session.principal == Principal(user_id=_USER_ID, kind="super_admin")
        assert (session.ui_language, session.response_language) == ("en", None)

    async def test_sessions_resolve_returns_an_authenticated_session(self) -> None:
        """The result is an AuthenticatedSession (a SealedModel) with an exact Principal."""
        session = await resolve_session(_Executor([_row()]), _VALID_TOKEN)

        assert type(session) is AuthenticatedSession
        assert type(session.principal) is Principal

    async def test_sessions_resolve_principal_ids_are_plain_uuids(self) -> None:
        """asyncpg's UUID subclass never reaches the Principal: plain uuid.UUID fields."""
        session = await resolve_session(_Executor([_row()]), _VALID_TOKEN)

        assert session is not None
        assert type(session.principal.user_id) is uuid.UUID
        assert type(session.principal.org_id) is uuid.UUID

    @pytest.mark.parametrize(
        ("role", "allowed"), [("org_admin", True), ("editor", True), ("viewer", False)]
    )
    async def test_sessions_resolve_principal_passes_can_for_its_role(
        self, role: str, allowed: bool
    ) -> None:
        """A member built from asyncpg UUIDs gets its role's capabilities (the #145 bug)."""
        session = await resolve_session(_Executor([_row(role=role)]), _VALID_TOKEN)

        assert session is not None
        assert can(session.principal, Capability.CHAT_SEND) is allowed
        assert can(session.principal, Capability.ACCOUNT_MANAGE) is True

    async def test_sessions_resolve_super_admin_passes_can(self) -> None:
        """The Super Admin keeps its platform capabilities and gets no content ones."""
        session = await resolve_session(_Executor([_super_admin_row()]), _VALID_TOKEN)

        assert session is not None
        assert can(session.principal, Capability.ORG_CREATE) is True
        assert can(session.principal, Capability.CHAT_SEND) is False

    async def test_sessions_resolve_session_is_sealed(self) -> None:
        """AuthenticatedSession is a SealedModel: frozen, no unvalidated construction."""
        session = await resolve_session(_Executor([_row()]), _VALID_TOKEN)

        assert isinstance(session, SealedModel)
        with pytest.raises(TypeError):
            AuthenticatedSession.model_construct(
                session_id=_SESSION_ID,
                principal=Principal(user_id=_USER_ID, kind="super_admin"),
                ui_language="en",
                response_language=None,
            )


# ---------------------------------------------------------------------------
# 7. resolve_session — the throttled last_seen_at touch
# ---------------------------------------------------------------------------


def _touch_where(call: tuple[str, str, tuple[Any, ...]]) -> str:
    """The WHERE clause of a touch, after checking that it only sets last_seen_at = now()."""
    sql = _norm(call[1])
    match = re.fullmatch(rf"update\s+sessions\s+set\s+last_seen_at = {NOW_SQL} where (.+)", sql)
    assert match is not None, sql
    return match.group(1)


class TestResolveSessionTouch:
    """An accepted session last seen at least a minute ago gets one last_seen_at write."""

    @pytest.mark.parametrize(
        ("idle", "seen_ago"),
        [
            pytest.param(60, timedelta(minutes=5), id="5-min"),
            pytest.param(60, timedelta(minutes=1, seconds=1), id="61-s"),
            pytest.param(60, timedelta(minutes=59), id="59-min"),
            pytest.param(480, timedelta(hours=7), id="7-h-of-480-min"),
        ],
    )
    async def test_sessions_resolve_touches_a_session_seen_a_minute_or_more_ago(
        self, idle: int, seen_ago: timedelta
    ) -> None:
        """The fetchrow, then exactly one UPDATE sessions; the session is still returned."""
        row = _row(idle_timeout_minutes=idle, last_seen_at=datetime.now(UTC) - seen_ago)
        executor = _Executor([row])

        session = await resolve_session(executor, _VALID_TOKEN)

        assert session is not None
        assert len(executor.calls) == 2
        assert executor.calls[0][0] == "fetchrow"
        assert len(_updates(executor)) == 1
        assert executor.calls[1] is _updates(executor)[0]

    async def test_sessions_resolve_touch_sets_last_seen_now_by_session_id(self) -> None:
        """UPDATE sessions SET last_seen_at = now() WHERE id = $n, $n bound to the session
        id: the database clock, one column, one row."""
        executor = _Executor([_row(last_seen_at=_ago(minutes=5))])

        await resolve_session(executor, _VALID_TOKEN)

        touch = _updates(executor)[0]
        where = _touch_where(touch)
        match = re.search(ID_PARAM_RE, where)
        assert match is not None, where
        assert str(touch[2][int(match.group(1)) - 1]) == str(_SESSION_ID)

    async def test_sessions_resolve_touch_never_carries_the_token_or_its_hash(self) -> None:
        """The touch is keyed by the session id: neither the token nor its hash is bound
        or named."""
        executor = _Executor([_row(last_seen_at=_ago(minutes=5))])

        await resolve_session(executor, _VALID_TOKEN)

        _, sql, args = _updates(executor)[0]
        assert "token_hash" not in _norm(sql)
        assert all(not isinstance(arg, bytes | bytearray) for arg in args)
        assert all(_VALID_TOKEN not in str(arg) for arg in args)
        assert str(_SESSION_ID) not in sql

    @pytest.mark.parametrize(
        "seen_ago",
        [
            pytest.param(timedelta(0), id="just-now"),
            pytest.param(timedelta(seconds=10), id="10-s"),
            pytest.param(timedelta(seconds=30), id="30-s"),
            pytest.param(timedelta(seconds=55), id="55-s"),
        ],
    )
    async def test_sessions_resolve_fresh_session_is_not_written(self, seen_ago: timedelta) -> None:
        """Under a minute since the last touch: only the fetchrow, no write at all."""
        executor = _Executor([_row(last_seen_at=datetime.now(UTC) - seen_ago)])

        session = await resolve_session(executor, _VALID_TOKEN)

        assert session is not None
        assert [method for method, _, _ in executor.calls] == ["fetchrow"]

    async def test_sessions_resolve_touch_boundary_is_one_minute(self) -> None:
        """Exactly LAST_SEEN_UPDATE_INTERVAL after the last touch the session is written
        (now - last_seen_at >= one minute)."""
        executor = _Executor([_row(last_seen_at=_exactly_ago(timedelta(minutes=1)))])

        session = await resolve_session(executor, _VALID_TOKEN)

        assert session is not None
        assert len(_updates(executor)) == 1

    @pytest.mark.parametrize("make_row", [*_REJECTED_ROWS, *_INVALID_PRINCIPAL_ROWS])
    async def test_sessions_resolve_rejected_session_is_never_touched(
        self, make_row: Callable[[datetime], dict[str, Any]]
    ) -> None:
        """A session that resolves to None (last seen 5 minutes ago unless the case says
        otherwise) gets no UPDATE and no other write."""
        executor = _Executor([make_row(_ago(minutes=5))])

        assert await resolve_session(executor, _VALID_TOKEN) is None
        assert [method for method, _, _ in executor.calls] == ["fetchrow"]

    async def test_sessions_resolve_touch_logs_nothing_identifying(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The touch logs neither the token, its hash nor the session id."""
        caplog.set_level(logging.DEBUG)

        await resolve_session(_Executor([_row(last_seen_at=_ago(minutes=5))]), _VALID_TOKEN)

        assert _VALID_TOKEN not in caplog.text
        assert hash_session_token(_VALID_TOKEN).hex() not in caplog.text
        assert str(_SESSION_ID) not in caplog.text


# ---------------------------------------------------------------------------
# 8. An already-open session is rejected once the user, the org or the session changes
# ---------------------------------------------------------------------------


class TestResolveSessionAlreadyOpen:
    """The row is re-read on every call, so a deactivation takes effect at once."""

    @pytest.mark.parametrize(
        "change",
        [
            pytest.param({"status": "deactivated"}, id="user-deactivated"),
            pytest.param({"deleted_at": datetime.now(UTC)}, id="user-deleted"),
            pytest.param({"org_status": "deactivated"}, id="org-deactivated"),
            pytest.param({"org_status": "pending_deletion"}, id="org-pending-deletion"),
        ],
    )
    async def test_sessions_open_session_rejected_after_change(
        self, change: dict[str, Any]
    ) -> None:
        """The same token resolves, then the re-read row shows the change → None."""
        executor = _Executor([_row(), _row(**change)])

        first = await resolve_session(executor, _VALID_TOKEN)
        second = await resolve_session(executor, _VALID_TOKEN)

        assert first is not None
        assert second is None
        assert [method for method, _, _ in executor.calls] == ["fetchrow", "fetchrow"]

    async def test_sessions_open_session_rejected_once_its_row_is_deleted(self) -> None:
        """Revoking deletes the row: the next resolve finds nothing → None."""
        executor = _Executor([_row(), None])

        first = await resolve_session(executor, _VALID_TOKEN)
        second = await resolve_session(executor, _VALID_TOKEN)

        assert first is not None
        assert second is None

    async def test_sessions_open_session_rejected_once_it_goes_idle(self) -> None:
        """The same session, re-read after its idle timeout passed → None."""
        executor = _Executor([_row(), _row(last_seen_at=_ago(minutes=61))])

        first = await resolve_session(executor, _VALID_TOKEN)
        second = await resolve_session(executor, _VALID_TOKEN)

        assert first is not None
        assert second is None

    async def test_sessions_role_change_takes_effect_on_the_next_request(self) -> None:
        """A demotion (editor → viewer) shows on the next resolve: nothing is cached."""
        executor = _Executor([_row(role="editor"), _row(role="viewer")])

        first = await resolve_session(executor, _VALID_TOKEN)
        second = await resolve_session(executor, _VALID_TOKEN)

        assert first is not None
        assert second is not None
        assert (first.principal.role, second.principal.role) == ("editor", "viewer")


# ---------------------------------------------------------------------------
# 9. revoke_session: logout deletes the row
# ---------------------------------------------------------------------------


class TestRevokeSession:
    """revoke_session deletes the session's row through one parameterized DELETE."""

    async def test_sessions_revoke_issues_one_delete(self) -> None:
        """DELETE FROM sessions WHERE token_hash = $1 (no UPDATE, no revoked_at)."""
        executor = _StatusExecutor("DELETE 1")

        result = await revoke_session(executor, _VALID_TOKEN)

        assert result is None
        assert len(executor.calls) == 1
        sql = _norm(executor.calls[0][1])
        assert re.fullmatch(r"delete from sessions where (?:\w+\.)?token_hash = \$1", sql), sql

    async def test_sessions_revoke_binds_the_token_hash(self) -> None:
        """The hash is the bind parameter; the raw token appears nowhere."""
        executor = _StatusExecutor("DELETE 1")

        await revoke_session(executor, _VALID_TOKEN)

        _, sql, args = executor.calls[0]
        assert args == (hash_session_token(_VALID_TOKEN),)
        assert _VALID_TOKEN not in sql

    @pytest.mark.parametrize("token", _MALFORMED_TOKENS)
    async def test_sessions_revoke_malformed_token_issues_no_query(self, token: str) -> None:
        """A token that can't exist is ignored without touching the database."""
        executor = _StatusExecutor("DELETE 0")

        await revoke_session(executor, token)

        assert executor.calls == []

    async def test_sessions_revoke_unknown_token_is_not_an_error(self) -> None:
        """Deleting nothing ("DELETE 0", e.g. an already purged row) returns quietly."""
        executor = _StatusExecutor("DELETE 0")

        assert await revoke_session(executor, _VALID_TOKEN) is None


# ---------------------------------------------------------------------------
# 10. revoke_user_sessions: every session of one user (password change, user
#     deactivation — the #164 service)
# ---------------------------------------------------------------------------


async def _revoke_user(executor: _Executor, user_id: Any = _USER_ID) -> Any:
    """Call admino.sessions.revoke_user_sessions, looked up at call time."""
    return await sessions_mod.revoke_user_sessions(executor, user_id)


class TestRevokeUserSessions:
    """revoke_user_sessions deletes every session row of a user with one DELETE."""

    async def test_sessions_revoke_user_issues_one_delete(self) -> None:
        """DELETE FROM sessions WHERE user_id = $1, through execute (for the status)."""
        executor = _StatusExecutor("DELETE 2")

        await _revoke_user(executor)

        assert len(executor.calls) == 1
        method, sql, _ = executor.calls[0]
        assert method == "execute"
        normalized = _norm(sql)
        assert re.fullmatch(r"delete from sessions where (?:\w+\.)?user_id = \$1", normalized), (
            normalized
        )

    async def test_sessions_revoke_user_binds_only_the_user_id(self) -> None:
        """The user id is the one bind parameter and never part of the SQL text."""
        executor = _StatusExecutor("DELETE 1")

        await _revoke_user(executor)

        _, sql, args = executor.calls[0]
        assert args == (_USER_ID,)
        assert str(_USER_ID) not in sql

    @pytest.mark.parametrize("count", [0, 1, 3, 250])
    async def test_sessions_revoke_user_returns_the_deleted_count(self, count: int) -> None:
        """The count comes from asyncpg's status string ("DELETE <n>") as an int."""
        result = await _revoke_user(_StatusExecutor(f"DELETE {count}"))

        assert result == count
        assert type(result) is int

    async def test_sessions_revoke_user_accepts_an_asyncpg_uuid(self) -> None:
        """The users row's asyncpg UUID can be passed straight through."""
        executor = _StatusExecutor("DELETE 1")

        await _revoke_user(executor, PgUUID(str(_USER_ID)))

        assert executor.calls[0][2] == (_USER_ID,)

    async def test_sessions_revoke_user_is_scoped_to_the_user_only(self) -> None:
        """No token hash or session id narrows or widens it: the user id is the scope."""
        executor = _StatusExecutor("DELETE 0")

        await _revoke_user(executor)

        sql = _norm(executor.calls[0][1])
        assert "token_hash" not in sql
        assert re.search(ID_PARAM_RE, sql) is None


# ---------------------------------------------------------------------------
# 11. revoke_org_sessions: every session of an org's users (the org deactivation
#     service of #154/#167)
# ---------------------------------------------------------------------------

_ORG_DELETE_FORMS = (
    # DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE org_id = $1)
    r"delete from sessions(?: (?:as )?\w+)? where (?:\w+\.)?user_id in "
    r"\( ?select (?:\w+\.)?id from users(?: (?:as )?\w+)? where (?:\w+\.)?org_id = \$1 ?\)",
    # DELETE FROM sessions s USING users u WHERE s.user_id = u.id AND u.org_id = $1
    r"delete from sessions(?: (?:as )?\w+)? using users(?: (?:as )?\w+)? where "
    r"(?:(?:\w+\.)?user_id = (?:\w+\.)?id|(?:\w+\.)?id = (?:\w+\.)?user_id) "
    r"and (?:\w+\.)?org_id = \$1",
    r"delete from sessions(?: (?:as )?\w+)? using users(?: (?:as )?\w+)? where "
    r"(?:\w+\.)?org_id = \$1 and "
    r"(?:(?:\w+\.)?user_id = (?:\w+\.)?id|(?:\w+\.)?id = (?:\w+\.)?user_id)",
)


async def _revoke_org(executor: _Executor, org_id: Any = _ORG_ID) -> Any:
    """Call admino.sessions.revoke_org_sessions, looked up at call time."""
    return await sessions_mod.revoke_org_sessions(executor, org_id)


class TestRevokeOrgSessions:
    """revoke_org_sessions deletes the sessions of every user of an org with one DELETE."""

    async def test_sessions_revoke_org_issues_one_delete_scoped_by_the_org(self) -> None:
        """One execute: DELETE FROM sessions of the users whose org_id = $1."""
        executor = _StatusExecutor("DELETE 4")

        await _revoke_org(executor)

        assert len(executor.calls) == 1
        method, sql, _ = executor.calls[0]
        assert method == "execute"
        normalized = _norm(sql)
        assert any(re.fullmatch(form, normalized) for form in _ORG_DELETE_FORMS), normalized

    async def test_sessions_revoke_org_binds_only_the_org_id(self) -> None:
        """The org id is the one bind parameter and never part of the SQL text."""
        executor = _StatusExecutor("DELETE 1")

        await _revoke_org(executor)

        _, sql, args = executor.calls[0]
        assert args == (_ORG_ID,)
        assert str(_ORG_ID) not in sql
        assert "token_hash" not in _norm(sql)

    @pytest.mark.parametrize("count", [0, 1, 7, 250])
    async def test_sessions_revoke_org_returns_the_deleted_count(self, count: int) -> None:
        """The count comes from asyncpg's status string ("DELETE <n>") as an int."""
        result = await _revoke_org(_StatusExecutor(f"DELETE {count}"))

        assert result == count
        assert type(result) is int

    async def test_sessions_revoke_org_accepts_an_asyncpg_uuid(self) -> None:
        """An organizations row's asyncpg UUID can be passed straight through."""
        executor = _StatusExecutor("DELETE 1")

        await _revoke_org(executor, PgUUID(str(_ORG_ID)))

        assert executor.calls[0][2] == (_ORG_ID,)

    def test_sessions_revoke_org_takes_the_executor_and_org_id(self) -> None:
        """revoke_org_sessions(executor, org_id): the caller's transaction connection."""
        params = list(inspect.signature(sessions_mod.revoke_org_sessions).parameters)

        assert params == ["executor", "org_id"]


# ---------------------------------------------------------------------------
# 12. Every revocation path deletes rows (against the in-memory database)
# ---------------------------------------------------------------------------


class TestRevocationDeletesRows:
    """Session rows don't outlive their session: every revocation deletes them."""

    async def test_sessions_revoke_session_deletes_only_that_row(self) -> None:
        """Logout: the row of this token is gone; the user's other session stays."""
        db = FakeDb()
        user_id = db.add_account()
        token = db.open_session(user_id)
        other = db.open_session(user_id)

        await revoke_session(db.pool, token)

        assert db.session_revoked(token)
        assert not db.session_revoked(other)

    async def test_sessions_revoke_user_deletes_every_row_of_the_user(self) -> None:
        """Live, idle and expired rows of the user are all deleted and counted; another
        user's rows stay."""
        db = FakeDb()
        user_id = db.add_account()
        bystander = db.add_account()
        mine = [
            db.open_session(user_id),
            db.open_session(user_id, last_seen_ago=timedelta(hours=2)),
            db.open_session(user_id, expires_in=timedelta(seconds=-1)),
        ]
        theirs = db.open_session(bystander)

        count = await sessions_mod.revoke_user_sessions(db.pool, user_id)

        assert count == 3
        assert all(db.session_revoked(token) for token in mine)
        assert not db.session_revoked(theirs)

    async def test_sessions_revoke_org_deletes_every_session_of_the_org(self) -> None:
        """Every user of the org loses every session (all roles, deactivated users'
        leftovers included); another org's users and a Super Admin keep theirs."""
        db = FakeDb()
        admin = db.add_account(role="org_admin")
        editor = db.add_account(role="editor")
        viewer = db.add_account(role="viewer", status="deactivated")
        outsider = db.add_account(org_id=OTHER_ORG_ID)
        super_admin = db.add_account(kind="super_admin", role=None, org_status=None)
        org_tokens = [
            db.open_session(admin),
            db.open_session(admin),
            db.open_session(editor),
            db.open_session(viewer),
        ]
        kept = [db.open_session(outsider), db.open_session(super_admin)]

        count = await sessions_mod.revoke_org_sessions(db.pool, ORG_ID)

        assert count == 4
        assert all(db.session_revoked(token) for token in org_tokens)
        assert not any(db.session_revoked(token) for token in kept)

    async def test_sessions_deactivation_is_immediate(self) -> None:
        """Right after revoke_user_sessions the user's tokens no longer resolve."""
        db = FakeDb()
        user_id = db.add_account()
        token = db.open_session(user_id)
        assert await resolve_session(db.pool, token) is not None

        await sessions_mod.revoke_user_sessions(db.pool, user_id)

        assert await resolve_session(db.pool, token) is None


# ---------------------------------------------------------------------------
# 13. purge_expired_sessions: rows past expires_at or idle past their timeout
# ---------------------------------------------------------------------------


def _purge_where(executor: _Executor) -> str:
    """The WHERE clause of the one purge DELETE."""
    assert len(executor.calls) == 1, executor.calls
    sql = _norm(executor.calls[0][1])
    match = re.fullmatch(r"delete from sessions where (.+)", sql)
    assert match is not None, sql
    return match.group(1)


class TestPurgeExpiredSessions:
    """One DELETE removes expired and idle-timed-out rows and keeps live ones."""

    async def test_sessions_purge_is_one_delete_without_bind_values(self) -> None:
        """One execute of DELETE FROM sessions WHERE ...; no user-supplied values."""
        executor = _StatusExecutor("DELETE 0")

        await sessions_mod.purge_expired_sessions(executor)

        assert len(executor.calls) == 1
        method, _, args = executor.calls[0]
        assert method == "execute"
        assert args == ()

    async def test_sessions_purge_deletes_expired_or_idle_rows(self) -> None:
        """WHERE expires_at <= now() OR last_seen_at + make_interval(mins =>
        idle_timeout_minutes) <= now(): each row's own timeout, the resolve boundary."""
        executor = _StatusExecutor("DELETE 0")

        await sessions_mod.purge_expired_sessions(executor)

        where = _purge_where(executor)
        expired = rf"\(?(?:{EXPIRED_RE})\)?"
        idle = rf"\(?(?:{IDLE_GONE_RE})\)?"
        assert re.fullmatch(rf"{expired} or {idle}|{idle} or {expired}", where), where

    @pytest.mark.parametrize("count", [0, 3, 1000])
    async def test_sessions_purge_returns_the_deleted_count(self, count: int) -> None:
        """The count comes from asyncpg's status string ("DELETE <n>") as an int."""
        result = await sessions_mod.purge_expired_sessions(_StatusExecutor(f"DELETE {count}"))

        assert result == count
        assert type(result) is int

    def test_sessions_purge_takes_only_the_executor(self) -> None:
        """purge_expired_sessions(executor): nothing else can widen or narrow it."""
        params = list(inspect.signature(sessions_mod.purge_expired_sessions).parameters)

        assert params == ["executor"]

    async def test_sessions_purge_deletes_expired_and_idle_rows_and_keeps_live_ones(
        self,
    ) -> None:
        """Against the in-memory database: expired rows and rows idle past their own
        timeout go; live rows (including a 480-minute session idle for 7h59) stay."""
        db = FakeDb()
        user_id = db.add_account()
        gone = [
            db.open_session(user_id, expires_in=timedelta(seconds=-1)),
            db.open_session(user_id, expires_in=timedelta(days=-3)),
            db.open_session(user_id, idle_timeout_minutes=60, last_seen_ago=timedelta(minutes=61)),
            db.open_session(user_id, idle_timeout_minutes=15, last_seen_ago=timedelta(minutes=16)),
        ]
        live = [
            db.open_session(user_id),
            db.open_session(user_id, idle_timeout_minutes=15, last_seen_ago=timedelta(minutes=14)),
            db.open_session(
                user_id, idle_timeout_minutes=480, last_seen_ago=timedelta(hours=7, minutes=59)
            ),
        ]

        count = await sessions_mod.purge_expired_sessions(db.pool)

        assert count == len(gone)
        assert all(db.session_revoked(token) for token in gone)
        assert not any(db.session_revoked(token) for token in live)

    async def test_sessions_purge_logs_no_ids(self, caplog: pytest.LogCaptureFixture) -> None:
        """A purge logs no session or user IDs."""
        caplog.set_level(logging.DEBUG)
        db = FakeDb()
        user_id = db.add_account()
        token = db.open_session(user_id, expires_in=timedelta(seconds=-1))
        session_id = db.session_id_of(token)

        await sessions_mod.purge_expired_sessions(db.pool)

        assert str(user_id) not in caplog.text
        assert str(session_id) not in caplog.text


# ---------------------------------------------------------------------------
# 14. run_session_purge_job: the (at least) hourly purge loop
# ---------------------------------------------------------------------------


def _purge_pool(call: Any) -> Any:
    """Return the executor a purge_expired_sessions call received (positional or keyword)."""
    if call.args:
        return call.args[0]
    return call.kwargs["executor"]


def _sleep_delay(call: Any) -> Any:
    """Return the delay an asyncio.sleep call received (positional or keyword)."""
    if call.args:
        return call.args[0]
    return call.kwargs["delay"]


def _cancelling_sleep(after: int, events: list[str] | None = None) -> AsyncMock:
    """A fake asyncio.sleep that returns at once and raises CancelledError on call `after`."""
    calls = {"count": 0}

    async def fake_sleep(delay: float) -> None:
        calls["count"] += 1
        if events is not None:
            events.append("sleep")
        if calls["count"] >= after:
            raise asyncio.CancelledError

    return AsyncMock(side_effect=fake_sleep)


@contextlib.contextmanager
def _patched_job(purge: AsyncMock, sleep: AsyncMock) -> Iterator[None]:
    """Patch purge_expired_sessions and asyncio.sleep as run_session_purge_job looks
    them up."""
    with (
        patch("admino.sessions.purge_expired_sessions", purge),
        patch("admino.sessions.asyncio.sleep", sleep),
    ):
        yield


async def _run_job(pool: Any, **kwargs: Any) -> None:
    """Call admino.sessions.run_session_purge_job, looked up at call time."""
    await sessions_mod.run_session_purge_job(pool, **kwargs)


_FAILURE_MARKER = "row-marker-5f0e8a3c 203.0.113.9 Mozilla/5.0"


class TestSessionPurgeJob:
    """run_session_purge_job purges now, then once per interval, and survives failures."""

    async def test_sessions_job_purges_then_sleeps_in_a_loop(self) -> None:
        """Purge, sleep, purge, sleep, ... until cancelled."""
        events: list[str] = []

        async def fake_purge(*_args: Any, **_kwargs: Any) -> int:
            events.append("purge")
            return 0

        with (
            _patched_job(AsyncMock(side_effect=fake_purge), _cancelling_sleep(3, events)),
            pytest.raises(asyncio.CancelledError),
        ):
            await _run_job(MagicMock())

        assert events == ["purge", "sleep", "purge", "sleep", "purge", "sleep"]

    async def test_sessions_job_first_purge_runs_immediately(self) -> None:
        """The first purge runs before the first sleep."""
        events: list[str] = []

        async def fake_purge(*_args: Any, **_kwargs: Any) -> int:
            events.append("purge")
            return 0

        with (
            _patched_job(AsyncMock(side_effect=fake_purge), _cancelling_sleep(1, events)),
            pytest.raises(asyncio.CancelledError),
        ):
            await _run_job(MagicMock())

        assert events == ["purge", "sleep"]

    async def test_sessions_job_defaults_to_the_purge_interval(self) -> None:
        """By default the job purges the given pool every PURGE_INTERVAL_SECONDS."""
        pool = MagicMock(name="pool")
        purge = AsyncMock(return_value=0)
        sleep = _cancelling_sleep(2)

        with _patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await _run_job(pool)

        interval = sessions_mod.PURGE_INTERVAL_SECONDS
        assert [_purge_pool(call) for call in purge.await_args_list] == [pool, pool]
        assert [_sleep_delay(call) for call in sleep.await_args_list] == [interval, interval]

    async def test_sessions_job_passes_a_custom_interval(self) -> None:
        """interval_seconds is what the job sleeps between runs."""
        purge = AsyncMock(return_value=0)
        sleep = _cancelling_sleep(1)

        with _patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await _run_job(MagicMock(), interval_seconds=5)

        assert _sleep_delay(sleep.await_args_list[0]) == 5

    def test_sessions_job_signature(self) -> None:
        """run_session_purge_job(pool, *, interval_seconds=PURGE_INTERVAL_SECONDS)."""
        params = list(inspect.signature(sessions_mod.run_session_purge_job).parameters.values())

        assert [p.name for p in params] == ["pool", "interval_seconds"]
        assert params[1].kind is inspect.Parameter.KEYWORD_ONLY
        assert params[1].default == sessions_mod.PURGE_INTERVAL_SECONDS

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(lambda: RuntimeError(_FAILURE_MARKER), id="runtime-error"),
            pytest.param(lambda: OSError(_FAILURE_MARKER), id="os-error"),
            pytest.param(lambda: ConnectionResetError(_FAILURE_MARKER), id="connection-reset"),
            pytest.param(
                lambda: asyncpg.exceptions.RaiseError(_FAILURE_MARKER), id="postgres-error"
            ),
            pytest.param(lambda: TimeoutError(_FAILURE_MARKER), id="timeout"),
            pytest.param(lambda: ValueError(_FAILURE_MARKER), id="value-error"),
        ],
    )
    async def test_sessions_job_retries_a_failed_run_at_the_next_interval(
        self, make_error: Callable[[], Exception]
    ) -> None:
        """A failing purge doesn't stop the job: it sleeps and purges again next interval."""
        purge = AsyncMock(side_effect=[make_error(), 4])
        sleep = _cancelling_sleep(2)

        with _patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await _run_job(MagicMock())

        interval = sessions_mod.PURGE_INTERVAL_SECONDS
        assert purge.await_count == 2
        assert [_sleep_delay(call) for call in sleep.await_args_list] == [interval, interval]

    async def test_sessions_job_logs_a_failed_run_by_class_name(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The failure is logged (WARNING or above, from an admino logger) and names the
        exception class."""
        caplog.set_level(logging.DEBUG)
        purge = AsyncMock(side_effect=ConnectionResetError(_FAILURE_MARKER))

        with _patched_job(purge, _cancelling_sleep(1)), pytest.raises(asyncio.CancelledError):
            await _run_job(MagicMock())

        failures = [
            entry
            for entry in caplog.records
            if entry.levelno >= logging.WARNING and entry.name.startswith("admino")
        ]
        assert len(failures) == 1
        assert "ConnectionResetError" in failures[0].getMessage()

    async def test_sessions_job_failure_log_carries_only_the_class_name(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No message text, no traceback, no IDs, IP or user agent from the failure."""
        caplog.set_level(logging.DEBUG)
        purge = AsyncMock(side_effect=asyncpg.exceptions.RaiseError(_FAILURE_MARKER))

        with _patched_job(purge, _cancelling_sleep(1)), pytest.raises(asyncio.CancelledError):
            await _run_job(MagicMock())

        assert "row-marker" not in caplog.text
        assert "5f0e8a3c" not in caplog.text
        assert _IP not in caplog.text
        assert "Mozilla" not in caplog.text
        assert all(entry.exc_info is None and entry.exc_text is None for entry in caplog.records)

    async def test_sessions_job_cancelled_purge_propagates(self) -> None:
        """Cancellation during a purge stops the job (it isn't treated as a failed run)."""
        purge = AsyncMock(side_effect=asyncio.CancelledError)
        sleep = _cancelling_sleep(5)

        with _patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await _run_job(MagicMock())

        assert purge.await_count == 1
        sleep.assert_not_awaited()

    async def test_sessions_job_task_cancel_stops_it(self) -> None:
        """Cancelling the job's task while it sleeps ends the task as cancelled."""
        sleeping = asyncio.Event()

        async def blocking_sleep(_delay: float) -> None:
            sleeping.set()
            await asyncio.Event().wait()

        purge = AsyncMock(return_value=0)
        with _patched_job(purge, AsyncMock(side_effect=blocking_sleep)):
            task = asyncio.create_task(_run_job(MagicMock()))
            async with asyncio.timeout(5):
                await sleeping.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        assert task.cancelled()


# ---------------------------------------------------------------------------
# 15. Hygiene: no revoked_at SQL left, nothing identifying in the logs
# ---------------------------------------------------------------------------


def _docstring_nodes(tree: ast.Module) -> set[int]:
    """ids of the module, class and function docstring constants."""
    nodes: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                nodes.add(id(body[0].value))
    return nodes


class TestSessionsHygiene:
    """sessions.py no longer writes revoked_at, and logs nothing identifying."""

    def test_sessions_module_sql_never_names_revoked_at(self) -> None:
        """No SQL string in sessions.py names revoked_at (no UPDATE ... SET revoked_at)."""
        tree = ast.parse((_SRC_DIR / "sessions.py").read_text(encoding="utf-8"))
        docstrings = _docstring_nodes(tree)
        offenders = [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstrings
            and re.search(r"\b(?:select|update|delete|insert)\b", node.value, re.IGNORECASE)
            and "revoked_at" in node.value.lower()
        ]

        assert offenders == []

    async def test_sessions_functions_log_no_token_hash_ip_or_user_agent(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Across create, resolve (with a touch), revoke, revoke_user, revoke_org and the
        purge, no log line carries the token, its hash, the IP or the user agent."""
        caplog.set_level(logging.DEBUG)
        db = FakeDb()
        user_id = db.add_account()
        seen = db.open_session(user_id, last_seen_ago=timedelta(minutes=5))

        token = await create_session(
            db.pool,
            user_id=user_id,
            policy=sessions_mod.SessionPolicy(),
            ip=_IP,
            user_agent=_USER_AGENT,
        )
        await resolve_session(db.pool, token)
        await resolve_session(db.pool, seen)
        await revoke_session(db.pool, token)
        await sessions_mod.revoke_user_sessions(db.pool, user_id)
        await sessions_mod.revoke_org_sessions(db.pool, ORG_ID)
        await sessions_mod.purge_expired_sessions(db.pool)

        for secret in (token, seen):
            assert secret not in caplog.text
            assert hash_session_token(secret).hex() not in caplog.text
        assert _IP not in caplog.text
        assert "UA-marker-7731" not in caplog.text


# ---------------------------------------------------------------------------
# 16. resolve_session_by_id: the OAuth callback's lookup by session row id (GH-162)
# ---------------------------------------------------------------------------


async def _by_id(executor: Any, session_id: uuid.UUID) -> Any:
    """sessions.resolve_session_by_id, looked up at call time so this file collects
    before GH-162."""
    return await sessions_mod.resolve_session_by_id(executor, session_id)


def _db_writes(db: FakeDb) -> list[Any]:
    """Every INSERT, UPDATE or DELETE the fake recorded (any table)."""
    return db.matching(r"^(?:insert into|update|delete from)\b")


def _session_in_org_with_status(db: FakeDb, status: str) -> str:
    """A live session of an active editor whose org then gets this status."""
    token = db.open_session(db.add_account(role="editor"))
    db.add_org(ORG_ID, status=status)
    return token


# FakeDb setups whose session must not resolve, built when the test runs: each
# returns the raw token of the stored session (looked up by its id in the test).
_GONE_BY_ID: list[Any] = [
    pytest.param(
        lambda db: db.open_session(db.add_account(), expires_in=timedelta(seconds=-1)),
        id="expired",
    ),
    pytest.param(
        lambda db: db.open_session(db.add_account(), last_seen_ago=timedelta(minutes=61)),
        id="idle-60",
    ),
    pytest.param(
        lambda db: db.open_session(
            db.add_account(), idle_timeout_minutes=15, last_seen_ago=timedelta(minutes=16)
        ),
        id="idle-15",
    ),
    pytest.param(
        lambda db: db.open_session(db.add_account(status="deactivated")), id="user-deactivated"
    ),
    pytest.param(lambda db: db.open_session(db.add_account(status="invited")), id="user-invited"),
    pytest.param(
        lambda db: db.open_session(db.add_account(deleted_at=_ago(days=1))), id="user-deleted"
    ),
    pytest.param(lambda db: _session_in_org_with_status(db, "deactivated"), id="org-deactivated"),
    pytest.param(
        lambda db: _session_in_org_with_status(db, "pending_deletion"),
        id="org-pending-deletion",
    ),
    pytest.param(
        lambda db: db.open_session(
            db.add_account(kind="super_admin", role=None, status="deactivated")
        ),
        id="super-admin-deactivated",
    ),
]


class TestResolveSessionById:
    """GH-162: the OAuth callback resolves the initiating user's session by its row id.

    The same checks and result as resolve_session (expired, idle past its own timeout,
    malformed row, inactive or deleted user, inactive org, invalid Principal: None), one
    parameterized ``... WHERE s.id = $1`` lookup, and never a write: the callback is a
    cross-site redirect, so it must not keep a session alive (no last_seen_at touch).
    """

    def test_sessions_by_id_is_a_coroutine_of_the_executor_and_session_id(self) -> None:
        resolve_by_id = sessions_mod.resolve_session_by_id

        assert inspect.iscoroutinefunction(resolve_by_id)
        assert list(inspect.signature(resolve_by_id).parameters) == ["executor", "session_id"]

    # -- against the in-memory database ---------------------------------------------

    @pytest.mark.parametrize("role", ["org_admin", "editor", "viewer"])
    async def test_sessions_by_id_live_member_session_matches_the_token_lookup(
        self, role: str
    ) -> None:
        """The same AuthenticatedSession as resolve_session: principal, session id and
        both languages."""
        db = FakeDb()
        user_id = db.add_account(role=role, ui_language="fr")
        db.users[user_id]["response_language"] = "it"
        token = db.open_session(user_id)
        session_id = db.session_id_of(token)

        by_id = await _by_id(db.pool, session_id)
        by_token = await resolve_session(db.pool, token)

        assert by_id is not None
        assert by_id == by_token
        assert type(by_id) is AuthenticatedSession
        assert by_id.principal == Principal(
            user_id=user_id, kind="member", org_id=ORG_ID, role=role
        )
        assert by_id.session_id == session_id
        assert (by_id.ui_language, by_id.response_language) == ("fr", "it")

    async def test_sessions_by_id_live_super_admin_session_matches_the_token_lookup(
        self,
    ) -> None:
        db = FakeDb()
        admin = db.add_account(kind="super_admin", role=None, ui_language="en")
        token = db.open_session(admin)

        by_id = await _by_id(db.pool, db.session_id_of(token))

        assert by_id is not None
        assert by_id == await resolve_session(db.pool, token)
        assert by_id.principal == Principal(user_id=admin, kind="super_admin")

    async def test_sessions_by_id_resolves_the_session_of_that_id(self) -> None:
        """Two users' sessions: each id resolves to its own user, never the other."""
        db = FakeDb()
        alice = db.add_account(role="editor")
        bob = db.add_account(role="org_admin", org_id=OTHER_ORG_ID)
        alice_token = db.open_session(alice)
        bob_token = db.open_session(bob)

        bob_session = await _by_id(db.pool, db.session_id_of(bob_token))
        alice_session = await _by_id(db.pool, db.session_id_of(alice_token))

        assert bob_session is not None
        assert alice_session is not None
        assert (bob_session.principal.user_id, bob_session.principal.org_id) == (
            bob,
            OTHER_ORG_ID,
        )
        assert (alice_session.principal.user_id, alice_session.principal.org_id) == (
            alice,
            ORG_ID,
        )

    async def test_sessions_by_id_unknown_id_returns_none(self) -> None:
        db = FakeDb()
        db.open_session(db.add_account())

        assert await _by_id(db.pool, uuid.uuid4()) is None
        assert _db_writes(db) == []

    async def test_sessions_by_id_revoked_session_returns_none(self) -> None:
        """Logout deletes the row: its id no longer resolves."""
        db = FakeDb()
        token = db.open_session(db.add_account())
        session_id = db.session_id_of(token)
        assert await _by_id(db.pool, session_id) is not None

        await revoke_session(db.pool, token)

        assert await _by_id(db.pool, session_id) is None

    @pytest.mark.parametrize("make_session", _GONE_BY_ID)
    async def test_sessions_by_id_rejects_a_session_resolve_session_rejects(
        self, make_session: Callable[[FakeDb], str]
    ) -> None:
        """Expired, idle past its own timeout, an inactive or deleted user, an org that
        isn't active → None, and nothing is written."""
        db = FakeDb()
        token = make_session(db)

        assert await _by_id(db.pool, db.session_id_of(token)) is None
        assert _db_writes(db) == []
        # The same session by its token is rejected too (the setup really is a reject).
        assert await resolve_session(db.pool, token) is None

    async def test_sessions_by_id_open_session_rejected_after_deactivation(self) -> None:
        """Re-read on every call: deactivating the user ends the lookup by id at once."""
        db = FakeDb()
        user_id = db.add_account()
        session_id = db.session_id_of(db.open_session(user_id))
        assert await _by_id(db.pool, session_id) is not None

        db.users[user_id]["status"] = "deactivated"

        assert await _by_id(db.pool, session_id) is None

    async def test_sessions_by_id_never_touches_a_session_seen_long_ago(self) -> None:
        """Last seen 7 hours ago (inside its 480-minute timeout): it resolves, but no
        UPDATE sessions is issued and last_seen_at keeps its value. The token lookup of
        the same session does touch it, so the setup would be written."""
        db = FakeDb()
        token = db.open_session(
            db.add_account(), idle_timeout_minutes=480, last_seen_ago=timedelta(hours=7)
        )
        before = dict(db.session(token))

        session = await _by_id(db.pool, db.session_id_of(token))

        assert session is not None
        assert db.matching(r"^update sessions\b") == []
        assert _db_writes(db) == []
        assert db.session(token) == before
        assert [call.method for call in db.calls] == ["fetchrow"]

        assert await resolve_session(db.pool, token) is not None
        assert len(db.matching(r"^update sessions\b")) == 1

    # -- the statement and the decision, against a recording executor ------------------

    async def test_sessions_by_id_issues_one_fetchrow_bound_to_the_session_id(self) -> None:
        """One fetchrow whose WHERE binds the id as a parameter: never inlined, and no
        token hash."""
        executor = _Executor([_row(last_seen_at=_ago(minutes=5))])

        session = await _by_id(executor, _SESSION_ID)

        assert session is not None
        assert [method for method, _, _ in executor.calls] == ["fetchrow"]
        _, sql, args = executor.calls[0]
        where = _norm(sql).split(" where ", 1)[1]
        match = re.search(ID_PARAM_RE, where)
        assert match is not None, where
        assert str(args[int(match.group(1)) - 1]) == str(_SESSION_ID)
        assert str(_SESSION_ID) not in sql
        assert _SESSION_ID.hex not in sql
        assert "token_hash" not in where
        assert all(not isinstance(arg, bytes | bytearray) for arg in args)

    async def test_sessions_by_id_reads_the_same_joins_as_the_token_lookup(self) -> None:
        """The session, its users row and (LEFT JOIN) its org; its own last_seen_at and
        idle_timeout_minutes; never revoked_at."""
        executor = _Executor([_row()])

        await _by_id(executor, _SESSION_ID)

        sql = _norm(executor.calls[0][1])
        assert re.search(r"\bfrom sessions\b", sql) is not None
        assert re.search(r"\bjoin users\b", sql) is not None
        assert re.search(r"\bleft (?:outer )?join organizations\b", sql) is not None
        assert re.search(r"\blast_seen_at\b", sql) is not None
        assert re.search(r"\bidle_timeout_minutes\b", sql) is not None
        assert "revoked_at" not in sql

    async def test_sessions_by_id_unknown_row_returns_none(self) -> None:
        assert await _by_id(_Executor([None]), _SESSION_ID) is None

    @pytest.mark.parametrize("make_row", [*_REJECTED_ROWS, *_INVALID_PRINCIPAL_ROWS])
    async def test_sessions_by_id_rejected_row_returns_none_without_a_write(
        self, make_row: Callable[[datetime], dict[str, Any]]
    ) -> None:
        """Every row resolve_session rejects (last seen 5 minutes ago unless the case says
        otherwise) → None, never raising, and only the fetchrow."""
        executor = _Executor([make_row(_ago(minutes=5))])

        assert await _by_id(executor, _SESSION_ID) is None
        assert [method for method, _, _ in executor.calls] == ["fetchrow"]

    @pytest.mark.parametrize("idle", [15, 60, 480])
    async def test_sessions_by_id_idle_boundary_is_refused(self, idle: int) -> None:
        """``last_seen_at + idle_timeout_minutes <= now`` is idle, as in resolve_session."""
        row = _row(idle_timeout_minutes=idle, last_seen_at=_exactly_ago(timedelta(minutes=idle)))

        assert await _by_id(_Executor([row]), _SESSION_ID) is None

    @pytest.mark.parametrize("role", ["org_admin", "editor", "viewer"])
    async def test_sessions_by_id_accepts_an_active_member(self, role: str) -> None:
        session = await _by_id(_Executor([_row(role=role)]), _SESSION_ID)

        assert type(session) is AuthenticatedSession
        assert session.principal == Principal(
            user_id=_USER_ID, kind="member", org_id=_ORG_ID, role=role
        )
        assert session.session_id == _SESSION_ID
        assert (session.ui_language, session.response_language) == ("de", "fr")
        assert type(session.principal.user_id) is uuid.UUID
        assert type(session.principal.org_id) is uuid.UUID

    async def test_sessions_by_id_accepts_an_active_super_admin(self) -> None:
        session = await _by_id(_Executor([_super_admin_row()]), _SESSION_ID)

        assert session is not None
        assert session.principal == Principal(user_id=_USER_ID, kind="super_admin")

    @pytest.mark.parametrize(
        ("idle", "seen_ago"),
        [
            pytest.param(60, timedelta(minutes=5), id="5-min"),
            pytest.param(60, timedelta(minutes=59), id="59-min"),
            pytest.param(480, timedelta(hours=7), id="7-h-of-480-min"),
        ],
    )
    async def test_sessions_by_id_never_writes_last_seen_at(
        self, idle: int, seen_ago: timedelta
    ) -> None:
        """A session resolve_session would touch (seen a minute or more ago) is returned
        with only the fetchrow: no UPDATE, no other statement."""
        row = _row(idle_timeout_minutes=idle, last_seen_at=datetime.now(UTC) - seen_ago)
        executor = _Executor([row])

        session = await _by_id(executor, _SESSION_ID)

        assert session is not None
        assert _updates(executor) == []
        assert [method for method, _, _ in executor.calls] == ["fetchrow"]

    async def test_sessions_by_id_logs_no_session_id(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Neither an accepted nor a rejected lookup logs the session id."""
        caplog.set_level(logging.DEBUG)

        await _by_id(_Executor([_row(last_seen_at=_ago(minutes=5))]), _SESSION_ID)
        await _by_id(_Executor([_row(status="deactivated")]), _SESSION_ID)
        await _by_id(_Executor([None]), _SESSION_ID)

        assert str(_SESSION_ID) not in caplog.text
        assert _SESSION_ID.hex not in caplog.text
