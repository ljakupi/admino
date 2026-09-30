"""Tests for admino.auth — the email/password login and logout service (GH-149, GH-152).

``login(pool, *, email, password, ip, user_agent)`` looks the account up by
email (case-insensitive), verifies the password with exactly one Argon2 call on
every path (a dummy hash stands in when there is no account or no password),
and either opens a session or fails with one generic ``LoginFailedError``.

What these tests pin down:
- Success: a session row with the token's hash, ``last_login_at`` updated, a
  ``login.success`` audit event (actor kind and user id from the row, the row's
  org, the client IP), and a frozen ``LoginResult`` returned: the raw token (kept
  out of its repr) and the cookie's ``max_age_seconds``. A hash with older
  parameters is rehashed with the current ones; a current hash is left alone.
- Session policy (GH-152): the session is opened with
  ``sessions.session_policy_for(<the account's kind>)``: a member's row stores
  the org policy's idle timeout and lifetime, a Super Admin's the platform
  policy's, and ``max_age_seconds`` is that lifetime in seconds (43200 by
  default).
- Failure, for every cause (unknown email, wrong password, invited user without
  a password, deactivated or deleted user, user of a deactivated or
  pending-deletion org): the same ``LoginFailedError("Invalid email or password")``,
  no session, and a ``login.failure`` audit event naming the account when it is
  known (a ``system`` actor with no user and no org otherwise).
- Equalized timing: ``admino.passwords.verify_password`` runs exactly once per
  login, whatever the outcome, off the event loop's thread.
- The email is a bind parameter of the lookup (``lower(email) = lower($1)``) and,
  since GH-157, the input of the login throttle's account subject
  (``sha256(convert_to(lower($n), 'UTF8'))``, computed by the database), and
  nowhere else: not in any other statement, not in the audit row or its
  metadata, not in any log line. The password is never logged. The throttle's
  own statements run on the login_throttle table of tests/db_fakes.py (a fresh
  counter per test pool, so no delay or lockout); its behavior is specified in
  tests/test_login_throttle.py.
- ``logout`` deletes the session row (GH-152: no revoked_at any more).

All asyncpg calls are mocked. No real PostgreSQL connections are made.

Security notes:
- No user enumeration: one message for every failure and one Argon2 verification
  on every path.
- Content-free audit (tracker #139 §5): IDs, the action and the IP only.
"""

from __future__ import annotations

import contextlib
import inspect
import json
import logging
import re
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest
from asyncpg.pgproto.pgproto import UUID as PgUUID  # noqa: N811

from admino import auth as auth_mod
from admino import passwords
from admino import sessions as sessions_mod
from admino.auth import LOGIN_FAILED_MESSAGE, LoginFailedError, login, logout
from admino.sessions import hash_session_token
from tests.db_fakes import FakeDb, NowPlus, insert_values

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EMAIL = "Marker.Person@Example.test"
_PASSWORD = "violet-Anchor-93-quartz"
_WRONG_PASSWORD = "violet-Anchor-93-quartzz"
_IP = "203.0.113.7"
_USER_AGENT = "Mozilla/5.0 (auth-test)"
_USER_ID = uuid.UUID("6a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d")
_ORG_ID = uuid.UUID("b7c8d9e0-f1a2-4b3c-9d4e-5f6a7b8c9d0e")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")


def _norm(sql: str) -> str:
    """Collapse whitespace and lowercase, for formatting-tolerant SQL matching."""
    return re.sub(r"\s+", " ", sql).strip().lower()


# GH-157: the login throttle's own statements (its login_throttle table, and the
# FROM-less digest the database computes as the account subject).
_DIGEST_RE = re.compile(
    r"sha256 ?\( ?convert_to ?\( ?lower ?\( ?\$(\d+)(?: ?:: ?\w+)? ?\) ?, ?'utf-?8' ?\) ?\)"
)


def _is_throttle_sql(sql: str) -> bool:
    """True for a statement of the login throttle (GH-157)."""
    normalized = _norm(sql)
    return re.search(r"\blogin_throttle\b", normalized) is not None or (
        normalized.startswith("select") and " from " not in normalized and "sha256" in normalized
    )


def _only_digests_the_email(sql: str, args: tuple[Any, ...]) -> bool:
    """True when every bind parameter carrying the email is used only as the input of
    sha256(convert_to(lower($n), 'UTF8')), the account subject (GH-157)."""
    normalized = _norm(sql)
    positions = [
        index + 1
        for index, arg in enumerate(args)
        if isinstance(arg, str) and arg.casefold() == _EMAIL.casefold()
    ]
    digested = [int(number) for number in _DIGEST_RE.findall(normalized)]
    return bool(positions) and all(
        len(re.findall(rf"\${position}(?!\d)", normalized)) == digested.count(position)
        for position in positions
    )


# ---------------------------------------------------------------------------
# A recording pool: the same calls whether the code uses the pool or a
# connection acquired from it (optionally inside a transaction)
# ---------------------------------------------------------------------------


class _FakeConnection:
    """Records (method, sql, args); fetchrow returns the account row for the lookup."""

    def __init__(self, pool: _FakePool) -> None:
        self._pool = pool

    async def execute(self, sql: str, *args: Any) -> Any:
        return self._pool.run("execute", sql, args)

    async def fetchrow(self, sql: str, *args: Any) -> Any:
        return self._pool.run("fetchrow", sql, args)

    async def fetchval(self, sql: str, *args: Any) -> Any:
        return self._pool.run("fetchval", sql, args)

    async def fetch(self, sql: str, *args: Any) -> Any:
        return self._pool.run("fetch", sql, args)

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        yield

    def is_in_transaction(self) -> bool:
        return True


class _FakePool(_FakeConnection):
    """The pool: records every call made through it or through acquired connections."""

    def __init__(self, account: dict[str, Any] | None) -> None:
        super().__init__(self)
        self.account = account
        self.calls: list[tuple[str, str, tuple[Any, ...]]] = []
        # GH-157: the login throttle's statements run on the shared fake's
        # login_throttle table (a fresh counter per pool: no delay, no lockout).
        self.throttle = FakeDb()

    def run(self, method: str, sql: str, args: tuple[Any, ...]) -> Any:
        """Record a call and answer it: the throttle's statements go to its table."""
        self.calls.append((method, sql, args))
        if _is_throttle_sql(sql):
            return self.throttle.handle(method, sql, args, "pool", None)
        if method == "fetchrow":
            return self.answer_fetchrow(sql)
        if method == "fetchval":
            return uuid.uuid4()
        if method == "fetch":
            return []
        return "OK"

    def answer_fetchrow(self, sql: str) -> Any:
        normalized = _norm(sql)
        if "users" in normalized and "sessions" not in normalized and "insert" not in normalized:
            return self.account
        return None

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[_FakeConnection]:
        yield _FakeConnection(self)

    # -- query helpers for the assertions ---------------------------------

    def matching(self, pattern: str) -> list[tuple[str, str, tuple[Any, ...]]]:
        """Calls whose normalized SQL matches the regex."""
        return [call for call in self.calls if re.search(pattern, _norm(call[1]))]

    def lookup(self) -> tuple[str, str, tuple[Any, ...]]:
        """The one account lookup."""
        lookups = [
            call
            for call in self.calls
            if call[0] == "fetchrow"
            and "users" in _norm(call[1])
            and "sessions" not in _norm(call[1])
        ]
        assert len(lookups) == 1, self.calls
        return lookups[0]

    def audit_rows(self) -> list[dict[str, Any]]:
        """Every INSERT INTO audit_events, mapped column → bind argument."""
        rows: list[dict[str, Any]] = []
        for _, sql, args in self.matching(r"insert into audit_events"):
            match = re.search(r"\(([^)]*)\)\s*values\s*\((.*)\)", _norm(sql))
            assert match is not None, sql
            columns = [c.strip() for c in match.group(1).split(",")]
            values = [v.strip() for v in match.group(2).split(",")]
            row: dict[str, Any] = {}
            for column, value in zip(columns, values, strict=True):
                placeholder = re.fullmatch(r"\$(\d+)(?:\s*::\s*\w+)?", value)
                assert placeholder is not None, value
                row[column] = args[int(placeholder.group(1)) - 1]
            rows.append(row)
        return rows

    def non_lookup_calls(self) -> list[tuple[str, str, tuple[Any, ...]]]:
        """Every call except the account lookup."""
        lookup = self.lookup()
        return [call for call in self.calls if call is not lookup]


# ---------------------------------------------------------------------------
# Accounts and fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def current_hash() -> str:
    """A real hash of _PASSWORD with the current parameters (one Argon2 call)."""
    return passwords.hash_password(_PASSWORD)


@pytest.fixture(scope="module")
def old_hash() -> str:
    """A real hash of _PASSWORD with older parameters (m=8192, t=1, p=1): cheap to verify."""
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    salt = bytes(range(16))
    digest = Argon2id(salt=salt, length=32, iterations=1, lanes=1, memory_cost=8192).derive(
        _PASSWORD.encode()
    )
    return passwords.encode_phc(memory_cost=8192, iterations=1, lanes=1, salt=salt, digest=digest)


def _member(password_hash: str | None, **overrides: Any) -> dict[str, Any]:
    """An active editor of an active org, as the lookup returns it (asyncpg UUIDs)."""
    row: dict[str, Any] = {
        "id": PgUUID(str(_USER_ID)),
        "email": _EMAIL,
        "kind": "member",
        "org_id": PgUUID(str(_ORG_ID)),
        "role": "editor",
        "status": "active",
        "deleted_at": None,
        "password_hash": password_hash,
        "org_status": "active",
        "ui_language": "en",
        "response_language": None,
    }
    row.update(overrides)
    return row


def _super_admin(password_hash: str | None, **overrides: Any) -> dict[str, Any]:
    """An active Super Admin: no org, no role, no org status."""
    fields: dict[str, Any] = {"kind": "super_admin", "org_id": None, "role": None}
    fields["org_status"] = None
    fields.update(overrides)
    return _member(password_hash, **fields)


class _VerifySpy:
    """Wraps the real passwords.verify_password; records each call and its thread."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[tuple[str, str]] = []
        self.threads: list[int] = []
        real = passwords.verify_password

        def spy(password: str, encoded: str) -> bool:
            self.calls.append((password, encoded))
            self.threads.append(threading.get_ident())
            return real(password, encoded)

        monkeypatch.setattr(passwords, "verify_password", spy)


async def _login(pool: _FakePool, **overrides: Any) -> Any:
    """Call login with the default credentials, IP and user agent; return its result
    (a LoginResult since GH-152)."""
    kwargs: dict[str, Any] = {
        "email": _EMAIL,
        "password": _PASSWORD,
        "ip": _IP,
        "user_agent": _USER_AGENT,
    }
    kwargs.update(overrides)
    return await login(pool, **kwargs)


# Every failure cause, with the account the lookup returns (None: unknown email)
# and the password tried. Built lazily: the hashes come from fixtures.
_FAILURE_CAUSES: list[str] = [
    "unknown-email",
    "wrong-password",
    "invited-no-password",
    "invited-with-password",
    "deactivated",
    "deleted",
    "org-deactivated",
    "org-pending-deletion",
    "super-admin-deactivated",
    "super-admin-deleted",
]


def _failure_case(cause: str, current_hash: str) -> tuple[dict[str, Any] | None, str]:
    """Return (account row, password) for one failure cause."""
    deleted_at = datetime.now(UTC) - timedelta(days=1)
    cases: dict[str, tuple[dict[str, Any] | None, str]] = {
        "unknown-email": (None, _PASSWORD),
        "wrong-password": (_member(current_hash), _WRONG_PASSWORD),
        "invited-no-password": (_member(None, status="invited"), _PASSWORD),
        "invited-with-password": (_member(current_hash, status="invited"), _PASSWORD),
        "deactivated": (_member(current_hash, status="deactivated"), _PASSWORD),
        "deleted": (_member(current_hash, deleted_at=deleted_at), _PASSWORD),
        "org-deactivated": (_member(current_hash, org_status="deactivated"), _PASSWORD),
        "org-pending-deletion": (_member(current_hash, org_status="pending_deletion"), _PASSWORD),
        "super-admin-deactivated": (_super_admin(current_hash, status="deactivated"), _PASSWORD),
        "super-admin-deleted": (_super_admin(current_hash, deleted_at=deleted_at), _PASSWORD),
    }
    return cases[cause]


# ---------------------------------------------------------------------------
# 1. The error type
# ---------------------------------------------------------------------------


class TestLoginFailedError:
    """One generic failure message for every cause."""

    def test_auth_login_failed_message(self) -> None:
        """The message is exactly 'Invalid email or password'."""
        assert LOGIN_FAILED_MESSAGE == "Invalid email or password"

    def test_auth_login_failed_error_str_is_the_message(self) -> None:
        """str(LoginFailedError()) is the generic message."""
        assert str(LoginFailedError()) == LOGIN_FAILED_MESSAGE

    def test_auth_login_failed_error_is_an_exception(self) -> None:
        """It is an Exception (not a ValueError a validation handler might echo)."""
        assert issubclass(LoginFailedError, Exception)


# ---------------------------------------------------------------------------
# 2. The account lookup
# ---------------------------------------------------------------------------


class TestLoginLookup:
    """One parameterized fetchrow, case-insensitive on the email."""

    async def test_auth_login_looks_up_lower_email_as_a_bind_parameter(
        self, current_hash: str
    ) -> None:
        """WHERE lower(email) = lower($1), the email bound as $1 and never in the SQL."""
        pool = _FakePool(_member(current_hash))

        await _login(pool)

        _, sql, args = pool.lookup()
        assert re.search(r"lower\((?:\w+\.)?email\) = lower\(\$1\)", _norm(sql)) is not None
        assert args[0].casefold() == _EMAIL.casefold()
        assert _EMAIL.casefold() not in _norm(sql)

    async def test_auth_login_lookup_left_joins_organizations(self, current_hash: str) -> None:
        """The org status comes from a LEFT JOIN (a Super Admin has no org)."""
        pool = _FakePool(_member(current_hash))

        await _login(pool)

        sql = _norm(pool.lookup()[1])
        assert re.search(r"\bleft (?:outer )?join organizations\b", sql) is not None

    async def test_auth_login_issues_a_single_read(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Exactly one read of the users table (the lookup); nothing else is read to decide
        the outcome but the login throttle's own state (GH-157: its login_throttle rows and
        the account subject's digest)."""
        pool = _FakePool(None)
        _VerifySpy(monkeypatch)

        with pytest.raises(LoginFailedError):
            await _login(pool)

        reads = [call for call in pool.calls if call[0] in {"fetchrow", "fetch", "fetchval"}]
        user_reads = [call for call in reads if re.search(r"\busers\b", _norm(call[1]))]
        assert len(user_reads) == 1
        assert all(_is_throttle_sql(call[1]) for call in reads if call not in user_reads)


# ---------------------------------------------------------------------------
# 3. Success
# ---------------------------------------------------------------------------


class TestLoginSuccess:
    """A valid login opens a session, stamps last_login_at and audits login.success."""

    async def test_auth_login_returns_a_session_token(self, current_hash: str) -> None:
        """The raw token (token_urlsafe(32)) is returned for the cookie."""
        token = (await _login(_FakePool(_member(current_hash)))).token

        assert _TOKEN_RE.fullmatch(token) is not None

    async def test_auth_login_creates_one_session_for_the_token(self, current_hash: str) -> None:
        """One INSERT INTO sessions whose bind parameters hold the returned token's hash
        and the user's id."""
        pool = _FakePool(_member(current_hash))

        token = (await _login(pool)).token

        inserts = pool.matching(r"insert into sessions")
        assert len(inserts) == 1
        args = inserts[0][2]
        assert hash_session_token(token) in args
        assert _USER_ID in args

    async def test_auth_login_updates_last_login_at(self, current_hash: str) -> None:
        """UPDATE users SET last_login_at = now() for that user id (bound)."""
        pool = _FakePool(_member(current_hash))

        await _login(pool)

        updates = pool.matching(r"update users set last_login_at = now\(\)")
        assert len(updates) == 1
        assert _USER_ID in updates[0][2]
        assert str(_USER_ID) not in updates[0][1]

    async def test_auth_login_success_is_audited(self, current_hash: str) -> None:
        """One login.success row: member actor, the user id, the user's org and the IP."""
        pool = _FakePool(_member(current_hash))

        await _login(pool)

        rows = pool.audit_rows()
        assert len(rows) == 1
        row = rows[0]
        assert row["action"] == "login.success"
        assert row["actor_kind"] == "member"
        assert row["actor_user_id"] == _USER_ID
        assert row["org_id"] == _ORG_ID
        assert str(row["ip"]) == _IP

    async def test_auth_login_super_admin_success_is_audited_without_org(
        self, current_hash: str
    ) -> None:
        """A Super Admin logs in (no org needed): actor super_admin, org_id NULL."""
        pool = _FakePool(_super_admin(current_hash))

        token = (await _login(pool)).token

        assert _TOKEN_RE.fullmatch(token) is not None
        row = pool.audit_rows()[0]
        assert (row["action"], row["actor_kind"]) == ("login.success", "super_admin")
        assert row["actor_user_id"] == _USER_ID
        assert row["org_id"] is None

    async def test_auth_login_success_audit_has_no_metadata_content(
        self, current_hash: str
    ) -> None:
        """The login.success metadata holds no email, name or password (empty or IDs only)."""
        pool = _FakePool(_member(current_hash))

        await _login(pool)

        metadata = json.loads(pool.audit_rows()[0]["metadata"])
        rendered = json.dumps(metadata).casefold()
        assert _EMAIL.casefold() not in rendered
        assert "marker" not in rendered
        assert _PASSWORD.casefold() not in rendered

    async def test_auth_login_accepts_the_email_in_any_case(self, current_hash: str) -> None:
        """The lookup is case-insensitive, so the login succeeds with another casing."""
        pool = _FakePool(_member(current_hash))

        token = (await _login(pool, email=_EMAIL.upper())).token

        assert _TOKEN_RE.fullmatch(token) is not None

    async def test_auth_login_passes_ip_and_user_agent_to_the_session(
        self, current_hash: str
    ) -> None:
        """The session row gets the client IP and user agent."""
        pool = _FakePool(_member(current_hash))

        await _login(pool)

        args = pool.matching(r"insert into sessions")[0][2]
        assert any(str(arg) == _IP for arg in args)
        assert _USER_AGENT in args


# ---------------------------------------------------------------------------
# 3b. The LoginResult and the session policy (GH-152)
# ---------------------------------------------------------------------------


def _session_insert(pool: _FakePool) -> dict[str, Any]:
    """The one INSERT INTO sessions, column → bound value (NowPlus for now() + $n)."""
    inserts = pool.matching(r"insert into sessions")
    assert len(inserts) == 1, pool.calls
    _, sql, args = inserts[0]
    return insert_values(sql, args)


def _policy(idle: int, lifetime: int) -> Any:
    return sessions_mod.SessionPolicy(idle_timeout_minutes=idle, max_lifetime_hours=lifetime)


class TestLoginResult:
    """login returns a frozen LoginResult: the token and the cookie's Max-Age."""

    async def test_auth_login_returns_a_login_result(self, current_hash: str) -> None:
        """An auth.LoginResult with the raw token and max_age_seconds (an int)."""
        result = await _login(_FakePool(_member(current_hash)))

        assert type(result) is auth_mod.LoginResult
        assert _TOKEN_RE.fullmatch(result.token) is not None
        assert result.max_age_seconds == 43200
        assert type(result.max_age_seconds) is int

    async def test_auth_login_result_repr_hides_the_token(self, current_hash: str) -> None:
        """repr() and str() never show the token (it may end up in a log or traceback)."""
        result = await _login(_FakePool(_member(current_hash)))

        assert result.token not in repr(result)
        assert result.token not in str(result)

    async def test_auth_login_result_is_frozen(self, current_hash: str) -> None:
        """The result can't be changed after login built it."""
        result = await _login(_FakePool(_member(current_hash)))

        assert type(result) is auth_mod.LoginResult
        with pytest.raises((AttributeError, TypeError, ValueError)):
            result.max_age_seconds = 1
        assert result.max_age_seconds == 43200

    def test_auth_login_is_annotated_to_return_a_login_result(self) -> None:
        """login's return annotation names LoginResult (no longer str)."""
        annotation = inspect.signature(login).return_annotation

        assert "LoginResult" in str(annotation)


class TestLoginSessionPolicy:
    """The session's idle timeout and lifetime come from sessions.session_policy_for."""

    async def test_auth_login_member_session_uses_the_org_default(self, current_hash: str) -> None:
        """A member: idle 60 minutes, expires_at = now() + 12 hours, Max-Age 43200."""
        pool = _FakePool(_member(current_hash))

        result = await _login(pool)

        row = _session_insert(pool)
        assert row["idle_timeout_minutes"] == 60
        assert row["expires_at"] == NowPlus(timedelta(hours=12))
        assert result.max_age_seconds == 43200

    async def test_auth_login_super_admin_session_uses_the_platform_default(
        self, current_hash: str
    ) -> None:
        """A Super Admin: the platform default (also 60 minutes / 12 hours)."""
        pool = _FakePool(_super_admin(current_hash))

        result = await _login(pool)

        row = _session_insert(pool)
        assert row["idle_timeout_minutes"] == 60
        assert row["expires_at"] == NowPlus(timedelta(hours=12))
        assert result.max_age_seconds == 43200

    async def test_auth_login_platform_policy_applies_to_super_admins_only(
        self, current_hash: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With a 30-minute / 8-hour platform policy the Super Admin's row stores 30 and
        now() + 8 h and Max-Age is 28800; a member in the same test keeps 60 / 12 h /
        43200."""
        monkeypatch.setattr(sessions_mod, "PLATFORM_SESSION_POLICY", _policy(30, 8))
        admin_pool = _FakePool(_super_admin(current_hash))
        member_pool = _FakePool(_member(current_hash))

        admin = await _login(admin_pool)
        member = await _login(member_pool)

        admin_row = _session_insert(admin_pool)
        assert (admin_row["idle_timeout_minutes"], admin_row["expires_at"]) == (
            30,
            NowPlus(timedelta(hours=8)),
        )
        assert admin.max_age_seconds == 28800
        member_row = _session_insert(member_pool)
        assert (member_row["idle_timeout_minutes"], member_row["expires_at"]) == (
            60,
            NowPlus(timedelta(hours=12)),
        )
        assert member.max_age_seconds == 43200

    async def test_auth_login_org_policy_applies_to_members_only(
        self, current_hash: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With a 20-minute / 2-hour org policy the member's row stores 20 and now() + 2 h
        and Max-Age is 7200; a Super Admin keeps 60 / 12 h / 43200."""
        monkeypatch.setattr(sessions_mod, "DEFAULT_ORG_SESSION_POLICY", _policy(20, 2))
        member_pool = _FakePool(_member(current_hash))
        admin_pool = _FakePool(_super_admin(current_hash))

        member = await _login(member_pool)
        admin = await _login(admin_pool)

        member_row = _session_insert(member_pool)
        assert (member_row["idle_timeout_minutes"], member_row["expires_at"]) == (
            20,
            NowPlus(timedelta(hours=2)),
        )
        assert member.max_age_seconds == 7200
        admin_row = _session_insert(admin_pool)
        assert (admin_row["idle_timeout_minutes"], admin_row["expires_at"]) == (
            60,
            NowPlus(timedelta(hours=12)),
        )
        assert admin.max_age_seconds == 43200

    async def test_auth_login_asks_session_policy_for_the_accounts_kind(
        self, current_hash: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The policy comes from sessions.session_policy_for(account kind)."""
        real = sessions_mod.session_policy_for
        kinds: list[str] = []

        def spy(kind: str) -> Any:
            kinds.append(kind)
            return real(kind)

        monkeypatch.setattr(sessions_mod, "session_policy_for", spy)

        await _login(_FakePool(_member(current_hash)))
        await _login(_FakePool(_super_admin(current_hash)))

        assert kinds == ["member", "super_admin"]

    @pytest.mark.parametrize("cause", ["wrong-password", "deactivated", "unknown-email"])
    async def test_auth_login_failure_asks_for_no_policy(
        self, cause: str, current_hash: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failed login opens no session, so it needs no policy."""
        calls: list[Any] = []
        monkeypatch.setattr(sessions_mod, "session_policy_for", lambda kind: calls.append(kind))
        account, password = _failure_case(cause, current_hash)

        with pytest.raises(LoginFailedError):
            await _login(_FakePool(account), password=password)

        assert calls == []


class TestLoginRehash:
    """A hash with older parameters is replaced on login; a current one is kept."""

    async def test_auth_login_rehashes_old_params(self, old_hash: str) -> None:
        """UPDATE users SET password_hash = $1 WHERE id = $2 with a current-params hash."""
        pool = _FakePool(_member(old_hash))

        await _login(pool)

        updates = pool.matching(r"update users set password_hash = \$1 where (?:\w+\.)?id = \$2")
        assert len(updates) == 1
        new_hash, user_id = updates[0][2][:2]
        assert new_hash.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
        assert user_id == _USER_ID
        assert passwords.verify_password(_PASSWORD, new_hash) is True

    async def test_auth_login_rehash_never_puts_the_password_in_sql(self, old_hash: str) -> None:
        """The new hash is a bind parameter; the plain password appears nowhere."""
        pool = _FakePool(_member(old_hash))

        await _login(pool)

        for _, sql, args in pool.calls:
            assert _PASSWORD not in sql
            assert all(arg != _PASSWORD for arg in args)

    async def test_auth_login_does_not_rehash_current_params(self, current_hash: str) -> None:
        """No password_hash UPDATE when the stored parameters are the current ones."""
        pool = _FakePool(_member(current_hash))

        await _login(pool)

        assert pool.matching(r"update users set password_hash") == []

    async def test_auth_login_failure_never_rehashes(self, old_hash: str) -> None:
        """A wrong password against an old hash changes nothing."""
        pool = _FakePool(_member(old_hash))

        with pytest.raises(LoginFailedError):
            await _login(pool, password=_WRONG_PASSWORD)

        assert pool.matching(r"update users set password_hash") == []


# ---------------------------------------------------------------------------
# 4. Failure: one error for every cause, audited, no session
# ---------------------------------------------------------------------------


class TestLoginFailure:
    """Every failure cause raises the same LoginFailedError and opens no session."""

    @pytest.mark.parametrize("cause", _FAILURE_CAUSES)
    async def test_auth_login_failure_raises_the_generic_error(
        self, cause: str, current_hash: str
    ) -> None:
        """str(exc) == 'Invalid email or password' for every cause."""
        account, password = _failure_case(cause, current_hash)

        with pytest.raises(LoginFailedError) as exc_info:
            await _login(_FakePool(account), password=password)

        assert str(exc_info.value) == LOGIN_FAILED_MESSAGE

    @pytest.mark.parametrize("cause", _FAILURE_CAUSES)
    async def test_auth_login_failure_opens_no_session(self, cause: str, current_hash: str) -> None:
        """No session INSERT and no last_login_at UPDATE on failure."""
        account, password = _failure_case(cause, current_hash)
        pool = _FakePool(account)

        with pytest.raises(LoginFailedError):
            await _login(pool, password=password)

        assert pool.matching(r"insert into sessions") == []
        assert pool.matching(r"last_login_at") == []

    @pytest.mark.parametrize("cause", [c for c in _FAILURE_CAUSES if c != "unknown-email"])
    async def test_auth_login_failure_for_known_user_is_audited_with_the_account(
        self, cause: str, current_hash: str
    ) -> None:
        """A known account: one login.failure row with its kind, id and org."""
        account, password = _failure_case(cause, current_hash)
        assert account is not None
        pool = _FakePool(account)

        with pytest.raises(LoginFailedError):
            await _login(pool, password=password)

        rows = pool.audit_rows()
        assert len(rows) == 1
        row = rows[0]
        assert row["action"] == "login.failure"
        assert row["actor_kind"] == account["kind"]
        assert row["actor_user_id"] == _USER_ID
        expected_org = None if account["org_id"] is None else _ORG_ID
        assert row["org_id"] == expected_org
        assert str(row["ip"]) == _IP

    async def test_auth_login_failure_for_unknown_email_is_audited_as_system(self) -> None:
        """No account: a system actor with no user and no org, and the IP."""
        pool = _FakePool(None)

        with pytest.raises(LoginFailedError):
            await _login(pool)

        rows = pool.audit_rows()
        assert len(rows) == 1
        row = rows[0]
        assert row["action"] == "login.failure"
        assert (row["actor_kind"], row["actor_user_id"], row["org_id"]) == ("system", None, None)
        assert str(row["ip"]) == _IP

    @pytest.mark.parametrize("cause", _FAILURE_CAUSES)
    async def test_auth_login_failure_error_carries_no_input(
        self, cause: str, current_hash: str
    ) -> None:
        """The error names neither the email nor the password."""
        account, password = _failure_case(cause, current_hash)

        with pytest.raises(LoginFailedError) as exc_info:
            await _login(_FakePool(account), password=password)

        rendered = f"{exc_info.value!s} {exc_info.value!r} {exc_info.value.args!r}".casefold()
        assert _EMAIL.casefold() not in rendered
        assert password.casefold() not in rendered


# ---------------------------------------------------------------------------
# 5. Equalized timing: exactly one Argon2 verification on every path
# ---------------------------------------------------------------------------


class TestLoginEqualizedTiming:
    """passwords.verify_password runs exactly once per login, off the event loop."""

    @pytest.mark.parametrize("cause", _FAILURE_CAUSES)
    async def test_auth_login_failure_verifies_exactly_once(
        self, cause: str, current_hash: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One verify_password call for every failure cause, incl. an unknown email."""
        account, password = _failure_case(cause, current_hash)
        spy = _VerifySpy(monkeypatch)

        with pytest.raises(LoginFailedError):
            await _login(_FakePool(account), password=password)

        assert len(spy.calls) == 1

    async def test_auth_login_success_verifies_exactly_once(
        self, current_hash: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A successful login also costs exactly one verification."""
        spy = _VerifySpy(monkeypatch)

        await _login(_FakePool(_member(current_hash)))

        assert len(spy.calls) == 1

    @pytest.mark.parametrize("cause", ["unknown-email", "invited-no-password"])
    async def test_auth_login_without_hash_verifies_against_a_current_params_dummy(
        self, cause: str, current_hash: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No account or no stored hash: the check runs against a real PHC hash with the
        current parameters, so it costs what a real check costs."""
        account, password = _failure_case(cause, current_hash)
        spy = _VerifySpy(monkeypatch)

        with pytest.raises(LoginFailedError):
            await _login(_FakePool(account), password=password)

        _, encoded = spy.calls[0]
        parsed = passwords.parse_phc(encoded)
        assert (parsed.memory_cost, parsed.iterations, parsed.lanes) == (19456, 2, 1)
        assert len(parsed.digest) == 32

    @pytest.mark.parametrize("cause", ["wrong-password", "deactivated", "org-deactivated"])
    async def test_auth_login_known_user_verifies_against_the_stored_hash(
        self, cause: str, current_hash: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A known account with a hash is verified against that hash, even when it is
        inactive (the status is only decided after the verification)."""
        account, password = _failure_case(cause, current_hash)
        spy = _VerifySpy(monkeypatch)

        with pytest.raises(LoginFailedError):
            await _login(_FakePool(account), password=password)

        assert spy.calls == [(password, current_hash)]

    async def test_auth_login_verifies_off_the_event_loop_thread(
        self, current_hash: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argon2 is CPU-bound (~200 ms): it runs in a worker thread (asyncio.to_thread),
        so logins don't stall every other request."""
        spy = _VerifySpy(monkeypatch)

        await _login(_FakePool(_member(current_hash)))

        assert spy.threads
        assert threading.get_ident() not in spy.threads


# ---------------------------------------------------------------------------
# 6. No email or password in audit rows, other statements or logs
# ---------------------------------------------------------------------------

_ALL_CAUSES = ["success", *_FAILURE_CAUSES]


def _case(cause: str, current_hash: str) -> tuple[dict[str, Any] | None, str]:
    if cause == "success":
        return _member(current_hash), _PASSWORD
    return _failure_case(cause, current_hash)


class TestLoginNoContent:
    """The email travels only as the lookup's bind parameter; the password nowhere."""

    @pytest.mark.parametrize("cause", _ALL_CAUSES)
    async def test_auth_login_email_only_in_the_lookup(self, cause: str, current_hash: str) -> None:
        """No other statement (audit, session, updates, throttle counters) carries the email
        in SQL or args; only the account subject's digest takes it as its input (GH-157)."""
        account, password = _case(cause, current_hash)
        pool = _FakePool(account)

        with pytest.raises(LoginFailedError) if cause != "success" else contextlib.nullcontext():
            await _login(pool, password=password)

        for _, sql, args in pool.non_lookup_calls():
            if any(isinstance(arg, str) and arg.casefold() == _EMAIL.casefold() for arg in args):
                assert _only_digests_the_email(sql, args), sql
                assert _EMAIL.casefold() not in sql.casefold()
                continue
            flattened = f"{sql} {' '.join(str(arg) for arg in args)}".casefold()
            assert _EMAIL.casefold() not in flattened
            assert "marker.person" not in flattened

    @pytest.mark.parametrize("cause", _ALL_CAUSES)
    async def test_auth_login_audit_row_has_no_email_or_password(
        self, cause: str, current_hash: str
    ) -> None:
        """Neither value is in any audit bind parameter or the metadata."""
        account, password = _case(cause, current_hash)
        pool = _FakePool(account)

        with pytest.raises(LoginFailedError) if cause != "success" else contextlib.nullcontext():
            await _login(pool, password=password)

        rows = pool.audit_rows()
        assert len(rows) == 1
        rendered = " ".join(str(value) for value in rows[0].values()).casefold()
        assert _EMAIL.casefold() not in rendered
        assert password.casefold() not in rendered

    @pytest.mark.parametrize("cause", _ALL_CAUSES)
    async def test_auth_login_logs_no_email_or_password(
        self, cause: str, current_hash: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No log record at any level carries the email, the password or the token."""
        caplog.set_level(logging.DEBUG)
        account, password = _case(cause, current_hash)
        token = ""

        with pytest.raises(LoginFailedError) if cause != "success" else contextlib.nullcontext():
            token = (await _login(_FakePool(account), password=password)).token

        text = caplog.text.casefold()
        assert _EMAIL.casefold() not in text
        assert "marker.person" not in text
        assert password.casefold() not in text
        if token:
            assert token not in caplog.text


# ---------------------------------------------------------------------------
# 7. Logout
# ---------------------------------------------------------------------------


class TestLogout:
    """logout deletes the session row behind the token (GH-152)."""

    async def test_auth_logout_deletes_the_session_row(self) -> None:
        """One DELETE FROM sessions WHERE token_hash = $1, bound to the token's hash; no
        UPDATE (the revoked_at column is gone)."""
        token = "L" * 43
        pool = _FakePool(None)

        await logout(pool, token)

        deletes = pool.matching(r"^delete from sessions where (?:\w+\.)?token_hash = \$1$")
        assert len(deletes) == 1
        assert deletes[0][2] == (hash_session_token(token),)
        assert pool.matching(r"^update sessions\b") == []
        assert all("revoked_at" not in _norm(sql) for _, sql, _ in pool.calls)

    async def test_auth_logout_malformed_token_issues_no_query(self) -> None:
        """A token that can't exist touches nothing."""
        pool = _FakePool(None)

        await logout(pool, "not-a-token")

        assert pool.calls == []
