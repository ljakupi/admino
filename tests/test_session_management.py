"""Tests for admino.session_management — listing and revoking sessions (GH-152).

``list_user_sessions(executor, *, user_id, current_session_id)`` lists a user's
live sessions; ``revoke_own_session(pool, *, principal, session_id, ip)`` lets a
user delete one of their own sessions (audited as ``session.revoke``);
``force_logout(pool, *, actor, user_id, ip)`` lets an Org Admin delete every
session of a user of their org (audited as ``session.force_logout``). The
models ``SessionSummary`` and ``SessionListResponse`` (admino.models) carry the
list.

What these tests pin down:
- ``SessionNotFoundError``: a fixed "Session not found" message, no IDs.
- The list: one ``fetch`` bound to the user id only; the SQL filters
  ``user_id = $1`` and live sessions (``expires_at > now()`` and ``last_seen_at +
  make_interval(mins => idle_timeout_minutes) > now()``), orders by
  ``last_seen_at DESC`` and never selects ``token_hash``. Rows map to
  ``SessionSummary`` with a plain ``uuid.UUID`` id, the IP as a string (asyncpg
  returns ipaddress objects for INET) and ``current`` true exactly for
  ``current_session_id``.
- Revoking one's own session: on one acquired connection, in one transaction,
  ``DELETE FROM sessions WHERE id = $a AND user_id = $b RETURNING id`` bound to the
  session id and the principal's user id; no row → ``SessionNotFoundError`` and
  no audit; otherwise a ``session.revoke`` event (actor = the principal, their org
  or none for a Super Admin, target the user, the IP, metadata ``{"session_id":
  <uuid string>}``) in the same transaction. An audit failure rolls the delete
  back.
- Forced logout: ``PermissionError`` before any query unless
  ``access.can(actor, Capability.ORG_USERS_MANAGE)``; then, in one transaction, a
  users lookup bound to the user id AND the actor's org AND ``deleted_at IS
  NULL`` (not found → ``accounts.UserNotInOrgError``, nothing deleted, nothing
  audited), every session of the target deleted through
  ``sessions.revoke_user_sessions`` on the transaction's connection, and a
  ``session.force_logout`` event with ``{"sessions_revoked": n}`` (also when n is
  0). Returns n. An audit failure rolls everything back.

All database calls go to the in-memory fake of tests/db_fakes.py or to a
recording executor. No real PostgreSQL connections are made.

Security notes:
- Tenant isolation at the data layer: every statement is scoped by the
  caller's user id or the actor's org id; another user's session, or a user of
  another org, is "not found" (the routes answer 404, never 403).
- The list never reads token hashes; errors carry no IDs; logs carry no token,
  IP, user agent or email.
- Content-free audit (tracker #139 §5): IDs, the IP and a count only.
"""

from __future__ import annotations

import inspect
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Any

import pytest
from asyncpg.pgproto.pgproto import UUID as PgUUID  # noqa: N811

from admino import accounts, models
from admino import sessions as sessions_mod
from admino.access import Capability, Principal
from admino.audit_events import AuditRecordError
from tests.db_fakes import (
    ID_PARAM_RE,
    LIVE_EXPIRY_RE,
    LIVE_IDLE_RE,
    ORG_ID,
    ORG_ID_PARAM_RE,
    OTHER_ORG_ID,
    USER_ID_PARAM_RE,
    Call,
    FakeDb,
)

if TYPE_CHECKING:
    from types import ModuleType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP = "203.0.113.7"
_USER_ID = uuid.UUID("7b8c9d0e-1f2a-4b3c-8d4e-5f6a7b8c9d0e")
_SESSION_A = uuid.UUID("11111111-aaaa-4aaa-8aaa-111111111111")
_SESSION_B = uuid.UUID("22222222-bbbb-4bbb-8bbb-222222222222")
_SESSION_C = uuid.UUID("33333333-cccc-4ccc-8ccc-333333333333")
_UA = "Mozilla/5.0 (session-list-marker)"


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def sm() -> ModuleType:
    """admino.session_management, imported per test so each test fails on its own until
    the module exists."""
    from admino import session_management

    return session_management


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database."""
    return FakeDb()


def _principal(db: FakeDb, user_id: uuid.UUID) -> Principal:
    """The Principal a resolved session of this stored account would carry."""
    account = db.users[user_id]
    if account["kind"] == "super_admin":
        return Principal(user_id=user_id, kind="super_admin")
    return Principal(user_id=user_id, kind="member", org_id=account["org_id"], role=account["role"])


def _add_super_admin(db: FakeDb) -> uuid.UUID:
    return db.add_account(kind="super_admin", role=None, org_status=None)


def _one(calls: list[Call]) -> Call:
    assert len(calls) == 1, calls
    return calls[0]


def _bound_to(call: Call, pattern: str) -> Any:
    """The bind argument of the ``<column> = $n`` the pattern finds in the call's SQL."""
    match = re.search(pattern, call.normalized)
    assert match is not None, call.normalized
    return call.args[int(match.group(1)) - 1]


class _ListExecutor:
    """Records every call; fetch() returns the given driver-shaped rows."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, str, tuple[Any, ...]]] = []

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        self.calls.append(("fetch", sql, args))
        return self.rows

    async def fetchrow(self, sql: str, *args: Any) -> Any:
        self.calls.append(("fetchrow", sql, args))
        return None

    async def fetchval(self, sql: str, *args: Any) -> Any:
        self.calls.append(("fetchval", sql, args))
        return None

    async def execute(self, sql: str, *args: Any) -> str:
        self.calls.append(("execute", sql, args))
        return "OK"


def _driver_row(session_id: uuid.UUID, **overrides: Any) -> dict[str, Any]:
    """A list row as asyncpg returns it: asyncpg UUID, INET as an ipaddress object."""
    now = datetime.now(UTC)
    row: dict[str, Any] = {
        "id": PgUUID(str(session_id)),
        "created_at": now - timedelta(hours=2),
        "last_seen_at": now - timedelta(minutes=3),
        "expires_at": now + timedelta(hours=10),
        "ip": IPv4Address("198.51.100.4"),
        "user_agent": _UA,
    }
    row.update(overrides)
    return row


async def _list(sm: ModuleType, executor: Any, current: uuid.UUID | None = _SESSION_A) -> Any:
    return await sm.list_user_sessions(executor, user_id=_USER_ID, current_session_id=current)


# ---------------------------------------------------------------------------
# 1. The models and the error
# ---------------------------------------------------------------------------


class TestSessionModels:
    """SessionSummary and SessionListResponse (admino.models) carry no secret."""

    def test_session_management_summary_has_exactly_the_listed_fields(self) -> None:
        """id, created_at, last_seen_at, expires_at, ip, user_agent, current: no token or
        token hash field."""
        assert set(models.SessionSummary.model_fields) == {
            "id",
            "created_at",
            "last_seen_at",
            "expires_at",
            "ip",
            "user_agent",
            "current",
        }

    def test_session_management_list_response_has_only_sessions(self) -> None:
        """SessionListResponse is {"sessions": [SessionSummary, ...]}."""
        now = datetime.now(UTC)
        summary = models.SessionSummary(
            id=_SESSION_A,
            created_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(hours=1),
            ip=None,
            user_agent=None,
            current=True,
        )

        response = models.SessionListResponse(sessions=[summary])

        assert set(models.SessionListResponse.model_fields) == {"sessions"}
        assert response.model_dump(mode="json")["sessions"][0]["id"] == str(_SESSION_A)

    def test_session_management_summary_field_types(self) -> None:
        """id is a UUID, the timestamps datetimes, ip and user_agent optional strings,
        current a bool."""
        now = datetime.now(UTC)

        summary = models.SessionSummary(
            id=_SESSION_A,
            created_at=now,
            last_seen_at=now,
            expires_at=now,
            ip="203.0.113.7",
            user_agent="ua",
            current=False,
        )

        assert type(summary.id) is uuid.UUID
        assert isinstance(summary.expires_at, datetime)
        assert (summary.ip, summary.user_agent, summary.current) == ("203.0.113.7", "ua", False)


class TestSessionNotFoundError:
    """One fixed message, no IDs."""

    def test_session_management_not_found_message(self, sm: ModuleType) -> None:
        """str(SessionNotFoundError()) is "Session not found"."""
        assert str(sm.SessionNotFoundError()) == "Session not found"

    def test_session_management_not_found_carries_no_ids(self, sm: ModuleType) -> None:
        """Its only argument is the fixed message."""
        assert sm.SessionNotFoundError().args == ("Session not found",)

    def test_session_management_not_found_is_an_exception(self, sm: ModuleType) -> None:
        assert issubclass(sm.SessionNotFoundError, Exception)


# ---------------------------------------------------------------------------
# 2. list_user_sessions
# ---------------------------------------------------------------------------


class TestListUserSessionsQuery:
    """One fetch, scoped to the user, live sessions only, newest activity first."""

    async def test_session_management_list_is_one_fetch_bound_to_the_user(
        self, sm: ModuleType
    ) -> None:
        """Exactly one fetch, and its only bind parameter is the user id."""
        executor = _ListExecutor([])

        await _list(sm, executor)

        assert len(executor.calls) == 1
        method, sql, args = executor.calls[0]
        assert method == "fetch"
        assert args == (_USER_ID,)
        assert str(_USER_ID) not in sql

    async def test_session_management_list_filters_by_user_and_liveness(
        self, sm: ModuleType
    ) -> None:
        """WHERE user_id = $1 AND expires_at > now() AND last_seen_at +
        make_interval(mins => idle_timeout_minutes) > now()."""
        executor = _ListExecutor([])

        await _list(sm, executor)

        sql = re.sub(r"\s+", " ", executor.calls[0][1]).strip().lower()
        where = sql.split(" where ", 1)[1]
        assert re.search(USER_ID_PARAM_RE, where) is not None, where
        assert re.search(LIVE_EXPIRY_RE, where) is not None, where
        assert re.search(LIVE_IDLE_RE, where) is not None, where

    async def test_session_management_list_orders_by_last_seen_desc(self, sm: ModuleType) -> None:
        """ORDER BY last_seen_at DESC: the most recently active session first."""
        executor = _ListExecutor([])

        await _list(sm, executor)

        sql = re.sub(r"\s+", " ", executor.calls[0][1]).strip().lower()
        assert re.search(r"\border by (?:\w+\.)?last_seen_at desc\b", sql) is not None, sql

    async def test_session_management_list_never_reads_the_token_hash(self, sm: ModuleType) -> None:
        """token_hash is never selected (nor used at all)."""
        executor = _ListExecutor([])

        await _list(sm, executor)

        assert "token_hash" not in executor.calls[0][1].lower()

    def test_session_management_list_signature(self, sm: ModuleType) -> None:
        """list_user_sessions(executor, *, user_id, current_session_id)."""
        params = list(inspect.signature(sm.list_user_sessions).parameters.values())

        assert [p.name for p in params] == ["executor", "user_id", "current_session_id"]
        assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in params[1:])


class TestListUserSessionsMapping:
    """Driver rows become SessionSummary models."""

    async def test_session_management_list_returns_session_summaries_in_row_order(
        self, sm: ModuleType
    ) -> None:
        """A list of exact SessionSummary instances, in the order the query returned."""
        executor = _ListExecutor([_driver_row(_SESSION_B), _driver_row(_SESSION_A)])

        result = await _list(sm, executor)

        assert type(result) is list
        assert all(type(item) is models.SessionSummary for item in result)
        assert [item.id for item in result] == [_SESSION_B, _SESSION_A]

    async def test_session_management_list_ids_are_plain_uuids(self, sm: ModuleType) -> None:
        """asyncpg's UUID subclass never leaks into the model."""
        result = await _list(sm, _ListExecutor([_driver_row(_SESSION_A)]))

        assert type(result[0].id) is uuid.UUID

    @pytest.mark.parametrize(
        ("stored", "expected"),
        [
            pytest.param(IPv4Address("198.51.100.4"), "198.51.100.4", id="ipv4"),
            pytest.param(IPv6Address("2001:db8::7"), "2001:db8::7", id="ipv6"),
            pytest.param(None, None, id="none"),
        ],
    )
    async def test_session_management_list_ip_is_a_string(
        self, sm: ModuleType, stored: Any, expected: str | None
    ) -> None:
        """INET comes back as an ipaddress object; the summary holds its string (or None)."""
        result = await _list(sm, _ListExecutor([_driver_row(_SESSION_A, ip=stored)]))

        assert result[0].ip == expected
        assert expected is None or type(result[0].ip) is str

    async def test_session_management_list_carries_the_row_values(self, sm: ModuleType) -> None:
        """user_agent and the three timestamps come from the row unchanged."""
        row = _driver_row(_SESSION_A, user_agent=None)

        summary = (await _list(sm, _ListExecutor([row])))[0]

        assert summary.user_agent is None
        assert (summary.created_at, summary.last_seen_at, summary.expires_at) == (
            row["created_at"],
            row["last_seen_at"],
            row["expires_at"],
        )

    async def test_session_management_list_marks_only_the_current_session(
        self, sm: ModuleType
    ) -> None:
        """current is True exactly for current_session_id (compared by value with the
        row's asyncpg UUID)."""
        rows = [_driver_row(_SESSION_A), _driver_row(_SESSION_B), _driver_row(_SESSION_C)]

        result = await _list(sm, _ListExecutor(rows), current=_SESSION_B)

        assert [(item.id, item.current) for item in result] == [
            (_SESSION_A, False),
            (_SESSION_B, True),
            (_SESSION_C, False),
        ]
        assert all(type(item.current) is bool for item in result)

    async def test_session_management_list_without_a_matching_current_marks_none(
        self, sm: ModuleType
    ) -> None:
        """A current session id that isn't in the list marks nothing current."""
        rows = [_driver_row(_SESSION_A), _driver_row(_SESSION_B)]

        result = await _list(sm, _ListExecutor(rows), current=_SESSION_C)

        assert [item.current for item in result] == [False, False]

    async def test_session_management_list_of_nothing_is_empty(self, sm: ModuleType) -> None:
        assert await _list(sm, _ListExecutor([])) == []


class TestListUserSessionsAgainstTheDatabase:
    """Through the in-memory database: the caller's live sessions only."""

    async def test_session_management_list_returns_only_the_users_live_sessions(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """Expired and idle sessions (not purged yet) and another user's sessions are left
        out; the live ones come newest activity first."""
        user_id = db.add_account()
        other = db.add_account()
        older = db.open_session(user_id, last_seen_ago=timedelta(minutes=30))
        newest = db.open_session(user_id)
        middle = db.open_session(
            user_id, idle_timeout_minutes=480, last_seen_ago=timedelta(hours=2)
        )
        db.open_session(user_id, expires_in=timedelta(seconds=-1))
        db.open_session(user_id, idle_timeout_minutes=15, last_seen_ago=timedelta(minutes=16))
        db.open_session(other)

        result = await sm.list_user_sessions(
            db.pool, user_id=user_id, current_session_id=db.session_id_of(newest)
        )

        assert [item.id for item in result] == [
            db.session_id_of(newest),
            db.session_id_of(older),
            db.session_id_of(middle),
        ]
        assert [item.current for item in result] == [True, False, False]


# ---------------------------------------------------------------------------
# 3. revoke_own_session
# ---------------------------------------------------------------------------


async def _revoke_own(
    sm: ModuleType, db: FakeDb, principal: Principal, session_id: uuid.UUID
) -> Any:
    return await sm.revoke_own_session(db.pool, principal=principal, session_id=session_id, ip=_IP)


def _revoke_delete(db: FakeDb) -> Call:
    """The one DELETE FROM sessions of a revoke_own_session call."""
    return _one(db.matching(r"^delete from sessions\b"))


class TestRevokeOwnSession:
    """A user deletes one of their own sessions; the deletion is audited."""

    async def test_session_management_revoke_own_deletes_the_row(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """The chosen session's row is gone; the user's other sessions stay."""
        user_id = db.add_account()
        target = db.open_session(user_id)
        kept = db.open_session(user_id)

        result = await _revoke_own(sm, db, _principal(db, user_id), db.session_id_of(target))

        assert result is None
        assert db.session_revoked(target)
        assert not db.session_revoked(kept)

    async def test_session_management_revoke_own_may_delete_the_current_session(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """The service doesn't care which session the request came from."""
        user_id = db.add_account()
        only = db.open_session(user_id)

        await _revoke_own(sm, db, _principal(db, user_id), db.session_id_of(only))

        assert db.session_revoked(only)

    async def test_session_management_revoke_own_delete_is_scoped_to_the_principal(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """DELETE FROM sessions WHERE id = $a AND user_id = $b RETURNING id, bound to the
        session id and the principal's user id (the data layer enforces ownership)."""
        user_id = db.add_account()
        target = db.open_session(user_id)
        session_id = db.session_id_of(target)

        await _revoke_own(sm, db, _principal(db, user_id), session_id)

        delete = _revoke_delete(db)
        where = delete.normalized.split(" where ", 1)[1]
        assert re.fullmatch(
            r"(?:(?:\w+\.)?id = \$\d+ and (?:\w+\.)?user_id = \$\d+"
            r"|(?:\w+\.)?user_id = \$\d+ and (?:\w+\.)?id = \$\d+) returning (?:\w+\.)?id",
            where,
        ), where
        assert _bound_to(delete, ID_PARAM_RE) == session_id
        assert _bound_to(delete, USER_ID_PARAM_RE) == user_id
        assert str(session_id) not in delete.sql
        assert str(user_id) not in delete.sql

    @pytest.mark.parametrize("who", ["member", "super-admin"])
    async def test_session_management_revoke_own_is_audited(
        self, sm: ModuleType, db: FakeDb, who: str
    ) -> None:
        """One session.revoke row: the principal as actor, their org (none for a Super
        Admin), target the user, the IP, metadata {"session_id": <uuid string>}."""
        user_id = db.add_account() if who == "member" else _add_super_admin(db)
        target = db.open_session(user_id)
        session_id = db.session_id_of(target)

        await _revoke_own(sm, db, _principal(db, user_id), session_id)

        rows = db.audit_rows("session.revoke")
        assert len(rows) == 1
        row = rows[0]
        assert row["actor_kind"] == ("member" if who == "member" else "super_admin")
        assert row["actor_user_id"] == user_id
        assert row["org_id"] == (ORG_ID if who == "member" else None)
        assert (row["target_type"], row["target_ids"]) == ("user", [str(user_id)])
        assert row["ip"] == _IP
        assert row["metadata"] == {"session_id": str(session_id)}
        assert db.audit_rows() == rows

    async def test_session_management_revoke_own_runs_in_one_committed_transaction(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """The DELETE and the audit INSERT share one acquired connection and one
        transaction, which commits."""
        user_id = db.add_account()
        target = db.open_session(user_id)

        await _revoke_own(sm, db, _principal(db, user_id), db.session_id_of(target))

        delete = _revoke_delete(db)
        audit = _one(db.matching(r"^insert into audit_events\b"))
        assert delete.via != "pool"
        assert delete.tx is not None
        assert (audit.via, audit.tx) == (delete.via, delete.tx)
        assert db.transactions == [(delete.tx, "commit")]

    async def test_session_management_revoke_own_other_users_session_is_not_found(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """Another user's session id → SessionNotFoundError; their row survives and
        nothing is audited."""
        caller = db.add_account()
        victim = db.add_account()
        theirs = db.open_session(victim)

        with pytest.raises(sm.SessionNotFoundError):
            await _revoke_own(sm, db, _principal(db, caller), db.session_id_of(theirs))

        assert not db.session_revoked(theirs)
        assert db.audit_rows() == []

    async def test_session_management_revoke_own_other_orgs_session_is_not_found(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """A session of a user in another org is just as unknown."""
        caller = db.add_account(role="org_admin")
        outsider = db.add_account(org_id=OTHER_ORG_ID)
        theirs = db.open_session(outsider)

        with pytest.raises(sm.SessionNotFoundError):
            await _revoke_own(sm, db, _principal(db, caller), db.session_id_of(theirs))

        assert not db.session_revoked(theirs)
        assert db.audit_rows() == []

    async def test_session_management_revoke_own_unknown_session_is_not_found(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """An id that matches nothing → SessionNotFoundError, nothing audited."""
        caller = db.add_account()
        mine = db.open_session(caller)

        with pytest.raises(sm.SessionNotFoundError):
            await _revoke_own(sm, db, _principal(db, caller), uuid.uuid4())

        assert not db.session_revoked(mine)
        assert db.audit_rows() == []

    async def test_session_management_revoke_own_not_found_error_carries_no_ids(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """The raised error names neither the session nor the user."""
        caller = db.add_account()
        unknown = uuid.uuid4()

        with pytest.raises(sm.SessionNotFoundError) as exc_info:
            await _revoke_own(sm, db, _principal(db, caller), unknown)

        assert str(unknown) not in repr(exc_info.value)
        assert str(caller) not in repr(exc_info.value)

    async def test_session_management_revoke_own_audit_failure_rolls_back(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """Fail closed: the audit write fails → AuditRecordError, and the session row is
        still there (the delete rolled back)."""
        user_id = db.add_account()
        target = db.open_session(user_id)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _revoke_own(sm, db, _principal(db, user_id), db.session_id_of(target))

        assert not db.session_revoked(target)
        assert [outcome for _, outcome in db.transactions] == ["rollback:AuditRecordError"]

    def test_session_management_revoke_own_signature(self, sm: ModuleType) -> None:
        """revoke_own_session(pool, *, principal, session_id, ip)."""
        params = list(inspect.signature(sm.revoke_own_session).parameters.values())

        assert [p.name for p in params] == ["pool", "principal", "session_id", "ip"]
        assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in params[1:])


# ---------------------------------------------------------------------------
# 4. force_logout
# ---------------------------------------------------------------------------


async def _force(sm: ModuleType, db: FakeDb, actor: Any, user_id: uuid.UUID) -> Any:
    return await sm.force_logout(db.pool, actor=actor, user_id=user_id, ip=_IP)


def _admin(db: FakeDb) -> tuple[uuid.UUID, Principal]:
    admin_id = db.add_account(role="org_admin")
    return admin_id, _principal(db, admin_id)


def _users_lookup(db: FakeDb) -> Call:
    """The one users lookup of a force_logout call."""
    return _one(
        [
            call
            for call in db.calls
            if call.method in {"fetchrow", "fetchval", "fetch"}
            and re.search(r"\bfrom users\b", call.normalized)
        ]
    )


class TestForceLogoutPermission:
    """Only an Org Admin (Capability.ORG_USERS_MANAGE) may force a logout."""

    @pytest.mark.parametrize("who", ["editor", "super-admin"])
    async def test_session_management_force_logout_refused_without_org_users_manage(
        self, sm: ModuleType, db: FakeDb, who: str
    ) -> None:
        """PermissionError before any query; the target keeps its sessions."""
        actor_id = _add_super_admin(db) if who == "super-admin" else db.add_account(role=who)
        target = db.add_account()
        token = db.open_session(target)
        db.calls.clear()

        with pytest.raises(PermissionError):
            await _force(sm, db, _principal(db, actor_id), target)

        assert db.calls == []
        assert not db.session_revoked(token)

    async def test_session_management_force_logout_refuses_a_non_principal(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """Fail closed: anything that isn't a well-formed Principal gets PermissionError."""
        target = db.add_account()

        with pytest.raises(PermissionError):
            await _force(sm, db, object(), target)

        assert db.calls == []

    async def test_session_management_force_logout_checks_org_users_manage(
        self, sm: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The decision goes through access.can(actor, Capability.ORG_USERS_MANAGE)."""
        from admino import access

        real = access.can
        seen: list[Any] = []

        def spy(principal: Any, capability: Any) -> bool:
            seen.append(capability)
            return real(principal, capability)

        monkeypatch.setattr(access, "can", spy)
        if hasattr(sm, "can"):
            monkeypatch.setattr(sm, "can", spy)
        _, admin = _admin(db)
        target = db.add_account()

        await _force(sm, db, admin, target)

        assert Capability.ORG_USERS_MANAGE in seen


class TestForceLogout:
    """An Org Admin logs a user of their org out of every device; it is audited."""

    async def test_session_management_force_logout_deletes_every_session_of_the_target(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """All the target's rows are gone, the count is returned; another user's sessions
        (same org and other org) are untouched."""
        _, admin = _admin(db)
        target = db.add_account()
        bystander = db.add_account()
        outsider = db.add_account(org_id=OTHER_ORG_ID)
        tokens = [
            db.open_session(target),
            db.open_session(target, last_seen_ago=timedelta(minutes=30)),
            db.open_session(target, expires_in=timedelta(seconds=-5)),
        ]
        kept = [db.open_session(bystander), db.open_session(outsider)]

        count = await _force(sm, db, admin, target)

        assert count == 3
        assert type(count) is int
        assert all(db.session_revoked(token) for token in tokens)
        assert not any(db.session_revoked(token) for token in kept)

    async def test_session_management_force_logout_is_audited(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """One session.force_logout row: the Org Admin as member actor, their org, target
        the user, the IP, metadata {"sessions_revoked": n}."""
        admin_id, admin = _admin(db)
        target = db.add_account()
        db.open_session(target)
        db.open_session(target)

        await _force(sm, db, admin, target)

        rows = db.audit_rows("session.force_logout")
        assert len(rows) == 1
        row = rows[0]
        assert (row["actor_kind"], row["actor_user_id"], row["org_id"]) == (
            "member",
            admin_id,
            ORG_ID,
        )
        assert (row["target_type"], row["target_ids"]) == ("user", [str(target)])
        assert row["ip"] == _IP
        assert row["metadata"] == {"sessions_revoked": 2}
        assert type(row["metadata"]["sessions_revoked"]) is int
        assert db.audit_rows() == rows

    async def test_session_management_force_logout_without_sessions_records_zero(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """A target with no session: returns 0, and the forced logout is still audited."""
        _, admin = _admin(db)
        target = db.add_account()

        count = await _force(sm, db, admin, target)

        assert count == 0
        rows = db.audit_rows("session.force_logout")
        assert [row["metadata"] for row in rows] == [{"sessions_revoked": 0}]

    async def test_session_management_force_logout_of_oneself(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """An Org Admin may target themselves: every own session goes."""
        admin_id, admin = _admin(db)
        tokens = [db.open_session(admin_id), db.open_session(admin_id)]

        count = await _force(sm, db, admin, admin_id)

        assert count == 2
        assert all(db.session_revoked(token) for token in tokens)
        assert db.audit_rows("session.force_logout")[0]["target_ids"] == [str(admin_id)]

    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    async def test_session_management_force_logout_any_role_of_the_org(
        self, sm: ModuleType, db: FakeDb, role: str
    ) -> None:
        """Every member of the admin's org can be logged out, another admin included."""
        _, admin = _admin(db)
        target = db.add_account(role=role)
        token = db.open_session(target)

        assert await _force(sm, db, admin, target) == 1
        assert db.session_revoked(token)

    async def test_session_management_force_logout_of_a_deactivated_user_cleans_up(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """A deactivated (not deleted) member of the org is found; leftover rows go."""
        _, admin = _admin(db)
        target = db.add_account(status="deactivated")
        token = db.open_session(target)

        assert await _force(sm, db, admin, target) == 1
        assert db.session_revoked(token)

    async def test_session_management_force_logout_revokes_through_revoke_user_sessions(
        self, sm: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The shared deactivation service does the deletion, once, on the transaction's
        connection, with the target's id."""
        _, admin = _admin(db)
        target = db.add_account()
        db.open_session(target)
        real = sessions_mod.revoke_user_sessions
        seen: list[tuple[Any, Any, bool]] = []

        async def spy(executor: Any, user_id: Any) -> int:
            in_transaction = executor is not db.pool and executor.is_in_transaction()
            seen.append((executor, user_id, in_transaction))
            count: int = await real(executor, user_id)
            return count

        monkeypatch.setattr(sessions_mod, "revoke_user_sessions", spy)

        await _force(sm, db, admin, target)

        assert len(seen) == 1
        executor, user_id, in_transaction = seen[0]
        assert user_id == target
        assert in_transaction

    async def test_session_management_force_logout_lookup_is_scoped_to_the_actors_org(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """The users lookup binds the target id AND the actor's org id, and skips deleted
        users (deleted_at IS NULL): tenant isolation at the data layer."""
        _, admin = _admin(db)
        target = db.add_account()

        await _force(sm, db, admin, target)

        lookup = _users_lookup(db)
        assert _bound_to(lookup, ID_PARAM_RE) == target
        assert _bound_to(lookup, ORG_ID_PARAM_RE) == ORG_ID
        assert re.search(r"\b(?:\w+\.)?deleted_at is null\b", lookup.normalized) is not None
        assert str(target) not in lookup.sql
        assert str(ORG_ID) not in lookup.sql

    async def test_session_management_force_logout_runs_in_one_committed_transaction(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """Lookup, DELETE and audit share one acquired connection and one transaction."""
        _, admin = _admin(db)
        target = db.add_account()
        db.open_session(target)

        await _force(sm, db, admin, target)

        lookup = _users_lookup(db)
        delete = _one(db.matching(r"^delete from sessions\b"))
        audit = _one(db.matching(r"^insert into audit_events\b"))
        assert lookup.via != "pool"
        assert lookup.tx is not None
        assert {(call.via, call.tx) for call in (lookup, delete, audit)} == {
            (lookup.via, lookup.tx)
        }
        assert db.transactions == [(lookup.tx, "commit")]

    @pytest.mark.parametrize("case", ["other-org", "unknown", "deleted", "super-admin"])
    async def test_session_management_force_logout_outside_the_org_is_user_not_in_org(
        self, sm: ModuleType, db: FakeDb, case: str
    ) -> None:
        """A user of another org, an unknown id, a deleted user or a Super Admin →
        accounts.UserNotInOrgError; nothing deleted, nothing audited."""
        _, admin = _admin(db)
        if case == "other-org":
            target = db.add_account(org_id=OTHER_ORG_ID)
        elif case == "deleted":
            target = db.add_account(deleted_at=datetime.now(UTC) - timedelta(days=1))
        elif case == "super-admin":
            target = _add_super_admin(db)
        else:
            target = uuid.uuid4()
        token = db.open_session(target) if target in db.users else None

        with pytest.raises(accounts.UserNotInOrgError):
            await _force(sm, db, admin, target)

        assert token is None or not db.session_revoked(token)
        assert db.matching(r"^delete from sessions\b") == []
        assert db.audit_rows() == []

    async def test_session_management_force_logout_audit_failure_rolls_back(
        self, sm: ModuleType, db: FakeDb
    ) -> None:
        """Fail closed: AuditRecordError propagates and the target's sessions survive."""
        _, admin = _admin(db)
        target = db.add_account()
        tokens = [db.open_session(target), db.open_session(target)]
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _force(sm, db, admin, target)

        assert not any(db.session_revoked(token) for token in tokens)
        assert [outcome for _, outcome in db.transactions] == ["rollback:AuditRecordError"]

    def test_session_management_force_logout_signature(self, sm: ModuleType) -> None:
        """force_logout(pool, *, actor, user_id, ip)."""
        params = list(inspect.signature(sm.force_logout).parameters.values())

        assert [p.name for p in params] == ["pool", "actor", "user_id", "ip"]
        assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in params[1:])


# ---------------------------------------------------------------------------
# 5. No content in logs
# ---------------------------------------------------------------------------


class TestSessionManagementLogs:
    """No token, token hash, IP, user agent or email in any log line."""

    async def test_session_management_logs_nothing_identifying(
        self, sm: ModuleType, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        admin_id, admin = _admin(db)
        db.users[admin_id]["email"] = "log.marker.admin@example.test"
        target = db.add_account(email="log.marker.target@example.test")
        mine = db.open_session(admin_id, ip="198.51.100.77", user_agent=_UA)
        theirs = db.open_session(target, ip="198.51.100.78", user_agent=_UA)

        await sm.list_user_sessions(
            db.pool, user_id=admin_id, current_session_id=db.session_id_of(mine)
        )
        await _revoke_own(sm, db, admin, db.session_id_of(mine))
        with pytest.raises(sm.SessionNotFoundError):
            await _revoke_own(sm, db, admin, db.session_id_of(theirs))
        await _force(sm, db, admin, target)

        text = caplog.text
        for token in (mine, theirs):
            assert token not in text
        assert "log.marker" not in text
        assert _IP not in text
        assert "198.51.100.7" not in text
        assert "session-list-marker" not in text
