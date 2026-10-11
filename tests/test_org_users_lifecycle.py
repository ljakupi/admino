"""Tests for the Org Admin user lifecycle of admino.org_users (GH-164).

``deactivate_org_user(pool, *, actor, user_id, ip)``,
``reactivate_org_user(pool, *, actor, user_id, public_url, ip)``,
``delete_org_user(pool, *, actor, user_id, ip)`` and
``trigger_password_reset(pool, *, actor, user_id, public_url, ip)`` let an Org
Admin manage the users of their own organization. These tests run the real
service against the in-memory database of tests/db_fakes.py.

What these tests pin down:
- Authorization first: an Editor or a Super Admin principal gets
  ``PermissionError`` before any query is issued (``db.calls`` stays empty) and
  nothing changes.
- Tenant isolation: a user of another org, an unknown id, an invited account,
  a deleted account (``deleted_at`` set) or a Super Admin is
  ``accounts.UserNotInOrgError``; nothing changes, nothing is audited, nothing
  is queued. Even another org's only active Org Admin is "not found", never
  ``LastAdminError``.
- Deactivation: the last-admin guard runs first (inside the transaction);
  then ``status = 'deactivated'``, every session row of the user deleted
  through ``sessions.revoke_user_sessions``, one ``account_deactivated`` email
  (``{"org_name": ...}``) and one ``user.deactivate`` event
  (``{"sessions_revoked": n}``, 0 included). Connections, memory and settings
  are kept. An already deactivated user is ``InvalidUserStatusError``.
- Reactivation: only a deactivated user; the org row is locked FOR UPDATE and
  the seats counted (active + invited, not deleted, this org only) before the
  change; no free seat is ``invitations.SeatLimitError``. Then ``status =
  'active'``, one ``account_activated`` email (``org_name``, ``login_link =
  {public_url}/login``) and one ``user.activate`` event.
- Deletion: the last-admin guard first, then the sessions are counted and
  deleted, then ``DELETE FROM users`` scoped by id AND org (the cascades remove
  OAuth connections, memory, user settings, the reset token and queued
  emails). One ``user.delete`` event (``{"sessions_revoked": n}``) survives the
  deletion, and the email is free again.
- Admin-triggered password reset: only an active user; one fresh token whose
  SHA-256 hash replaces the previous one, one ``password_reset`` email with
  ``{public_url}/reset-password#token=<43 chars>``, one
  ``password_reset.request`` event with the admin as actor and
  ``{"email_sent": True}``; returns None. The public ``request_reset`` (#151)
  keeps working next to it.
- One transaction per action (committed); an audit failure propagates
  (``AuditRecordError``) and rolls everything back.
- No content: no audit row and no log line carries the user's name, email,
  a token or a link; errors carry no ids.

No real PostgreSQL, no network: every statement goes to ``FakeDb``.

Security notes:
- Tenant isolation at the data layer: every statement is scoped by the
  actor's org; another org's user answers exactly like an unknown id.
- Operator blindness: a Super Admin principal is refused before any query.
- Fail closed: no change, email or token survives a failed audit write.
"""

from __future__ import annotations

import inspect
import json
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import accounts, invitations, models, password_reset
from admino import sessions as sessions_mod
from admino.access import Principal
from admino.audit_events import AuditRecordError
from tests.db_fakes import (
    ID_PARAM_RE,
    LINK_PREFIX,
    ORG_ID,
    ORG_ID_PARAM_RE,
    ORG_NAME,
    OTHER_ORG_ID,
    PUBLIC_URL,
    TOKEN_RE,
    Call,
    FakeDb,
    plain,
    sha256,
)

if TYPE_CHECKING:
    from types import ModuleType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP: Final = "203.0.113.41"
_INVALID_STATUS_MESSAGE: Final = "This change isn't possible in the user's current status."
_LOGIN_LINK: Final = PUBLIC_URL + "/login"

_ACTIONS: Final = ("deactivate", "reactivate", "delete", "password_reset")
# The status a target must have for the action to apply.
_VALID_STATUS: Final = {
    "deactivate": "active",
    "reactivate": "deactivated",
    "delete": "active",
    "password_reset": "active",
}
_AUDIT_ACTION: Final = {
    "deactivate": "user.deactivate",
    "reactivate": "user.activate",
    "delete": "user.delete",
    "password_reset": "password_reset.request",
}
_OUTSIDE_CASES: Final = ("other-org", "unknown", "invited", "deleted", "super-admin")
_INACTIVE_OTHER_ADMINS: Final = ("none", "deactivated", "invited", "deleted", "other-org")

_GUARD_RE: Final = r"\bas is_active_admin from users\b"
_WRITE_RE: Final = r"^(?:insert|update|delete)\b"
_ORG_LOCK_RE: Final = r"\bfrom organizations\b.*\bfor (?:no key )?update\b"


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def ou() -> ModuleType:
    """admino.org_users, imported per test so each test fails on its own until the
    module exists."""
    from admino import org_users

    return org_users


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database."""
    return FakeDb()


def _member(user_id: uuid.UUID, role: str, org_id: uuid.UUID = ORG_ID) -> Principal:
    return Principal(user_id=user_id, kind="member", org_id=org_id, role=role)  # type: ignore[arg-type]


def _admin(db: FakeDb, **fields: Any) -> tuple[uuid.UUID, Principal]:
    """An active Org Admin of ORG_ID and the Principal of their session."""
    admin_id = db.add_account(role="org_admin", **fields)
    return admin_id, _member(admin_id, "org_admin")


def _forbidden_actor(db: FakeDb, kind: str) -> Principal:
    """An Editor of ORG_ID or a Super Admin: neither may manage users."""
    if kind == "super_admin":
        user_id = db.add_account(kind="super_admin", role=None)
        return Principal(user_id=user_id, kind="super_admin")
    return _member(db.add_account(role=kind), kind)


def _target(db: FakeDb, action: str, **fields: Any) -> uuid.UUID:
    """A member of ORG_ID in the status the action applies to."""
    fields.setdefault("status", _VALID_STATUS[action])
    return db.add_account(**fields)


def _outside_target(db: FakeDb, case: str, action: str) -> uuid.UUID:
    """A user id the actor (an Org Admin of ORG_ID) must not reach."""
    status = _VALID_STATUS[action]
    if case == "other-org":
        # The other org's only Org Admin: a guard without the org scope would leak
        # LastAdminError (409) instead of "not found".
        return db.add_account(org_id=OTHER_ORG_ID, role="org_admin", status=status)
    if case == "invited":
        user_id = db.add_account(status="invited", password_hash=None, name=None)
        db.add_invitation(user_id)
        return user_id
    if case == "deleted":
        return db.add_account(status=status, deleted_at=datetime.now(UTC) - timedelta(days=1))
    if case == "super-admin":
        return db.add_account(kind="super_admin", role=None)
    return uuid.uuid4()


def _inactive_other_admin(db: FakeDb, case: str) -> None:
    """Another Org Admin who does NOT count as an active Org Admin of ORG_ID."""
    if case == "deactivated":
        db.add_account(role="org_admin", status="deactivated")
    elif case == "invited":
        db.add_account(role="org_admin", status="invited", password_hash=None, name=None)
    elif case == "deleted":
        db.add_account(role="org_admin", deleted_at=datetime.now(UTC) - timedelta(days=1))
    elif case == "other-org":
        db.add_account(role="org_admin", org_id=OTHER_ORG_ID)


async def _act(ou: ModuleType, db: FakeDb, action: str, actor: Principal, user_id: Any) -> Any:
    """Call the service function of an action with the default IP and public URL."""
    if action == "deactivate":
        return await ou.deactivate_org_user(db.pool, actor=actor, user_id=user_id, ip=_IP)
    if action == "reactivate":
        return await ou.reactivate_org_user(
            db.pool, actor=actor, user_id=user_id, public_url=PUBLIC_URL, ip=_IP
        )
    if action == "delete":
        return await ou.delete_org_user(db.pool, actor=actor, user_id=user_id, ip=_IP)
    return await ou.trigger_password_reset(
        db.pool, actor=actor, user_id=user_id, public_url=PUBLIC_URL, ip=_IP
    )


def _one(calls: list[Call]) -> Call:
    assert len(calls) == 1, calls
    return calls[0]


def _bound_to(call: Call, pattern: str) -> Any:
    """The bind argument of the ``<column> = $n`` the pattern finds in the call's SQL."""
    match = re.search(pattern, call.normalized)
    assert match is not None, call.normalized
    return call.args[int(match.group(1)) - 1]


def _index(db: FakeDb, pattern: str) -> int:
    """The position of the first call whose normalized SQL matches."""
    for index, call in enumerate(db.calls):
        if re.search(pattern, call.normalized):
            return index
    msg = f"no call matches {pattern!r}"
    raise AssertionError(msg)


def _audit_one(db: FakeDb, action: str) -> dict[str, Any]:
    """The single audit row of the action (and no other audit row at all)."""
    rows = db.audit_rows(action)
    assert len(rows) == 1, db.audit
    assert db.audit_rows() == rows, db.audit
    return rows[0]


def _assert_member_event(row: dict[str, Any], *, actor_id: uuid.UUID, target: uuid.UUID) -> None:
    """Actor = the Org Admin as a member, their org, target the user, the client IP."""
    assert (row["actor_kind"], str(row["actor_user_id"]), str(row["org_id"])) == (
        "member",
        str(actor_id),
        str(ORG_ID),
    )
    assert (row["target_type"], row["target_ids"]) == ("user", [str(target)])
    assert row["ip"] == _IP


def _assert_single_committed_transaction(db: FakeDb) -> int:
    """Every statement ran on one acquired connection, inside one committed transaction."""
    assert db.calls
    first = db.calls[0]
    assert first.via != "pool"
    assert first.tx is not None
    assert {(call.via, call.tx) for call in db.calls} == {(first.via, first.tx)}
    assert db.transactions == [(first.tx, "commit")]
    return first.tx


def _spy_revoke_user_sessions(
    ou: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
) -> list[tuple[Any, bool, int]]:
    """Wrap sessions.revoke_user_sessions (and a direct import in org_users, if any)."""
    real = sessions_mod.revoke_user_sessions
    seen: list[tuple[Any, bool, int]] = []

    async def spy(executor: Any, user_id: Any) -> int:
        in_transaction = executor is not db.pool and executor.is_in_transaction()
        count: int = await real(executor, user_id)
        seen.append((user_id, in_transaction, count))
        return count

    monkeypatch.setattr(sessions_mod, "revoke_user_sessions", spy)
    if hasattr(ou, "revoke_user_sessions"):
        monkeypatch.setattr(ou, "revoke_user_sessions", spy)
    return seen


# ---------------------------------------------------------------------------
# 1. Public surface
# ---------------------------------------------------------------------------


class TestLifecycleSurface:
    """Signatures and the fixed messages of the contract."""

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("deactivate_org_user", ["pool", "actor", "user_id", "ip"]),
            ("reactivate_org_user", ["pool", "actor", "user_id", "public_url", "ip"]),
            ("delete_org_user", ["pool", "actor", "user_id", "ip"]),
            ("trigger_password_reset", ["pool", "actor", "user_id", "public_url", "ip"]),
        ],
    )
    def test_org_users_lifecycle_signature_is_keyword_only_after_pool(
        self, ou: ModuleType, name: str, expected: list[str]
    ) -> None:
        function = getattr(ou, name)
        params = list(inspect.signature(function).parameters.values())

        assert inspect.iscoroutinefunction(function)
        assert [param.name for param in params] == expected
        assert all(param.kind is inspect.Parameter.KEYWORD_ONLY for param in params[1:])

    def test_org_users_lifecycle_messages_are_fixed(self, ou: ModuleType) -> None:
        """The 404 and invalid-status messages are fixed strings, never built from input."""
        assert ou.USER_NOT_FOUND_MESSAGE == "User not found"
        assert ou.INVALID_USER_STATUS_MESSAGE == _INVALID_STATUS_MESSAGE
        assert issubclass(ou.InvalidUserStatusError, Exception)


# ---------------------------------------------------------------------------
# 2. Authorization before any query
# ---------------------------------------------------------------------------


class TestLifecycleAuthorization:
    """Only an Org Admin (ORG_USERS_MANAGE) may act; the refusal issues no query."""

    @pytest.mark.parametrize("action", _ACTIONS)
    @pytest.mark.parametrize("kind", ["editor", "super_admin"])
    async def test_org_users_lifecycle_without_manage_capability_is_forbidden_before_any_query(
        self, ou: ModuleType, db: FakeDb, action: str, kind: str
    ) -> None:
        _admin(db)
        actor = _forbidden_actor(db, kind)
        target = _target(db, action)
        db.open_session(target)
        db.add_reset_token(target)
        before = db.snapshot()

        with pytest.raises(PermissionError):
            await _act(ou, db, action, actor, target)

        assert db.calls == []
        assert db.snapshot() == before


# ---------------------------------------------------------------------------
# 3. Tenant isolation
# ---------------------------------------------------------------------------


class TestLifecycleTenantIsolation:
    """Outside the actor's org (or not a user here): UserNotInOrgError, nothing changes."""

    @pytest.mark.parametrize("action", _ACTIONS)
    @pytest.mark.parametrize("case", _OUTSIDE_CASES)
    async def test_org_users_lifecycle_target_outside_the_org_is_user_not_in_org(
        self, ou: ModuleType, db: FakeDb, action: str, case: str
    ) -> None:
        _, admin = _admin(db)
        target = _outside_target(db, case, action)
        if target in db.users:
            db.open_session(target)
            db.add_reset_token(target)
        before = db.snapshot()

        with pytest.raises(accounts.UserNotInOrgError) as excinfo:
            await _act(ou, db, action, admin, target)

        assert db.snapshot() == before
        assert db.audit == []
        assert db.outbox == []
        assert str(target) not in str(excinfo.value)


# ---------------------------------------------------------------------------
# 4. Deactivation
# ---------------------------------------------------------------------------


class TestDeactivate:
    """deactivate_org_user: status, sessions, email, audit, guards."""

    async def test_org_users_deactivate_sets_status_deactivated(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        _, admin = _admin(db)
        target = _target(db, "deactivate")

        await _act(ou, db, "deactivate", admin, target)

        assert db.users[target]["status"] == "deactivated"

    async def test_org_users_deactivate_returns_the_deactivated_summary(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """An OrgUserSummary of the target with status "deactivated" and its stored fields."""
        _, admin = _admin(db)
        created = datetime(2026, 5, 4, 3, 2, 1, tzinfo=UTC)
        last_login = datetime(2026, 9, 30, 8, 15, tzinfo=UTC)
        target = _target(
            db,
            "deactivate",
            role="org_admin",
            email="summary.target@example.test",
            name="Summary Person",
            created_at=created,
            last_login_at=last_login,
        )

        result = await _act(ou, db, "deactivate", admin, target)

        assert isinstance(result, models.OrgUserSummary)
        assert type(result.id) is uuid.UUID
        assert (
            result.id,
            result.name,
            result.email,
            result.role,
            result.status,
            result.created_at,
            result.last_login_at,
        ) == (
            target,
            "Summary Person",
            "summary.target@example.test",
            "org_admin",
            "deactivated",
            created,
            last_login,
        )

    async def test_org_users_deactivate_revokes_every_session_of_the_user_only(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """Live, idle and expired session rows of the target go; everyone else's stay."""
        admin_id, admin = _admin(db)
        target = _target(db, "deactivate")
        bystander = db.add_account()
        outsider = db.add_account(org_id=OTHER_ORG_ID)
        theirs = [
            db.open_session(target),
            db.open_session(target, last_seen_ago=timedelta(minutes=90)),
            db.open_session(target, expires_in=timedelta(seconds=-5)),
        ]
        kept = [db.open_session(admin_id), db.open_session(bystander), db.open_session(outsider)]

        await _act(ou, db, "deactivate", admin, target)

        assert db.sessions_of(target) == []
        assert all(db.session_revoked(token) for token in theirs)
        assert not any(db.session_revoked(token) for token in kept)

    async def test_org_users_deactivate_is_audited(self, ou: ModuleType, db: FakeDb) -> None:
        """One user.deactivate row: the admin as member actor, their org, target the user,
        the IP, metadata {"sessions_revoked": n}."""
        admin_id, admin = _admin(db)
        target = _target(db, "deactivate")
        for _ in range(3):
            db.open_session(target)

        await _act(ou, db, "deactivate", admin, target)

        row = _audit_one(db, "user.deactivate")
        _assert_member_event(row, actor_id=admin_id, target=target)
        assert row["metadata"] == {"sessions_revoked": 3}
        assert type(row["metadata"]["sessions_revoked"]) is int

    async def test_org_users_deactivate_without_sessions_records_zero(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        _, admin = _admin(db)
        target = _target(db, "deactivate")

        await _act(ou, db, "deactivate", admin, target)

        assert _audit_one(db, "user.deactivate")["metadata"] == {"sessions_revoked": 0}

    async def test_org_users_deactivate_queues_one_account_deactivated_email(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """One pending account_deactivated email to the user, params {"org_name": ...} only."""
        _, admin = _admin(db)
        target = _target(db, "deactivate", email="deactivated.user@example.test")

        await _act(ou, db, "deactivate", admin, target)

        assert len(db.outbox) == 1
        row = db.outbox[0]
        assert row["user_id"] == target
        assert row["recipient_address"] == "deactivated.user@example.test"
        assert row["template_key"] == "account_deactivated"
        assert row["status"] == "pending"
        assert row["params"] == {"org_name": ORG_NAME}

    async def test_org_users_deactivate_keeps_connections_memory_and_settings(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """Deactivation is reversible: OAuth connections, memory and user settings stay."""
        _, admin = _admin(db)
        target = _target(db, "deactivate")
        db.add_oauth_token(target, "google", encrypted_refresh_token="enc-google")
        db.add_oauth_token(target, "microsoft", encrypted_refresh_token="enc-microsoft")
        db.add_memory(target, "favourite_colour", "blue")
        db.add_user_settings(target, theme="dark")

        await _act(ou, db, "deactivate", admin, target)

        assert db.oauth_token(target, "google") is not None
        assert db.oauth_token(target, "microsoft") is not None
        assert db.memories_of(target) == {"favourite_colour": "blue"}
        assert db.user_settings[target]["theme"] == "dark"

    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    async def test_org_users_deactivate_any_role_of_the_org(
        self, ou: ModuleType, db: FakeDb, role: str
    ) -> None:
        """Any member of the org can be deactivated (another admin included, not the last)."""
        _, admin = _admin(db)
        target = _target(db, "deactivate", role=role)

        result = await _act(ou, db, "deactivate", admin, target)

        assert result.status == "deactivated"
        assert db.users[target]["status"] == "deactivated"

    async def test_org_users_deactivate_already_deactivated_is_invalid_status(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """InvalidUserStatusError with the fixed message (no ids); nothing queued, audited or
        revoked."""
        _, admin = _admin(db)
        target = db.add_account(status="deactivated")
        db.open_session(target)
        before = db.snapshot()

        with pytest.raises(ou.InvalidUserStatusError) as excinfo:
            await _act(ou, db, "deactivate", admin, target)

        assert str(excinfo.value) == _INVALID_STATUS_MESSAGE
        assert str(target) not in repr(excinfo.value.args)
        assert db.snapshot() == before

    @pytest.mark.parametrize("other_admin", _INACTIVE_OTHER_ADMINS)
    async def test_org_users_deactivate_last_active_admin_is_refused(
        self, ou: ModuleType, db: FakeDb, other_admin: str
    ) -> None:
        """The only active Org Admin (other admins deactivated, invited, deleted or in another
        org don't count) can't be deactivated: LastAdminError, nothing changes."""
        admin_id, admin = _admin(db)
        _inactive_other_admin(db, other_admin)
        db.open_session(admin_id)
        before = db.snapshot()

        with pytest.raises(accounts.LastAdminError):
            await _act(ou, db, "deactivate", admin, admin_id)

        assert db.snapshot() == before

    @pytest.mark.parametrize("who", ["self", "other"])
    async def test_org_users_deactivate_admin_with_a_second_active_admin_passes(
        self, ou: ModuleType, db: FakeDb, who: str
    ) -> None:
        """With another active Org Admin the guard passes, self-deactivation included."""
        admin_id, admin = _admin(db)
        second = db.add_account(role="org_admin")
        target = admin_id if who == "self" else second
        token = db.open_session(target)

        await _act(ou, db, "deactivate", admin, target)

        assert db.users[target]["status"] == "deactivated"
        assert db.session_revoked(token)
        assert _audit_one(db, "user.deactivate")["target_ids"] == [str(target)]

    async def test_org_users_deactivate_runs_the_last_admin_guard_first(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """accounts.ensure_not_last_active_admin's query, bound to (actor's org, target), runs
        in the transaction before the status change and the session deletion."""
        _, admin = _admin(db)
        target = _target(db, "deactivate")
        db.open_session(target)

        await _act(ou, db, "deactivate", admin, target)

        guard = db.calls[_index(db, _GUARD_RE)]
        update = _one(db.matching(r"^update users\b"))
        assert [plain(arg) for arg in guard.args] == [ORG_ID, target]
        assert (guard.via, guard.tx) == (update.via, update.tx)
        assert _index(db, _GUARD_RE) < db.calls.index(update)
        assert _index(db, _GUARD_RE) < _index(db, r"^delete from sessions\b")

    async def test_org_users_deactivate_update_is_scoped_to_the_actors_org(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """The UPDATE binds the target id and the actor's org id (never interpolated)."""
        _, admin = _admin(db)
        target = _target(db, "deactivate")

        await _act(ou, db, "deactivate", admin, target)

        update = _one(db.matching(r"^update users\b"))
        assert plain(_bound_to(update, ID_PARAM_RE)) == target
        assert plain(_bound_to(update, ORG_ID_PARAM_RE)) == ORG_ID
        assert str(target) not in update.sql

    async def test_org_users_deactivate_revokes_through_revoke_user_sessions(
        self, ou: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The shared revocation service deletes the sessions, once, inside the transaction."""
        _, admin = _admin(db)
        target = _target(db, "deactivate")
        db.open_session(target)
        db.open_session(target)
        seen = _spy_revoke_user_sessions(ou, db, monkeypatch)

        await _act(ou, db, "deactivate", admin, target)

        assert len(seen) == 1
        user_id, in_transaction, count = seen[0]
        assert plain(user_id) == target
        assert in_transaction
        assert count == 2

    async def test_org_users_deactivate_runs_in_one_committed_transaction(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        _, admin = _admin(db)
        target = _target(db, "deactivate")
        db.open_session(target)

        await _act(ou, db, "deactivate", admin, target)

        _assert_single_committed_transaction(db)

    async def test_org_users_deactivate_audit_failure_changes_nothing(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """Fail closed: AuditRecordError propagates; status, sessions and outbox as before."""
        _, admin = _admin(db)
        target = _target(db, "deactivate")
        tokens = [db.open_session(target), db.open_session(target)]
        before = db.snapshot()
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _act(ou, db, "deactivate", admin, target)

        assert db.snapshot() == before
        assert db.users[target]["status"] == "active"
        assert not any(db.session_revoked(token) for token in tokens)
        assert db.outbox == []
        assert [outcome for _, outcome in db.transactions] == ["rollback:AuditRecordError"]


# ---------------------------------------------------------------------------
# 5. Reactivation
# ---------------------------------------------------------------------------


class TestReactivate:
    """reactivate_org_user: status, seats, email, audit."""

    async def test_org_users_reactivate_sets_status_active(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        _, admin = _admin(db)
        target = _target(db, "reactivate")

        await _act(ou, db, "reactivate", admin, target)

        assert db.users[target]["status"] == "active"

    async def test_org_users_reactivate_returns_the_active_summary(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        _, admin = _admin(db)
        target = _target(db, "reactivate", role="editor", email="back.again@example.test")

        result = await _act(ou, db, "reactivate", admin, target)

        assert isinstance(result, models.OrgUserSummary)
        assert (result.id, result.email, result.role, result.status) == (
            target,
            "back.again@example.test",
            "editor",
            "active",
        )

    async def test_org_users_reactivate_is_audited(self, ou: ModuleType, db: FakeDb) -> None:
        """One user.activate row: the admin as member actor, their org, target the user, IP."""
        admin_id, admin = _admin(db)
        target = _target(db, "reactivate")

        await _act(ou, db, "reactivate", admin, target)

        _assert_member_event(_audit_one(db, "user.activate"), actor_id=admin_id, target=target)

    async def test_org_users_reactivate_queues_one_account_activated_email(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """One pending account_activated email: org_name and login_link = {public_url}/login."""
        _, admin = _admin(db)
        target = _target(db, "reactivate", email="reactivated.user@example.test")

        await _act(ou, db, "reactivate", admin, target)

        assert len(db.outbox) == 1
        row = db.outbox[0]
        assert row["user_id"] == target
        assert row["recipient_address"] == "reactivated.user@example.test"
        assert row["template_key"] == "account_activated"
        assert row["status"] == "pending"
        assert row["params"] == {"org_name": ORG_NAME, "login_link": _LOGIN_LINK}

    async def test_org_users_reactivate_active_user_is_invalid_status(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        _, admin = _admin(db)
        target = db.add_account(status="active")
        before = db.snapshot()

        with pytest.raises(ou.InvalidUserStatusError) as excinfo:
            await _act(ou, db, "reactivate", admin, target)

        assert str(excinfo.value) == _INVALID_STATUS_MESSAGE
        assert db.snapshot() == before

    @pytest.mark.parametrize("occupant", ["active", "invited"])
    async def test_org_users_reactivate_without_a_free_seat_is_seat_limit(
        self, ou: ModuleType, db: FakeDb, occupant: str
    ) -> None:
        """Seats == active + invited users (invited accounts take a seat): SeatLimitError,
        the user stays deactivated, nothing queued or audited."""
        _, admin = _admin(db)
        if occupant == "invited":
            db.add_account(status="invited", password_hash=None, name=None)
        else:
            db.add_account(status="active")
        target = _target(db, "reactivate")
        db.add_org(ORG_ID, seats=2)
        before = db.snapshot()

        with pytest.raises(invitations.SeatLimitError) as excinfo:
            await _act(ou, db, "reactivate", admin, target)

        assert str(excinfo.value) == invitations.SEAT_LIMIT_MESSAGE
        assert db.users[target]["status"] == "deactivated"
        assert db.snapshot() == before

    async def test_org_users_reactivate_in_an_over_full_org_is_seat_limit(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """More seats taken than the org has (seats lowered later): still refused."""
        _, admin = _admin(db)
        db.add_account(status="active")
        db.add_account(status="active")
        target = _target(db, "reactivate")
        db.add_org(ORG_ID, seats=1)

        with pytest.raises(invitations.SeatLimitError):
            await _act(ou, db, "reactivate", admin, target)

        assert db.users[target]["status"] == "deactivated"
        assert db.audit == []
        assert db.outbox == []

    async def test_org_users_reactivate_takes_the_last_free_seat(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """One seat free (seats 2, the admin active): the reactivation passes."""
        _, admin = _admin(db)
        target = _target(db, "reactivate")
        db.add_org(ORG_ID, seats=2)

        await _act(ou, db, "reactivate", admin, target)

        assert db.users[target]["status"] == "active"

    async def test_org_users_reactivate_deactivated_users_take_no_seat(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        _, admin = _admin(db)
        for _ in range(3):
            db.add_account(status="deactivated")
        target = _target(db, "reactivate")
        db.add_org(ORG_ID, seats=2)

        await _act(ou, db, "reactivate", admin, target)

        assert db.users[target]["status"] == "active"

    async def test_org_users_reactivate_deleted_users_take_no_seat(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        _, admin = _admin(db)
        gone = datetime.now(UTC) - timedelta(days=3)
        db.add_account(status="active", deleted_at=gone)
        db.add_account(status="invited", password_hash=None, name=None, deleted_at=gone)
        target = _target(db, "reactivate")
        db.add_org(ORG_ID, seats=2)

        await _act(ou, db, "reactivate", admin, target)

        assert db.users[target]["status"] == "active"

    async def test_org_users_reactivate_other_orgs_users_take_no_seat(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        _, admin = _admin(db)
        for _ in range(3):
            db.add_account(status="active", org_id=OTHER_ORG_ID)
        target = _target(db, "reactivate")
        db.add_org(ORG_ID, seats=2)

        await _act(ou, db, "reactivate", admin, target)

        assert db.users[target]["status"] == "active"

    async def test_org_users_reactivate_locks_the_org_row_before_counting_and_updating(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """SELECT ... FROM organizations ... FOR UPDATE of the actor's org, in the same
        transaction, before the seat count and before the status UPDATE."""
        _, admin = _admin(db)
        target = _target(db, "reactivate")

        await _act(ou, db, "reactivate", admin, target)

        update = _one(db.matching(r"^update users\b"))
        lock_index = _index(db, _ORG_LOCK_RE)
        lock = db.calls[lock_index]
        assert (lock.via, lock.tx) == (update.via, update.tx)
        assert lock.tx is not None
        assert ORG_ID in [plain(arg) for arg in lock.args if isinstance(arg, uuid.UUID)]
        counts = [
            index
            for index, call in enumerate(db.calls)
            if call.tx == update.tx
            and re.search(r"\bcount ?\(", call.normalized)
            and re.search(r"\bfrom users\b", call.normalized)
        ]
        assert counts, "the seats are never counted"
        assert lock_index < min(counts) < db.calls.index(update)

    async def test_org_users_reactivate_runs_in_one_committed_transaction(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        _, admin = _admin(db)
        target = _target(db, "reactivate")

        await _act(ou, db, "reactivate", admin, target)

        _assert_single_committed_transaction(db)

    async def test_org_users_reactivate_audit_failure_changes_nothing(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """Fail closed: AuditRecordError propagates; still deactivated, no email queued."""
        _, admin = _admin(db)
        target = _target(db, "reactivate")
        before = db.snapshot()
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _act(ou, db, "reactivate", admin, target)

        assert db.snapshot() == before
        assert db.users[target]["status"] == "deactivated"
        assert db.outbox == []
        assert [outcome for _, outcome in db.transactions] == ["rollback:AuditRecordError"]


# ---------------------------------------------------------------------------
# 6. Deletion
# ---------------------------------------------------------------------------


def _seed_user_data(db: FakeDb, user_id: uuid.UUID) -> None:
    """Two sessions, both connections, a note, settings, a reset token and a queued email."""
    db.open_session(user_id)
    db.open_session(user_id)
    db.add_oauth_token(user_id, "google", encrypted_refresh_token="enc-google")
    db.add_oauth_token(user_id, "microsoft", encrypted_refresh_token="enc-microsoft")
    db.add_memory(user_id, "project_notes", "quarterly close")
    db.add_user_settings(user_id, theme="dark")
    db.add_reset_token(user_id)
    db.add_email(
        user_id,
        template_key="account_activated",
        params={"org_name": ORG_NAME, "login_link": _LOGIN_LINK},
    )


def _user_data(db: FakeDb, user_id: uuid.UUID) -> dict[str, Any]:
    """Everything stored for a user, by table."""
    return {
        "user": user_id in db.users,
        "sessions": len(db.sessions_of(user_id)),
        "google": db.oauth_token(user_id, "google") is not None,
        "microsoft": db.oauth_token(user_id, "microsoft") is not None,
        "memory": db.memories_of(user_id),
        "settings": user_id in db.user_settings,
        "reset_token": user_id in db.tokens,
        "emails": len([row for row in db.outbox if row["user_id"] == user_id]),
    }


class TestDelete:
    """delete_org_user: the account and everything of it go; the audit stays."""

    async def test_org_users_delete_removes_the_account_and_all_its_data(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """Users row, sessions, OAuth connections, memory, settings, reset token and queued
        emails of the user are gone; the function returns None."""
        _, admin = _admin(db)
        target = _target(db, "delete")
        _seed_user_data(db, target)

        result = await _act(ou, db, "delete", admin, target)

        assert result is None
        assert _user_data(db, target) == {
            "user": False,
            "sessions": 0,
            "google": False,
            "microsoft": False,
            "memory": {},
            "settings": False,
            "reset_token": False,
            "emails": 0,
        }

    async def test_org_users_delete_keeps_other_users_data(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        admin_id, admin = _admin(db)
        target = _target(db, "delete")
        bystander = db.add_account()
        outsider = db.add_account(org_id=OTHER_ORG_ID)
        for user_id in (target, admin_id, bystander, outsider):
            _seed_user_data(db, user_id)
        expected = {user_id: _user_data(db, user_id) for user_id in (admin_id, bystander, outsider)}

        await _act(ou, db, "delete", admin, target)

        assert {user_id: _user_data(db, user_id) for user_id in expected} == expected

    async def test_org_users_delete_is_audited_and_the_row_survives(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """One user.delete row (admin as member actor, org, target, IP,
        {"sessions_revoked": n}) that outlives the deleted account."""
        admin_id, admin = _admin(db)
        target = _target(db, "delete")
        for _ in range(3):
            db.open_session(target)

        await _act(ou, db, "delete", admin, target)

        assert target not in db.users
        row = _audit_one(db, "user.delete")
        _assert_member_event(row, actor_id=admin_id, target=target)
        assert row["metadata"] == {"sessions_revoked": 3}
        assert type(row["metadata"]["sessions_revoked"]) is int

    async def test_org_users_delete_without_sessions_records_zero(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        _, admin = _admin(db)
        target = _target(db, "delete")

        await _act(ou, db, "delete", admin, target)

        assert _audit_one(db, "user.delete")["metadata"] == {"sessions_revoked": 0}

    async def test_org_users_delete_frees_the_email(self, ou: ModuleType, db: FakeDb) -> None:
        """Afterwards no user has the address (any capitalization): it can be invited again."""
        _, admin = _admin(db)
        target = _target(db, "delete", email="Reusable.Address@example.test")

        await _act(ou, db, "delete", admin, target)

        assert await accounts.email_exists(db.pool, "reusable.address@example.test") is False

    async def test_org_users_delete_queues_no_email(self, ou: ModuleType, db: FakeDb) -> None:
        """Nothing is left in the outbox for the deleted user (no orphaned email)."""
        _, admin = _admin(db)
        target = _target(db, "delete")

        await _act(ou, db, "delete", admin, target)

        assert db.outbox == []
        assert target not in db.users

    async def test_org_users_delete_deactivated_user(self, ou: ModuleType, db: FakeDb) -> None:
        _, admin = _admin(db)
        target = db.add_account(status="deactivated")
        _seed_user_data(db, target)

        await _act(ou, db, "delete", admin, target)

        assert _user_data(db, target)["user"] is False
        assert _audit_one(db, "user.delete")["target_ids"] == [str(target)]

    async def test_org_users_delete_deactivated_admin_while_actor_is_the_only_active_admin(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """A deactivated Org Admin isn't an active one: the guard lets the deletion pass."""
        _, admin = _admin(db)
        target = db.add_account(role="org_admin", status="deactivated")

        await _act(ou, db, "delete", admin, target)

        assert target not in db.users

    @pytest.mark.parametrize("other_admin", _INACTIVE_OTHER_ADMINS)
    async def test_org_users_delete_last_active_admin_is_refused(
        self, ou: ModuleType, db: FakeDb, other_admin: str
    ) -> None:
        """Deleting the only active Org Admin: LastAdminError, nothing removed."""
        admin_id, admin = _admin(db)
        _inactive_other_admin(db, other_admin)
        _seed_user_data(db, admin_id)
        before = db.snapshot()

        with pytest.raises(accounts.LastAdminError):
            await _act(ou, db, "delete", admin, admin_id)

        assert db.snapshot() == before
        assert _user_data(db, admin_id)["user"] is True

    @pytest.mark.parametrize("who", ["self", "other"])
    async def test_org_users_delete_admin_with_a_second_active_admin_passes(
        self, ou: ModuleType, db: FakeDb, who: str
    ) -> None:
        """A non-last Org Admin can be deleted, the actor themselves included."""
        admin_id, admin = _admin(db)
        second = db.add_account(role="org_admin")
        target = admin_id if who == "self" else second
        db.open_session(target)

        await _act(ou, db, "delete", admin, target)

        assert target not in db.users
        row = _audit_one(db, "user.delete")
        _assert_member_event(row, actor_id=admin_id, target=target)
        assert row["metadata"] == {"sessions_revoked": 1}

    async def test_org_users_delete_runs_the_guard_and_revokes_sessions_before_the_delete(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """Guard query (bound to the actor's org and the target) first, then the sessions
        DELETE, then the users DELETE, all in one transaction."""
        _, admin = _admin(db)
        target = _target(db, "delete")
        db.open_session(target)

        await _act(ou, db, "delete", admin, target)

        guard_index = _index(db, _GUARD_RE)
        sessions_index = _index(db, r"^delete from sessions\b")
        users_delete = _one(db.matching(r"^delete from users\b"))
        assert [plain(arg) for arg in db.calls[guard_index].args] == [ORG_ID, target]
        assert guard_index < sessions_index < db.calls.index(users_delete)

    async def test_org_users_delete_statement_is_scoped_to_the_actors_org(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """DELETE FROM users binds the target id AND the actor's org id."""
        _, admin = _admin(db)
        target = _target(db, "delete")

        await _act(ou, db, "delete", admin, target)

        delete = _one(db.matching(r"^delete from users\b"))
        assert plain(_bound_to(delete, ID_PARAM_RE)) == target
        assert plain(_bound_to(delete, ORG_ID_PARAM_RE)) == ORG_ID
        assert str(target) not in delete.sql

    async def test_org_users_delete_revokes_through_revoke_user_sessions(
        self, ou: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, admin = _admin(db)
        target = _target(db, "delete")
        for _ in range(3):
            db.open_session(target)
        seen = _spy_revoke_user_sessions(ou, db, monkeypatch)

        await _act(ou, db, "delete", admin, target)

        assert len(seen) == 1
        user_id, in_transaction, count = seen[0]
        assert plain(user_id) == target
        assert in_transaction
        assert count == 3

    async def test_org_users_delete_runs_in_one_committed_transaction(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        _, admin = _admin(db)
        target = _target(db, "delete")
        db.open_session(target)

        await _act(ou, db, "delete", admin, target)

        _assert_single_committed_transaction(db)

    async def test_org_users_delete_audit_failure_removes_nothing(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """Fail closed: AuditRecordError propagates; the account and all its rows stay."""
        _, admin = _admin(db)
        target = _target(db, "delete")
        _seed_user_data(db, target)
        before = db.snapshot()
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _act(ou, db, "delete", admin, target)

        assert db.snapshot() == before
        assert _user_data(db, target)["user"] is True
        assert [outcome for _, outcome in db.transactions] == ["rollback:AuditRecordError"]


# ---------------------------------------------------------------------------
# 7. Admin-triggered password reset
# ---------------------------------------------------------------------------


class TestTriggerPasswordReset:
    """trigger_password_reset: #151's flow, started by an Org Admin for an active user."""

    async def test_org_users_reset_queues_one_password_reset_email(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """One pending password_reset email to the user with
        {public_url}/reset-password#token=<43 URL-safe characters>."""
        _, admin = _admin(db)
        target = _target(db, "password_reset", email="forgetful.user@example.test")

        await _act(ou, db, "password_reset", admin, target)

        assert len(db.outbox) == 1
        row = db.outbox[0]
        assert row["user_id"] == target
        assert row["recipient_address"] == "forgetful.user@example.test"
        assert row["template_key"] == "password_reset"
        assert row["status"] == "pending"
        link = row["params"]["reset_link"]
        assert link.startswith(LINK_PREFIX)
        assert TOKEN_RE.fullmatch(link[len(LINK_PREFIX) :]) is not None

    async def test_org_users_reset_stores_only_the_token_hash(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """The stored token is the SHA-256 of the emailed one; the raw token travels only in
        the queued email's params."""
        _, admin = _admin(db)
        target = _target(db, "password_reset")

        await _act(ou, db, "password_reset", admin, target)

        token = db.issued_token()
        assert db.tokens[target]["token_hash"] == sha256(token)
        for call in db.calls:
            if call.normalized.startswith("insert into email_outbox"):
                continue
            assert token not in call.sql
            assert not any(token in str(arg) for arg in call.args), call.normalized

    async def test_org_users_reset_replaces_the_previous_token(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """One live token per user: the older link stops matching."""
        _, admin = _admin(db)
        target = _target(db, "password_reset")
        old = db.add_reset_token(target)

        await _act(ou, db, "password_reset", admin, target)

        assert db.tokens[target]["token_hash"] != sha256(old)
        assert db.tokens[target]["token_hash"] == sha256(db.issued_token())

    async def test_org_users_reset_token_lives_30_minutes(self, ou: ModuleType, db: FakeDb) -> None:
        """The token upsert carries the 30-minute lifetime of #151."""
        _, admin = _admin(db)
        target = _target(db, "password_reset")

        await _act(ou, db, "password_reset", admin, target)

        upsert = _one(db.matching(r"^insert into password_reset_tokens\b"))
        assert timedelta(minutes=30) in upsert.args or re.search(
            r"interval '30 min", upsert.normalized
        )

    async def test_org_users_reset_is_audited_with_the_admin_as_actor(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """One password_reset.request row: the admin (member) as actor, their org, target the
        user, the IP, metadata {"email_sent": True}."""
        admin_id, admin = _admin(db)
        target = _target(db, "password_reset")

        await _act(ou, db, "password_reset", admin, target)

        row = _audit_one(db, "password_reset.request")
        _assert_member_event(row, actor_id=admin_id, target=target)
        assert row["metadata"] == {"email_sent": True}

    async def test_org_users_reset_returns_none(self, ou: ModuleType, db: FakeDb) -> None:
        """The admin never sees the token or the link."""
        _, admin = _admin(db)
        target = _target(db, "password_reset")

        result = await _act(ou, db, "password_reset", admin, target)

        assert result is None

    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    async def test_org_users_reset_any_role_of_the_org(
        self, ou: ModuleType, db: FakeDb, role: str
    ) -> None:
        _, admin = _admin(db)
        target = _target(db, "password_reset", role=role)

        await _act(ou, db, "password_reset", admin, target)

        assert db.tokens[target]["token_hash"] == sha256(db.issued_token())

    async def test_org_users_reset_for_a_deactivated_user_is_invalid_status(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """InvalidUserStatusError; no email queued, the previous token untouched, no audit."""
        _, admin = _admin(db)
        target = db.add_account(status="deactivated")
        old = db.add_reset_token(target)
        before = db.snapshot()

        with pytest.raises(ou.InvalidUserStatusError) as excinfo:
            await _act(ou, db, "password_reset", admin, target)

        assert str(excinfo.value) == _INVALID_STATUS_MESSAGE
        assert db.snapshot() == before
        assert db.tokens[target]["token_hash"] == sha256(old)
        assert db.outbox == []

    async def test_org_users_reset_runs_in_one_committed_transaction(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """Token upsert, email and audit share one connection and one committed transaction."""
        _, admin = _admin(db)
        target = _target(db, "password_reset")

        await _act(ou, db, "password_reset", admin, target)

        writes = [
            _one(db.matching(r"^insert into password_reset_tokens\b")),
            _one(db.matching(r"^insert into email_outbox\b")),
            _one(db.matching(r"^insert into audit_events\b")),
        ]
        assert writes[0].tx is not None
        assert writes[0].via != "pool"
        assert {(call.via, call.tx) for call in db.matching(_WRITE_RE)} == {
            (writes[0].via, writes[0].tx)
        }
        assert (writes[0].tx, "commit") in db.transactions
        assert all(outcome == "commit" for _, outcome in db.transactions)

    async def test_org_users_reset_audit_failure_stores_and_queues_nothing(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """Fail closed: AuditRecordError propagates; the old token still matches, no email."""
        _, admin = _admin(db)
        target = _target(db, "password_reset")
        old = db.add_reset_token(target)
        before = db.snapshot()
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _act(ou, db, "password_reset", admin, target)

        assert db.snapshot() == before
        assert db.tokens[target]["token_hash"] == sha256(old)
        assert db.outbox == []
        assert "rollback:AuditRecordError" in [outcome for _, outcome in db.transactions]

    async def test_org_users_reset_keeps_the_public_reset_flow_working(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        """After an admin-triggered reset, the user's own request (#151, the public route)
        still queues its email, replaces the admin-issued token and audits the user as
        actor: extracting the shared helper broke nothing."""
        admin_id, admin = _admin(db)
        target = _target(db, "password_reset", email="self.service@example.test")

        await _act(ou, db, "password_reset", admin, target)
        await password_reset.request_reset(
            db.pool, email="self.service@example.test", public_url=PUBLIC_URL, ip=_IP
        )

        assert len(db.reset_links()) == 2
        admin_token, own_token = db.issued_token(0), db.issued_token(1)
        assert db.tokens[target]["token_hash"] == sha256(own_token)
        assert db.tokens[target]["token_hash"] != sha256(admin_token)
        rows = db.audit_rows("password_reset.request")
        assert [str(row["actor_user_id"]) for row in rows] == [str(admin_id), str(target)]
        assert [row["metadata"] for row in rows] == [{"email_sent": True}, {"email_sent": True}]


# ---------------------------------------------------------------------------
# 8. No content in audit rows or logs
# ---------------------------------------------------------------------------

_MARKER_EMAIL: Final = "content.marker@example.test"
_MARKER_NAME: Final = "Zelda Markerperson"


class TestLifecycleNoContent:
    """IDs, counts and bools only: never a name, an email, a token or a link."""

    async def test_org_users_lifecycle_audit_rows_carry_no_content(
        self, ou: ModuleType, db: FakeDb
    ) -> None:
        _, admin = _admin(db, email="admin.marker@example.test", name="Ada Adminmarker")
        target = db.add_account(email=_MARKER_EMAIL, name=_MARKER_NAME)

        await _act(ou, db, "deactivate", admin, target)
        await _act(ou, db, "reactivate", admin, target)
        await _act(ou, db, "password_reset", admin, target)
        token = db.issued_token()
        await _act(ou, db, "delete", admin, target)

        assert [row["action"] for row in db.audit] == [
            "user.deactivate",
            "user.activate",
            "password_reset.request",
            "user.delete",
        ]
        text = json.dumps(db.audit, default=str)
        for secret in (_MARKER_EMAIL, "Markerperson", "admin.marker", "Adminmarker", token):
            assert secret not in text
        assert PUBLIC_URL not in text

    async def test_org_users_lifecycle_logs_carry_no_content(
        self, ou: ModuleType, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Successful and refused actions log no name, email, token or link."""
        caplog.set_level(logging.DEBUG)
        admin_id, admin = _admin(db, email="admin.marker@example.test", name="Ada Adminmarker")
        target = db.add_account(email=_MARKER_EMAIL, name=_MARKER_NAME)
        outsider = db.add_account(
            org_id=OTHER_ORG_ID, email="outsider.marker@example.test", name="Otto Outsidermarker"
        )
        db.open_session(target)

        await _act(ou, db, "deactivate", admin, target)
        with pytest.raises(ou.InvalidUserStatusError):
            await _act(ou, db, "deactivate", admin, target)
        with pytest.raises(ou.InvalidUserStatusError):
            await _act(ou, db, "password_reset", admin, target)
        await _act(ou, db, "reactivate", admin, target)
        await _act(ou, db, "password_reset", admin, target)
        token = db.issued_token()
        with pytest.raises(accounts.UserNotInOrgError):
            await _act(ou, db, "delete", admin, outsider)
        with pytest.raises(accounts.LastAdminError):
            await _act(ou, db, "deactivate", admin, admin_id)
        await _act(ou, db, "delete", admin, target)

        text = caplog.text
        for secret in (
            _MARKER_EMAIL,
            "Markerperson",
            "admin.marker",
            "Adminmarker",
            "outsider.marker",
            "Outsidermarker",
            token,
            PUBLIC_URL,
        ):
            assert secret not in text
