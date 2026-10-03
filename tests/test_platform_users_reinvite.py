"""Tests for admino.platform_users.reinvite_org_admin — the Super Admin re-invites an org's
primary admin (GH-167).

While an organization has no active Org Admin (its first invitation is still
pending), the Super Admin can act on that invited Org Admin's invitation from
the users list: without an email the invitation is sent again with a new link
(#153's resend), with an email the invited account is replaced by a new
invitation to that address (#153's revoke, then #153's send).

What these tests pin down:
- Authorization first: only ``Capability.PLATFORM_USERS_MANAGE`` (the Super
  Admin). Every member role, the admin CLI's ``Operator`` and a malformed
  principal get ``PermissionError("Forbidden")`` before any query.
- The order of the refusals, all in one transaction that changes nothing: an
  unknown org (``organizations.OrgNotFoundError``), an org that isn't active
  (``organizations.InvalidOrgStatusError``), a target that isn't a non-deleted
  user of that org (``accounts.UserNotInOrgError``: unknown, another org's,
  deleted, a Super Admin), a target that isn't an invited Org Admin with a
  pending invitation (``org_users.InvalidUserStatusError``), and an org that
  already has an active Org Admin (``platform_users.OrgHasActiveAdminError``,
  ``HAS_ACTIVE_ADMIN_MESSAGE``).
- Resend (``email=None``): the same invitation and users row; the token is
  rotated (the old link stops working at once, the new one works);
  ``sent_at = now``, ``expires_at = now + 72 h`` (an expired invitation
  included, without a seat check); the invitation email still queued with the
  old link is cancelled; a new email carries
  ``{public_url}/accept-invitation#token=<43 chars>``; one ``invitation.resend``
  audit row; the returned ``InvitationSummary`` has the same id and the new
  dates.
- Replace (an email): the invited account, its invitation and its queued email
  are gone (old link dead); a new invited Org Admin with the email and
  ``ui_language = language``, a new invitation and an email in that language;
  ``invitation.revoke`` then ``invitation.create``; the new summary. The same
  address in another capitalization works (new ids). A taken email
  (``accounts.DuplicateEmailError``) or an org over its seats even after the
  old seat is freed (``invitations.SeatLimitError``) rolls the whole
  transaction back and is then recorded as ``invitation.refuse``.
- Fail closed: a failed audit write raises ``AuditRecordError`` and nothing
  changes; the old link keeps working.

All database calls go to the in-memory fake of tests/db_fakes.py; the world is
built with the real #153/#154 code (``invitations.invite_first_org_admin``,
``organizations.create_org``). No real PostgreSQL, no SMTP.

Security notes:
- Every audit row is the Super Admin's (actor kind ``super_admin``) in the
  affected org's log, with the client IP; never an email, a token or a link.
- Nothing is logged, on success or on a refusal; errors carry fixed messages
  only (no IDs, no email).
- The raw token travels only inside the queued email's link: never in the
  returned summary or an audit row.
"""

from __future__ import annotations

import copy
import inspect
import json
import logging
import re
import traceback
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any

import pytest

from admino import accounts, invitations, models, org_users, organizations
from admino.access import Operator, Principal
from admino.audit_events import AuditRecordError
from tests.db_fakes import INVITE_LINK_PREFIX, PUBLIC_URL, TOKEN_RE, Call, FakeDb, plain, sha256

if TYPE_CHECKING:
    from types import ModuleType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP = "203.0.113.67"
_ORG_NAME = "Kanzlei Wiedereinladung AG"
_ADMIN_EMAIL = "Primary.Admin.Marker@Example.ch"
_NEW_EMAIL = "Grace.Replacement.Marker@Example.ch"
_TAKEN = "taken.person.marker@example.ch"
_OTHER_PUBLIC_URL = "https://kanzlei.example.org"
_DELETED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_HAS_ACTIVE_ADMIN = "The organization already has an active Org Admin."
_DUPLICATE_MESSAGE = "A user with this email already exists."
_SEAT_MESSAGE = "The organization has no free seats."
_ORG_NOT_FOUND_MESSAGE = "Organization not found"
_MODES = [pytest.param(None, id="resend"), pytest.param(_NEW_EMAIL, id="replace")]


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def pu() -> ModuleType:
    """admino.platform_users, imported per test so each test fails on its own until it exists."""
    from admino import platform_users

    return platform_users


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database."""
    return FakeDb()


@dataclass(frozen=True)
class _World:
    """An org whose only Org Admin is still invited: the first invitation is pending."""

    super_admin: Principal
    org_id: uuid.UUID
    user_id: uuid.UUID  # the invited primary admin
    invitation_id: uuid.UUID
    token: str  # the token of the link in the queued invitation email


def _id_of(db: FakeDb, email: str) -> uuid.UUID:
    """The id of the users row with this email (any capitalization)."""
    row = db.user_by_email(email)
    assert row is not None, email
    return plain(row["id"])


def _super_admin(db: FakeDb) -> Principal:
    return Principal(user_id=db.add_account(kind="super_admin", role=None), kind="super_admin")


async def _world(
    db: FakeDb,
    *,
    name: str = _ORG_NAME,
    email: str = _ADMIN_EMAIL,
    super_admin: Principal | None = None,
) -> _World:
    """A Super Admin and an org whose first Org Admin was invited (#153) but hasn't accepted.

    The setup's own calls are cleared: ``db.calls`` holds only what the test runs.
    """
    actor = super_admin or _super_admin(db)
    org_id = db.add_org(name=name, seats=5)
    summary = await invitations.invite_first_org_admin(
        db.pool,
        actor=actor,
        org_id=org_id,
        email=email,
        language="de",
        public_url=PUBLIC_URL,
        ip=_IP,
    )
    user_id = _id_of(db, email)
    db.calls.clear()
    return _World(actor, org_id, user_id, plain(summary.id), db.invitation_token(user_id))


async def _reinvite(
    pu: ModuleType,
    db: FakeDb,
    world: _World,
    *,
    email: str | None = None,
    actor: Any = None,
    org_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    language: str = "fr",
    public_url: str = PUBLIC_URL,
) -> Any:
    return await pu.reinvite_org_admin(
        db.pool,
        actor=world.super_admin if actor is None else actor,
        org_id=world.org_id if org_id is None else org_id,
        user_id=world.user_id if user_id is None else user_id,
        email=email,
        language=language,
        public_url=public_url,
        ip=_IP,
    )


def _invited(db: FakeDb, org_id: uuid.UUID, role: str, *, email: str | None = None) -> uuid.UUID:
    """An invited account of the org with a pending invitation and its queued email."""
    user_id = db.add_account(
        role=role, org_id=org_id, status="invited", name=None, password_hash=None, email=email
    )
    token = db.add_invitation(user_id)
    db.add_email(user_id, params={"accept_link": INVITE_LINK_PREFIX + token})
    return user_id


def _age(db: FakeDb, invitation_id: uuid.UUID, by: timedelta) -> None:
    """Move an invitation back in time: created_at, sent_at and expires_at together."""
    row = db.invitations[invitation_id]
    for column in ("created_at", "sent_at", "expires_at"):
        row[column] -= by


def _token_of(link: str, public_url: str = PUBLIC_URL) -> str:
    """The token of an accept link built from ``public_url``."""
    prefix = f"{public_url}/accept-invitation#token="
    assert link.startswith(prefix), link
    token = link[len(prefix) :]
    assert TOKEN_RE.fullmatch(token), link
    return token


async def _assert_link_works(db: FakeDb, token: str, email: str, org_name: str = _ORG_NAME) -> None:
    details = await invitations.get_invitation(db.pool, token)
    assert (details.email, details.role, details.org_name) == (email, "org_admin", org_name)


async def _assert_link_dead(db: FakeDb, token: str) -> None:
    with pytest.raises(invitations.InvalidInvitationError):
        await invitations.get_invitation(db.pool, token)


def _added_audit(db: FakeDb, before: dict[str, Any]) -> list[dict[str, Any]]:
    """The audit rows written since ``before`` (the earlier rows must be untouched)."""
    assert db.audit[: len(before["audit"])] == before["audit"]
    return db.audit[len(before["audit"]) :]


def _assert_super_admin_event(row: dict[str, Any], world: _World, action: str) -> None:
    """The Super Admin's event in the affected org's log, with the client IP."""
    assert row["action"] == action
    assert (row["actor_kind"], plain(row["actor_user_id"]), plain(row["org_id"])) == (
        "super_admin",
        world.super_admin.user_id,
        world.org_id,
    )
    assert row["ip"] == _IP


def _assert_only_refusal_audited(
    db: FakeDb, before: dict[str, Any], world: _World, reason: str
) -> None:
    """Every table is as before except audit_events, which gained exactly one content-free
    invitation.refuse row by the Super Admin in the org's log."""
    after = db.snapshot()
    assert {k: v for k, v in after.items() if k != "audit"} == {
        k: v for k, v in before.items() if k != "audit"
    }
    (row,) = _added_audit(db, before)
    _assert_super_admin_event(row, world, "invitation.refuse")
    assert (row["target_type"], row["target_ids"]) == (None, [])
    assert row["metadata"] == {"role": "org_admin", reason: True}


def _assert_no_ids(error: BaseException, *ids: uuid.UUID) -> None:
    """A refusal's message is fixed: it names no ID."""
    text = str(error).lower()
    for value in ids:
        assert str(value) not in text
        assert value.hex not in text


def _one(calls: list[Call]) -> Call:
    assert len(calls) == 1, calls
    return calls[0]


def _org_locks(db: FakeDb) -> list[Call]:
    """The statements that lock an organizations row."""
    return [
        call
        for call in db.calls
        if re.search(r"\bfrom organizations\b", call.normalized)
        and re.search(r"\bfor (?:no key )?update\b", call.normalized)
    ]


def _admino_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.name.startswith("admino")]


def _forge(principal: Principal, **fields: object) -> Principal:
    """Overwrite fields of a validated Principal without validation (a bypass's result)."""
    for name, value in fields.items():
        object.__setattr__(principal, name, value)
    return principal


class _PrincipalSubclass(Principal):
    """A Principal subclass: can() only trusts Principal itself."""


class _PrincipalLookalike:
    """A duck-typed object with a Super Admin's attributes, not a Principal."""

    def __init__(self) -> None:
        self.user_id = uuid.uuid4()
        self.kind = "super_admin"
        self.org_id = None
        self.role = None


def _unauthorized(db: FakeDb, world: _World, who: str) -> Any:
    """An actor without platform.users.manage."""
    if who in {"org_admin", "editor", "viewer"}:
        user_id = db.add_account(role=who, org_id=world.org_id)
        return Principal(user_id=user_id, kind="member", org_id=world.org_id, role=who)
    if who == "operator":
        return Operator()
    if who == "member-forged-as-super-admin":
        member = Principal(
            user_id=db.add_account(role="org_admin", org_id=world.org_id),
            kind="member",
            org_id=world.org_id,
            role="org_admin",
        )
        return _forge(member, kind="super_admin")
    if who == "super-admin-given-an-org":
        return _forge(_super_admin(db), org_id=world.org_id)
    if who == "principal-subclass":
        return _PrincipalSubclass(user_id=world.super_admin.user_id, kind="super_admin")
    assert who == "lookalike", who
    return _PrincipalLookalike()


_UNAUTHORIZED = [
    "org_admin",
    "editor",
    "viewer",
    "operator",
    "member-forged-as-super-admin",
    "super-admin-given-an-org",
    "principal-subclass",
    "lookalike",
]


# ---------------------------------------------------------------------------
# 1. The surface
# ---------------------------------------------------------------------------


class TestSurface:
    """The constant, the error and the signature."""

    def test_platform_users_has_active_admin_message(self, pu: ModuleType) -> None:
        assert pu.HAS_ACTIVE_ADMIN_MESSAGE == _HAS_ACTIVE_ADMIN

    def test_platform_users_has_active_admin_error_carries_the_fixed_message(
        self, pu: ModuleType
    ) -> None:
        """Built without arguments, so it can't carry an ID."""
        error = pu.OrgHasActiveAdminError()

        assert isinstance(error, Exception)
        assert str(error) == _HAS_ACTIVE_ADMIN
        assert error.args == (_HAS_ACTIVE_ADMIN,)

    def test_platform_users_reinvite_has_no_role_parameter(self, pu: ModuleType) -> None:
        """The role is always org_admin; every argument after the pool is keyword-only."""
        parameters = inspect.signature(pu.reinvite_org_admin).parameters

        assert "role" not in parameters
        named = {"actor", "org_id", "user_id", "email", "language", "public_url", "ip"}
        assert named <= set(parameters)
        assert all(parameters[name].kind is inspect.Parameter.KEYWORD_ONLY for name in named)


# ---------------------------------------------------------------------------
# 2. Authorization
# ---------------------------------------------------------------------------


class TestAuthorization:
    """Only the Super Admin (platform.users.manage), checked before any query."""

    @pytest.mark.parametrize("email", _MODES)
    @pytest.mark.parametrize("who", _UNAUTHORIZED)
    async def test_platform_users_reinvite_without_users_manage_is_refused_before_any_query(
        self, pu: ModuleType, db: FakeDb, who: str, email: str | None
    ) -> None:
        """Member roles, the Operator and malformed principals → PermissionError("Forbidden");
        no statement runs and nothing changes."""
        world = await _world(db)
        actor = _unauthorized(db, world, who)
        before = db.snapshot()

        with pytest.raises(PermissionError) as caught:
            await _reinvite(pu, db, world, actor=actor, email=email)

        assert str(caught.value) == "Forbidden"
        assert db.calls == []
        assert db.snapshot() == before


# ---------------------------------------------------------------------------
# 3. Refusals and their order
# ---------------------------------------------------------------------------


async def _not_in_org_target(db: FakeDb, world: _World, case: str) -> uuid.UUID:
    """A user id that isn't a non-deleted user of the world's org."""
    if case == "unknown":
        return uuid.uuid4()
    if case == "other-org":
        # Another org's invited first admin: a pending invitation, no active admin there.
        other = await _world(
            db,
            name="Zweite Kanzlei AG",
            email="other.admin.marker@example.ch",
            super_admin=world.super_admin,
        )
        return other.user_id
    if case == "deleted":
        db.users[world.user_id]["deleted_at"] = _DELETED_AT
        return world.user_id
    if case == "other-super-admin":
        return _super_admin(db).user_id
    assert case == "the-super-admin", case
    return world.super_admin.user_id


_NOT_IN_ORG = ["unknown", "other-org", "deleted", "other-super-admin", "the-super-admin"]


def _wrong_status_target(db: FakeDb, world: _World, case: str) -> uuid.UUID:
    """A non-deleted user of the world's org that isn't an invited Org Admin with a pending
    invitation (the org still has no active Org Admin)."""
    if case == "active-editor":
        return db.add_account(role="editor", org_id=world.org_id)
    if case == "deactivated-org-admin":
        return db.add_account(role="org_admin", org_id=world.org_id, status="deactivated")
    if case == "deactivated-editor":
        return db.add_account(role="editor", org_id=world.org_id, status="deactivated")
    if case in {"invited-editor", "invited-viewer"}:
        return _invited(db, world.org_id, case.removeprefix("invited-"))
    assert case == "invited-org-admin-without-invitation", case
    del db.invitations[world.invitation_id]
    return world.user_id


_WRONG_STATUS = [
    "active-editor",
    "deactivated-org-admin",
    "deactivated-editor",
    "invited-editor",
    "invited-viewer",
    "invited-org-admin-without-invitation",
]


class TestRefusals:
    """Each refusal raises its error and changes nothing: no rotation, email or audit row."""

    @pytest.mark.parametrize("email", _MODES)
    async def test_platform_users_reinvite_unknown_org_is_not_found(
        self, pu: ModuleType, db: FakeDb, email: str | None
    ) -> None:
        """An org that doesn't exist (with an existing invited admin's id) →
        organizations.OrgNotFoundError."""
        world = await _world(db)
        unknown = uuid.uuid4()
        before = db.snapshot()

        with pytest.raises(organizations.OrgNotFoundError) as caught:
            await _reinvite(pu, db, world, org_id=unknown, email=email)

        assert str(caught.value) == _ORG_NOT_FOUND_MESSAGE
        assert db.snapshot() == before
        await _assert_link_works(db, world.token, _ADMIN_EMAIL)

    @pytest.mark.parametrize("email", _MODES)
    @pytest.mark.parametrize("status", ["deactivated", "pending_deletion"])
    async def test_platform_users_reinvite_org_not_active_is_refused(
        self, pu: ModuleType, db: FakeDb, status: str, email: str | None
    ) -> None:
        """A deactivated org or one pending deletion → organizations.InvalidOrgStatusError (a
        link into it couldn't be used)."""
        world = await _world(db)
        db.add_org(world.org_id, status=status)
        before = db.snapshot()

        with pytest.raises(organizations.InvalidOrgStatusError) as caught:
            await _reinvite(pu, db, world, email=email)

        assert str(caught.value) == organizations.INVALID_STATUS_MESSAGE
        _assert_no_ids(caught.value, world.org_id, world.user_id)
        assert db.snapshot() == before

    @pytest.mark.parametrize("email", _MODES)
    @pytest.mark.parametrize("case", _NOT_IN_ORG)
    async def test_platform_users_reinvite_target_outside_the_org_is_not_found(
        self, pu: ModuleType, db: FakeDb, case: str, email: str | None
    ) -> None:
        """An unknown id, another org's invited admin, a deleted account or a Super Admin's id
        → accounts.UserNotInOrgError; the other org's invitation is untouched too."""
        world = await _world(db)
        target = await _not_in_org_target(db, world, case)
        db.calls.clear()
        before = db.snapshot()

        with pytest.raises(accounts.UserNotInOrgError) as caught:
            await _reinvite(pu, db, world, user_id=target, email=email)

        _assert_no_ids(caught.value, world.org_id, target)
        assert db.snapshot() == before

    @pytest.mark.parametrize("email", _MODES)
    @pytest.mark.parametrize("case", _WRONG_STATUS)
    async def test_platform_users_reinvite_target_not_a_pending_invited_admin_is_refused(
        self, pu: ModuleType, db: FakeDb, case: str, email: str | None
    ) -> None:
        """An active, a deactivated or an invited member who isn't an invited Org Admin with a
        pending invitation → org_users.InvalidUserStatusError; nothing changes."""
        world = await _world(db)
        target = _wrong_status_target(db, world, case)
        before = db.snapshot()

        with pytest.raises(org_users.InvalidUserStatusError) as caught:
            await _reinvite(pu, db, world, user_id=target, email=email)

        assert str(caught.value) == org_users.INVALID_USER_STATUS_MESSAGE
        _assert_no_ids(caught.value, world.org_id, target)
        assert db.snapshot() == before

    @pytest.mark.parametrize("email", _MODES)
    async def test_platform_users_reinvite_org_with_an_active_admin_is_refused(
        self, pu: ModuleType, db: FakeDb, email: str | None
    ) -> None:
        """An invited Org Admin of an org that already has an active Org Admin →
        OrgHasActiveAdminError (HAS_ACTIVE_ADMIN_MESSAGE); the invitation stays as it is."""
        world = await _world(db)
        db.add_account(role="org_admin", org_id=world.org_id)
        before = db.snapshot()

        with pytest.raises(pu.OrgHasActiveAdminError) as caught:
            await _reinvite(pu, db, world, email=email)

        assert str(caught.value) == _HAS_ACTIVE_ADMIN
        _assert_no_ids(caught.value, world.org_id, world.user_id)
        assert db.snapshot() == before
        await _assert_link_works(db, world.token, _ADMIN_EMAIL)

    @pytest.mark.parametrize("email", _MODES)
    @pytest.mark.parametrize(
        ("case", "expected"),
        [
            pytest.param("org-status-before-target", "org_status", id="org-status-first"),
            pytest.param("target-before-user-status", "not_in_org", id="target-second"),
            pytest.param("user-status-before-admin", "user_status", id="user-status-third"),
            pytest.param("active-admin-is-a-user-status", "user_status", id="active-admin-target"),
        ],
    )
    async def test_platform_users_reinvite_refusals_come_in_order(
        self, pu: ModuleType, db: FakeDb, case: str, expected: str, email: str | None
    ) -> None:
        """org (404) → org status (409) → target (404) → target status (409) → active admin
        (409): when two refusals apply, the earlier one is raised."""
        world = await _world(db)
        active_admin = db.add_account(role="org_admin", org_id=world.org_id)
        target = world.user_id
        if case == "org-status-before-target":
            db.add_org(world.org_id, status="deactivated")
            target = uuid.uuid4()
        elif case == "target-before-user-status":
            target = uuid.uuid4()
        elif case == "user-status-before-admin":
            target = _invited(db, world.org_id, "editor")
        else:
            target = active_admin
        errors: dict[str, type[Exception]] = {
            "org_status": organizations.InvalidOrgStatusError,
            "not_in_org": accounts.UserNotInOrgError,
            "user_status": org_users.InvalidUserStatusError,
        }
        before = db.snapshot()

        # Any of the refusals is caught; the exact class must be the earlier one.
        with pytest.raises((*errors.values(), pu.OrgHasActiveAdminError)) as caught:
            await _reinvite(pu, db, world, user_id=target, email=email)

        assert type(caught.value) is errors[expected]
        assert db.snapshot() == before

    @pytest.mark.parametrize("email", _MODES)
    async def test_platform_users_reinvite_refusals_log_nothing(
        self, pu: ModuleType, db: FakeDb, caplog: pytest.LogCaptureFixture, email: str | None
    ) -> None:
        """No log line for any refusal (not found, statuses, an active admin, forbidden)."""
        caplog.set_level(logging.DEBUG)
        world = await _world(db)
        member = _unauthorized(db, world, "editor")
        with pytest.raises(PermissionError):
            await _reinvite(pu, db, world, actor=member, email=email)
        with pytest.raises(organizations.OrgNotFoundError):
            await _reinvite(pu, db, world, org_id=uuid.uuid4(), email=email)
        with pytest.raises(accounts.UserNotInOrgError):
            await _reinvite(pu, db, world, user_id=uuid.uuid4(), email=email)
        with pytest.raises(org_users.InvalidUserStatusError):
            await _reinvite(pu, db, world, user_id=member.user_id, email=email)
        db.add_account(role="org_admin", org_id=world.org_id)
        with pytest.raises(pu.OrgHasActiveAdminError):
            await _reinvite(pu, db, world, email=email)
        db.add_org(world.org_id, status="pending_deletion")
        with pytest.raises(organizations.InvalidOrgStatusError):
            await _reinvite(pu, db, world, email=email)

        assert _admino_records(caplog) == []
        assert "marker" not in caplog.text.lower()


# ---------------------------------------------------------------------------
# 4. Which orgs qualify
# ---------------------------------------------------------------------------


def _bystander(db: FakeDb, world: _World, case: str) -> None:
    """Another account that isn't an active Org Admin of the world's org."""
    if case == "deactivated-editor":
        db.add_account(role="editor", org_id=world.org_id, status="deactivated")
    elif case == "deactivated-org-admin":
        db.add_account(role="org_admin", org_id=world.org_id, status="deactivated")
    elif case == "deleted-org-admin":
        db.add_account(role="org_admin", org_id=world.org_id, deleted_at=_DELETED_AT)
    elif case == "other-orgs-active-admin":
        db.add_account(role="org_admin", org_id=db.add_org(name="Dritte Kanzlei AG"))
    elif case == "second-invited-org-admin":
        _invited(db, world.org_id, "org_admin")
    else:
        assert case == "active-editor", case
        db.add_account(role="editor", org_id=world.org_id)


_BYSTANDERS = [
    "deactivated-editor",
    "deactivated-org-admin",
    "deleted-org-admin",
    "other-orgs-active-admin",
    "second-invited-org-admin",
    "active-editor",
]


class TestQualifyingOrgs:
    """Only an active Org Admin of the org itself blocks the re-invite."""

    @pytest.mark.parametrize("email", _MODES)
    @pytest.mark.parametrize("case", _BYSTANDERS)
    async def test_platform_users_reinvite_org_without_an_active_admin_qualifies(
        self, pu: ModuleType, db: FakeDb, case: str, email: str | None
    ) -> None:
        """Deactivated, deleted or invited admins, other orgs' admins and other roles don't
        count as the org's active Org Admin: the re-invite goes through."""
        world = await _world(db)
        _bystander(db, world, case)

        summary = await _reinvite(pu, db, world, email=email)

        assert summary.role == "org_admin"
        assert summary.email == (email or _ADMIN_EMAIL)
        await _assert_link_dead(db, world.token)

    async def test_platform_users_reinvite_org_created_by_the_cli_without_email_qualifies(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """An org created at the terminal without SMTP (#154: no email queued, the link shown
        once) with a deactivated editor: resending queues the first email with a new link and
        the link the CLI showed stops working."""
        super_admin = _super_admin(db)
        request = models.OrgCreateRequest(
            name=_ORG_NAME,
            primary_admin_email=_ADMIN_EMAIL,
            seats=5,
            monthly_budget_chf=Decimal("10.00"),
            storage_quota=1024**3,
            status="active",
        )
        created = await organizations.create_org(
            db.pool,
            actor=Operator(),
            request=request,
            language="de",
            public_url=PUBLIC_URL,
            ip=None,
            queue_email=False,
        )
        org_id = plain(created.organization.id)
        user_id = _id_of(db, _ADMIN_EMAIL)
        db.add_account(role="editor", org_id=org_id, status="deactivated")
        world = _World(
            super_admin,
            org_id,
            user_id,
            plain(created.invitation.id),
            _token_of(created.accept_link),
        )
        assert db.invitation_emails(user_id) == []

        summary = await _reinvite(pu, db, world)

        assert summary.id == world.invitation_id
        (email,) = db.invitation_emails(user_id)
        assert email["status"] == "pending"
        await _assert_link_works(db, _token_of(email["params"]["accept_link"]), _ADMIN_EMAIL)
        await _assert_link_dead(db, world.token)


# ---------------------------------------------------------------------------
# 5. Resend (no email)
# ---------------------------------------------------------------------------


class TestResend:
    """#153's resend on the invited Org Admin's invitation."""

    async def test_platform_users_resend_keeps_the_invitation_and_the_account(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """The same invitation id and the same users row, unchanged (email, language, status)."""
        world = await _world(db)
        account = copy.deepcopy(db.users[world.user_id])

        await _reinvite(pu, db, world, language="fr")

        assert list(db.invitations) == [world.invitation_id]
        assert db.users[world.user_id] == account

    async def test_platform_users_resend_rotates_the_token(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """A new 256-bit token; the old link stops working at once, the new one works."""
        world = await _world(db)

        await _reinvite(pu, db, world)

        new = db.invitation_token(world.user_id)
        assert new != world.token
        assert TOKEN_RE.fullmatch(new)
        assert db.invitations[world.invitation_id]["token_hash"] == sha256(new)
        await _assert_link_dead(db, world.token)
        await _assert_link_works(db, new, _ADMIN_EMAIL)

    async def test_platform_users_resend_resets_sent_at_and_the_expiry(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """sent_at is now and expires_at 72 hours later; created_at stays."""
        world = await _world(db)
        _age(db, world.invitation_id, timedelta(hours=10))
        created_at = db.invitations[world.invitation_id]["created_at"]
        before = datetime.now(UTC)

        await _reinvite(pu, db, world)

        row = db.invitations[world.invitation_id]
        assert before <= row["sent_at"] <= datetime.now(UTC)
        assert row["expires_at"] - row["sent_at"] == timedelta(hours=72)
        assert row["created_at"] == created_at
        assert row["accepted_at"] is None

    async def test_platform_users_resend_revives_an_expired_invitation(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """An invitation that expired an hour ago is sent again with a working link."""
        world = await _world(db)
        _age(db, world.invitation_id, timedelta(hours=73))

        summary = await _reinvite(pu, db, world)

        assert summary.expired is False
        assert summary.expires_at > datetime.now(UTC)
        await _assert_link_works(db, db.invitation_token(world.user_id), _ADMIN_EMAIL)

    @pytest.mark.parametrize("over", [0, 1], ids=["full", "over-full"])
    async def test_platform_users_resend_needs_no_free_seat(
        self, pu: ModuleType, db: FakeDb, over: int
    ) -> None:
        """The invitation already holds its seat: resending works in a full or over-full org,
        and no refusal is recorded."""
        world = await _world(db)
        db.add_org(world.org_id, seats=1)
        for _ in range(over):
            db.add_account(role="editor", org_id=world.org_id)

        summary = await _reinvite(pu, db, world)

        assert summary.id == world.invitation_id
        assert db.audit_rows("invitation.refuse") == []
        assert len(db.invitation_emails(world.user_id)) == 2

    async def test_platform_users_resend_cancels_the_queued_email_with_the_old_link(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """The earlier email, still pending, is marked failed with its params cleared: the old
        link leaves the outbox and only the new email waits for delivery."""
        world = await _world(db)

        await _reinvite(pu, db, world)

        old, new = db.invitation_emails(world.user_id)
        assert (old["status"], old["params"]) == ("failed", {})
        assert old["finished_at"] is not None
        assert new["status"] == "pending"
        assert world.token not in json.dumps(db.outbox, default=str)

    async def test_platform_users_resend_queues_a_new_invitation_email(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """A new invitation email to the invited admin, in their language: the org name, the
        new link and the new expiry."""
        world = await _world(db)

        await _reinvite(pu, db, world, language="fr")

        newest = db.invitation_emails(world.user_id)[-1]
        assert (newest["template_key"], newest["language"]) == ("invitation", "de")
        assert newest["recipient_address"] == _ADMIN_EMAIL
        assert newest["params"]["org_name"] == _ORG_NAME
        token = _token_of(newest["params"]["accept_link"])
        assert db.invitations[world.invitation_id]["token_hash"] == sha256(token)
        assert (
            datetime.fromisoformat(newest["params"]["expires_at"])
            == db.invitations[world.invitation_id]["expires_at"]
        )

    async def test_platform_users_resend_is_audited(self, pu: ModuleType, db: FakeDb) -> None:
        """Exactly one invitation.resend row: the Super Admin in the org's log, target the
        invitation, metadata the role and the invited user's id, the IP."""
        world = await _world(db)
        before = db.snapshot()

        await _reinvite(pu, db, world)

        (row,) = _added_audit(db, before)
        _assert_super_admin_event(row, world, "invitation.resend")
        assert (row["target_type"], row["target_ids"]) == ("invitation", [str(world.invitation_id)])
        assert row["metadata"] == {"role": "org_admin", "user_id": str(world.user_id)}

    async def test_platform_users_resend_returns_the_invitation_summary(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """The same id, the email, role org_admin, not expired, the new dates; no token or link."""
        world = await _world(db)
        _age(db, world.invitation_id, timedelta(hours=73))

        summary = await _reinvite(pu, db, world)

        row = db.invitations[world.invitation_id]
        assert type(summary) is models.InvitationSummary
        assert (summary.id, summary.email, summary.role, summary.expired) == (
            world.invitation_id,
            _ADMIN_EMAIL,
            "org_admin",
            False,
        )
        assert (summary.sent_at, summary.expires_at) == (row["sent_at"], row["expires_at"])
        dumped = summary.model_dump_json()
        assert db.invitation_token(world.user_id) not in dumped
        assert "accept-invitation" not in dumped

    async def test_platform_users_resend_locks_the_org_and_writes_in_one_transaction(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """The org row is locked FOR UPDATE first; the rotation, the cancelled and the new
        email and the audit event share that transaction, which commits."""
        world = await _world(db)

        await _reinvite(pu, db, world)

        rotate = _one(db.matching(r"^update invitations\b"))
        writes = [
            rotate,
            _one(db.matching(r"^update email_outbox\b")),
            _one(db.matching(r"^insert into email_outbox\b")),
            _one(db.matching(r"^insert into audit_events\b")),
        ]
        locks = _org_locks(db)
        assert locks, "the org row isn't locked"
        assert rotate.tx is not None
        assert {(call.via, call.tx) for call in [locks[0], *writes]} == {(rotate.via, rotate.tx)}
        assert db.calls.index(locks[0]) < db.calls.index(rotate)
        assert (rotate.tx, "commit") in db.transactions


# ---------------------------------------------------------------------------
# 6. Replace (an email)
# ---------------------------------------------------------------------------


class TestReplace:
    """#153's revoke of the invited account, then #153's send to the new email."""

    async def test_platform_users_replace_removes_the_old_account_and_invitation(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """The invited account, its invitation and its queued email are gone; the old link is
        dead."""
        world = await _world(db)

        await _reinvite(pu, db, world, email=_NEW_EMAIL)

        assert world.user_id not in db.users
        assert world.invitation_id not in db.invitations
        assert db.invitation_emails(world.user_id) == []
        await _assert_link_dead(db, world.token)

    @pytest.mark.parametrize("language", ["fr", "en"])
    async def test_platform_users_replace_creates_an_invited_org_admin(
        self, pu: ModuleType, db: FakeDb, language: str
    ) -> None:
        """A member of the org with role org_admin, status invited, no name, no password, the
        email as given and the Super Admin's session language."""
        world = await _world(db)

        await _reinvite(pu, db, world, email=_NEW_EMAIL, language=language)

        row = db.user_by_email(_NEW_EMAIL)
        assert row is not None
        assert (row["email"], row["kind"], plain(row["org_id"]), row["role"], row["status"]) == (
            _NEW_EMAIL,
            "member",
            world.org_id,
            "org_admin",
            "invited",
        )
        assert (row["name"], row["password_hash"], row["deleted_at"]) == (None, None, None)
        assert row["ui_language"] == language

    async def test_platform_users_replace_sends_a_new_invitation(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """A pending 72-hour invitation and an invitation email in the given language with a
        working link to the new address."""
        world = await _world(db)

        await _reinvite(pu, db, world, email=_NEW_EMAIL, language="fr")

        new_user = _id_of(db, _NEW_EMAIL)
        invitation = db.invitation_of(new_user)
        assert invitation is not None
        assert invitation["accepted_at"] is None
        assert invitation["expires_at"] - invitation["sent_at"] == timedelta(hours=72)
        (email,) = db.invitation_emails(new_user)
        assert (email["status"], email["language"]) == ("pending", "fr")
        assert email["recipient_address"] == _NEW_EMAIL
        assert email["params"]["org_name"] == _ORG_NAME
        token = _token_of(email["params"]["accept_link"])
        assert invitation["token_hash"] == sha256(token)
        await _assert_link_works(db, token, _NEW_EMAIL)

    async def test_platform_users_replace_is_audited_as_revoke_then_create(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """invitation.revoke (target the old invitation, metadata the old user id), then
        invitation.create (target the new invitation, the role and the new user id); both the
        Super Admin's in the org's log."""
        world = await _world(db)
        before = db.snapshot()

        summary = await _reinvite(pu, db, world, email=_NEW_EMAIL)

        revoke, create = _added_audit(db, before)
        _assert_super_admin_event(revoke, world, "invitation.revoke")
        assert (revoke["target_type"], revoke["target_ids"]) == (
            "invitation",
            [str(world.invitation_id)],
        )
        assert revoke["metadata"] == {"user_id": str(world.user_id)}
        _assert_super_admin_event(create, world, "invitation.create")
        assert (create["target_type"], create["target_ids"]) == ("invitation", [str(summary.id)])
        new_user = _id_of(db, _NEW_EMAIL)
        assert create["metadata"] == {"role": "org_admin", "user_id": str(new_user)}

    async def test_platform_users_replace_returns_the_new_invitation_summary(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """A new id, the new email, role org_admin, not expired, the row's dates; no token or
        link."""
        world = await _world(db)

        summary = await _reinvite(pu, db, world, email=_NEW_EMAIL)

        invitation = db.invitation_of(_id_of(db, _NEW_EMAIL))
        assert invitation is not None
        assert type(summary) is models.InvitationSummary
        assert summary.id == plain(invitation["id"])
        assert summary.id != world.invitation_id
        assert (summary.email, summary.role, summary.expired) == (_NEW_EMAIL, "org_admin", False)
        assert (summary.sent_at, summary.expires_at) == (
            invitation["sent_at"],
            invitation["expires_at"],
        )
        assert "accept-invitation" not in summary.model_dump_json()

    @pytest.mark.parametrize(
        "spelling",
        [_ADMIN_EMAIL, _ADMIN_EMAIL.lower(), _ADMIN_EMAIL.upper()],
        ids=["same", "lower", "upper"],
    )
    async def test_platform_users_replace_with_the_same_address_makes_a_new_invitation(
        self, pu: ModuleType, db: FakeDb, spelling: str
    ) -> None:
        """The invited address itself (any capitalization) isn't taken: a new account and a new
        invitation id, the address as given, a working new link."""
        world = await _world(db)

        summary = await _reinvite(pu, db, world, email=spelling)

        matches = [row for row in db.users.values() if row["email"].lower() == spelling.lower()]
        assert len(matches) == 1
        assert matches[0]["email"] == spelling
        new_user = plain(matches[0]["id"])
        assert new_user != world.user_id
        assert summary.id != world.invitation_id
        assert summary.email == spelling
        await _assert_link_dead(db, world.token)
        await _assert_link_works(db, db.invitation_token(new_user), spelling)

    async def test_platform_users_replace_frees_the_old_seat_first(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """A full org (2 seats: the invited admin and an editor): the old seat is freed before
        the seat check, so the replacement fits."""
        world = await _world(db)
        db.add_org(world.org_id, seats=2)
        db.add_account(role="editor", org_id=world.org_id)

        summary = await _reinvite(pu, db, world, email=_NEW_EMAIL)

        assert summary.email == _NEW_EMAIL
        assert db.audit_rows("invitation.refuse") == []

    async def test_platform_users_replace_works_on_an_expired_invitation(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        world = await _world(db)
        _age(db, world.invitation_id, timedelta(hours=73))

        summary = await _reinvite(pu, db, world, email=_NEW_EMAIL)

        assert summary.expired is False
        assert world.user_id not in db.users
        await _assert_link_works(db, db.invitation_token(_id_of(db, _NEW_EMAIL)), _NEW_EMAIL)

    async def test_platform_users_replace_leaves_everything_else(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """Other accounts, their invitations, emails and sessions stay as they were."""
        world = await _world(db)
        kept_invited = _invited(db, world.org_id, "editor", email="kept.invitee@example.ch")
        kept_user = db.add_account(role="editor", org_id=world.org_id, status="deactivated")
        session = db.open_session(world.super_admin.user_id)
        kept_rows = copy.deepcopy([db.users[kept_invited], db.users[kept_user]])
        kept_invitation = copy.deepcopy(db.invitation_of(kept_invited))
        kept_emails = copy.deepcopy(db.invitation_emails(kept_invited))

        await _reinvite(pu, db, world, email=_NEW_EMAIL)

        assert [db.users[kept_invited], db.users[kept_user]] == kept_rows
        assert db.invitation_of(kept_invited) == kept_invitation
        assert db.invitation_emails(kept_invited) == kept_emails
        assert not db.session_revoked(session)
        assert len(db.invitations) == 2

    async def test_platform_users_replace_locks_the_org_and_writes_in_one_transaction(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """The org row is locked FOR UPDATE first; the delete, the inserts, the email and both
        audit events share that transaction, which commits; the delete precedes the insert."""
        world = await _world(db)

        await _reinvite(pu, db, world, email=_NEW_EMAIL)

        delete = _one(db.matching(r"^delete from users\b"))
        insert = _one(db.matching(r"^insert into users\b"))
        audits = db.matching(r"^insert into audit_events\b")
        assert len(audits) == 2
        writes = [
            delete,
            insert,
            _one(db.matching(r"^insert into invitations\b")),
            _one(db.matching(r"^insert into email_outbox\b")),
            *audits,
        ]
        locks = _org_locks(db)
        assert locks, "the org row isn't locked"
        assert delete.tx is not None
        assert {(call.via, call.tx) for call in [locks[0], *writes]} == {(delete.via, delete.tx)}
        assert db.calls.index(locks[0]) < db.calls.index(delete) < db.calls.index(insert)
        assert (delete.tx, "commit") in db.transactions

    @pytest.mark.parametrize("email", _MODES)
    async def test_platform_users_reinvite_link_uses_the_given_public_url(
        self, pu: ModuleType, db: FakeDb, email: str | None
    ) -> None:
        """The link base is the public_url argument (the configured origin)."""
        world = await _world(db)

        await _reinvite(pu, db, world, email=email, public_url=_OTHER_PUBLIC_URL)

        recipient = world.user_id if email is None else _id_of(db, email)
        link = db.invitation_emails(recipient)[-1]["params"]["accept_link"]
        await _assert_link_works(db, _token_of(link, _OTHER_PUBLIC_URL), email or _ADMIN_EMAIL)


# ---------------------------------------------------------------------------
# 7. Replace refusals: a taken email, no free seat
# ---------------------------------------------------------------------------


def _take(db: FakeDb, world: _World, case: str) -> None:
    """A users row that already holds _TAKEN (in some spelling)."""
    other_org = db.add_org(name="Vierte Kanzlei AG")
    if case == "active-other-org":
        db.add_account(email=_TAKEN, org_id=other_org)
    elif case == "other-capitalization":
        db.add_account(email=_TAKEN.upper(), org_id=other_org)
    elif case == "super-admin":
        db.add_account(email=_TAKEN, kind="super_admin", role=None)
    elif case == "deactivated-same-org":
        db.add_account(email=_TAKEN, org_id=world.org_id, status="deactivated")
    elif case == "soft-deleted":
        db.add_account(email=_TAKEN, org_id=other_org, deleted_at=_DELETED_AT)
    elif case == "invited-same-org":
        _invited(db, world.org_id, "editor", email=_TAKEN)
    else:
        assert case == "invited-elsewhere", case
        _invited(db, other_org, "org_admin", email=_TAKEN)


_TAKEN_CASES = [
    "active-other-org",
    "other-capitalization",
    "super-admin",
    "deactivated-same-org",
    "soft-deleted",
    "invited-same-org",
    "invited-elsewhere",
]


class TestReplaceRefusals:
    """A refused replacement rolls everything back; only invitation.refuse is recorded."""

    @pytest.mark.parametrize("case", _TAKEN_CASES)
    async def test_platform_users_replace_taken_email_is_refused_and_rolled_back(
        self, pu: ModuleType, db: FakeDb, case: str
    ) -> None:
        """accounts.DuplicateEmailError; the old account, invitation and queued email are intact
        and the old link still works; only the content-free invitation.refuse row is added."""
        world = await _world(db)
        _take(db, world, case)
        before = db.snapshot()

        with pytest.raises(accounts.DuplicateEmailError):
            await _reinvite(pu, db, world, email=_TAKEN)

        _assert_only_refusal_audited(db, before, world, "email_taken")
        await _assert_link_works(db, world.token, _ADMIN_EMAIL)

    async def test_platform_users_replace_taken_email_error_carries_no_email(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """The fixed message only; the driver's error (which repeats the email) doesn't travel
        with it, not even in the formatted traceback."""
        world = await _world(db)
        _take(db, world, "active-other-org")

        with pytest.raises(accounts.DuplicateEmailError) as caught:
            await _reinvite(pu, db, world, email=_TAKEN)

        assert str(caught.value) == _DUPLICATE_MESSAGE
        formatted = "".join(traceback.format_exception(caught.value)).lower()
        assert "taken.person" not in formatted

    async def test_platform_users_replace_refusal_is_recorded_after_the_rollback(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """The refused transaction rolls back (the revoke included); invitation.refuse is
        written outside it, so it survives."""
        world = await _world(db)
        _take(db, world, "active-other-org")

        with pytest.raises(accounts.DuplicateEmailError):
            await _reinvite(pu, db, world, email=_TAKEN)

        rolled_back = [tx for tx, outcome in db.transactions if outcome.startswith("rollback")]
        assert len(rolled_back) == 1
        assert (rolled_back[0], "rollback:DuplicateEmailError") in db.transactions
        refuse = db.matching(r"^insert into audit_events\b")[-1]
        assert refuse.tx != rolled_back[0]
        assert [row["action"] for row in db.audit_rows()][-1] == "invitation.refuse"
        assert db.audit_rows("invitation.revoke") == []

    async def test_platform_users_replace_without_a_free_seat_is_refused(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """1 seat, the invited admin and an active editor: even with the old seat freed the org
        is full → invitations.SeatLimitError, rolled back, invitation.refuse {"seat_limit"}."""
        world = await _world(db)
        db.add_org(world.org_id, seats=1)
        db.add_account(role="editor", org_id=world.org_id)
        before = db.snapshot()

        with pytest.raises(invitations.SeatLimitError) as caught:
            await _reinvite(pu, db, world, email=_NEW_EMAIL)

        assert str(caught.value) == _SEAT_MESSAGE
        _assert_only_refusal_audited(db, before, world, "seat_limit")
        assert db.user_by_email(_NEW_EMAIL) is None
        await _assert_link_works(db, world.token, _ADMIN_EMAIL)

    async def test_platform_users_replace_refusal_audit_failure_raises(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """If the refusal can't be recorded, AuditRecordError propagates; nothing is written
        and the old link still works."""
        world = await _world(db)
        _take(db, world, "active-other-org")
        before = db.snapshot()
        db.fail_audit_when = lambda row: row["action"] == "invitation.refuse"

        with pytest.raises(AuditRecordError):
            await _reinvite(pu, db, world, email=_TAKEN)

        assert db.snapshot() == before
        await _assert_link_works(db, world.token, _ADMIN_EMAIL)


# ---------------------------------------------------------------------------
# 8. Fail closed
# ---------------------------------------------------------------------------


class TestAuditFailure:
    """A failed audit write rolls the whole re-invite back."""

    @pytest.mark.parametrize(
        ("email", "failing"),
        [
            pytest.param(None, None, id="resend-every-write"),
            pytest.param(None, "invitation.resend", id="resend-the-resend-event"),
            pytest.param(_NEW_EMAIL, None, id="replace-every-write"),
            pytest.param(_NEW_EMAIL, "invitation.revoke", id="replace-the-revoke-event"),
            pytest.param(_NEW_EMAIL, "invitation.create", id="replace-the-create-event"),
        ],
    )
    async def test_platform_users_reinvite_audit_failure_changes_nothing(
        self, pu: ModuleType, db: FakeDb, email: str | None, failing: str | None
    ) -> None:
        """AuditRecordError; no rotation, deletion, new account or email, no refusal row; the
        old link keeps working."""
        world = await _world(db)
        before = db.snapshot()
        if failing is None:
            db.fail_audit = True
        else:
            db.fail_audit_when = lambda row: row["action"] == failing

        with pytest.raises(AuditRecordError):
            await _reinvite(pu, db, world, email=email)

        assert db.snapshot() == before
        db.fail_audit = False
        db.fail_audit_when = None
        await _assert_link_works(db, world.token, _ADMIN_EMAIL)


# ---------------------------------------------------------------------------
# 9. No content in audit rows or logs
# ---------------------------------------------------------------------------


class TestNoContent:
    """Emails, tokens and links never reach an audit row or a log line."""

    async def _flow(self, pu: ModuleType, db: FakeDb) -> list[str]:
        """Resend, replace, then refuse a taken email; return every raw token issued."""
        world = await _world(db)
        tokens = [world.token]
        await _reinvite(pu, db, world)
        tokens.append(db.invitation_token(world.user_id))
        replaced = await _reinvite(pu, db, world, email=_NEW_EMAIL)
        new_user = _id_of(db, _NEW_EMAIL)
        tokens.append(db.invitation_token(new_user))
        world = _World(world.super_admin, world.org_id, new_user, replaced.id, tokens[-1])
        _take(db, world, "active-other-org")
        with pytest.raises(accounts.DuplicateEmailError):
            await _reinvite(pu, db, world, email=_TAKEN)
        return tokens

    async def test_platform_users_reinvite_audit_rows_carry_no_content(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        tokens = await self._flow(pu, db)

        stored = json.dumps(db.audit, default=str).lower()
        assert {row["action"] for row in db.audit} >= {
            "invitation.resend",
            "invitation.revoke",
            "invitation.create",
            "invitation.refuse",
        }
        assert "marker" not in stored
        assert "example.ch" not in stored
        assert "accept-invitation" not in stored
        for token in tokens:
            assert token.lower() not in stored
            assert sha256(token).hex() not in stored

    async def test_platform_users_reinvite_logs_nothing(
        self, pu: ModuleType, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)

        tokens = await self._flow(pu, db)

        assert _admino_records(caplog) == []
        text = caplog.text
        assert "marker" not in text.lower()
        assert "accept-invitation" not in text
        for token in tokens:
            assert token not in text
