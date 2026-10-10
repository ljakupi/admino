"""Tests for admino.organizations — the organization lifecycle for the Super Admin (GH-154).

A Super Admin (or the platform operator at the server's terminal, for creation
only) creates an organization with its first Org Admin invitation
(``create_org``), lists every org (``list_orgs``), edits its plan limits
(``update_limits``) and its data residency policy (``set_residency``),
deactivates and reactivates it (``deactivate_org`` / ``reactivate_org``),
schedules it for deletion and cancels that (``schedule_deletion`` /
``cancel_deletion``). A background job (``run_org_purge_job``) purges the orgs
whose grace period is over (``purge_due_orgs``): rows, audit events and files.

What these tests pin down (the spec: the issue, its decisions, tracker #139 §5):
- Constants and errors: the attachments root, an hourly purge, fixed
  input-free error messages; keyword-only signatures. GH-160: the grace period
  is no module constant any more (``DELETION_GRACE_PERIOD`` is gone).
- Authorization through ``access.can`` before any query: a Super Admin only
  (``org.create``, ``org.lifecycle.manage``, ``org.limits.manage``,
  ``org.residency.manage``); Org Admins and Editors get
  ``PermissionError``; an ``access.Operator`` is accepted by ``create_org`` only.
- create_org, in one committed transaction: the organizations row, its tool
  permission matrix (GH-161: ``org_permissions.seed_org_permissions``, the 34
  default rows, right after the org INSERT), ``org.create``
  (exact content-free metadata, the budget in cents), the invited Org Admin
  (#153's rules: a SHA-256 token hash only, 72 h on the database clock,
  ``invitation.create`` by the same actor), the invitation email through the
  outbox unless ``queue_email`` is False, and a ``CreatedOrg`` whose one-time
  ``accept_link`` stays out of ``repr()``. A taken email or a failed audit
  write leaves nothing behind at all (no permission rows either).
- Every status transition from every status (allowed ones change the status,
  the deletion dates and ``updated_at`` and write exactly one audit row;
  refused ones raise ``InvalidOrgStatusError`` and write nothing), the org row
  locked ``FOR UPDATE`` first, change and audit in one transaction.
- Deactivating and scheduling delete every session of every user of the org
  (only that org), keep its content, and count them in the audit row.
  Scheduling sets ``purge_after = now() + <grace days>`` on the database clock
  and emails every active, non-deleted Org Admin of the org in their language.
  GH-160: the grace days are the stored platform default
  ``retention.org_deletion_grace_days`` (30 by default, 7 to 90), read through
  ``scoped_settings.current_platform_settings`` after the authorization; the
  ``org.deletion_schedule`` metadata's ``grace_days`` is that value; a change
  applies to the next scheduling only (a scheduled deletion keeps its date).
  Cancelling always lands on ``deactivated``.
- update_limits and set_residency: exact old/new metadata, refused while a
  deletion is pending.
- purge_due_orgs: only due orgs, each in its own transaction; every row of the
  org (users of every status and what cascades from them, the org row and,
  GH-161, its permission rows through ON DELETE CASCADE), its
  audit events (only through ``purge_org_audit_events``) and its directory under
  the attachments root (never following a symlink) go; everything else stays;
  one platform ``org.purge`` record with counts. GH-220 order, in that one
  transaction: the org row locked ``FOR UPDATE``, ``DELETE FROM users WHERE
  org_id = $1``, then ``SELECT purge_org_audit_events($1)``, which deletes the
  org's audit events and then the organizations row (migration 0019: owner-run,
  so the runtime role needs no DELETE on organizations), then the ``org.purge``
  record, the files last. The app never issues a DELETE on organizations
  itself. A failure (the function refusing while a user still names the org
  included) rolls that org back (files untouched) without stopping the others
  and is logged by class name only. A concurrent cancel is skipped. #147's
  default organization, scheduled by migration 0011, ends up with no org row
  and no audit event.
- run_org_purge_job: purge now, then once per interval, surviving failures,
  stopping on cancellation.

All database calls go to the in-memory fake of tests/db_fakes.py (which
models migration 0004's organizations CHECKs, ON DELETE RESTRICT, the cascades,
migration 0011's append-only trigger and the ``purge_org_audit_events`` of
migrations 0011 and 0019). Files live under pytest's ``tmp_path``. No real
PostgreSQL, no SMTP.

Security notes:
- Operator blindness and no content in logs or audit rows: IDs, counts, bools
  and ints only; never the org name, the admin email, the invitation token or
  link, or a file path. Purge failures are logged with the exception class name.
- The raw invitation token lives only in the queued email's link (or, without
  email, in the returned ``accept_link``): never in a table, a statement, an
  audit row or a log line.
- Fail closed: every change shares one transaction with its audit event.
- Irreversible deletion is gated twice: the app re-checks the org under a lock,
  and the database function refuses an org that isn't pending and due. Only
  that owner-run function removes an organizations row (GH-220): the runtime
  role has no DELETE on the table. A symlink under the attachments root is
  removed, never followed.
- Parameterized SQL only: values travel as bind parameters.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import dataclasses
import inspect
import json
import logging
import os
import re
import traceback
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

import asyncpg
import pytest

from admino import accounts, models
from admino.access import Principal
from admino.audit_events import AuditRecordError
from tests.conftest import default_test_platform_settings
from tests.db_fakes import (
    INVITE_LINK_PREFIX,
    ORG_ID,
    ORG_NAME,
    OTHER_ORG_ID,
    PUBLIC_URL,
    TOKEN_RE,
    Call,
    FakeDb,
    norm,
    plain,
    sha256,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from types import ModuleType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP = "203.0.113.7"
_NEW_NAME = "Kanzlei Zeitreise Marker AG"
_ADMIN_EMAIL = "Grace.Primary.Marker@Example.ch"
_SEATS = 12
_BUDGET = Decimal("123.45")
_BUDGET_CENTS = 12345
_QUOTA = 5 * 1024**3
_DEFAULT_ORG_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")
_NOT_FOUND = "Organization not found"
_INVALID_STATUS = "This change isn't possible in the organization's current status."
_DUPLICATE = "A user with this email already exists."
_MEMBER_ROLES = ["org_admin", "editor"]
_STATUSES = ["active", "deactivated", "pending_deletion"]
_OLD = datetime(2025, 1, 2, 3, 4, 5, tzinfo=UTC)
_DELETED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_UNKNOWN_ORG = uuid.UUID("9e8d7c6b-5a49-4382-a716-0f1e2d3c4b5a")

# function -> (audit action, the statuses it's allowed from, the status it sets)
_TRANSITIONS: dict[str, tuple[str, frozenset[str], str]] = {
    "deactivate_org": ("org.deactivate", frozenset({"active"}), "deactivated"),
    "reactivate_org": ("org.reactivate", frozenset({"deactivated"}), "active"),
    "schedule_deletion": (
        "org.deletion_schedule",
        frozenset({"active", "deactivated"}),
        "pending_deletion",
    ),
    "cancel_deletion": ("org.deletion_cancel", frozenset({"pending_deletion"}), "deactivated"),
}
_ALLOWED = [
    pytest.param(name, start, id=f"{name}-from-{start}")
    for name, (_, allowed, _) in _TRANSITIONS.items()
    for start in _STATUSES
    if start in allowed
]
_REFUSED = [
    pytest.param(name, start, id=f"{name}-from-{start}")
    for name, (_, allowed, _) in _TRANSITIONS.items()
    for start in _STATUSES
    if start not in allowed
]
_ORG_FUNCTIONS = [*_TRANSITIONS, "update_limits", "set_residency"]
_ALL_FUNCTIONS = ["create_org", "list_orgs", *_ORG_FUNCTIONS]
_NOT_CREATE = ["list_orgs", *_ORG_FUNCTIONS]


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def orgs() -> ModuleType:
    """admino.organizations, imported per test so each test fails on its own until it exists."""
    from admino import organizations

    return organizations


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database."""
    return FakeDb()


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    """The attachments root of the purge tests (an empty directory)."""
    path = tmp_path / "attachments"
    path.mkdir()
    return path


class _ExactlyNow(datetime):
    """An aware datetime that equals "now" whenever it is compared or subtracted.

    Stored as an org's ``purge_after``, it is due at exactly the instant the
    code (or the database) reads its clock: ==, <= and >= are True; <, > and !=
    are False; the difference is zero.
    """

    def __eq__(self, other: object) -> bool:
        return True if isinstance(other, datetime) else NotImplemented

    __hash__ = datetime.__hash__

    def __ne__(self, other: object) -> bool:
        return False if isinstance(other, datetime) else NotImplemented

    def __lt__(self, other: object) -> bool:
        return False if isinstance(other, datetime) else NotImplemented

    def __gt__(self, other: object) -> bool:
        return False if isinstance(other, datetime) else NotImplemented

    def __le__(self, other: object) -> bool:
        return True if isinstance(other, datetime) else NotImplemented

    def __ge__(self, other: object) -> bool:
        return True if isinstance(other, datetime) else NotImplemented

    def __sub__(self, other: Any) -> Any:
        if isinstance(other, datetime):
            return timedelta(0)
        return super().__sub__(other)

    def __rsub__(self, other: Any) -> Any:
        if isinstance(other, datetime):
            return timedelta(0)
        return NotImplemented


def _exactly_now() -> _ExactlyNow:
    now = datetime.now(UTC)
    return _ExactlyNow(
        now.year, now.month, now.day, now.hour, now.minute, now.second, now.microsecond, UTC
    )


def _principal(db: FakeDb, user_id: uuid.UUID) -> Principal:
    """The Principal a resolved session of this stored account would carry."""
    account = db.users[user_id]
    if account["kind"] == "super_admin":
        return Principal(user_id=user_id, kind="super_admin")
    return Principal(user_id=user_id, kind="member", org_id=account["org_id"], role=account["role"])


def _super_admin(db: FakeDb) -> Principal:
    return _principal(db, db.add_account(kind="super_admin", role=None))


def _member(db: FakeDb, role: str, org_id: uuid.UUID = ORG_ID) -> Principal:
    return _principal(db, db.add_account(role=role, org_id=org_id))


def _operator() -> Any:
    """The platform operator at the server's terminal (access.Operator, new in GH-154)."""
    from admino.access import Operator

    return Operator()


def _request(**overrides: Any) -> Any:
    """A valid OrgCreateRequest (models.OrgCreateRequest, new in GH-154)."""
    fields: dict[str, Any] = {
        "name": _NEW_NAME,
        "primary_admin_email": _ADMIN_EMAIL,
        "seats": _SEATS,
        "monthly_budget_chf": _BUDGET,
        "storage_quota": _QUOTA,
        "status": "active",
    }
    fields.update(overrides)
    return models.OrgCreateRequest(**fields)


async def _create(
    orgs: ModuleType,
    db: FakeDb,
    actor: Any,
    *,
    request: Any = None,
    language: str = "fr",
    public_url: str = PUBLIC_URL,
    ip: str | None = _IP,
    queue_email: bool = True,
) -> Any:
    return await orgs.create_org(
        db.pool,
        actor=actor,
        request=request if request is not None else _request(),
        language=language,
        public_url=public_url,
        ip=ip,
        queue_email=queue_email,
    )


async def _transition(
    orgs: ModuleType, db: FakeDb, name: str, actor: Any, org_id: uuid.UUID = ORG_ID
) -> Any:
    return await getattr(orgs, name)(db.pool, actor=actor, org_id=org_id, ip=_IP)


async def _limits(
    orgs: ModuleType, db: FakeDb, actor: Any, org_id: uuid.UUID = ORG_ID, **fields: Any
) -> Any:
    patch_ = models.OrgLimitsPatch(**fields)
    return await orgs.update_limits(db.pool, actor=actor, org_id=org_id, patch=patch_, ip=_IP)


async def _residency(
    orgs: ModuleType, db: FakeDb, actor: Any, *, enabled: bool, org_id: uuid.UUID = ORG_ID
) -> Any:
    return await orgs.set_residency(db.pool, actor=actor, org_id=org_id, enabled=enabled, ip=_IP)


async def _invoke(
    orgs: ModuleType, db: FakeDb, name: str, actor: Any, org_id: uuid.UUID = ORG_ID
) -> Any:
    """Call one service function with valid arguments."""
    if name == "create_org":
        return await _create(orgs, db, actor)
    if name == "list_orgs":
        return await orgs.list_orgs(db.pool, actor=actor)
    if name == "update_limits":
        return await _limits(orgs, db, actor, org_id, seats=5)
    if name == "set_residency":
        return await _residency(orgs, db, actor, enabled=False, org_id=org_id)
    return await _transition(orgs, db, name, actor, org_id)


async def _purge(orgs: ModuleType, db: FakeDb, root: Path) -> Any:
    return await orgs.purge_due_orgs(db.pool, attachments_root=root)


def _state(db: FakeDb) -> dict[str, Any]:
    """A deep copy of every table, for "nothing changed" checks."""
    return copy.deepcopy(
        {
            "users": db.users,
            "orgs": db.orgs,
            "invitations": db.invitations,
            "sessions": db.sessions,
            "tokens": db.tokens,
            "outbox": db.outbox,
            "audit": db.audit,
        }
    )


def _one(items: list[Any]) -> Any:
    assert len(items) == 1, items
    return items[0]


def _text(value: Any) -> str:
    """A bind argument as text, for leak checks."""
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("latin-1")
    return value if isinstance(value, str) else repr(value)


def _bound_ids(call: Call) -> list[uuid.UUID]:
    return [plain(arg) for arg in call.args if isinstance(arg, uuid.UUID)]


def _new_org_id(db: FakeDb, before: set[uuid.UUID]) -> uuid.UUID:
    """The id of the one organization created since ``before``."""
    return _one(sorted(set(db.orgs) - before))


def _link_token(link: str, public_url: str = PUBLIC_URL) -> str:
    prefix = public_url + "/accept-invitation#token="
    assert link.startswith(prefix), link
    token = link[len(prefix) :]
    assert TOKEN_RE.fullmatch(token), link
    return token


def _audit_for(db: FakeDb, action: str) -> dict[str, Any]:
    return _one(db.audit_rows(action))


def _assert_org_event(
    row: dict[str, Any],
    *,
    action: str,
    actor: Principal,
    org_id: uuid.UUID,
    metadata: dict[str, Any],
) -> None:
    """One org.* event of a Super Admin: the org's own log, target the org, the IP."""
    assert row["action"] == action
    assert (row["actor_kind"], row["actor_user_id"]) == ("super_admin", actor.user_id)
    assert row["org_id"] == org_id
    assert (row["target_type"], row["target_ids"]) == ("organization", [str(org_id)])
    assert row["ip"] == _IP
    assert row["metadata"] == metadata
    for key, value in metadata.items():
        assert type(row["metadata"][key]) is type(value), key


def _scoped_settings() -> ModuleType:
    """admino.scoped_settings (its platform settings cache, GH-160)."""
    from admino import scoped_settings

    return scoped_settings


def _store_grace_days(monkeypatch: pytest.MonkeyPatch, grace_days: int) -> None:
    """Make the cached platform settings carry this org deletion grace period (GH-160).

    Built from a dict at call time: StoredPlatformSettings' retention section is
    new in #160.
    """
    scoped_settings = _scoped_settings()
    data = default_test_platform_settings().model_dump()
    data["retention"] = {**data.get("retention", {}), "org_deletion_grace_days": grace_days}
    stored = scoped_settings.StoredPlatformSettings.model_validate(data)
    monkeypatch.setattr(scoped_settings, "_platform_cache", stored)


def _log_text(caplog: pytest.LogCaptureFixture) -> str:
    return "\n".join(
        f"{record.name} {record.getMessage()} {record.exc_text or ''}" for record in caplog.records
    )


def _warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """The WARNING-or-worse records of admino.organizations."""
    return [
        record
        for record in caplog.records
        if record.name == "admino.organizations" and record.levelno >= logging.WARNING
    ]


def _assert_no_leak(text: str, *markers: object) -> None:
    lowered = text.lower()
    for marker in markers:
        value = str(marker).lower()
        assert value not in lowered, value
        if isinstance(marker, uuid.UUID):
            assert marker.hex not in lowered, marker.hex


def _sessions(db: FakeDb, *user_ids: uuid.UUID) -> list[str]:
    """Open one live session for each user; return the raw tokens."""
    return [db.open_session(user_id) for user_id in user_ids]


# ---------------------------------------------------------------------------
# 1. Constants, errors and signatures
# ---------------------------------------------------------------------------


class TestConstantsAndErrors:
    """The fixed values and the input-free errors."""

    def test_organizations_grace_period_constant_is_retired(self, orgs: ModuleType) -> None:
        """GH-160: the grace period is a stored platform default (retention
        org_deletion_grace_days), no longer a module constant."""
        assert not hasattr(orgs, "DELETION_GRACE_PERIOD")

    def test_organizations_attachments_root(self, orgs: ModuleType) -> None:
        assert Path("/app/data/attachments") == orgs.ATTACHMENTS_ROOT

    def test_organizations_purge_runs_hourly(self, orgs: ModuleType) -> None:
        assert orgs.PURGE_INTERVAL_SECONDS == 3600

    def test_organizations_messages(self, orgs: ModuleType) -> None:
        assert orgs.ORG_NOT_FOUND_MESSAGE == _NOT_FOUND
        assert orgs.INVALID_STATUS_MESSAGE == _INVALID_STATUS

    @pytest.mark.parametrize(
        ("name", "message"),
        [("OrgNotFoundError", _NOT_FOUND), ("InvalidOrgStatusError", _INVALID_STATUS)],
    )
    def test_organizations_errors_carry_a_fixed_message(
        self, orgs: ModuleType, name: str, message: str
    ) -> None:
        """Built without arguments, so they can't carry an id or an input."""
        error = getattr(orgs, name)()

        assert isinstance(error, Exception)
        assert str(error) == message

    @pytest.mark.parametrize("name", [*_ALL_FUNCTIONS, "purge_due_orgs", "run_org_purge_job"])
    def test_organizations_functions_are_async_and_keyword_only_after_the_pool(
        self, orgs: ModuleType, name: str
    ) -> None:
        function = getattr(orgs, name)
        parameters = list(inspect.signature(function).parameters.values())

        assert inspect.iscoroutinefunction(function)
        assert parameters[0].name == "pool"
        assert parameters[0].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
        assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in parameters[1:])

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("create_org", ["actor", "request", "language", "public_url", "ip", "queue_email"]),
            ("list_orgs", ["actor"]),
            ("update_limits", ["actor", "org_id", "patch", "ip"]),
            ("deactivate_org", ["actor", "org_id", "ip"]),
            ("reactivate_org", ["actor", "org_id", "ip"]),
            ("schedule_deletion", ["actor", "org_id", "ip"]),
            ("cancel_deletion", ["actor", "org_id", "ip"]),
            ("set_residency", ["actor", "org_id", "enabled", "ip"]),
            ("purge_due_orgs", ["attachments_root"]),
            ("run_org_purge_job", ["attachments_root", "interval_seconds"]),
        ],
    )
    def test_organizations_function_parameters(
        self, orgs: ModuleType, name: str, expected: list[str]
    ) -> None:
        parameters = list(inspect.signature(getattr(orgs, name)).parameters)

        assert parameters[1:] == expected

    def test_organizations_defaults(self, orgs: ModuleType) -> None:
        """Emails are queued by default; the purge defaults to the attachments root setting
        read at call time (None) and to the hour."""
        create = inspect.signature(orgs.create_org).parameters
        purge = inspect.signature(orgs.purge_due_orgs).parameters
        job = inspect.signature(orgs.run_org_purge_job).parameters

        assert create["queue_email"].default is True
        # GH-281 Decision 8 (A5): None = organizations.ATTACHMENTS_ROOT read at call time.
        assert purge["attachments_root"].default is None
        assert job["attachments_root"].default is None
        assert job["interval_seconds"].default == orgs.PURGE_INTERVAL_SECONDS


# ---------------------------------------------------------------------------
# 2. Authorization: a Super Admin only (and the operator for create_org)
# ---------------------------------------------------------------------------


class TestAuthorization:
    """access.can decides before any query; only create_org accepts an Operator."""

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    @pytest.mark.parametrize("name", _ALL_FUNCTIONS)
    async def test_organizations_members_are_refused_before_any_query(
        self, orgs: ModuleType, db: FakeDb, name: str, role: str
    ) -> None:
        """An Org Admin or Editor gets PermissionError("Forbidden"); nothing is read or
        written."""
        actor = _member(db, role)
        before = _state(db)

        with pytest.raises(PermissionError) as caught:
            await _invoke(orgs, db, name, actor)

        assert str(caught.value) == "Forbidden"
        assert db.calls == []
        assert _state(db) == before

    @pytest.mark.parametrize("name", _NOT_CREATE)
    async def test_organizations_operator_is_refused_except_for_create(
        self, orgs: ModuleType, db: FakeDb, name: str
    ) -> None:
        """The operator (admin CLI) may only create orgs."""
        db.add_org(ORG_ID)
        before = _state(db)

        with pytest.raises(PermissionError):
            await _invoke(orgs, db, name, _operator())

        assert db.calls == []
        assert _state(db) == before

    async def test_organizations_operator_can_create(self, orgs: ModuleType, db: FakeDb) -> None:
        before = set(db.orgs)

        await _create(orgs, db, _operator(), ip=None)

        assert len(set(db.orgs) - before) == 1

    @pytest.mark.parametrize("name", _ALL_FUNCTIONS)
    async def test_organizations_super_admin_is_allowed(
        self, orgs: ModuleType, db: FakeDb, name: str
    ) -> None:
        """No PermissionError: the call reaches the database."""
        db.add_org(ORG_ID, status="deactivated" if name == "reactivate_org" else None)
        if name == "cancel_deletion":
            db.add_org(ORG_ID, status="pending_deletion")

        await _invoke(orgs, db, name, _super_admin(db))

        assert db.calls


# ---------------------------------------------------------------------------
# 3. create_org
# ---------------------------------------------------------------------------


class TestCreateOrg:
    """A new org, its org.create event and its first Org Admin's invitation."""

    async def test_organizations_create_inserts_the_org_row(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """The requested name, status and limits; residency on, English responses, no
        deletion dates; created and updated now."""
        actor = _super_admin(db)
        before_ids = set(db.orgs)
        before = datetime.now(UTC)

        await _create(orgs, db, actor)

        row = db.orgs[_new_org_id(db, before_ids)]
        assert (row["name"], row["status"], row["seats"]) == (_NEW_NAME, "active", _SEATS)
        assert row["monthly_budget_chf"] == _BUDGET
        assert row["storage_quota_bytes"] == _QUOTA
        assert (row["data_residency"], row["default_response_language"]) == (True, "en")
        assert (row["deletion_requested_at"], row["purge_after"]) == (None, None)
        assert before <= row["created_at"] <= datetime.now(UTC)
        assert before <= row["updated_at"] <= datetime.now(UTC)

    async def test_organizations_create_deactivated(self, orgs: ModuleType, db: FakeDb) -> None:
        """status "deactivated" at creation: the org starts deactivated, still with its
        first Org Admin's invitation."""
        actor = _super_admin(db)
        before_ids = set(db.orgs)

        await _create(orgs, db, actor, request=_request(status="deactivated"))

        org_id = _new_org_id(db, before_ids)
        assert db.orgs[org_id]["status"] == "deactivated"
        assert _audit_for(db, "org.create")["metadata"]["active"] is False
        invited = db.user_by_email(_ADMIN_EMAIL)
        assert invited is not None
        assert db.invitation_of(invited["id"]) is not None

    async def test_organizations_create_is_audited_as_the_super_admin(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """org.create in the new org's log: target the org, the IP, metadata exactly
        seats, the budget in cents, the quota in bytes and whether it is active."""
        actor = _super_admin(db)
        before_ids = set(db.orgs)

        await _create(orgs, db, actor)

        org_id = _new_org_id(db, before_ids)
        _assert_org_event(
            _audit_for(db, "org.create"),
            action="org.create",
            actor=actor,
            org_id=org_id,
            metadata={
                "seats": _SEATS,
                "monthly_budget_chf_cents": _BUDGET_CENTS,
                "storage_quota_bytes": _QUOTA,
                "active": True,
            },
        )

    @pytest.mark.parametrize(
        ("budget", "cents"),
        [
            (Decimal(0), 0),
            (Decimal("0.05"), 5),
            (Decimal("12.3"), 1230),
            (Decimal(100), 10000),
            (Decimal("9999999999.99"), 999999999999),
        ],
    )
    async def test_organizations_create_budget_in_cents(
        self, orgs: ModuleType, db: FakeDb, budget: Decimal, cents: int
    ) -> None:
        actor = _super_admin(db)

        await _create(orgs, db, actor, request=_request(monthly_budget_chf=budget))

        metadata = _audit_for(db, "org.create")["metadata"]
        assert metadata["monthly_budget_chf_cents"] == cents
        assert type(metadata["monthly_budget_chf_cents"]) is int

    async def test_organizations_create_by_the_operator_is_audited_as_operator(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """The CLI's events: actor_kind operator, no user id, no IP; both events."""
        before_ids = set(db.orgs)

        await _create(orgs, db, _operator(), ip=None)

        org_id = _new_org_id(db, before_ids)
        for action in ("org.create", "invitation.create"):
            row = _audit_for(db, action)
            assert (row["actor_kind"], row["actor_user_id"]) == ("operator", None)
            assert row["org_id"] == org_id
            assert row["ip"] is None

    async def test_organizations_create_writes_exactly_two_audit_rows(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        actor = _super_admin(db)

        await _create(orgs, db, actor)

        assert sorted(row["action"] for row in db.audit) == ["invitation.create", "org.create"]

    async def test_organizations_create_invites_the_first_org_admin(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """An invited member of the new org with the org_admin role, no name, no password,
        in the given language."""
        actor = _super_admin(db)
        before_ids = set(db.orgs)

        await _create(orgs, db, actor, language="fr")

        org_id = _new_org_id(db, before_ids)
        row = db.user_by_email(_ADMIN_EMAIL)
        assert row is not None
        assert (row["email"], row["kind"], row["org_id"], row["role"], row["status"]) == (
            _ADMIN_EMAIL,
            "member",
            org_id,
            "org_admin",
            "invited",
        )
        assert (row["name"], row["password_hash"], row["deleted_at"]) == (None, None, None)
        assert row["ui_language"] == "fr"

    async def test_organizations_create_stores_only_the_token_hash(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """The invitations row holds sha256(token) of a token_urlsafe(32) token, not
        accepted, expiring exactly 72 hours after it was sent (the database clock)."""
        actor = _super_admin(db)

        await _create(orgs, db, actor)

        invited = db.user_by_email(_ADMIN_EMAIL)
        assert invited is not None
        invitation = db.invitation_of(invited["id"])
        assert invitation is not None
        token = db.invitation_token(invited["id"])
        assert invitation["token_hash"] == sha256(token)
        assert invitation["accepted_at"] is None
        assert invitation["expires_at"] - invitation["sent_at"] == timedelta(hours=72)

    async def test_organizations_create_invitation_is_audited_by_the_same_actor(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """invitation.create: the Super Admin, the new org, target the invitation, the IP,
        metadata {"role": "org_admin", "user_id": <invited user>}."""
        actor = _super_admin(db)
        before_ids = set(db.orgs)

        await _create(orgs, db, actor)

        org_id = _new_org_id(db, before_ids)
        invited = db.user_by_email(_ADMIN_EMAIL)
        assert invited is not None
        invitation = db.invitation_of(invited["id"])
        assert invitation is not None
        row = _audit_for(db, "invitation.create")
        assert (row["actor_kind"], row["actor_user_id"]) == ("super_admin", actor.user_id)
        assert row["org_id"] == org_id
        assert (row["target_type"], row["target_ids"]) == ("invitation", [str(invitation["id"])])
        assert row["ip"] == _IP
        assert row["metadata"] == {"role": "org_admin", "user_id": str(invited["id"])}

    async def test_organizations_create_queues_the_invitation_email(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """One outbox row for the invited admin in their language: the org name, the link
        {public_url}/accept-invitation#token=<token> and the expiry."""
        actor = _super_admin(db)

        await _create(orgs, db, actor, language="de")

        invited = db.user_by_email(_ADMIN_EMAIL)
        assert invited is not None
        email = _one(db.outbox)
        assert (email["user_id"], email["template_key"], email["language"]) == (
            invited["id"],
            "invitation",
            "de",
        )
        assert set(email["params"]) == {"org_name", "accept_link", "expires_at"}
        assert email["params"]["org_name"] == _NEW_NAME
        token = _link_token(email["params"]["accept_link"])
        assert email["params"]["accept_link"] == INVITE_LINK_PREFIX + token
        invitation = db.invitation_of(invited["id"])
        assert invitation is not None
        assert invitation["token_hash"] == sha256(token)
        assert datetime.fromisoformat(email["params"]["expires_at"]) == invitation["expires_at"]

    async def test_organizations_create_link_uses_the_given_public_url(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        actor = _super_admin(db)

        created = await _create(orgs, db, actor, public_url="https://app.example.org")

        link = _one(db.outbox)["params"]["accept_link"]
        token = _link_token(link, "https://app.example.org")
        assert created.accept_link == link
        assert TOKEN_RE.fullmatch(token)

    async def test_organizations_create_without_email_queues_nothing(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """queue_email=False: no outbox row at all, but the invitation exists and the
        returned link opens it."""
        before_ids = set(db.orgs)

        created = await _create(orgs, db, _operator(), ip=None, queue_email=False)

        assert db.outbox == []
        org_id = _new_org_id(db, before_ids)
        invited = db.user_by_email(_ADMIN_EMAIL)
        assert invited is not None
        assert invited["org_id"] == org_id
        invitation = db.invitation_of(invited["id"])
        assert invitation is not None
        assert invitation["token_hash"] == sha256(_link_token(created.accept_link))

    async def test_organizations_create_returns_the_created_org(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """A CreatedOrg: the new OrgSummary, the InvitationSummary and the queued link."""
        actor = _super_admin(db)
        before_ids = set(db.orgs)

        created = await _create(orgs, db, actor)

        org_id = _new_org_id(db, before_ids)
        row = db.orgs[org_id]
        assert type(created) is orgs.CreatedOrg
        summary = created.organization
        assert type(summary) is models.OrgSummary
        assert summary.id == org_id
        assert (summary.name, summary.status, summary.seats) == (_NEW_NAME, "active", _SEATS)
        assert summary.monthly_budget_chf == _BUDGET
        assert (summary.storage_quota, summary.data_residency) == (_QUOTA, True)
        assert (summary.deletion_requested_at, summary.purge_after) == (None, None)
        assert (summary.created_at, summary.updated_at) == (row["created_at"], row["updated_at"])
        invited = db.user_by_email(_ADMIN_EMAIL)
        assert invited is not None
        invitation = db.invitation_of(invited["id"])
        assert invitation is not None
        assert type(created.invitation) is models.InvitationSummary
        assert created.invitation.id == invitation["id"]
        assert (created.invitation.email, created.invitation.role) == (_ADMIN_EMAIL, "org_admin")
        assert (created.invitation.sent_at, created.invitation.expires_at) == (
            invitation["sent_at"],
            invitation["expires_at"],
        )
        assert created.invitation.expired is False
        assert created.accept_link == _one(db.outbox)["params"]["accept_link"]

    async def test_organizations_created_org_is_a_frozen_dataclass(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        created = await _create(orgs, db, _super_admin(db))

        assert dataclasses.is_dataclass(created)
        assert {field.name for field in dataclasses.fields(created)} == {
            "organization",
            "invitation",
            "accept_link",
        }
        with pytest.raises(dataclasses.FrozenInstanceError):
            created.accept_link = "https://evil.example"

    async def test_organizations_created_org_repr_hides_the_link(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """accept_link is a one-time secret: repr() shows neither the link nor its token."""
        created = await _create(orgs, db, _super_admin(db))

        token = _link_token(created.accept_link)
        assert created.accept_link not in repr(created)
        assert token not in repr(created)

    async def test_organizations_create_writes_in_one_committed_transaction(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """The org, the invited user, the invitation, the email and both audit events
        share one connection and one committed transaction."""
        actor = _super_admin(db)

        await _create(orgs, db, actor)

        org_insert = _one(db.matching(r"^insert into organizations\b"))
        writes = [
            org_insert,
            _one(db.matching(r"^insert into users\b")),
            _one(db.matching(r"^insert into invitations\b")),
            _one(db.matching(r"^insert into email_outbox\b")),
            *db.matching(r"^insert into audit_events\b"),
        ]
        assert len(writes) == 6
        assert org_insert.tx is not None
        assert {(call.via, call.tx) for call in writes} == {(org_insert.via, org_insert.tx)}
        assert (org_insert.tx, "commit") in db.transactions

    async def test_organizations_create_binds_name_and_email(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """Parameterized SQL: the name and the email travel as bind parameters only."""
        await _create(orgs, db, _super_admin(db))

        for call in db.calls:
            assert _NEW_NAME not in call.sql
            assert _ADMIN_EMAIL.lower() not in call.sql.lower()
        assert any(_NEW_NAME in call.args for call in db.calls)

    async def test_organizations_create_token_travels_only_in_the_email(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """The raw token appears only in the queued email's link: in no statement text,
        no other bind argument, no table row and no audit row."""
        await _create(orgs, db, _super_admin(db))

        token = _link_token(_one(db.outbox)["params"]["accept_link"])
        for call in db.calls:
            assert token not in call.sql
            if call.normalized.startswith("insert into email_outbox"):
                continue
            for arg in call.args:
                assert token not in _text(arg), call.normalized
        for table in (db.users, db.orgs, db.invitations, db.sessions, db.tokens, db.audit):
            assert token not in repr(table)
        others = {key: value for key, value in _one(db.outbox).items() if key != "params"}
        assert token not in repr(others)

    async def test_organizations_create_without_email_token_is_nowhere_in_the_database(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        created = await _create(orgs, db, _operator(), ip=None, queue_email=False)

        token = _link_token(created.accept_link)
        for call in db.calls:
            assert token not in call.sql
            for arg in call.args:
                assert token not in _text(arg), call.normalized
        assert token not in repr(_state(db))

    async def test_organizations_create_tokens_differ(self, orgs: ModuleType, db: FakeDb) -> None:
        actor = _super_admin(db)

        first = await _create(orgs, db, actor)
        second = await _create(
            orgs, db, actor, request=_request(primary_admin_email="second.admin@example.ch")
        )

        assert _link_token(first.accept_link) != _link_token(second.accept_link)


# ---------------------------------------------------------------------------
# 4. create_org refusals: a taken email, a failed audit write
# ---------------------------------------------------------------------------

_TAKEN = "taken.person@example.ch"
_TAKEN_CASES = [
    "active-other-org",
    "other-capitalization",
    "super-admin",
    "invited-elsewhere",
    "deactivated-other-org",
    "soft-deleted",
]


def _existing(db: FakeDb, case: str) -> None:
    """A users row that already holds _TAKEN (in some spelling)."""
    if case == "active-other-org":
        db.add_account(email=_TAKEN, org_id=OTHER_ORG_ID)
    elif case == "other-capitalization":
        db.add_account(email="TAKEN.Person@EXAMPLE.ch")
    elif case == "super-admin":
        db.add_account(email=_TAKEN, kind="super_admin", role=None)
    elif case == "invited-elsewhere":
        db.add_account(
            email=_TAKEN, org_id=OTHER_ORG_ID, status="invited", name=None, password_hash=None
        )
    elif case == "deactivated-other-org":
        db.add_account(email=_TAKEN, org_id=OTHER_ORG_ID, status="deactivated")
    else:
        db.add_account(email=_TAKEN, deleted_at=_DELETED_AT)


class TestCreateOrgRefusals:
    """Nothing at all is written when the create can't complete."""

    @pytest.mark.parametrize("case", _TAKEN_CASES)
    async def test_organizations_create_taken_email_writes_nothing(
        self, orgs: ModuleType, db: FakeDb, case: str
    ) -> None:
        """accounts.DuplicateEmailError; no org, user, invitation, email or audit row (not
        even invitation.refuse: there is no org to log it in)."""
        actor = _super_admin(db)
        _existing(db, case)
        before = _state(db)

        with pytest.raises(accounts.DuplicateEmailError):
            await _create(orgs, db, actor, request=_request(primary_admin_email=_TAKEN))

        assert _state(db) == before

    async def test_organizations_create_taken_email_error_carries_no_email(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """The fixed message; the driver's text (which repeats the email) doesn't travel
        with it, not even in the formatted traceback."""
        actor = _super_admin(db)
        _existing(db, "active-other-org")

        with pytest.raises(accounts.DuplicateEmailError) as caught:
            await _create(orgs, db, actor, request=_request(primary_admin_email=_TAKEN))

        assert str(caught.value) == _DUPLICATE
        formatted = "".join(traceback.format_exception(caught.value)).lower()
        assert "taken.person" not in formatted

    async def test_organizations_create_audit_failure_writes_nothing(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """Fail closed: every audit write fails -> AuditRecordError, nothing remains."""
        actor = _super_admin(db)
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _create(orgs, db, actor)

        assert _state(db) == before
        assert db.transactions[-1][1] == "rollback:AuditRecordError"

    @pytest.mark.parametrize("action", ["org.create", "invitation.create"])
    async def test_organizations_create_one_failed_audit_event_writes_nothing(
        self, orgs: ModuleType, db: FakeDb, action: str
    ) -> None:
        """Either event failing rolls back the org row too."""
        actor = _super_admin(db)
        before = _state(db)
        db.fail_audit_when = lambda row: row["action"] == action

        with pytest.raises(AuditRecordError):
            await _create(orgs, db, actor)

        assert _state(db) == before


# ---------------------------------------------------------------------------
# 4b. create_org seeds the new org's permission matrix (GH-161)
# ---------------------------------------------------------------------------


def _default_matrix() -> dict[str, dict[str, str]]:
    """build_default_permissions_config() as tool -> {action: state} (34 rows)."""
    from admino.permissions import build_default_permissions_config

    config = build_default_permissions_config()
    return {tool: dict(perms.actions) for tool, perms in config.tools.items()}


def _permission_inserts(db: FakeDb) -> list[Call]:
    return db.matching(r"^insert into permissions\b")


class TestCreateOrgSeedsPermissions:
    """A new org starts from the default matrix, seeded inside create_org's transaction;
    a creation that rolls back leaves no permission row; the purge removes them."""

    async def test_organizations_create_seeds_the_default_permission_matrix(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        actor = _super_admin(db)

        created = await _create(orgs, db, actor)

        org_id = created.organization.id
        assert db.org_permissions(org_id) == _default_matrix()
        assert sum(len(actions) for actions in db.org_permissions(org_id).values()) == 34

    async def test_organizations_create_seeds_permissions_in_the_org_insert_transaction(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """Every seed INSERT runs in the committed transaction of the org INSERT, after it."""
        actor = _super_admin(db)

        await _create(orgs, db, actor)

        org_insert = _one(db.matching(r"^insert into organizations\b"))
        seeds = _permission_inserts(db)
        assert seeds
        assert {call.tx for call in seeds} == {org_insert.tx}
        assert org_insert.tx is not None
        assert (org_insert.tx, "commit") in db.transactions
        assert db.calls.index(org_insert) < db.calls.index(seeds[0])

    async def test_organizations_create_by_the_operator_seeds_the_matrix_too(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        created = await _create(orgs, db, _operator(), ip=None, queue_email=False)

        assert db.org_permissions(created.organization.id) == _default_matrix()

    async def test_organizations_create_leaves_other_orgs_permissions_alone(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        actor = _super_admin(db)
        db.add_org(ORG_ID)
        db.add_permissions(ORG_ID, {"gmail": {"read": "deny"}})
        before = copy.deepcopy(db.permissions)

        created = await _create(orgs, db, actor)

        new_org = created.organization.id
        assert db.org_permissions(new_org) == _default_matrix()
        kept = {key: row for key, row in db.permissions.items() if plain(key[0]) != new_org}
        assert kept == before
        assert db.org_permissions(ORG_ID) == {"gmail": {"read": "deny"}}

    async def test_organizations_create_taken_email_leaves_no_permission_rows(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """The seed ran inside the transaction (after the org INSERT, before the invited
        admin's INSERT failed) and was rolled back with it."""
        actor = _super_admin(db)
        _existing(db, "active-other-org")
        before = copy.deepcopy(db.permissions)

        with pytest.raises(accounts.DuplicateEmailError):
            await _create(orgs, db, actor, request=_request(primary_admin_email=_TAKEN))

        seeds = _permission_inserts(db)
        assert seeds
        rolled_back = {tx for tx, outcome in db.transactions if outcome.startswith("rollback")}
        assert {call.tx for call in seeds} <= rolled_back
        assert db.permissions == before

    async def test_organizations_create_audit_failure_leaves_no_permission_rows(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """The invitation.create record fails after the seed: everything rolls back."""
        actor = _super_admin(db)
        before_orgs = set(db.orgs)
        db.fail_audit_when = lambda row: row["action"] == "invitation.create"

        with pytest.raises(AuditRecordError):
            await _create(orgs, db, actor)

        seeds = _permission_inserts(db)
        assert seeds
        rolled_back = {tx for tx, outcome in db.transactions if outcome.startswith("rollback")}
        assert {call.tx for call in seeds} <= rolled_back
        assert db.permissions == {}
        assert set(db.orgs) == before_orgs

    async def test_organizations_purge_removes_the_orgs_permission_rows(
        self, orgs: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """ON DELETE CASCADE: the purged org's matrix goes with its row (which
        purge_org_audit_events deletes, GH-220); another org's stays."""
        actor = _super_admin(db)
        db.add_org(ORG_ID)
        db.add_permissions(ORG_ID)
        kept = copy.deepcopy(db.org_permissions(ORG_ID))
        created = await _create(orgs, db, actor)
        org_id = created.organization.id
        assert db.org_permissions(org_id) == _default_matrix()
        _due(db, org_id)

        assert await _purge(orgs, db, root) == 1

        assert db.org_permissions(org_id) == {}
        assert not any(plain(key[0]) == org_id for key in db.permissions)
        assert db.org_permissions(ORG_ID) == kept


# ---------------------------------------------------------------------------
# 5. list_orgs
# ---------------------------------------------------------------------------

_ORG_X = uuid.UUID("cccccccc-0000-4000-8000-000000000003")
_ORG_Y = uuid.UUID("bbbbbbbb-0000-4000-8000-000000000002")
_ORG_Z = uuid.UUID("aaaaaaaa-0000-4000-8000-000000000001")


class TestListOrgs:
    """Every org, whatever its status, as OrgSummary, ordered by creation then id."""

    async def test_organizations_list_every_status_in_order(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """created_at first, then id for a tie."""
        later = _OLD + timedelta(days=2)
        db.add_org(_ORG_X, status="pending_deletion", created_at=later)
        db.add_org(_ORG_Y, status="deactivated", created_at=_OLD)
        db.add_org(_ORG_Z, created_at=later)

        result = await orgs.list_orgs(db.pool, actor=_super_admin(db))

        assert [summary.id for summary in result] == [_ORG_Y, _ORG_Z, _ORG_X]
        assert [summary.status for summary in result] == [
            "deactivated",
            "active",
            "pending_deletion",
        ]

    async def test_organizations_list_summary_values(self, orgs: ModuleType, db: FakeDb) -> None:
        """Every field of an OrgSummary comes from the row (storage_quota is the quota in
        bytes)."""
        requested = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
        db.add_org(
            ORG_ID,
            name="Summary Marker GmbH",
            seats=42,
            status="pending_deletion",
            monthly_budget_chf=Decimal("77.50"),
            storage_quota_bytes=123456789,
            data_residency=False,
            deletion_requested_at=requested,
            purge_after=requested + timedelta(days=30),
            created_at=_OLD,
            updated_at=requested,
        )

        (summary,) = await orgs.list_orgs(db.pool, actor=_super_admin(db))

        assert type(summary) is models.OrgSummary
        assert summary.model_dump() == {
            "id": ORG_ID,
            "name": "Summary Marker GmbH",
            "status": "pending_deletion",
            "seats": 42,
            "monthly_budget_chf": Decimal("77.50"),
            "storage_quota": 123456789,
            "data_residency": False,
            "deletion_requested_at": requested,
            "purge_after": requested + timedelta(days=30),
            "created_at": _OLD,
            "updated_at": requested,
        }

    async def test_organizations_list_without_orgs_is_empty(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        assert await orgs.list_orgs(db.pool, actor=_super_admin(db)) == []

    async def test_organizations_list_writes_nothing(self, orgs: ModuleType, db: FakeDb) -> None:
        db.add_org(ORG_ID)
        actor = _super_admin(db)
        before = _state(db)

        await orgs.list_orgs(db.pool, actor=actor)

        assert _state(db) == before


# ---------------------------------------------------------------------------
# 6. Status transitions
# ---------------------------------------------------------------------------


def _expected_metadata(name: str) -> dict[str, Any]:
    """The metadata of a transition on an org without users or sessions."""
    if name == "deactivate_org":
        return {"sessions_revoked": 0}
    if name == "schedule_deletion":
        return {"sessions_revoked": 0, "emails_queued": 0, "grace_days": 30}
    return {}


class TestTransitions:
    """active <-> deactivated, active/deactivated -> pending_deletion -> deactivated."""

    @pytest.mark.parametrize(("name", "start"), _ALLOWED)
    async def test_organizations_transition_changes_the_status(
        self, orgs: ModuleType, db: FakeDb, name: str, start: str
    ) -> None:
        """The new status, updated_at now, and the returned OrgSummary."""
        db.add_org(ORG_ID, status=start, updated_at=_OLD)
        before = datetime.now(UTC)

        result = await _transition(orgs, db, name, _super_admin(db))

        row = db.orgs[ORG_ID]
        target = _TRANSITIONS[name][2]
        assert row["status"] == target
        assert before <= row["updated_at"] <= datetime.now(UTC)
        assert type(result) is models.OrgSummary
        assert (result.id, result.status, result.updated_at) == (ORG_ID, target, row["updated_at"])
        assert (result.deletion_requested_at, result.purge_after) == (
            row["deletion_requested_at"],
            row["purge_after"],
        )

    @pytest.mark.parametrize(("name", "start"), _ALLOWED)
    async def test_organizations_transition_sets_or_clears_the_deletion_dates(
        self, orgs: ModuleType, db: FakeDb, name: str, start: str
    ) -> None:
        """Only scheduling sets them; every other allowed transition leaves none."""
        db.add_org(ORG_ID, status=start)

        await _transition(orgs, db, name, _super_admin(db))

        row = db.orgs[ORG_ID]
        scheduled = name == "schedule_deletion"
        assert (row["deletion_requested_at"] is not None) is scheduled
        assert (row["purge_after"] is not None) is scheduled

    @pytest.mark.parametrize(("name", "start"), _ALLOWED)
    async def test_organizations_transition_writes_exactly_one_audit_row(
        self, orgs: ModuleType, db: FakeDb, name: str, start: str
    ) -> None:
        """The action, the Super Admin, the org's own log, target the org, the IP, the
        exact metadata."""
        db.add_org(ORG_ID, status=start)
        actor = _super_admin(db)

        await _transition(orgs, db, name, actor)

        row = _one(db.audit)
        _assert_org_event(
            row,
            action=_TRANSITIONS[name][0],
            actor=actor,
            org_id=ORG_ID,
            metadata=_expected_metadata(name),
        )

    @pytest.mark.parametrize(("name", "start"), _REFUSED)
    async def test_organizations_transition_from_a_wrong_status_is_refused(
        self, orgs: ModuleType, db: FakeDb, name: str, start: str
    ) -> None:
        """InvalidOrgStatusError with the fixed message; nothing is written, no audit."""
        db.add_org(ORG_ID, status=start)
        actor = _super_admin(db)
        _sessions(db, db.add_account(role="org_admin"))
        before = _state(db)

        with pytest.raises(orgs.InvalidOrgStatusError) as caught:
            await _transition(orgs, db, name, actor)

        assert str(caught.value) == _INVALID_STATUS
        assert _state(db) == before

    @pytest.mark.parametrize("name", _ORG_FUNCTIONS)
    async def test_organizations_unknown_org_is_not_found(
        self, orgs: ModuleType, db: FakeDb, name: str
    ) -> None:
        """OrgNotFoundError with the fixed message (no id); nothing is written."""
        db.add_org(ORG_ID)
        actor = _super_admin(db)
        before = _state(db)

        with pytest.raises(orgs.OrgNotFoundError) as caught:
            await _invoke(orgs, db, name, actor, org_id=_UNKNOWN_ORG)

        assert str(caught.value) == _NOT_FOUND
        assert _state(db) == before

    @pytest.mark.parametrize(("name", "start"), _ALLOWED)
    async def test_organizations_transition_locks_the_org_row_first(
        self, orgs: ModuleType, db: FakeDb, name: str, start: str
    ) -> None:
        """SELECT ... FROM organizations ... FOR UPDATE of this org, in the transaction of
        the change, before the UPDATE."""
        db.add_org(ORG_ID, status=start)

        await _transition(orgs, db, name, _super_admin(db))

        update = _one(db.matching(r"^update organizations\b"))
        locks = [
            index
            for index, call in enumerate(db.calls)
            if re.search(r"\bfrom organizations\b", call.normalized)
            and re.search(r"\bfor (?:no key )?update\b", call.normalized)
            and ORG_ID in _bound_ids(call)
            and (call.via, call.tx) == (update.via, update.tx)
        ]
        assert locks, "the org row is never locked"
        assert locks[0] < db.calls.index(update)

    @pytest.mark.parametrize(("name", "start"), _ALLOWED)
    async def test_organizations_transition_and_audit_share_a_committed_transaction(
        self, orgs: ModuleType, db: FakeDb, name: str, start: str
    ) -> None:
        db.add_org(ORG_ID, status=start)

        await _transition(orgs, db, name, _super_admin(db))

        update = _one(db.matching(r"^update organizations\b"))
        audit = _one(db.matching(r"^insert into audit_events\b"))
        assert update.tx is not None
        assert (audit.via, audit.tx) == (update.via, update.tx)
        assert (update.tx, "commit") in db.transactions

    @pytest.mark.parametrize(("name", "start"), _ALLOWED)
    async def test_organizations_transition_audit_failure_changes_nothing(
        self, orgs: ModuleType, db: FakeDb, name: str, start: str
    ) -> None:
        """Fail closed: the status, the dates, the sessions and the outbox stay."""
        db.add_org(ORG_ID, status=start)
        actor = _super_admin(db)
        admin = db.add_account(role="org_admin")
        _sessions(db, admin, admin)
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _transition(orgs, db, name, actor)

        assert _state(db) == before
        assert db.transactions[-1][1] == "rollback:AuditRecordError"

    @pytest.mark.parametrize(("name", "start"), _ALLOWED)
    async def test_organizations_transition_binds_the_org_id(
        self, orgs: ModuleType, db: FakeDb, name: str, start: str
    ) -> None:
        """Parameterized SQL: the id travels as a bind parameter."""
        db.add_org(ORG_ID, status=start)

        await _transition(orgs, db, name, _super_admin(db))

        for call in db.calls:
            assert str(ORG_ID) not in call.sql
            assert ORG_ID.hex not in call.sql
            assert _IP not in call.sql

    async def test_organizations_transition_touches_only_the_given_org(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID)
        db.add_org(OTHER_ORG_ID)
        other_before = copy.deepcopy(db.orgs[OTHER_ORG_ID])

        await _transition(orgs, db, "schedule_deletion", _super_admin(db))

        assert db.orgs[OTHER_ORG_ID] == other_before


# ---------------------------------------------------------------------------
# 7. Session revocation on deactivation and scheduling
# ---------------------------------------------------------------------------


def _org_people(db: FakeDb) -> tuple[list[uuid.UUID], list[str]]:
    """Users of ORG_ID in every role and status, with sessions; returns (ids, tokens)."""
    users = [
        db.add_account(role="org_admin"),
        db.add_account(role="editor"),
        db.add_account(role="editor"),
        db.add_account(role="editor", status="deactivated"),
        db.add_account(role="editor", status="invited", name=None, password_hash=None),
        db.add_account(role="org_admin", deleted_at=_DELETED_AT),
    ]
    tokens = _sessions(db, users[0], users[0], *users[1:])
    return users, tokens


class TestSessionRevocation:
    """Deactivating and scheduling end every session of the org's users, and only those."""

    @pytest.mark.parametrize("name", ["deactivate_org", "schedule_deletion"])
    async def test_organizations_revokes_every_session_of_the_org(
        self, orgs: ModuleType, db: FakeDb, name: str
    ) -> None:
        """All roles and statuses; the count lands in the audit metadata."""
        db.add_org(ORG_ID)
        actor = _super_admin(db)
        _, tokens = _org_people(db)

        await _transition(orgs, db, name, actor)

        assert all(db.session_revoked(token) for token in tokens)
        metadata = _audit_for(db, _TRANSITIONS[name][0])["metadata"]
        assert metadata["sessions_revoked"] == len(tokens)

    @pytest.mark.parametrize("name", ["deactivate_org", "schedule_deletion"])
    async def test_organizations_keeps_other_orgs_and_super_admin_sessions(
        self, orgs: ModuleType, db: FakeDb, name: str
    ) -> None:
        db.add_org(ORG_ID)
        actor = _super_admin(db)
        _org_people(db)
        kept = _sessions(
            db,
            actor.user_id,
            db.add_account(kind="super_admin", role=None),
            db.add_account(role="org_admin", org_id=OTHER_ORG_ID),
            db.add_account(role="editor", org_id=OTHER_ORG_ID),
        )

        await _transition(orgs, db, name, actor)

        assert not any(db.session_revoked(token) for token in kept)

    @pytest.mark.parametrize("name", ["deactivate_org", "schedule_deletion"])
    async def test_organizations_keeps_the_orgs_content(
        self, orgs: ModuleType, db: FakeDb, name: str
    ) -> None:
        """Users rows and invitations are kept (only sessions end)."""
        db.add_org(ORG_ID)
        actor = _super_admin(db)
        users, _ = _org_people(db)
        db.add_invitation(users[4])
        users_before = copy.deepcopy({user_id: db.users[user_id] for user_id in users})
        invitations_before = copy.deepcopy(db.invitations)

        await _transition(orgs, db, name, actor)

        assert {user_id: db.users[user_id] for user_id in users} == users_before
        assert db.invitations == invitations_before

    @pytest.mark.parametrize("name", ["deactivate_org", "schedule_deletion"])
    async def test_organizations_revocation_shares_the_transaction(
        self, orgs: ModuleType, db: FakeDb, name: str
    ) -> None:
        db.add_org(ORG_ID)
        actor = _super_admin(db)
        _org_people(db)

        await _transition(orgs, db, name, actor)

        update = _one(db.matching(r"^update organizations\b"))
        revoke = _one(db.matching(r"^delete from sessions\b"))
        assert (revoke.via, revoke.tx) == (update.via, update.tx)
        assert ORG_ID in _bound_ids(revoke)


# ---------------------------------------------------------------------------
# 8. Scheduling: the purge date and the Org Admins' emails
# ---------------------------------------------------------------------------


class TestScheduleDeletion:
    """purge_after = now() + 30 days on the database clock; the active Org Admins are told."""

    @pytest.mark.parametrize("start", ["active", "deactivated"])
    async def test_organizations_schedule_sets_the_dates(
        self, orgs: ModuleType, db: FakeDb, start: str
    ) -> None:
        """deletion_requested_at = now, purge_after exactly the grace period later."""
        db.add_org(ORG_ID, status=start)
        before = datetime.now(UTC)

        await _transition(orgs, db, "schedule_deletion", _super_admin(db))

        row = db.orgs[ORG_ID]
        assert before <= row["deletion_requested_at"] <= datetime.now(UTC)
        assert row["purge_after"] - row["deletion_requested_at"] == timedelta(days=30)

    async def test_organizations_schedule_uses_the_database_clock(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """No date is computed in Python: no organizations UPDATE binds a datetime."""
        db.add_org(ORG_ID)

        await _transition(orgs, db, "schedule_deletion", _super_admin(db))

        update = _one(db.matching(r"^update organizations\b"))
        assert not any(isinstance(arg, datetime) for arg in update.args)

    @pytest.mark.parametrize("start", ["active", "deactivated"])
    async def test_organizations_schedule_emails_only_active_org_admins(
        self, orgs: ModuleType, db: FakeDb, start: str
    ) -> None:
        """One org_deletion_scheduled email per active, non-deleted Org Admin of the org,
        in their language; not editors, invited, deactivated or deleted admins, nor other
        orgs' admins or Super Admins."""
        db.add_org(ORG_ID, status=start)
        actor = _super_admin(db)
        admin_de = db.add_account(role="org_admin", ui_language="de")
        admin_fr = db.add_account(role="org_admin", ui_language="fr")
        db.add_account(role="org_admin", status="deactivated")
        db.add_account(role="org_admin", status="invited", name=None, password_hash=None)
        db.add_account(role="org_admin", deleted_at=_DELETED_AT)
        db.add_account(role="editor")
        db.add_account(role="org_admin", org_id=OTHER_ORG_ID)
        db.add_account(kind="super_admin", role=None)

        await _transition(orgs, db, "schedule_deletion", actor)

        emails = [row for row in db.outbox if row["template_key"] == "org_deletion_scheduled"]
        assert len(db.outbox) == len(emails) == 2
        assert {(row["user_id"], row["language"]) for row in emails} == {
            (admin_de, "de"),
            (admin_fr, "fr"),
        }
        metadata = _audit_for(db, "org.deletion_schedule")["metadata"]
        assert metadata["emails_queued"] == 2

    async def test_organizations_schedule_email_params(self, orgs: ModuleType, db: FakeDb) -> None:
        """Exactly the org's display name and the stored purge date."""
        db.add_org(ORG_ID)
        db.add_account(role="org_admin")

        await _transition(orgs, db, "schedule_deletion", _super_admin(db))

        params = _one(db.outbox)["params"]
        assert set(params) == {"org_name", "purge_after"}
        assert params["org_name"] == ORG_NAME
        assert datetime.fromisoformat(params["purge_after"]) == db.orgs[ORG_ID]["purge_after"]

    async def test_organizations_schedule_emails_share_the_transaction(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID)
        db.add_account(role="org_admin")
        db.add_account(role="org_admin")

        await _transition(orgs, db, "schedule_deletion", _super_admin(db))

        update = _one(db.matching(r"^update organizations\b"))
        enqueues = db.matching(r"^insert into email_outbox\b")
        assert len(enqueues) == 2
        assert {(call.via, call.tx) for call in enqueues} == {(update.via, update.tx)}

    async def test_organizations_schedule_audit_metadata_counts(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID)
        actor = _super_admin(db)
        admin = db.add_account(role="org_admin")
        editor = db.add_account(role="editor")
        _sessions(db, admin, editor, editor)

        await _transition(orgs, db, "schedule_deletion", actor)

        _assert_org_event(
            _audit_for(db, "org.deletion_schedule"),
            action="org.deletion_schedule",
            actor=actor,
            org_id=ORG_ID,
            metadata={"sessions_revoked": 3, "emails_queued": 1, "grace_days": 30},
        )


class TestScheduleDeletionGracePeriod:
    """GH-160: purge_after = now() + the stored retention.org_deletion_grace_days."""

    @pytest.mark.parametrize("grace_days", [7, 45, 90])
    async def test_organizations_schedule_uses_the_stored_grace_period(
        self, orgs: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch, grace_days: int
    ) -> None:
        """purge_after is exactly the stored number of days after deletion_requested_at,
        and the org.deletion_schedule metadata's grace_days is that number."""
        _store_grace_days(monkeypatch, grace_days)
        db.add_org(ORG_ID)
        actor = _super_admin(db)

        await _transition(orgs, db, "schedule_deletion", actor)

        row = db.orgs[ORG_ID]
        assert row["purge_after"] - row["deletion_requested_at"] == timedelta(days=grace_days)
        _assert_org_event(
            _audit_for(db, "org.deletion_schedule"),
            action="org.deletion_schedule",
            actor=actor,
            org_id=ORG_ID,
            metadata={"sessions_revoked": 0, "emails_queued": 0, "grace_days": grace_days},
        )

    async def test_organizations_schedule_reads_the_grace_period_from_the_row(
        self, orgs: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With an empty cache the grace period comes from the platform_settings row."""
        monkeypatch.setattr(_scoped_settings(), "_platform_cache", None)
        db.add_platform_settings(org_deletion_grace_days=60)
        db.add_org(ORG_ID)

        await _transition(orgs, db, "schedule_deletion", _super_admin(db))

        row = db.orgs[ORG_ID]
        assert row["purge_after"] - row["deletion_requested_at"] == timedelta(days=60)
        assert _audit_for(db, "org.deletion_schedule")["metadata"]["grace_days"] == 60

    async def test_organizations_schedule_after_a_change_uses_the_new_grace_period(
        self, orgs: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """AC: a deletion scheduled after the change gets the new grace period; one
        scheduled before keeps its purge_after."""
        db.add_org(ORG_ID)
        db.add_org(OTHER_ORG_ID)
        actor = _super_admin(db)
        _store_grace_days(monkeypatch, 7)
        await _transition(orgs, db, "schedule_deletion", actor, ORG_ID)
        earlier = dict(db.orgs[ORG_ID])

        _store_grace_days(monkeypatch, 90)
        await _transition(orgs, db, "schedule_deletion", actor, OTHER_ORG_ID)

        later = db.orgs[OTHER_ORG_ID]
        assert later["purge_after"] - later["deletion_requested_at"] == timedelta(days=90)
        assert db.orgs[ORG_ID]["purge_after"] == earlier["purge_after"]
        assert earlier["purge_after"] - earlier["deletion_requested_at"] == timedelta(days=7)
        grace = [row["metadata"]["grace_days"] for row in db.audit_rows("org.deletion_schedule")]
        assert grace == [7, 90]

    async def test_organizations_schedule_reads_the_settings_only_once_authorized(
        self, orgs: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The grace period is read through scoped_settings.current_platform_settings
        (once, with the pool) after the authorization: a refused Org Admin reads
        nothing."""
        scoped_settings = _scoped_settings()
        real = scoped_settings.current_platform_settings
        executors: list[Any] = []

        async def spy(executor: Any) -> Any:
            executors.append(executor)
            return await real(executor)

        monkeypatch.setattr(scoped_settings, "current_platform_settings", spy)
        db.add_org(ORG_ID)

        with pytest.raises(PermissionError):
            await _transition(orgs, db, "schedule_deletion", _member(db, "org_admin"))
        refused = list(executors)
        await _transition(orgs, db, "schedule_deletion", _super_admin(db))

        assert refused == []
        assert executors == [db.pool]


# ---------------------------------------------------------------------------
# 9. Cancelling a scheduled deletion
# ---------------------------------------------------------------------------


class TestCancelDeletion:
    """Back to deactivated (never active), dates cleared, as long as it isn't purged."""

    async def test_organizations_cancel_after_scheduling_an_active_org_lands_on_deactivated(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID)
        actor = _super_admin(db)

        await _transition(orgs, db, "schedule_deletion", actor)
        await _transition(orgs, db, "cancel_deletion", actor)

        row = db.orgs[ORG_ID]
        assert row["status"] == "deactivated"
        assert (row["deletion_requested_at"], row["purge_after"]) == (None, None)

    async def test_organizations_cancel_works_after_purge_after_passed(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        """The purge job hasn't run yet: the org can still be saved."""
        db.add_org(
            ORG_ID,
            status="pending_deletion",
            deletion_requested_at=_OLD,
            purge_after=datetime.now(UTC) - timedelta(days=1),
        )

        await _transition(orgs, db, "cancel_deletion", _super_admin(db))

        assert db.orgs[ORG_ID]["status"] == "deactivated"

    async def test_organizations_cancel_queues_no_email(self, orgs: ModuleType, db: FakeDb) -> None:
        db.add_org(ORG_ID, status="pending_deletion")
        db.add_account(role="org_admin")

        await _transition(orgs, db, "cancel_deletion", _super_admin(db))

        assert db.outbox == []


# ---------------------------------------------------------------------------
# 10. update_limits
# ---------------------------------------------------------------------------


class TestUpdateLimits:
    """Only the given limits change; old and new values are audited (the budget in cents)."""

    @pytest.mark.parametrize(
        ("fields", "stored", "metadata"),
        [
            pytest.param(
                {"seats": 7},
                {"seats": 7},
                {"seats_old": 100, "seats_new": 7},
                id="seats",
            ),
            pytest.param(
                {"monthly_budget_chf": Decimal("250.5")},
                {"monthly_budget_chf": Decimal("250.50")},
                {"monthly_budget_chf_cents_old": 1000, "monthly_budget_chf_cents_new": 25050},
                id="budget",
            ),
            pytest.param(
                {"storage_quota": 2048},
                {"storage_quota_bytes": 2048},
                {"storage_quota_bytes_old": 4096, "storage_quota_bytes_new": 2048},
                id="storage",
            ),
            pytest.param(
                {"seats": 3, "monthly_budget_chf": Decimal(0), "storage_quota": 0},
                {"seats": 3, "monthly_budget_chf": Decimal(0), "storage_quota_bytes": 0},
                {
                    "seats_old": 100,
                    "seats_new": 3,
                    "monthly_budget_chf_cents_old": 1000,
                    "monthly_budget_chf_cents_new": 0,
                    "storage_quota_bytes_old": 4096,
                    "storage_quota_bytes_new": 0,
                },
                id="all",
            ),
            pytest.param(
                {"seats": 9, "monthly_budget_chf": None, "storage_quota": None},
                {"seats": 9},
                {"seats_old": 100, "seats_new": 9},
                id="nulls-are-not-given",
            ),
        ],
    )
    async def test_organizations_limits_change_only_the_given_fields(
        self,
        orgs: ModuleType,
        db: FakeDb,
        fields: dict[str, Any],
        stored: dict[str, Any],
        metadata: dict[str, Any],
    ) -> None:
        db.add_org(
            ORG_ID,
            monthly_budget_chf=Decimal("10.00"),
            storage_quota_bytes=4096,
            updated_at=_OLD,
        )
        actor = _super_admin(db)
        before_row = copy.deepcopy(db.orgs[ORG_ID])
        before = datetime.now(UTC)

        result = await _limits(orgs, db, actor, **fields)

        row = db.orgs[ORG_ID]
        expected = {**before_row, **stored, "updated_at": row["updated_at"]}
        assert row == expected
        assert before <= row["updated_at"] <= datetime.now(UTC)
        _assert_org_event(
            _audit_for(db, "org.limits_change"),
            action="org.limits_change",
            actor=actor,
            org_id=ORG_ID,
            metadata=metadata,
        )
        assert type(result) is models.OrgSummary
        assert result.seats == row["seats"]
        assert result.monthly_budget_chf == row["monthly_budget_chf"]
        assert result.storage_quota == row["storage_quota_bytes"]

    async def test_organizations_limits_seats_may_go_below_the_seats_in_use(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID)
        for _ in range(3):
            db.add_account(role="editor")

        await _limits(orgs, db, _super_admin(db), seats=1)

        assert db.orgs[ORG_ID]["seats"] == 1

    async def test_organizations_limits_of_a_deactivated_org(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID, status="deactivated")

        await _limits(orgs, db, _super_admin(db), seats=4)

        assert db.orgs[ORG_ID]["seats"] == 4

    async def test_organizations_limits_refused_while_deletion_is_pending(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID, status="pending_deletion")
        actor = _super_admin(db)
        before = _state(db)

        with pytest.raises(orgs.InvalidOrgStatusError):
            await _limits(orgs, db, actor, seats=4)

        assert _state(db) == before

    async def test_organizations_limits_audit_failure_changes_nothing(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID)
        actor = _super_admin(db)
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _limits(orgs, db, actor, seats=4)

        assert _state(db) == before

    async def test_organizations_limits_change_and_audit_share_a_transaction(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID)

        await _limits(orgs, db, _super_admin(db), seats=4)

        update = _one(db.matching(r"^update organizations\b"))
        audit = _one(db.matching(r"^insert into audit_events\b"))
        assert update.tx is not None
        assert (audit.via, audit.tx) == (update.via, update.tx)
        assert (update.tx, "commit") in db.transactions


# ---------------------------------------------------------------------------
# 11. set_residency
# ---------------------------------------------------------------------------


class TestSetResidency:
    """data_residency on or off, audited in the org's own log (its admins see it)."""

    @pytest.mark.parametrize(
        ("previous", "enabled"),
        [(True, False), (False, True), (True, True), (False, False)],
    )
    async def test_organizations_residency_is_set_and_audited(
        self, orgs: ModuleType, db: FakeDb, previous: bool, enabled: bool
    ) -> None:
        """Also audited when the value doesn't change."""
        db.add_org(ORG_ID, data_residency=previous, updated_at=_OLD)
        actor = _super_admin(db)

        result = await _residency(orgs, db, actor, enabled=enabled)

        row = db.orgs[ORG_ID]
        assert row["data_residency"] is enabled
        assert row["updated_at"] > _OLD
        _assert_org_event(
            _audit_for(db, "org.residency_change"),
            action="org.residency_change",
            actor=actor,
            org_id=ORG_ID,
            metadata={"enabled": enabled, "previous": previous},
        )
        assert type(result) is models.OrgSummary
        assert result.data_residency is enabled

    async def test_organizations_residency_of_a_deactivated_org(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID, status="deactivated")

        await _residency(orgs, db, _super_admin(db), enabled=False)

        assert db.orgs[ORG_ID]["data_residency"] is False

    async def test_organizations_residency_refused_while_deletion_is_pending(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID, status="pending_deletion")
        actor = _super_admin(db)
        before = _state(db)

        with pytest.raises(orgs.InvalidOrgStatusError):
            await _residency(orgs, db, actor, enabled=False)

        assert _state(db) == before

    async def test_organizations_residency_audit_failure_changes_nothing(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID)
        actor = _super_admin(db)
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _residency(orgs, db, actor, enabled=False)

        assert _state(db) == before

    async def test_organizations_residency_touches_only_the_given_org(
        self, orgs: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID)
        db.add_org(OTHER_ORG_ID)

        await _residency(orgs, db, _super_admin(db), enabled=False)

        assert db.orgs[OTHER_ORG_ID]["data_residency"] is True


# ---------------------------------------------------------------------------
# 12. purge_due_orgs: completeness
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class _World:
    """A platform with one due org and everything that must survive its purge."""

    due: uuid.UUID
    kept_orgs: list[uuid.UUID]
    due_users: list[uuid.UUID]
    due_audit_count: int
    super_admin: uuid.UUID
    super_admin_token: str
    platform_events: list[uuid.UUID]
    snapshots: dict[uuid.UUID, dict[str, Any]]
    kept_files: dict[Path, bytes]


def _populate(db: FakeDb, org_id: uuid.UUID, root: Path, super_admin: uuid.UUID) -> list[uuid.UUID]:
    """Users of every status, their sessions, an invitation, emails, a reset token, audit
    events (old ones and Super Admin actions included) and nested files."""
    users = [
        db.add_account(role="org_admin", org_id=org_id),
        db.add_account(role="editor", org_id=org_id),
        db.add_account(role="editor", org_id=org_id, ui_language="fr"),
        db.add_account(
            role="editor", org_id=org_id, status="invited", name=None, password_hash=None
        ),
        db.add_account(role="editor", org_id=org_id, status="deactivated"),
        db.add_account(role="editor", org_id=org_id, deleted_at=_DELETED_AT),
    ]
    _sessions(db, users[0], users[0], users[1], users[4], users[5])
    db.add_invitation(users[3])
    db.add_email(users[3], params={"org_name": "x", "accept_link": "y", "expires_at": "z"})
    db.add_email(users[0], template_key="password_reset", status="sent")
    db.add_reset_token(users[1])
    now = datetime.now(UTC)
    for _ in range(3):
        db.add_audit(org_id=org_id, action="tool.call", actor_user_id=users[1])
    db.add_audit(
        org_id=org_id,
        action="login.success",
        actor_user_id=users[0],
        occurred_at=now - timedelta(days=400),
        ip=_IP,
    )
    for action in ("org.create", "org.deletion_schedule"):
        db.add_audit(
            org_id=org_id,
            action=action,
            actor_kind="super_admin",
            actor_user_id=super_admin,
            target_type="organization",
            target_ids=(org_id,),
        )
    db.add_audit(
        org_id=org_id,
        action="org.limits_change",
        actor_kind="operator",
        target_type="organization",
        target_ids=(org_id,),
    )
    directory = root / str(org_id)
    (directory / "chats" / "c1").mkdir(parents=True)
    (directory / "empty").mkdir()
    (directory / "a.txt").write_bytes(b"contract draft " + org_id.bytes)
    (directory / "chats" / "c1" / "b.bin").write_bytes(os.urandom(64))
    return users


_POPULATED_AUDIT_EVENTS = 7


def _org_content(db: FakeDb, org_id: uuid.UUID) -> dict[str, Any]:
    """Everything the database holds for one org."""
    user_ids = {user_id for user_id, row in db.users.items() if row["org_id"] == org_id}
    return copy.deepcopy(
        {
            "org": db.orgs.get(org_id),
            "users": {user_id: db.users[user_id] for user_id in user_ids},
            "sessions": {k: v for k, v in db.sessions.items() if v["user_id"] in user_ids},
            "invitations": {k: v for k, v in db.invitations.items() if v["user_id"] in user_ids},
            "outbox": [row for row in db.outbox if row["user_id"] in user_ids],
            "tokens": {k: v for k, v in db.tokens.items() if k in user_ids},
            "audit": [row for row in db.audit if row["org_id"] == org_id],
        }
    )


def _files(directory: Path) -> dict[Path, bytes]:
    return {path: path.read_bytes() for path in sorted(directory.rglob("*")) if path.is_file()}


def _due(db: FakeDb, org_id: uuid.UUID | None = None, **fields: Any) -> uuid.UUID:
    """A pending_deletion org whose purge date passed a minute ago."""
    now = datetime.now(UTC)
    values: dict[str, Any] = {
        "deletion_requested_at": now - timedelta(days=30, minutes=1),
        "purge_after": now - timedelta(minutes=1),
    }
    values.update(fields)
    return db.add_org(org_id, status="pending_deletion", **values)


# GH-220: a DELETE on organizations anywhere in a statement (normalized SQL) or in
# the module's source. Only the owner-run purge_org_audit_events deletes the row.
_ORG_DELETE_RE = r'\bdelete from (?:only )?(?:public\.)?"?organizations\b'
_ORG_DELETE_SOURCE_RE = r'\bdelete\s+from\s+(?:only\s+)?(?:public\s*\.\s*)?"?organizations\b'


def _locks_the_org(call: Call, org_id: uuid.UUID) -> bool:
    """Whether the call reads the org's organizations row FOR UPDATE."""
    return (
        re.search(r"\bfrom organizations\b", call.normalized) is not None
        and re.search(r"\bfor (?:no key )?update\b", call.normalized) is not None
        and org_id in _bound_ids(call)
    )


@pytest.fixture()
def world(db: FakeDb, root: Path) -> _World:
    """One due org, plus an active, a deactivated and a pending-but-not-due org with the
    same content, Super Admins, platform audit events and files under the root."""
    super_admin = db.add_account(kind="super_admin", role=None)
    super_admin_token = db.open_session(super_admin)
    due = _due(db)
    active = db.add_org(OTHER_ORG_ID)
    deactivated = db.add_org(status="deactivated")
    not_due = db.add_org(status="pending_deletion")
    due_users = _populate(db, due, root, super_admin)
    for org_id in (active, deactivated, not_due):
        _populate(db, org_id, root, super_admin)
    db.add_account(kind="super_admin", role=None)
    platform_events = [
        db.add_audit(
            org_id=None,
            action="audit.purge",
            actor_kind="system",
            metadata={"retention_months": 12, "purged_count": 3},
        ),
        db.add_audit(org_id=None, action="login.success", actor_kind="super_admin"),
        db.add_audit(
            org_id=None,
            action="org.purge",
            actor_kind="system",
            target_type="organization",
            target_ids=(uuid.uuid4(),),
            metadata={"users_purged": 2, "audit_events_purged": 5},
        ),
    ]
    (root / "README.txt").write_bytes(b"attachments root")
    (root / f"{due}-old").mkdir()
    (root / f"{due}-old" / "keep.txt").write_bytes(b"not the org's directory")
    kept_orgs = [active, deactivated, not_due]
    return _World(
        due=due,
        kept_orgs=kept_orgs,
        due_users=due_users,
        due_audit_count=_POPULATED_AUDIT_EVENTS,
        super_admin=super_admin,
        super_admin_token=super_admin_token,
        platform_events=platform_events,
        snapshots={org_id: _org_content(db, org_id) for org_id in kept_orgs},
        kept_files={
            path: data for path, data in _files(root).items() if str(due) not in path.parts
        },
    )


class TestPurgeCompleteness:
    """Everything of the due org goes; everything else stays."""

    async def test_organizations_purge_returns_the_number_purged(
        self, orgs: ModuleType, db: FakeDb, root: Path, world: _World
    ) -> None:
        assert await _purge(orgs, db, root) == 1

    async def test_organizations_purge_removes_the_org_row_and_its_users(
        self, orgs: ModuleType, db: FakeDb, root: Path, world: _World
    ) -> None:
        """Users of every status (active, invited, deactivated, soft-deleted)."""
        await _purge(orgs, db, root)

        assert world.due not in db.orgs
        assert not any(row["org_id"] == world.due for row in db.users.values())
        assert not set(world.due_users) & set(db.users)

    async def test_organizations_purge_removes_what_cascades_from_the_users(
        self, orgs: ModuleType, db: FakeDb, root: Path, world: _World
    ) -> None:
        """Sessions, invitations, queued and sent emails and reset tokens."""
        await _purge(orgs, db, root)

        gone = set(world.due_users)
        assert not any(row["user_id"] in gone for row in db.sessions.values())
        assert not any(row["user_id"] in gone for row in db.invitations.values())
        assert not any(row["user_id"] in gone for row in db.outbox)
        assert not gone & set(db.tokens)

    async def test_organizations_purge_removes_every_audit_event_of_the_org(
        self, orgs: ModuleType, db: FakeDb, root: Path, world: _World
    ) -> None:
        """Old ones and the Super Admin's and operator's actions on it included."""
        await _purge(orgs, db, root)

        assert not any(row["org_id"] == world.due for row in db.audit)

    async def test_organizations_purge_removes_the_orgs_directory(
        self, orgs: ModuleType, db: FakeDb, root: Path, world: _World
    ) -> None:
        await _purge(orgs, db, root)

        assert not os.path.lexists(root / str(world.due))

    async def test_organizations_purge_keeps_other_orgs(
        self, orgs: ModuleType, db: FakeDb, root: Path, world: _World
    ) -> None:
        """An active, a deactivated and a pending-but-not-due org are untouched."""
        await _purge(orgs, db, root)

        for org_id in world.kept_orgs:
            assert _org_content(db, org_id) == world.snapshots[org_id], org_id

    async def test_organizations_purge_keeps_platform_events_and_super_admins(
        self, orgs: ModuleType, db: FakeDb, root: Path, world: _World
    ) -> None:
        await _purge(orgs, db, root)

        ids = {row["id"] for row in db.audit}
        assert set(world.platform_events) <= ids
        assert world.super_admin in db.users
        assert not db.session_revoked(world.super_admin_token)
        assert sum(1 for row in db.users.values() if row["kind"] == "super_admin") == 2

    async def test_organizations_purge_keeps_other_files(
        self, orgs: ModuleType, db: FakeDb, root: Path, world: _World
    ) -> None:
        """Other orgs' directories, a lookalike directory name and files directly under
        the root are untouched."""
        await _purge(orgs, db, root)

        assert _files(root) == world.kept_files

    async def test_organizations_purge_records_one_platform_event(
        self, orgs: ModuleType, db: FakeDb, root: Path, world: _World
    ) -> None:
        """org.purge: the system, no org (it outlives it), target the org, exact counts,
        no IP."""
        before = {row["id"] for row in db.audit}

        await _purge(orgs, db, root)

        row = _one([row for row in db.audit if row["id"] not in before])
        assert row["action"] == "org.purge"
        assert (row["actor_kind"], row["actor_user_id"], row["org_id"]) == ("system", None, None)
        assert (row["target_type"], row["target_ids"]) == ("organization", [str(world.due)])
        assert row["ip"] is None
        assert row["metadata"] == {
            "users_purged": len(world.due_users),
            "audit_events_purged": world.due_audit_count,
        }

    async def test_organizations_purge_deletes_audit_events_only_through_the_function(
        self, orgs: ModuleType, db: FakeDb, root: Path, world: _World
    ) -> None:
        """SELECT purge_org_audit_events($n) with the org's id; no DELETE on audit_events
        (the append-only trigger would refuse it)."""
        await _purge(orgs, db, root)

        call = _one(db.matching(r"\bpurge_org_audit_events\b"))
        assert _bound_ids(call) == [world.due]
        assert db.matching(r"\bdelete from audit_events\b") == []

    async def test_organizations_purge_runs_in_one_committed_transaction(
        self, orgs: ModuleType, db: FakeDb, root: Path, world: _World
    ) -> None:
        """GH-220 order, in one committed transaction: the org row locked FOR UPDATE, the
        org's users deleted, purge_org_audit_events (the audit events and the org row),
        then the org.purge record. The app itself issues no DELETE on organizations."""
        await _purge(orgs, db, root)

        function = _one(db.matching(r"\bpurge_org_audit_events\b"))
        assert function.tx is not None
        same_tx = [
            (index, call)
            for index, call in enumerate(db.calls)
            if (call.via, call.tx) == (function.via, function.tx)
        ]
        locks = [index for index, call in same_tx if _locks_the_org(call, world.due)]
        assert locks, "the org row is never locked"
        users_index, users = _one(
            [
                (index, call)
                for index, call in same_tx
                if call.normalized.startswith("delete from users")
            ]
        )
        assert world.due in _bound_ids(users)
        record_index, _ = _one(
            [
                (index, call)
                for index, call in same_tx
                if call.normalized.startswith("insert into audit_events")
            ]
        )
        assert locks[0] < users_index < db.calls.index(function) < record_index
        assert (function.tx, "commit") in db.transactions
        assert db.matching(_ORG_DELETE_RE) == []

    async def test_organizations_purge_deletes_the_users_before_calling_the_function(
        self, orgs: ModuleType, db: FakeDb, root: Path, world: _World
    ) -> None:
        """users.org_id is ON DELETE RESTRICT and the function deletes the org row, so
        DELETE FROM users (bound to the due org) runs before purge_org_audit_events."""
        await _purge(orgs, db, root)

        users = _one(db.matching(r"^delete from users\b"))
        function = _one(db.matching(r"\bpurge_org_audit_events\b"))
        assert world.due in _bound_ids(users)
        assert db.calls.index(users) < db.calls.index(function)

    async def test_organizations_purge_org_row_is_deleted_by_the_function_only(
        self,
        orgs: ModuleType,
        db: FakeDb,
        root: Path,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The org row still exists when purge_org_audit_events is called and is gone
        when it returns; no statement of the app deletes an organizations row (the
        runtime role has no DELETE on the table, migration 0019)."""
        seen: list[tuple[bool, bool]] = []
        handle = db.handle

        def probe(method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None) -> Any:
            if not re.search(r"\bpurge_org_audit_events\b", norm(sql)):
                return handle(method, sql, args, via, tx)
            existed = world.due in db.orgs
            result = handle(method, sql, args, via, tx)
            seen.append((existed, world.due in db.orgs))
            return result

        monkeypatch.setattr(db, "handle", probe)

        assert await _purge(orgs, db, root) == 1

        assert seen == [(True, False)]
        assert world.due not in db.orgs
        assert db.matching(_ORG_DELETE_RE) == []

    def test_organizations_source_has_no_org_delete_statement(self, orgs: ModuleType) -> None:
        """GH-220: organizations.py holds no DELETE on organizations (not even in a
        docstring: say "no DELETE on organizations") and no _DELETE_ORG_SQL constant."""
        source = inspect.getsource(orgs)

        assert re.search(_ORG_DELETE_SOURCE_RE, source, re.IGNORECASE) is None
        assert "_DELETE_ORG_SQL" not in source
        assert not hasattr(orgs, "_DELETE_ORG_SQL")

    async def test_organizations_purge_again_finds_nothing(
        self, orgs: ModuleType, db: FakeDb, root: Path, world: _World
    ) -> None:
        await _purge(orgs, db, root)
        after = _state(db)

        assert await _purge(orgs, db, root) == 0
        assert _state(db) == after


# ---------------------------------------------------------------------------
# 13. purge_due_orgs: which orgs are due
# ---------------------------------------------------------------------------


class TestPurgeSelection:
    """Only pending_deletion orgs whose purge_after has come."""

    async def test_organizations_purge_boundary_is_due(
        self, orgs: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """purge_after exactly now counts as due ("<= now()")."""
        org_id = db.add_org(status="pending_deletion", purge_after=_exactly_now())

        assert await _purge(orgs, db, root) == 1
        assert org_id not in db.orgs

    async def test_organizations_purge_never_touches_orgs_not_due(
        self, orgs: ModuleType, db: FakeDb, root: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Pending but not due yet, active, deactivated: nothing changes, no statement is
        bound to their ids (not even a lock) and nothing is logged as failed."""
        caplog.set_level(logging.DEBUG)
        ids = [
            db.add_org(
                status="pending_deletion", purge_after=datetime.now(UTC) + timedelta(minutes=1)
            ),
            db.add_org(),
            db.add_org(status="deactivated"),
        ]
        before = _state(db)

        assert await _purge(orgs, db, root) == 0

        assert _state(db) == before
        assert not any(set(ids) & set(_bound_ids(call)) for call in db.calls)
        assert _warnings(caplog) == []

    async def test_organizations_purge_every_due_org_in_its_own_transaction(
        self, orgs: ModuleType, db: FakeDb, root: Path
    ) -> None:
        first, second = _due(db), _due(db)

        assert await _purge(orgs, db, root) == 2

        assert first not in db.orgs
        assert second not in db.orgs
        calls = db.matching(r"\bpurge_org_audit_events\b")
        assert len(calls) == 2
        assert calls[0].tx != calls[1].tx

    async def test_organizations_purge_without_a_directory(
        self, orgs: ModuleType, db: FakeDb, root: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A missing directory is fine: the org is purged, nothing is logged as failed."""
        caplog.set_level(logging.DEBUG)
        org_id = _due(db)

        assert await _purge(orgs, db, root / "missing-root") == 1
        assert org_id not in db.orgs
        assert _warnings(caplog) == []

    async def test_organizations_purge_skips_an_org_cancelled_concurrently(
        self, orgs: ModuleType, db: FakeDb, root: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Cancelled between the lookup and the lock: the locked re-check skips it (no
        failure), nothing is deleted."""
        caplog.set_level(logging.DEBUG)
        org_id = _due(db)
        db.add_account(org_id=org_id)
        db.add_audit(org_id=org_id)
        (root / str(org_id)).mkdir()
        (root / str(org_id) / "keep.txt").write_bytes(b"kept")

        def cancel() -> None:
            db.add_org(org_id, status="deactivated")

        db.after_org_lookup = cancel

        assert await _purge(orgs, db, root) == 0

        assert db.orgs[org_id]["status"] == "deactivated"
        assert any(row["org_id"] == org_id for row in db.users.values())
        assert any(row["org_id"] == org_id for row in db.audit)
        assert db.audit_rows("org.purge") == []
        assert (root / str(org_id) / "keep.txt").read_bytes() == b"kept"
        assert _warnings(caplog) == []


# ---------------------------------------------------------------------------
# 14. purge_due_orgs: files, symlinks and the worker thread
# ---------------------------------------------------------------------------


class TestPurgeFiles:
    """The org's directory is removed in a worker thread, never following a symlink."""

    async def test_organizations_purge_removes_files_in_a_worker_thread(
        self, orgs: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """The directory disappears inside an asyncio.to_thread call."""
        org_id = _due(db)
        directory = root / str(org_id)
        (directory / "nested").mkdir(parents=True)
        (directory / "nested" / "f.txt").write_bytes(b"x")
        real_to_thread = asyncio.to_thread
        observed: list[tuple[bool, bool]] = []

        async def spy(func: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
            existed = os.path.lexists(directory)
            result = await real_to_thread(func, *args, **kwargs)
            observed.append((existed, os.path.lexists(directory)))
            return result

        with patch("admino.organizations.asyncio.to_thread", spy):
            assert await _purge(orgs, db, root) == 1

        assert (True, False) in observed

    async def test_organizations_purge_symlinked_directory_removes_only_the_link(
        self, orgs: ModuleType, db: FakeDb, root: Path, tmp_path: Path
    ) -> None:
        """<root>/<org_id> is a symlink: the link goes, its target is never followed."""
        org_id = _due(db)
        target = tmp_path / "elsewhere"
        (target / "inner").mkdir(parents=True)
        (target / "keep.txt").write_bytes(b"not the org's")
        (target / "inner" / "deep.txt").write_bytes(b"not the org's either")
        (root / str(org_id)).symlink_to(target, target_is_directory=True)
        kept = _files(target)

        assert await _purge(orgs, db, root) == 1

        assert not os.path.lexists(root / str(org_id))
        assert _files(target) == kept
        assert org_id not in db.orgs

    async def test_organizations_purge_symlink_inside_the_directory_is_not_followed(
        self, orgs: ModuleType, db: FakeDb, root: Path, tmp_path: Path
    ) -> None:
        org_id = _due(db)
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_bytes(b"outside the org")
        directory = root / str(org_id)
        directory.mkdir()
        (directory / "own.txt").write_bytes(b"the org's")
        (directory / "link").symlink_to(outside, target_is_directory=True)

        assert await _purge(orgs, db, root) == 1

        assert not os.path.lexists(directory)
        assert (outside / "keep.txt").read_bytes() == b"outside the org"


# ---------------------------------------------------------------------------
# 15. purge_due_orgs: failures roll one org back
# ---------------------------------------------------------------------------


def _small_org(db: FakeDb, root: Path) -> uuid.UUID:
    """A due org with a user, a session, an audit event and a file."""
    org_id = _due(db)
    user_id = db.add_account(org_id=org_id, role="org_admin")
    db.open_session(user_id)
    db.add_audit(org_id=org_id, actor_user_id=user_id)
    (root / str(org_id) / "sub").mkdir(parents=True)
    (root / str(org_id) / "sub" / "file.txt").write_bytes(b"org file")
    return org_id


def _user_joins_after_the_users_delete(
    db: FakeDb, org_id: uuid.UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Add a user to the org right after the first DELETE FROM users has run (a race the
    test injects), so purge_org_audit_events still finds a user naming the org."""
    handle = db.handle
    joined: list[uuid.UUID] = []

    def joining(method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None) -> Any:
        result = handle(method, sql, args, via, tx)
        if not joined and norm(sql).startswith("delete from users"):
            joined.append(db.add_account(org_id=org_id, role="editor"))
        return result

    monkeypatch.setattr(db, "handle", joining)


class TestPurgeFailures:
    """A failure rolls that org back entirely and is logged by class name only."""

    @pytest.mark.parametrize(
        "pattern",
        [
            pytest.param(r"\bpurge_org_audit_events\b", id="audit-purge"),
            pytest.param(r"^delete from users\b", id="users-delete"),
        ],
    )
    async def test_organizations_purge_database_failure_keeps_rows_and_files(
        self, orgs: ModuleType, db: FakeDb, root: Path, pattern: str
    ) -> None:
        """Files are removed last: a failing database step never deletes a file. The
        injected failure is what rolled the org back (the step was reached). GH-220: no
        org-delete step any more, the function deletes the org row."""
        org_id = _small_org(db, root)
        before = _org_content(db, org_id)
        files = _files(root)
        db.fail_sql = pattern

        assert await _purge(orgs, db, root) == 0

        assert _org_content(db, org_id) == before
        assert _files(root) == files
        assert [outcome for _, outcome in db.transactions] == ["rollback:DeadlockDetectedError"]

    async def test_organizations_purge_function_refusing_a_remaining_user_rolls_back(
        self,
        orgs: ModuleType,
        db: FakeDb,
        root: Path,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A user still names the org when purge_org_audit_events runs (one joins right
        after the users DELETE): the function raises ForeignKeyViolationError and the
        org's whole transaction rolls back, the users DELETE included. The org, its
        users, audit rows and files are kept, nothing counts as purged, and the log
        names the class only."""
        caplog.set_level(logging.DEBUG)
        org_id = _small_org(db, root)
        before = _org_content(db, org_id)
        files = _files(root)
        _user_joins_after_the_users_delete(db, org_id, monkeypatch)

        assert await _purge(orgs, db, root) == 0

        assert _org_content(db, org_id) == before
        assert _files(root) == files
        assert db.audit_rows("org.purge") == []
        users = _one(db.matching(r"^delete from users\b"))
        function = _one(db.matching(r"\bpurge_org_audit_events\b"))
        assert users.tx is not None
        assert (users.via, users.tx) == (function.via, function.tx)
        assert db.calls.index(users) < db.calls.index(function)
        assert (function.tx, "rollback:ForeignKeyViolationError") in db.transactions
        assert any(
            "ForeignKeyViolationError" in record.getMessage() for record in _warnings(caplog)
        )
        _assert_no_leak(
            _log_text(caplog), org_id, "violates", "foreign key constraint", ORG_NAME, str(root)
        )

    async def test_organizations_purge_audit_failure_keeps_rows_and_files(
        self, orgs: ModuleType, db: FakeDb, root: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        org_id = _small_org(db, root)
        before = _org_content(db, org_id)
        files = _files(root)
        db.fail_audit = True

        assert await _purge(orgs, db, root) == 0

        assert _org_content(db, org_id) == before
        assert _files(root) == files
        assert any("AuditRecordError" in record.getMessage() for record in _warnings(caplog))

    async def test_organizations_purge_file_failure_rolls_the_org_back(
        self, orgs: ModuleType, db: FakeDb, root: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Removing the directory fails -> the database changes roll back (retried next
        run); the log names the class only, not the path or the org."""
        caplog.set_level(logging.DEBUG)
        org_id = _small_org(db, root)
        before = _org_content(db, org_id)
        path = str(root / str(org_id))

        async def failing(func: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
            raise PermissionError(13, "Permission denied", path)

        with patch("admino.organizations.asyncio.to_thread", failing):
            assert await _purge(orgs, db, root) == 0

        assert _org_content(db, org_id) == before
        assert db.audit_rows("org.purge") == []
        assert any("PermissionError" in record.getMessage() for record in _warnings(caplog))
        _assert_no_leak(_log_text(caplog), org_id, path, ORG_NAME)

    async def test_organizations_purge_one_failure_doesnt_stop_the_others(
        self, orgs: ModuleType, db: FakeDb, root: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The first org's org.purge record fails: it stays whole, the second is purged."""
        caplog.set_level(logging.DEBUG)
        failing, purged = _small_org(db, root), _small_org(db, root)
        before = _org_content(db, failing)
        db.fail_audit_when = lambda row: row["target_ids"] == [str(failing)]

        assert await _purge(orgs, db, root) == 1

        assert _org_content(db, failing) == before
        assert (root / str(failing) / "sub" / "file.txt").read_bytes() == b"org file"
        assert purged not in db.orgs
        assert not os.path.lexists(root / str(purged))
        assert _warnings(caplog)
        _assert_no_leak(_log_text(caplog), failing, purged, str(root))

    async def test_organizations_purge_file_failure_for_one_org_only(
        self, orgs: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """The first directory removal fails: exactly one org stays whole (rows and files),
        the other is purged."""
        first, second = _small_org(db, root), _small_org(db, root)
        snapshots = {org_id: _org_content(db, org_id) for org_id in (first, second)}
        real_to_thread = asyncio.to_thread
        calls = {"count": 0}

        async def fail_once(func: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
            calls["count"] += 1
            if calls["count"] == 1:
                raise OSError("disk trouble")
            return await real_to_thread(func, *args, **kwargs)

        with patch("admino.organizations.asyncio.to_thread", fail_once):
            assert await _purge(orgs, db, root) == 1

        survivors = [org_id for org_id in (first, second) if org_id in db.orgs]
        survivor = _one(survivors)
        other = second if survivor == first else first
        assert _org_content(db, survivor) == snapshots[survivor]
        assert (root / str(survivor) / "sub" / "file.txt").exists()
        assert not os.path.lexists(root / str(other))


# ---------------------------------------------------------------------------
# 16. #147's default organization
# ---------------------------------------------------------------------------


class TestDefaultOrgCleanup:
    """Migration 0011 schedules it for immediate purge; the purge removes it for good."""

    async def test_organizations_default_org_is_purged_with_its_audit_events(
        self, orgs: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """No organization row and no audit event with DEFAULT_ORG_ID remain: an upgraded
        install ends with 0 organizations."""
        now = datetime.now(UTC)
        db.add_org(
            _DEFAULT_ORG_ID,
            name="Default organization",
            seats=1,
            status="pending_deletion",
            deletion_requested_at=now,
            purge_after=now,
        )
        for _ in range(3):
            db.add_audit(org_id=_DEFAULT_ORG_ID, action="tool.call")

        assert await _purge(orgs, db, root) == 1

        assert db.orgs == {}
        assert not any(row["org_id"] == _DEFAULT_ORG_ID for row in db.audit)
        row = _one(db.audit_rows("org.purge"))
        assert row["target_ids"] == [str(_DEFAULT_ORG_ID)]
        assert row["metadata"] == {"users_purged": 0, "audit_events_purged": 3}


# ---------------------------------------------------------------------------
# 17. run_org_purge_job
# ---------------------------------------------------------------------------


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
    """Patch purge_due_orgs and asyncio.sleep as run_org_purge_job looks them up."""
    with (
        patch("admino.organizations.purge_due_orgs", purge),
        patch("admino.organizations.asyncio.sleep", sleep),
    ):
        yield


def _delay(call: Any) -> Any:
    return call.args[0] if call.args else call.kwargs["delay"]


class TestPurgeJob:
    """Purge now, then once per interval, until cancelled; failures don't stop it."""

    async def test_organizations_job_purges_then_sleeps_in_a_loop(self, orgs: ModuleType) -> None:
        events: list[str] = []

        async def fake_purge(*_args: Any, **_kwargs: Any) -> int:
            events.append("purge")
            return 0

        with (
            _patched_job(AsyncMock(side_effect=fake_purge), _cancelling_sleep(3, events)),
            pytest.raises(asyncio.CancelledError),
        ):
            await orgs.run_org_purge_job(MagicMock())

        assert events == ["purge", "sleep", "purge", "sleep", "purge", "sleep"]

    async def test_organizations_job_defaults_to_hourly_on_the_attachments_root(
        self, orgs: ModuleType
    ) -> None:
        pool = MagicMock()
        purge = AsyncMock(return_value=0)
        sleep = _cancelling_sleep(2)

        with _patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await orgs.run_org_purge_job(pool)

        assert [call.args[0] for call in purge.await_args_list] == [pool, pool]
        assert [call.kwargs["attachments_root"] for call in purge.await_args_list] == [
            orgs.ATTACHMENTS_ROOT,
            orgs.ATTACHMENTS_ROOT,
        ]
        assert [_delay(call) for call in sleep.await_args_list] == [3600, 3600]

    async def test_organizations_job_passes_root_and_interval_through(
        self, orgs: ModuleType, root: Path
    ) -> None:
        purge = AsyncMock(return_value=0)
        sleep = _cancelling_sleep(1)

        with _patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await orgs.run_org_purge_job(MagicMock(), attachments_root=root, interval_seconds=5)

        assert purge.await_args is not None
        assert purge.await_args.kwargs["attachments_root"] == root
        assert _delay(sleep.await_args_list[0]) == 5

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(lambda: RuntimeError("boom"), id="runtime-error"),
            pytest.param(lambda: OSError("disk"), id="os-error"),
            pytest.param(lambda: asyncpg.exceptions.RaiseError("refused"), id="postgres-error"),
            pytest.param(lambda: AuditRecordError(), id="audit-record-error"),
        ],
    )
    async def test_organizations_job_survives_a_failed_run(
        self, orgs: ModuleType, make_error: Callable[[], Exception]
    ) -> None:
        purge = AsyncMock(side_effect=[make_error(), 1])
        sleep = _cancelling_sleep(2)

        with _patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await orgs.run_org_purge_job(MagicMock())

        assert purge.await_count == 2

    async def test_organizations_job_logs_a_failure_by_class_name_only(
        self, orgs: ModuleType, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        marker = uuid.uuid4()
        error = RuntimeError(f"purge of {marker} under /app/data/attachments/{marker} failed")
        purge = AsyncMock(side_effect=error)

        with _patched_job(purge, _cancelling_sleep(1)), pytest.raises(asyncio.CancelledError):
            await orgs.run_org_purge_job(MagicMock())

        assert any("RuntimeError" in record.getMessage() for record in _warnings(caplog))
        _assert_no_leak(_log_text(caplog), marker, "/app/data/attachments")

    async def test_organizations_job_cancelled_run_propagates(self, orgs: ModuleType) -> None:
        """Cancellation during a run stops the job (it isn't a failed run)."""
        purge = AsyncMock(side_effect=asyncio.CancelledError)
        sleep = _cancelling_sleep(5)

        with _patched_job(purge, sleep), pytest.raises(asyncio.CancelledError):
            await orgs.run_org_purge_job(MagicMock())

        assert purge.await_count == 1
        sleep.assert_not_awaited()

    async def test_organizations_job_task_cancel_stops_it(self, orgs: ModuleType) -> None:
        sleeping = asyncio.Event()

        async def blocking_sleep(_delay: float) -> None:
            sleeping.set()
            await asyncio.Event().wait()

        purge = AsyncMock(return_value=0)
        with _patched_job(purge, AsyncMock(side_effect=blocking_sleep)):
            task = asyncio.create_task(orgs.run_org_purge_job(MagicMock()))
            async with asyncio.timeout(5):
                await sleeping.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        assert task.cancelled()

    async def test_organizations_job_purges_due_orgs_right_away(
        self, orgs: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """End to end on the fake: the first run, before any sleep, purges a due org."""
        org_id = _small_org(db, root)

        with (
            patch("admino.organizations.asyncio.sleep", _cancelling_sleep(1)),
            pytest.raises(asyncio.CancelledError),
        ):
            await orgs.run_org_purge_job(db.pool, attachments_root=root)

        assert org_id not in db.orgs
        assert not os.path.lexists(root / str(org_id))


# ---------------------------------------------------------------------------
# 18. No content in logs or audit rows
# ---------------------------------------------------------------------------


class TestNoContent:
    """Operator blindness: IDs, counts, bools and ints only; no names, emails or links."""

    async def _whole_lifecycle(self, orgs: ModuleType, db: FakeDb, root: Path) -> list[str]:
        """Create (with and without email), list, change, deactivate, reactivate,
        schedule, cancel, schedule again and purge; return the links handed out."""
        actor = _super_admin(db)
        before_ids = set(db.orgs)
        created = await _create(orgs, db, actor)
        other = await _create(
            orgs,
            db,
            _operator(),
            request=_request(name="Zweite Marker Treuhand", primary_admin_email="op@example.ch"),
            ip=None,
            queue_email=False,
        )
        org_id = created.organization.id
        assert org_id in set(db.orgs) - before_ids
        await orgs.list_orgs(db.pool, actor=actor)
        await _limits(orgs, db, actor, org_id, seats=3, monthly_budget_chf=Decimal("9.99"))
        await _residency(orgs, db, actor, enabled=False, org_id=org_id)
        for name in (
            "deactivate_org",
            "reactivate_org",
            "schedule_deletion",
            "cancel_deletion",
            "schedule_deletion",
        ):
            await _transition(orgs, db, name, actor, org_id)
        db.orgs[org_id]["purge_after"] = datetime.now(UTC) - timedelta(seconds=1)
        await _purge(orgs, db, root)
        return [created.accept_link, other.accept_link]

    async def test_organizations_logs_carry_no_content(
        self, orgs: ModuleType, db: FakeDb, root: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)

        links = await self._whole_lifecycle(orgs, db, root)

        tokens = [_link_token(link) for link in links]
        _assert_no_leak(
            _log_text(caplog),
            _NEW_NAME,
            "Zweite Marker",
            _ADMIN_EMAIL,
            "op@example.ch",
            *links,
            *tokens,
        )

    async def test_organizations_audit_rows_carry_no_content(
        self, orgs: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """Every row: no name, email, token or link; metadata values are ints, bools or
        IDs (plus the role token)."""
        links = await self._whole_lifecycle(orgs, db, root)

        tokens = [_link_token(link) for link in links]
        stored = json.dumps(db.audit, default=str)
        _assert_no_leak(
            stored, _NEW_NAME, "Zweite Marker", _ADMIN_EMAIL, "op@example.ch", *links, *tokens
        )
        uuid_re = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        for row in db.audit:
            for value in row["metadata"].values():
                assert (
                    type(value) in {int, bool}
                    or value == "org_admin"
                    or (isinstance(value, str) and uuid_re.fullmatch(value))
                ), (row["action"], value)
