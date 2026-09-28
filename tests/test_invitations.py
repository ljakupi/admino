"""Tests for admino.invitations — invitations and the first Org Admin (GH-153).

An Org Admin invites people into their org (``create_invitation``), lists the
pending invitations (``list_invitations``), revokes one (``revoke_invitation``)
or sends it again with a new link (``resend_invitation``). The invitee opens
the link (``get_invitation``: the org name, the role and the email) and
accepts it with a name and a password (``accept_invitation``), which
activates the account and opens a session. A Super Admin invites the first
Org Admin of an empty org (``invite_first_org_admin``, for #154). The request
and response models live in ``admino.models``.

What these tests pin down:
- Models: ``InvitationCreateRequest`` (email stripped, 3 to 254 characters, no
  whitespace or control characters, one '@' after a non-empty local part, a
  '.' inside the domain; a member role; nothing else), ``InvitationSummary``
  (id, email, role, sent_at, expires_at, expired), ``InvitationListResponse``,
  ``InvitationDetails`` (exactly org_name, role, email) and
  ``InvitationAcceptRequest`` (a stripped name of 1 to 120 characters without
  control, format or line/paragraph separator characters; a SecretStr
  password of 1 to 1024 characters; nothing else).
- Sending (one transaction): the org row is locked FOR UPDATE, the seats are
  counted (active and invited users of the org, expired invitations included,
  deactivated and deleted users not), and a full org raises ``SeatLimitError``
  before anything is inserted; then an invited ``users`` row (no name, no
  password, the inviting admin's language), an ``invitations`` row holding the
  SHA-256 of a ``secrets.token_urlsafe(32)`` token with ``expires_at = now() +
  72 hours`` on the database clock, the ``invitation`` email through the outbox
  (org name, ``{public_url}/accept-invitation#token=<token>``, the expiry) and
  an ``invitation.create`` audit event. An email that exists anywhere on the
  platform (any capitalization, any status, a Super Admin, a pending invitation)
  raises ``accounts.DuplicateEmailError`` and nothing is written.
- Listing: the pending invitations of the caller's org only, most recently
  sent first, each flagged ``expired``.
- Revoking deletes the invited users row (its invitation and queued email go
  with it), which frees the email and the seat; resending rotates the token,
  resets ``sent_at`` and the expiry, queues a new email and needs no free
  seat. Both answer ``InvitationNotFoundError`` for an unknown id, another
  org's invitation or an accepted one.
- Every link that can't be used (malformed, unknown, expired, used, revoked,
  rotated, an account no longer invited, an org that isn't active) raises the
  one ``InvalidInvitationError``; a malformed one without any query.
- Accepting checks the link, then the password policy against the
  invitation's email (a refusal writes nothing and keeps the link usable),
  hashes the password in a worker thread, and then in one transaction marks the
  invitation used (atomically: single use), activates the user with the name
  and hash, stamps ``last_login_at``, opens a session with the org's policy and
  records ``invitation.accept``; it returns an ``auth.LoginResult``.
- The first Org Admin: only a Super Admin (``org.create``), only into an
  existing org without any users row, always the ``org_admin`` role, audited as
  the Super Admin in that org.
- Authorization through ``admino.access.can`` (``org.users.invite`` /
  ``org.users.view``) before any query; tenant isolation by the actor's org.

All database calls go to the in-memory fake of tests/db_fakes.py; Argon2 is a
fast spy. No real PostgreSQL, no SMTP.

Security notes:
- The raw token lives only in the queued email's link: never in a table, a
  statement, an audit row, an error or a log line.
- Content-free audit and logs: IDs, roles and the IP only; never an email,
  name, password, token or link.
- Fail closed: a failed audit write rolls the whole change back.
"""

from __future__ import annotations

import copy
import inspect
import json
import logging
import re
import threading
import traceback
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest
from asyncpg.pgproto.pgproto import UUID as PgUUID  # noqa: N811
from pydantic import SecretStr, ValidationError

from admino import accounts, auth, models, passwords
from admino import sessions as sessions_mod
from admino.access import Principal
from admino.audit_events import AuditRecordError
from tests.db_fakes import (
    INVITE_LINK_PREFIX,
    NOW_SQL,
    ORG_ID,
    ORG_NAME,
    OTHER_ORG_ID,
    OTHER_ORG_NAME,
    PUBLIC_URL,
    TOKEN_RE,
    Call,
    FakeDb,
    fake_hash,
    plain,
    sha256,
)

if TYPE_CHECKING:
    from types import ModuleType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP = "203.0.113.7"
_UA = "pytest-browser/1.0 (invite-ua-marker)"
_EMAIL = "Ada.Invitee.Marker@Example.ch"
_NAME = "Ada Lovelace"
_PASSWORD = "violet-Anchor-93-quartz"
_OTHER_PASSWORD = "Tidal-Lantern-58-cobalt"
_INVALID_MESSAGE = "This invitation link is invalid or has expired."
_NOT_FOUND_MESSAGE = "Invitation not found"
_SEAT_MESSAGE = "The organization has no free seats."
_DUPLICATE_MESSAGE = "A user with this email already exists."
_DELETED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_WELL_FORMED_UNKNOWN = "Q" * 21 + "-" + "z" * 20 + "_"
_ROLES = ["org_admin", "editor", "viewer"]
_NOT_ADMINS = ["editor", "viewer", "super_admin"]


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def inv() -> ModuleType:
    """admino.invitations, imported per test so each test fails on its own until it exists."""
    from admino import invitations

    return invitations


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database."""
    return FakeDb()


class _HashSpy:
    """Replaces passwords.hash_password with a fast fake; records each call and its thread."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[str] = []
        self.threads: list[int] = []

        def spy(password: str) -> str:
            self.calls.append(password)
            self.threads.append(threading.get_ident())
            return fake_hash(password)

        monkeypatch.setattr(passwords, "hash_password", spy)


@pytest.fixture(autouse=True)
def hash_spy(monkeypatch: pytest.MonkeyPatch) -> _HashSpy:
    """Argon2 is replaced by a fast spy in every test of this module."""
    return _HashSpy(monkeypatch)


class _ExactlyNow(datetime):
    """An aware datetime that equals "now" whenever it is compared or subtracted.

    Stored as an invitation's ``expires_at``, it behaves as if the invitation
    expired at exactly the instant the code reads its clock, whatever clock it
    reads: ==, <= and >= are True; <, > and != are False; the difference is zero.
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


def _admin(db: FakeDb, org_id: uuid.UUID = ORG_ID, **fields: Any) -> Principal:
    """An active Org Admin of the org."""
    return _principal(db, db.add_account(role="org_admin", org_id=org_id, **fields))


def _super_admin(db: FakeDb) -> Principal:
    return _principal(db, db.add_account(kind="super_admin", role=None))


def _actor(db: FakeDb, who: str) -> Principal:
    """A Super Admin, or an active member of ORG_ID with the given role."""
    if who == "super_admin":
        return _super_admin(db)
    return _principal(db, db.add_account(role=who))


async def _create(
    inv: ModuleType,
    db: FakeDb,
    actor: Principal,
    *,
    email: str = _EMAIL,
    role: str = "editor",
    language: str = "de",
    public_url: str = PUBLIC_URL,
) -> Any:
    return await inv.create_invitation(
        db.pool,
        actor=actor,
        email=email,
        role=role,
        language=language,
        public_url=public_url,
        ip=_IP,
    )


async def _accept(
    inv: ModuleType,
    db: FakeDb,
    token: str,
    *,
    name: str = _NAME,
    password: str = _PASSWORD,
) -> Any:
    return await inv.accept_invitation(
        db.pool, token=token, name=name, password=password, ip=_IP, user_agent=_UA
    )


async def _resend(inv: ModuleType, db: FakeDb, actor: Principal, invitation_id: Any) -> Any:
    return await inv.resend_invitation(
        db.pool, actor=actor, invitation_id=invitation_id, public_url=PUBLIC_URL, ip=_IP
    )


async def _revoke(inv: ModuleType, db: FakeDb, actor: Principal, invitation_id: Any) -> None:
    await inv.revoke_invitation(db.pool, actor=actor, invitation_id=invitation_id, ip=_IP)


async def _first(
    inv: ModuleType, db: FakeDb, actor: Principal, org_id: uuid.UUID, email: str = _EMAIL
) -> Any:
    return await inv.invite_first_org_admin(
        db.pool,
        actor=actor,
        org_id=org_id,
        email=email,
        language="fr",
        public_url=PUBLIC_URL,
        ip=_IP,
    )


def _invited_id(db: FakeDb, email: str = _EMAIL) -> uuid.UUID:
    """The id of the users row with this email."""
    row = db.user_by_email(email)
    assert row is not None, email
    return uuid.UUID(int=row["id"].int)


def _invitation(db: FakeDb, email: str = _EMAIL) -> dict[str, Any]:
    """The invitations row of the user with this email."""
    row = db.invitation_of(_invited_id(db, email))
    assert row is not None, email
    return row


def _age(db: FakeDb, invitation_id: Any, by: timedelta) -> None:
    """Move an invitation back in time: created_at, sent_at and expires_at together (the
    CHECKs still hold)."""
    row = db.invitations[plain(invitation_id)]
    for column in ("created_at", "sent_at", "expires_at"):
        row[column] -= by


def _expire(db: FakeDb, invitation_id: Any) -> None:
    """An invitation sent 73 hours ago: it expired an hour ago."""
    _age(db, invitation_id, timedelta(hours=73))


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


def _assert_only_refusal_audited(
    db: FakeDb,
    before: dict[str, Any],
    *,
    actor_kind: str,
    actor_user_id: Any,
    org_id: Any,
    role: str,
    reason: str,
) -> None:
    """Every table is unchanged except audit_events, which gained exactly one content-free
    invitation.refuse row (GH-153 security follow-up: probing is visible in the org's log)."""
    after = _state(db)
    audit_before = before.pop("audit")
    audit_after = after.pop("audit")
    assert after == before
    assert audit_after[: len(audit_before)] == audit_before
    added = audit_after[len(audit_before) :]
    assert len(added) == 1, added
    row = added[0]
    assert row["action"] == "invitation.refuse"
    assert row["actor_kind"] == actor_kind
    assert plain(row["actor_user_id"]) == plain(actor_user_id)
    assert plain(row["org_id"]) == plain(org_id)
    assert row["target_type"] is None
    assert row["target_ids"] == []
    assert row["metadata"] == {"role": role, reason: True}


def _one(calls: list[Call]) -> Call:
    assert len(calls) == 1, calls
    return calls[0]


def _text(value: Any) -> str:
    """A bind argument as text, for leak checks."""
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("latin-1")
    return value if isinstance(value, str) else repr(value)


def _split_top_level(text: str) -> list[str]:
    """Split at commas outside parentheses."""
    items: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            items.append(text[start:index].strip())
            start = index + 1
    items.append(text[start:].strip())
    return items


def _insert_expression(call: Call, column: str) -> str:
    """The VALUES expression an INSERT gives a column."""
    match = re.search(r"insert into \w+ ?\(([^)]*)\) ?values ?\((.*)\)", call.normalized)
    assert match is not None, call.normalized
    columns = [name.strip() for name in match.group(1).split(",")]
    expressions = _split_top_level(match.group(2))
    assert column in columns, call.normalized
    return expressions[columns.index(column)]


def _bound_interval(call: Call, expression: str) -> Any:
    """The value bound to ``now() + $n::interval`` (the expression must be exactly that)."""
    match = re.fullmatch(rf"\(?{NOW_SQL} ?\+ ?\$(\d+) ?:: ?interval\)?", expression)
    assert match is not None, f"not computed on the database clock: {expression}"
    return call.args[int(match.group(1)) - 1]


# ---------------------------------------------------------------------------
# 1. The models
# ---------------------------------------------------------------------------

_LONGEST_EMAIL = "a" * (254 - len("@example.ch")) + "@example.ch"


class TestInvitationModels:
    """The request and response models in admino.models."""

    def test_invitations_create_request_has_exactly_email_and_role(self) -> None:
        assert set(models.InvitationCreateRequest.model_fields) == {"email", "role"}

    @pytest.mark.parametrize(
        ("email", "expected"),
        [
            pytest.param("ada@example.ch", "ada@example.ch", id="plain"),
            pytest.param("Ada.Lovelace@Example.CH", "Ada.Lovelace@Example.CH", id="case-kept"),
            pytest.param("x@y.z", "x@y.z", id="short"),
            pytest.param("first.last+tag@sub.example.co.uk", None, id="plus-and-subdomains"),
            pytest.param("  padded@example.ch\t", "padded@example.ch", id="stripped"),
            pytest.param(_LONGEST_EMAIL, None, id="254-chars"),
        ],
    )
    def test_invitations_create_request_accepts_valid_email(
        self, email: str, expected: str | None
    ) -> None:
        """A valid email passes; surrounding whitespace is stripped, capitalization kept."""
        request = models.InvitationCreateRequest(email=email, role="editor")

        assert request.email == (expected or email)

    @pytest.mark.parametrize(
        "email",
        [
            pytest.param("", id="empty"),
            pytest.param("   ", id="whitespace-only"),
            pytest.param("a@b", id="no-dot-3-chars"),
            pytest.param("no-at-sign.example.ch", id="no-at"),
            pytest.param("@example.ch", id="empty-local-part"),
            pytest.param("a@b@example.ch", id="two-ats"),
            pytest.param("a@examplech", id="no-dot-in-domain"),
            pytest.param("a@.examplech", id="only-dot-first-in-domain"),
            pytest.param("a@examplech.", id="only-dot-last-in-domain"),
            pytest.param("a@", id="empty-domain"),
            pytest.param("new person@example.ch", id="space-inside"),
            pytest.param("new.person@exa\tmple.ch", id="tab-inside"),
            pytest.param("new.person@example.ch\nBcc: x@example.ch", id="newline-inside"),
            pytest.param("a" + chr(0) + "b@example.ch", id="nul"),
            pytest.param("a" + chr(0x7F) + "b@example.ch", id="del"),
            pytest.param("a" + chr(0xA0) + "b@example.ch", id="nbsp"),
            pytest.param("a" + chr(0x200B) + "b@example.ch", id="zero-width-space"),
            pytest.param("a" + chr(0x202E) + "b@example.ch", id="rtl-override"),
            pytest.param(chr(0xFEFF) + "ab@example.ch", id="bom"),
            pytest.param("a" + chr(0x2028) + "b@example.ch", id="line-separator"),
            pytest.param("a" + chr(0x2029) + "b@example.ch", id="paragraph-separator"),
            pytest.param("a" + chr(0xD800) + "b@example.ch", id="lone-surrogate"),
            pytest.param("a" + _LONGEST_EMAIL, id="255-chars"),
            pytest.param(123, id="int"),
            pytest.param(None, id="none"),
            pytest.param(["a@example.ch"], id="list"),
        ],
    )
    def test_invitations_create_request_rejects_malformed_email(self, email: Any) -> None:
        with pytest.raises(ValidationError):
            models.InvitationCreateRequest(email=email, role="editor")

    @pytest.mark.parametrize("role", _ROLES)
    def test_invitations_create_request_accepts_member_roles(self, role: str) -> None:
        assert models.InvitationCreateRequest(email="a@example.ch", role=role).role == role

    @pytest.mark.parametrize("role", ["super_admin", "admin", "Editor", "", None, 1, "owner"])
    def test_invitations_create_request_rejects_other_roles(self, role: Any) -> None:
        with pytest.raises(ValidationError):
            models.InvitationCreateRequest(email="a@example.ch", role=role)

    @pytest.mark.parametrize(
        "extra",
        [
            pytest.param({"org_id": str(OTHER_ORG_ID)}, id="org_id"),
            pytest.param({"name": "Ada"}, id="name"),
            pytest.param({"kind": "super_admin"}, id="kind"),
            pytest.param({"language": "fr"}, id="language"),
        ],
    )
    def test_invitations_create_request_refuses_unknown_fields(self, extra: dict[str, Any]) -> None:
        """The org and the language are never chosen by the request."""
        with pytest.raises(ValidationError):
            models.InvitationCreateRequest.model_validate(
                {"email": "a@example.ch", "role": "editor", **extra}
            )

    def test_invitations_summary_has_exactly_the_listed_fields(self) -> None:
        assert set(models.InvitationSummary.model_fields) == {
            "id",
            "email",
            "role",
            "sent_at",
            "expires_at",
            "expired",
        }

    def test_invitations_summary_id_is_a_plain_uuid(self) -> None:
        """An asyncpg UUID from a row becomes a plain uuid.UUID."""
        raw = uuid.uuid4()
        now = datetime.now(UTC)

        summary = models.InvitationSummary(
            id=PgUUID(str(raw)),
            email="a@example.ch",
            role="viewer",
            sent_at=now,
            expires_at=now + timedelta(hours=72),
            expired=False,
        )

        assert type(summary.id) is uuid.UUID
        assert summary.id == raw

    def test_invitations_list_response_has_only_invitations(self) -> None:
        assert set(models.InvitationListResponse.model_fields) == {"invitations"}

    def test_invitations_details_has_exactly_org_name_role_and_email(self) -> None:
        """The acceptance page gets the minimum: no ids, no dates, no token."""
        assert set(models.InvitationDetails.model_fields) == {"org_name", "role", "email"}

    def test_invitations_accept_request_has_exactly_name_and_password(self) -> None:
        assert set(models.InvitationAcceptRequest.model_fields) == {"name", "password"}

    def test_invitations_accept_request_refuses_unknown_fields(self) -> None:
        with pytest.raises(ValidationError):
            models.InvitationAcceptRequest.model_validate(
                {"name": _NAME, "password": _PASSWORD, "role": "org_admin"}
            )

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            pytest.param("Ada Lovelace", "Ada Lovelace", id="plain"),
            pytest.param("  Ada Lovelace \t", "Ada Lovelace", id="stripped"),
            pytest.param("Zoë Müller-Łukasiewicz", "Zoë Müller-Łukasiewicz", id="unicode"),
            pytest.param("a" * 120, "a" * 120, id="120-chars"),
            pytest.param("  " + "a" * 120 + "  ", "a" * 120, id="120-after-strip"),
            pytest.param("X", "X", id="one-char"),
        ],
    )
    def test_invitations_accept_request_accepts_valid_name(self, name: str, expected: str) -> None:
        request = models.InvitationAcceptRequest(name=name, password=_PASSWORD)

        assert request.name == expected

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("", id="empty"),
            pytest.param("   \t ", id="whitespace-only"),
            pytest.param("a" * 121, id="121-chars"),
            pytest.param("Ada" + chr(0) + "Lovelace", id="nul"),
            pytest.param("Ada\nLovelace", id="newline"),
            pytest.param("Ada\tLovelace", id="tab"),
            pytest.param("Ada" + chr(0x7F) + "Lovelace", id="del"),
            pytest.param("Ada" + chr(0x202E) + "Lovelace", id="rtl-override"),
            pytest.param("Ada" + chr(0x200B) + "Lovelace", id="zero-width-space"),
            pytest.param("Ada" + chr(0x2028) + "Lovelace", id="line-separator"),
            pytest.param("Ada" + chr(0x2029) + "Lovelace", id="paragraph-separator"),
            pytest.param(123, id="int"),
            pytest.param(None, id="none"),
        ],
    )
    def test_invitations_accept_request_rejects_bad_name(self, name: Any) -> None:
        with pytest.raises(ValidationError):
            models.InvitationAcceptRequest(name=name, password=_PASSWORD)

    def test_invitations_accept_request_password_is_secret(self) -> None:
        """The password is a SecretStr: repr() and str() never show it."""
        request = models.InvitationAcceptRequest(name=_NAME, password=_PASSWORD)

        assert isinstance(request.password, SecretStr)
        assert request.password.get_secret_value() == _PASSWORD
        assert _PASSWORD not in repr(request)
        assert _PASSWORD not in str(request)

    @pytest.mark.parametrize("password", ["x", "x" * 1024])
    def test_invitations_accept_request_password_bounds_accept(self, password: str) -> None:
        """1 to 1024 characters reach the service (the policy decides the rest)."""
        request = models.InvitationAcceptRequest(name=_NAME, password=password)

        assert request.password.get_secret_value() == password

    @pytest.mark.parametrize("password", ["", "x" * 1025, None, 123])
    def test_invitations_accept_request_password_bounds_refuse(self, password: Any) -> None:
        with pytest.raises(ValidationError):
            models.InvitationAcceptRequest(name=_NAME, password=password)


# ---------------------------------------------------------------------------
# 2. Constants and errors
# ---------------------------------------------------------------------------


class TestConstantsAndErrors:
    """The lifetime and the fixed, input-free error messages."""

    def test_invitations_lifetime_is_72_hours(self, inv: ModuleType) -> None:
        assert timedelta(hours=72) == inv.INVITATION_LIFETIME

    def test_invitations_messages(self, inv: ModuleType) -> None:
        assert inv.INVALID_INVITATION_MESSAGE == _INVALID_MESSAGE
        assert inv.INVITATION_NOT_FOUND_MESSAGE == _NOT_FOUND_MESSAGE
        assert inv.SEAT_LIMIT_MESSAGE == _SEAT_MESSAGE

    @pytest.mark.parametrize(
        ("name", "message"),
        [
            ("InvalidInvitationError", _INVALID_MESSAGE),
            ("InvitationNotFoundError", _NOT_FOUND_MESSAGE),
            ("SeatLimitError", _SEAT_MESSAGE),
        ],
    )
    def test_invitations_errors_carry_a_fixed_message(
        self, inv: ModuleType, name: str, message: str
    ) -> None:
        """Built without arguments, so they can't carry an input."""
        error = getattr(inv, name)()

        assert isinstance(error, Exception)
        assert str(error) == message

    @pytest.mark.parametrize("name", ["OrgHasUsersError", "OrgNotFoundError"])
    def test_invitations_first_admin_errors_exist(self, inv: ModuleType, name: str) -> None:
        assert isinstance(getattr(inv, name)(), Exception)


# ---------------------------------------------------------------------------
# 3. Sending an invitation
# ---------------------------------------------------------------------------


class TestCreateInvitation:
    """An Org Admin invites an email into their org."""

    async def test_invitations_create_inserts_an_invited_users_row(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """A member of the admin's org with the role, status invited, no name, no password,
        and the language the admin passed."""
        admin = _admin(db)

        await _create(inv, db, admin, role="viewer", language="fr")

        row = db.user_by_email(_EMAIL)
        assert row is not None
        assert (row["email"], row["kind"], row["org_id"], row["role"], row["status"]) == (
            _EMAIL,
            "member",
            ORG_ID,
            "viewer",
            "invited",
        )
        assert (row["name"], row["password_hash"], row["deleted_at"]) == (None, None, None)
        assert row["ui_language"] == "fr"

    async def test_invitations_create_stores_the_hash_of_a_256_bit_token(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """The invitations row holds sha256(token) (32 bytes) for a token_urlsafe(32) token;
        not accepted yet; it expires 72 hours after it was sent."""
        admin = _admin(db)
        before = datetime.now(UTC)

        await _create(inv, db, admin)

        token = db.invitation_token()
        invitation = _invitation(db)
        assert TOKEN_RE.fullmatch(token)
        assert invitation["token_hash"] == sha256(token)
        assert len(invitation["token_hash"]) == 32
        assert invitation["accepted_at"] is None
        assert invitation["expires_at"] - invitation["sent_at"] == timedelta(hours=72)
        assert before <= invitation["sent_at"] <= datetime.now(UTC)

    async def test_invitations_create_queues_the_invitation_email(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """One outbox row for the invitee: template invitation, in the language of the
        invited row, with the org name, the link and the expiry only."""
        admin = _admin(db)

        await _create(inv, db, admin, language="en")

        user_id = _invited_id(db)
        assert len(db.outbox) == 1
        email = db.outbox[0]
        assert (email["user_id"], email["template_key"], email["language"]) == (
            user_id,
            "invitation",
            "en",
        )
        assert set(email["params"]) == {"org_name", "accept_link", "expires_at"}
        assert email["params"]["org_name"] == ORG_NAME
        assert email["params"]["accept_link"] == INVITE_LINK_PREFIX + db.invitation_token()
        sent_expiry = datetime.fromisoformat(email["params"]["expires_at"])
        assert sent_expiry == _invitation(db)["expires_at"]

    async def test_invitations_create_link_uses_the_given_public_url(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """{public_url}/accept-invitation#token=<token>: the token in the fragment."""
        admin = _admin(db)

        await _create(inv, db, admin, public_url="https://app.example.org")

        link = db.outbox[0]["params"]["accept_link"]
        prefix = "https://app.example.org/accept-invitation#token="
        assert link.startswith(prefix)
        assert TOKEN_RE.fullmatch(link[len(prefix) :])
        assert _invitation(db)["token_hash"] == sha256(link[len(prefix) :])

    async def test_invitations_create_returns_the_summary(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """An InvitationSummary of the new invitation (a plain UUID id, not expired)."""
        admin = _admin(db)

        summary = await _create(inv, db, admin, role="viewer")

        invitation = _invitation(db)
        assert type(summary) is models.InvitationSummary
        assert type(summary.id) is uuid.UUID
        assert summary.id == invitation["id"]
        assert (summary.email, summary.role, summary.expired) == (_EMAIL, "viewer", False)
        assert (summary.sent_at, summary.expires_at) == (
            invitation["sent_at"],
            invitation["expires_at"],
        )

    @pytest.mark.parametrize("role", _ROLES)
    async def test_invitations_create_accepts_every_member_role(
        self, inv: ModuleType, db: FakeDb, role: str
    ) -> None:
        admin = _admin(db)

        summary = await _create(inv, db, admin, role=role)

        assert summary.role == role
        row = db.user_by_email(_EMAIL)
        assert row is not None
        assert row["role"] == role

    async def test_invitations_create_is_audited(self, inv: ModuleType, db: FakeDb) -> None:
        """One invitation.create row: the admin, their org, target the invitation, the IP,
        metadata {"role", "user_id"}."""
        admin = _admin(db)

        summary = await _create(inv, db, admin, role="viewer")

        assert len(db.audit) == 1
        row = _one_row(db.audit_rows("invitation.create"))
        assert (row["actor_kind"], row["actor_user_id"], row["org_id"]) == (
            "member",
            admin.user_id,
            ORG_ID,
        )
        assert (row["target_type"], row["target_ids"]) == ("invitation", [str(summary.id)])
        assert row["ip"] == _IP
        assert row["metadata"] == {"role": "viewer", "user_id": str(_invited_id(db))}

    async def test_invitations_create_writes_in_one_transaction(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """The users and invitations inserts, the queued email and the audit event share
        one connection and one committed transaction."""
        admin = _admin(db)

        await _create(inv, db, admin)

        users_insert = _one(db.matching(r"^insert into users\b"))
        writes = [
            users_insert,
            _one(db.matching(r"^insert into invitations\b")),
            _one(db.matching(r"^insert into email_outbox\b")),
            _one(db.matching(r"^insert into audit_events\b")),
        ]
        assert users_insert.tx is not None
        assert {(call.via, call.tx) for call in writes} == {(users_insert.via, users_insert.tx)}
        assert (users_insert.tx, "commit") in db.transactions

    async def test_invitations_create_locks_the_org_row_before_counting_and_inserting(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """SELECT ... FROM organizations ... FOR UPDATE of the admin's org, in the same
        transaction, before the seat count and before the users insert: two concurrent
        sends can't both take the last seat."""
        admin = _admin(db)

        await _create(inv, db, admin)

        users_insert = _one(db.matching(r"^insert into users\b"))
        tx = users_insert.tx
        locks = [
            index
            for index, call in enumerate(db.calls)
            if re.search(r"\bfrom organizations\b", call.normalized)
            and re.search(r"\bfor (?:no key )?update\b", call.normalized)
        ]
        assert locks, "the organizations row is never locked"
        lock = db.calls[locks[0]]
        assert (lock.via, lock.tx) == (users_insert.via, tx)
        assert ORG_ID in [plain(arg) for arg in lock.args if isinstance(arg, uuid.UUID)]
        counts = [
            index
            for index, call in enumerate(db.calls)
            if call.tx == tx
            and re.search(r"\bcount ?\(", call.normalized)
            and re.search(r"\bfrom users\b", call.normalized)
        ]
        assert counts, "the seats are never counted"
        assert locks[0] < min(counts)
        assert locks[0] < db.calls.index(users_insert)

    async def test_invitations_create_expiry_is_computed_on_the_database_clock(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """expires_at is now() + $n::interval with INVITATION_LIFETIME bound (the CHECK
        compares it with sent_at, on the same clock)."""
        admin = _admin(db)

        await _create(inv, db, admin)

        call = _one(db.matching(r"^insert into invitations\b"))
        interval = _bound_interval(call, _insert_expression(call, "expires_at"))
        assert interval == inv.INVITATION_LIFETIME

    async def test_invitations_create_never_stores_or_sends_the_raw_token_elsewhere(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """The raw token appears only in the queued email's link: in no statement text, no
        other bind argument, no table row and no audit row."""
        admin = _admin(db)

        await _create(inv, db, admin)

        token = db.invitation_token()
        for call in db.calls:
            assert token not in call.sql
            if call.normalized.startswith("insert into email_outbox"):
                continue  # the queued email carries the link
            for arg in call.args:
                assert token not in _text(arg), call.normalized
        for table in (db.users, db.orgs, db.invitations, db.sessions, db.tokens, db.audit):
            assert token not in repr(table)
        for row in db.outbox:
            others = {key: value for key, value in row.items() if key != "params"}
            assert token not in repr(others)
            params = {key: value for key, value in row["params"].items() if key != "accept_link"}
            assert token not in repr(params)

    async def test_invitations_create_tokens_differ_per_invitation(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        admin = _admin(db)

        await _create(inv, db, admin, email="first.person@example.ch")
        await _create(inv, db, admin, email="second.person@example.ch")

        first = db.invitation_token(_invited_id(db, "first.person@example.ch"))
        second = db.invitation_token(_invited_id(db, "second.person@example.ch"))
        assert first != second
        assert len({row["token_hash"] for row in db.invitations.values()}) == 2

    @pytest.mark.parametrize("who", _NOT_ADMINS)
    async def test_invitations_create_without_org_users_invite_is_refused_before_any_query(
        self, inv: ModuleType, db: FakeDb, who: str
    ) -> None:
        """An Editor, a Viewer and a Super Admin get PermissionError; nothing is read or
        written."""
        actor = _actor(db, who)

        with pytest.raises(PermissionError):
            await _create(inv, db, actor)

        assert db.calls == []
        assert (db.invitations, db.outbox, db.audit) == ({}, [], [])

    async def test_invitations_create_invites_into_the_actors_org(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """The org is always the admin's own: another org's admin invites into theirs."""
        admin = _admin(db, org_id=OTHER_ORG_ID)

        await _create(inv, db, admin)

        row = db.user_by_email(_EMAIL)
        assert row is not None
        assert row["org_id"] == OTHER_ORG_ID
        assert db.outbox[0]["params"]["org_name"] == OTHER_ORG_NAME
        assert db.audit_rows("invitation.create")[0]["org_id"] == OTHER_ORG_ID

    async def test_invitations_create_audit_failure_writes_nothing(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """Fail closed: the audit write fails → AuditRecordError, and no users row, no
        invitation and no queued email remain."""
        admin = _admin(db)
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _create(inv, db, admin)

        assert _state(db) == before
        assert db.transactions[-1][1] == "rollback:AuditRecordError"


def _one_row(rows: list[dict[str, Any]]) -> dict[str, Any]:
    assert len(rows) == 1, rows
    return rows[0]


# ---------------------------------------------------------------------------
# 4. An email that exists anywhere on the platform
# ---------------------------------------------------------------------------

_TAKEN = "taken.person@example.ch"
_TAKEN_CASES = [
    "active-other-org",
    "other-capitalization",
    "super-admin",
    "deactivated",
    "soft-deleted",
    "invited-elsewhere",
]


def _existing(db: FakeDb, case: str) -> None:
    """A users row that already holds _TAKEN (in some spelling)."""
    if case == "active-other-org":
        db.add_account(email=_TAKEN, org_id=OTHER_ORG_ID)
    elif case == "other-capitalization":
        db.add_account(email="TAKEN.Person@EXAMPLE.ch")
    elif case == "super-admin":
        db.add_account(email=_TAKEN, kind="super_admin", role=None)
    elif case == "deactivated":
        db.add_account(email=_TAKEN, status="deactivated")
    elif case == "soft-deleted":
        db.add_account(email=_TAKEN, deleted_at=_DELETED_AT)
    else:
        db.add_account(
            email=_TAKEN, org_id=OTHER_ORG_ID, status="invited", name=None, password_hash=None
        )


class TestDuplicateEmail:
    """The platform-wide, case-insensitive unique email refuses the send."""

    @pytest.mark.parametrize("case", _TAKEN_CASES)
    async def test_invitations_create_existing_email_is_refused(
        self, inv: ModuleType, db: FakeDb, case: str
    ) -> None:
        """accounts.DuplicateEmailError; no users row, invitation or email is written, only
        the content-free invitation.refuse audit row."""
        admin = _admin(db)
        _existing(db, case)
        before = _state(db)

        with pytest.raises(accounts.DuplicateEmailError):
            await _create(inv, db, admin, email=_TAKEN)

        _assert_only_refusal_audited(
            db,
            before,
            actor_kind="member",
            actor_user_id=admin.user_id,
            org_id=ORG_ID,
            role="editor",
            reason="email_taken",
        )

    async def test_invitations_create_pending_invitation_email_is_refused(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """An email with a pending invitation can't be invited twice (any capitalization)."""
        admin = _admin(db)
        await _create(inv, db, admin)
        before = _state(db)

        with pytest.raises(accounts.DuplicateEmailError):
            await _create(inv, db, admin, email=_EMAIL.upper(), role="viewer")

        _assert_only_refusal_audited(
            db,
            before,
            actor_kind="member",
            actor_user_id=admin.user_id,
            org_id=ORG_ID,
            role="viewer",
            reason="email_taken",
        )

    async def test_invitations_create_duplicate_rolls_the_transaction_back(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        admin = _admin(db)
        _existing(db, "active-other-org")

        with pytest.raises(accounts.DuplicateEmailError):
            await _create(inv, db, admin, email=_TAKEN)

        assert db.transactions[-1][1] == "rollback:DuplicateEmailError"

    async def test_invitations_create_duplicate_error_carries_no_email(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """The fixed message only; the driver's error (which repeats the email) doesn't
        travel with it, not even in the formatted traceback."""
        admin = _admin(db)
        _existing(db, "active-other-org")

        with pytest.raises(accounts.DuplicateEmailError) as caught:
            await _create(inv, db, admin, email=_TAKEN)

        assert str(caught.value) == _DUPLICATE_MESSAGE
        formatted = "".join(traceback.format_exception(caught.value)).lower()
        assert "taken.person" not in formatted

    async def test_invitations_create_refusal_is_audited_outside_the_rolled_back_transaction(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """The refused transaction rolls back; the invitation.refuse row is written after
        it, outside that transaction, so it survives."""
        admin = _admin(db)
        _existing(db, "active-other-org")

        with pytest.raises(accounts.DuplicateEmailError):
            await _create(inv, db, admin, email=_TAKEN)

        rolled_back = db.transactions[-1][0]
        refuse = _one(db.matching(r"^insert into audit_events\b"))
        assert refuse.tx != rolled_back
        assert [row["action"] for row in db.audit_rows()] == ["invitation.refuse"]

    async def test_invitations_create_refusal_audit_row_carries_no_email(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        admin = _admin(db)
        _existing(db, "active-other-org")

        with pytest.raises(accounts.DuplicateEmailError):
            await _create(inv, db, admin, email=_TAKEN)

        (row,) = db.audit_rows("invitation.refuse")
        assert "taken.person" not in json.dumps(row, default=str).lower()
        assert str(row["ip"]) == _IP

    async def test_invitations_create_refusal_audit_failure_raises(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """If the refusal can't be recorded, AuditRecordError propagates (the send is
        refused either way; nothing is written)."""
        admin = _admin(db)
        _existing(db, "active-other-org")
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _create(inv, db, admin, email=_TAKEN)

        assert _state(db) == before


# ---------------------------------------------------------------------------
# 5. The seat limit
# ---------------------------------------------------------------------------


class TestSeatLimit:
    """Active plus invited users of the org, plus the new one, must fit the seats."""

    async def test_invitations_seat_limit_last_free_seat_can_be_taken(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """3 seats, an admin and an editor: the third seat is free."""
        db.add_org(ORG_ID, seats=3)
        admin = _admin(db)
        db.add_account()

        summary = await _create(inv, db, admin)

        assert summary.id in db.invitations

    async def test_invitations_seat_limit_full_org_is_refused(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """2 seats, an admin and an editor: SeatLimitError, only the invitation.refuse audit
        row is written, and the users insert never ran (the count comes first)."""
        db.add_org(ORG_ID, seats=2)
        admin = _admin(db)
        db.add_account()
        before = _state(db)

        with pytest.raises(inv.SeatLimitError) as caught:
            await _create(inv, db, admin)

        assert str(caught.value) == _SEAT_MESSAGE
        _assert_only_refusal_audited(
            db,
            before,
            actor_kind="member",
            actor_user_id=admin.user_id,
            org_id=ORG_ID,
            role="editor",
            reason="seat_limit",
        )
        assert db.matching(r"^insert into users\b") == []
        assert db.transactions[-1][1] == "rollback:SeatLimitError"

    @pytest.mark.parametrize(
        "fields",
        [
            pytest.param({"status": "deactivated"}, id="deactivated"),
            pytest.param({"deleted_at": _DELETED_AT}, id="deleted-active"),
            pytest.param(
                {"status": "invited", "deleted_at": _DELETED_AT, "name": None},
                id="deleted-invited",
            ),
            pytest.param({"status": "deactivated", "deleted_at": _DELETED_AT}, id="deleted-deact"),
        ],
    )
    async def test_invitations_seat_limit_deactivated_and_deleted_users_dont_count(
        self, inv: ModuleType, db: FakeDb, fields: dict[str, Any]
    ) -> None:
        """2 seats, an admin and a deactivated or deleted user: a seat is free."""
        db.add_org(ORG_ID, seats=2)
        admin = _admin(db)
        db.add_account(**fields)

        summary = await _create(inv, db, admin)

        assert summary.id in db.invitations

    async def test_invitations_seat_limit_pending_invitations_count(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """2 seats, an admin and a pending invitation: full."""
        db.add_org(ORG_ID, seats=2)
        admin = _admin(db)
        await _create(inv, db, admin, email="first.person@example.ch")

        with pytest.raises(inv.SeatLimitError):
            await _create(inv, db, admin, email="second.person@example.ch")

        assert db.user_by_email("second.person@example.ch") is None

    async def test_invitations_seat_limit_expired_invitations_count(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """An expired invitation holds its seat until it is revoked (or accepted)."""
        db.add_org(ORG_ID, seats=2)
        admin = _admin(db)
        first = await _create(inv, db, admin, email="first.person@example.ch")
        _expire(db, first.id)

        with pytest.raises(inv.SeatLimitError):
            await _create(inv, db, admin, email="second.person@example.ch")

    async def test_invitations_seat_limit_accepted_invitations_count(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """An accepted invitation is an active user: it keeps the seat."""
        db.add_org(ORG_ID, seats=2)
        admin = _admin(db)
        await _create(inv, db, admin, email="first.person@example.ch")
        await _accept(inv, db, db.invitation_token())

        with pytest.raises(inv.SeatLimitError):
            await _create(inv, db, admin, email="second.person@example.ch")

    async def test_invitations_seat_limit_other_orgs_and_super_admins_dont_count(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """2 seats: users of another org and Super Admins leave the second seat free."""
        db.add_org(ORG_ID, seats=2)
        admin = _admin(db)
        for _ in range(3):
            db.add_account(org_id=OTHER_ORG_ID)
            db.add_account(kind="super_admin", role=None)

        summary = await _create(inv, db, admin)

        assert summary.id in db.invitations

    async def test_invitations_seat_limit_revoke_frees_the_seat(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID, seats=2)
        admin = _admin(db)
        first = await _create(inv, db, admin, email="first.person@example.ch")
        await _revoke(inv, db, admin, first.id)

        second = await _create(inv, db, admin, email="second.person@example.ch")

        assert list(db.invitations) == [second.id]


# ---------------------------------------------------------------------------
# 6. Listing
# ---------------------------------------------------------------------------


class TestListInvitations:
    """The pending invitations of the caller's org, most recently sent first."""

    async def test_invitations_list_is_the_orgs_pending_invitations_newest_first(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """Sent 1h, 3h and 2h ago → [1h, 2h, 3h]; an accepted invitation and another org's
        pending one are left out."""
        admin = _admin(db)
        first = await _create(inv, db, admin, email="first.person@example.ch")
        second = await _create(inv, db, admin, email="second.person@example.ch", role="viewer")
        third = await _create(inv, db, admin, email="third.person@example.ch", role="org_admin")
        _age(db, first.id, timedelta(hours=1))
        _age(db, second.id, timedelta(hours=3))
        _age(db, third.id, timedelta(hours=2))
        await _create(inv, db, admin, email="accepted.person@example.ch")
        await _accept(inv, db, db.invitation_token())
        await _create(inv, db, _admin(db, org_id=OTHER_ORG_ID), email="other.org@example.ch")

        result = await inv.list_invitations(db.pool, actor=admin)

        assert [summary.id for summary in result] == [first.id, third.id, second.id]
        assert all(type(summary) is models.InvitationSummary for summary in result)
        assert [(summary.email, summary.role) for summary in result] == [
            ("first.person@example.ch", "editor"),
            ("third.person@example.ch", "org_admin"),
            ("second.person@example.ch", "viewer"),
        ]

    async def test_invitations_list_flags_expired_invitations(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """An expired invitation is still listed (it holds a seat), flagged expired."""
        admin = _admin(db)
        live = await _create(inv, db, admin, email="live.person@example.ch")
        stale = await _create(inv, db, admin, email="stale.person@example.ch")
        _expire(db, stale.id)

        result = {
            summary.id: summary for summary in await inv.list_invitations(db.pool, actor=admin)
        }

        assert (result[live.id].expired, result[stale.id].expired) == (False, True)
        assert result[stale.id].expires_at == db.invitations[stale.id]["expires_at"]

    async def test_invitations_list_expiry_boundary_counts_as_expired(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """expires_at exactly now is expired (a live link needs expires_at > now)."""
        admin = _admin(db)
        summary = await _create(inv, db, admin)
        db.invitations[summary.id]["expires_at"] = _exactly_now()

        result = await inv.list_invitations(db.pool, actor=admin)

        assert [entry.expired for entry in result] == [True]

    async def test_invitations_list_of_an_org_without_invitations_is_empty(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        admin = _admin(db)
        await _create(inv, db, _admin(db, org_id=OTHER_ORG_ID))

        assert await inv.list_invitations(db.pool, actor=admin) == []

    @pytest.mark.parametrize("who", _NOT_ADMINS)
    async def test_invitations_list_without_org_users_view_is_refused_before_any_query(
        self, inv: ModuleType, db: FakeDb, who: str
    ) -> None:
        actor = _actor(db, who)

        with pytest.raises(PermissionError):
            await inv.list_invitations(db.pool, actor=actor)

        assert db.calls == []


# ---------------------------------------------------------------------------
# 7. Revoking
# ---------------------------------------------------------------------------


class TestRevokeInvitation:
    """Revoking deletes the invited account; its invitation and email go with it."""

    async def test_invitations_revoke_deletes_the_invited_account(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        admin = _admin(db)
        summary = await _create(inv, db, admin)
        user_id = _invited_id(db)

        await _revoke(inv, db, admin, summary.id)

        assert user_id not in db.users
        assert db.invitations == {}
        assert db.invitation_emails(user_id) == []

    async def test_invitations_revoke_is_audited(self, inv: ModuleType, db: FakeDb) -> None:
        """One invitation.revoke row: the admin, their org, target the invitation, the IP,
        metadata {"user_id"}."""
        admin = _admin(db)
        summary = await _create(inv, db, admin)
        user_id = _invited_id(db)

        await _revoke(inv, db, admin, summary.id)

        row = _one_row(db.audit_rows("invitation.revoke"))
        assert (row["actor_kind"], row["actor_user_id"], row["org_id"]) == (
            "member",
            admin.user_id,
            ORG_ID,
        )
        assert (row["target_type"], row["target_ids"]) == ("invitation", [str(summary.id)])
        assert row["ip"] == _IP
        assert row["metadata"] == {"user_id": str(user_id)}

    async def test_invitations_revoke_writes_in_one_transaction(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        admin = _admin(db)
        summary = await _create(inv, db, admin)
        db.calls.clear()

        await _revoke(inv, db, admin, summary.id)

        delete = _one(db.matching(r"^delete from users\b"))
        audit = _one(db.matching(r"^insert into audit_events\b"))
        assert delete.tx is not None
        assert (audit.via, audit.tx) == (delete.via, delete.tx)
        assert (delete.tx, "commit") in db.transactions

    async def test_invitations_revoke_makes_the_link_unusable(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        admin = _admin(db)
        summary = await _create(inv, db, admin)
        token = db.invitation_token()

        await _revoke(inv, db, admin, summary.id)

        with pytest.raises(inv.InvalidInvitationError):
            await inv.get_invitation(db.pool, token)
        with pytest.raises(inv.InvalidInvitationError):
            await _accept(inv, db, token)

    async def test_invitations_revoke_frees_the_email(self, inv: ModuleType, db: FakeDb) -> None:
        admin = _admin(db)
        summary = await _create(inv, db, admin)
        await _revoke(inv, db, admin, summary.id)

        again = await _create(inv, db, admin, role="viewer")

        assert list(db.invitations) == [again.id]

    async def test_invitations_revoke_works_on_an_expired_invitation(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        admin = _admin(db)
        summary = await _create(inv, db, admin)
        _expire(db, summary.id)

        await _revoke(inv, db, admin, summary.id)

        assert db.invitations == {}
        assert db.user_by_email(_EMAIL) is None

    async def test_invitations_revoke_leaves_everything_else(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """Another pending invitation, its email and every other account stay."""
        admin = _admin(db)
        target = await _create(inv, db, admin, email="target.person@example.ch")
        kept = await _create(inv, db, admin, email="kept.person@example.ch")
        bystander = db.add_account()

        await _revoke(inv, db, admin, target.id)

        assert list(db.invitations) == [kept.id]
        kept_user = _invited_id(db, "kept.person@example.ch")
        assert len(db.invitation_emails(kept_user)) == 1
        assert {admin.user_id, bystander, kept_user} == set(db.users)

    @pytest.mark.parametrize("case", ["other-org", "unknown", "accepted"])
    async def test_invitations_revoke_outside_the_orgs_pending_invitations_is_not_found(
        self, inv: ModuleType, db: FakeDb, case: str
    ) -> None:
        """Another org's invitation, an unknown id or an accepted invitation →
        InvitationNotFoundError; nothing changes and nothing is audited."""
        admin = _admin(db)
        if case == "other-org":
            invitation_id = (await _create(inv, db, _admin(db, org_id=OTHER_ORG_ID))).id
        elif case == "accepted":
            invitation_id = (await _create(inv, db, admin)).id
            await _accept(inv, db, db.invitation_token())
        else:
            invitation_id = uuid.uuid4()
        before = _state(db)

        with pytest.raises(inv.InvitationNotFoundError) as caught:
            await _revoke(inv, db, admin, invitation_id)

        assert str(caught.value) == _NOT_FOUND_MESSAGE
        assert _state(db) == before

    @pytest.mark.parametrize("who", _NOT_ADMINS)
    async def test_invitations_revoke_without_org_users_invite_is_refused_before_any_query(
        self, inv: ModuleType, db: FakeDb, who: str
    ) -> None:
        summary = await _create(inv, db, _admin(db))
        actor = _actor(db, who)
        db.calls.clear()

        with pytest.raises(PermissionError):
            await _revoke(inv, db, actor, summary.id)

        assert db.calls == []
        assert summary.id in db.invitations

    async def test_invitations_revoke_audit_failure_deletes_nothing(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        admin = _admin(db)
        summary = await _create(inv, db, admin)
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _revoke(inv, db, admin, summary.id)

        assert _state(db) == before


# ---------------------------------------------------------------------------
# 8. Resending
# ---------------------------------------------------------------------------


class TestResendInvitation:
    """Resending rotates the token, resets the expiry and queues a new email."""

    async def test_invitations_resend_rotates_the_token(self, inv: ModuleType, db: FakeDb) -> None:
        """A new token; the old link stops working at once, the new one works."""
        admin = _admin(db)
        summary = await _create(inv, db, admin)
        user_id = _invited_id(db)
        old = db.invitation_token(user_id)

        await _resend(inv, db, admin, summary.id)

        new = db.invitation_token(user_id)
        assert new != old
        assert TOKEN_RE.fullmatch(new)
        assert db.invitations[summary.id]["token_hash"] == sha256(new)
        with pytest.raises(inv.InvalidInvitationError):
            await inv.get_invitation(db.pool, old)
        details = await inv.get_invitation(db.pool, new)
        assert details.email == _EMAIL

    async def test_invitations_resend_resets_sent_at_and_the_expiry(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """sent_at is now, expires_at 72 hours later; created_at stays; the summary shows
        the new dates and the same id."""
        admin = _admin(db)
        summary = await _create(inv, db, admin, role="viewer")
        _age(db, summary.id, timedelta(hours=10))
        created_at = db.invitations[summary.id]["created_at"]
        before = datetime.now(UTC)

        resent = await _resend(inv, db, admin, summary.id)

        row = db.invitations[summary.id]
        assert before <= row["sent_at"] <= datetime.now(UTC)
        assert row["expires_at"] - row["sent_at"] == timedelta(hours=72)
        assert row["created_at"] == created_at
        assert type(resent) is models.InvitationSummary
        assert (resent.id, resent.email, resent.role, resent.expired) == (
            summary.id,
            _EMAIL,
            "viewer",
            False,
        )
        assert (resent.sent_at, resent.expires_at) == (row["sent_at"], row["expires_at"])

    async def test_invitations_resend_queues_a_new_email(self, inv: ModuleType, db: FakeDb) -> None:
        """A second invitation email with the new link and the new expiry."""
        admin = _admin(db)
        summary = await _create(inv, db, admin, language="fr")
        user_id = _invited_id(db)

        await _resend(inv, db, admin, summary.id)

        emails = db.invitation_emails(user_id)
        assert len(emails) == 2
        newest = emails[-1]
        assert newest["language"] == "fr"
        assert newest["params"]["org_name"] == ORG_NAME
        assert newest["params"]["accept_link"] == INVITE_LINK_PREFIX + db.invitation_token(user_id)
        assert (
            datetime.fromisoformat(newest["params"]["expires_at"])
            == db.invitations[summary.id]["expires_at"]
        )

    async def test_invitations_resend_cancels_the_queued_email_with_the_old_link(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """The earlier email, still pending, is marked failed with its params cleared: the
        old link leaves the outbox, and only the new email waits for delivery."""
        admin = _admin(db)
        summary = await _create(inv, db, admin)
        user_id = _invited_id(db)
        old_token = db.invitation_token(user_id)

        await _resend(inv, db, admin, summary.id)

        old, new = db.invitation_emails(user_id)
        assert (old["status"], old["params"]) == ("failed", {})
        assert old["finished_at"] is not None
        assert new["status"] == "pending"
        assert old_token not in json.dumps(db.outbox, default=str)

    async def test_invitations_resend_leaves_sent_and_other_emails_alone(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """Only this user's pending invitation emails are cancelled: a delivered one and
        another invitee's pending one keep their state."""
        admin = _admin(db)
        summary = await _create(inv, db, admin)
        await _create(inv, db, admin, email="other.person@example.ch")
        user_id = _invited_id(db)
        other_id = _invited_id(db, "other.person@example.ch")
        (delivered,) = db.invitation_emails(user_id)
        delivered.update(status="sent", params={}, finished_at=datetime.now(UTC))
        other_before = copy.deepcopy(db.invitation_emails(other_id))

        await _resend(inv, db, admin, summary.id)

        old, new = db.invitation_emails(user_id)
        assert old["status"] == "sent"
        assert new["status"] == "pending"
        assert db.invitation_emails(other_id) == other_before

    async def test_invitations_resend_is_audited(self, inv: ModuleType, db: FakeDb) -> None:
        """One invitation.resend row, shaped like invitation.create."""
        admin = _admin(db)
        summary = await _create(inv, db, admin, role="org_admin")

        await _resend(inv, db, admin, summary.id)

        row = _one_row(db.audit_rows("invitation.resend"))
        assert (row["actor_kind"], row["actor_user_id"], row["org_id"]) == (
            "member",
            admin.user_id,
            ORG_ID,
        )
        assert (row["target_type"], row["target_ids"]) == ("invitation", [str(summary.id)])
        assert row["ip"] == _IP
        assert row["metadata"] == {"role": "org_admin", "user_id": str(_invited_id(db))}

    async def test_invitations_resend_writes_in_one_transaction(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        admin = _admin(db)
        summary = await _create(inv, db, admin)
        db.calls.clear()

        await _resend(inv, db, admin, summary.id)

        rotate = _one(db.matching(r"^update invitations\b"))
        writes = [
            rotate,
            _one(db.matching(r"^insert into email_outbox\b")),
            _one(db.matching(r"^insert into audit_events\b")),
        ]
        assert rotate.tx is not None
        assert {(call.via, call.tx) for call in writes} == {(rotate.via, rotate.tx)}
        assert (rotate.tx, "commit") in db.transactions

    async def test_invitations_resend_expiry_is_computed_on_the_database_clock(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """SET sent_at = now(), expires_at = now() + $n::interval (INVITATION_LIFETIME)."""
        admin = _admin(db)
        summary = await _create(inv, db, admin)
        db.calls.clear()

        await _resend(inv, db, admin, summary.id)

        rotate = _one(db.matching(r"^update invitations\b"))
        assert re.search(rf"\bsent_at = {NOW_SQL}", rotate.normalized), rotate.normalized
        match = re.search(
            r"\bexpires_at = (.+?)(?:,| from | where | returning |$)", rotate.normalized
        )
        assert match is not None, rotate.normalized
        assert _bound_interval(rotate, match.group(1).strip()) == inv.INVITATION_LIFETIME

    async def test_invitations_resend_revives_an_expired_invitation(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        admin = _admin(db)
        summary = await _create(inv, db, admin)
        _expire(db, summary.id)

        resent = await _resend(inv, db, admin, summary.id)

        assert resent.expired is False
        details = await inv.get_invitation(db.pool, db.invitation_token())
        assert details.email == _EMAIL

    async def test_invitations_resend_needs_no_free_seat(self, inv: ModuleType, db: FakeDb) -> None:
        """The invitation already holds its seat: resending works in a full (even
        over-full) org."""
        db.add_org(ORG_ID, seats=2)
        admin = _admin(db)
        summary = await _create(inv, db, admin)
        db.add_org(ORG_ID, seats=1)

        resent = await _resend(inv, db, admin, summary.id)

        assert resent.id == summary.id
        assert len(db.invitation_emails()) == 2

    @pytest.mark.parametrize("case", ["other-org", "unknown", "accepted", "revoked"])
    async def test_invitations_resend_outside_the_orgs_pending_invitations_is_not_found(
        self, inv: ModuleType, db: FakeDb, case: str
    ) -> None:
        """Another org's invitation, an unknown id, an accepted or a revoked invitation →
        InvitationNotFoundError; nothing changes (no new token, email or audit row)."""
        admin = _admin(db)
        if case == "other-org":
            invitation_id = (await _create(inv, db, _admin(db, org_id=OTHER_ORG_ID))).id
        elif case == "accepted":
            invitation_id = (await _create(inv, db, admin)).id
            await _accept(inv, db, db.invitation_token())
        elif case == "revoked":
            invitation_id = (await _create(inv, db, admin)).id
            await _revoke(inv, db, admin, invitation_id)
        else:
            invitation_id = uuid.uuid4()
        before = _state(db)

        with pytest.raises(inv.InvitationNotFoundError) as caught:
            await _resend(inv, db, admin, invitation_id)

        assert str(caught.value) == _NOT_FOUND_MESSAGE
        assert _state(db) == before

    @pytest.mark.parametrize("who", _NOT_ADMINS)
    async def test_invitations_resend_without_org_users_invite_is_refused_before_any_query(
        self, inv: ModuleType, db: FakeDb, who: str
    ) -> None:
        summary = await _create(inv, db, _admin(db))
        actor = _actor(db, who)
        db.calls.clear()

        with pytest.raises(PermissionError):
            await _resend(inv, db, actor, summary.id)

        assert db.calls == []

    async def test_invitations_resend_audit_failure_keeps_the_old_link(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """Fail closed: no rotation, no new email; the old link still works."""
        admin = _admin(db)
        summary = await _create(inv, db, admin)
        old = db.invitation_token()
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _resend(inv, db, admin, summary.id)

        assert _state(db) == before
        db.fail_audit = False
        assert (await inv.get_invitation(db.pool, old)).email == _EMAIL


# ---------------------------------------------------------------------------
# 9. Opening a link
# ---------------------------------------------------------------------------

_MALFORMED_TOKENS = [
    pytest.param("", id="empty"),
    pytest.param("short", id="short"),
    pytest.param("A" * 42, id="42-chars"),
    pytest.param("A" * 44, id="44-chars"),
    pytest.param("A" * 42 + ".", id="dot"),
    pytest.param("A" * 42 + "+", id="plus"),
    pytest.param("A" * 42 + "=", id="padding"),
    pytest.param("A" * 42 + "~", id="tilde"),
    pytest.param("A" * 21 + " " + "A" * 21, id="space"),
    pytest.param("x" * 200, id="200-chars"),
]


async def _unusable(inv: ModuleType, db: FakeDb, case: str) -> str:
    """Send an invitation (as an Org Admin of ORG_ID), make its link unusable in one way,
    and return the token of that link."""
    admin = _admin(db)
    summary = await _create(inv, db, admin)
    user_id = _invited_id(db)
    token = db.invitation_token(user_id)
    if case == "unknown":
        return _WELL_FORMED_UNKNOWN
    if case == "expired":
        _expire(db, summary.id)
    elif case == "expiry-boundary":
        db.invitations[summary.id]["expires_at"] = _exactly_now()
    elif case == "accepted":
        await _accept(inv, db, token)
    elif case == "revoked":
        await _revoke(inv, db, admin, summary.id)
    elif case == "rotated":
        await _resend(inv, db, admin, summary.id)
    elif case == "user-deactivated":
        db.users[user_id]["status"] = "deactivated"
    elif case == "user-deleted":
        db.users[user_id]["deleted_at"] = _DELETED_AT
    elif case == "org-deactivated":
        db.add_org(ORG_ID, status="deactivated")
    elif case == "org-pending-deletion":
        db.add_org(ORG_ID, status="pending_deletion")
    else:
        msg = f"unknown case {case}"
        raise AssertionError(msg)
    return token


_UNUSABLE_CASES = [
    "unknown",
    "expired",
    "expiry-boundary",
    "accepted",
    "revoked",
    "rotated",
    "user-deactivated",
    "user-deleted",
    "org-deactivated",
    "org-pending-deletion",
]


class TestGetInvitation:
    """The acceptance page's metadata: the org name, the role and the email."""

    async def test_invitations_get_returns_org_name_role_and_email(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        await _create(inv, db, _admin(db), role="viewer")

        details = await inv.get_invitation(db.pool, db.invitation_token())

        assert type(details) is models.InvitationDetails
        assert (details.org_name, details.role, details.email) == (ORG_NAME, "viewer", _EMAIL)

    async def test_invitations_get_works_on_an_expiring_invitation(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """Sent 71 hours ago: still usable for an hour."""
        summary = await _create(inv, db, _admin(db))
        _age(db, summary.id, timedelta(hours=71))

        details = await inv.get_invitation(db.pool, db.invitation_token())

        assert details.email == _EMAIL

    @pytest.mark.parametrize("token", _MALFORMED_TOKENS)
    async def test_invitations_get_malformed_token_is_refused_without_a_query(
        self, inv: ModuleType, db: FakeDb, token: str
    ) -> None:
        with pytest.raises(inv.InvalidInvitationError):
            await inv.get_invitation(db.pool, token)

        assert db.calls == []

    @pytest.mark.parametrize("case", _UNUSABLE_CASES)
    async def test_invitations_get_unusable_link_is_invalid(
        self, inv: ModuleType, db: FakeDb, case: str
    ) -> None:
        """Unknown, expired (also at exactly now), used, revoked, rotated, an account no
        longer invited, an org that isn't active: the one InvalidInvitationError."""
        token = await _unusable(inv, db, case)

        with pytest.raises(inv.InvalidInvitationError) as caught:
            await inv.get_invitation(db.pool, token)

        assert str(caught.value) == _INVALID_MESSAGE
        assert token not in str(caught.value)

    async def test_invitations_get_binds_only_the_token_hash(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """The lookup is bound to sha256(token); the raw token reaches no statement."""
        await _create(inv, db, _admin(db))
        token = db.invitation_token()
        db.calls.clear()

        await inv.get_invitation(db.pool, token)

        assert any(sha256(token) in call.args for call in db.calls)
        for call in db.calls:
            assert token not in call.sql
            assert all(token not in _text(arg) for arg in call.args)

    async def test_invitations_get_writes_nothing(self, inv: ModuleType, db: FakeDb) -> None:
        await _create(inv, db, _admin(db))
        before = _state(db)

        await inv.get_invitation(db.pool, db.invitation_token())

        assert _state(db) == before


# ---------------------------------------------------------------------------
# 10. Accepting
# ---------------------------------------------------------------------------


class TestAcceptInvitation:
    """Accepting sets the name and password, activates the user and opens a session."""

    async def test_invitations_accept_activates_the_account(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """status active, the name, the Argon2 hash, last_login_at now."""
        await _create(inv, db, _admin(db))
        before = datetime.now(UTC)

        await _accept(inv, db, db.invitation_token())

        row = db.user_by_email(_EMAIL)
        assert row is not None
        assert (row["status"], row["name"], row["password_hash"]) == (
            "active",
            _NAME,
            fake_hash(_PASSWORD),
        )
        assert row["last_login_at"] is not None
        assert before <= row["last_login_at"] <= datetime.now(UTC)
        assert (row["role"], row["org_id"], row["deleted_at"]) == ("editor", ORG_ID, None)

    async def test_invitations_accept_marks_the_invitation_used(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        await _create(inv, db, _admin(db))
        before = datetime.now(UTC)

        await _accept(inv, db, db.invitation_token())

        accepted_at = _invitation(db)["accepted_at"]
        assert accepted_at is not None
        assert before <= accepted_at <= datetime.now(UTC)

    async def test_invitations_accept_starts_a_session(self, inv: ModuleType, db: FakeDb) -> None:
        """A LoginResult with the session token and the org policy's lifetime (43200 s);
        the session row stores the policy's idle timeout, the IP and the user agent."""
        await _create(inv, db, _admin(db))

        result = await _accept(inv, db, db.invitation_token())

        assert type(result) is auth.LoginResult
        assert result.max_age_seconds == 43200
        row = db.session(result.token)
        assert row["user_id"] == _invited_id(db)
        assert row["idle_timeout_minutes"] == 60
        assert row["expires_at"] - row["created_at"] == timedelta(hours=12)
        assert (row["ip"], row["user_agent"]) == (_IP, _UA)
        assert len(db.sessions_of(_invited_id(db))) == 1

    async def test_invitations_accept_session_resolves_to_the_invited_member(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """The new cookie works: a member of the inviting org with the invited role and the
        inviting admin's language."""
        await _create(inv, db, _admin(db), role="viewer", language="fr")

        result = await _accept(inv, db, db.invitation_token())

        session = await sessions_mod.resolve_session(db.pool, result.token)
        assert session is not None
        principal = session.principal
        assert (principal.user_id, principal.kind, principal.org_id, principal.role) == (
            _invited_id(db),
            "member",
            ORG_ID,
            "viewer",
        )
        assert session.ui_language == "fr"

    async def test_invitations_accept_uses_the_org_session_policy(
        self, inv: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With a 2-hour, 20-minute org policy the session gets exactly that."""
        monkeypatch.setattr(
            sessions_mod,
            "DEFAULT_ORG_SESSION_POLICY",
            sessions_mod.SessionPolicy(idle_timeout_minutes=20, max_lifetime_hours=2),
        )
        await _create(inv, db, _admin(db))

        result = await _accept(inv, db, db.invitation_token())

        assert result.max_age_seconds == 7200
        row = db.session(result.token)
        assert row["idle_timeout_minutes"] == 20
        assert row["expires_at"] - row["created_at"] == timedelta(hours=2)

    async def test_invitations_accept_is_audited(self, inv: ModuleType, db: FakeDb) -> None:
        """One invitation.accept row: the new member as the actor, their org, target the
        invitation, the IP, metadata {"role"}."""
        summary = await _create(inv, db, _admin(db), role="viewer")

        await _accept(inv, db, db.invitation_token())

        row = _one_row(db.audit_rows("invitation.accept"))
        assert (row["actor_kind"], row["actor_user_id"], row["org_id"]) == (
            "member",
            _invited_id(db),
            ORG_ID,
        )
        assert (row["target_type"], row["target_ids"]) == ("invitation", [str(summary.id)])
        assert row["ip"] == _IP
        assert row["metadata"] == {"role": "viewer"}

    async def test_invitations_accept_writes_in_one_transaction(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """Marking the invitation used, activating the user, opening the session and the
        audit event share one committed transaction."""
        await _create(inv, db, _admin(db))
        db.calls.clear()

        await _accept(inv, db, db.invitation_token())

        mark = _one(db.matching(r"^update invitations\b"))
        writes = [
            mark,
            _one(db.matching(r"^update users\b")),
            _one(db.matching(r"^insert into sessions\b")),
            _one(db.matching(r"^insert into audit_events\b")),
        ]
        assert mark.tx is not None
        assert {(call.via, call.tx) for call in writes} == {(mark.via, mark.tx)}
        assert (mark.tx, "commit") in db.transactions

    async def test_invitations_accept_is_single_use(self, inv: ModuleType, db: FakeDb) -> None:
        """A second accept with the same link is refused: no second session, no change."""
        await _create(inv, db, _admin(db))
        token = db.invitation_token()
        await _accept(inv, db, token)
        before = _state(db)

        with pytest.raises(inv.InvalidInvitationError):
            await _accept(inv, db, token, name="Someone Else", password=_OTHER_PASSWORD)

        assert _state(db) == before
        assert len(db.sessions_of(_invited_id(db))) == 1

    async def test_invitations_accept_hashes_in_a_worker_thread(
        self, inv: ModuleType, db: FakeDb, hash_spy: _HashSpy
    ) -> None:
        await _create(inv, db, _admin(db))

        await _accept(inv, db, db.invitation_token())

        assert hash_spy.calls == [_PASSWORD]
        assert hash_spy.threads[0] != threading.get_ident()

    @pytest.mark.parametrize("token", _MALFORMED_TOKENS)
    async def test_invitations_accept_malformed_token_is_refused_without_a_query(
        self, inv: ModuleType, db: FakeDb, hash_spy: _HashSpy, token: str
    ) -> None:
        with pytest.raises(inv.InvalidInvitationError):
            await _accept(inv, db, token)

        assert db.calls == []
        assert hash_spy.calls == []

    @pytest.mark.parametrize("case", _UNUSABLE_CASES)
    async def test_invitations_accept_unusable_link_is_refused_and_writes_nothing(
        self, inv: ModuleType, db: FakeDb, hash_spy: _HashSpy, case: str
    ) -> None:
        """InvalidInvitationError; no table changes and the password is never hashed."""
        token = await _unusable(inv, db, case)
        before = _state(db)
        hash_spy.calls.clear()

        with pytest.raises(inv.InvalidInvitationError) as caught:
            await _accept(inv, db, token, password=_OTHER_PASSWORD)

        assert str(caught.value) == _INVALID_MESSAGE
        assert _state(db) == before
        assert hash_spy.calls == []

    @pytest.mark.parametrize(
        ("password", "reason"),
        [
            pytest.param("Kq7#vX9!pL2", "too_short", id="11-chars"),
            pytest.param("Qwerty123456", "common", id="common"),
            pytest.param(_EMAIL.lower(), "equals_email", id="equals-the-invitation-email"),
        ],
    )
    async def test_invitations_accept_policy_failure_writes_nothing_and_keeps_the_link(
        self, inv: ModuleType, db: FakeDb, hash_spy: _HashSpy, password: str, reason: str
    ) -> None:
        """PasswordPolicyError with its reason; nothing written, no transaction, nothing
        hashed; the same link then works with a good password."""
        await _create(inv, db, _admin(db))
        token = db.invitation_token()
        before = _state(db)
        transactions = list(db.transactions)

        with pytest.raises(passwords.PasswordPolicyError) as caught:
            await _accept(inv, db, token, password=password)

        assert caught.value.reason == reason
        assert _state(db) == before
        assert db.transactions == transactions
        assert hash_spy.calls == []
        result = await _accept(inv, db, token)
        assert type(result) is auth.LoginResult

    async def test_invitations_accept_checks_the_link_before_the_password(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """An expired link with a too-short password is an invalid link, not a policy
        failure."""
        token = await _unusable(inv, db, "expired")

        with pytest.raises(inv.InvalidInvitationError):
            await _accept(inv, db, token, password="short")

    @pytest.mark.parametrize(
        "race", ["accepted-concurrently", "expired", "revoked", "rotated", "user-deactivated"]
    )
    async def test_invitations_accept_race_after_the_lookup_is_refused(
        self, inv: ModuleType, db: FakeDb, race: str
    ) -> None:
        """Between the lookup and the transaction the link is used, expires, is revoked or
        rotated, or the account stops being invited: InvalidInvitationError, the
        invitation isn't marked used by this call, no session is opened, nothing is
        audited."""
        summary = await _create(inv, db, _admin(db))
        user_id = _invited_id(db)
        token = db.invitation_token(user_id)
        other_token = "R" * 43

        def race_hook() -> None:
            if race == "accepted-concurrently":
                db.invitations[summary.id]["accepted_at"] = datetime.now(UTC)
                db.users[user_id].update(
                    status="active", name="First Winner", password_hash=fake_hash(_OTHER_PASSWORD)
                )
            elif race == "expired":
                _expire(db, summary.id)
            elif race == "revoked":
                db.delete_row("users", db.users[user_id])
            elif race == "rotated":
                db.invitations[summary.id]["token_hash"] = sha256(other_token)
            else:
                db.users[user_id]["status"] = "deactivated"

        db.after_invitation_lookup = race_hook

        with pytest.raises(inv.InvalidInvitationError):
            await _accept(inv, db, token)

        assert db.audit_rows("invitation.accept") == []
        if race == "revoked":
            assert user_id not in db.users
            return
        assert db.sessions_of(user_id) == []
        user = db.users[user_id]
        if race == "accepted-concurrently":
            assert (user["name"], user["password_hash"]) == (
                "First Winner",
                fake_hash(_OTHER_PASSWORD),
            )
        else:
            assert (user["name"], user["password_hash"]) == (None, None)
            assert user["status"] == ("deactivated" if race == "user-deactivated" else "invited")
            assert db.invitations[summary.id]["accepted_at"] is None

    async def test_invitations_accept_audit_failure_changes_nothing(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """Fail closed: AuditRecordError; the user stays invited, the invitation unused, no
        session; the link works once the audit log is back."""
        await _create(inv, db, _admin(db))
        token = db.invitation_token()
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _accept(inv, db, token)

        assert _state(db) == before
        db.fail_audit = False
        assert type(await _accept(inv, db, token)) is auth.LoginResult

    async def test_invitations_accept_invited_org_admin_gets_an_org_admin_session(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        await _create(inv, db, _admin(db), role="org_admin")

        result = await _accept(inv, db, db.invitation_token())

        session = await sessions_mod.resolve_session(db.pool, result.token)
        assert session is not None
        assert session.principal.role == "org_admin"

    async def test_invitations_accept_result_hides_the_session_token(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        await _create(inv, db, _admin(db))

        result = await _accept(inv, db, db.invitation_token())

        assert result.token not in repr(result)
        assert result.token not in str(result)


# ---------------------------------------------------------------------------
# 11. The first Org Admin of an org (for #154)
# ---------------------------------------------------------------------------

_NEW_ORG_NAME = "Neue Kanzlei AG"


def _empty_org(db: FakeDb) -> uuid.UUID:
    return db.add_org(name=_NEW_ORG_NAME, seats=5)


class TestFirstOrgAdmin:
    """A Super Admin invites the first user of an empty org, who becomes Org Admin."""

    async def test_invitations_first_admin_invites_an_org_admin(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """An invited org_admin of that org in the given language, an invitation, and the
        email with the org's name."""
        org_id = _empty_org(db)

        summary = await _first(inv, db, _super_admin(db), org_id)

        row = db.user_by_email(_EMAIL)
        assert row is not None
        assert (row["kind"], row["org_id"], row["role"], row["status"]) == (
            "member",
            org_id,
            "org_admin",
            "invited",
        )
        assert row["ui_language"] == "fr"
        assert (summary.role, summary.email, summary.expired) == ("org_admin", _EMAIL, False)
        assert summary.id in db.invitations
        email = _one_row(db.invitation_emails())
        assert email["params"]["org_name"] == _NEW_ORG_NAME
        assert email["params"]["accept_link"] == INVITE_LINK_PREFIX + db.invitation_token()

    async def test_invitations_first_admin_is_audited_as_the_super_admin(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """invitation.create by the Super Admin, in the org's log (org_id = the org)."""
        org_id = _empty_org(db)
        super_admin = _super_admin(db)

        summary = await _first(inv, db, super_admin, org_id)

        row = _one_row(db.audit_rows("invitation.create"))
        assert (row["actor_kind"], row["actor_user_id"], row["org_id"]) == (
            "super_admin",
            super_admin.user_id,
            org_id,
        )
        assert (row["target_type"], row["target_ids"]) == ("invitation", [str(summary.id)])
        assert row["metadata"] == {"role": "org_admin", "user_id": str(_invited_id(db))}
        assert row["ip"] == _IP

    async def test_invitations_first_admin_accepting_makes_an_org_admin(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        org_id = _empty_org(db)
        await _first(inv, db, _super_admin(db), org_id)

        result = await _accept(inv, db, db.invitation_token())

        session = await sessions_mod.resolve_session(db.pool, result.token)
        assert session is not None
        assert (session.principal.org_id, session.principal.role) == (org_id, "org_admin")

    async def test_invitations_first_admin_has_no_role_parameter(self, inv: ModuleType) -> None:
        """The role is always org_admin: it can't be chosen."""
        parameters = inspect.signature(inv.invite_first_org_admin).parameters

        assert "role" not in parameters
        assert {"actor", "org_id", "email", "language", "public_url", "ip"} <= set(parameters)

    async def test_invitations_first_admin_locks_the_org_row(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        org_id = _empty_org(db)

        await _first(inv, db, _super_admin(db), org_id)

        users_insert = _one(db.matching(r"^insert into users\b"))
        locks = [
            call
            for call in db.calls
            if re.search(r"\bfrom organizations\b", call.normalized)
            and re.search(r"\bfor (?:no key )?update\b", call.normalized)
        ]
        assert locks
        assert (locks[0].via, locks[0].tx) == (users_insert.via, users_insert.tx)
        assert db.calls.index(locks[0]) < db.calls.index(users_insert)

    @pytest.mark.parametrize(
        "fields",
        [
            pytest.param({}, id="active"),
            pytest.param({"status": "invited", "name": None, "password_hash": None}, id="invited"),
            pytest.param({"status": "deactivated"}, id="deactivated"),
            pytest.param({"deleted_at": _DELETED_AT}, id="deleted"),
            pytest.param({"status": "deactivated", "deleted_at": _DELETED_AT}, id="deleted-deact"),
        ],
    )
    async def test_invitations_first_admin_refused_once_the_org_has_any_user(
        self, inv: ModuleType, db: FakeDb, fields: dict[str, Any]
    ) -> None:
        """Any users row of the org (any status, deleted or not) → OrgHasUsersError; nothing
        is written."""
        org_id = _empty_org(db)
        super_admin = _super_admin(db)
        db.add_account(org_id=org_id, **fields)
        before = _state(db)

        with pytest.raises(inv.OrgHasUsersError):
            await _first(inv, db, super_admin, org_id)

        assert _state(db) == before

    async def test_invitations_first_admin_second_invite_is_refused(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """The first invitation's invited row counts: a second first-admin invite fails."""
        org_id = _empty_org(db)
        super_admin = _super_admin(db)
        await _first(inv, db, super_admin, org_id)

        with pytest.raises(inv.OrgHasUsersError):
            await _first(inv, db, super_admin, org_id, email="second.admin@example.ch")

        assert db.user_by_email("second.admin@example.ch") is None

    async def test_invitations_first_admin_existing_email_is_refused_and_audited(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        """DuplicateEmailError; only an invitation.refuse row, by the Super Admin, in the
        org's log."""
        org_id = _empty_org(db)
        super_admin = _super_admin(db)
        db.add_account(email=_EMAIL, org_id=ORG_ID)
        before = _state(db)

        with pytest.raises(accounts.DuplicateEmailError):
            await _first(inv, db, super_admin, org_id)

        _assert_only_refusal_audited(
            db,
            before,
            actor_kind="super_admin",
            actor_user_id=super_admin.user_id,
            org_id=org_id,
            role="org_admin",
            reason="email_taken",
        )

    async def test_invitations_first_admin_other_orgs_users_dont_count(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        org_id = _empty_org(db)
        db.add_account(org_id=ORG_ID)

        summary = await _first(inv, db, _super_admin(db), org_id)

        assert summary.id in db.invitations

    async def test_invitations_first_admin_unknown_org_is_refused(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        super_admin = _super_admin(db)
        before = _state(db)

        with pytest.raises(inv.OrgNotFoundError):
            await _first(inv, db, super_admin, uuid.uuid4())

        assert _state(db) == before

    @pytest.mark.parametrize("role", _ROLES)
    async def test_invitations_first_admin_needs_org_create(
        self, inv: ModuleType, db: FakeDb, role: str
    ) -> None:
        """Only a Super Admin (org.create): members get PermissionError before any query."""
        org_id = _empty_org(db)
        actor = _principal(db, db.add_account(role=role))

        with pytest.raises(PermissionError):
            await _first(inv, db, actor, org_id)

        assert db.calls == []

    async def test_invitations_first_admin_audit_failure_writes_nothing(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        org_id = _empty_org(db)
        super_admin = _super_admin(db)
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _first(inv, db, super_admin, org_id)

        assert _state(db) == before


# ---------------------------------------------------------------------------
# 12. No content in logs, errors or audit rows
# ---------------------------------------------------------------------------


class TestNoContent:
    """Emails, names, passwords, tokens and links never reach a log line or audit row."""

    async def _flow(self, inv: ModuleType, db: FakeDb) -> list[str]:
        """Send, refuse a duplicate, resend, open, fail the policy, accept, revoke another
        invitation; return every raw token issued."""
        admin = _admin(db, email="log.marker.admin@example.ch")
        summary = await _create(inv, db, admin, email="log.marker.invitee@example.ch")
        with pytest.raises(accounts.DuplicateEmailError):
            await _create(inv, db, admin, email="LOG.MARKER.INVITEE@example.ch")
        user_id = _invited_id(db, "log.marker.invitee@example.ch")
        first = db.invitation_token(user_id)
        await _resend(inv, db, admin, summary.id)
        second = db.invitation_token(user_id)
        await inv.get_invitation(db.pool, second)
        with pytest.raises(passwords.PasswordPolicyError):
            await _accept(inv, db, second, name="Grace Hoppermarker", password="short")
        await _accept(inv, db, second, name="Grace Hoppermarker")
        with pytest.raises(inv.InvalidInvitationError):
            await _accept(inv, db, first, name="Grace Hoppermarker")
        other = await _create(inv, db, admin, email="log.marker.other@example.ch")
        await _revoke(inv, db, admin, other.id)
        return [first, second]

    async def test_invitations_flow_logs_no_content(
        self, inv: ModuleType, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)

        tokens = await self._flow(inv, db)

        text = caplog.text
        assert "log.marker" not in text.lower()
        assert "hoppermarker" not in text.lower()
        assert _PASSWORD not in text
        assert "accept-invitation" not in text
        for token in tokens:
            assert token not in text
            assert sha256(token).hex() not in text

    async def test_invitations_audit_rows_carry_no_content(
        self, inv: ModuleType, db: FakeDb
    ) -> None:
        tokens = await self._flow(inv, db)

        stored = json.dumps(db.audit, default=str).lower()
        assert {row["action"] for row in db.audit} >= {
            "invitation.create",
            "invitation.resend",
            "invitation.accept",
            "invitation.revoke",
        }
        assert "log.marker" not in stored
        assert "hoppermarker" not in stored
        assert "accept-invitation" not in stored
        for token in tokens:
            assert token.lower() not in stored
            assert sha256(token).hex() not in stored
