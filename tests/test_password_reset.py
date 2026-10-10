"""Tests for admino.password_reset — self-service password reset by email (GH-151).

``request_reset(pool, *, email, public_url, ip)`` looks the account up by email
(case-insensitive) and, for an account that may log in, stores the SHA-256 hash
of a fresh 256-bit token (one live token per user: a newer request replaces the
older one), queues a ``password_reset`` email through the #148 outbox with the
link ``{public_url}/reset-password#token=<token>`` and records
``password_reset.request``, all in one transaction. It always returns None.

``confirm_reset(pool, *, token, new_password, ip)`` refuses a malformed token
without touching the database, looks the token up by its hash, refuses an
unknown or expired token or an account that may no longer log in, applies the
password policy, and then, in one transaction, consumes the token atomically,
stores the new Argon2 hash, ends every session of the user by deleting its rows
(``sessions.revoke_user_sessions``; GH-152 made revocation a DELETE) and records
``password_reset.complete``.

What these tests pin down:
- Constants: a 30-minute lifetime; one generic ``InvalidResetTokenError``
  ("This reset link is invalid or has expired.") that carries no input.
- The lookup: one ``pool.fetchrow`` with ``lower(email) = lower($1)``, the email
  as its only bind parameter and in no other statement.
- Eligibility (same rule as login): active, not deleted, and a Super Admin or a
  member of an active org. Invited, deactivated and deleted users and members
  of a deactivated or pending-deletion org get no token and no email, and the
  caller can't tell: None is returned either way and nothing is raised.
- The token: 43 URL-safe characters (256 bits), only its 32-byte SHA-256 digest
  is ever a bind parameter; the raw token travels only inside the queued
  email's ``reset_link``; the link is built from ``public_url``.
- The upsert: ``INSERT INTO password_reset_tokens ... VALUES (..., now() + 30
  minutes) ON CONFLICT (user_id) DO UPDATE ... RETURNING expires_at``, and the
  email's ``expires_at`` is the value it returns.
- Expiry (past and exactly now), single use, invalidation by a newer request,
  a consume that lost a race, and eligibility re-checked at confirm: all
  refused with ``InvalidResetTokenError`` and nothing written.
- The policy runs after the token checks; a policy failure writes nothing and
  leaves the token usable.
- Success: token consumed first, new hash (computed off the event loop's
  thread) stored, every session row of the user deleted (others untouched),
  audit with the deleted count; one committed transaction.
- Audit rows: exact actors, targets, IP and metadata; an audit failure
  propagates and rolls everything back (fail closed).
- No email, token, password or link in any log line, audit row or error.

All database calls go to the in-memory fake of tests/db_fakes.py (re-exported by
tests/password_reset_fakes.py).
Argon2 is replaced by a fast spy (the real hashing is covered by
tests/test_passwords.py); the real policy, outbox, audit and session code runs.

Security notes:
- No user enumeration: request_reset behaves identically to its caller for
  every email; admins reusing this flow (#164, #167) never see a token.
- Reset-link poisoning: the link base is the configured public URL only.
- Content-free audit (tracker #139 §5): IDs, the IP, a bool and a count.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import threading
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from admino import passwords, sessions
from admino.audit_events import AuditRecordError
from tests.password_reset_fakes import (
    FAKE_LIFETIME,
    LINK_PREFIX,
    ORG_ID,
    PUBLIC_URL,
    TOKEN_RE,
    FakeDb,
    fake_hash,
    sha256,
)

if TYPE_CHECKING:
    import uuid
    from types import ModuleType

    from tests.password_reset_fakes import Call

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EMAIL = "Reset.Marker@Example.test"
_NEW_PASSWORD = "violet-Anchor-93-quartz"
_OTHER_PASSWORD = "Tidal-Lantern-58-cobalt"
_IP = "203.0.113.7"
_INVALID_MESSAGE = "This reset link is invalid or has expired."
_DELETED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)

# Transaction-time "now" in SQL (created_at defaults to now(), and the CHECK
# bounds expires_at by created_at + 30 minutes).
_NOW_SQL = r"(?:now\(\)|current_timestamp)"


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def pr() -> ModuleType:
    """admino.password_reset, imported per test so each test fails on its own until it exists."""
    from admino import password_reset

    return password_reset


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

    Stored as a token's ``expires_at``, it behaves as if the token expired at
    exactly the instant the service reads its clock, whatever clock it reads:
    ==, <= and >= are True; <, > and != are False; the difference is zero.
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


def _add_active(db: FakeDb, **overrides: Any) -> uuid.UUID:
    """The account under test (email _EMAIL): an active editor of an active org."""
    fields: dict[str, Any] = {"email": _EMAIL}
    fields.update(overrides)
    return db.add_account(**fields)


def _super_admin_fields(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {"kind": "super_admin", "role": None, "org_status": None}
    fields.update(overrides)
    return fields


async def _request(pr: ModuleType, db: FakeDb, **overrides: Any) -> Any:
    """Call request_reset with the default email, public URL and IP."""
    kwargs: dict[str, Any] = {"email": _EMAIL, "public_url": PUBLIC_URL, "ip": _IP}
    kwargs.update(overrides)
    return await pr.request_reset(db.pool, **kwargs)


async def _confirm(pr: ModuleType, db: FakeDb, token: Any, **overrides: Any) -> Any:
    """Call confirm_reset with the default new password and IP."""
    kwargs: dict[str, Any] = {"token": token, "new_password": _NEW_PASSWORD, "ip": _IP}
    kwargs.update(overrides)
    return await pr.confirm_reset(db.pool, **kwargs)


async def _issue(pr: ModuleType, db: FakeDb) -> str:
    """Request a reset for _EMAIL and return the token from the queued email."""
    await _request(pr, db)
    return db.issued_token()


def _one(calls: list[Call]) -> Call:
    assert len(calls) == 1, calls
    return calls[0]


def _upsert(db: FakeDb) -> Call:
    """The one INSERT INTO password_reset_tokens."""
    return _one(db.matching(r"^insert into password_reset_tokens\b"))


def _consume(db: FakeDb) -> Call:
    """The one DELETE FROM password_reset_tokens."""
    return _one(db.matching(r"^delete from password_reset_tokens\b"))


def _token_lookups(db: FakeDb) -> list[Call]:
    """The reads that name password_reset_tokens (the confirm's lookup)."""
    return [
        call
        for call in db.calls
        if call.method in {"fetchrow", "fetch"} and "password_reset_tokens" in call.normalized
    ]


def _writes(db: FakeDb) -> list[Call]:
    """Every INSERT, UPDATE or DELETE issued."""
    return db.matching(r"^(?:insert|update|delete)\b")


def _split_top_level(text: str) -> list[str]:
    """Split at commas outside parentheses and '...' literals."""
    items: list[str] = []
    depth = 0
    quote = False
    start = 0
    for index, char in enumerate(text):
        if char == "'":
            quote = not quote
        elif quote:
            continue
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            items.append(text[start:index].strip())
            start = index + 1
    items.append(text[start:].strip())
    return items


def _insert_values(call: Call) -> dict[str, str]:
    """Map each column of the upsert to its VALUES expression (normalized SQL text)."""
    sql = call.normalized
    match = re.search(r"^insert into password_reset_tokens\s*\(([^)]*)\)\s*values\s*\(", sql)
    assert match is not None, sql
    columns = [c.strip().strip('"') for c in match.group(1).split(",")]
    depth = 0
    end = match.end() - 1
    for index in range(match.end() - 1, len(sql)):
        if sql[index] == "(":
            depth += 1
        elif sql[index] == ")":
            depth -= 1
            if depth == 0:
                end = index
                break
    values = _split_top_level(sql[match.end() : end])
    assert len(columns) == len(values), sql
    return dict(zip(columns, values, strict=True))


def _bound(call: Call, expression: str) -> Any:
    """The bind argument behind a ``$n`` (optionally cast) expression."""
    placeholder = re.fullmatch(r"\$(\d+)(?:\s*::\s*\w+)?", expression)
    assert placeholder is not None, f"not a bind parameter: {expression}"
    return call.args[int(placeholder.group(1)) - 1]


def _upsert_lifetime(call: Call) -> timedelta | None:
    """The lifetime the upsert adds to now(): an interval literal or a bound interval."""
    sql = call.normalized
    units = {"second": 1, "sec": 1, "minute": 60, "min": 60, "hour": 3600}
    literal = re.search(
        rf"{_NOW_SQL} \+ (?:interval )?'(\d+) ?(second|sec|minute|min|hour)s?'(?: ?:: ?interval)?",
        sql,
    )
    if literal is not None:
        return timedelta(seconds=int(literal.group(1)) * units[literal.group(2)])
    made = re.search(rf"{_NOW_SQL} \+ make_interval\((mins|secs) => \$(\d+)\)", sql)
    if made is not None:
        value = call.args[int(made.group(2)) - 1]
        return timedelta(minutes=value) if made.group(1) == "mins" else timedelta(seconds=value)
    bound = re.search(rf"{_NOW_SQL} \+ \$(\d+)(?: ?:: ?interval)?", sql)
    if bound is not None:
        value = call.args[int(bound.group(1)) - 1]
        return value if isinstance(value, timedelta) else None
    return None


def _carries(call: Call, secret: str) -> bool:
    """True when the SQL text or any bind argument contains the secret."""
    if secret in call.sql:
        return True
    for arg in call.args:
        if isinstance(arg, bytes | bytearray):
            if secret.encode() in arg:
                return True
        elif secret in str(arg):
            return True
    return False


def _carries_email(call: Call) -> bool:
    rendered = f"{call.sql} {' '.join(str(arg) for arg in call.args)}".casefold()
    return _EMAIL.casefold() in rendered or "reset.marker" in rendered


# Accounts that must get no token and no email ("unknown": no account at all).
_NOT_SENT_CAUSES: dict[str, dict[str, Any] | None] = {
    "unknown": None,
    "invited": {"status": "invited", "password_hash": None},
    "deactivated": {"status": "deactivated"},
    "deleted": {"deleted_at": _DELETED_AT},
    "org-deactivated": {"org_status": "deactivated"},
    "org-pending-deletion": {"org_status": "pending_deletion"},
    "super-admin-deactivated": _super_admin_fields(status="deactivated"),
    "super-admin-deleted": _super_admin_fields(deleted_at=_DELETED_AT),
}
_KNOWN_NOT_SENT = [cause for cause in _NOT_SENT_CAUSES if cause != "unknown"]

# Accounts that may reset their password.
_ELIGIBLE: dict[str, dict[str, Any]] = {
    "org-admin": {"role": "org_admin"},
    "editor": {"role": "editor"},
    "super-admin": _super_admin_fields(),
}


def _setup_cause(db: FakeDb, cause: str) -> uuid.UUID | None:
    """Add an unrelated active account, plus the account of ``cause`` (none if unknown)."""
    db.add_account(email="someone.else@example.test")
    fields = _NOT_SENT_CAUSES[cause]
    return None if fields is None else _add_active(db, **fields)


# ---------------------------------------------------------------------------
# 1. Constants and the error type
# ---------------------------------------------------------------------------


class TestPasswordResetConstants:
    """The lifetime and the one generic error."""

    def test_password_reset_token_lifetime_is_30_minutes(self, pr: ModuleType) -> None:
        assert timedelta(minutes=30) == pr.RESET_TOKEN_LIFETIME

    def test_password_reset_invalid_token_message(self, pr: ModuleType) -> None:
        assert pr.INVALID_RESET_TOKEN_MESSAGE == _INVALID_MESSAGE

    def test_password_reset_invalid_token_error_str_is_the_message(self, pr: ModuleType) -> None:
        """str() is the generic message and the args carry nothing else."""
        exc = pr.InvalidResetTokenError()

        assert str(exc) == _INVALID_MESSAGE
        assert exc.args == (_INVALID_MESSAGE,)

    def test_password_reset_invalid_token_error_is_an_exception(self, pr: ModuleType) -> None:
        assert issubclass(pr.InvalidResetTokenError, Exception)

    def test_password_reset_fake_lifetime_matches(self, pr: ModuleType) -> None:
        """The test fake stores the same lifetime the module declares."""
        assert pr.RESET_TOKEN_LIFETIME == FAKE_LIFETIME


# ---------------------------------------------------------------------------
# 2. request_reset: the account lookup
# ---------------------------------------------------------------------------


class TestRequestLookup:
    """One parameterized, case-insensitive fetchrow on the pool."""

    @pytest.mark.parametrize("cause", ["eligible", *_NOT_SENT_CAUSES])
    async def test_password_reset_request_looks_up_lower_email_once(
        self, pr: ModuleType, db: FakeDb, cause: str
    ) -> None:
        """WHERE lower(email) = lower($1), the email the only bind parameter, on the pool."""
        if cause == "eligible":
            _add_active(db)
        else:
            _setup_cause(db, cause)

        await _request(pr, db)

        lookup = _one(
            [
                call
                for call in db.calls
                if call.method == "fetchrow"
                and re.search(r"\bfrom users\b", call.normalized)
                and "password_reset_tokens" not in call.normalized
            ]
        )
        assert re.search(r"lower\((?:\w+\.)?email\) = lower\(\$1\)", lookup.normalized)
        assert len(lookup.args) == 1
        assert lookup.args[0].casefold() == _EMAIL.casefold()
        assert _EMAIL.casefold() not in lookup.normalized
        assert (lookup.via, lookup.tx) == ("pool", None)

    async def test_password_reset_request_lookup_left_joins_organizations(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """The org status comes from a LEFT JOIN (a Super Admin has no org)."""
        _add_active(db)

        await _request(pr, db)

        lookup = db.calls[0]
        assert re.search(r"\bleft (?:outer )?join organizations\b", lookup.normalized)

    async def test_password_reset_request_email_is_case_insensitive(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """Another casing of the address still reaches the account."""
        _add_active(db)

        await _request(pr, db, email="RESET.marker@example.TEST")

        assert len(db.reset_links()) == 1

    @pytest.mark.parametrize("cause", ["eligible", *_NOT_SENT_CAUSES])
    async def test_password_reset_request_email_only_in_the_lookup(
        self, pr: ModuleType, db: FakeDb, cause: str
    ) -> None:
        """No other statement (upsert, outbox, audit) carries the email in SQL or args."""
        if cause == "eligible":
            _add_active(db)
        else:
            _setup_cause(db, cause)

        await _request(pr, db)

        carrying = [call for call in db.calls if _carries_email(call)]
        assert len(carrying) == 1
        assert carrying[0] is db.calls[0]


# ---------------------------------------------------------------------------
# 3. request_reset: an eligible account gets a token and an email
# ---------------------------------------------------------------------------


class TestRequestEligible:
    """A token row, one queued email with the link, and the audit event."""

    @pytest.mark.parametrize("who", list(_ELIGIBLE))
    async def test_password_reset_request_returns_none(
        self, pr: ModuleType, db: FakeDb, who: str
    ) -> None:
        """Never the token: admins reusing this flow can't see it."""
        _add_active(db, **_ELIGIBLE[who])

        assert await _request(pr, db) is None

    @pytest.mark.parametrize("who", list(_ELIGIBLE))
    async def test_password_reset_request_queues_one_reset_email(
        self, pr: ModuleType, db: FakeDb, who: str
    ) -> None:
        """One password_reset outbox row for the account (address and language come from
        the users row inside the outbox statement)."""
        user_id = _add_active(db, **_ELIGIBLE[who])

        await _request(pr, db)

        assert len(db.outbox) == 1
        assert db.outbox[0]["user_id"] == user_id
        assert db.outbox[0]["template_key"] == "password_reset"
        assert set(db.outbox[0]["params"]) == {"reset_link", "expires_at"}

    async def test_password_reset_request_link_is_public_url_with_fragment_token(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """reset_link == f"{public_url}/reset-password#token={token}"."""
        _add_active(db)

        await _request(pr, db)

        link = db.reset_links()[0]
        assert link.startswith(LINK_PREFIX)
        assert TOKEN_RE.fullmatch(link[len(LINK_PREFIX) :]) is not None

    @pytest.mark.parametrize(
        "public_url",
        ["https://reset.example.org", "https://admino.example.ch:8443", "http://localhost:8000"],
    )
    async def test_password_reset_request_link_uses_the_given_public_url(
        self, pr: ModuleType, db: FakeDb, public_url: str
    ) -> None:
        """The link base is exactly the public_url passed in (the configured one)."""
        _add_active(db)

        await _request(pr, db, public_url=public_url)

        link = db.reset_links()[0]
        prefix = f"{public_url}/reset-password#token="
        assert link.startswith(prefix)
        assert TOKEN_RE.fullmatch(link[len(prefix) :]) is not None

    async def test_password_reset_request_token_carries_256_bits(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """43 URL-safe characters decode to 32 random bytes."""
        _add_active(db)

        token = await _issue(pr, db)

        assert len(base64.urlsafe_b64decode(token + "=")) == 32

    async def test_password_reset_request_tokens_are_unique(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """Every request mints a new token."""
        _add_active(db)

        for _ in range(5):
            await _request(pr, db)

        tokens = [link[len(LINK_PREFIX) :] for link in db.reset_links()]
        assert len(set(tokens)) == 5

    async def test_password_reset_request_stores_only_the_token_hash(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """The stored token_hash is the 32-byte SHA-256 digest of the emailed token."""
        user_id = _add_active(db)

        token = await _issue(pr, db)

        assert db.tokens[user_id]["token_hash"] == sha256(token)
        assert len(db.tokens[user_id]["token_hash"]) == 32

    async def test_password_reset_request_email_expiry_is_the_upserted_expiry(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """The email's expires_at is the value the upsert returned (the row's expiry)."""
        user_id = _add_active(db)

        await _request(pr, db)

        sent = datetime.fromisoformat(db.outbox[0]["params"]["expires_at"])
        assert sent == db.tokens[user_id]["expires_at"]
        assert sent.tzinfo is not None

    async def test_password_reset_request_writes_in_one_transaction(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """The upsert, the outbox row and the audit event run on one acquired connection
        inside one transaction, which commits."""
        _add_active(db)

        await _request(pr, db)

        upsert = _upsert(db)
        outbox = _one(db.matching(r"^insert into email_outbox\b"))
        audit = _one(db.matching(r"^insert into audit_events\b"))
        assert upsert.via != "pool"
        assert upsert.tx is not None
        assert {(c.via, c.tx) for c in (upsert, outbox, audit)} == {(upsert.via, upsert.tx)}
        assert (upsert.tx, "commit") in db.transactions

    async def test_password_reset_request_upserts_before_queueing(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """The email is queued after the upsert (it carries the upsert's expires_at)."""
        _add_active(db)

        await _request(pr, db)

        assert db.calls.index(_upsert(db)) < db.calls.index(
            _one(db.matching(r"^insert into email_outbox\b"))
        )

    @pytest.mark.parametrize("who", list(_ELIGIBLE))
    async def test_password_reset_request_is_audited_with_the_account(
        self, pr: ModuleType, db: FakeDb, who: str
    ) -> None:
        """password_reset.request: the account as actor, its org, target user [id], the IP,
        metadata {"email_sent": true}."""
        user_id = _add_active(db, **_ELIGIBLE[who])
        account = db.users[user_id]

        await _request(pr, db)

        rows = db.audit_rows()
        assert len(rows) == 1
        row = rows[0]
        assert row["action"] == "password_reset.request"
        assert row["actor_kind"] == account["kind"]
        assert row["actor_user_id"] == user_id
        assert row["org_id"] == (ORG_ID if account["kind"] == "member" else None)
        assert row["target_type"] == "user"
        assert row["target_ids"] == [str(user_id)]
        assert row["ip"] == _IP
        assert row["metadata"] == {"email_sent": True}
        assert type(row["metadata"]["email_sent"]) is bool

    async def test_password_reset_request_non_ip_peer_is_audited_without_ip(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """A peer that isn't an IP address (e.g. 'testclient') is stored as NULL."""
        _add_active(db)

        await _request(pr, db, ip="testclient")

        assert db.audit_rows()[0]["ip"] is None

    async def test_password_reset_request_again_replaces_the_token(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """A newer request leaves one token row for the user, holding the newest hash."""
        user_id = _add_active(db)

        await _request(pr, db)
        await _request(pr, db)

        assert list(db.tokens) == [user_id]
        assert db.tokens[user_id]["token_hash"] == sha256(db.issued_token(-1))
        assert len(db.reset_links()) == 2


# ---------------------------------------------------------------------------
# 4. request_reset: the upsert statement
# ---------------------------------------------------------------------------


class TestRequestUpsert:
    """INSERT ... VALUES (digest, user, now() + 30 minutes) ON CONFLICT (user_id) DO UPDATE
    ... RETURNING expires_at, through fetchval."""

    async def test_password_reset_upsert_is_a_fetchval_returning_expires_at(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        _add_active(db)

        await _request(pr, db)

        upsert = _upsert(db)
        assert upsert.method == "fetchval"
        assert re.search(r"\breturning (?:\w+\.)?expires_at\s*$", upsert.normalized)

    async def test_password_reset_upsert_binds_the_digest_and_the_user(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """token_hash is bound to the 32-byte digest and user_id to the account's id."""
        user_id = _add_active(db)

        token = await _issue(pr, db)

        upsert = _upsert(db)
        values = _insert_values(upsert)
        assert set(values) == {"token_hash", "user_id", "expires_at"}
        assert _bound(upsert, values["token_hash"]) == sha256(token)
        assert _bound(upsert, values["user_id"]) == user_id

    async def test_password_reset_upsert_expiry_is_now_plus_30_minutes(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """expires_at is computed by the database: now() + 30 minutes (the same clock as
        created_at, so the CHECK constraint holds)."""
        _add_active(db)

        await _request(pr, db)

        upsert = _upsert(db)
        assert re.match(rf"{_NOW_SQL} \+ ", _insert_values(upsert)["expires_at"])
        assert _upsert_lifetime(upsert) == timedelta(minutes=30)

    async def test_password_reset_upsert_replaces_the_users_row(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """ON CONFLICT (user_id) DO UPDATE sets a new token_hash, created_at and expires_at,
        so the older token's hash no longer exists."""
        _add_active(db)

        await _request(pr, db)

        sql = _upsert(db).normalized
        match = re.search(r"\bon conflict \(\s*user_id\s*\) do update set (.*?) returning\b", sql)
        assert match is not None, sql
        updates = match.group(1)
        assert re.search(r"\btoken_hash = (?:excluded\.token_hash|\$\d+)", updates)
        assert re.search(
            rf"\bcreated_at = (?:{_NOW_SQL}|excluded\.created_at|default)(?:\s|,|$)", updates
        )
        assert re.search(rf"\bexpires_at = (?:excluded\.expires_at|{_NOW_SQL} \+ )", updates)

    async def test_password_reset_raw_token_is_bound_only_inside_the_email_link(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """The raw token is in no SQL text and no bind argument, except the queued email's
        params, and there only as part of reset_link."""
        _add_active(db)

        token = await _issue(pr, db)

        carrying = [call for call in db.calls if _carries(call, token)]
        outbox = _one(carrying)
        assert outbox.normalized.startswith("insert into email_outbox")
        assert token not in outbox.sql
        params = json.loads(outbox.args[2])
        assert token in params["reset_link"]
        assert token not in params["expires_at"]


# ---------------------------------------------------------------------------
# 5. request_reset: unknown or ineligible accounts
# ---------------------------------------------------------------------------


class TestRequestNotSent:
    """No token and no email, but the same None for the caller, and an audit event."""

    @pytest.mark.parametrize("cause", list(_NOT_SENT_CAUSES))
    async def test_password_reset_request_not_sent_returns_none(
        self, pr: ModuleType, db: FakeDb, cause: str
    ) -> None:
        """Nothing is raised and nothing is returned: the caller can't tell."""
        _setup_cause(db, cause)

        assert await _request(pr, db) is None

    @pytest.mark.parametrize("cause", list(_NOT_SENT_CAUSES))
    async def test_password_reset_request_not_sent_creates_no_token_or_email(
        self, pr: ModuleType, db: FakeDb, cause: str
    ) -> None:
        """No statement touches password_reset_tokens or email_outbox."""
        _setup_cause(db, cause)

        await _request(pr, db)

        assert db.tokens == {}
        assert db.outbox == []
        assert db.matching(r"password_reset_tokens|email_outbox") == []

    async def test_password_reset_request_unknown_email_is_audited_as_system(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """A system actor, no user, no org, no target, the IP, email_sent false; written
        through the pool."""
        _setup_cause(db, "unknown")

        await _request(pr, db)

        rows = db.audit_rows()
        assert len(rows) == 1
        row = rows[0]
        assert row["action"] == "password_reset.request"
        assert (row["actor_kind"], row["actor_user_id"], row["org_id"]) == ("system", None, None)
        assert (row["target_type"], row["target_ids"]) == (None, [])
        assert row["ip"] == _IP
        assert row["metadata"] == {"email_sent": False}
        assert _one(db.matching(r"^insert into audit_events\b")).via == "pool"

    @pytest.mark.parametrize("cause", _KNOWN_NOT_SENT)
    async def test_password_reset_request_ineligible_is_audited_with_the_account(
        self, pr: ModuleType, db: FakeDb, cause: str
    ) -> None:
        """The account as actor (kind, id, org), target user [id], the IP, email_sent false."""
        user_id = _setup_cause(db, cause)
        assert user_id is not None
        account = db.users[user_id]

        await _request(pr, db)

        rows = db.audit_rows()
        assert len(rows) == 1
        row = rows[0]
        assert row["action"] == "password_reset.request"
        assert row["actor_kind"] == account["kind"]
        assert row["actor_user_id"] == user_id
        assert row["org_id"] == (ORG_ID if account["kind"] == "member" else None)
        assert row["target_type"] == "user"
        assert row["target_ids"] == [str(user_id)]
        assert row["ip"] == _IP
        assert row["metadata"] == {"email_sent": False}

    @pytest.mark.parametrize("cause", list(_NOT_SENT_CAUSES))
    async def test_password_reset_request_not_sent_mints_no_hash_work(
        self, pr: ModuleType, db: FakeDb, cause: str, hash_spy: _HashSpy
    ) -> None:
        """A request never hashes a password."""
        _setup_cause(db, cause)

        await _request(pr, db)

        assert hash_spy.calls == []


# ---------------------------------------------------------------------------
# 6. request_reset: a failed audit record rolls everything back
# ---------------------------------------------------------------------------


class TestRequestAuditFailure:
    """Fail closed: no token and no email without the audit event."""

    async def test_password_reset_request_audit_failure_propagates(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        _add_active(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _request(pr, db)

    async def test_password_reset_request_audit_failure_rolls_back(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """The transaction is rolled back: no token row and no queued email remain."""
        _add_active(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _request(pr, db)

        assert db.tokens == {}
        assert db.outbox == []
        assert db.transactions == [(_upsert(db).tx, "rollback:AuditRecordError")]


# ---------------------------------------------------------------------------
# 7. confirm_reset: a malformed token never reaches the database
# ---------------------------------------------------------------------------

_MALFORMED_TOKENS: list[Any] = [
    pytest.param("", id="empty"),
    pytest.param("short", id="short"),
    pytest.param("A" * 42, id="42-chars"),
    pytest.param("A" * 44, id="44-chars"),
    pytest.param("A" * 42 + "=", id="padding"),
    pytest.param("A" * 42 + "+", id="plus"),
    pytest.param("A" * 42 + "/", id="slash"),
    pytest.param("A" * 42 + ".", id="dot"),
    pytest.param("A" * 42 + " ", id="space"),
    pytest.param("A" * 43 + "\n", id="trailing-newline"),
    pytest.param("A" * 42 + chr(0xE9), id="non-ascii-letter"),
    pytest.param("A" * 42 + chr(0xFF11), id="fullwidth-digit"),
    pytest.param("A" * 42 + chr(0), id="nul"),
    pytest.param("' OR 1=1 --" + "A" * 32, id="sql-ish"),
    pytest.param(None, id="none"),
    pytest.param(b"A" * 43, id="bytes"),
    pytest.param(12345, id="int"),
]


class TestConfirmMalformedToken:
    """A value that can't be a token_urlsafe(32) token is refused without a query."""

    @pytest.mark.parametrize("token", _MALFORMED_TOKENS)
    async def test_password_reset_confirm_malformed_token_is_refused_without_query(
        self, pr: ModuleType, db: FakeDb, token: Any, hash_spy: _HashSpy
    ) -> None:
        """InvalidResetTokenError, no database call and no hashing."""
        _add_active(db)

        with pytest.raises(pr.InvalidResetTokenError) as exc_info:
            await _confirm(pr, db, token)

        assert str(exc_info.value) == _INVALID_MESSAGE
        assert db.calls == []
        assert hash_spy.calls == []

    async def test_password_reset_confirm_malformed_token_beats_a_policy_failure(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """A bad token with a too-short password is still just an invalid link."""
        with pytest.raises(pr.InvalidResetTokenError):
            await _confirm(pr, db, "short", new_password="short")


# ---------------------------------------------------------------------------
# 8. confirm_reset: the token lookup
# ---------------------------------------------------------------------------


class TestConfirmLookup:
    """One pool.fetchrow by the token's hash, joined to users and organizations."""

    async def test_password_reset_confirm_looks_up_by_hash_only(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """The digest is the only bind parameter; the raw token is nowhere in the call."""
        _add_active(db)
        token = await _issue(pr, db)
        db.calls.clear()

        await _confirm(pr, db, token)

        lookup = _one(_token_lookups(db))
        assert lookup.method == "fetchrow"
        assert (lookup.via, lookup.tx) == ("pool", None)
        assert lookup.args == (sha256(token),)
        assert not _carries(lookup, token)

    async def test_password_reset_confirm_lookup_joins_users_and_organizations(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        _add_active(db)
        token = await _issue(pr, db)
        db.calls.clear()

        await _confirm(pr, db, token)

        sql = _one(_token_lookups(db)).normalized
        assert re.search(r"\bjoin users\b", sql)
        assert re.search(r"\bjoin organizations\b", sql)

    async def test_password_reset_confirm_unknown_token_is_refused(
        self, pr: ModuleType, db: FakeDb, hash_spy: _HashSpy
    ) -> None:
        """A well-formed token that was never issued: refused after the lookup, nothing
        written, no hashing."""
        user_id = _add_active(db)

        with pytest.raises(pr.InvalidResetTokenError):
            await _confirm(pr, db, "Q" * 21 + "-" + "z" * 20 + "_")

        assert len(db.calls) == 1
        assert _writes(db) == []
        assert hash_spy.calls == []
        assert db.users[user_id]["password_hash"] == "fake$initial"


# ---------------------------------------------------------------------------
# 9. confirm_reset: expired tokens and accounts that may no longer log in
# ---------------------------------------------------------------------------


def _expire(db: FakeDb, user_id: uuid.UUID, when: str) -> None:
    """Move the stored token's expiry: 'past', 'exactly-now' or 'one-second-left'."""
    now = datetime.now(UTC)
    values = {
        "past": now - timedelta(seconds=1),
        "long-past": now - timedelta(days=2),
        "exactly-now": _exactly_now(),
        "one-second-left": now + timedelta(seconds=1),
    }
    db.tokens[user_id]["expires_at"] = values[when]


# Changes to the account between the request and the confirm.
_BECAME_INELIGIBLE: list[Any] = [
    pytest.param({"status": "deactivated"}, id="deactivated"),
    pytest.param({"status": "invited"}, id="invited"),
    pytest.param({"deleted_at": _DELETED_AT}, id="deleted"),
    pytest.param({"org_status": "deactivated"}, id="org-deactivated"),
    pytest.param({"org_status": "pending_deletion"}, id="org-pending-deletion"),
]


class TestConfirmRefused:
    """Expired tokens and ineligible accounts: InvalidResetTokenError, nothing written."""

    @pytest.mark.parametrize("when", ["past", "long-past", "exactly-now"])
    async def test_password_reset_confirm_expired_token_is_refused(
        self, pr: ModuleType, db: FakeDb, when: str, hash_spy: _HashSpy
    ) -> None:
        """expires_at <= now: refused after the lookup alone (the token isn't consumed, no
        hashing, no other statement)."""
        user_id = _add_active(db)
        token = await _issue(pr, db)
        _expire(db, user_id, when)
        db.calls.clear()

        with pytest.raises(pr.InvalidResetTokenError) as exc_info:
            await _confirm(pr, db, token)

        assert str(exc_info.value) == _INVALID_MESSAGE
        assert len(db.calls) == 1
        assert hash_spy.calls == []
        assert db.users[user_id]["password_hash"] == "fake$initial"
        assert user_id in db.tokens

    async def test_password_reset_confirm_one_second_before_expiry_works(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """A token with a second left is still accepted."""
        user_id = _add_active(db)
        token = await _issue(pr, db)
        _expire(db, user_id, "one-second-left")

        await _confirm(pr, db, token)

        assert db.users[user_id]["password_hash"] == fake_hash(_NEW_PASSWORD)

    @pytest.mark.parametrize("change", _BECAME_INELIGIBLE)
    async def test_password_reset_confirm_ineligible_account_is_refused(
        self, pr: ModuleType, db: FakeDb, change: dict[str, Any], hash_spy: _HashSpy
    ) -> None:
        """An account deactivated, deleted or left without an active org after the request
        can't use its link: refused after the lookup alone."""
        user_id = _add_active(db)
        session = db.open_session(user_id)
        token = await _issue(pr, db)
        db.users[user_id].update(change)
        db.calls.clear()

        with pytest.raises(pr.InvalidResetTokenError):
            await _confirm(pr, db, token)

        assert len(db.calls) == 1
        assert hash_spy.calls == []
        assert db.users[user_id]["password_hash"] == "fake$initial"
        assert not db.session_revoked(session)
        assert user_id in db.tokens

    @pytest.mark.parametrize(
        "change",
        [
            pytest.param({"status": "deactivated"}, id="deactivated"),
            pytest.param({"deleted_at": _DELETED_AT}, id="deleted"),
        ],
    )
    async def test_password_reset_confirm_ineligible_super_admin_is_refused(
        self, pr: ModuleType, db: FakeDb, change: dict[str, Any]
    ) -> None:
        user_id = _add_active(db, **_super_admin_fields())
        token = await _issue(pr, db)
        db.users[user_id].update(change)

        with pytest.raises(pr.InvalidResetTokenError):
            await _confirm(pr, db, token)

        assert db.users[user_id]["password_hash"] == "fake$initial"

    async def test_password_reset_confirm_expired_token_beats_a_policy_failure(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """The token is checked before the policy: an expired link with a too-short
        password is an invalid link, not a policy error."""
        user_id = _add_active(db)
        token = await _issue(pr, db)
        _expire(db, user_id, "past")

        with pytest.raises(pr.InvalidResetTokenError):
            await _confirm(pr, db, token, new_password="short")

    async def test_password_reset_confirm_refusal_carries_no_input(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """The error names neither the token nor the password."""
        user_id = _add_active(db)
        token = await _issue(pr, db)
        _expire(db, user_id, "past")

        with pytest.raises(pr.InvalidResetTokenError) as exc_info:
            await _confirm(pr, db, token)

        rendered = f"{exc_info.value!s} {exc_info.value!r} {exc_info.value.args!r}"
        assert token not in rendered
        assert _NEW_PASSWORD not in rendered


# ---------------------------------------------------------------------------
# 10. confirm_reset: the password policy
# ---------------------------------------------------------------------------

_POLICY_FAILURES: list[Any] = [
    pytest.param("Kq7#vX9!pL2", "too_short", id="11-chars"),
    pytest.param("Kq7#vX9!pL2m" * 10 + "Kq7#vX9!p", "too_long", id="129-chars"),
    pytest.param("Qwerty123456", "common", id="common-any-case"),
    pytest.param(_EMAIL.lower(), "equals_email", id="equals-email-other-case"),
]


class TestConfirmPolicy:
    """The policy is applied with the account's email; a failure writes nothing."""

    @pytest.mark.parametrize(("password", "reason"), _POLICY_FAILURES)
    async def test_password_reset_confirm_policy_failure_propagates(
        self, pr: ModuleType, db: FakeDb, password: str, reason: str
    ) -> None:
        """passwords.PasswordPolicyError with the policy's reason, unchanged."""
        _add_active(db)
        token = await _issue(pr, db)

        with pytest.raises(passwords.PasswordPolicyError) as exc_info:
            await _confirm(pr, db, token, new_password=password)

        assert exc_info.value.reason == reason
        assert str(exc_info.value) == str(passwords.PasswordPolicyError(reason))

    @pytest.mark.parametrize(("password", "reason"), _POLICY_FAILURES)
    async def test_password_reset_confirm_policy_failure_writes_nothing(
        self, pr: ModuleType, db: FakeDb, password: str, reason: str, hash_spy: _HashSpy
    ) -> None:
        """Only the lookup ran: no hashing, the token isn't consumed, sessions stay."""
        user_id = _add_active(db)
        session = db.open_session(user_id)
        token = await _issue(pr, db)
        db.calls.clear()

        with pytest.raises(passwords.PasswordPolicyError):
            await _confirm(pr, db, token, new_password=password)

        assert len(db.calls) == 1
        assert hash_spy.calls == []
        assert db.tokens[user_id]["token_hash"] == sha256(token)
        assert not db.session_revoked(session)
        assert db.audit_rows("password_reset.complete") == []

    @pytest.mark.parametrize(("password", "reason"), _POLICY_FAILURES)
    async def test_password_reset_confirm_token_stays_usable_after_policy_failure(
        self, pr: ModuleType, db: FakeDb, password: str, reason: str
    ) -> None:
        """The user can retry with a better password and the same link."""
        user_id = _add_active(db)
        token = await _issue(pr, db)
        with pytest.raises(passwords.PasswordPolicyError):
            await _confirm(pr, db, token, new_password=password)

        await _confirm(pr, db, token)

        assert db.users[user_id]["password_hash"] == fake_hash(_NEW_PASSWORD)

    @pytest.mark.parametrize(
        "password",
        [
            pytest.param("Kq7#vX9!pL2m", id="12-chars"),
            pytest.param("Kq7#vX9!pL2m" * 10 + "Kq7#vX9!", id="128-chars"),
        ],
    )
    async def test_password_reset_confirm_policy_bounds_are_accepted(
        self, pr: ModuleType, db: FakeDb, password: str
    ) -> None:
        user_id = _add_active(db)
        token = await _issue(pr, db)

        await _confirm(pr, db, token, new_password=password)

        assert db.users[user_id]["password_hash"] == fake_hash(password)

    async def test_password_reset_confirm_policy_uses_the_accounts_email(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """The email compared is the account's own (from the token row)."""
        other_email = "Another.Owner@Example.test"
        _add_active(db, email=other_email)
        await _request(pr, db, email=other_email)
        token = db.issued_token()

        with pytest.raises(passwords.PasswordPolicyError) as exc_info:
            await _confirm(pr, db, token, new_password=other_email.upper())

        assert exc_info.value.reason == "equals_email"


# ---------------------------------------------------------------------------
# 11. confirm_reset: success
# ---------------------------------------------------------------------------


class TestConfirmSuccess:
    """Token consumed, new hash stored, every session deleted, audited: one transaction."""

    async def test_password_reset_confirm_returns_none(self, pr: ModuleType, db: FakeDb) -> None:
        _add_active(db)
        token = await _issue(pr, db)

        assert await _confirm(pr, db, token) is None

    async def test_password_reset_confirm_stores_the_new_hash(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """UPDATE users SET password_hash = $1 WHERE id = $2 with the new hash and the id."""
        user_id = _add_active(db)
        token = await _issue(pr, db)

        await _confirm(pr, db, token)

        update = _one(
            db.matching(r"^update users set password_hash = \$1 where (?:\w+\.)?id = \$2")
        )
        assert update.args[:2] == (fake_hash(_NEW_PASSWORD), user_id)
        assert db.users[user_id]["password_hash"] == fake_hash(_NEW_PASSWORD)

    async def test_password_reset_confirm_hashes_once_off_the_event_loop(
        self, pr: ModuleType, db: FakeDb, hash_spy: _HashSpy
    ) -> None:
        """passwords.hash_password runs once, with the new password, in a worker thread."""
        _add_active(db)
        token = await _issue(pr, db)

        await _confirm(pr, db, token)

        assert hash_spy.calls == [_NEW_PASSWORD]
        assert threading.get_ident() not in hash_spy.threads

    async def test_password_reset_confirm_consumes_the_token_atomically(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """DELETE FROM password_reset_tokens WHERE token_hash = $1 AND user_id = $2 AND
        expires_at > now() RETURNING user_id, through fetchval."""
        user_id = _add_active(db)
        token = await _issue(pr, db)

        await _confirm(pr, db, token)

        consume = _consume(db)
        sql = consume.normalized
        assert consume.method == "fetchval"
        assert re.search(r"\btoken_hash = \$1\b", sql)
        assert re.search(r"\buser_id = \$2\b", sql)
        assert re.search(rf"\bexpires_at > {_NOW_SQL}", sql)
        assert re.search(r"\breturning (?:\w+\.)?user_id\s*$", sql)
        assert consume.args[:2] == (sha256(token), user_id)
        assert user_id not in db.tokens

    async def test_password_reset_confirm_deletes_every_session_of_the_user(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """All the user's session rows are deleted; another user's sessions are untouched."""
        user_id = _add_active(db)
        other_id = db.add_account(email="bystander@example.test")
        mine = [db.open_session(user_id) for _ in range(3)]
        theirs = db.open_session(other_id)
        token = await _issue(pr, db)

        await _confirm(pr, db, token)

        assert all(db.session_revoked(session) for session in mine)
        assert not db.session_revoked(theirs)

    async def test_password_reset_confirm_revokes_through_revoke_user_sessions(
        self, pr: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The shared service (#166 reuses it) is called once, on the transaction's
        connection, with the user's id."""
        user_id = _add_active(db)
        token = await _issue(pr, db)
        real = sessions.revoke_user_sessions
        seen: list[tuple[Any, Any, bool]] = []

        async def spy(executor: Any, target: Any) -> int:
            in_transaction = executor is not db.pool and executor.is_in_transaction()
            seen.append((executor, target, in_transaction))
            count: int = await real(executor, target)
            return count

        monkeypatch.setattr(sessions, "revoke_user_sessions", spy)

        await _confirm(pr, db, token)

        assert len(seen) == 1
        executor, target, in_transaction = seen[0]
        assert target == user_id
        assert executor is not db.pool
        assert in_transaction
        assert executor.name == _consume(db).via

    @pytest.mark.parametrize("who", list(_ELIGIBLE))
    async def test_password_reset_confirm_is_audited_with_the_revoked_count(
        self, pr: ModuleType, db: FakeDb, who: str
    ) -> None:
        """password_reset.complete: the account as actor, its org, target user [id], the IP,
        metadata {"sessions_revoked": <session rows of the user deleted>}; another user's
        session isn't counted."""
        user_id = _add_active(db, **_ELIGIBLE[who])
        account = db.users[user_id]
        db.open_session(user_id)
        db.open_session(user_id)
        db.open_session(db.add_account(email="bystander@example.test"))
        token = await _issue(pr, db)

        await _confirm(pr, db, token)

        rows = db.audit_rows("password_reset.complete")
        assert len(rows) == 1
        row = rows[0]
        assert row["actor_kind"] == account["kind"]
        assert row["actor_user_id"] == user_id
        assert row["org_id"] == (ORG_ID if account["kind"] == "member" else None)
        assert row["target_type"] == "user"
        assert row["target_ids"] == [str(user_id)]
        assert row["ip"] == _IP
        assert row["metadata"] == {"sessions_revoked": 2}
        assert type(row["metadata"]["sessions_revoked"]) is int

    async def test_password_reset_confirm_without_sessions_records_zero(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        _add_active(db)
        token = await _issue(pr, db)

        await _confirm(pr, db, token)

        assert db.audit_rows("password_reset.complete")[0]["metadata"] == {"sessions_revoked": 0}

    async def test_password_reset_confirm_writes_in_one_committed_transaction(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """Consume, password update, session deletion and audit share one connection and
        one transaction, which commits; the token is consumed first and the audit is last."""
        _add_active(db)
        token = await _issue(pr, db)
        db.calls.clear()
        db.transactions.clear()

        await _confirm(pr, db, token)

        consume = _consume(db)
        assert consume.via != "pool"
        assert consume.tx is not None
        in_tx = [call for call in db.calls if call.tx == consume.tx]
        kinds = [call.normalized.split(" (")[0][:40] for call in in_tx]
        assert in_tx[0] is consume, kinds
        assert in_tx[-1].normalized.startswith("insert into audit_events"), kinds
        assert _one(db.matching(r"^update users set password_hash")).tx == consume.tx
        assert _one(db.matching(r"^delete from sessions\b")).tx == consume.tx
        assert db.matching(r"^update sessions\b") == []
        assert db.transactions == [(consume.tx, "commit")]
        assert {call.via for call in _writes(db)} == {consume.via}

    async def test_password_reset_confirm_never_binds_the_password_or_token(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """Only the hash and the digest travel to SQL, never the plain values."""
        _add_active(db)
        token = await _issue(pr, db)
        db.calls.clear()

        await _confirm(pr, db, token)

        assert [call for call in db.calls if _carries(call, _NEW_PASSWORD)] == []
        assert [call for call in db.calls if _carries(call, token)] == []


# ---------------------------------------------------------------------------
# 12. confirm_reset: the consume loses a race
# ---------------------------------------------------------------------------


class TestConfirmConsumeRace:
    """The token vanished, changed or expired between the lookup and the DELETE."""

    @pytest.mark.parametrize("race", ["used-concurrently", "superseded", "just-expired"])
    async def test_password_reset_confirm_lost_race_is_refused_and_writes_nothing(
        self, pr: ModuleType, db: FakeDb, race: str
    ) -> None:
        """The DELETE returns no row: InvalidResetTokenError, and no password update, no
        session deletion and no audit statement follow."""
        user_id = _add_active(db)
        session = db.open_session(user_id)
        token = await _issue(pr, db)

        def interfere() -> None:
            if race == "used-concurrently":
                del db.tokens[user_id]
            elif race == "superseded":
                db.tokens[user_id]["token_hash"] = sha256("N" * 43)
            else:
                db.tokens[user_id]["expires_at"] = datetime.now(UTC) - timedelta(seconds=1)

        db.after_token_lookup = interfere
        db.calls.clear()

        with pytest.raises(pr.InvalidResetTokenError):
            await _confirm(pr, db, token)

        assert db.matching(r"^update users\b") == []
        assert db.matching(r"^(?:update|delete from) sessions\b") == []
        assert db.matching(r"^insert into audit_events\b") == []
        assert db.users[user_id]["password_hash"] == "fake$initial"
        assert not db.session_revoked(session)


# ---------------------------------------------------------------------------
# 13. confirm_reset: a failed audit record rolls everything back
# ---------------------------------------------------------------------------


class TestConfirmAuditFailure:
    """Fail closed: no password change, no session deletion and no consumed token
    unaudited."""

    async def test_password_reset_confirm_audit_failure_propagates_and_rolls_back(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        user_id = _add_active(db)
        session = db.open_session(user_id)
        token = await _issue(pr, db)
        db.fail_audit = True
        db.transactions.clear()

        with pytest.raises(AuditRecordError):
            await _confirm(pr, db, token)

        assert db.users[user_id]["password_hash"] == "fake$initial"
        assert not db.session_revoked(session)
        assert db.tokens[user_id]["token_hash"] == sha256(token)
        assert [outcome for _, outcome in db.transactions] == ["rollback:AuditRecordError"]


# ---------------------------------------------------------------------------
# 14. The lifecycle: single use, invalidation, expiry
# ---------------------------------------------------------------------------


class TestResetLifecycle:
    """End to end through the fake: a link works once, only the newest link works."""

    async def test_password_reset_token_is_single_use(self, pr: ModuleType, db: FakeDb) -> None:
        """A second confirm with the same token is refused and changes nothing."""
        user_id = _add_active(db)
        token = await _issue(pr, db)
        await _confirm(pr, db, token)
        session = db.open_session(user_id)

        with pytest.raises(pr.InvalidResetTokenError):
            await _confirm(pr, db, token, new_password=_OTHER_PASSWORD)

        assert db.users[user_id]["password_hash"] == fake_hash(_NEW_PASSWORD)
        assert not db.session_revoked(session)
        assert len(db.audit_rows("password_reset.complete")) == 1

    async def test_password_reset_newer_request_invalidates_the_older_token(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """After a second request the first link is refused; the second one works."""
        user_id = _add_active(db)
        first = await _issue(pr, db)
        second = await _issue(pr, db)

        with pytest.raises(pr.InvalidResetTokenError):
            await _confirm(pr, db, first)
        assert db.users[user_id]["password_hash"] == "fake$initial"

        await _confirm(pr, db, second)
        assert db.users[user_id]["password_hash"] == fake_hash(_NEW_PASSWORD)

    async def test_password_reset_tokens_are_per_user(self, pr: ModuleType, db: FakeDb) -> None:
        """A request by another user leaves this user's link valid."""
        user_id = _add_active(db)
        db.add_account(email="colleague@example.test")
        token = await _issue(pr, db)
        await _request(pr, db, email="colleague@example.test")

        await _confirm(pr, db, token)

        assert db.users[user_id]["password_hash"] == fake_hash(_NEW_PASSWORD)


# ---------------------------------------------------------------------------
# 15. No email, token, password or link in logs, audit rows or errors
# ---------------------------------------------------------------------------


class TestNoContent:
    """Content-free logs and audit rows on every path."""

    async def test_password_reset_logs_nothing_sensitive(
        self, pr: ModuleType, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Requests (eligible, unknown, ineligible) and confirms (policy failure, success,
        reuse) log no email, token, password or link at any level."""
        caplog.set_level(logging.DEBUG)
        _add_active(db)
        db.add_account(email="Ghost.Marker@Example.test", status="deactivated")

        await _request(pr, db)
        await _request(pr, db, email="nobody.marker@example.test")
        await _request(pr, db, email="Ghost.Marker@Example.test")
        token = db.issued_token()
        with pytest.raises(passwords.PasswordPolicyError):
            await _confirm(pr, db, token, new_password="Qwerty123456")
        await _confirm(pr, db, token)
        with pytest.raises(pr.InvalidResetTokenError):
            await _confirm(pr, db, token)

        text = caplog.text.casefold()
        for marker in ("reset.marker", "ghost.marker", "nobody.marker", "example.test"):
            assert marker not in text
        assert token not in caplog.text
        assert _NEW_PASSWORD.casefold() not in text
        assert "reset-password" not in text

    async def test_password_reset_audit_rows_hold_no_content(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """No audit value carries the email, the token, the password or the link."""
        _add_active(db)
        await _request(pr, db)
        await _request(pr, db, email="nobody.marker@example.test")
        token = db.issued_token()
        await _confirm(pr, db, token)

        assert len(db.audit_rows()) == 3
        rendered = " ".join(json.dumps(row, default=str) for row in db.audit_rows()).casefold()
        assert "marker" not in rendered
        assert token.casefold() not in rendered
        assert _NEW_PASSWORD.casefold() not in rendered
        assert "reset-password" not in rendered

    async def test_password_reset_audit_calls_hold_no_content(
        self, pr: ModuleType, db: FakeDb
    ) -> None:
        """The audit INSERT statements themselves carry no email, token or password."""
        _add_active(db)
        token = await _issue(pr, db)
        await _confirm(pr, db, token)

        for call in db.matching(r"^insert into audit_events\b"):
            assert not _carries_email(call)
            assert not _carries(call, token)
            assert not _carries(call, _NEW_PASSWORD)
