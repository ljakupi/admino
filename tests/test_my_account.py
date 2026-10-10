"""Tests for admino.my_account: a signed-in user's own account page (GH-166).

``get_account(pool, *, principal)`` reads the caller's own profile,
``update_account(pool, *, principal, patch)`` changes it
(``admino.models.MyAccountPatch``) and both return
``admino.models.MyAccountResponse``. ``change_password(pool, *, principal,
current_password, new_password, ip)`` sets a new password and returns how many
sessions it ended.

What these tests pin down (the GH-166 contract, section 1.4):
- Authorization first: every function requires ``Capability.ACCOUNT_MANAGE``
  through ``access.can`` (every role and the Super Admin have it); without it,
  or for anything that isn't a Principal, ``PermissionError`` before any
  statement runs.
- Own row only: every users statement is bound to ``principal.user_id`` (never
  a request value) and states ``deleted_at IS NULL``: a deleted or missing
  account is ``AccountNotFoundError`` (its text is ``ACCOUNT_NOT_FOUND_MESSAGE``,
  "Account not found", with no IDs).
- ``update_account`` is ONE ``UPDATE ... RETURNING`` (no SELECT-then-UPDATE):
  only the fields in the patch change; ``response_language`` given as None
  stores NULL (the org default) while an absent one leaves the stored value;
  ``personal_instructions`` "" clears. It returns the stored values, touches no
  other row, writes no audit row (decision D2) and logs nothing.
- ``change_password``, cheapest check first: the account's email is read
  (deleted or missing: ``AccountNotFoundError``); the password policy
  (``passwords.check_password_policy``) runs BEFORE re-authentication, so a
  refused new password costs no throttle counting and no Argon2 work; then
  ``auth.reauthenticate`` (a wrong current password is ``WrongPasswordError``
  and counts in the login throttle like a failed login; a locked account is
  refused even with the right password). The new hash is computed off the
  event loop and outside the transaction; then ONE transaction writes the hash,
  deletes EVERY session of the user (the current one included; other users'
  sessions stay) and records one ``password.change`` audit row (actor, org or
  NULL for a Super Admin, target the user, the IP, metadata exactly
  ``{"sessions_revoked": n}``). A failed audit write rolls everything back.
- No password reaches a log record, an exception, an audit row or any SQL
  argument (only its hash is bound); no name, email, timezone or instructions
  reach a log record; errors carry no IDs.
- GH-307 (Decision 4): ``MyAccountResponse.password_changed_at`` is the
  caller's stored ``users.password_changed_at`` (None until the first change),
  returned by ``get_account`` and ``update_account``. A successful
  ``change_password`` sets it with the database clock (``now()``) in the same
  ``UPDATE`` that stores the new hash (contract C4), so it shares the
  transaction of the session revoke and the audit row. Every refused change
  (wrong current password, policy, a deleted or deactivated account, a failed
  audit write) leaves it as it was; another user's value never changes or
  shows; the audit metadata and the logs gain nothing.

All database calls go to the in-memory tests/db_fakes.FakeDb (``db.pool``).
``passwords.verify_password`` and ``passwords.hash_password`` are fast recording
stand-ins (never real Argon2) and the login throttle's delays are recorded
instead of slept (``login_delays``). ``admino.my_account`` and the new models
are imported per test, so each test fails on its own until they exist.

Security notes:
- Tenant isolation at the data layer: the only user a statement may touch is
  the authenticated principal.
- Fail closed: a refused capability, a deleted account, a wrong current
  password or a failed audit write changes nothing.
- Content-free audit and logs (tracker #139 section 5): IDs and counts only.
"""

from __future__ import annotations

import inspect
import json
import logging
import re
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import access, login_throttle, passwords
from admino.access import Capability, Principal
from admino.audit_events import AuditRecordError
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, account_subject, fake_hash, plain

if TYPE_CHECKING:
    from types import ModuleType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CURRENT: Final = "Account-Marker-Current-Quartz-71"
_NEW: Final = "Account-Marker-Fresh-Basalt-72"
_WRONG: Final = "Account-Marker-Wrong-Slate-73"
_EMAIL: Final = "Own.Account.Marker@Example.test"
_NAME: Final = "Marker Anneliese Account"
_INSTRUCTIONS: Final = "Marker-instructions: I run a fiduciary office, sign off as Anneliese."
_TIMEZONE: Final = "America/Argentina/Buenos_Aires"
_IP: Final = "203.0.113.47"
# The default lockout_after_failures of tests/conftest.py's platform row.
_LIMIT: Final = 10
_NOT_FOUND: Final = "Account not found"
_ACCOUNT_FIELDS: Final = (
    "email",
    "name",
    "ui_language",
    "response_language",
    "timezone",
    "personal_instructions",
    # GH-307: the date of the last password change.
    "password_changed_at",
)
_UUID_RE: Final = re.compile(
    r"[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}", re.IGNORECASE
)
_FUNCTIONS: Final = ("get_account", "update_account", "change_password")


# ---------------------------------------------------------------------------
# Fakes and fixtures
# ---------------------------------------------------------------------------


class _Verifier:
    """Fast stand-in for passwords.verify_password; records each check."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def __call__(self, password: str, encoded: str) -> bool:
        self.calls.append((password, encoded))
        return encoded == fake_hash(password)


class _Hasher:
    """Fast stand-in for passwords.hash_password; records the password, the thread and
    how many transactions were open when it ran."""

    def __init__(self, db: FakeDb) -> None:
        self._db = db
        self.calls: list[str] = []
        self.threads: list[int] = []
        self.open_transactions: list[int] = []

    def __call__(self, password: str) -> str:
        self.calls.append(password)
        self.threads.append(threading.get_ident())
        self.open_transactions.append(self._db.open_transactions)
        return fake_hash(password)


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database with two active orgs."""
    fake = FakeDb()
    fake.add_org(ORG_ID)
    fake.add_org(OTHER_ORG_ID)
    return fake


@pytest.fixture(autouse=True)
def verifier(monkeypatch: pytest.MonkeyPatch, login_delays: list[float]) -> _Verifier:
    """Replace Argon2 verification with the fast spy; record the throttle's delays."""
    spy = _Verifier()
    monkeypatch.setattr(passwords, "verify_password", spy)
    monkeypatch.setattr(passwords, "needs_rehash", lambda _encoded: False)
    return spy


@pytest.fixture(autouse=True)
def hasher(monkeypatch: pytest.MonkeyPatch, db: FakeDb) -> _Hasher:
    """Replace Argon2 hashing with the fast recording spy."""
    spy = _Hasher(db)
    monkeypatch.setattr(passwords, "hash_password", spy)
    return spy


@pytest.fixture()
def ma(monkeypatch: pytest.MonkeyPatch, hasher: _Hasher, verifier: _Verifier) -> ModuleType:
    """admino.my_account, imported per test so each test fails on its own until it exists.

    If the module imported the password functions by name, those names get the
    spies too (the contract calls them through ``passwords``)."""
    from admino import my_account

    if hasattr(my_account, "hash_password"):
        monkeypatch.setattr(my_account, "hash_password", hasher)
    if hasattr(my_account, "verify_password"):
        monkeypatch.setattr(my_account, "verify_password", verifier)
    return my_account


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _member(
    db: FakeDb,
    *,
    role: str = "editor",
    org_id: uuid.UUID = ORG_ID,
    email: str = _EMAIL,
    password: str = _CURRENT,
    **fields: Any,
) -> Principal:
    """An active member whose password is ``password``, and their Principal."""
    user_id = db.add_account(
        role=role, org_id=org_id, email=email, password_hash=fake_hash(password), **fields
    )
    return Principal(user_id=user_id, kind="member", org_id=org_id, role=role)


def _super_admin(
    db: FakeDb, *, email: str = _EMAIL, password: str = _CURRENT, **fields: Any
) -> Principal:
    """An active Super Admin whose password is ``password``, and their Principal."""
    user_id = db.add_account(
        kind="super_admin", role=None, email=email, password_hash=fake_hash(password), **fields
    )
    return Principal(user_id=user_id, kind="super_admin")


def _ghost() -> Principal:
    """A principal whose users row doesn't exist."""
    return Principal(user_id=uuid.uuid4(), kind="member", org_id=ORG_ID, role="editor")


def _patch(**fields: Any) -> Any:
    """A MyAccountPatch whose fields_set is exactly the given keys."""
    from admino.models import MyAccountPatch

    return MyAccountPatch.model_validate(fields)


def _response_type() -> type:
    from admino.models import MyAccountResponse

    return MyAccountResponse


def _stored(db: FakeDb, user_id: uuid.UUID) -> dict[str, Any]:
    """The account self-service columns of a stored users row."""
    return {field: db.users[user_id][field] for field in _ACCOUNT_FIELDS}


def _has_id(text: str) -> bool:
    return _UUID_RE.search(text) is not None


def _bound_user_ids(db: FakeDb) -> set[uuid.UUID]:
    """Every UUID bound to a statement that names the users table."""
    return {
        plain(arg)
        for call in db.calls
        if re.search(r"\busers\b", call.normalized)
        for arg in call.args
        if isinstance(arg, uuid.UUID)
    }


def _log_text(caplog: pytest.LogCaptureFixture) -> str:
    return "\n".join(
        f"{record.name} {record.getMessage()} {record.exc_text or ''} {record.args!r}"
        for record in caplog.records
    ).casefold()


def _deny_account_manage(monkeypatch: pytest.MonkeyPatch, ma: ModuleType) -> list[Any]:
    """access.can (and my_account.can, if imported by name) refuses ACCOUNT_MANAGE only;
    returns the capabilities asked for."""
    real = access.can
    seen: list[Any] = []

    def spy(principal: Any, capability: Any) -> bool:
        seen.append(capability)
        return capability is not Capability.ACCOUNT_MANAGE and real(principal, capability)

    monkeypatch.setattr(access, "can", spy)
    if hasattr(ma, "can"):
        monkeypatch.setattr(ma, "can", spy)
    return seen


def _spy_can(monkeypatch: pytest.MonkeyPatch, ma: ModuleType) -> list[Any]:
    """access.can (and my_account.can) record each capability and ask the real matrix."""
    real = access.can
    seen: list[Any] = []

    def spy(principal: Any, capability: Any) -> bool:
        seen.append(capability)
        return real(principal, capability)

    monkeypatch.setattr(access, "can", spy)
    if hasattr(ma, "can"):
        monkeypatch.setattr(ma, "can", spy)
    return seen


async def _call(ma: ModuleType, name: str, db: FakeDb, principal: Any) -> Any:
    """Call one of the three service functions with valid arguments."""
    if name == "get_account":
        return await ma.get_account(db.pool, principal=principal)
    if name == "update_account":
        return await ma.update_account(
            db.pool, principal=principal, patch=_patch(name="Marker Changed Name")
        )
    return await ma.change_password(
        db.pool, principal=principal, current_password=_CURRENT, new_password=_NEW, ip=_IP
    )


async def _change(
    ma: ModuleType,
    db: FakeDb,
    principal: Principal,
    *,
    current: str = _CURRENT,
    new: str = _NEW,
    ip: str | None = _IP,
) -> Any:
    return await ma.change_password(
        db.pool, principal=principal, current_password=current, new_password=new, ip=ip
    )


def _locked(row: dict[str, Any] | None) -> bool:
    return (
        row is not None
        and row["locked_until"] is not None
        and row["locked_until"] > datetime.now(UTC)
    )


# ---------------------------------------------------------------------------
# 1. Module surface
# ---------------------------------------------------------------------------


class TestSurface:
    """Signatures and constants of the new module."""

    @pytest.mark.parametrize(
        ("name", "keyword_only"),
        [
            ("get_account", ["principal"]),
            ("update_account", ["principal", "patch"]),
            ("change_password", ["principal", "current_password", "new_password", "ip"]),
        ],
    )
    def test_my_account_functions_are_coroutines_with_keyword_only_arguments(
        self, ma: ModuleType, name: str, keyword_only: list[str]
    ) -> None:
        function = getattr(ma, name)
        params = list(inspect.signature(function).parameters.values())

        assert inspect.iscoroutinefunction(function)
        assert [p.name for p in params] == ["pool", *keyword_only]
        assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in params[1:])

    def test_my_account_not_found_message_is_fixed(self, ma: ModuleType) -> None:
        assert ma.ACCOUNT_NOT_FOUND_MESSAGE == _NOT_FOUND

    def test_my_account_errors_are_exceptions(self, ma: ModuleType) -> None:
        assert issubclass(ma.AccountNotFoundError, Exception)
        assert issubclass(ma.WrongPasswordError, Exception)


# ---------------------------------------------------------------------------
# 2. Authorization (Capability.ACCOUNT_MANAGE, before any query)
# ---------------------------------------------------------------------------


class TestAuthorization:
    """Every function checks ACCOUNT_MANAGE first; refused means no statement at all."""

    @pytest.mark.parametrize("name", _FUNCTIONS)
    async def test_my_account_without_account_manage_is_refused_before_any_query(
        self,
        ma: ModuleType,
        db: FakeDb,
        monkeypatch: pytest.MonkeyPatch,
        verifier: _Verifier,
        hasher: _Hasher,
        name: str,
    ) -> None:
        principal = _member(db)
        db.open_session(principal.user_id)
        before = db.snapshot()
        seen = _deny_account_manage(monkeypatch, ma)

        with pytest.raises(PermissionError):
            await _call(ma, name, db, principal)

        assert Capability.ACCOUNT_MANAGE in seen
        assert db.calls == []
        assert db.snapshot() == before
        assert verifier.calls == []
        assert hasher.calls == []

    @pytest.mark.parametrize("name", _FUNCTIONS)
    async def test_my_account_not_a_principal_is_refused_before_any_query(
        self, ma: ModuleType, db: FakeDb, name: str
    ) -> None:
        """Fail closed: anything that isn't a well-formed Principal gets PermissionError."""
        _member(db)

        with pytest.raises(PermissionError):
            await _call(ma, name, db, object())

        assert db.calls == []

    @pytest.mark.parametrize("name", _FUNCTIONS)
    async def test_my_account_asks_access_can_for_account_manage(
        self, ma: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch, name: str
    ) -> None:
        principal = _member(db)
        seen = _spy_can(monkeypatch, ma)

        await _call(ma, name, db, principal)

        assert Capability.ACCOUNT_MANAGE in seen


# ---------------------------------------------------------------------------
# 3. get_account
# ---------------------------------------------------------------------------


class TestGetAccount:
    """The caller's own profile, read by their id; a deleted account is not found."""

    async def test_my_account_get_returns_the_members_own_profile(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _member(
            db,
            name=_NAME,
            ui_language="fr",
            response_language="it",
            timezone="Europe/Zurich",
            personal_instructions=_INSTRUCTIONS,
        )

        result = await ma.get_account(db.pool, principal=principal)

        assert isinstance(result, _response_type())
        assert result.model_dump() == {
            "email": _EMAIL,
            "name": _NAME,
            "ui_language": "fr",
            "response_language": "it",
            "timezone": "Europe/Zurich",
            "personal_instructions": _INSTRUCTIONS,
            "password_changed_at": None,
        }

    async def test_my_account_get_unset_preferences_are_none_and_empty(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        """No response language (org default), no timezone yet, no instructions."""
        principal = _member(db)

        result = await ma.get_account(db.pool, principal=principal)

        assert result.response_language is None
        assert result.timezone is None
        assert result.personal_instructions == ""

    @pytest.mark.parametrize("role", ["org_admin", "editor", "viewer"])
    async def test_my_account_get_works_for_every_member_role(
        self, ma: ModuleType, db: FakeDb, role: str
    ) -> None:
        principal = _member(db, role=role, name=_NAME)

        result = await ma.get_account(db.pool, principal=principal)

        assert result.model_dump() == _stored(db, principal.user_id)

    async def test_my_account_get_works_for_the_super_admin(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _super_admin(db, name=_NAME, ui_language="en", timezone=_TIMEZONE)

        result = await ma.get_account(db.pool, principal=principal)

        assert result.model_dump() == _stored(db, principal.user_id)
        assert (result.email, result.timezone) == (_EMAIL, _TIMEZONE)

    async def test_my_account_get_never_returns_another_users_data(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        """Two users of the same org and one of another org: each gets their own row."""
        principal = _member(db, name=_NAME, personal_instructions=_INSTRUCTIONS)
        neighbour = _member(
            db,
            email="neighbour.marker@example.test",
            name="Neighbour Marker",
            ui_language="en",
            response_language="de",
            timezone="Europe/Berlin",
            personal_instructions="Neighbour marker instructions.",
        )
        outsider = _member(
            db,
            org_id=OTHER_ORG_ID,
            email="outsider.marker@example.test",
            name="Outsider Marker",
            personal_instructions="Outsider marker instructions.",
        )

        own = await ma.get_account(db.pool, principal=principal)
        theirs = await ma.get_account(db.pool, principal=neighbour)
        foreign = await ma.get_account(db.pool, principal=outsider)

        assert own.model_dump() == _stored(db, principal.user_id)
        assert theirs.model_dump() == _stored(db, neighbour.user_id)
        assert foreign.model_dump() == _stored(db, outsider.user_id)

    async def test_my_account_get_deleted_account_is_not_found(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _member(db, deleted_at=datetime.now(UTC) - timedelta(minutes=5))

        with pytest.raises(ma.AccountNotFoundError) as caught:
            await ma.get_account(db.pool, principal=principal)

        assert str(caught.value) == _NOT_FOUND
        assert not _has_id(repr(caught.value))

    async def test_my_account_get_missing_row_is_not_found(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        _member(db)

        with pytest.raises(ma.AccountNotFoundError) as caught:
            await ma.get_account(db.pool, principal=_ghost())

        assert str(caught.value) == _NOT_FOUND

    async def test_my_account_get_reads_only_the_principals_row_by_id(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        """Only users SELECTs, each bound to the principal's id and nothing else."""
        principal = _member(db)
        other = _member(db, email="other.marker@example.test")

        await ma.get_account(db.pool, principal=principal)

        assert db.calls
        for call in db.calls:
            assert call.normalized.startswith("select"), call.normalized
            assert re.search(r"\bfrom users\b", call.normalized), call.normalized
            assert [plain(arg) for arg in call.args] == [principal.user_id]
        assert other.user_id not in _bound_user_ids(db)

    async def test_my_account_get_writes_nothing(self, ma: ModuleType, db: FakeDb) -> None:
        principal = _member(db, name=_NAME)
        before = db.snapshot()

        await ma.get_account(db.pool, principal=principal)

        assert db.snapshot() == before


# ---------------------------------------------------------------------------
# 4. update_account
# ---------------------------------------------------------------------------


def _patchable(db: FakeDb, **fields: Any) -> Principal:
    """A member with every self-service field set, so each change is observable."""
    defaults: dict[str, Any] = {
        "name": _NAME,
        "ui_language": "de",
        "response_language": "fr",
        "timezone": "Europe/Zurich",
        "personal_instructions": _INSTRUCTIONS,
    }
    defaults.update(fields)
    return _member(db, **defaults)


class TestUpdateAccount:
    """One UPDATE of the caller's own row; only the patched fields change."""

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("name", "Marker Renamed Person"),
            ("ui_language", "en"),
            ("response_language", "it"),
            ("timezone", _TIMEZONE),
            ("personal_instructions", "New marker instructions: be brief."),
        ],
    )
    async def test_my_account_update_one_field_changes_only_that_field(
        self, ma: ModuleType, db: FakeDb, field: str, value: str
    ) -> None:
        principal = _patchable(db)
        expected = {**_stored(db, principal.user_id), field: value}

        result = await ma.update_account(
            db.pool, principal=principal, patch=_patch(**{field: value})
        )

        assert _stored(db, principal.user_id) == expected
        assert result.model_dump() == expected

    async def test_my_account_update_several_fields_at_once(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _patchable(db)
        changes = {
            "name": "Marker Several Person",
            "ui_language": "fr",
            "response_language": "de",
            "timezone": "Etc/GMT+5",
            "personal_instructions": "Several marker instructions.",
        }

        result = await ma.update_account(db.pool, principal=principal, patch=_patch(**changes))

        expected = {"email": _EMAIL, **changes, "password_changed_at": None}
        assert _stored(db, principal.user_id) == expected
        assert result.model_dump() == expected

    async def test_my_account_update_response_language_none_stores_null(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        """Given as None: back to the org default (NULL), not "unchanged"."""
        principal = _patchable(db, response_language="fr")

        result = await ma.update_account(
            db.pool, principal=principal, patch=_patch(response_language=None)
        )

        assert db.users[principal.user_id]["response_language"] is None
        assert result.response_language is None

    async def test_my_account_update_absent_response_language_keeps_the_stored_one(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _patchable(db, response_language="fr")

        result = await ma.update_account(
            db.pool, principal=principal, patch=_patch(name="Marker Other Name")
        )

        assert db.users[principal.user_id]["response_language"] == "fr"
        assert result.response_language == "fr"

    async def test_my_account_update_empty_instructions_clear_them(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _patchable(db, personal_instructions=_INSTRUCTIONS)

        result = await ma.update_account(
            db.pool, principal=principal, patch=_patch(personal_instructions="")
        )

        assert db.users[principal.user_id]["personal_instructions"] == ""
        assert result.personal_instructions == ""

    async def test_my_account_update_sets_a_timezone_that_was_null(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _patchable(db, timezone=None)

        result = await ma.update_account(
            db.pool, principal=principal, patch=_patch(timezone="Europe/Zurich")
        )

        assert db.users[principal.user_id]["timezone"] == "Europe/Zurich"
        assert result.timezone == "Europe/Zurich"

    async def test_my_account_update_returns_the_stored_values(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _patchable(db)

        result = await ma.update_account(
            db.pool, principal=principal, patch=_patch(ui_language="en", response_language=None)
        )

        assert isinstance(result, _response_type())
        assert result.model_dump() == _stored(db, principal.user_id)

    async def test_my_account_update_changes_only_the_callers_row(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        """Another user of the same org and one of another org keep every column; no other
        table changes."""
        principal = _patchable(db)
        neighbour = _patchable(db, email="neighbour.marker@example.test")
        outsider = _patchable(db, org_id=OTHER_ORG_ID, email="outsider.marker@example.test")
        db.open_session(principal.user_id)
        before = db.snapshot()

        await ma.update_account(
            db.pool,
            principal=principal,
            patch=_patch(name="Marker Only Mine", response_language=None, timezone=_TIMEZONE),
        )

        after = db.snapshot()
        del before["users"][principal.user_id]
        del after["users"][principal.user_id]
        assert after == before
        assert {neighbour.user_id, outsider.user_id}.isdisjoint(_bound_user_ids(db))

    async def test_my_account_update_deleted_account_is_not_found_and_changes_nothing(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _patchable(db, deleted_at=datetime.now(UTC) - timedelta(minutes=5))
        before = db.snapshot()

        with pytest.raises(ma.AccountNotFoundError) as caught:
            await ma.update_account(
                db.pool, principal=principal, patch=_patch(name="Marker Ghost Name")
            )

        assert db.snapshot() == before
        assert str(caught.value) == _NOT_FOUND
        assert not _has_id(repr(caught.value))

    async def test_my_account_update_missing_row_is_not_found(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        _patchable(db)
        before = db.snapshot()

        with pytest.raises(ma.AccountNotFoundError):
            await ma.update_account(db.pool, principal=_ghost(), patch=_patch(ui_language="en"))

        assert db.snapshot() == before

    async def test_my_account_update_is_one_update_statement_bound_to_the_principal(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        """No SELECT-then-UPDATE race: exactly one UPDATE users ... RETURNING, whose only
        id is the principal's."""
        principal = _patchable(db)

        await ma.update_account(
            db.pool, principal=principal, patch=_patch(name="Marker One Statement")
        )

        assert len(db.calls) == 1, [call.normalized for call in db.calls]
        (call,) = db.calls
        assert call.normalized.startswith("update users "), call.normalized
        assert " returning " in call.normalized
        assert [plain(arg) for arg in call.args if isinstance(arg, uuid.UUID)] == [
            principal.user_id
        ]

    async def test_my_account_update_is_not_audited(self, ma: ModuleType, db: FakeDb) -> None:
        principal = _patchable(db)

        await ma.update_account(
            db.pool,
            principal=principal,
            patch=_patch(name="Marker Unaudited", personal_instructions="Unaudited marker."),
        )

        assert db.audit == []
        assert db.matching(r"\baudit_events\b") == []

    async def test_my_account_update_logs_nothing(
        self, ma: ModuleType, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No record from the module, and no name, email, timezone or instructions in any
        record."""
        caplog.set_level(logging.DEBUG)
        principal = _patchable(db)
        new_name = "Marker Logged Name Zeta"
        new_instructions = "Marker logged instructions Zeta."

        await ma.update_account(
            db.pool,
            principal=principal,
            patch=_patch(name=new_name, timezone=_TIMEZONE, personal_instructions=new_instructions),
        )

        assert [r.name for r in caplog.records if r.name.startswith("admino.my_account")] == []
        text = _log_text(caplog)
        for marker in (new_name, new_instructions, _TIMEZONE, _NAME, _INSTRUCTIONS, _EMAIL):
            assert marker.casefold() not in text


# ---------------------------------------------------------------------------
# 5. change_password: success
# ---------------------------------------------------------------------------


class TestChangePasswordSuccess:
    """New hash, every session of the user gone, one password.change row, one transaction."""

    async def test_my_account_change_password_stores_the_new_hash(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _member(db)

        await _change(ma, db, principal)

        stored = db.users[principal.user_id]["password_hash"]
        assert stored == fake_hash(_NEW)
        assert stored != fake_hash(_CURRENT)

    async def test_my_account_change_password_checks_the_current_password_against_the_stored_hash(
        self, ma: ModuleType, db: FakeDb, verifier: _Verifier
    ) -> None:
        principal = _member(db)

        await _change(ma, db, principal)

        assert verifier.calls == [(_CURRENT, fake_hash(_CURRENT))]

    async def test_my_account_change_password_hashes_off_the_loop_and_outside_the_transaction(
        self, ma: ModuleType, db: FakeDb, hasher: _Hasher
    ) -> None:
        principal = _member(db)

        await _change(ma, db, principal)

        assert hasher.calls == [_NEW]
        assert threading.get_ident() not in hasher.threads
        assert hasher.open_transactions == [0]

    async def test_my_account_change_password_ends_every_session_of_the_user(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        """The current session included; other users' sessions (same org, other org,
        a Super Admin) stay; the count is returned."""
        principal = _member(db)
        neighbour = _member(db, email="neighbour.marker@example.test")
        outsider = _member(db, org_id=OTHER_ORG_ID, email="outsider.marker@example.test")
        admin = _super_admin(db, email="platform.marker@example.test")
        current = db.open_session(principal.user_id)
        own = [
            current,
            db.open_session(principal.user_id, last_seen_ago=timedelta(minutes=20)),
            db.open_session(principal.user_id, user_agent="curl/8.5.0"),
        ]
        kept = [
            db.open_session(neighbour.user_id),
            db.open_session(outsider.user_id),
            db.open_session(admin.user_id),
        ]

        revoked = await _change(ma, db, principal)

        assert revoked == 3
        assert type(revoked) is int
        assert all(db.session_revoked(token) for token in own)
        assert db.sessions_of(principal.user_id) == []
        assert not any(db.session_revoked(token) for token in kept)

    async def test_my_account_change_password_records_one_audit_row_for_a_member(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _member(db, role="viewer")
        for _ in range(3):
            db.open_session(principal.user_id)

        await _change(ma, db, principal)

        rows = db.audit_rows("password.change")
        assert len(rows) == 1
        row = rows[0]
        assert row["actor_kind"] == "member"
        assert plain(row["actor_user_id"]) == principal.user_id
        assert plain(row["org_id"]) == ORG_ID
        assert row["target_type"] == "user"
        assert row["target_ids"] == [str(principal.user_id)]
        assert row["ip"] == _IP
        assert row["metadata"] == {"sessions_revoked": 3}

    async def test_my_account_change_password_records_a_platform_row_for_the_super_admin(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _super_admin(db, name=_NAME)
        db.open_session(principal.user_id)

        revoked = await _change(ma, db, principal)

        rows = db.audit_rows("password.change")
        assert revoked == 1
        assert len(rows) == 1
        row = rows[0]
        assert row["actor_kind"] == "super_admin"
        assert plain(row["actor_user_id"]) == principal.user_id
        assert row["org_id"] is None
        assert row["target_type"] == "user"
        assert row["target_ids"] == [str(principal.user_id)]
        assert row["metadata"] == {"sessions_revoked": 1}
        assert db.users[principal.user_id]["password_hash"] == fake_hash(_NEW)

    async def test_my_account_change_password_without_sessions_records_zero(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _member(db)

        revoked = await _change(ma, db, principal, ip=None)

        assert revoked == 0
        (row,) = db.audit_rows("password.change")
        assert row["metadata"] == {"sessions_revoked": 0}
        assert row["ip"] is None

    async def test_my_account_change_password_writes_in_one_transaction(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        """The hash UPDATE, the sessions DELETE and the audit INSERT share one committed
        transaction on one connection."""
        principal = _member(db)
        db.open_session(principal.user_id)

        await _change(ma, db, principal)

        hash_updates = db.matching(r"^update users set password_hash\b")
        deletes = db.matching(r"^delete from sessions\b")
        inserts = db.matching(r"^insert into audit_events\b")
        assert (len(hash_updates), len(deletes), len(inserts)) == (1, 1, 1)
        steps = [hash_updates[0], deletes[0], inserts[0]]
        tx = steps[0].tx
        assert tx is not None
        assert {(call.via, call.tx) for call in steps} == {(steps[0].via, tx)}
        assert (tx, "commit") in db.transactions

    async def test_my_account_change_password_hash_update_is_bound_to_the_principal(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _member(db)
        other = _member(db, email="other.marker@example.test")
        db.open_session(other.user_id)

        await _change(ma, db, principal)

        (update,) = db.matching(r"^update users set password_hash\b")
        assert [plain(arg) for arg in update.args if isinstance(arg, uuid.UUID)] == [
            principal.user_id
        ]
        assert fake_hash(_NEW) in update.args
        assert other.user_id not in _bound_user_ids(db)
        assert db.users[other.user_id]["password_hash"] == fake_hash(_CURRENT)

    async def test_my_account_change_password_writes_nothing_else_to_the_users_row(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _patchable(db)
        before = dict(db.users[principal.user_id])

        await _change(ma, db, principal)

        after = dict(db.users[principal.user_id])
        assert after.pop("password_hash") == fake_hash(_NEW)
        # GH-307: the change date moves with the hash (its value: TestPasswordChangedAt).
        assert after.pop("password_changed_at") is not None
        before.pop("password_hash")
        before.pop("password_changed_at")
        assert after == before


# ---------------------------------------------------------------------------
# 6. change_password: a failed audit write
# ---------------------------------------------------------------------------


class TestChangePasswordAuditFailure:
    """Fail closed: no audit row, no change."""

    async def test_my_account_change_password_failed_audit_rolls_everything_back(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _member(db)
        tokens = [db.open_session(principal.user_id) for _ in range(3)]
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _change(ma, db, principal)

        assert db.users[principal.user_id]["password_hash"] == fake_hash(_CURRENT)
        assert not any(db.session_revoked(token) for token in tokens)
        assert db.audit_rows("password.change") == []
        assert db.transactions
        assert db.transactions[-1][1].startswith("rollback")


# ---------------------------------------------------------------------------
# 7. change_password: the current password (re-authentication)
# ---------------------------------------------------------------------------


class TestChangePasswordWrongCurrent:
    """A wrong current password is WrongPasswordError, counted like a failed login."""

    async def test_my_account_change_password_wrong_current_password_changes_nothing(
        self, ma: ModuleType, db: FakeDb, hasher: _Hasher
    ) -> None:
        principal = _member(db)
        tokens = [db.open_session(principal.user_id) for _ in range(2)]

        with pytest.raises(ma.WrongPasswordError):
            await _change(ma, db, principal, current=_WRONG)

        assert db.users[principal.user_id]["password_hash"] == fake_hash(_CURRENT)
        assert not any(db.session_revoked(token) for token in tokens)
        assert db.audit_rows("password.change") == []
        assert db.matching(r"^update users set password_hash\b") == []
        assert db.matching(r"^delete from sessions\b") == []
        assert hasher.calls == []

    async def test_my_account_change_password_wrong_current_password_counts_in_the_throttle(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        """One failure on the account (its stored email's subject) and on the IP."""
        principal = _member(db)

        with pytest.raises(ma.WrongPasswordError):
            await _change(ma, db, principal, current=_WRONG)

        account = db.throttle_row("account", account_subject(_EMAIL))
        ip = db.throttle_row("ip", login_throttle.ip_subject(_IP))
        assert account is not None and account["failures"] == 1
        assert ip is not None and ip["failures"] == 1

    async def test_my_account_change_password_wrong_password_error_carries_nothing(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _member(db)

        with pytest.raises(ma.WrongPasswordError) as caught:
            await _change(ma, db, principal, current=_WRONG)

        text = f"{caught.value!s} {caught.value!r}".casefold()
        assert not _has_id(text)
        for marker in (_WRONG, _NEW, _CURRENT, _EMAIL):
            assert marker.casefold() not in text

    async def test_my_account_change_password_repeated_wrong_passwords_lock_the_account(
        self, ma: ModuleType, db: FakeDb, verifier: _Verifier
    ) -> None:
        """The Nth wrong password locks the account (one login.lockout row naming the
        member); the right password is then refused too, without a check, and nothing
        changes."""
        principal = _member(db)
        token = db.open_session(principal.user_id)
        for _ in range(_LIMIT):
            with pytest.raises(ma.WrongPasswordError):
                await _change(ma, db, principal, current=_WRONG, ip=None)

        assert _locked(db.throttle_row("account", account_subject(_EMAIL)))
        lockouts = db.audit_rows("login.lockout")
        assert len(lockouts) == 1
        assert lockouts[0]["actor_kind"] == "member"
        assert plain(lockouts[0]["actor_user_id"]) == principal.user_id
        assert plain(lockouts[0]["org_id"]) == ORG_ID
        checks = len(verifier.calls)

        with pytest.raises(ma.WrongPasswordError):
            await _change(ma, db, principal, current=_CURRENT, ip=None)

        assert len(verifier.calls) == checks
        assert db.users[principal.user_id]["password_hash"] == fake_hash(_CURRENT)
        assert not db.session_revoked(token)
        assert db.audit_rows("password.change") == []


# ---------------------------------------------------------------------------
# 8. change_password: the policy (before re-authentication)
# ---------------------------------------------------------------------------

_POLICY_CASES: Final = [
    pytest.param("Short-1", "too_short", id="too_short"),
    pytest.param("Long-" + "y" * 130, "too_long", id="too_long"),
    pytest.param("q1w2e3r4t5y6", "common", id="common"),
    pytest.param(_EMAIL.upper(), "equals_email", id="equals_email"),
]


class TestChangePasswordPolicy:
    """A refused new password costs nothing: no throttle, no Argon2, no write."""

    @pytest.mark.parametrize(("new_password", "reason"), _POLICY_CASES)
    async def test_my_account_change_password_policy_failure_is_refused_before_reauth(
        self,
        ma: ModuleType,
        db: FakeDb,
        verifier: _Verifier,
        hasher: _Hasher,
        new_password: str,
        reason: str,
    ) -> None:
        if reason == "common":
            # The case's precondition: long enough, and on the shipped list.
            assert len(new_password) >= passwords.MIN_PASSWORD_LENGTH
            assert new_password in passwords.common_passwords()
        principal = _member(db)
        db.open_session(principal.user_id)
        before = db.snapshot()

        with pytest.raises(passwords.PasswordPolicyError) as caught:
            await _change(ma, db, principal, new=new_password)

        assert caught.value.reason == reason
        assert db.snapshot() == before
        assert db.matching(r"\blogin_throttle\b") == []
        assert db.matching(r"\bsha256 ?\(") == []
        assert verifier.calls == []
        assert hasher.calls == []

    async def test_my_account_change_password_policy_wins_over_a_wrong_current_password(
        self, ma: ModuleType, db: FakeDb, verifier: _Verifier
    ) -> None:
        """The cheap policy check runs first: a wrong current password with a refused new
        one is the policy error, and no failure is counted."""
        principal = _member(db)

        with pytest.raises(passwords.PasswordPolicyError) as caught:
            await _change(ma, db, principal, current=_WRONG, new="Short-2")

        assert caught.value.reason == "too_short"
        assert db.throttle == []
        assert verifier.calls == []

    async def test_my_account_change_password_equals_email_uses_the_stored_email(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        """Compared with the principal's own stored email, ignoring case."""
        principal = _member(db, email="Mixed.Case.Owner@Example.test")

        with pytest.raises(passwords.PasswordPolicyError) as caught:
            await _change(ma, db, principal, new="mixed.case.OWNER@example.TEST")

        assert caught.value.reason == "equals_email"


# ---------------------------------------------------------------------------
# 9. change_password: a deleted or missing account
# ---------------------------------------------------------------------------


class TestChangePasswordNotFound:
    async def test_my_account_change_password_deleted_account_is_not_found(
        self, ma: ModuleType, db: FakeDb, verifier: _Verifier, hasher: _Hasher
    ) -> None:
        principal = _member(db, deleted_at=datetime.now(UTC) - timedelta(minutes=5))
        db.open_session(principal.user_id)
        before = db.snapshot()

        with pytest.raises(ma.AccountNotFoundError) as caught:
            await _change(ma, db, principal)

        assert str(caught.value) == _NOT_FOUND
        assert not _has_id(repr(caught.value))
        assert db.snapshot() == before
        assert db.matching(r"\blogin_throttle\b") == []
        assert verifier.calls == []
        assert hasher.calls == []

    async def test_my_account_change_password_missing_row_is_not_found(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        _member(db)
        before = db.snapshot()

        with pytest.raises(ma.AccountNotFoundError):
            await _change(ma, db, _ghost())

        assert db.snapshot() == before


class TestChangePasswordAccountGoneAfterReauth:
    """Security audit M2: an account deleted or deactivated after the current
    password was checked, before the transaction, keeps its password and sessions."""

    @pytest.mark.parametrize("change", ["deleted", "deactivated"])
    async def test_my_account_change_password_account_gone_after_reauth_changes_nothing(
        self,
        ma: ModuleType,
        db: FakeDb,
        hasher: _Hasher,
        monkeypatch: pytest.MonkeyPatch,
        change: str,
    ) -> None:
        principal = _member(db)
        db.open_session(principal.user_id)
        db.open_session(principal.user_id)
        row = db.users[principal.user_id]

        def hash_then_lose_the_account(password: str) -> str:
            # Runs after the re-authentication and before the transaction opens.
            encoded = hasher(password)
            if change == "deleted":
                row["deleted_at"] = datetime.now(UTC)
            else:
                row["status"] = "deactivated"
            return encoded

        monkeypatch.setattr(passwords, "hash_password", hash_then_lose_the_account)

        with pytest.raises(ma.AccountNotFoundError) as caught:
            await _change(ma, db, principal)

        assert str(caught.value) == _NOT_FOUND
        assert row["password_hash"] == fake_hash(_CURRENT)
        assert len(db.sessions_of(principal.user_id)) == 2
        assert db.audit_rows("password.change") == []
        assert db.transactions[-1][1].startswith("rollback")


# ---------------------------------------------------------------------------
# 10. No secrets, no content
# ---------------------------------------------------------------------------


class TestNoSecrets:
    """The passwords never leave the function except as the new hash."""

    async def test_my_account_change_password_never_exposes_the_passwords(
        self, ma: ModuleType, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Across a success, a wrong current password, a policy refusal and a failed audit
        write: no plaintext password in a log record, an exception, an audit row or any SQL
        argument; the email and name aren't logged either."""
        caplog.set_level(logging.DEBUG)
        principal = _member(db, name=_NAME)
        db.open_session(principal.user_id)
        errors: list[BaseException] = []

        await _change(ma, db, principal, current=_CURRENT, new=_NEW)
        with pytest.raises(ma.WrongPasswordError) as wrong:
            await _change(ma, db, principal, current=_WRONG, new=_NEW + "-again")
        errors.append(wrong.value)
        with pytest.raises(passwords.PasswordPolicyError) as policy:
            await _change(ma, db, principal, current=_NEW, new=_EMAIL.lower())
        errors.append(policy.value)
        db.fail_audit = True
        with pytest.raises(AuditRecordError) as audit:
            await _change(ma, db, principal, current=_NEW, new=_CURRENT + "-later")
        errors.append(audit.value)

        assert len(db.audit_rows("password.change")) == 1
        secrets_ = (_CURRENT, _NEW, _WRONG, _NEW + "-again", _CURRENT + "-later")
        logs = _log_text(caplog)
        error_text = " ".join(f"{exc!s} {exc!r}" for exc in errors).casefold()
        audit_text = json.dumps(db.audit, default=str).casefold()
        for secret in secrets_:
            folded = secret.casefold()
            assert folded not in logs
            assert folded not in error_text
            assert folded not in audit_text
            for call in db.calls:
                assert all(folded not in str(arg).casefold() for arg in call.args), call.sql
        for marker in (_EMAIL, _NAME):
            assert marker.casefold() not in logs

    async def test_my_account_change_password_binds_only_the_principals_user_id(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _member(db)
        _member(db, email="neighbour.marker@example.test")
        _member(db, org_id=OTHER_ORG_ID, email="outsider.marker@example.test")

        await _change(ma, db, principal)

        assert _bound_user_ids(db) == {principal.user_id}

    async def test_my_account_get_logs_no_profile_content(
        self, ma: ModuleType, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        principal = _patchable(db, timezone=_TIMEZONE)

        await ma.get_account(db.pool, principal=principal)
        with pytest.raises(ma.AccountNotFoundError):
            await ma.get_account(db.pool, principal=_ghost())

        text = _log_text(caplog)
        for marker in (_EMAIL, _NAME, _INSTRUCTIONS, _TIMEZONE):
            assert marker.casefold() not in text


# ---------------------------------------------------------------------------
# 11. password_changed_at (GH-307)
# ---------------------------------------------------------------------------

# A change stored before the test (with microseconds, so a lossy copy shows).
_EARLIER_CHANGE: Final = datetime(2026, 3, 4, 5, 6, 7, 890123, tzinfo=UTC)
_EARLIER: Final = [
    pytest.param(None, id="never-changed"),
    pytest.param(_EARLIER_CHANGE, id="changed-before"),
]

# Contract C4: the new hash and the change date in ONE statement, the date from the
# database's clock (now()), never a value bound from Python.
_HASH_UPDATE_RE: Final = re.compile(
    r"update users set password_hash = \$1 ?, ?password_changed_at = now\(\) "
    r"where id = \$2 and deleted_at is null and status = 'active' returning id"
)

# Every way change_password refuses (decision 4: "a refused change leaves it as it was").
_REFUSED_CHANGES: Final = (
    "wrong-current-password",
    "policy",
    "audit-failure",
    "deleted-account",
    "deleted-after-reauth",
    "deactivated-after-reauth",
)


def _changed_at(db: FakeDb, user_id: uuid.UUID) -> Any:
    """The stored users.password_changed_at of an account."""
    return db.users[user_id]["password_changed_at"]


def _assert_utc_between(value: Any, before: datetime, after: datetime) -> None:
    """``value`` is an aware UTC datetime read from the clock between the two bounds."""
    assert isinstance(value, datetime), value
    assert value.utcoffset() == timedelta(0), value
    assert before <= value <= after, (before, value, after)


async def _refused_change(
    ma: ModuleType,
    db: FakeDb,
    principal: Principal,
    cause: str,
    monkeypatch: pytest.MonkeyPatch,
    hasher: _Hasher,
) -> None:
    """Run one change_password that is refused for ``cause``, and check its error."""
    row = db.users[principal.user_id]
    if cause == "wrong-current-password":
        with pytest.raises(ma.WrongPasswordError):
            await _change(ma, db, principal, current=_WRONG)
    elif cause == "policy":
        with pytest.raises(passwords.PasswordPolicyError):
            await _change(ma, db, principal, new="Short-307")
    elif cause == "audit-failure":
        db.fail_audit = True
        with pytest.raises(AuditRecordError):
            await _change(ma, db, principal)
    elif cause == "deleted-account":
        row["deleted_at"] = datetime.now(UTC) - timedelta(minutes=5)
        with pytest.raises(ma.AccountNotFoundError):
            await _change(ma, db, principal)
    else:

        def hash_then_lose_the_account(password: str) -> str:
            # Runs after the re-authentication and before the transaction opens.
            encoded = hasher(password)
            if cause == "deleted-after-reauth":
                row["deleted_at"] = datetime.now(UTC)
            else:
                row["status"] = "deactivated"
            return encoded

        monkeypatch.setattr(passwords, "hash_password", hash_then_lose_the_account)
        with pytest.raises(ma.AccountNotFoundError):
            await _change(ma, db, principal)


def _undo_refusal(
    db: FakeDb, principal: Principal, monkeypatch: pytest.MonkeyPatch, hasher: _Hasher
) -> None:
    """Remove whatever made ``_refused_change`` refuse, so the next change is accepted."""
    db.fail_audit = False
    row = db.users[principal.user_id]
    row["deleted_at"] = None
    row["status"] = "active"
    monkeypatch.setattr(passwords, "hash_password", hasher)


class TestPasswordChangedAt:
    """GH-307: set by a successful change (now(), in the hash UPDATE), returned by
    get_account and update_account, left alone by everything else."""

    async def test_my_account_get_password_changed_at_is_none_until_the_first_change(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _member(db)

        result = await ma.get_account(db.pool, principal=principal)

        assert result.password_changed_at is None

    @pytest.mark.parametrize("who", ["member", "super_admin"])
    async def test_my_account_get_returns_the_stored_password_changed_at(
        self, ma: ModuleType, db: FakeDb, who: str
    ) -> None:
        make = _member if who == "member" else _super_admin
        principal = make(db, password_changed_at=_EARLIER_CHANGE)

        result = await ma.get_account(db.pool, principal=principal)

        assert result.password_changed_at == _EARLIER_CHANGE

    async def test_my_account_update_returns_the_stored_password_changed_at(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        """The PATCH /api/me response carries it too; a profile change doesn't touch it."""
        principal = _patchable(db, password_changed_at=_EARLIER_CHANGE)

        result = await ma.update_account(
            db.pool, principal=principal, patch=_patch(name="Marker Renamed Person")
        )

        assert result.password_changed_at == _EARLIER_CHANGE
        assert _changed_at(db, principal.user_id) == _EARLIER_CHANGE

    @pytest.mark.parametrize("earlier", _EARLIER)
    async def test_my_account_change_password_sets_password_changed_at_to_now(
        self, ma: ModuleType, db: FakeDb, earlier: datetime | None
    ) -> None:
        """The first change sets it; a later one replaces the earlier date."""
        principal = _member(db, password_changed_at=earlier)
        before = datetime.now(UTC)

        await _change(ma, db, principal)

        _assert_utc_between(_changed_at(db, principal.user_id), before, datetime.now(UTC))

    async def test_my_account_change_password_date_is_returned_by_get_account(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _member(db)

        await _change(ma, db, principal)
        result = await ma.get_account(db.pool, principal=principal)

        assert result.password_changed_at is not None
        assert result.password_changed_at == _changed_at(db, principal.user_id)

    async def test_my_account_change_password_twice_moves_the_date_forward(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        principal = _member(db)
        await _change(ma, db, principal)
        first = _changed_at(db, principal.user_id)
        before = datetime.now(UTC)

        await _change(ma, db, principal, current=_NEW, new=_NEW + "-second")

        second = _changed_at(db, principal.user_id)
        _assert_utc_between(second, before, datetime.now(UTC))
        assert first < second

    async def test_my_account_change_password_sets_the_date_in_the_hash_update(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        """Contract C4: the hash UPDATE sets password_changed_at = now() (no clock value is
        bound), in the transaction of the session revoke and the audit row; no other
        write names the column."""
        principal = _member(db)
        db.open_session(principal.user_id)

        await _change(ma, db, principal)

        (update,) = db.matching(r"^update users set password_hash\b")
        assert _HASH_UPDATE_RE.fullmatch(update.normalized), update.normalized
        assert [plain(arg) if isinstance(arg, uuid.UUID) else arg for arg in update.args] == [
            fake_hash(_NEW),
            principal.user_id,
        ]
        writes = db.matching(r"^(?:update|insert|delete)\b")
        assert [call for call in writes if "password_changed_at" in call.normalized] == [update]
        (revoke,) = db.matching(r"^delete from sessions\b")
        (audit,) = db.matching(r"^insert into audit_events\b")
        assert update.tx is not None
        assert {(call.via, call.tx) for call in (update, revoke, audit)} == {
            (update.via, update.tx)
        }

    @pytest.mark.parametrize("earlier", _EARLIER)
    @pytest.mark.parametrize("cause", _REFUSED_CHANGES)
    async def test_my_account_refused_change_keeps_password_changed_at(
        self,
        ma: ModuleType,
        db: FakeDb,
        hasher: _Hasher,
        monkeypatch: pytest.MonkeyPatch,
        cause: str,
        earlier: datetime | None,
    ) -> None:
        """Null stays null and an earlier date stays that date, whatever the refusal; the
        same account's next, accepted change then sets it (the positive control)."""
        principal = _member(db, password_changed_at=earlier)

        await _refused_change(ma, db, principal, cause, monkeypatch, hasher)

        assert _changed_at(db, principal.user_id) == earlier
        assert db.users[principal.user_id]["password_hash"] == fake_hash(_CURRENT)
        _undo_refusal(db, principal, monkeypatch, hasher)
        before = datetime.now(UTC)
        await _change(ma, db, principal)
        _assert_utc_between(_changed_at(db, principal.user_id), before, datetime.now(UTC))

    async def test_my_account_change_password_sets_only_the_callers_date(
        self, ma: ModuleType, db: FakeDb
    ) -> None:
        """A colleague (never changed), another org's member (changed before) and a Super
        Admin keep theirs, and the colleague still reads None."""
        principal = _member(db)
        colleague = _member(db, email="colleague.marker@example.test")
        outsider = _member(
            db,
            org_id=OTHER_ORG_ID,
            email="outsider.marker@example.test",
            password_changed_at=_EARLIER_CHANGE,
        )
        admin = _super_admin(db, email="platform.marker@example.test")

        await _change(ma, db, principal)
        theirs = await ma.get_account(db.pool, principal=colleague)

        assert _changed_at(db, principal.user_id) is not None
        assert [_changed_at(db, other.user_id) for other in (colleague, outsider, admin)] == [
            None,
            _EARLIER_CHANGE,
            None,
        ]
        assert theirs.password_changed_at is None

    async def test_my_account_change_password_date_is_not_logged_or_audited(
        self, ma: ModuleType, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The password.change metadata stays exactly {"sessions_revoked": n}; no log
        record names the column or carries the stored date."""
        caplog.set_level(logging.DEBUG)
        principal = _member(db)
        db.open_session(principal.user_id)

        await _change(ma, db, principal)
        await ma.get_account(db.pool, principal=principal)

        stamp = _changed_at(db, principal.user_id)
        (row,) = db.audit_rows("password.change")
        assert row["metadata"] == {"sessions_revoked": 1}
        assert "password_changed_at" not in json.dumps(db.audit, default=str)
        text = _log_text(caplog)
        assert "password_changed_at" not in text
        for rendered in (stamp.isoformat(), str(stamp)):
            assert rendered.casefold() not in text
