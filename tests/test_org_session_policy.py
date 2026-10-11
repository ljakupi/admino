"""End-to-end spec of the org session policy (GH-169: retire #152's session policy defaults).

The FastAPI app from ``create_app()`` runs against the in-memory database of
tests/db_fakes.py (what ``admino.database.get_pool`` returns). The real
``require_session``, ``admino.auth``, ``admino.sessions``,
``admino.scoped_settings``, ``admino.invitations`` and ``admino.audit_events``
code runs over HTTP; only Argon2 is replaced by a fast fake.

The issue's cleanup criterion, verbatim: new sessions of the org's members take
the stored idle timeout and lifetime, instead of the code defaults in
``sessions`` (``DEFAULT_ORG_SESSION_POLICY``, removed); a policy change applies
to the org's open sessions (their stored ``idle_timeout_minutes`` and their
expiry, ``created_at`` + lifetime, are updated in the same transaction as the
change). "Test: after a policy change, a new login stores the new values, and
an open session follows the change."

What these tests pin down (contract sections 3 to 6):
- After an Org Admin's ``PATCH /api/org/settings {"security": {...}}`` (200),
  a member's ``POST /api/auth/login`` stores the org's new idle timeout and
  ``expires_at = now() + <new lifetime>``, and the cookie's Max-Age is the new
  lifetime in seconds. A patch of one field keeps the other stored field (the
  merged stored + patch values apply).
- Every LIVE session of every user of that org (any role, the patching Org
  Admin's own included) takes the new ``idle_timeout_minutes`` and
  ``expires_at = created_at + <new lifetime>``: one older than a shortened
  lifetime, or idle past a shortened timeout, is a 401 on its next request; a
  session that had already ended (expired, or idle past its old timeout) is
  neither changed nor revived by a longer policy.
- Another org's sessions and logins and the Super Admin's sessions and logins
  are untouched (the Super Admin keeps the stored platform policy).
- An invitation accepted after the change opens a session with the new policy.
- The sessions change in the transaction of the settings change: an audit
  failure is a 500 and rolls the sessions back too; the security audit event
  counts the re-timed sessions (``sessions_updated``). A patch that changes no
  session field (the same values, or another section) touches no session.

All database calls are faked. No network, no real PostgreSQL, no SMTP.

Security notes:
- Tenant isolation: the org is the patching admin's (from the session), never
  another org's sessions; a Super Admin's sessions follow only the platform policy.
- Fail closed: a shortened policy ends the sessions it no longer allows at once,
  and an ended session never comes back to life.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from admino import scoped_settings, server
from admino.server import create_app
from tests.conftest import default_test_platform_settings
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, PUBLIC_URL, FakeDb, fake_hash

if TYPE_CHECKING:
    import uuid

    import httpx
    from fastapi import FastAPI

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE = "admino_session"
_PASSWORD = "violet-Anchor-93-quartz"
_IP = "203.0.113.5"
_ORG_SETTINGS = "/api/org/settings"
_INVITES = "/api/org/invitations"
_INVITEE_EMAIL = "Policy.Invitee.Marker@Example.ch"
_INVITEE_NAME = "Grace Hopper"
_UNAUTHORIZED = {"detail": "Unauthorized"}
_IDLE = "session_idle_timeout_minutes"
_LIFETIME = "session_max_lifetime_hours"
# apply_org_policy's statement (contract section 3), normalized.
_POLICY_UPDATE = r"^update sessions set idle_timeout_minutes\b"
# Functional tests aren't about rate limits: these routes get a large bucket.
_RATE_KEYS = (
    "/api/auth/login",
    "/api/auth/me",
    "/api/org/settings/get",
    "/api/org/settings/patch",
    "/api/org/invitations/create",
    "/api/auth/invitations/accept",
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch) -> FakeDb:
    """The fake database the server's get_pool() returns: two active orgs, no
    org_settings row yet."""
    fake = FakeDb()
    fake.add_org(ORG_ID)
    fake.add_org(OTHER_ORG_ID)
    monkeypatch.setattr("admino.database.get_pool", lambda: fake.pool)
    return fake


@pytest.fixture(autouse=True)
def _fast_passwords(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace Argon2 with a fast fake (the real hashing is covered by test_passwords)."""
    monkeypatch.setattr(
        "admino.passwords.verify_password", lambda password, encoded: encoded == fake_hash(password)
    )
    monkeypatch.setattr("admino.passwords.needs_rehash", lambda _encoded: False)
    monkeypatch.setattr("admino.passwords.hash_password", fake_hash)


@pytest.fixture(autouse=True)
def _large_buckets(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _RATE_KEYS:
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))


def _config() -> MagicMock:
    """A minimal config with the public URL invitation links are built from."""
    config = MagicMock()
    del config.auth
    config.limits.max_message_length = 4000
    config.server.host = "127.0.0.1"
    config.server.port = 8000
    config.server.cookie_secure = True
    config.server.public_url = PUBLIC_URL
    config.llm.provider = "infomaniak"
    config.llm.active_model_name = "test-model"
    return config


def _app() -> FastAPI:
    """create_app with a stub agent and the fake config (no lifespan runs under TestClient)."""
    return create_app(agent=MagicMock(), config=_config())  # type: ignore[arg-type]


def _client(**kwargs: Any) -> TestClient:
    """A client of a fresh app; redirects are not followed."""
    return TestClient(_app(), client=(_IP, 50000), follow_redirects=False, **kwargs)


def _cookie(token: str) -> dict[str, str]:
    return {"Cookie": f"{_COOKIE}={token}"}


def _account(db: FakeDb, role: str = "editor", org_id: uuid.UUID = ORG_ID) -> uuid.UUID:
    """An active member of the org who can log in with _PASSWORD."""
    return db.add_account(role=role, org_id=org_id, password_hash=fake_hash(_PASSWORD))


def _super_admin(db: FakeDb) -> uuid.UUID:
    return db.add_account(kind="super_admin", role=None, password_hash=fake_hash(_PASSWORD))


def _admin_session(db: FakeDb, created_ago: timedelta = timedelta(hours=1)) -> str:
    """A live session of a new Org Admin of ORG_ID, created ``created_ago`` ago."""
    return db.open_session(_account(db, "org_admin"), created_ago=created_ago)


def _security(idle: int | None = None, lifetime: int | None = None) -> dict[str, Any]:
    """A PATCH body changing the given session fields only."""
    section: dict[str, int] = {}
    if idle is not None:
        section[_IDLE] = idle
    if lifetime is not None:
        section[_LIFETIME] = lifetime
    return {"security": section}


def _patch(client: TestClient, token: str, body: dict[str, Any]) -> httpx.Response:
    return client.patch(_ORG_SETTINGS, json=body, headers=_cookie(token))


def _change_policy(
    client: TestClient, token: str, idle: int | None = None, lifetime: int | None = None
) -> None:
    """The Org Admin's PATCH of the security section; it must succeed."""
    response = _patch(client, token, _security(idle, lifetime))
    assert response.status_code == 200, response.text


def _session_set_cookie(response: httpx.Response) -> tuple[str, dict[str, str | None]]:
    """Return (value, attributes) of the one admino_session Set-Cookie header."""
    headers = [
        h for h in response.headers.get_list("set-cookie") if h.lower().startswith(f"{_COOKIE}=")
    ]
    assert len(headers) == 1, response.headers.get_list("set-cookie")
    parts = [part.strip() for part in headers[0].split(";")]
    value = parts[0].split("=", 1)[1]
    attributes: dict[str, str | None] = {}
    for part in parts[1:]:
        key, sep, attr_value = part.partition("=")
        attributes[key.strip().lower()] = attr_value.strip() if sep else None
    return value, attributes


def _login(client: TestClient, db: FakeDb, user_id: uuid.UUID) -> tuple[str, str | None]:
    """POST /api/auth/login as the account (204): (session token, cookie Max-Age)."""
    response = client.post(
        "/api/auth/login", json={"email": db.users[user_id]["email"], "password": _PASSWORD}
    )
    client.cookies.clear()
    assert response.status_code == 204, response.text
    token, attributes = _session_set_cookie(response)
    return token, attributes.get("max-age")


def _policy_of(db: FakeDb, token: str) -> tuple[int, timedelta]:
    """(idle_timeout_minutes, expires_at - created_at) of a stored session."""
    row = db.session(token)
    return row["idle_timeout_minutes"], row["expires_at"] - row["created_at"]


def _row(db: FakeDb, token: str) -> dict[str, Any]:
    """A copy of a stored session row, for "unchanged" checks."""
    return dict(db.session(token))


def _me(client: TestClient, token: str) -> httpx.Response:
    """The next request of a session."""
    return client.get("/api/auth/me", headers=_cookie(token))


def _store_platform_policy(monkeypatch: pytest.MonkeyPatch, *, idle: int, lifetime: int) -> None:
    """Make the cached platform settings carry this Super Admin session policy (GH-160)."""
    data = default_test_platform_settings().model_dump()
    data["security"] = {**data.get("security", {}), _IDLE: idle, _LIFETIME: lifetime}
    stored = scoped_settings.StoredPlatformSettings.model_validate(data)
    monkeypatch.setattr(scoped_settings, "_platform_cache", stored)


# ---------------------------------------------------------------------------
# 1. The issue's test: a new login and an open session after a change
# ---------------------------------------------------------------------------


class TestPolicyChangeAcceptance:
    """AC: after a policy change, a new login stores the new values, and an open session
    follows the change."""

    def test_org_session_policy_new_login_and_open_session_follow_the_change(
        self, db: FakeDb
    ) -> None:
        """Stored 30 min / 6 h: a member's first login gets exactly that. The Org Admin
        changes it to 25 min / 3 h: the member's next login stores 25 and now() + 3 h
        (Max-Age 10800), and the first session (still open) now stores 25 and
        created_at + 3 h and still resolves."""
        db.add_org_settings(ORG_ID, session_idle_timeout_minutes=30, session_max_lifetime_hours=6)
        admin_token = _admin_session(db)
        member = _account(db)
        client = _client()
        first_token, first_max_age = _login(client, db, member)
        assert (first_max_age, _policy_of(db, first_token)) == ("21600", (30, timedelta(hours=6)))

        _change_policy(client, admin_token, idle=25, lifetime=3)
        token, max_age = _login(client, db, member)

        assert max_age == "10800"
        assert _policy_of(db, token) == (25, timedelta(hours=3))
        assert _policy_of(db, first_token) == (25, timedelta(hours=3))
        assert _me(client, first_token).status_code == 200


# ---------------------------------------------------------------------------
# 2. New logins after a change
# ---------------------------------------------------------------------------

# (stored policy or None for no org_settings row, the patch, the expected merged policy)
_CHANGES = [
    pytest.param(None, (25, 3), (25, 3), id="both-fields"),
    pytest.param((30, 6), (45, None), (45, 6), id="idle-only"),
    pytest.param((30, 6), (None, 2), (30, 2), id="lifetime-only"),
]


class TestNewLoginAfterAChange:
    """A member's next login stores the org's merged stored + patched policy."""

    @pytest.mark.parametrize(("stored", "patch", "expected"), _CHANGES)
    def test_org_session_policy_new_member_login_stores_the_changed_policy(
        self,
        db: FakeDb,
        stored: tuple[int, int] | None,
        patch: tuple[int | None, int | None],
        expected: tuple[int, int],
    ) -> None:
        """The PATCH answers the merged security section and stores it; the login's row
        stores the idle timeout and expires_at = now() + lifetime, and Max-Age is the
        lifetime in seconds."""
        if stored is not None:
            db.add_org_settings(
                ORG_ID, session_idle_timeout_minutes=stored[0], session_max_lifetime_hours=stored[1]
            )
        admin_token = _admin_session(db)
        member = _account(db, "editor")
        client = _client()

        response = _patch(client, admin_token, _security(*patch))
        token, max_age = _login(client, db, member)

        idle, lifetime = expected
        assert response.status_code == 200, response.text
        assert response.json()["security"] == {_IDLE: idle, _LIFETIME: lifetime}
        stored_row = db.org_settings_row(ORG_ID)
        assert stored_row is not None
        assert (stored_row[_IDLE], stored_row[_LIFETIME]) == (idle, lifetime)
        assert max_age == str(lifetime * 3600)
        assert _policy_of(db, token) == (idle, timedelta(hours=lifetime))


# ---------------------------------------------------------------------------
# 3. Open sessions follow the change
# ---------------------------------------------------------------------------


class TestOpenSessionsFollow:
    """Every live session of every user of the org takes the new policy."""

    @pytest.mark.parametrize("role", ["editor", "org_admin"])
    def test_org_session_policy_open_session_follows_the_change(
        self, db: FakeDb, role: str
    ) -> None:
        """A live session created an hour ago (60 min / 12 h) stores 25 and created_at + 3 h
        after the change, and its next request is still 200."""
        admin_token = _admin_session(db)
        token = db.open_session(_account(db, role), created_ago=timedelta(hours=1))
        created_at = db.session(token)["created_at"]
        client = _client()

        _change_policy(client, admin_token, idle=25, lifetime=3)

        row = db.session(token)
        assert row["idle_timeout_minutes"] == 25
        assert row["expires_at"] == created_at + timedelta(hours=3)
        assert _me(client, token).status_code == 200

    @pytest.mark.parametrize(("stored", "patch", "expected"), _CHANGES)
    def test_org_session_policy_open_session_follows_the_merged_policy(
        self,
        db: FakeDb,
        stored: tuple[int, int] | None,
        patch: tuple[int | None, int | None],
        expected: tuple[int, int],
    ) -> None:
        """A patch of one field re-times the open sessions with the merged policy: the
        patched field and the other field's STORED value (not its column default)."""
        if stored is not None:
            db.add_org_settings(
                ORG_ID, session_idle_timeout_minutes=stored[0], session_max_lifetime_hours=stored[1]
            )
        admin_token = _admin_session(db)
        token = db.open_session(_account(db), created_ago=timedelta(minutes=30))
        client = _client()

        _change_policy(client, admin_token, *patch)

        idle, lifetime = expected
        assert _policy_of(db, token) == (idle, timedelta(hours=lifetime))

    def test_org_session_policy_session_older_than_a_shortened_lifetime_ends(
        self, db: FakeDb
    ) -> None:
        """A session created 5 hours ago, seen just now: a 3-hour lifetime makes it expire
        at created_at + 3 h (in the past), so its next request is 401."""
        admin_token = _admin_session(db)
        token = db.open_session(_account(db), created_ago=timedelta(hours=5))
        created_at = db.session(token)["created_at"]
        client = _client()

        _change_policy(client, admin_token, lifetime=3)

        assert db.session(token)["expires_at"] == created_at + timedelta(hours=3)
        response = _me(client, token)
        assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)

    def test_org_session_policy_session_idle_past_a_shortened_timeout_ends(
        self, db: FakeDb
    ) -> None:
        """A session last seen 40 minutes ago (60-minute timeout): a 25-minute timeout ends
        it, so its next request is 401."""
        admin_token = _admin_session(db)
        token = db.open_session(_account(db), last_seen_ago=timedelta(minutes=40))
        client = _client()

        _change_policy(client, admin_token, idle=25)

        assert db.session(token)["idle_timeout_minutes"] == 25
        response = _me(client, token)
        assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)

    @pytest.mark.parametrize(
        "ended",
        [
            pytest.param(
                {"last_seen_ago": timedelta(minutes=70), "created_ago": timedelta(hours=2)},
                id="idle-past-the-old-timeout",
            ),
            pytest.param(
                {"expires_in": -timedelta(hours=1), "created_ago": timedelta(hours=13)},
                id="expired",
            ),
        ],
    )
    def test_org_session_policy_ended_session_is_not_revived_by_a_longer_policy(
        self, db: FakeDb, ended: dict[str, timedelta]
    ) -> None:
        """A session that had already ended (idle 70 minutes with a 60-minute timeout, or
        expired an hour ago after 12 hours) but isn't purged yet: a 120-minute / 24-hour
        policy changes nothing on its row and its next request is still 401."""
        admin_token = _admin_session(db)
        token = db.open_session(_account(db), **ended)
        before = _row(db, token)
        client = _client()

        _change_policy(client, admin_token, idle=120, lifetime=24)

        assert _row(db, token) == before
        assert _me(client, token).status_code == 401

    def test_org_session_policy_org_admins_own_session_follows(self, db: FakeDb) -> None:
        """The patching Org Admin's own session (created 2 hours ago) stores 25 and
        created_at + 3 h, and keeps working."""
        admin_token = _admin_session(db, created_ago=timedelta(hours=2))
        created_at = db.session(admin_token)["created_at"]
        client = _client()

        _change_policy(client, admin_token, idle=25, lifetime=3)

        row = db.session(admin_token)
        assert row["idle_timeout_minutes"] == 25
        assert row["expires_at"] == created_at + timedelta(hours=3)
        assert _me(client, admin_token).status_code == 200

    def test_org_session_policy_org_admins_own_older_session_ends_after_the_change(
        self, db: FakeDb
    ) -> None:
        """The patching Org Admin's own session, created 5 hours ago: the PATCH to a
        3-hour lifetime answers 200, and the session's next request is 401."""
        admin_token = _admin_session(db, created_ago=timedelta(hours=5))
        client = _client()

        response = _patch(client, admin_token, _security(lifetime=3))

        assert response.status_code == 200, response.text
        assert _me(client, admin_token).status_code == 401


# ---------------------------------------------------------------------------
# 4. Another org and the Super Admin are untouched
# ---------------------------------------------------------------------------


class TestIsolation:
    """The change reaches the patching admin's org only."""

    def test_org_session_policy_other_orgs_sessions_are_untouched(self, db: FakeDb) -> None:
        """Another org's member and Org Admin sessions keep their rows exactly and still
        resolve; every policy UPDATE binds the patching admin's org, never the other one;
        the other org's settings row isn't created."""
        admin_token = _admin_session(db)
        other_tokens = [
            db.open_session(_account(db, role, OTHER_ORG_ID), created_ago=timedelta(hours=4))
            for role in ("editor", "org_admin")
        ]
        before = [_row(db, token) for token in other_tokens]
        client = _client()

        _change_policy(client, admin_token, idle=25, lifetime=3)

        assert [_row(db, token) for token in other_tokens] == before
        updates = db.matching(_POLICY_UPDATE)
        assert updates != []
        assert all(ORG_ID in call.args and OTHER_ORG_ID not in call.args for call in updates)
        assert db.org_settings_row(OTHER_ORG_ID) is None
        assert [_me(client, token).status_code for token in other_tokens] == [200, 200]

    def test_org_session_policy_other_orgs_login_keeps_its_own_policy(self, db: FakeDb) -> None:
        """The other org stores 50 min / 9 h: after ORG_ID's change to 25 min / 3 h, its
        member's login stores 50 and now() + 9 h (Max-Age 32400) while ORG_ID's member
        gets 25 and now() + 3 h (Max-Age 10800)."""
        db.add_org_settings(
            OTHER_ORG_ID, session_idle_timeout_minutes=50, session_max_lifetime_hours=9
        )
        admin_token = _admin_session(db)
        member = _account(db)
        other_member = _account(db, "editor", OTHER_ORG_ID)
        client = _client()

        _change_policy(client, admin_token, idle=25, lifetime=3)
        other_token, other_max_age = _login(client, db, other_member)
        token, max_age = _login(client, db, member)

        assert (other_max_age, _policy_of(db, other_token)) == ("32400", (50, timedelta(hours=9)))
        assert (max_age, _policy_of(db, token)) == ("10800", (25, timedelta(hours=3)))

    def test_org_session_policy_super_admin_keeps_the_platform_policy(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With a stored 35 min / 7 h platform policy: a Super Admin's open session keeps
        its row exactly, and a Super Admin login after ORG_ID's change to 25 min / 3 h
        stores 35 and now() + 7 h (Max-Age 25200)."""
        _store_platform_policy(monkeypatch, idle=35, lifetime=7)
        admin_token = _admin_session(db)
        super_admin = _super_admin(db)
        open_token = db.open_session(super_admin, created_ago=timedelta(hours=4))
        before = _row(db, open_token)
        client = _client()

        _change_policy(client, admin_token, idle=25, lifetime=3)
        token, max_age = _login(client, db, super_admin)

        assert _row(db, open_token) == before
        assert (max_age, _policy_of(db, token)) == ("25200", (35, timedelta(hours=7)))


# ---------------------------------------------------------------------------
# 5. Invitations accepted after a change
# ---------------------------------------------------------------------------


class TestInvitationAfterAChange:
    """Accepting an invitation opens a session with the org's current stored policy."""

    def test_org_session_policy_accepted_invitation_gets_the_new_policy(self, db: FakeDb) -> None:
        """Invited under 60 min / 12 h, accepted after the change to 25 min / 3 h: the
        cookie's Max-Age is 10800 and the session stores 25 and created_at + 3 h."""
        admin_token = _admin_session(db)
        client = _client()
        created = client.post(
            _INVITES,
            json={"email": _INVITEE_EMAIL, "role": "editor"},
            headers=_cookie(admin_token),
        )
        assert created.status_code == 201, created.text
        invite_token = db.invitation_token()

        _change_policy(client, admin_token, idle=25, lifetime=3)
        response = client.post(
            f"/api/auth/invitations/{invite_token}/accept",
            json={"name": _INVITEE_NAME, "password": _PASSWORD},
        )
        client.cookies.clear()

        assert response.status_code == 204, response.text
        token, attributes = _session_set_cookie(response)
        assert attributes.get("max-age") == "10800"
        assert _policy_of(db, token) == (25, timedelta(hours=3))


# ---------------------------------------------------------------------------
# 6. One transaction with the change; audited; only a session-field change
# ---------------------------------------------------------------------------


class TestSameTransaction:
    """The sessions change with the settings, in one committed transaction."""

    def test_org_session_policy_sessions_are_retimed_in_the_settings_transaction(
        self, db: FakeDb
    ) -> None:
        """The org_settings UPDATE and the sessions UPDATE run in one transaction, which
        commits."""
        admin_token = _admin_session(db)
        db.open_session(_account(db), created_ago=timedelta(hours=1))
        client = _client()

        _change_policy(client, admin_token, idle=25, lifetime=3)

        calls = [*db.matching(r"^update org_settings\b"), *db.matching(_POLICY_UPDATE)]
        assert len(db.matching(_POLICY_UPDATE)) == 1
        transactions = {call.tx for call in calls}
        assert len(transactions) == 1
        (tx,) = transactions
        assert tx is not None
        assert (tx, "commit") in db.transactions

    def test_org_session_policy_audit_failure_rolls_the_sessions_back(self, db: FakeDb) -> None:
        """An audit failure is a 500 and nothing changed (the open session's row, the org's
        settings row, the audit log), although the sessions UPDATE had run inside the
        transaction that rolled back."""
        admin_token = _admin_session(db)
        token = db.open_session(_account(db), created_ago=timedelta(hours=1))
        before_row = _row(db, token)
        before = db.snapshot()
        db.fail_audit = True

        response = _patch(
            _client(raise_server_exceptions=False), admin_token, _security(idle=25, lifetime=3)
        )

        assert response.status_code == 500
        updates = db.matching(_POLICY_UPDATE)
        assert len(updates) == 1
        assert updates[0].tx is not None
        assert (updates[0].tx, "commit") not in db.transactions
        assert _row(db, token) == before_row
        assert db.snapshot() == before

    def test_org_session_policy_audit_counts_the_retimed_sessions(self, db: FakeDb) -> None:
        """One org.settings_change event: the old and new values of both fields and
        sessions_updated = the org's live sessions (the Org Admin's, an Editor's and a
        second Org Admin's: 3), not the ended one, another org's or the Super Admin's."""
        admin_token = _admin_session(db)
        db.open_session(_account(db, "editor"))
        db.open_session(_account(db, "org_admin"))
        db.open_session(_account(db), last_seen_ago=timedelta(minutes=70))
        db.open_session(_account(db, "editor", OTHER_ORG_ID))
        db.open_session(_super_admin(db))
        client = _client()

        _change_policy(client, admin_token, idle=25, lifetime=3)

        rows = db.audit_rows("org.settings_change")
        assert len(rows) == 1
        assert rows[0]["metadata"] == {
            f"{_IDLE}_old": 60,
            f"{_IDLE}_new": 25,
            f"{_LIFETIME}_old": 12,
            f"{_LIFETIME}_new": 3,
            "sessions_updated": 3,
        }

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param(_security(idle=30, lifetime=6), id="same-security-values"),
            pytest.param({"instructions": "Answer briefly."}, id="instructions-only"),
            pytest.param({"retention": {"trash_retention_days": 14}}, id="retention-only"),
        ],
    )
    def test_org_session_policy_change_without_a_session_field_touches_no_session(
        self, db: FakeDb, body: dict[str, Any]
    ) -> None:
        """Stored 30 min / 6 h: a PATCH that changes no session field (the same values, or
        another section) answers 200, issues no sessions UPDATE and leaves the open
        session's row exactly as it was."""
        db.add_org_settings(ORG_ID, session_idle_timeout_minutes=30, session_max_lifetime_hours=6)
        admin_token = _admin_session(db)
        token = db.open_session(_account(db), created_ago=timedelta(hours=1))
        before = _row(db, token)

        response = _patch(_client(), admin_token, body)

        assert response.status_code == 200, response.text
        assert db.matching(_POLICY_UPDATE) == []
        assert _row(db, token) == before
