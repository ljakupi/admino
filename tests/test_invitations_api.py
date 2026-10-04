"""HTTP-layer spec for invitations (GH-153).

The FastAPI app from ``create_app()`` runs against the in-memory database of
tests/db_fakes.py (what ``admino.database.get_pool`` returns) with a fake
config whose ``server.public_url`` is ``https://admino.example.ch``. The real
``admino.invitations``, ``admino.sessions``, ``admino.email_outbox`` and
``admino.audit_events`` code runs, through the real ``require_session``; only
Argon2 is replaced by a fast fake.

What these tests pin down:
- ``POST /api/org/invitations {email, role}`` (Org Admin) → 201 with the
  ``InvitationSummary`` (id, email, role, sent_at, expires_at, expired); the
  invited account gets the caller's session ``ui_language``; the email link is
  built from ``server.public_url`` only. 409 ``{"detail", "reason":
  "email_taken"}`` for an email that exists anywhere on the platform and
  ``{"detail", "reason": "seat_limit"}`` for a full org, with nothing written;
  422 for a bad body without echo.
- ``GET /api/org/invitations`` → 200 ``{"invitations": [...]}``: the caller's
  org's pending invitations, most recently sent first, flagged ``expired``.
- ``DELETE /api/org/invitations/{id}`` → 204; ``POST
  /api/org/invitations/{id}/resend`` → 200 with the new summary. Another org's,
  an unknown or an accepted invitation → 404 ``{"detail": "Invitation not
  found"}``; a non-UUID id → 422 without echo.
- The four org routes need a session (401), authorize through
  ``admino.access.can`` (``org.users.invite`` / ``org.users.view``): an Editor,
  a Viewer and a Super Admin get 403 ``{"detail": "Forbidden"}``.
- ``GET /api/auth/invitations/{token}`` (public) → 200 exactly ``{"org_name",
  "role", "email"}``; ``POST /api/auth/invitations/{token}/accept {name,
  password}`` (public) → 204 with the ``admino_session`` cookie (HttpOnly,
  SameSite=Strict, Path=/, Max-Age = the lifetime of the invited org's stored
  session policy (GH-169: its org_settings row), Secure iff
  ``server.cookie_secure``). Every link that can't be used → 404 ``{"detail":
  "This invitation link is invalid or has expired."}`` (a malformed one before
  any database call); a password the policy refuses → 422 ``{"detail",
  "reason"}`` and the link stays usable; an audit failure → 500 and nothing
  changes.
- Rate limits: per user on the org routes (``/api/org/invitations/create``,
  ``/get``, ``/revoke``, ``/resend``), per client IP on the public ones
  (``/api/auth/invitations/get``, ``/accept``); one caller never throttles
  another. Cross-origin writes are refused (403) before any database call.
- No email, name, password, token or link in any log line or audit row.

All database calls are faked. No network, no real PostgreSQL, no SMTP.

Security notes:
- Tenant isolation: another org's invitation answers 404 like an unknown id.
- Link poisoning: the link base is ``server.public_url``, never a request header.
- Fail closed: an audit failure is a 500 and nothing is written.
"""

from __future__ import annotations

import contextlib
import copy
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from admino import passwords, server
from admino.access import Capability
from admino.server import create_app
from tests.db_fakes import (
    INVITE_LINK_PREFIX,
    ORG_ID,
    ORG_NAME,
    OTHER_ORG_ID,
    PUBLIC_URL,
    TOKEN_RE,
    FakeDb,
    fake_hash,
    plain,
    sha256,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    import httpx
    from fastapi import FastAPI
    from fastapi.dependencies.models import Dependant

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE = "admino_session"
_IP_A = "203.0.113.5"
_IP_B = "198.51.100.23"
_UA = "pytest-browser/1.0 (ua-marker-5151)"
_INVITES = "/api/org/invitations"
_EMAIL = "Api.Invitee.Marker@Example.ch"
_NAME = "Grace Hopper"
_PASSWORD = "violet-Anchor-93-quartz"
_OTHER_PASSWORD = "Tidal-Lantern-58-cobalt"
_DELETED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_WELL_FORMED_UNKNOWN = "Q" * 21 + "-" + "z" * 20 + "_"
_UNAUTHORIZED = {"detail": "Unauthorized"}
_FORBIDDEN = {"detail": "Forbidden"}
_CSRF_REFUSED = {"detail": "Cross-origin request refused"}
_RATE_LIMITED = {"detail": "Rate limit exceeded"}
_INVALID = {"detail": "This invitation link is invalid or has expired."}
_NOT_FOUND = {"detail": "Invitation not found"}
_EMAIL_TAKEN = {"detail": "A user with this email already exists.", "reason": "email_taken"}
_SEAT_LIMIT = {"detail": "The organization has no free seats.", "reason": "seat_limit"}
_SUMMARY_KEYS = {"id", "email", "role", "sent_at", "expires_at", "expired"}
_ROLES = ["org_admin", "editor", "viewer"]
_NOT_ADMINS = ["editor", "viewer", "super_admin"]

_ORG_ROUTES: list[tuple[str, str]] = [
    ("POST", "/api/org/invitations"),
    ("GET", "/api/org/invitations"),
    ("DELETE", "/api/org/invitations/{invitation_id}"),
    ("POST", "/api/org/invitations/{invitation_id}/resend"),
]
_PUBLIC_ROUTES: list[tuple[str, str]] = [
    ("GET", "/api/auth/invitations/{token}"),
    ("POST", "/api/auth/invitations/{token}/accept"),
]
_KEY_CREATE = "/api/org/invitations/create"
_KEY_LIST = "/api/org/invitations/get"
_KEY_REVOKE = "/api/org/invitations/revoke"
_KEY_RESEND = "/api/org/invitations/resend"
_KEY_DETAILS = "/api/auth/invitations/get"
_KEY_ACCEPT = "/api/auth/invitations/accept"
# The separate, tighter per-user budget of refused sends (email_taken, seat_limit).
_KEY_REFUSED = "/api/org/invitations/refused"
_RATE_KEYS = [
    _KEY_CREATE,
    _KEY_LIST,
    _KEY_REVOKE,
    _KEY_RESEND,
    _KEY_DETAILS,
    _KEY_ACCEPT,
    _KEY_REFUSED,
]
# Read at import, before any fixture patches the limits.
_CONFIGURED_REFUSED_LIMIT = server._RATE_LIMITS.get(_KEY_REFUSED)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch) -> FakeDb:
    """The fake database the server's get_pool() returns."""
    fake = FakeDb()
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
def configured_keys(monkeypatch: pytest.MonkeyPatch) -> frozenset[str]:
    """Functional tests aren't about rate limits: give the six invitation routes a large
    bucket (the rate-limit tests set their own). Returns the keys the server configured
    itself, before this fixture patched them."""
    present = frozenset(key for key in _RATE_KEYS if key in server._RATE_LIMITS)
    for key in _RATE_KEYS:
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))
    return present


def _config(*, cookie_secure: bool = True) -> MagicMock:
    """A minimal config with the public URL invitation links are built from."""
    config = MagicMock()
    del config.auth
    config.limits.max_message_length = 4000
    config.server.host = "127.0.0.1"
    config.server.port = 8000
    config.server.cookie_secure = cookie_secure
    config.server.public_url = PUBLIC_URL
    config.llm.provider = "infomaniak"
    config.llm.active_model_name = "test-model"
    return config


def _app(*, cookie_secure: bool = True) -> FastAPI:
    """create_app with a stub agent and the fake config (no lifespan runs under TestClient)."""
    return create_app(agent=MagicMock(), config=_config(cookie_secure=cookie_secure))  # type: ignore[arg-type]


def _client(app: FastAPI, ip: str = _IP_A, **kwargs: Any) -> TestClient:
    """A client whose peer address is ``ip``; redirects are not followed."""
    return TestClient(app, client=(ip, 50000), follow_redirects=False, **kwargs)


def _cookie(token: str, **extra: str) -> dict[str, str]:
    """Request headers carrying a session cookie (plus any extra headers)."""
    return {"Cookie": f"{_COOKIE}={token}", **extra}


def _session_cookie_headers(response: httpx.Response) -> list[str]:
    return [
        h for h in response.headers.get_list("set-cookie") if h.lower().startswith(f"{_COOKIE}=")
    ]


def _session_set_cookie(response: httpx.Response) -> tuple[str, dict[str, str | None]]:
    """Return (value, attributes) of the one admino_session Set-Cookie header."""
    headers = _session_cookie_headers(response)
    assert len(headers) == 1, response.headers.get_list("set-cookie")
    parts = [part.strip() for part in headers[0].split(";")]
    value = parts[0].split("=", 1)[1]
    attributes: dict[str, str | None] = {}
    for part in parts[1:]:
        key, sep, attr_value = part.partition("=")
        attributes[key.strip().lower()] = attr_value.strip() if sep else None
    return value, attributes


def _depends_on(dependant: Dependant, target: Callable[..., Any]) -> bool:
    """True when the dependency tree below ``dependant`` contains ``target``."""
    return any(dep.call is target or _depends_on(dep, target) for dep in dependant.dependencies)


def _route(app: FastAPI, method: str, path: str) -> APIRoute:
    """The one APIRoute registered for (method, path)."""
    matches = [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and route.path == path and method in route.methods
    ]
    assert len(matches) == 1, f"{method} {path} is not registered"
    return matches[0]


def _admin(db: FakeDb, org_id: uuid.UUID = ORG_ID, **fields: Any) -> tuple[uuid.UUID, str]:
    """An Org Admin with a live session: (user id, session token)."""
    user_id = db.add_account(role="org_admin", org_id=org_id, **fields)
    return user_id, db.open_session(user_id)


def _session_of(db: FakeDb, who: str) -> str:
    """A live session of a Super Admin or of a member of ORG_ID with the given role."""
    if who == "super_admin":
        return db.open_session(db.add_account(kind="super_admin", role=None))
    return db.open_session(db.add_account(role=who))


def _create(
    client: TestClient, session: str, email: str = _EMAIL, role: str = "editor", **headers: str
) -> httpx.Response:
    return client.post(
        _INVITES, json={"email": email, "role": role}, headers=_cookie(session, **headers)
    )


def _list(client: TestClient, session: str) -> httpx.Response:
    return client.get(_INVITES, headers=_cookie(session))


def _revoke(
    client: TestClient, session: str, invitation_id: object, **headers: str
) -> httpx.Response:
    return client.delete(f"{_INVITES}/{invitation_id}", headers=_cookie(session, **headers))


def _resend(
    client: TestClient, session: str, invitation_id: object, **headers: str
) -> httpx.Response:
    return client.post(f"{_INVITES}/{invitation_id}/resend", headers=_cookie(session, **headers))


def _details(client: TestClient, token: str, **kwargs: Any) -> httpx.Response:
    return client.get(f"/api/auth/invitations/{token}", **kwargs)


def _accept(
    client: TestClient,
    token: str,
    name: str = _NAME,
    password: str = _PASSWORD,
    **kwargs: Any,
) -> httpx.Response:
    return client.post(
        f"/api/auth/invitations/{token}/accept", json={"name": name, "password": password}, **kwargs
    )


def _invite(
    db: FakeDb, client: TestClient, session: str, email: str = _EMAIL, role: str = "editor"
) -> tuple[str, str]:
    """Send an invitation over HTTP: (invitation id as sent in JSON, raw token)."""
    response = _create(client, session, email, role)
    assert response.status_code == 201, response.text
    user = db.user_by_email(email.strip())
    assert user is not None
    return response.json()["id"], db.invitation_token(uuid.UUID(int=user["id"].int))


def _invited_id(db: FakeDb, email: str = _EMAIL) -> uuid.UUID:
    row = db.user_by_email(email)
    assert row is not None, email
    return uuid.UUID(int=row["id"].int)


def _age(db: FakeDb, invitation_id: Any, by: timedelta) -> None:
    """Move an invitation back in time (created_at, sent_at, expires_at together)."""
    row = db.invitations[plain(uuid.UUID(str(invitation_id)))]
    for column in ("created_at", "sent_at", "expires_at"):
        row[column] -= by


def _expire(db: FakeDb, invitation_id: Any) -> None:
    _age(db, invitation_id, timedelta(hours=73))


def _state(db: FakeDb) -> dict[str, Any]:
    """A deep copy of every table except the sessions, for "nothing changed" checks."""
    return copy.deepcopy(
        {
            "users": db.users,
            "orgs": db.orgs,
            "invitations": db.invitations,
            "tokens": db.tokens,
            "outbox": db.outbox,
            "audit": db.audit,
        }
    )


def _assert_only_refusal_audited(
    db: FakeDb, before: dict[str, Any], *, actor: uuid.UUID, role: str, reason: str
) -> None:
    """Every table is unchanged except audit_events, which gained exactly one content-free
    invitation.refuse row by the admin, with the client IP."""
    after = _state(db)
    audit_before = before.pop("audit")
    audit_after = after.pop("audit")
    assert after == before
    added = audit_after[len(audit_before) :]
    assert audit_after[: len(audit_before)] == audit_before
    assert len(added) == 1, added
    row = added[0]
    assert row["action"] == "invitation.refuse"
    assert (row["actor_kind"], plain(row["actor_user_id"])) == ("member", actor)
    assert plain(row["org_id"]) == ORG_ID
    assert (row["target_type"], row["target_ids"]) == (None, [])
    assert row["metadata"] == {"role": role, reason: True}
    assert row["ip"] == _IP_A


def _policy_body(reason: str) -> dict[str, str]:
    """The 422 body of a policy failure."""
    return {"detail": str(passwords.PasswordPolicyError(reason)), "reason": reason}  # type: ignore[arg-type]


def _unusable(db: FakeDb, client: TestClient, session: str, case: str) -> str:
    """Send an invitation over HTTP as the Org Admin of ``session``, make its link unusable
    in one way and return that link's token."""
    invitation_id, token = _invite(db, client, session)
    user_id = _invited_id(db)
    if case == "unknown":
        return _WELL_FORMED_UNKNOWN
    if case == "expired":
        _expire(db, invitation_id)
    elif case == "accepted":
        assert _accept(client, token).status_code == 204
        client.cookies.clear()
    elif case == "revoked":
        assert _revoke(client, session, invitation_id).status_code == 204
    elif case == "rotated":
        assert _resend(client, session, invitation_id).status_code == 200
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
    "accepted",
    "revoked",
    "rotated",
    "user-deactivated",
    "user-deleted",
    "org-deactivated",
    "org-pending-deletion",
]

_MALFORMED_TOKENS = [
    pytest.param("short", id="short"),
    pytest.param("A" * 42, id="42-chars"),
    pytest.param("A" * 44, id="44-chars"),
    pytest.param("A" * 42 + ".", id="dot"),
    pytest.param("A" * 42 + "~", id="tilde"),
    pytest.param("A" * 42 + "=", id="padding"),
    pytest.param("x" * 200, id="200-chars"),
]


class _CanSpy:
    """Wraps admino.access.can wherever it is looked up; records every capability asked
    for and can refuse chosen capabilities."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, deny: frozenset[Capability] = frozenset()
    ) -> None:
        from admino import access

        real = access.can
        self.capabilities: list[Capability] = []

        def spy(principal: Any, capability: Any) -> bool:
            self.capabilities.append(capability)
            if capability in deny:
                return False
            return real(principal, capability)

        monkeypatch.setattr(access, "can", spy)
        monkeypatch.setattr(server, "can", spy)
        with contextlib.suppress(ImportError):
            from admino import invitations

            if hasattr(invitations, "can"):
                monkeypatch.setattr(invitations, "can", spy)


# ---------------------------------------------------------------------------
# 1. The routes
# ---------------------------------------------------------------------------


class TestRoutes:
    """Four org routes behind a session, two public ones, each with its own bucket."""

    @pytest.mark.parametrize(("method", "path"), _ORG_ROUTES + _PUBLIC_ROUTES)
    def test_invitations_api_route_is_registered(self, method: str, path: str) -> None:
        _route(_app(), method, path)

    @pytest.mark.parametrize(("method", "path"), _ORG_ROUTES)
    def test_invitations_api_org_route_depends_on_require_session(
        self, method: str, path: str
    ) -> None:
        route = _route(_app(), method, path)

        assert _depends_on(route.dependant, server.require_session)

    @pytest.mark.parametrize(("method", "path"), _PUBLIC_ROUTES)
    def test_invitations_api_public_route_does_not_depend_on_require_session(
        self, method: str, path: str
    ) -> None:
        """The invitee has no account yet: the link routes work logged out."""
        route = _route(_app(), method, path)

        assert not _depends_on(route.dependant, server.require_session)

    def test_invitations_api_rate_limit_keys_are_configured(
        self, configured_keys: frozenset[str]
    ) -> None:
        """Each route has its own (rate, burst) entry in server._RATE_LIMITS."""
        assert configured_keys == frozenset(_RATE_KEYS)

    @pytest.mark.parametrize(
        ("method", "url", "template"),
        [
            ("POST", _INVITES, "/api/org/invitations"),
            ("GET", _INVITES, "/api/org/invitations"),
            ("DELETE", f"{_INVITES}/{uuid.uuid4()}", "/api/org/invitations/{invitation_id}"),
            (
                "POST",
                f"{_INVITES}/{uuid.uuid4()}/resend",
                "/api/org/invitations/{invitation_id}/resend",
            ),
        ],
    )
    def test_invitations_api_org_route_without_a_session_is_401(
        self, db: FakeDb, method: str, url: str, template: str
    ) -> None:
        """No cookie → 401 and nothing is read or written."""
        _route(_app(), method, template)
        body = {"json": {"email": "a@example.ch", "role": "editor"}} if url == _INVITES else {}

        response = _client(_app()).request(method, url, **body)

        assert response.status_code == 401
        assert response.json() == _UNAUTHORIZED
        assert db.calls == []


# ---------------------------------------------------------------------------
# 2. POST /api/org/invitations
# ---------------------------------------------------------------------------

_BAD_BODIES = [
    pytest.param({"email": "ECHOMARK42 x@example.ch", "role": "editor"}, id="space-in-email"),
    pytest.param({"email": "ECHOMARK42.example.ch", "role": "editor"}, id="no-at"),
    pytest.param({"email": "ECHOMARK42@a@example.ch", "role": "editor"}, id="two-ats"),
    pytest.param({"email": "ECHOMARK42@examplech", "role": "editor"}, id="no-dot"),
    pytest.param({"email": "ECHOMARK42@examplech.", "role": "editor"}, id="dot-last"),
    pytest.param(
        {"email": "ECHOMARK42" + "a" * 245 + "@example.ch", "role": "editor"}, id="too-long"
    ),
    pytest.param({"email": "ECHOMARK42@example.ch", "role": "ECHOMARK42"}, id="unknown-role"),
    pytest.param({"email": "ECHOMARK42@example.ch", "role": "super_admin"}, id="super-admin-role"),
    pytest.param(
        {"email": "ECHOMARK42@example.ch", "role": "editor", "org_id": "ECHOMARK42"},
        id="extra-org-id",
    ),
    pytest.param({"email": "ECHOMARK42@example.ch"}, id="no-role"),
    pytest.param({"role": "editor"}, id="no-email"),
    pytest.param({}, id="empty"),
]


class TestCreateRoute:
    """An Org Admin sends an invitation."""

    def test_invitations_api_create_returns_201_with_the_summary(self, db: FakeDb) -> None:
        """201; exactly the summary fields; the id is the new invitation's."""
        _, session = _admin(db)

        response = _create(_client(_app()), session, role="viewer")

        assert response.status_code == 201
        body = response.json()
        assert set(body) == _SUMMARY_KEYS
        invitation = db.invitation_of(_invited_id(db))
        assert invitation is not None
        assert body["id"] == str(invitation["id"])
        assert (body["email"], body["role"], body["expired"]) == (_EMAIL, "viewer", False)
        assert datetime.fromisoformat(body["sent_at"]) == invitation["sent_at"]
        assert datetime.fromisoformat(body["expires_at"]) == invitation["expires_at"]

    def test_invitations_api_create_invites_into_the_callers_org(self, db: FakeDb) -> None:
        """An invited member of the caller's org with the role, no name, no password."""
        _, session = _admin(db, org_id=OTHER_ORG_ID)

        _create(_client(_app()), session, role="org_admin")

        row = db.user_by_email(_EMAIL)
        assert row is not None
        assert (row["org_id"], row["role"], row["status"], row["kind"]) == (
            OTHER_ORG_ID,
            "org_admin",
            "invited",
            "member",
        )
        assert (row["name"], row["password_hash"]) == (None, None)

    @pytest.mark.parametrize("language", ["de", "fr", "en"])
    def test_invitations_api_create_copies_the_callers_language(
        self, db: FakeDb, language: str
    ) -> None:
        """The invited row gets the caller's session ui_language; so does the email."""
        _, session = _admin(db, ui_language=language)

        _create(_client(_app()), session)

        row = db.user_by_email(_EMAIL)
        assert row is not None
        assert row["ui_language"] == language
        assert [email["language"] for email in db.invitation_emails()] == [language]

    def test_invitations_api_create_strips_the_email(self, db: FakeDb) -> None:
        _, session = _admin(db)

        response = _create(_client(_app()), session, email="  padded.person@example.ch\t")

        assert response.status_code == 201
        assert response.json()["email"] == "padded.person@example.ch"
        assert db.user_by_email("padded.person@example.ch") is not None

    def test_invitations_api_create_link_comes_from_the_configured_public_url(
        self, db: FakeDb
    ) -> None:
        """A hostile Host / X-Forwarded-Host doesn't change the link (link poisoning)."""
        _, session = _admin(db)

        _create(
            _client(_app()),
            session,
            **{"X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "http"},
        )

        link = db.invitation_emails()[0]["params"]["accept_link"]
        assert link.startswith(INVITE_LINK_PREFIX)
        assert TOKEN_RE.fullmatch(link[len(INVITE_LINK_PREFIX) :])
        assert "evil" not in json.dumps(db.outbox, default=str)

    def test_invitations_api_create_is_audited_with_the_client_ip(self, db: FakeDb) -> None:
        admin, session = _admin(db)

        response = _create(_client(_app(), ip=_IP_B), session)

        rows = db.audit_rows("invitation.create")
        assert len(rows) == 1
        assert (rows[0]["actor_user_id"], rows[0]["org_id"], rows[0]["ip"]) == (
            admin,
            ORG_ID,
            _IP_B,
        )
        assert rows[0]["target_ids"] == [response.json()["id"]]

    @pytest.mark.parametrize("role", _ROLES)
    def test_invitations_api_create_accepts_every_member_role(self, db: FakeDb, role: str) -> None:
        _, session = _admin(db)

        response = _create(_client(_app()), session, role=role)

        assert response.status_code == 201
        assert response.json()["role"] == role

    @pytest.mark.parametrize("body", _BAD_BODIES)
    def test_invitations_api_create_bad_body_is_422_without_echo(
        self, db: FakeDb, body: dict[str, Any]
    ) -> None:
        """422; nothing the caller sent comes back; nothing is inserted."""
        _route(_app(), "POST", _INVITES)
        _, session = _admin(db)
        before = _state(db)

        response = _client(_app()).post(_INVITES, json=body, headers=_cookie(session))

        assert response.status_code == 422
        assert "ECHOMARK42" not in response.text
        assert "a" * 40 not in response.text
        assert _state(db) == before
        assert db.matching(r"^insert into users\b") == []

    @pytest.mark.parametrize("who", _NOT_ADMINS)
    def test_invitations_api_create_forbidden_without_org_users_invite(
        self, db: FakeDb, who: str
    ) -> None:
        """An Editor, a Viewer and a Super Admin get 403 {"detail": "Forbidden"}; nothing is
        written."""
        _route(_app(), "POST", _INVITES)
        session = _session_of(db, who)
        before = _state(db)

        response = _create(_client(_app()), session)

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        assert _state(db) == before

    @pytest.mark.parametrize(
        "existing",
        [
            pytest.param({"org_id": OTHER_ORG_ID}, id="active-other-org"),
            pytest.param({"email": "API.INVITEE.MARKER@example.CH"}, id="other-capitalization"),
            pytest.param({"kind": "super_admin", "role": None}, id="super-admin"),
            pytest.param({"status": "deactivated"}, id="deactivated"),
            pytest.param({"deleted_at": _DELETED_AT}, id="soft-deleted"),
        ],
    )
    def test_invitations_api_create_existing_email_is_409_email_taken(
        self, db: FakeDb, existing: dict[str, Any]
    ) -> None:
        """409 {"detail", "reason": "email_taken"}; only the invitation.refuse audit row is
        written."""
        _route(_app(), "POST", _INVITES)
        admin, session = _admin(db)
        db.add_account(**{"email": _EMAIL, **existing})
        before = _state(db)

        response = _create(_client(_app()), session)

        assert response.status_code == 409
        assert response.json() == _EMAIL_TAKEN
        _assert_only_refusal_audited(db, before, actor=admin, role="editor", reason="email_taken")

    def test_invitations_api_create_pending_invitation_email_is_409(self, db: FakeDb) -> None:
        """Inviting an email twice (padded and in capitals the second time) → 409."""
        admin, session = _admin(db)
        client = _client(_app())
        _invite(db, client, session)
        before = _state(db)

        response = _create(client, session, email="  " + _EMAIL.upper() + " ", role="viewer")

        assert response.status_code == 409
        assert response.json() == _EMAIL_TAKEN
        _assert_only_refusal_audited(db, before, actor=admin, role="viewer", reason="email_taken")

    def test_invitations_api_create_full_org_is_409_seat_limit(self, db: FakeDb) -> None:
        """One seat, taken by the admin: 409 {"detail", "reason": "seat_limit"}; only the
        invitation.refuse audit row is written."""
        _route(_app(), "POST", _INVITES)
        db.add_org(ORG_ID, seats=1)
        admin, session = _admin(db)
        before = _state(db)

        response = _create(_client(_app()), session)

        assert response.status_code == 409
        assert response.json() == _SEAT_LIMIT
        _assert_only_refusal_audited(db, before, actor=admin, role="editor", reason="seat_limit")

    def test_invitations_api_create_audit_failure_is_500_and_writes_nothing(
        self, db: FakeDb
    ) -> None:
        _route(_app(), "POST", _INVITES)
        _, session = _admin(db)
        before = _state(db)
        db.fail_audit = True

        response = _create(_client(_app(), raise_server_exceptions=False), session)

        assert response.status_code == 500
        assert _state(db) == before

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
            pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
        ],
    )
    def test_invitations_api_create_cross_origin_is_refused(
        self, db: FakeDb, headers: dict[str, str]
    ) -> None:
        """CSRF: 403 before anything runs (no database call at all)."""
        _route(_app(), "POST", _INVITES)
        _, session = _admin(db)

        response = _create(_client(_app()), session, **headers)

        assert response.status_code == 403
        assert response.json() == _CSRF_REFUSED
        assert db.calls == []

    def test_invitations_api_create_rate_limit_is_per_user(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The bucket is ("/api/org/invitations/create", "user:<id>"); one admin spending it
        doesn't throttle another."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _KEY_CREATE, (0.001, 2))
        first, token_a = _admin(db)
        _, token_b = _admin(db)
        client = _client(app)

        statuses = [
            _create(client, token_a, email=f"person.{index}@example.ch").status_code
            for index in range(3)
        ]
        limited = _create(client, token_a, email="person.9@example.ch")
        other = _create(client, token_b, email="other.person@example.ch")

        assert statuses == [201, 201, 429]
        assert limited.json() == _RATE_LIMITED
        assert other.status_code == 201
        assert (_KEY_CREATE, f"user:{first}") in server._rate_buckets

    def test_invitations_api_refused_budget_is_tighter_than_create(self) -> None:
        """Refused sends have their own budget: at most a burst of 5, then one a minute."""
        assert _CONFIGURED_REFUSED_LIMIT is not None
        rate, burst = _CONFIGURED_REFUSED_LIMIT
        assert rate <= 1 / 60
        assert burst <= 5

    def test_invitations_api_refused_sends_spend_a_per_user_budget(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two refused sends spend a budget of 2: the next send, even of a fresh email, is a
        429 before any database work. Another admin keeps their own budget."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _KEY_REFUSED, (0.001, 2))
        first, token_a = _admin(db)
        _, token_b = _admin(db)
        db.add_account(email="taken.one@example.ch", org_id=OTHER_ORG_ID)
        db.add_account(email="taken.two@example.ch", org_id=OTHER_ORG_ID)
        client = _client(app)

        refused = [
            _create(client, token_a, email=email).status_code
            for email in ("taken.one@example.ch", "taken.two@example.ch")
        ]
        calls_before = len(db.calls)
        users_before = copy.deepcopy(db.users)
        limited = _create(client, token_a, email="fresh.person@example.ch")
        calls_during = db.calls[calls_before:]
        other = _create(client, token_b, email="taken.one@example.ch")

        assert refused == [409, 409]
        assert limited.status_code == 429
        assert limited.json() == _RATE_LIMITED
        # Only the session lookup of the throttled request ran: no invitation work (no
        # invitations statement, no org row lock, no users insert).
        assert not any("invitations" in call.normalized for call in calls_during)
        assert not any(" for update" in call.normalized for call in calls_during)
        assert not any(call.normalized.startswith("insert into users") for call in calls_during)
        assert db.users == users_before
        assert other.status_code == 409
        assert (_KEY_REFUSED, f"user:{first}") in server._rate_buckets

    def test_invitations_api_successful_sends_dont_spend_the_refused_budget(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Successful sends leave the refused budget alone; a seat_limit refusal spends it
        like an email_taken one."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _KEY_REFUSED, (0.001, 1))
        db.add_org(ORG_ID, seats=4)
        _, session = _admin(db)
        client = _client(app)

        sent = [
            _create(client, session, email=f"person.{index}@example.ch").status_code
            for index in range(3)
        ]
        full = _create(client, session, email="person.9@example.ch")
        after = _create(client, session, email="person.10@example.ch")

        assert sent == [201, 201, 201]
        assert full.status_code == 409
        assert full.json() == _SEAT_LIMIT
        assert after.status_code == 429


# ---------------------------------------------------------------------------
# 3. GET /api/org/invitations
# ---------------------------------------------------------------------------


class TestListRoute:
    """The caller's org's pending invitations."""

    def test_invitations_api_list_shape_order_and_scope(self, db: FakeDb) -> None:
        """200 {"invitations": [...]}: exactly the summary fields; most recently sent
        first; accepted invitations and another org's are left out."""
        _, session = _admin(db)
        _, other_session = _admin(db, org_id=OTHER_ORG_ID)
        client = _client(_app())
        older, _ = _invite(db, client, session, email="older.person@example.ch")
        newer, _ = _invite(db, client, session, email="newer.person@example.ch", role="viewer")
        _age(db, older, timedelta(hours=5))
        _age(db, newer, timedelta(hours=1))
        _, accepted_token = _invite(db, client, session, email="accepted.person@example.ch")
        assert _accept(client, accepted_token).status_code == 204
        client.cookies.clear()
        _invite(db, client, other_session, email="other.org@example.ch")

        response = _list(client, session)

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"invitations"}
        entries = body["invitations"]
        assert [entry["id"] for entry in entries] == [newer, older]
        assert all(set(entry) == _SUMMARY_KEYS for entry in entries)
        assert [(entry["email"], entry["role"]) for entry in entries] == [
            ("newer.person@example.ch", "viewer"),
            ("older.person@example.ch", "editor"),
        ]

    def test_invitations_api_list_flags_expired_invitations(self, db: FakeDb) -> None:
        _, session = _admin(db)
        client = _client(_app())
        live, _ = _invite(db, client, session, email="live.person@example.ch")
        stale, _ = _invite(db, client, session, email="stale.person@example.ch")
        _expire(db, stale)

        entries = {entry["id"]: entry for entry in _list(client, session).json()["invitations"]}

        assert (entries[live]["expired"], entries[stale]["expired"]) == (False, True)

    def test_invitations_api_list_never_shows_a_token_or_hash(self, db: FakeDb) -> None:
        _, session = _admin(db)
        client = _client(_app())
        _, token = _invite(db, client, session)

        response = _list(client, session)

        assert response.status_code == 200
        assert token not in response.text
        assert sha256(token).hex() not in response.text
        assert "token" not in response.text

    @pytest.mark.parametrize("who", _NOT_ADMINS)
    def test_invitations_api_list_forbidden_without_org_users_view(
        self, db: FakeDb, who: str
    ) -> None:
        _route(_app(), "GET", _INVITES)
        session = _session_of(db, who)

        response = _list(_client(_app()), session)

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN

    def test_invitations_api_list_rate_limit_is_per_user(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _KEY_LIST, (0.001, 2))
        first, token_a = _admin(db)
        _, token_b = _admin(db)
        client = _client(app)

        statuses = [_list(client, token_a).status_code for _ in range(3)]
        other = _list(client, token_b)

        assert statuses == [200, 200, 429]
        assert _list(client, token_a).json() == _RATE_LIMITED
        assert other.status_code == 200
        assert (_KEY_LIST, f"user:{first}") in server._rate_buckets


# ---------------------------------------------------------------------------
# 4. DELETE /api/org/invitations/{invitation_id}
# ---------------------------------------------------------------------------


def _foreign_or_unknown(db: FakeDb, client: TestClient, session: str, case: str) -> str:
    """An invitation id the Org Admin of ORG_ID (``session``) can't act on."""
    if case == "other-org":
        _, other_session = _admin(db, org_id=OTHER_ORG_ID)
        invitation_id, _ = _invite(db, client, other_session, email="other.org@example.ch")
        return invitation_id
    if case == "accepted":
        invitation_id, token = _invite(db, client, session, email="accepted.person@example.ch")
        assert _accept(client, token).status_code == 204
        client.cookies.clear()
        return invitation_id
    return str(uuid.uuid4())


class TestRevokeRoute:
    """An Org Admin revokes a pending invitation of their org."""

    def test_invitations_api_revoke_deletes_the_invitation(self, db: FakeDb) -> None:
        """204 with an empty body; the invited account, its invitation and its email are
        gone, and the link answers 404."""
        _, session = _admin(db)
        client = _client(_app())
        invitation_id, token = _invite(db, client, session)
        user_id = _invited_id(db)

        response = _revoke(client, session, invitation_id)

        assert response.status_code == 204
        assert response.content == b""
        assert user_id not in db.users
        assert db.invitations == {}
        assert db.invitation_emails(user_id) == []
        assert _details(client, token).status_code == 404

    def test_invitations_api_revoke_is_audited_with_the_client_ip(self, db: FakeDb) -> None:
        admin, session = _admin(db)
        invitation_id, _ = _invite(db, _client(_app()), session)
        user_id = _invited_id(db)

        _revoke(_client(_app(), ip=_IP_B), session, invitation_id)

        rows = db.audit_rows("invitation.revoke")
        assert len(rows) == 1
        assert (rows[0]["actor_user_id"], rows[0]["org_id"], rows[0]["ip"]) == (
            admin,
            ORG_ID,
            _IP_B,
        )
        assert rows[0]["target_ids"] == [invitation_id]
        assert rows[0]["metadata"] == {"user_id": str(user_id)}

    @pytest.mark.parametrize("case", ["other-org", "unknown", "accepted"])
    def test_invitations_api_revoke_outside_the_orgs_pending_invitations_is_404(
        self, db: FakeDb, case: str
    ) -> None:
        """404 {"detail": "Invitation not found"}; nothing changes; nothing is audited."""
        _, session = _admin(db)
        client = _client(_app())
        invitation_id = _foreign_or_unknown(db, client, session, case)
        before = _state(db)

        response = _revoke(client, session, invitation_id)

        assert response.status_code == 404
        assert response.json() == _NOT_FOUND
        assert _state(db) == before

    def test_invitations_api_revoke_404_bodies_are_identical(self, db: FakeDb) -> None:
        _, session = _admin(db)
        client = _client(_app())
        ids = [
            _foreign_or_unknown(db, client, session, case)
            for case in ("other-org", "unknown", "accepted")
        ]

        responses = [_revoke(client, session, invitation_id) for invitation_id in ids]

        assert {response.status_code for response in responses} == {404}
        assert len({response.content for response in responses}) == 1

    @pytest.mark.parametrize("bad_id", ["not-a-uuid-ECHOMARK42", "12345", "x" * 200])
    def test_invitations_api_revoke_non_uuid_is_422_without_echo(
        self, db: FakeDb, bad_id: str
    ) -> None:
        _route(_app(), "DELETE", "/api/org/invitations/{invitation_id}")
        _, session = _admin(db)

        response = _revoke(_client(_app()), session, bad_id)

        assert response.status_code == 422
        assert "ECHOMARK42" not in response.text
        assert "x" * 20 not in response.text
        assert db.matching(r"^delete from\b") == []

    @pytest.mark.parametrize("who", _NOT_ADMINS)
    def test_invitations_api_revoke_forbidden_without_org_users_invite(
        self, db: FakeDb, who: str
    ) -> None:
        _, session = _admin(db)
        client = _client(_app())
        invitation_id, _ = _invite(db, client, session)
        before = _state(db)

        response = _revoke(client, _session_of(db, who), invitation_id)

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        after = _state(db)
        after["users"] = {key: row for key, row in after["users"].items() if key in before["users"]}
        assert after == before

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
            pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
        ],
    )
    def test_invitations_api_revoke_cross_origin_is_refused(
        self, db: FakeDb, headers: dict[str, str]
    ) -> None:
        _route(_app(), "DELETE", "/api/org/invitations/{invitation_id}")
        _, session = _admin(db)
        client = _client(_app())
        invitation_id, _ = _invite(db, client, session)
        db.calls.clear()

        response = _revoke(client, session, invitation_id, **headers)

        assert response.status_code == 403
        assert response.json() == _CSRF_REFUSED
        assert db.calls == []
        assert len(db.invitations) == 1

    def test_invitations_api_revoke_audit_failure_is_500_and_deletes_nothing(
        self, db: FakeDb
    ) -> None:
        _, session = _admin(db)
        invitation_id, _ = _invite(db, _client(_app()), session)
        before = _state(db)
        db.fail_audit = True

        response = _revoke(_client(_app(), raise_server_exceptions=False), session, invitation_id)

        assert response.status_code == 500
        assert _state(db) == before

    def test_invitations_api_revoke_rate_limit_is_per_user(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _KEY_REVOKE, (0.001, 1))
        first, token_a = _admin(db)
        _, token_b = _admin(db)
        client = _client(app)

        _revoke(client, token_a, uuid.uuid4())
        exhausted = _revoke(client, token_a, uuid.uuid4())
        other = _revoke(client, token_b, uuid.uuid4())

        assert exhausted.status_code == 429
        assert exhausted.json() == _RATE_LIMITED
        assert other.status_code == 404
        assert (_KEY_REVOKE, f"user:{first}") in server._rate_buckets


# ---------------------------------------------------------------------------
# 5. POST /api/org/invitations/{invitation_id}/resend
# ---------------------------------------------------------------------------


class TestResendRoute:
    """An Org Admin sends a pending invitation again with a new link."""

    def test_invitations_api_resend_rotates_the_link(self, db: FakeDb) -> None:
        """200 with the summary (same id, new dates); a second email; the old link answers
        404 and the new one works."""
        _, session = _admin(db)
        client = _client(_app())
        invitation_id, old = _invite(db, client, session)
        _age(db, invitation_id, timedelta(hours=10))
        user_id = _invited_id(db)

        response = _resend(client, session, invitation_id)

        assert response.status_code == 200
        body = response.json()
        assert set(body) == _SUMMARY_KEYS
        row = db.invitations[plain(uuid.UUID(invitation_id))]
        assert (body["id"], body["expired"]) == (invitation_id, False)
        assert datetime.fromisoformat(body["sent_at"]) == row["sent_at"]
        assert datetime.fromisoformat(body["expires_at"]) == row["expires_at"]
        new = db.invitation_token(user_id)
        assert new != old
        assert len(db.invitation_emails(user_id)) == 2
        assert _details(client, old).status_code == 404
        assert _details(client, new).status_code == 200

    def test_invitations_api_resend_is_audited_with_the_client_ip(self, db: FakeDb) -> None:
        admin, session = _admin(db)
        invitation_id, _ = _invite(db, _client(_app()), session, role="viewer")

        _resend(_client(_app(), ip=_IP_B), session, invitation_id)

        rows = db.audit_rows("invitation.resend")
        assert len(rows) == 1
        assert (rows[0]["actor_user_id"], rows[0]["org_id"], rows[0]["ip"]) == (
            admin,
            ORG_ID,
            _IP_B,
        )
        assert rows[0]["target_ids"] == [invitation_id]
        assert rows[0]["metadata"] == {"role": "viewer", "user_id": str(_invited_id(db))}

    @pytest.mark.parametrize("case", ["other-org", "unknown", "accepted"])
    def test_invitations_api_resend_outside_the_orgs_pending_invitations_is_404(
        self, db: FakeDb, case: str
    ) -> None:
        _, session = _admin(db)
        client = _client(_app())
        invitation_id = _foreign_or_unknown(db, client, session, case)
        before = _state(db)

        response = _resend(client, session, invitation_id)

        assert response.status_code == 404
        assert response.json() == _NOT_FOUND
        assert _state(db) == before

    @pytest.mark.parametrize("bad_id", ["not-a-uuid-ECHOMARK42", "12345", "x" * 200])
    def test_invitations_api_resend_non_uuid_is_422_without_echo(
        self, db: FakeDb, bad_id: str
    ) -> None:
        _route(_app(), "POST", "/api/org/invitations/{invitation_id}/resend")
        _, session = _admin(db)

        response = _resend(_client(_app()), session, bad_id)

        assert response.status_code == 422
        assert "ECHOMARK42" not in response.text
        assert "x" * 20 not in response.text
        assert db.matching(r"^update invitations\b") == []

    @pytest.mark.parametrize("who", _NOT_ADMINS)
    def test_invitations_api_resend_forbidden_without_org_users_invite(
        self, db: FakeDb, who: str
    ) -> None:
        _, session = _admin(db)
        client = _client(_app())
        invitation_id, _ = _invite(db, client, session)
        before = _state(db)

        response = _resend(client, _session_of(db, who), invitation_id)

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        after = _state(db)
        after["users"] = {key: row for key, row in after["users"].items() if key in before["users"]}
        assert after == before

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
            pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
        ],
    )
    def test_invitations_api_resend_cross_origin_is_refused(
        self, db: FakeDb, headers: dict[str, str]
    ) -> None:
        _route(_app(), "POST", "/api/org/invitations/{invitation_id}/resend")
        _, session = _admin(db)
        client = _client(_app())
        invitation_id, _ = _invite(db, client, session)
        db.calls.clear()

        response = _resend(client, session, invitation_id, **headers)

        assert response.status_code == 403
        assert response.json() == _CSRF_REFUSED
        assert db.calls == []

    def test_invitations_api_resend_rate_limit_is_per_user(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _KEY_RESEND, (0.001, 1))
        first, token_a = _admin(db)
        _, token_b = _admin(db)
        client = _client(app)

        _resend(client, token_a, uuid.uuid4())
        exhausted = _resend(client, token_a, uuid.uuid4())
        other = _resend(client, token_b, uuid.uuid4())

        assert exhausted.status_code == 429
        assert exhausted.json() == _RATE_LIMITED
        assert other.status_code == 404
        assert (_KEY_RESEND, f"user:{first}") in server._rate_buckets


# ---------------------------------------------------------------------------
# 6. GET /api/auth/invitations/{token}
# ---------------------------------------------------------------------------


class TestDetailsRoute:
    """The acceptance page's metadata, public."""

    def test_invitations_api_details_returns_exactly_org_name_role_and_email(
        self, db: FakeDb
    ) -> None:
        _, session = _admin(db)
        client = _client(_app())
        _, token = _invite(db, client, session, role="viewer")

        response = _details(client, token)

        assert response.status_code == 200
        assert response.json() == {"org_name": ORG_NAME, "role": "viewer", "email": _EMAIL}

    def test_invitations_api_details_works_without_a_session(self, db: FakeDb) -> None:
        """No cookie, or a garbage one: the public route still answers 200."""
        _, session = _admin(db)
        app = _app()
        _, token = _invite(db, _client(app), session)

        plain_response = _details(_client(app, ip=_IP_B), token)
        garbage = _details(_client(app, ip=_IP_B), token, headers=_cookie("not-a-session-token"))

        assert (plain_response.status_code, garbage.status_code) == (200, 200)

    @pytest.mark.parametrize("token", _MALFORMED_TOKENS)
    def test_invitations_api_details_malformed_token_is_404_without_a_query(
        self, db: FakeDb, token: str
    ) -> None:
        _route(_app(), "GET", "/api/auth/invitations/{token}")

        response = _details(_client(_app()), token)

        assert response.status_code == 404
        assert response.json() == _INVALID
        # GH-157: only the IP throttle's own statements run; no invitation or user lookup.
        assert [
            call.normalized for call in db.calls if "login_throttle" not in call.normalized
        ] == []

    @pytest.mark.parametrize("case", _UNUSABLE_CASES)
    def test_invitations_api_details_unusable_link_is_404(self, db: FakeDb, case: str) -> None:
        """Unknown, expired, used, revoked, rotated, an account no longer invited, an org
        that isn't active: the same 404."""
        _route(_app(), "GET", "/api/auth/invitations/{token}")
        _, session = _admin(db)
        client = _client(_app())
        token = _unusable(db, client, session, case)

        response = _details(client, token)

        assert response.status_code == 404
        assert response.json() == _INVALID

    def test_invitations_api_details_rate_limit_is_per_ip(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The bucket is ("/api/auth/invitations/get", "ip:<host>"); one IP spending it
        doesn't throttle another."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _KEY_DETAILS, (0.001, 2))
        client_a = _client(app, ip=_IP_A)
        client_b = _client(app, ip=_IP_B)

        statuses = [_details(client_a, _WELL_FORMED_UNKNOWN).status_code for _ in range(3)]
        other = _details(client_b, _WELL_FORMED_UNKNOWN)

        assert statuses == [404, 404, 429]
        assert _details(client_a, _WELL_FORMED_UNKNOWN).json() == _RATE_LIMITED
        assert other.status_code == 404
        assert (_KEY_DETAILS, f"ip:{_IP_A}") in server._rate_buckets


# ---------------------------------------------------------------------------
# 7. POST /api/auth/invitations/{token}/accept
# ---------------------------------------------------------------------------

_BAD_ACCEPT_BODIES = [
    pytest.param({"name": "", "password": _PASSWORD}, id="empty-name"),
    pytest.param({"name": "   \t", "password": _PASSWORD}, id="blank-name"),
    pytest.param({"name": "ECHOMARK42" + "a" * 111, "password": _PASSWORD}, id="121-char-name"),
    pytest.param({"name": "ECHOMARK42" + chr(0) + "x", "password": _PASSWORD}, id="nul-name"),
    pytest.param({"name": "ECHOMARK42\nx", "password": _PASSWORD}, id="newline-name"),
    pytest.param({"name": "ECHOMARK42" + chr(0x202E) + "x", "password": _PASSWORD}, id="rtl-name"),
    pytest.param({"name": "ECHOMARK42" + chr(0x2028) + "x", "password": _PASSWORD}, id="ls-name"),
    pytest.param({"name": _NAME, "password": ""}, id="empty-password"),
    pytest.param({"name": _NAME, "password": "ECHOMARK42" + "p" * 1015}, id="1025-password"),
    pytest.param({"name": _NAME}, id="no-password"),
    pytest.param({"password": _PASSWORD}, id="no-name"),
    pytest.param({"name": _NAME, "password": _PASSWORD, "role": "ECHOMARK42"}, id="extra-field"),
]


class TestAcceptRoute:
    """The invitee accepts: 204 and a session cookie, like a login."""

    def test_invitations_api_accept_returns_204_with_the_session_cookie(self, db: FakeDb) -> None:
        """204, no body; admino_session: HttpOnly, SameSite=Strict, Path=/, Max-Age=43200,
        Secure; the cookie's session is the new user's."""
        _, session = _admin(db)
        client = _client(_app())
        _, token = _invite(db, client, session)

        response = _accept(client, token)

        assert response.status_code == 204
        assert response.content == b""
        value, attributes = _session_set_cookie(response)
        assert "httponly" in attributes
        assert (attributes.get("samesite") or "").lower() == "strict"
        assert attributes.get("path") == "/"
        assert attributes.get("max-age") == "43200"
        assert "secure" in attributes
        assert TOKEN_RE.fullmatch(value)
        assert db.session(value)["user_id"] == _invited_id(db)
        assert db.session(value)["idle_timeout_minutes"] == 60

    def test_invitations_api_accept_cookie_is_not_secure_when_disabled(self, db: FakeDb) -> None:
        _, session = _admin(db)
        client = _client(_app(cookie_secure=False))
        _, token = _invite(db, client, session)

        response = _accept(client, token)

        _, attributes = _session_set_cookie(response)
        assert "secure" not in attributes

    def test_invitations_api_accept_activates_the_account(self, db: FakeDb) -> None:
        """The stripped name, the password hash, status active, last_login_at; the
        invitation is used."""
        _, session = _admin(db)
        client = _client(_app())
        _, token = _invite(db, client, session)

        _accept(client, token, name="  Grace Hopper  ")

        row = db.user_by_email(_EMAIL)
        assert row is not None
        assert (row["status"], row["name"], row["password_hash"]) == (
            "active",
            "Grace Hopper",
            fake_hash(_PASSWORD),
        )
        assert row["last_login_at"] is not None
        invitation = db.invitation_of(_invited_id(db))
        assert invitation is not None
        assert invitation["accepted_at"] is not None

    def test_invitations_api_accept_cookie_logs_the_member_in(self, db: FakeDb) -> None:
        """GET /api/auth/me with the new cookie: the invited member, role and org, in the
        inviting admin's language."""
        _, session = _admin(db, ui_language="fr")
        client = _client(_app())
        _, token = _invite(db, client, session, role="viewer")
        cookie, _ = _session_set_cookie(_accept(client, token))
        client.cookies.clear()

        response = client.get("/api/auth/me", headers=_cookie(cookie))

        assert response.status_code == 200
        body = response.json()
        assert (body["user_id"], body["kind"], body["org_id"], body["role"]) == (
            str(_invited_id(db)),
            "member",
            str(ORG_ID),
            "viewer",
        )
        assert body["ui_language"] == "fr"

    def test_invitations_api_accept_uses_the_org_session_policy(self, db: FakeDb) -> None:
        """GH-169: the invited org's stored policy (its org_settings row: 20 minutes / 2
        hours) sets the cookie's Max-Age and the session row; another org's stored policy
        (90 minutes / 24 hours) doesn't apply."""
        _, session = _admin(db)
        db.add_org(OTHER_ORG_ID)
        db.add_org_settings(ORG_ID, session_idle_timeout_minutes=20, session_max_lifetime_hours=2)
        db.add_org_settings(
            OTHER_ORG_ID, session_idle_timeout_minutes=90, session_max_lifetime_hours=24
        )
        client = _client(_app())
        _, token = _invite(db, client, session)

        value, attributes = _session_set_cookie(_accept(client, token))

        assert attributes.get("max-age") == "7200"
        row = db.session(value)
        assert row["idle_timeout_minutes"] == 20
        assert row["expires_at"] - row["created_at"] == timedelta(hours=2)

    def test_invitations_api_accept_is_audited_with_the_client_ip(self, db: FakeDb) -> None:
        _, session = _admin(db)
        invitation_id, token = _invite(db, _client(_app()), session, role="org_admin")

        _accept(_client(_app(), ip=_IP_B), token, headers={"User-Agent": _UA})

        rows = db.audit_rows("invitation.accept")
        assert len(rows) == 1
        assert (rows[0]["actor_kind"], rows[0]["actor_user_id"], rows[0]["org_id"]) == (
            "member",
            _invited_id(db),
            ORG_ID,
        )
        assert (rows[0]["ip"], rows[0]["target_ids"]) == (_IP_B, [invitation_id])
        assert rows[0]["metadata"] == {"role": "org_admin"}

    def test_invitations_api_accept_is_single_use(self, db: FakeDb) -> None:
        """The second accept and a later GET answer 404; still one session."""
        _, session = _admin(db)
        client = _client(_app())
        _, token = _invite(db, client, session)
        assert _accept(client, token).status_code == 204
        client.cookies.clear()

        again = _accept(client, token, name="Someone Else", password=_OTHER_PASSWORD)

        assert again.status_code == 404
        assert again.json() == _INVALID
        assert _session_cookie_headers(again) == []
        assert _details(client, token).status_code == 404
        assert len(db.sessions_of(_invited_id(db))) == 1

    @pytest.mark.parametrize("case", _UNUSABLE_CASES)
    def test_invitations_api_accept_unusable_link_is_404_and_changes_nothing(
        self, db: FakeDb, case: str
    ) -> None:
        _route(_app(), "POST", "/api/auth/invitations/{token}/accept")
        _, session = _admin(db)
        client = _client(_app())
        token = _unusable(db, client, session, case)
        before = _state(db)
        sessions_before = set(db.sessions)

        response = _accept(client, token, password=_OTHER_PASSWORD)

        assert response.status_code == 404
        assert response.json() == _INVALID
        assert _session_cookie_headers(response) == []
        assert _state(db) == before
        assert set(db.sessions) == sessions_before

    @pytest.mark.parametrize("token", _MALFORMED_TOKENS)
    def test_invitations_api_accept_malformed_token_is_404_without_a_query(
        self, db: FakeDb, token: str
    ) -> None:
        _route(_app(), "POST", "/api/auth/invitations/{token}/accept")

        response = _accept(_client(_app()), token)

        assert response.status_code == 404
        assert response.json() == _INVALID
        # GH-157: only the IP throttle's own statements run; no invitation or user lookup.
        assert [
            call.normalized for call in db.calls if "login_throttle" not in call.normalized
        ] == []

    def test_invitations_api_accept_404_bodies_are_identical(self, db: FakeDb) -> None:
        _, session = _admin(db)
        client = _client(_app())
        tokens = [
            _unusable(db, client, session, "expired"),
            _WELL_FORMED_UNKNOWN,
            "short",
        ]

        responses = [_accept(client, token) for token in tokens]

        assert {response.status_code for response in responses} == {404}
        assert len({response.content for response in responses}) == 1

    @pytest.mark.parametrize(
        ("password", "reason"),
        [
            pytest.param("Kq7#vX9!pL2", "too_short", id="11-chars"),
            pytest.param("Qwerty123456", "common", id="common"),
            pytest.param(_EMAIL.upper(), "equals_email", id="equals-email"),
        ],
    )
    def test_invitations_api_accept_policy_failure_is_422_and_keeps_the_link(
        self, db: FakeDb, password: str, reason: str
    ) -> None:
        """422 {"detail": <policy message>, "reason"}; no cookie, nothing written; the same
        link then works."""
        _, session = _admin(db)
        client = _client(_app())
        _, token = _invite(db, client, session)
        before = _state(db)

        response = _accept(client, token, password=password)

        assert response.status_code == 422
        assert response.json() == _policy_body(reason)
        assert _session_cookie_headers(response) == []
        assert _state(db) == before
        assert _accept(client, token).status_code == 204

    def test_invitations_api_accept_unusable_link_wins_over_the_policy(self, db: FakeDb) -> None:
        """An expired link with a too-short password is 404, not 422."""
        _, session = _admin(db)
        client = _client(_app())
        token = _unusable(db, client, session, "expired")

        response = _accept(client, token, password="short")

        assert response.status_code == 404
        assert response.json() == _INVALID

    @pytest.mark.parametrize("body", _BAD_ACCEPT_BODIES)
    def test_invitations_api_accept_bad_body_is_422_without_echo(
        self, db: FakeDb, body: dict[str, Any]
    ) -> None:
        _route(_app(), "POST", "/api/auth/invitations/{token}/accept")
        _, session = _admin(db)
        client = _client(_app())
        _, token = _invite(db, client, session)
        before = _state(db)

        response = client.post(f"/api/auth/invitations/{token}/accept", json=body)

        assert response.status_code == 422
        assert "ECHOMARK42" not in response.text
        assert _PASSWORD not in response.text
        assert _state(db) == before
        assert _accept(client, token).status_code == 204

    def test_invitations_api_accept_audit_failure_is_500_and_changes_nothing(
        self, db: FakeDb
    ) -> None:
        _, session = _admin(db)
        client = _client(_app(), raise_server_exceptions=False)
        _, token = _invite(db, client, session)
        before = _state(db)
        db.fail_audit = True

        response = _accept(client, token)

        assert response.status_code == 500
        assert _session_cookie_headers(response) == []
        assert _state(db) == before
        assert db.sessions_of(_invited_id(db)) == []
        db.fail_audit = False
        assert _accept(client, token).status_code == 204

    def test_invitations_api_accept_ignores_a_bad_session_cookie(self, db: FakeDb) -> None:
        """A stale or garbage cookie doesn't turn the public accept into a 401."""
        _, session = _admin(db)
        client = _client(_app())
        _, token = _invite(db, client, session)

        response = _accept(client, token, headers=_cookie("not-a-session-token"))

        assert response.status_code == 204

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
            pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
        ],
    )
    def test_invitations_api_accept_cross_origin_is_refused(
        self, db: FakeDb, headers: dict[str, str]
    ) -> None:
        _route(_app(), "POST", "/api/auth/invitations/{token}/accept")
        _, session = _admin(db)
        client = _client(_app())
        _, token = _invite(db, client, session)
        db.calls.clear()

        response = _accept(client, token, headers=headers)

        assert response.status_code == 403
        assert response.json() == _CSRF_REFUSED
        assert db.calls == []

    def test_invitations_api_accept_rate_limit_is_per_ip(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _KEY_ACCEPT, (0.001, 2))
        client_a = _client(app, ip=_IP_A)
        client_b = _client(app, ip=_IP_B)

        statuses = [_accept(client_a, _WELL_FORMED_UNKNOWN).status_code for _ in range(3)]
        other = _accept(client_b, _WELL_FORMED_UNKNOWN)

        assert statuses == [404, 404, 429]
        assert _accept(client_a, _WELL_FORMED_UNKNOWN).json() == _RATE_LIMITED
        assert other.status_code == 404
        assert (_KEY_ACCEPT, f"ip:{_IP_A}") in server._rate_buckets


# ---------------------------------------------------------------------------
# 8. Authorization goes through admino.access.can()
# ---------------------------------------------------------------------------


class TestAuthorizationThroughCan:
    """Sending, revoking and resending check org.users.invite; listing org.users.view."""

    def test_invitations_api_create_asks_for_org_users_invite(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = _CanSpy(monkeypatch)
        _, session = _admin(db)

        assert _create(_client(_app()), session).status_code == 201
        assert Capability.ORG_USERS_INVITE in spy.capabilities

    def test_invitations_api_list_asks_for_org_users_view(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = _CanSpy(monkeypatch)
        _, session = _admin(db)

        assert _list(_client(_app()), session).status_code == 200
        assert Capability.ORG_USERS_VIEW in spy.capabilities

    @pytest.mark.parametrize("action", ["revoke", "resend"])
    def test_invitations_api_revoke_and_resend_ask_for_org_users_invite(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        _, session = _admin(db)
        client = _client(_app())
        invitation_id, _ = _invite(db, client, session)
        spy = _CanSpy(monkeypatch)

        response = (_revoke if action == "revoke" else _resend)(client, session, invitation_id)

        assert response.status_code in {200, 204}
        assert Capability.ORG_USERS_INVITE in spy.capabilities

    def test_invitations_api_org_users_invite_refused_is_403(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When can() refuses org.users.invite even an Org Admin gets 403 on the three
        writes; nothing is written."""
        _route(_app(), "POST", _INVITES)
        _, session = _admin(db)
        client = _client(_app())
        invitation_id, _ = _invite(db, client, session)
        _CanSpy(monkeypatch, deny=frozenset({Capability.ORG_USERS_INVITE}))
        before = _state(db)

        responses = [
            _create(client, session, email="blocked.person@example.ch"),
            _revoke(client, session, invitation_id),
            _resend(client, session, invitation_id),
        ]

        assert [(r.status_code, r.json()) for r in responses] == [(403, _FORBIDDEN)] * 3
        assert _state(db) == before

    def test_invitations_api_org_users_view_refused_is_403(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _route(_app(), "GET", _INVITES)
        _CanSpy(monkeypatch, deny=frozenset({Capability.ORG_USERS_VIEW}))
        _, session = _admin(db)

        response = _list(_client(_app()), session)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)


# ---------------------------------------------------------------------------
# 9. The whole flow: no content in logs or audit rows
# ---------------------------------------------------------------------------


def _server_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured record (with its traceback) except the test client's own request log.

    httpx (TestClient) logs each request URL at INFO, and the two public routes carry
    the token in their path; that line is the test's client, not the app. The server
    runs uvicorn with access_log=False (admino.main), so the app never logs paths.
    """
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(
        formatter.format(record) for record in caplog.records if not record.name.startswith("httpx")
    )


class TestNoContentInLogs:
    """Emails, names, passwords, tokens and links never reach a log line or audit row."""

    def _flow(self, db: FakeDb) -> list[str]:
        """Invite, refuse a duplicate, resend, open, fail the policy, accept, reuse the old
        link, revoke another invitation; return every raw token issued."""
        _, session = _admin(db, email="log.marker.admin@example.ch")
        client = _client(_app())
        invitation_id, first = _invite(db, client, session, email="log.marker.invitee@example.ch")
        assert _create(client, session, email="LOG.MARKER.INVITEE@example.ch").status_code == 409
        assert _resend(client, session, invitation_id).status_code == 200
        second = db.invitation_token(_invited_id(db, "log.marker.invitee@example.ch"))
        assert _details(client, second).status_code == 200
        assert (
            _accept(client, second, name="Grace Hoppermarker", password="short").status_code == 422
        )
        response = _accept(client, second, name="Grace Hoppermarker")
        assert response.status_code == 204
        cookie, _ = _session_set_cookie(response)
        client.cookies.clear()
        assert _accept(client, first, name="Grace Hoppermarker").status_code == 404
        other_id, _ = _invite(db, client, session, email="log.marker.other@example.ch")
        assert _list(client, session).status_code == 200
        assert _revoke(client, session, other_id).status_code == 204
        return [first, second, cookie]

    def test_invitations_api_flow_logs_no_content(
        self, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)

        tokens = self._flow(db)

        text = _server_log_text(caplog)
        assert "log.marker" not in text.lower()
        assert "hoppermarker" not in text.lower()
        assert _PASSWORD not in text
        assert "accept-invitation" not in text
        for token in tokens:
            assert token not in text
            assert sha256(token).hex() not in text

    def test_invitations_api_audit_rows_carry_no_content(self, db: FakeDb) -> None:
        tokens = self._flow(db)

        stored = json.dumps(db.audit, default=str).lower()
        assert "log.marker" not in stored
        assert "hoppermarker" not in stored
        assert "accept-invitation" not in stored
        for token in tokens:
            assert token.lower() not in stored
