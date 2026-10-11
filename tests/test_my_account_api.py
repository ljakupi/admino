"""HTTP-layer spec for account self-service (GH-166).

The FastAPI app from ``create_app()`` runs against the in-memory database of
tests/db_fakes.py (what ``admino.database.get_pool`` returns). The real
``admino.my_account``, ``admino.auth``, ``admino.sessions``,
``admino.login_throttle`` and ``admino.audit_events`` code runs, through the
real ``require_session`` and real session cookies; only Argon2 is replaced by
a fast fake.

What these tests pin down:
- ``GET /api/me`` → 200 ``MyAccountResponse``: exactly ``email``, ``name``,
  ``ui_language``, ``response_language`` (None: the org default),
  ``timezone`` (None: not preset yet), ``personal_instructions`` ('':
  none) and (GH-307) ``password_changed_at`` (null until the first change,
  then an ISO 8601 UTC timestamp), read from the caller's own users row, for
  every role (the Super Admin included). No id, kind, role, org or hash.
- GH-307 (Decision 4): a successful ``POST /api/me/password`` sets
  ``password_changed_at`` (the database clock); ``GET /api/me`` and the
  ``PATCH /api/me`` response show it; a refused change (403, 422, 500) leaves
  it as it was; another user's value never changes or shows; ``GET
  /api/auth/me`` doesn't carry it; a PATCH can't set it (422); it reaches no
  log line and no audit row.
- ``PATCH /api/me`` (``MyAccountPatch``) → 200 with the stored values: each
  field on its own (the name stripped, the instructions as typed);
  ``response_language: null`` stores NULL, an absent field stays as it was.
  The change shows on the next ``GET /api/me``, and the language ones on
  ``GET /api/auth/me``, whose shape doesn't change (no timezone there). 422
  without echo and without a write for ``{}``, any other key, a bad language,
  an unknown timezone, instructions over 1500 code points or with control
  characters, a name with control/format/separator characters, an empty or
  too long name, a null name, ui_language, timezone or instructions. Not
  audited. Another user's and another org's rows are untouched.
- ``POST /api/me/password`` (``PasswordChangeRequest``) → 204: the stored
  hash is the new password's, every session of the caller ends (the current
  one included: the cookie is cleared), other users stay logged in, the new
  password logs in and the old one doesn't, one ``password.change`` audit row
  (metadata ``{"sessions_revoked": n}``, the client IP). A wrong current
  password → 403 ``{"detail": "Re-authentication failed."}`` (never 401):
  nothing changes, the session survives, and it counts in the login throttle
  up to a lockout (``login.lockout``), after which the right password is
  refused too. A new password that breaks the policy → 422 ``{"detail",
  "reason"}``, checked before the current password (nothing counted). A
  failed audit write → 500 and nothing changes.
- All three depend on ``require_session`` (401 without a session), spend a
  per-user rate-limit bucket (``/api/me/get`` (1.0, 10), ``/api/me/patch``
  (0.5, 5), ``/api/me/password`` (0.1, 3)) before asking ``access.can`` for
  ``Capability.ACCOUNT_MANAGE``, both before any database work. PATCH and
  POST are refused cross-origin. Every role can use them.

All database calls are faked. No network, no real PostgreSQL.

Security notes:
- No password, hash, email, name, timezone or instructions text in a 422 body,
  an audit row or a log line.
- Tenant isolation: only the caller's own users row is read or written.
- Fail closed: an audit failure on the password change is a 500 and nothing
  changes (the hash and every session stay).
"""

from __future__ import annotations

import copy
import logging
import re
import sys
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final, cast
from unittest.mock import MagicMock

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from admino import server
from admino.access import Capability
from admino.login_throttle import ip_subject
from admino.passwords import PasswordPolicyError
from admino.server import create_app
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, account_subject, fake_hash, plain

if TYPE_CHECKING:
    from collections.abc import Callable

    import httpx
    from fastapi import FastAPI
    from fastapi.dependencies.models import Dependant

    from admino.passwords import PolicyReason

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE: Final = "admino_session"
_PASSWORD: Final = "violet-Anchor-93-quartz"
_NEW_PASSWORD: Final = "Copper-Lantern-166-meadow"
_WRONG_PASSWORD: Final = "not-my-Password-166-xx"
_TOO_SHORT: Final = "Kq7#vX9!pL2"
_IP_A: Final = "203.0.113.66"
_IP_B: Final = "198.51.100.66"
_EMAIL: Final = "lina.muster-166@example.ch"
_ECHO: Final = "ECHOMARK42"

_ME: Final = "/api/me"
_ME_PASSWORD: Final = "/api/me/password"
_AUTH_ME: Final = "/api/auth/me"
_LOGIN: Final = "/api/auth/login"

_UNAUTHORIZED: Final = {"detail": "Unauthorized"}
_FORBIDDEN: Final = {"detail": "Forbidden"}
_REAUTH_FAILED: Final = {"detail": "Re-authentication failed."}
_CSRF_REFUSED: Final = {"detail": "Cross-origin request refused"}
_RATE_LIMITED: Final = {"detail": "Rate limit exceeded"}

_ACCOUNT_KEYS: Final = frozenset(
    {
        "email",
        "name",
        "ui_language",
        "response_language",
        "timezone",
        "personal_instructions",
        # GH-307: the date of the last password change.
        "password_changed_at",
    }
)
# The columns a body is compared with (password_changed_at: a stored None is the JSON
# null; a stored date is compared through _parsed_changed_at).
_ACCOUNT_COLUMNS: Final = (
    "email",
    "name",
    "ui_language",
    "response_language",
    "timezone",
    "personal_instructions",
    "password_changed_at",
)
# GET /api/auth/me is unchanged by GH-166 (no timezone, no instructions).
_AUTH_ME_KEYS: Final = frozenset(
    {"user_id", "kind", "org_id", "role", "ui_language", "response_language"}
)
_ROLES: Final = ("org_admin", "editor", "super_admin")

_NEW_ROUTES: Final[list[tuple[str, str]]] = [
    ("GET", _ME),
    ("PATCH", _ME),
    ("POST", _ME_PASSWORD),
]

# The three routes, by a short action name.
_ACTIONS: Final = ("get", "patch", "password")
_ROUTE_OF: Final[dict[str, tuple[str, str]]] = {
    "get": ("GET", _ME),
    "patch": ("PATCH", _ME),
    "password": ("POST", _ME_PASSWORD),
}
_ROUTE_KEYS: Final[dict[str, str]] = {
    "get": "/api/me/get",
    "patch": "/api/me/patch",
    "password": "/api/me/password",
}
_SUCCESS: Final[dict[str, int]] = {"get": 200, "patch": 200, "password": 204}
_VALID_BODIES: Final[dict[str, dict[str, Any] | None]] = {
    "get": None,
    "patch": {"timezone": "Europe/Zurich"},
    "password": {"current_password": _PASSWORD, "new_password": _NEW_PASSWORD},
}
# A call that spends a token but keeps the caller's session (a successful
# password change would end it, so the next call would be a 401, not a 429).
_SPENDING_BODIES: Final[dict[str, dict[str, Any] | None]] = {
    "get": None,
    "patch": {"timezone": "Europe/Zurich"},
    "password": {"current_password": _PASSWORD, "new_password": _TOO_SHORT},
}
_SPENDING_STATUS: Final[dict[str, int]] = {"get": 200, "patch": 200, "password": 422}

_EXPECTED_LIMITS: Final[dict[str, tuple[float, int]]] = {
    "/api/me/get": (1.0, 10),
    "/api/me/patch": (0.5, 5),
    "/api/me/password": (0.1, 3),
}
# Read at import, before any fixture patches the limits.
_CONFIGURED_LIMITS: Final = {key: server._RATE_LIMITS.get(key) for key in _EXPECTED_LIMITS}

_CROSS_ORIGIN: Final = [
    pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
    pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
]

# What require_session runs for every request: the session lookup and the
# last_seen_at refresh. Anything else is the route's own database work.
_SESSION_RESOLVE_RE: Final = re.compile(
    r"\bfrom sessions s join users u\b|^update sessions set last_seen_at\b"
)
_USER_WRITE_RE: Final = re.compile(r"^(?:update users\b|insert into users\b|delete from users\b)")

# The account the PATCH tests start from: every column set, none a default.
_START: Final[dict[str, Any]] = {
    "email": "old.name-166@example.ch",
    "name": "Old Name",
    "ui_language": "de",
    "response_language": "en",
    "timezone": "Europe/Zurich",
    "personal_instructions": "Old instructions.",
}


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
def _roomy_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Functional tests aren't about rate limits: the three keys get a large bucket (the
    rate-limit tests set their own after this)."""
    for key in _EXPECTED_LIMITS:
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))


def _config() -> MagicMock:
    """A minimal config (no old auth section)."""
    config = MagicMock()
    del config.auth
    config.limits.max_message_length = 4000
    config.server.host = "127.0.0.1"
    config.server.port = 8000
    config.server.cookie_secure = True
    config.server.public_url = "https://admino.example.ch"
    config.llm.provider = "infomaniak"
    config.llm.active_model_name = "test-model"
    return config


def _app() -> FastAPI:
    """create_app with a stub agent and the fake config (no lifespan runs under TestClient)."""
    return create_app(agent=MagicMock(), config=_config())  # type: ignore[arg-type]


def _client(app: FastAPI, ip: str = _IP_A, **kwargs: Any) -> TestClient:
    """A client whose peer address is ``ip``; redirects are not followed."""
    return TestClient(app, client=(ip, 50000), follow_redirects=False, **kwargs)


def _cookie(token: str, **extra: str) -> dict[str, str]:
    """Request headers carrying a session cookie (plus any extra headers)."""
    return {"Cookie": f"{_COOKIE}={token}", **extra}


def _account(db: FakeDb, who: str = "editor", **fields: Any) -> uuid.UUID:
    """An account (a member with role ``who``, or a Super Admin) that logs in with
    _PASSWORD."""
    if who == "super_admin":
        return db.add_account(
            kind="super_admin", role=None, password_hash=fake_hash(_PASSWORD), **fields
        )
    return db.add_account(role=who, password_hash=fake_hash(_PASSWORD), **fields)


def _signed_in(db: FakeDb, who: str = "editor", **fields: Any) -> tuple[uuid.UUID, str]:
    """An account with a live session: (user id, session token)."""
    user_id = _account(db, who, **fields)
    return user_id, db.open_session(user_id)


def _get(client: TestClient, token: str, **headers: str) -> httpx.Response:
    return client.get(_ME, headers=_cookie(token, **headers))


def _patch(client: TestClient, token: str, body: Any, **headers: str) -> httpx.Response:
    return client.patch(_ME, json=body, headers=_cookie(token, **headers))


def _change(
    client: TestClient,
    token: str,
    *,
    current: str = _PASSWORD,
    new: str = _NEW_PASSWORD,
    **headers: str,
) -> httpx.Response:
    """POST /api/me/password with the current and the new password."""
    return client.post(
        _ME_PASSWORD,
        json={"current_password": current, "new_password": new},
        headers=_cookie(token, **headers),
    )


def _call(
    client: TestClient,
    action: str,
    token: str | None,
    *,
    body: dict[str, Any] | None = None,
    **headers: str,
) -> httpx.Response:
    """Call one of the three routes (its valid body unless one is given)."""
    method, path = _ROUTE_OF[action]
    payload = _VALID_BODIES[action] if body is None else body
    kwargs: dict[str, Any] = {} if payload is None else {"json": payload}
    request_headers = headers if token is None else _cookie(token, **headers)
    return client.request(method, path, headers=request_headers, **kwargs)


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


def _stored(db: FakeDb, user_id: uuid.UUID) -> dict[str, Any]:
    """The six account columns of a users row."""
    return {column: db.users[user_id][column] for column in _ACCOUNT_COLUMNS}


def _users(db: FakeDb) -> dict[uuid.UUID, dict[str, Any]]:
    """A deep copy of every users row."""
    return copy.deepcopy(db.users)


def _user_writes(db: FakeDb, since: int) -> list[str]:
    """Every INSERT, UPDATE or DELETE on users after call ``since``."""
    return [call.normalized for call in db.calls[since:] if _USER_WRITE_RE.match(call.normalized)]


def _route_work(db: FakeDb, since: int) -> list[str]:
    """Every statement after call ``since`` that isn't require_session's own."""
    return [
        call.normalized
        for call in db.calls[since:]
        if not _SESSION_RESOLVE_RE.search(call.normalized)
    ]


def _binds_any(db: FakeDb, since: int, ids: tuple[uuid.UUID, ...]) -> list[str]:
    """Statements after call ``since`` that bind one of ``ids``."""
    wanted = {str(user_id) for user_id in ids}
    return [
        call.normalized
        for call in db.calls[since:]
        if any(str(arg) in wanted for arg in call.args if isinstance(arg, uuid.UUID))
    ]


def _echo_markers(value: Any) -> list[str]:
    """What a 422 body must never contain: the ECHOMARK42 marker and every long string
    (20+ characters) or large number the request carried."""
    markers = [_ECHO]
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str) and len(item) >= 20:
            markers.append(item[:40])
        elif isinstance(item, int) and not isinstance(item, bool) and abs(item) >= 100000:
            markers.append(str(item))
    return markers


def _assert_no_echo(response: httpx.Response, *texts: str) -> None:
    """The response repeats none of ``texts``, and no error carries its input."""
    for text in texts:
        assert text not in response.text, text
    detail = response.json().get("detail")
    if isinstance(detail, list):
        assert all("input" not in error and "ctx" not in error for error in detail), detail


def _session_cookie_headers(response: httpx.Response) -> list[str]:
    """Every Set-Cookie header naming admino_session."""
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


def _log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured app record (not the test client's own httpx request lines)."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(
        formatter.format(record)
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore"))
    )


def _lockout_after() -> int:
    """The stored lockout threshold the throttle applies (the primed platform cache)."""
    from admino import scoped_settings

    cache = scoped_settings._platform_cache
    assert cache is not None
    return int(cache.security.lockout_after_failures)


def _policy_body(reason: str) -> dict[str, str]:
    """The 422 body of a password policy failure."""
    return {"detail": str(PasswordPolicyError(cast("PolicyReason", reason))), "reason": reason}


def _uuid(value: Any) -> uuid.UUID | None:
    return None if value is None else plain(value)


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
        monkeypatch.setattr(server, "can", spy, raising=False)
        # The service module (imported by the server) may check too.
        service = sys.modules.get("admino.my_account")
        if service is not None and hasattr(service, "can"):
            monkeypatch.setattr(service, "can", spy)


# ---------------------------------------------------------------------------
# 1. The routes exist, need a session and have their rate limits
# ---------------------------------------------------------------------------


class TestRoutes:
    """GET /api/me, PATCH /api/me and POST /api/me/password."""

    @pytest.mark.parametrize(("method", "path"), _NEW_ROUTES)
    def test_my_account_api_route_is_registered(self, method: str, path: str) -> None:
        _route(_app(), method, path)

    @pytest.mark.parametrize(("method", "path"), _NEW_ROUTES)
    def test_my_account_api_route_depends_on_require_session(self, method: str, path: str) -> None:
        """server.require_session is in the route's dependency tree."""
        route = _route(_app(), method, path)

        assert _depends_on(route.dependant, server.require_session)

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_my_account_api_route_without_a_session_is_401(self, db: FakeDb, action: str) -> None:
        """No cookie → 401 Unauthorized, and nothing is read or written."""
        _account(db)

        response = _call(_client(_app()), action, None)

        assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)
        assert db.calls == []

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_my_account_api_route_with_an_unknown_cookie_is_401(
        self, db: FakeDb, action: str
    ) -> None:
        """A cookie that resolves to no session → 401; no account statement runs."""
        user_id = _account(db)
        before = _users(db)

        response = _call(_client(_app()), action, "not-a-live-session-token-166-xxxxxxxxxxxxxxx")

        assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)
        assert _users(db) == before
        assert db.users[user_id]["password_hash"] == fake_hash(_PASSWORD)

    @pytest.mark.parametrize(("key", "rate"), list(_EXPECTED_LIMITS.items()))
    def test_my_account_api_rate_limits(self, key: str, rate: tuple[float, int]) -> None:
        """(tokens per second, burst) per route key, as configured by the server."""
        assert _CONFIGURED_LIMITS[key] == pytest.approx(rate)


# ---------------------------------------------------------------------------
# 2. GET /api/me
# ---------------------------------------------------------------------------


class TestGetAccount:
    """The caller's own profile, languages, timezone and personal instructions."""

    def test_my_account_api_get_new_member(self, db: FakeDb) -> None:
        """A member as created: the org default response language (None), no timezone yet
        (None), no instructions ('')."""
        _, token = _signed_in(db, "editor", email=_EMAIL, name="Lina Muster")

        response = _get(_client(_app()), token)

        assert response.status_code == 200, response.text
        assert response.json() == {
            "email": _EMAIL,
            "name": "Lina Muster",
            "ui_language": "de",
            "response_language": None,
            "timezone": None,
            "personal_instructions": "",
            "password_changed_at": None,
        }

    def test_my_account_api_get_super_admin(self, db: FakeDb) -> None:
        """A Super Admin created without a name: 200 with name None."""
        _, token = _signed_in(
            db, "super_admin", email="root-166@example.ch", name=None, ui_language="en"
        )

        response = _get(_client(_app()), token)

        assert response.status_code == 200, response.text
        assert response.json() == {
            "email": "root-166@example.ch",
            "name": None,
            "ui_language": "en",
            "response_language": None,
            "timezone": None,
            "personal_instructions": "",
            "password_changed_at": None,
        }

    def test_my_account_api_get_returns_the_stored_values(self, db: FakeDb) -> None:
        """Every column comes from the users row."""
        instructions = "Sign off as Lina.\nKeep it short."
        _, token = _signed_in(
            db,
            "editor",
            email=_EMAIL,
            name="Lina Muster",
            ui_language="fr",
            response_language="it",
            timezone="America/Argentina/Buenos_Aires",
            personal_instructions=instructions,
        )

        response = _get(_client(_app()), token)

        assert response.status_code == 200, response.text
        assert response.json() == {
            "email": _EMAIL,
            "name": "Lina Muster",
            "ui_language": "fr",
            "response_language": "it",
            "timezone": "America/Argentina/Buenos_Aires",
            "personal_instructions": instructions,
            "password_changed_at": None,
        }

    @pytest.mark.parametrize("who", ["editor", "super_admin"])
    def test_my_account_api_get_has_exactly_the_seven_fields(self, db: FakeDb, who: str) -> None:
        """No user id, kind, org id, role, status or hash in the body."""
        user_id, token = _signed_in(db, who)

        response = _get(_client(_app()), token)

        assert response.status_code == 200, response.text
        assert set(response.json()) == _ACCOUNT_KEYS
        assert str(user_id) not in response.text
        assert str(ORG_ID) not in response.text
        assert fake_hash(_PASSWORD) not in response.text

    def test_my_account_api_get_reads_only_the_callers_row(self, db: FakeDb) -> None:
        """A colleague's and another org's values never appear; no statement binds their
        ids."""
        _, token = _signed_in(db, "editor", email=_EMAIL, name="Lina Muster")
        colleague = _account(
            db,
            "org_admin",
            email="colleague-166@example.ch",
            name="Colleague Zephyr",
            timezone="Asia/Tokyo",
            personal_instructions="Colleague secret instructions",
        )
        outsider = _account(
            db,
            "editor",
            org_id=OTHER_ORG_ID,
            email="outsider-166@example.ch",
            name="Outsider Quasar",
            response_language="it",
            personal_instructions="Outsider secret instructions",
        )
        mark = len(db.calls)

        response = _get(_client(_app()), token)

        assert response.status_code == 200, response.text
        assert response.json()["email"] == _EMAIL
        for marker in ("colleague", "Zephyr", "Tokyo", "outsider", "Quasar", "secret"):
            assert marker.lower() not in response.text.lower(), marker
        assert _binds_any(db, mark, (colleague, outsider)) == []

    def test_my_account_api_get_is_not_audited_and_writes_nothing(self, db: FakeDb) -> None:
        user_id, token = _signed_in(db)
        before = _users(db)
        mark = len(db.calls)

        response = _get(_client(_app()), token)

        assert response.status_code == 200, response.text
        assert _users(db) == before
        assert _user_writes(db, mark) == []
        assert db.audit_rows() == []
        assert _stored(db, user_id)["timezone"] is None


# ---------------------------------------------------------------------------
# 3. PATCH /api/me
# ---------------------------------------------------------------------------

_FIELD_CHANGES: Final = [
    pytest.param({"name": "  Lina Muster  "}, {"name": "Lina Muster"}, id="name-stripped"),
    pytest.param({"name": "N" * 120}, {"name": "N" * 120}, id="name-120-chars"),
    pytest.param({"name": "Zoë Ñúñez-Łukasz"}, {"name": "Zoë Ñúñez-Łukasz"}, id="name-accents"),
    pytest.param({"ui_language": "fr"}, {"ui_language": "fr"}, id="ui-language-fr"),
    pytest.param({"ui_language": "en"}, {"ui_language": "en"}, id="ui-language-en"),
    pytest.param({"response_language": "it"}, {"response_language": "it"}, id="response-it"),
    pytest.param({"response_language": "de"}, {"response_language": "de"}, id="response-de"),
    pytest.param(
        {"timezone": "America/Argentina/Buenos_Aires"},
        {"timezone": "America/Argentina/Buenos_Aires"},
        id="timezone-three-parts",
    ),
    pytest.param({"timezone": "Etc/GMT+5"}, {"timezone": "Etc/GMT+5"}, id="timezone-etc"),
    pytest.param({"timezone": "UTC"}, {"timezone": "UTC"}, id="timezone-utc"),
    pytest.param(
        {"personal_instructions": "  Sign off as Lina.\n\tKeep it short.\r\n"},
        {"personal_instructions": "  Sign off as Lina.\n\tKeep it short.\r\n"},
        id="instructions-not-stripped",
    ),
    pytest.param({"personal_instructions": ""}, {"personal_instructions": ""}, id="cleared"),
    pytest.param(
        {"personal_instructions": "i" * 1500},
        {"personal_instructions": "i" * 1500},
        id="instructions-1500",
    ),
    pytest.param(
        {"personal_instructions": chr(0x1F600) * 1500},
        {"personal_instructions": chr(0x1F600) * 1500},
        id="instructions-1500-code-points",
    ),
]


class TestPatchAccount:
    """The caller changes their own name, languages, timezone or instructions."""

    @pytest.mark.parametrize(("body", "changes"), _FIELD_CHANGES)
    def test_my_account_api_patch_changes_one_field(
        self, db: FakeDb, body: dict[str, Any], changes: dict[str, Any]
    ) -> None:
        """200 with the stored values; only the given column changes."""
        user_id, token = _signed_in(db, **_START)
        expected = {**_stored(db, user_id), **changes}

        response = _patch(_client(_app()), token, body)

        assert response.status_code == 200, response.text
        assert _stored(db, user_id) == expected
        assert response.json() == expected

    def test_my_account_api_patch_null_response_language_is_the_org_default(
        self, db: FakeDb
    ) -> None:
        """``response_language: null`` stores NULL ("use the org default")."""
        user_id, token = _signed_in(db, **{**_START, "response_language": "it"})
        expected = {**_stored(db, user_id), "response_language": None}

        response = _patch(_client(_app()), token, {"response_language": None})

        assert response.status_code == 200, response.text
        assert db.users[user_id]["response_language"] is None
        assert _stored(db, user_id) == expected
        assert response.json() == expected

    def test_my_account_api_patch_without_response_language_keeps_it(self, db: FakeDb) -> None:
        """An absent response_language stays as it was (absent is not null)."""
        user_id, token = _signed_in(db, **{**_START, "response_language": "it"})

        response = _patch(_client(_app()), token, {"name": "New Name"})

        assert response.status_code == 200, response.text
        assert db.users[user_id]["response_language"] == "it"
        assert response.json()["response_language"] == "it"
        assert db.users[user_id]["name"] == "New Name"

    def test_my_account_api_patch_keeps_a_null_response_language(self, db: FakeDb) -> None:
        """A caller on the org default who changes something else stays on it."""
        user_id, token = _signed_in(db, **{**_START, "response_language": None})

        response = _patch(_client(_app()), token, {"timezone": "Asia/Tokyo"})

        assert response.status_code == 200, response.text
        assert db.users[user_id]["response_language"] is None
        assert db.users[user_id]["timezone"] == "Asia/Tokyo"

    def test_my_account_api_patch_presets_a_null_timezone(self, db: FakeDb) -> None:
        """A new account (timezone NULL) gets its first timezone (the frontend preset)."""
        user_id, token = _signed_in(db, "editor")

        response = _patch(_client(_app()), token, {"timezone": "Europe/Berlin"})

        assert response.status_code == 200, response.text
        assert db.users[user_id]["timezone"] == "Europe/Berlin"

    def test_my_account_api_patch_several_fields_at_once(self, db: FakeDb) -> None:
        user_id, token = _signed_in(db, **_START)
        body = {
            "name": "Lina Muster",
            "ui_language": "en",
            "response_language": "fr",
            "timezone": "Europe/Paris",
            "personal_instructions": "Formal tone.",
        }

        response = _patch(_client(_app()), token, body)

        assert response.status_code == 200, response.text
        expected = {"email": _START["email"], **body, "password_changed_at": None}
        assert _stored(db, user_id) == expected
        assert response.json() == expected

    def test_my_account_api_patch_shows_on_the_next_get(self, db: FakeDb) -> None:
        _, token = _signed_in(db, **_START)
        client = _client(_app())

        patched = _patch(client, token, {"name": "Lina Muster", "timezone": "Asia/Tokyo"})
        read = _get(client, token)

        assert patched.status_code == 200, patched.text
        assert read.status_code == 200, read.text
        assert read.json() == patched.json()
        assert (read.json()["name"], read.json()["timezone"]) == ("Lina Muster", "Asia/Tokyo")

    def test_my_account_api_patch_languages_show_on_auth_me_whose_shape_is_unchanged(
        self, db: FakeDb
    ) -> None:
        """The next GET /api/auth/me has the new ui_language and response_language, and
        still exactly its six fields (no timezone, no instructions)."""
        user_id, token = _signed_in(db, **_START)
        client = _client(_app())

        patched = _patch(
            client,
            token,
            {"ui_language": "fr", "response_language": "it", "timezone": "Asia/Tokyo"},
        )
        me = client.get(_AUTH_ME, headers=_cookie(token))

        assert patched.status_code == 200, patched.text
        assert me.status_code == 200, me.text
        assert set(me.json()) == _AUTH_ME_KEYS
        assert (me.json()["ui_language"], me.json()["response_language"]) == ("fr", "it")
        assert me.json()["user_id"] == str(user_id)
        assert "Asia/Tokyo" not in me.text

    def test_my_account_api_patch_changes_only_the_callers_row(self, db: FakeDb) -> None:
        """A colleague's and another org's rows are untouched; no statement binds their
        ids."""
        user_id, token = _signed_in(db, **_START)
        colleague = _account(db, "org_admin", name="Colleague", personal_instructions="Mine.")
        outsider = _account(
            db, "editor", org_id=OTHER_ORG_ID, name="Outsider", timezone="Asia/Tokyo"
        )
        others = {other: copy.deepcopy(db.users[other]) for other in (colleague, outsider)}
        mark = len(db.calls)

        response = _patch(
            _client(_app()),
            token,
            {
                "name": "Changed",
                "ui_language": "en",
                "response_language": None,
                "timezone": "Europe/Paris",
                "personal_instructions": "Changed.",
            },
        )

        assert response.status_code == 200, response.text
        assert db.users[user_id]["name"] == "Changed"
        assert {other: db.users[other] for other in others} == others
        assert _binds_any(db, mark, (colleague, outsider)) == []

    def test_my_account_api_patch_is_not_audited(self, db: FakeDb) -> None:
        _, token = _signed_in(db, **_START)

        response = _patch(_client(_app()), token, {"name": "Lina Muster"})

        assert response.status_code == 200, response.text
        assert db.audit_rows() == []

    def test_my_account_api_patch_leaves_the_password_and_sessions_alone(self, db: FakeDb) -> None:
        user_id, token = _signed_in(db, **_START)
        other = db.open_session(user_id)

        response = _patch(_client(_app()), token, {"name": "Lina Muster"})

        assert response.status_code == 200, response.text
        assert db.users[user_id]["password_hash"] == fake_hash(_PASSWORD)
        assert not db.session_revoked(token)
        assert not db.session_revoked(other)
        assert _session_cookie_headers(response) == []

    @pytest.mark.parametrize("headers", _CROSS_ORIGIN)
    def test_my_account_api_patch_cross_origin_is_refused(
        self, db: FakeDb, headers: dict[str, str]
    ) -> None:
        """CSRF: a cross-origin PATCH is 403 before anything runs; nothing changes."""
        _route(_app(), "PATCH", _ME)
        _, token = _signed_in(db, **_START)
        before = _users(db)

        response = _patch(_client(_app()), token, {"name": "Evil Name"}, **headers)

        assert (response.status_code, response.json()) == (403, _CSRF_REFUSED)
        assert _users(db) == before
        assert db.calls == []

    def test_my_account_api_patch_logs_no_content(
        self, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No email, name, timezone or instructions in any app log record."""
        caplog.set_level(logging.DEBUG)
        _, token = _signed_in(
            db, **{**_START, "email": "zephyrmarker.me@example.ch", "name": "Zephyrmarker Old"}
        )
        client = _client(_app(), raise_server_exceptions=False)

        patched = _patch(
            client,
            token,
            {
                "name": "Zephyrmarker New",
                "timezone": "Pacific/Chatham",
                "personal_instructions": "zephyrmarker instructions",
            },
        )
        refused = _patch(client, token, {"name": f"Zephyrmarker{chr(7)}"})
        read = _get(client, token)

        assert patched.status_code == 200, patched.text
        assert refused.status_code == 422, refused.text
        assert read.status_code == 200, read.text
        logs = _log_text(caplog)
        assert "zephyrmarker" not in logs.lower()
        assert "Chatham" not in logs


# ---------------------------------------------------------------------------
# 4. PATCH /api/me refuses bad bodies (422, no echo, nothing written)
# ---------------------------------------------------------------------------

_FORBIDDEN_KEYS: Final = (
    "email",
    "role",
    "password",
    "password_hash",
    "kind",
    "org_id",
    "user_id",
    "status",
    "theme",
)

_BAD_PATCHES: Final = [
    pytest.param({}, id="empty"),
    *[pytest.param({key: f"{_ECHO}-value"}, id=f"extra-{key}") for key in _FORBIDDEN_KEYS],
    pytest.param({"name": "Lina", "email": f"{_ECHO}@example.ch"}, id="valid-plus-email"),
    pytest.param({"timezone": "Europe/Zurich", "role": "org_admin"}, id="valid-plus-role"),
    pytest.param({"ui_language": "it"}, id="ui-language-it"),
    pytest.param({"ui_language": "xx"}, id="ui-language-xx"),
    pytest.param({"ui_language": "DE"}, id="ui-language-upper"),
    pytest.param({"response_language": "es"}, id="response-language-es"),
    pytest.param({"response_language": ""}, id="response-language-empty"),
    pytest.param({"timezone": "Mars/Olympus"}, id="timezone-mars"),
    pytest.param({"timezone": f"Mars/{_ECHO}"}, id="timezone-marker"),
    pytest.param({"timezone": "europe/zurich"}, id="timezone-lowercase"),
    pytest.param({"timezone": "Europe/Zurich "}, id="timezone-trailing-space"),
    pytest.param({"timezone": "../etc/passwd"}, id="timezone-path"),
    pytest.param({"timezone": ""}, id="timezone-empty"),
    pytest.param({"timezone": "A" * 65}, id="timezone-65-chars"),
    pytest.param({"timezone": 5}, id="timezone-int"),
    pytest.param({"personal_instructions": _ECHO + "x" * 1491}, id="instructions-1501"),
    pytest.param({"personal_instructions": chr(0x1F600) * 1501}, id="instructions-1501-emoji"),
    pytest.param({"personal_instructions": f"{_ECHO}{chr(0)}"}, id="instructions-nul"),
    pytest.param({"personal_instructions": f"{_ECHO}{chr(0x1B)}[31m"}, id="instructions-esc"),
    pytest.param({"personal_instructions": f"{_ECHO}{chr(0x7F)}"}, id="instructions-del"),
    pytest.param({"personal_instructions": f"{_ECHO}{chr(0x08)}"}, id="instructions-backspace"),
    pytest.param({"name": f"Lina{chr(7)}{_ECHO}"}, id="name-bell"),
    pytest.param({"name": f"Lina{chr(10)}{_ECHO}"}, id="name-newline"),
    pytest.param({"name": f"Lina{chr(0x200B)}{_ECHO}"}, id="name-zero-width-space"),
    pytest.param({"name": f"Lina{chr(0x202E)}{_ECHO}"}, id="name-bidi-override"),
    pytest.param({"name": f"Lina{chr(0x2028)}{_ECHO}"}, id="name-line-separator"),
    pytest.param({"name": f"Lina{chr(0x2029)}{_ECHO}"}, id="name-paragraph-separator"),
    pytest.param({"name": ""}, id="name-empty"),
    pytest.param({"name": "   "}, id="name-blank"),
    pytest.param({"name": _ECHO + "n" * 111}, id="name-121-chars"),
    pytest.param({"name": 123456789}, id="name-int"),
    pytest.param({"name": [_ECHO]}, id="name-list"),
    pytest.param({"name": None}, id="name-null"),
    pytest.param({"ui_language": None}, id="ui-language-null"),
    pytest.param({"timezone": None}, id="timezone-null"),
    pytest.param({"personal_instructions": None}, id="instructions-null"),
    pytest.param([{"name": _ECHO}], id="not-an-object"),
]


class TestPatchRefusals:
    """Every refused body is a 422 that writes nothing and echoes nothing."""

    @pytest.mark.parametrize("body", _BAD_PATCHES)
    def test_my_account_api_patch_bad_body_is_422_without_effect(
        self, db: FakeDb, body: Any
    ) -> None:
        _route(_app(), "PATCH", _ME)
        _, token = _signed_in(db, **_START)
        before = _users(db)
        mark = len(db.calls)

        response = _patch(_client(_app()), token, body)

        assert response.status_code == 422, response.text
        assert _users(db) == before
        assert _user_writes(db, mark) == []
        assert db.audit_rows() == []
        _assert_no_echo(response, *_echo_markers(body))

    @pytest.mark.parametrize("field", ["name", "personal_instructions"])
    def test_my_account_api_patch_lone_surrogate_is_422(self, db: FakeDb, field: str) -> None:
        """A lone UTF-16 surrogate (category Cs) is refused, not stored."""
        _route(_app(), "PATCH", _ME)
        _, token = _signed_in(db, **_START)
        before = _users(db)
        content = b'{"' + field.encode() + b'": "Lina\\ud800' + _ECHO.encode() + b'"}'

        response = _client(_app()).patch(
            _ME, content=content, headers=_cookie(token, **{"Content-Type": "application/json"})
        )

        assert response.status_code == 422, response.text
        assert _users(db) == before
        _assert_no_echo(response, _ECHO)


# ---------------------------------------------------------------------------
# 5. POST /api/me/password
# ---------------------------------------------------------------------------

_POLICY_CASES: Final = [
    pytest.param(_TOO_SHORT, "too_short", id="11-chars"),
    pytest.param("Qwerty123456", "common", id="common"),
    pytest.param(_EMAIL.upper(), "equals_email", id="equals-email"),
    pytest.param("Ab1-" * 33, "too_long", id="132-chars"),
]

_BAD_PASSWORD_BODIES: Final = [
    pytest.param({}, id="empty"),
    pytest.param({"current_password": _PASSWORD}, id="no-new-password"),
    pytest.param({"new_password": _NEW_PASSWORD}, id="no-current-password"),
    pytest.param(
        {"current_password": _PASSWORD, "new_password": _NEW_PASSWORD, "email": _ECHO},
        id="extra-email",
    ),
    pytest.param(
        {"current_password": _PASSWORD, "new_password": _NEW_PASSWORD, "user_id": _ECHO},
        id="extra-user-id",
    ),
    pytest.param(
        {
            "current_password": _PASSWORD,
            "new_password": _NEW_PASSWORD,
            "confirm_password": _NEW_PASSWORD,
        },
        id="extra-confirm",
    ),
    pytest.param({"current_password": "", "new_password": _NEW_PASSWORD}, id="empty-current"),
    pytest.param({"current_password": _PASSWORD, "new_password": ""}, id="empty-new"),
    pytest.param(
        {"current_password": _PASSWORD, "new_password": "N" * 1025}, id="new-over-1024-chars"
    ),
    pytest.param(
        {"current_password": "C" * 1025, "new_password": _NEW_PASSWORD},
        id="current-over-1024-chars",
    ),
    pytest.param(
        {"current_password": _PASSWORD, "new_password": 123456789012}, id="new-not-a-string"
    ),
    pytest.param({"current_password": None, "new_password": _NEW_PASSWORD}, id="null-current"),
    pytest.param([_PASSWORD, _NEW_PASSWORD], id="not-an-object"),
]


class TestChangePassword:
    """The caller changes their own password; every session of theirs ends."""

    def test_my_account_api_password_change_stores_the_new_hash(self, db: FakeDb) -> None:
        """204 with an empty body; the stored hash is the new password's."""
        user_id, token = _signed_in(db)

        response = _change(_client(_app()), token)

        assert response.status_code == 204, response.text
        assert response.content == b""
        assert db.users[user_id]["password_hash"] == fake_hash(_NEW_PASSWORD)

    def test_my_account_api_password_change_clears_the_session_cookie(self, db: FakeDb) -> None:
        """Set-Cookie admino_session with an empty value, Max-Age=0 and Path=/."""
        _, token = _signed_in(db)

        response = _change(_client(_app()), token)

        assert response.status_code == 204, response.text
        value, attributes = _session_set_cookie(response)
        assert value in {"", '""'}
        assert attributes.get("max-age") == "0"
        assert attributes.get("path") == "/"

    def test_my_account_api_password_change_ends_the_current_session(self, db: FakeDb) -> None:
        """The cookie that made the change no longer resolves: 401 on /api/auth/me and
        /api/me."""
        _, token = _signed_in(db)
        client = _client(_app())

        response = _change(client, token)

        assert response.status_code == 204, response.text
        assert db.session_revoked(token)
        assert client.get(_AUTH_ME, headers=_cookie(token)).status_code == 401
        assert _get(client, token).status_code == 401

    def test_my_account_api_password_change_ends_every_session_of_the_caller(
        self, db: FakeDb
    ) -> None:
        """Every other device of the caller is logged out too."""
        user_id, token = _signed_in(db)
        others = [db.open_session(user_id) for _ in range(3)]
        client = _client(_app())

        response = _change(client, token)

        assert response.status_code == 204, response.text
        assert db.sessions_of(user_id) == []
        assert [db.session_revoked(other) for other in others] == [True] * 3
        assert [client.get(_AUTH_ME, headers=_cookie(other)).status_code for other in others] == [
            401
        ] * 3

    def test_my_account_api_password_change_keeps_other_users_logged_in(self, db: FakeDb) -> None:
        """A colleague, another org's member and a Super Admin keep their sessions and
        their passwords."""
        _, token = _signed_in(db, "org_admin")
        others = [
            _account(db, "editor"),
            _account(db, "editor", org_id=OTHER_ORG_ID),
            _account(db, "super_admin"),
        ]
        tokens = [db.open_session(other) for other in others]
        client = _client(_app())

        response = _change(client, token)

        assert response.status_code == 204, response.text
        assert [client.get(_AUTH_ME, headers=_cookie(t)).status_code for t in tokens] == [200] * 3
        assert [db.users[other]["password_hash"] for other in others] == [fake_hash(_PASSWORD)] * 3

    def test_my_account_api_password_change_new_password_logs_in_old_does_not(
        self, db: FakeDb
    ) -> None:
        """POST /api/auth/login: the old password is 401, the new one 204."""
        _, token = _signed_in(db, email=_EMAIL)
        client = _client(_app())

        response = _change(client, token)
        client.cookies.clear()
        old = client.post(_LOGIN, json={"email": _EMAIL, "password": _PASSWORD})
        client.cookies.clear()
        new = client.post(_LOGIN, json={"email": _EMAIL, "password": _NEW_PASSWORD})
        client.cookies.clear()

        assert response.status_code == 204, response.text
        assert old.status_code == 401, old.text
        assert new.status_code == 204, new.text

    @pytest.mark.parametrize("who", ["member", "super_admin"])
    def test_my_account_api_password_change_is_audited(self, db: FakeDb, who: str) -> None:
        """One password.change row: the caller, their org (none for a Super Admin),
        target the caller, the client IP, metadata {"sessions_revoked": 3}; nothing else
        is audited."""
        user_id, token = _signed_in(db, "editor" if who == "member" else "super_admin")
        db.open_session(user_id)
        db.open_session(user_id)

        response = _change(_client(_app(), ip=_IP_B), token)

        assert response.status_code == 204, response.text
        assert [row["action"] for row in db.audit_rows()] == ["password.change"]
        row = db.audit_rows("password.change")[0]
        assert (row["actor_kind"], _uuid(row["actor_user_id"])) == (who, user_id)
        assert _uuid(row["org_id"]) == (ORG_ID if who == "member" else None)
        assert (row["target_type"], row["target_ids"]) == ("user", [str(user_id)])
        assert row["ip"] == _IP_B
        assert row["metadata"] == {"sessions_revoked": 3}

    def test_my_account_api_password_change_audit_row_has_no_secret(self, db: FakeDb) -> None:
        _, token = _signed_in(db, email=_EMAIL)

        response = _change(_client(_app()), token)

        assert response.status_code == 204, response.text
        text = repr(db.audit_rows())
        for secret in (_PASSWORD, _NEW_PASSWORD, fake_hash(_NEW_PASSWORD), _EMAIL):
            assert secret not in text

    def test_my_account_api_password_wrong_current_is_403_and_changes_nothing(
        self, db: FakeDb
    ) -> None:
        """403 Re-authentication failed (never 401): the hash, both sessions and the
        cookie stay, nothing is audited, and the session still works."""
        user_id, token = _signed_in(db)
        other = db.open_session(user_id)
        client = _client(_app())

        response = _change(client, token, current=_WRONG_PASSWORD)

        assert (response.status_code, response.json()) == (403, _REAUTH_FAILED)
        assert db.users[user_id]["password_hash"] == fake_hash(_PASSWORD)
        assert not db.session_revoked(token)
        assert not db.session_revoked(other)
        assert _session_cookie_headers(response) == []
        assert db.audit_rows("password.change") == []
        assert client.get(_AUTH_ME, headers=_cookie(token)).status_code == 200
        assert _WRONG_PASSWORD not in response.text

    def test_my_account_api_password_wrong_current_counts_in_the_login_throttle(
        self, db: FakeDb
    ) -> None:
        """Like a failed login: one failure on the account's subject and on the IP."""
        _, token = _signed_in(db, email=_EMAIL)

        response = _change(_client(_app()), token, current=_WRONG_PASSWORD)

        assert response.status_code == 403, response.text
        account_row = db.throttle_row("account", account_subject(_EMAIL))
        ip_row = db.throttle_row("ip", ip_subject(_IP_A))
        assert account_row is not None
        assert account_row["failures"] == 1
        assert ip_row is not None
        assert ip_row["failures"] == 1

    @pytest.mark.usefixtures("login_delays")
    def test_my_account_api_password_lockout_refuses_even_the_right_password(
        self, db: FakeDb
    ) -> None:
        """After the lockout threshold of wrong current passwords, the right one is 403
        too; the Nth failure records login.lockout with the caller's actor columns."""
        user_id, token = _signed_in(db, email=_EMAIL)
        client = _client(_app())
        limit = _lockout_after()

        wrong = [_change(client, token, current=_WRONG_PASSWORD) for _ in range(limit)]
        right = _change(client, token)

        assert [response.status_code for response in wrong] == [403] * limit
        assert (right.status_code, right.json()) == (403, _REAUTH_FAILED)
        lockouts = db.audit_rows("login.lockout")
        assert any(
            (_uuid(row["actor_user_id"]), _uuid(row["org_id"])) == (user_id, ORG_ID)
            for row in lockouts
        ), lockouts
        assert db.users[user_id]["password_hash"] == fake_hash(_PASSWORD)
        assert db.audit_rows("password.change") == []
        assert client.get(_AUTH_ME, headers=_cookie(token)).status_code == 200

    def test_my_account_api_password_another_users_password_is_refused(self, db: FakeDb) -> None:
        """The current password is the caller's OWN: a colleague's is a 403."""
        colleague_password = "Colleague-Password-166-x"
        db.add_account(password_hash=fake_hash(colleague_password))
        user_id, token = _signed_in(db)

        response = _change(_client(_app()), token, current=colleague_password)

        assert (response.status_code, response.json()) == (403, _REAUTH_FAILED)
        assert db.users[user_id]["password_hash"] == fake_hash(_PASSWORD)

    @pytest.mark.parametrize(("new", "reason"), _POLICY_CASES)
    def test_my_account_api_password_policy_failure_is_422_with_reason(
        self, db: FakeDb, new: str, reason: str
    ) -> None:
        """{"detail": <policy message>, "reason": <reason>}; neither password echoed;
        nothing changes and nothing counts in the throttle."""
        user_id, token = _signed_in(db, email=_EMAIL)
        client = _client(_app())

        response = _change(client, token, new=new)

        assert response.status_code == 422, response.text
        assert response.json() == _policy_body(reason)
        assert new not in response.text
        assert _PASSWORD not in response.text
        assert db.users[user_id]["password_hash"] == fake_hash(_PASSWORD)
        assert not db.session_revoked(token)
        assert db.audit_rows() == []
        assert db.throttle == []

    def test_my_account_api_password_policy_is_checked_before_the_current_password(
        self, db: FakeDb
    ) -> None:
        """A weak new password with a wrong current one is the policy 422, not a 403, and
        counts nothing in the login throttle."""
        _, token = _signed_in(db, email=_EMAIL)

        response = _change(_client(_app()), token, current=_WRONG_PASSWORD, new=_TOO_SHORT)

        assert response.status_code == 422, response.text
        assert response.json() == _policy_body("too_short")
        assert db.throttle == []

    @pytest.mark.parametrize("body", _BAD_PASSWORD_BODIES)
    def test_my_account_api_password_bad_body_is_422_without_echo(
        self, db: FakeDb, body: Any
    ) -> None:
        """Missing, empty, oversized, mistyped or extra fields: 422, no password echoed,
        nothing changes, nothing counted."""
        _route(_app(), "POST", _ME_PASSWORD)
        user_id, token = _signed_in(db)
        client = _client(_app())

        response = client.post(_ME_PASSWORD, json=body, headers=_cookie(token))

        assert response.status_code == 422, response.text
        _assert_no_echo(response, _PASSWORD, _NEW_PASSWORD, *_echo_markers(body))
        assert db.users[user_id]["password_hash"] == fake_hash(_PASSWORD)
        assert not db.session_revoked(token)
        assert db.audit_rows() == []
        assert db.throttle == []

    @pytest.mark.parametrize("headers", _CROSS_ORIGIN)
    def test_my_account_api_password_cross_origin_is_refused(
        self, db: FakeDb, headers: dict[str, str]
    ) -> None:
        """CSRF: a cross-origin POST is 403 before anything runs; nothing changes."""
        _route(_app(), "POST", _ME_PASSWORD)
        user_id, token = _signed_in(db)
        other = db.open_session(user_id)

        response = _change(_client(_app()), token, **headers)

        assert (response.status_code, response.json()) == (403, _CSRF_REFUSED)
        assert db.users[user_id]["password_hash"] == fake_hash(_PASSWORD)
        assert not db.session_revoked(token)
        assert not db.session_revoked(other)
        assert db.audit_rows() == []
        assert db.calls == []

    def test_my_account_api_password_audit_failure_is_500_and_changes_nothing(
        self, db: FakeDb
    ) -> None:
        """Fail closed: the audit write fails → 500; the old hash and every session stay."""
        user_id, token = _signed_in(db)
        other = db.open_session(user_id)
        db.fail_audit = True
        client = _client(_app(), raise_server_exceptions=False)

        response = _change(client, token)

        assert response.status_code == 500
        assert db.users[user_id]["password_hash"] == fake_hash(_PASSWORD)
        assert not db.session_revoked(token)
        assert not db.session_revoked(other)
        assert db.audit_rows("password.change") == []
        db.fail_audit = False
        assert client.get(_AUTH_ME, headers=_cookie(token)).status_code == 200

    def test_my_account_api_password_logs_no_secret(
        self, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No password, hash or email in any app log record (wrong, refused, done)."""
        caplog.set_level(logging.DEBUG)
        _, token = _signed_in(db, email="zephyrmarker.pw@example.ch")
        client = _client(_app(), raise_server_exceptions=False)

        wrong = _change(client, token, current=_WRONG_PASSWORD)
        refused = _change(client, token, new=_TOO_SHORT)
        done = _change(client, token)

        assert [wrong.status_code, refused.status_code, done.status_code] == [403, 422, 204]
        logs = _log_text(caplog)
        for secret in (
            _PASSWORD,
            _NEW_PASSWORD,
            _WRONG_PASSWORD,
            _TOO_SHORT,
            fake_hash(_NEW_PASSWORD),
            "zephyrmarker",
        ):
            assert secret not in logs, secret


# ---------------------------------------------------------------------------
# 6. Rate limits, the capability check and their order
# ---------------------------------------------------------------------------


class TestRateLimitsAndCapability:
    """Per-user buckets; the limiter runs before the capability check and the database."""

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_my_account_api_rate_limit_is_per_user(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        """With a burst of 1: user A's second call is 429; user B (same org) still gets
        through; the bucket is (key, "user:<A>")."""
        app = _app()
        _route(app, *_ROUTE_OF[action])
        monkeypatch.setitem(server._RATE_LIMITS, _ROUTE_KEYS[action], (0.001, 1))
        user_a, token_a = _signed_in(db)
        user_b, token_b = _signed_in(db)
        client = _client(app)

        first = _call(client, action, token_a, body=_SPENDING_BODIES[action])
        limited = _call(client, action, token_a)
        other = _call(client, action, token_b)

        assert first.status_code == _SPENDING_STATUS[action], first.text
        assert (limited.status_code, limited.json()) == (429, _RATE_LIMITED)
        assert other.status_code == _SUCCESS[action], other.text
        assert (_ROUTE_KEYS[action], f"user:{user_a}") in server._rate_buckets
        assert (_ROUTE_KEYS[action], f"user:{user_b}") in server._rate_buckets
        assert db.users[user_a]["password_hash"] == fake_hash(_PASSWORD)

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_my_account_api_rate_limited_call_does_no_database_work(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        """The 429 runs no statement besides require_session's own; nothing changes."""
        app = _app()
        _route(app, *_ROUTE_OF[action])
        monkeypatch.setitem(server._RATE_LIMITS, _ROUTE_KEYS[action], (0.001, 1))
        user_id, token = _signed_in(db, **_START)
        client = _client(app)
        _call(client, action, token, body=_SPENDING_BODIES[action])
        before = _users(db)
        mark = len(db.calls)

        limited = _call(client, action, token)

        assert (limited.status_code, limited.json()) == (429, _RATE_LIMITED)
        assert _route_work(db, mark) == []
        assert _users(db) == before
        assert not db.session_revoked(token)
        assert db.throttle == []
        assert db.users[user_id]["password_hash"] == fake_hash(_PASSWORD)

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_my_account_api_rate_limit_runs_before_the_capability_check(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        """A caller refused by can() spends its own bucket: 403, then 429."""
        app = _app()
        _route(app, *_ROUTE_OF[action])
        monkeypatch.setitem(server._RATE_LIMITS, _ROUTE_KEYS[action], (0.001, 1))
        _, token = _signed_in(db)
        _CanSpy(monkeypatch, deny=frozenset({Capability.ACCOUNT_MANAGE}))
        client = _client(app)

        first = _call(client, action, token)
        second = _call(client, action, token)

        assert (first.status_code, first.json()) == (403, _FORBIDDEN)
        assert (second.status_code, second.json()) == (429, _RATE_LIMITED)

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_my_account_api_route_asks_can_for_account_manage(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        _, token = _signed_in(db)
        spy = _CanSpy(monkeypatch)

        response = _call(_client(_app()), action, token)

        assert response.status_code == _SUCCESS[action], response.text
        assert Capability.ACCOUNT_MANAGE in spy.capabilities

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_my_account_api_capability_refused_is_403_before_the_database(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        """can() refusing account.manage → 403 Forbidden; no statement besides
        require_session's, nothing changes, nothing audited."""
        _route(_app(), *_ROUTE_OF[action])
        user_id, token = _signed_in(db, **_START)
        _CanSpy(monkeypatch, deny=frozenset({Capability.ACCOUNT_MANAGE}))
        before = _users(db)
        mark = len(db.calls)

        response = _call(_client(_app()), action, token)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _route_work(db, mark) == []
        assert _users(db) == before
        assert not db.session_revoked(token)
        assert db.audit_rows() == []
        assert db.users[user_id]["password_hash"] == fake_hash(_PASSWORD)


# ---------------------------------------------------------------------------
# 7. Every role manages its own account
# ---------------------------------------------------------------------------


class TestEveryRole:
    """Capability.ACCOUNT_MANAGE: Org Admin, Editor and Super Admin."""

    @pytest.mark.parametrize("who", _ROLES)
    @pytest.mark.parametrize("action", _ACTIONS)
    def test_my_account_api_every_role_can_use_the_route(
        self, db: FakeDb, action: str, who: str
    ) -> None:
        _, token = _signed_in(db, who)

        response = _call(_client(_app()), action, token)

        assert response.status_code == _SUCCESS[action], response.text

    @pytest.mark.parametrize("who", _ROLES)
    def test_my_account_api_every_role_changes_its_own_password(self, db: FakeDb, who: str) -> None:
        user_id, token = _signed_in(db, who)

        response = _change(_client(_app()), token)

        assert response.status_code == 204, response.text
        assert db.users[user_id]["password_hash"] == fake_hash(_NEW_PASSWORD)
        assert db.sessions_of(user_id) == []

    @pytest.mark.parametrize("who", _ROLES)
    def test_my_account_api_every_role_patches_its_own_profile(self, db: FakeDb, who: str) -> None:
        user_id, token = _signed_in(db, who, **_START)

        response = _patch(_client(_app()), token, {"name": "Renamed", "timezone": "Europe/Vienna"})

        assert response.status_code == 200, response.text
        assert (db.users[user_id]["name"], db.users[user_id]["timezone"]) == (
            "Renamed",
            "Europe/Vienna",
        )


# ---------------------------------------------------------------------------
# 8. password_changed_at (GH-307)
# ---------------------------------------------------------------------------

# A change stored before the test (with microseconds, so a lossy copy shows).
_EARLIER_CHANGE: Final = datetime(2026, 3, 4, 5, 6, 7, 890123, tzinfo=UTC)

_REFUSED_CHANGES: Final = [
    pytest.param("wrong-current-password", 403, id="wrong-current-password-403"),
    pytest.param("policy", 422, id="policy-422"),
    pytest.param("audit-failure", 500, id="audit-failure-500"),
]


def _parsed_changed_at(body: dict[str, Any]) -> datetime | None:
    """A body's password_changed_at: null, or an ISO 8601 string with a UTC offset,
    parsed to the instant it names."""
    value = body["password_changed_at"]
    if value is None:
        return None
    assert isinstance(value, str), value
    parsed = datetime.fromisoformat(value)
    assert parsed.utcoffset() == timedelta(0), value
    return parsed


class TestPasswordChangedAt:
    """Set by POST /api/me/password, shown by GET and PATCH /api/me, nothing else."""

    def test_my_account_api_password_change_sets_password_changed_at(self, db: FakeDb) -> None:
        """204; the stored date is an aware UTC datetime from the clock during the request,
        and the next GET /api/me (a new session: the change ended them all) shows it."""
        user_id, token = _signed_in(db)
        before = datetime.now(UTC)

        response = _change(_client(_app()), token)

        after = datetime.now(UTC)
        stored = db.users[user_id]["password_changed_at"]
        read = _get(_client(_app()), db.open_session(user_id))
        assert response.status_code == 204, response.text
        assert isinstance(stored, datetime), stored
        assert stored.utcoffset() == timedelta(0)
        assert before <= stored <= after
        assert read.status_code == 200, read.text
        assert _parsed_changed_at(read.json()) == stored

    def test_my_account_api_patch_response_carries_password_changed_at(self, db: FakeDb) -> None:
        """The PATCH /api/me response and the next GET show the stored date; a profile
        change leaves it as it is."""
        user_id, token = _signed_in(db, **_START, password_changed_at=_EARLIER_CHANGE)
        client = _client(_app())

        patched = _patch(client, token, {"name": "Lina Muster"})
        read = _get(client, token)

        assert patched.status_code == 200, patched.text
        assert _parsed_changed_at(patched.json()) == _EARLIER_CHANGE
        assert _parsed_changed_at(read.json()) == _EARLIER_CHANGE
        assert db.users[user_id]["password_changed_at"] == _EARLIER_CHANGE

    @pytest.mark.parametrize(("cause", "status"), _REFUSED_CHANGES)
    def test_my_account_api_refused_password_change_keeps_password_changed_at(
        self, db: FakeDb, cause: str, status: int
    ) -> None:
        """A wrong current password, a refused new one or a failed audit write: the
        earlier date stays (stored and on GET /api/me); the next accepted change then
        moves it (the positive control)."""
        user_id, token = _signed_in(db, password_changed_at=_EARLIER_CHANGE)
        client = _client(_app(), raise_server_exceptions=False)
        db.fail_audit = cause == "audit-failure"

        refused = _change(
            client,
            token,
            current=_WRONG_PASSWORD if cause == "wrong-current-password" else _PASSWORD,
            new=_TOO_SHORT if cause == "policy" else _NEW_PASSWORD,
        )
        db.fail_audit = False
        kept = db.users[user_id]["password_changed_at"]
        read = _get(client, token)
        accepted = _change(client, token)

        assert refused.status_code == status, refused.text
        assert kept == _EARLIER_CHANGE
        assert _parsed_changed_at(read.json()) == _EARLIER_CHANGE
        assert accepted.status_code == 204, accepted.text
        assert db.users[user_id]["password_changed_at"] > _EARLIER_CHANGE

    def test_my_account_api_password_changed_at_is_the_callers_own(self, db: FakeDb) -> None:
        """Before the change the caller reads null while a colleague has a date; after it,
        the colleague's and another org's dates are unchanged and the colleague still
        reads their own."""
        user_id, token = _signed_in(db)
        colleague, colleague_token = _signed_in(
            db, "org_admin", password_changed_at=_EARLIER_CHANGE
        )
        outsider = _account(db, "editor", org_id=OTHER_ORG_ID, password_changed_at=_EARLIER_CHANGE)
        client = _client(_app())

        own_before = _get(client, token)
        changed = _change(client, token)
        theirs = _get(_client(_app()), colleague_token)

        assert own_before.status_code == 200, own_before.text
        assert own_before.json()["password_changed_at"] is None
        assert changed.status_code == 204, changed.text
        assert db.users[user_id]["password_changed_at"] is not None
        assert [db.users[other]["password_changed_at"] for other in (colleague, outsider)] == [
            _EARLIER_CHANGE,
            _EARLIER_CHANGE,
        ]
        assert _parsed_changed_at(theirs.json()) == _EARLIER_CHANGE

    def test_my_account_api_auth_me_does_not_carry_password_changed_at(self, db: FakeDb) -> None:
        """GET /api/auth/me keeps its six keys; GET /api/me is where the date shows."""
        _, token = _signed_in(db, password_changed_at=_EARLIER_CHANGE)
        client = _client(_app())

        auth_me = client.get(_AUTH_ME, headers=_cookie(token))
        me = _get(client, token)

        assert auth_me.status_code == 200, auth_me.text
        assert set(auth_me.json()) == _AUTH_ME_KEYS
        assert _parsed_changed_at(me.json()) == _EARLIER_CHANGE

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param({"password_changed_at": "2020-01-02T03:04:05Z"}, id="a-date"),
            pytest.param({"name": "Lina Muster", "password_changed_at": None}, id="null-and-name"),
        ],
    )
    def test_my_account_api_patch_cannot_set_password_changed_at(
        self, db: FakeDb, body: dict[str, Any]
    ) -> None:
        """An unknown field of MyAccountPatch: 422, nothing written, the date unchanged."""
        user_id, token = _signed_in(db, **_START, password_changed_at=_EARLIER_CHANGE)
        client = _client(_app())

        response = _patch(client, token, body)
        read = _get(client, token)

        assert response.status_code == 422, response.text
        assert db.users[user_id]["name"] == _START["name"]
        assert db.users[user_id]["password_changed_at"] == _EARLIER_CHANGE
        assert _parsed_changed_at(read.json()) == _EARLIER_CHANGE

    def test_my_account_api_password_changed_at_reaches_no_log_or_audit_row(
        self, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The password.change metadata stays exactly {"sessions_revoked": n}; no app log
        record names the column or carries the date."""
        caplog.set_level(logging.DEBUG)
        user_id, token = _signed_in(db)

        changed = _change(_client(_app()), token)
        read = _get(_client(_app()), db.open_session(user_id))

        assert changed.status_code == 204, changed.text
        assert read.status_code == 200, read.text
        stamp = db.users[user_id]["password_changed_at"]
        assert [row["metadata"] for row in db.audit_rows()] == [{"sessions_revoked": 1}]
        logs = _log_text(caplog)
        assert "password_changed_at" not in logs
        for rendered in (stamp.isoformat(), str(stamp), read.json()["password_changed_at"]):
            assert rendered not in logs
