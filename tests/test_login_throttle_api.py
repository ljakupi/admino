"""HTTP-layer spec for brute-force protection and lockouts (GH-157).

The FastAPI app from ``create_app()`` runs against the in-memory database of
tests/db_fakes.py (what ``admino.database.get_pool`` returns). The real
``admino.auth``, ``admino.login_throttle``, ``admino.password_reset``,
``admino.invitations``, ``admino.sessions`` and ``admino.audit_events`` code
runs; only Argon2 is replaced by a fast fake, and the progressive delay is
recorded through the ``login_delays`` fixture (nothing really sleeps). Each
attempt starts from an empty token-bucket map (``server._rate_buckets``), so
the login's own per-IP bucket (0.2/s, burst 5, unchanged) never answers first,
except in the tests about it.

What these tests pin down:
- ``POST /api/auth/login`` while the account or the IP is locked: a 401 whose
  status, body and headers equal a wrong-password 401, and no session cookie.
  A lockout is never a 429.
- ``POST /api/auth/password-reset/confirm``, ``GET
  /api/auth/invitations/{token}`` and ``POST
  /api/auth/invitations/{token}/accept`` share the login's per-IP counter:
  an IP that is locked (or has 10 failures in the window) gets 429 ``{"detail":
  "Too many attempts. Try again later."}`` before any token or account lookup,
  and nothing is written. Otherwise the attempt reserves one failure and waits
  out the progressive delay before the token is checked. An unusable link
  (400/404, malformed included) keeps the failure, and the 10th locks the IP
  with a per-IP ``login.lockout`` event; a success, or a password-policy 422,
  releases it. 10 failed logins block these routes from that IP, and 10
  unusable links block the login from that IP; other IPs are unaffected.
- ``POST /api/auth/password-reset``: a locked IP gets the same 429 before
  anything is queued; otherwise the IP's delay applies, then the usual 202.
  The request never counts as a failure.
- The route's existing token bucket runs first: an exhausted bucket answers
  429 "Rate limit exceeded" without touching the throttle.
- The client IP is the one the trusted-proxy middleware resolves.
- The counters survive a restart: a new app on the same database is still
  locked.

All database calls are faked. No network, no real PostgreSQL, no sleeping.

Security notes:
- No user enumeration: a locked login is indistinguishable from a failed one.
- A lockout on a token route writes nothing and looks nothing up.
"""

from __future__ import annotations

import copy
import re
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from admino import server
from admino.config import AppConfig
from admino.server import create_app
from tests.db_fakes import FakeDb, account_subject, fake_hash, plain, sha256

if TYPE_CHECKING:
    from types import ModuleType

    import httpx
    from fastapi import FastAPI

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE = "admino_session"
_LOGIN = "/api/auth/login"
_REQUEST = "/api/auth/password-reset"
_CONFIRM = "/api/auth/password-reset/confirm"
_EMAIL = "Api.Throttle.Marker@Example.test"
_OTHER_EMAIL = "other.person@example.test"
_RESET_EMAIL = "reset.person@example.test"
_INVITEE = "invited.person@example.ch"
_NAME = "Grace Hopper"
_PASSWORD = "violet-Anchor-93-quartz"
_WRONG = "violet-Anchor-93-quartzz"
_SHORT = "Kq7#vX9!pL2"
_IP_A = "203.0.113.5"
_IP_B = "198.51.100.23"
_WELL_FORMED_UNKNOWN = "Q" * 21 + "-" + "z" * 20 + "_"
_PUBLIC_URL = "https://admino.example.ch"
_LOGIN_FAILED = {"detail": "Invalid email or password"}
_TOO_MANY = {"detail": "Too many attempts. Try again later."}
_RATE_LIMITED = {"detail": "Rate limit exceeded"}
_ACCOUNT_LOCK = {"per_ip": False, "lockout_minutes": 15}
_IP_LOCK = {"per_ip": True, "lockout_minutes": 15}
_SEQUENCE_TO_TEN = [1.0, 2.0, 4.0, 8.0, 8.0, 8.0, 8.0]

_TOKEN_ROUTES = ["reset-confirm", "invitation-details", "invitation-accept"]
_UNUSABLE_STATUS = {"reset-confirm": 400, "invitation-details": 404, "invitation-accept": 404}
_SUCCESS_STATUS = {"reset-confirm": 204, "invitation-details": 200, "invitation-accept": 204}
_BUCKET_KEYS = {
    "reset-confirm": "/api/auth/password-reset/confirm",
    "invitation-details": "/api/auth/invitations/get",
    "invitation-accept": "/api/auth/invitations/accept",
}
# Statements that look a token or an account up.
_LOOKUP_TABLES = r"\b(?:password_reset_tokens|invitations|users)\b"

# The proxy on the internal network and two browser clients behind it (GH-156).
_PROXY_IP = "172.31.0.10"
_CLIENT_A = "203.0.113.7"
_CLIENT_B = "203.0.113.8"


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def throttle() -> ModuleType:
    """admino.login_throttle, imported per test."""
    import admino.login_throttle as module

    return module


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


def _config() -> MagicMock:
    """A minimal config: the public URL links are built from, no trusted proxy."""
    config = MagicMock()
    del config.auth
    config.limits.max_message_length = 4000
    config.server.host = "127.0.0.1"
    config.server.port = 8000
    config.server.cookie_secure = True
    config.server.public_url = _PUBLIC_URL
    config.server.trusted_proxies = []
    config.llm.provider = "infomaniak"
    config.llm.active_model_name = "test-model"
    return config


def _app() -> FastAPI:
    """create_app with a stub agent (no lifespan runs under TestClient)."""
    return create_app(agent=MagicMock(), config=_config())  # type: ignore[arg-type]


def _client(app: FastAPI, ip: str) -> TestClient:
    """A client whose peer address is ``ip``; redirects are not followed."""
    return TestClient(app, client=(ip, 50000), follow_redirects=False)


def _now() -> datetime:
    return datetime.now(UTC)


def _login(
    client: TestClient, email: str, password: str, *, clear_buckets: bool = True, **kwargs: Any
) -> httpx.Response:
    """POST /api/auth/login from an empty bucket map; the cookie jar is emptied after."""
    if clear_buckets:
        server._rate_buckets.clear()
    response = client.post(_LOGIN, json={"email": email, "password": password}, **kwargs)
    client.cookies.clear()
    return response


def _token_request(
    client: TestClient,
    route: str,
    token: str,
    password: str = _PASSWORD,
    *,
    clear_buckets: bool = True,
) -> httpx.Response:
    """One attempt on a throttled token route, from an empty bucket map."""
    if clear_buckets:
        server._rate_buckets.clear()
    if route == "reset-confirm":
        response = client.post(_CONFIRM, json={"token": token, "new_password": password})
    elif route == "invitation-details":
        response = client.get(f"/api/auth/invitations/{token}")
    else:
        response = client.post(
            f"/api/auth/invitations/{token}/accept", json={"name": _NAME, "password": password}
        )
    client.cookies.clear()
    return response


def _reset_request(client: TestClient, email: str) -> httpx.Response:
    server._rate_buckets.clear()
    return client.post(_REQUEST, json={"email": email})


def _account(db: FakeDb, email: str = _EMAIL) -> Any:
    return db.add_account(email=email, password_hash=fake_hash(_PASSWORD))


def _valid_token(db: FakeDb, route: str) -> str:
    """A usable reset token or invitation token for the route."""
    if route == "reset-confirm":
        return db.add_reset_token(_account(db, _RESET_EMAIL))
    invitee = db.add_account(email=_INVITEE, status="invited", password_hash=None, name=None)
    return db.add_invitation(invitee)


def _still_usable(db: FakeDb, route: str, token: str) -> bool:
    """The token wasn't consumed (reset) or accepted (invitation)."""
    if route == "reset-confirm":
        return any(row["token_hash"] == sha256(token) for row in db.tokens.values())
    row = db.invitation_by_token(token)
    return row is not None and row["accepted_at"] is None


def _ip_row(db: FakeDb, throttle: ModuleType, ip: str = _IP_A) -> dict[str, Any] | None:
    return db.throttle_row("ip", throttle.ip_subject(ip))


def _seed_ip(db: FakeDb, throttle: ModuleType, ip: str = _IP_A, **fields: Any) -> None:
    db.add_throttle("ip", throttle.ip_subject(ip), **fields)


def _lock_ip(db: FakeDb, throttle: ModuleType, ip: str = _IP_A) -> None:
    _seed_ip(db, throttle, ip, locked_until=_now() + timedelta(minutes=10))


def _locked(row: dict[str, Any] | None) -> bool:
    return row is not None and row["locked_until"] is not None and row["locked_until"] > _now()


def _lockouts(db: FakeDb) -> list[tuple[Any, ...]]:
    """(actor kind, actor user, org, ip, metadata) of every login.lockout row."""
    return [
        (
            row["actor_kind"],
            None if row["actor_user_id"] is None else plain(row["actor_user_id"]),
            None if row["org_id"] is None else plain(row["org_id"]),
            row["ip"],
            row["metadata"],
        )
        for row in db.audit_rows("login.lockout")
    ]


def _session_cookies(response: httpx.Response) -> list[str]:
    return [
        h for h in response.headers.get_list("set-cookie") if h.lower().startswith(f"{_COOKIE}=")
    ]


# GH-158: every response gets a fresh X-Request-ID (uuid4().hex), compared by shape only.
_REQUEST_ID_SHAPE = re.compile(r"[0-9a-f]{32}")


def _comparable_header(key: str, value: str) -> tuple[str, str]:
    """A header for comparison: a well-formed X-Request-ID becomes a fixed placeholder."""
    name = key.lower()
    if name == "x-request-id" and _REQUEST_ID_SHAPE.fullmatch(value):
        return name, "<request-id>"
    return name, value


def _comparable(response: httpx.Response) -> tuple[int, bytes, list[tuple[str, str]]]:
    """Status, body and every header except Date (X-Request-ID by shape only)."""
    headers = sorted(
        _comparable_header(key, value)
        for key, value in response.headers.multi_items()
        if key != "date"
    )
    return response.status_code, response.content, headers


def _lookups_since(db: FakeDb, start: int) -> list[str]:
    """Statements since ``start`` that touch a token or an account."""
    return [
        call.normalized for call in db.calls[start:] if re.search(_LOOKUP_TABLES, call.normalized)
    ]


# ---------------------------------------------------------------------------
# 1. The login route
# ---------------------------------------------------------------------------


class TestLoginRoute:
    """A lockout looks exactly like a failed login."""

    def test_login_throttle_api_locked_login_is_the_wrong_password_401(self, db: FakeDb) -> None:
        _account(db)
        _account(db, _OTHER_EMAIL)
        db.add_throttle("account", account_subject(_EMAIL), locked_until=_now() + timedelta(1))
        app = _app()

        locked = _login(_client(app, _IP_A), _EMAIL, _PASSWORD)
        wrong = _login(_client(app, _IP_B), _OTHER_EMAIL, _WRONG)

        assert locked.status_code == 401
        assert locked.json() == _LOGIN_FAILED
        assert _comparable(locked) == _comparable(wrong)
        assert _session_cookies(locked) == []
        assert db.sessions == {}

    def test_login_throttle_api_ten_failures_lock_the_login(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        _account(db)
        client = _client(_app(), _IP_A)

        statuses = [_login(client, _EMAIL, _WRONG).status_code for _ in range(10)]
        locked = _login(client, _EMAIL, _PASSWORD)
        elsewhere = _login(_client(_app(), _IP_B), _EMAIL, _PASSWORD)

        assert statuses == [401] * 10
        assert (locked.status_code, locked.json()) == (401, _LOGIN_FAILED)
        assert (elsewhere.status_code, elsewhere.json()) == (401, _LOGIN_FAILED)
        assert _session_cookies(locked) == _session_cookies(elsewhere) == []
        assert login_delays[:7] == _SEQUENCE_TO_TEN
        assert [(kind, ip, metadata) for kind, _, _, ip, metadata in _lockouts(db)] == [
            ("member", _IP_A, _ACCOUNT_LOCK),
            ("system", _IP_A, _IP_LOCK),
        ]

    def test_login_throttle_api_ip_lock_refuses_logins_from_that_ip_only(
        self, db: FakeDb, throttle: ModuleType
    ) -> None:
        _account(db)
        _lock_ip(db, throttle)
        app = _app()

        refused = _login(_client(app, _IP_A), _EMAIL, _PASSWORD)
        allowed = _login(_client(app, _IP_B), _EMAIL, _PASSWORD)

        assert (refused.status_code, refused.json()) == (401, _LOGIN_FAILED)
        assert allowed.status_code == 204

    def test_login_throttle_api_login_bucket_runs_before_the_throttle(
        self, db: FakeDb, throttle: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The existing per-IP bucket answers first; the throttle isn't touched."""
        _account(db)
        _lock_ip(db, throttle)
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _LOGIN, (0.001, 1))
        client = _client(app, _IP_A)
        first = _login(client, _EMAIL, _PASSWORD, clear_buckets=False)
        start = len(db.calls)

        second = _login(client, _EMAIL, _PASSWORD, clear_buckets=False)

        assert (first.status_code, first.json()) == (401, _LOGIN_FAILED)
        assert db.matching(r"\blogin_throttle\b") != []
        assert (second.status_code, second.json()) == (429, _RATE_LIMITED)
        assert db.calls[start:] == []


# ---------------------------------------------------------------------------
# 2. The token routes share the IP counter
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", _TOKEN_ROUTES)
class TestTokenRoutes:
    """Password-reset confirm and the invitation link routes are IP-throttled."""

    def test_login_throttle_api_locked_ip_is_429_before_any_lookup(
        self, db: FakeDb, throttle: ModuleType, route: str
    ) -> None:
        token = _valid_token(db, route)
        _lock_ip(db, throttle)
        app = _app()
        throttle_before = copy.deepcopy(db.throttle)
        audit_before = copy.deepcopy(db.audit)
        start = len(db.calls)

        response = _token_request(_client(app, _IP_A), route, token)

        assert (response.status_code, response.json()) == (429, _TOO_MANY)
        assert _lookups_since(db, start) == []
        assert db.throttle == throttle_before
        assert db.audit == audit_before
        assert _still_usable(db, route, token)
        assert _session_cookies(response) == []
        other = _token_request(_client(app, _IP_B), route, token)
        assert other.status_code == _SUCCESS_STATUS[route]

    def test_login_throttle_api_ten_failures_without_a_lock_are_429(
        self, db: FakeDb, throttle: ModuleType, route: str
    ) -> None:
        token = _valid_token(db, route)
        _seed_ip(db, throttle, failures=10, window_started_at=_now() - timedelta(minutes=1))
        before = copy.deepcopy(db.throttle)

        response = _token_request(_client(_app(), _IP_A), route, token)

        assert (response.status_code, response.json()) == (429, _TOO_MANY)
        assert db.throttle == before
        assert _still_usable(db, route, token)

    @pytest.mark.parametrize("token", [_WELL_FORMED_UNKNOWN, "not-a-token"])
    def test_login_throttle_api_unusable_link_counts_as_a_failure(
        self, db: FakeDb, throttle: ModuleType, route: str, token: str
    ) -> None:
        """An unknown or malformed link keeps its reservation."""
        response = _token_request(_client(_app(), _IP_A), route, token)

        assert response.status_code == _UNUSABLE_STATUS[route]
        row = _ip_row(db, throttle)
        assert row is not None
        assert row["failures"] == 1
        assert len(db.throttle) == 1

    def test_login_throttle_api_success_releases_the_reservation(
        self, db: FakeDb, throttle: ModuleType, route: str, login_delays: list[float]
    ) -> None:
        token = _valid_token(db, route)
        _seed_ip(db, throttle, failures=5)

        response = _token_request(_client(_app(), _IP_A), route, token)

        assert response.status_code == _SUCCESS_STATUS[route]
        row = _ip_row(db, throttle)
        assert row is not None
        assert row["failures"] == 5
        assert login_delays == [4.0]

    def test_login_throttle_api_tenth_unusable_link_locks_the_ip(
        self, db: FakeDb, throttle: ModuleType, route: str, login_delays: list[float]
    ) -> None:
        token = _valid_token(db, route)
        client = _client(_app(), _IP_A)

        statuses = [
            _token_request(client, route, _WELL_FORMED_UNKNOWN).status_code for _ in range(10)
        ]
        refused = _token_request(client, route, token)

        assert statuses == [_UNUSABLE_STATUS[route]] * 10
        assert _locked(_ip_row(db, throttle))
        assert _lockouts(db) == [("system", None, None, _IP_A, _IP_LOCK)]
        assert (refused.status_code, refused.json()) == (429, _TOO_MANY)
        assert _still_usable(db, route, token)
        assert login_delays[:7] == _SEQUENCE_TO_TEN

    def test_login_throttle_api_delay_comes_before_the_token_check(
        self,
        db: FakeDb,
        throttle: ModuleType,
        route: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _seed_ip(db, throttle, failures=3)
        seen: list[tuple[float, int, int | None]] = []

        async def sleep(delay: float, *_args: Any, **_kwargs: Any) -> None:
            row = _ip_row(db, throttle)
            seen.append(
                (delay, len(_lookups_since(db, 0)), None if row is None else row["failures"])
            )

        monkeypatch.setattr(throttle, "sleep", sleep)

        response = _token_request(_client(_app(), _IP_A), route, _WELL_FORMED_UNKNOWN)

        assert response.status_code == _UNUSABLE_STATUS[route]
        assert seen == [(1.0, 0, 4)]

    def test_login_throttle_api_failed_logins_block_the_route(
        self, db: FakeDb, throttle: ModuleType, route: str, login_delays: list[float]
    ) -> None:
        """10 failed logins from an IP (10 different emails): the route answers 429 from
        that IP only."""
        token = _valid_token(db, route)
        app = _app()
        for index in range(10):
            _login(_client(app, _IP_A), f"ghost{index}.marker@example.test", _WRONG)

        refused = _token_request(_client(app, _IP_A), route, token)
        allowed = _token_request(_client(app, _IP_B), route, token)

        assert (refused.status_code, refused.json()) == (429, _TOO_MANY)
        assert allowed.status_code == _SUCCESS_STATUS[route]

    def test_login_throttle_api_route_bucket_runs_before_the_throttle(
        self, db: FakeDb, throttle: ModuleType, route: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        token = _valid_token(db, route)
        _lock_ip(db, throttle)
        monkeypatch.setitem(server._RATE_LIMITS, _BUCKET_KEYS[route], (0.001, 1))
        client = _client(_app(), _IP_A)
        first = _token_request(client, route, token, clear_buckets=False)
        start = len(db.calls)

        second = _token_request(client, route, token, clear_buckets=False)

        assert (first.status_code, first.json()) == (429, _TOO_MANY)
        assert (second.status_code, second.json()) == (429, _RATE_LIMITED)
        assert db.calls[start:] == []


@pytest.mark.parametrize("route", ["reset-confirm", "invitation-accept"])
def test_login_throttle_api_policy_failure_releases_the_reservation(
    db: FakeDb, throttle: ModuleType, route: str, login_delays: list[float]
) -> None:
    """A 422 means the token was valid: the failure is released and the link stays."""
    token = _valid_token(db, route)
    _seed_ip(db, throttle, failures=5)

    response = _token_request(_client(_app(), _IP_A), route, token, _SHORT)

    assert response.status_code == 422
    row = _ip_row(db, throttle)
    assert row is not None
    assert row["failures"] == 5
    assert _still_usable(db, route, token)


def test_login_throttle_api_token_routes_share_one_counter(
    db: FakeDb, throttle: ModuleType, login_delays: list[float]
) -> None:
    """Six unusable links over the three routes: one IP row, one delay sequence."""
    client = _client(_app(), _IP_A)

    for route in _TOKEN_ROUTES:
        for token in (_WELL_FORMED_UNKNOWN, "short"):
            _token_request(client, route, token)

    row = _ip_row(db, throttle)
    assert row is not None
    assert row["failures"] == 6
    assert len(db.throttle) == 1
    assert login_delays == [1.0, 2.0, 4.0]


def test_login_throttle_api_unusable_links_block_the_login(
    db: FakeDb, throttle: ModuleType, login_delays: list[float]
) -> None:
    """10 unusable links from an IP, over all three routes: a login from that IP fails
    with the generic 401 even with the right password; another IP logs in."""
    _account(db)
    app = _app()
    client = _client(app, _IP_A)
    for route, count in (("reset-confirm", 4), ("invitation-details", 3), ("invitation-accept", 3)):
        for _ in range(count):
            _token_request(client, route, _WELL_FORMED_UNKNOWN)

    refused = _login(_client(app, _IP_A), _EMAIL, _PASSWORD)
    allowed = _login(_client(app, _IP_B), _EMAIL, _PASSWORD)

    assert _locked(_ip_row(db, throttle))
    assert (refused.status_code, refused.json()) == (401, _LOGIN_FAILED)
    assert _session_cookies(refused) == []
    assert allowed.status_code == 204


# ---------------------------------------------------------------------------
# 3. The password reset request
# ---------------------------------------------------------------------------


class TestResetRequest:
    """Locked IPs get 429 before anything is queued; the request never counts."""

    def test_login_throttle_api_reset_request_from_a_locked_ip_queues_nothing(
        self, db: FakeDb, throttle: ModuleType
    ) -> None:
        _account(db, _RESET_EMAIL)
        _lock_ip(db, throttle)
        start = len(db.calls)

        response = _reset_request(_client(_app(), _IP_A), _RESET_EMAIL)

        assert (response.status_code, response.json()) == (429, _TOO_MANY)
        assert db.outbox == []
        assert db.tokens == {}
        assert db.audit == []
        assert _lookups_since(db, start) == []

    def test_login_throttle_api_reset_request_at_the_limit_is_429(
        self, db: FakeDb, throttle: ModuleType
    ) -> None:
        _account(db, _RESET_EMAIL)
        _seed_ip(db, throttle, failures=10, window_started_at=_now() - timedelta(minutes=1))

        response = _reset_request(_client(_app(), _IP_A), _RESET_EMAIL)

        assert (response.status_code, response.json()) == (429, _TOO_MANY)
        assert db.outbox == []

    def test_login_throttle_api_reset_request_waits_out_the_ip_delay(
        self, db: FakeDb, throttle: ModuleType, login_delays: list[float]
    ) -> None:
        _account(db, _RESET_EMAIL)
        _seed_ip(db, throttle, failures=4)

        response = _reset_request(_client(_app(), _IP_A), _RESET_EMAIL)

        assert response.status_code == 202
        assert login_delays == [2.0]
        assert len(db.reset_links()) == 1
        row = _ip_row(db, throttle)
        assert row is not None
        assert row["failures"] == 4

    def test_login_throttle_api_reset_requests_never_count(
        self, db: FakeDb, throttle: ModuleType, login_delays: list[float]
    ) -> None:
        _account(db, _RESET_EMAIL)
        client = _client(_app(), _IP_A)

        statuses = [_reset_request(client, email).status_code for email in [_RESET_EMAIL] * 12]

        assert statuses == [202] * 12
        assert login_delays == []
        row = _ip_row(db, throttle)
        assert row is None or row["failures"] == 0


# ---------------------------------------------------------------------------
# 4. The client IP behind the trusted proxy, and restarts
# ---------------------------------------------------------------------------


def test_login_throttle_api_counts_the_forwarded_client_not_the_proxy(
    db: FakeDb, throttle: ModuleType, login_delays: list[float]
) -> None:
    """Through the trusted proxy, failures count per X-Forwarded-For client."""
    _account(db)
    config = AppConfig.model_validate(
        {"server": {"public_url": _PUBLIC_URL, "trusted_proxies": [_PROXY_IP]}}
    )
    app = create_app(agent=MagicMock(), config=config)
    client = TestClient(
        app,
        base_url="http://admino.example.ch",
        client=(_PROXY_IP, 50000),
        follow_redirects=False,
    )

    def through_proxy(browser: str, email: str, password: str) -> httpx.Response:
        headers = {"X-Forwarded-For": browser, "X-Forwarded-Proto": "https"}
        return _login(client, email, password, headers=headers)

    for index in range(10):
        through_proxy(_CLIENT_A, f"ghost{index}.marker@example.test", _WRONG)

    assert _locked(_ip_row(db, throttle, _CLIENT_A))
    assert _ip_row(db, throttle, _PROXY_IP) is None
    assert through_proxy(_CLIENT_B, _EMAIL, _PASSWORD).status_code == 204
    assert through_proxy(_CLIENT_A, _EMAIL, _PASSWORD).status_code == 401
    assert _lockouts(db) == [("system", None, None, _CLIENT_A, _IP_LOCK)]


def test_login_throttle_api_lock_survives_an_app_restart(
    db: FakeDb, login_delays: list[float]
) -> None:
    """A new app (fresh process state, empty buckets) on the same database is still
    locked: the account from every IP, and the IP on the token routes."""
    _account(db)
    token = _valid_token(db, "reset-confirm")
    first_app = _app()
    for _ in range(10):
        _login(_client(first_app, _IP_A), _EMAIL, _WRONG)

    restarted = _app()
    server._rate_buckets.clear()

    assert _login(_client(restarted, _IP_A), _EMAIL, _PASSWORD).status_code == 401
    assert _login(_client(restarted, _IP_B), _EMAIL, _PASSWORD).status_code == 401
    refused = _token_request(_client(restarted, _IP_A), "reset-confirm", token)
    assert (refused.status_code, refused.json()) == (429, _TOO_MANY)
    assert _still_usable(db, "reset-confirm", token)
