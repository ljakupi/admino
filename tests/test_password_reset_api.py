"""HTTP-layer spec for self-service password reset (GH-151).

The FastAPI app from ``create_app()`` runs against the in-memory database of
tests/db_fakes.py (what ``admino.database.get_pool`` returns) with
a fake config whose ``server.public_url`` is ``https://admino.example.ch``. The
real ``admino.password_reset``, ``admino.sessions``, ``admino.email_outbox``
and ``admino.audit_events`` code runs; only Argon2 is replaced by a fast fake.

What these tests pin down:
- ``POST /api/auth/password-reset {email}`` answers 202 with an empty body and
  the same headers for every email (eligible, unknown, invited, deactivated,
  deleted, deactivated org, org pending deletion); only an eligible account
  gets a token row and a queued email. The service runs as a background task
  after the response has started, with the configured public URL (never the
  request's Host or X-Forwarded-Host) and the client IP. A failure in that task
  still answers 202 and logs the exception class name only.
- ``POST /api/auth/password-reset/confirm {token, new_password}``: 204 with an
  empty body, the ``admino_session`` cookie deleted, the password changed and
  every session row of the user deleted (other devices are logged out at once).
  An unknown, malformed, expired, used or superseded token, or an account that
  may no longer log in → 400 ``{"detail": "This reset link is invalid or has
  expired."}`` and nothing changes. A policy failure → 422 ``{"detail": <policy
  message>, "reason": <reason>}`` and the link stays usable. An audit failure →
  500 and nothing changes.
- Both routes are public (no ``require_session``), rate-limited per client IP
  (``ip:<host>``; one IP can't throttle another), refused as cross-origin
  before any database call, and validate their bodies (422) without echoing
  input.
- No email, token, password or link in any log line, audit row or response.

All database calls are faked. No network, no real PostgreSQL, no SMTP.

Security notes:
- No user enumeration: identical 202 responses, and the response doesn't wait
  for the account's work (the service runs after the response starts).
- Reset-link poisoning: the link base is ``server.public_url`` only.
- A reset logs out every device, the resetting browser included.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from admino import models, passwords, server
from admino.server import create_app
from tests.password_reset_fakes import (
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
    from collections.abc import Callable

    import httpx
    from fastapi import FastAPI
    from fastapi.dependencies.models import Dependant

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_REQUEST = "/api/auth/password-reset"
_CONFIRM = "/api/auth/password-reset/confirm"
_COOKIE = "admino_session"
_EMAIL = "Api.Reset.Marker@Example.test"
_NEW_PASSWORD = "violet-Anchor-93-quartz"
_OTHER_PASSWORD = "Tidal-Lantern-58-cobalt"
_IP_A = "203.0.113.5"
_IP_B = "198.51.100.23"
_INVALID = {"detail": "This reset link is invalid or has expired."}
_CSRF_REFUSED = {"detail": "Cross-origin request refused"}
_RATE_LIMITED = {"detail": "Rate limit exceeded"}
_DELETED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_WELL_FORMED_UNKNOWN = "Q" * 21 + "-" + "z" * 20 + "_"


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
def _fast_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace Argon2 with a fast fake (the real hashing is covered by test_passwords)."""
    monkeypatch.setattr("admino.passwords.hash_password", fake_hash)


@pytest.fixture(autouse=True)
def _generous_reset_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Functional tests aren't about rate limits: give both reset routes a large bucket.
    The rate-limit tests below set their own small buckets."""
    monkeypatch.setitem(server._RATE_LIMITS, _REQUEST, (1000.0, 1000))
    monkeypatch.setitem(server._RATE_LIMITS, _CONFIRM, (1000.0, 1000))


def _config(public_url: str = PUBLIC_URL) -> MagicMock:
    """A minimal config with the public URL reset links are built from."""
    config = MagicMock()
    del config.auth
    config.limits.max_message_length = 4000
    config.server.host = "127.0.0.1"
    config.server.port = 8000
    config.server.cookie_secure = True
    config.server.public_url = public_url
    config.llm.provider = "infomaniak"
    config.llm.active_model_name = "test-model"
    return config


def _app(public_url: str = PUBLIC_URL) -> FastAPI:
    """create_app with a stub agent and the fake config (no lifespan runs under TestClient)."""
    return create_app(agent=MagicMock(), config=_config(public_url))  # type: ignore[arg-type]


def _client(app: FastAPI, ip: str = _IP_A, **kwargs: Any) -> TestClient:
    """A client whose peer address is ``ip``; redirects are not followed."""
    return TestClient(app, client=(ip, 50000), follow_redirects=False, **kwargs)


def _request_reset(client: TestClient, email: str, **kwargs: Any) -> httpx.Response:
    return client.post(_REQUEST, json={"email": email}, **kwargs)


def _confirm(
    client: TestClient, token: str, new_password: str = _NEW_PASSWORD, **kwargs: Any
) -> httpx.Response:
    return client.post(_CONFIRM, json={"token": token, "new_password": new_password}, **kwargs)


def _issue(db: FakeDb, app: FastAPI, email: str = _EMAIL) -> str:
    """Request a reset over HTTP and return the token from the queued email."""
    response = _request_reset(_client(app), email)
    assert response.status_code == 202
    return db.issued_token()


def _cookie(token: str) -> dict[str, str]:
    return {"Cookie": f"{_COOKIE}={token}"}


def _me(app: FastAPI, session: str) -> int:
    """Status of GET /api/auth/me with a session cookie."""
    return _client(app).get("/api/auth/me", headers=_cookie(session)).status_code


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


def _comparable(response: httpx.Response) -> tuple[int, bytes, list[tuple[str, str]]]:
    """Status, body and every header except Date."""
    headers = sorted(
        (key.lower(), value) for key, value in response.headers.multi_items() if key != "date"
    )
    return response.status_code, response.content, headers


def _depends_on(dependant: Dependant, target: Callable[..., Any]) -> bool:
    """True when the dependency tree below ``dependant`` contains ``target``."""
    return any(dep.call is target or _depends_on(dep, target) for dep in dependant.dependencies)


def _route(app: FastAPI, method: str, path: str) -> APIRoute:
    matches = [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and route.path == path and method in route.methods
    ]
    assert len(matches) == 1, f"{method} {path} is not registered"
    return matches[0]


def _policy_body(reason: str) -> dict[str, str]:
    """The 422 body of a policy failure."""
    return {"detail": str(passwords.PasswordPolicyError(reason)), "reason": reason}  # type: ignore[arg-type]


# Every account that must get no token and no email ("unknown": none at all).
_NOT_SENT: dict[str, dict[str, Any] | None] = {
    "unknown": None,
    "invited": {"status": "invited", "password_hash": None},
    "deactivated": {"status": "deactivated"},
    "deleted": {"deleted_at": _DELETED_AT},
    "org-deactivated": {"org_status": "deactivated"},
    "org-pending-deletion": {"org_status": "pending_deletion"},
}


# ---------------------------------------------------------------------------
# 1. Both routes exist and are public
# ---------------------------------------------------------------------------


class TestResetRoutesArePublic:
    """Registered, outside require_session, usable without a cookie."""

    @pytest.mark.parametrize("path", [_REQUEST, _CONFIRM])
    def test_password_reset_api_route_is_registered(self, path: str) -> None:
        _route(_app(), "POST", path)

    @pytest.mark.parametrize("path", [_REQUEST, _CONFIRM])
    def test_password_reset_api_route_does_not_require_a_session(self, path: str) -> None:
        """No server.require_session anywhere in the route's dependency tree."""
        route = _route(_app(), "POST", path)

        assert not _depends_on(route.dependant, server.require_session)

    def test_password_reset_api_flow_works_without_any_cookie(self, db: FakeDb) -> None:
        """Request and confirm both succeed logged out."""
        db.add_account(email=_EMAIL)
        app = _app()

        token = _issue(db, app)
        response = _confirm(_client(app), token)

        assert response.status_code == 204

    def test_password_reset_api_confirm_ignores_a_bad_session_cookie(self, db: FakeDb) -> None:
        """A stale or garbage session cookie doesn't turn the public confirm into a 401."""
        db.add_account(email=_EMAIL)
        app = _app()
        token = _issue(db, app)

        response = _confirm(_client(app), token, headers=_cookie("not-a-session-token"))

        assert response.status_code == 204


# ---------------------------------------------------------------------------
# 2. POST /api/auth/password-reset
# ---------------------------------------------------------------------------


class TestRequestEndpoint:
    """Always 202 with an empty body; only an eligible account gets an email."""

    def test_password_reset_api_request_returns_202_with_empty_body(self, db: FakeDb) -> None:
        db.add_account(email=_EMAIL)

        response = _request_reset(_client(_app()), _EMAIL)

        assert response.status_code == 202
        assert response.content == b""

    def test_password_reset_api_request_responses_are_identical(self, db: FakeDb) -> None:
        """Eligible, unknown and every ineligible account: same status, body and headers
        (apart from Date)."""
        app = _app()
        emails = {"eligible": db.add_account(email="eligible.one@example.test")}
        responses = [_request_reset(_client(app, "192.0.2.1"), "eligible.one@example.test")]
        for index, (cause, fields) in enumerate(_NOT_SENT.items(), start=2):
            email = f"{cause}.person@example.test"
            if fields is not None:
                emails[cause] = db.add_account(email=email, **fields)
            responses.append(_request_reset(_client(app, f"192.0.2.{index}"), email))

        assert {r.status_code for r in responses} == {202}
        assert len({json.dumps(_comparable(r)[2]) for r in responses}) == 1
        assert {r.content for r in responses} == {b""}

    def test_password_reset_api_request_only_eligible_account_gets_token_and_email(
        self, db: FakeDb
    ) -> None:
        """One token row and one queued email, both for the eligible account."""
        app = _app()
        eligible = db.add_account(email="eligible.one@example.test")
        _request_reset(_client(app, "192.0.2.1"), "eligible.one@example.test")
        for index, (cause, fields) in enumerate(_NOT_SENT.items(), start=2):
            email = f"{cause}.person@example.test"
            if fields is not None:
                db.add_account(email=email, **fields)
            _request_reset(_client(app, f"192.0.2.{index}"), email)

        assert list(db.tokens) == [eligible]
        assert [row["user_id"] for row in db.outbox] == [eligible]
        assert db.outbox[0]["template_key"] == "password_reset"

    def test_password_reset_api_request_email_is_case_insensitive(self, db: FakeDb) -> None:
        db.add_account(email="Mixed.Case@Example.test")

        _request_reset(_client(_app()), "mixed.case@EXAMPLE.test")

        assert len(db.reset_links()) == 1

    def test_password_reset_api_request_super_admin_gets_an_email(self, db: FakeDb) -> None:
        db.add_account(email=_EMAIL, kind="super_admin", role=None, org_status=None)

        _request_reset(_client(_app()), _EMAIL)

        assert len(db.reset_links()) == 1

    def test_password_reset_api_link_comes_from_the_configured_public_url(self, db: FakeDb) -> None:
        """A hostile Host / X-Forwarded-Host doesn't change the link (reset-link poisoning)."""
        db.add_account(email=_EMAIL)

        response = _request_reset(
            _client(_app()),
            _EMAIL,
            headers={
                "Host": "evil.example",
                "X-Forwarded-Host": "evil.example",
                "X-Forwarded-Proto": "http",
                "Forwarded": "host=evil.example;proto=http",
            },
        )

        assert response.status_code == 202
        link = db.reset_links()[0]
        assert link.startswith(LINK_PREFIX)
        assert TOKEN_RE.fullmatch(link[len(LINK_PREFIX) :]) is not None
        assert "evil" not in link

    def test_password_reset_api_link_follows_the_config(self, db: FakeDb) -> None:
        """Another configured public URL is the link base."""
        db.add_account(email=_EMAIL)

        _request_reset(_client(_app(public_url="https://reset.example.org")), _EMAIL)

        assert db.reset_links()[0].startswith("https://reset.example.org/reset-password#token=")

    def test_password_reset_api_request_calls_the_service_with_config_and_ip(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """password_reset.request_reset(get_pool(), email=<body email>,
        public_url=<server.public_url>, ip=<client host>)."""
        spy = AsyncMock(return_value=None)
        monkeypatch.setattr("admino.password_reset.request_reset", spy)

        response = _request_reset(_client(_app(), _IP_B), "Someone@Example.test")

        assert response.status_code == 202
        spy.assert_awaited_once()
        call = spy.await_args
        assert call is not None
        pool = call.args[0] if call.args else call.kwargs["pool"]
        assert pool is db.pool
        assert {key: call.kwargs[key] for key in ("email", "public_url", "ip")} == {
            "email": "Someone@Example.test",
            "public_url": PUBLIC_URL,
            "ip": _IP_B,
        }

    async def test_password_reset_api_request_runs_after_the_response_starts(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The 202 is on its way before the service does any work, so the response time
        doesn't depend on whether the account exists (a background task)."""
        sent: list[dict[str, Any]] = []
        seen_when_called: list[list[str]] = []

        async def service(*_args: Any, **_kwargs: Any) -> None:
            seen_when_called.append([message["type"] for message in sent])

        monkeypatch.setattr("admino.password_reset.request_reset", service)
        body = json.dumps({"email": _EMAIL}).encode()
        scope: dict[str, Any] = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": _REQUEST,
            "raw_path": _REQUEST.encode(),
            "root_path": "",
            "query_string": b"",
            "headers": [
                (b"host", b"testserver"),
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
            "client": (_IP_A, 50000),
            "server": ("testserver", 80),
        }
        delivered = False
        never = asyncio.Event()

        async def receive() -> dict[str, Any]:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            await never.wait()
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        await asyncio.wait_for(_app()(scope, receive, send), timeout=10)

        assert len(seen_when_called) == 1
        assert "http.response.start" in seen_when_called[0]
        assert sent[0]["type"] == "http.response.start"
        assert sent[0]["status"] == 202

    def test_password_reset_api_request_service_failure_still_answers_202(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """An exception in the background task is caught: 202, and one log line naming the
        exception class only (no message text, no traceback, no email)."""
        caplog.set_level(logging.DEBUG)
        monkeypatch.setattr(
            "admino.password_reset.request_reset",
            AsyncMock(side_effect=RuntimeError(f"boom-detail {_EMAIL}")),
        )

        response = _request_reset(_client(_app()), _EMAIL)

        assert response.status_code == 202
        assert response.content == b""
        assert any("RuntimeError" in record.getMessage() for record in caplog.records)
        assert "boom-detail" not in caplog.text
        assert "api.reset.marker" not in caplog.text.casefold()
        assert all(record.exc_info is None for record in caplog.records)

    def test_password_reset_api_request_audit_failure_rolls_back_and_answers_202(
        self, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A failed audit record: no token and no email remain, the caller still gets 202,
        and the log names AuditRecordError only."""
        caplog.set_level(logging.DEBUG)
        db.add_account(email=_EMAIL)
        db.fail_audit = True

        response = _request_reset(_client(_app()), _EMAIL)

        assert response.status_code == 202
        assert db.tokens == {}
        assert db.outbox == []
        assert any("AuditRecordError" in record.getMessage() for record in caplog.records)
        assert "api.reset.marker" not in caplog.text.casefold()

    def test_password_reset_api_request_is_audited(self, db: FakeDb) -> None:
        """One password_reset.request row per request, eligible or not."""
        user_id = db.add_account(email=_EMAIL)
        app = _app()

        _request_reset(_client(app), _EMAIL)
        _request_reset(_client(app), "nobody@example.test")

        rows = db.audit_rows("password_reset.request")
        assert [(row["actor_user_id"], row["metadata"]) for row in rows] == [
            (user_id, {"email_sent": True}),
            (None, {"email_sent": False}),
        ]
        assert rows[0]["org_id"] == ORG_ID
        assert {row["ip"] for row in rows} == {_IP_A}


# ---------------------------------------------------------------------------
# 3. POST /api/auth/password-reset/confirm
# ---------------------------------------------------------------------------


class TestConfirmSuccess:
    """204, cookie cleared, new password, every session row deleted, audited."""

    def test_password_reset_api_confirm_returns_204_with_empty_body(self, db: FakeDb) -> None:
        user_id = db.add_account(email=_EMAIL)
        app = _app()
        token = _issue(db, app)

        response = _confirm(_client(app), token)

        assert response.status_code == 204
        assert response.content == b""
        assert db.users[user_id]["password_hash"] == fake_hash(_NEW_PASSWORD)

    def test_password_reset_api_confirm_deletes_the_session_cookie(self, db: FakeDb) -> None:
        """Set-Cookie: admino_session=""; Max-Age=0; Path=/."""
        db.add_account(email=_EMAIL)
        app = _app()
        token = _issue(db, app)

        response = _confirm(_client(app), token)

        value, attributes = _session_set_cookie(response)
        assert value in {"", '""'}
        assert attributes.get("max-age") == "0"
        assert attributes.get("path") == "/"

    def test_password_reset_api_confirm_logs_out_every_device(self, db: FakeDb) -> None:
        """Every session of the user stops resolving at once; another user's session stays."""
        user_id = db.add_account(email=_EMAIL)
        bystander = db.add_account(email="bystander@example.test")
        devices = [db.open_session(user_id) for _ in range(3)]
        other = db.open_session(bystander)
        app = _app()
        assert {_me(app, session) for session in devices} == {200}
        token = _issue(db, app)

        _confirm(_client(app), token)

        assert [_me(app, session) for session in devices] == [401, 401, 401]
        assert _me(app, other) == 200

    def test_password_reset_api_confirm_deletes_the_callers_own_session(self, db: FakeDb) -> None:
        """The browser that resets is logged out too: its session row is gone."""
        user_id = db.add_account(email=_EMAIL)
        session = db.open_session(user_id)
        app = _app()
        token = _issue(db, app)

        response = _confirm(_client(app), token, headers=_cookie(session))

        assert response.status_code == 204
        assert db.session_revoked(session)

    def test_password_reset_api_confirm_is_audited_with_the_revoked_count(self, db: FakeDb) -> None:
        user_id = db.add_account(email=_EMAIL)
        db.open_session(user_id)
        db.open_session(user_id)
        app = _app()
        token = _issue(db, app)

        _confirm(_client(app, _IP_B), token)

        rows = db.audit_rows("password_reset.complete")
        assert len(rows) == 1
        assert (rows[0]["actor_kind"], rows[0]["actor_user_id"], rows[0]["org_id"]) == (
            "member",
            user_id,
            ORG_ID,
        )
        assert (rows[0]["target_type"], rows[0]["target_ids"]) == ("user", [str(user_id)])
        assert rows[0]["ip"] == _IP_B
        assert rows[0]["metadata"] == {"sessions_revoked": 2}

    def test_password_reset_api_confirm_one_second_before_expiry_works(self, db: FakeDb) -> None:
        user_id = db.add_account(email=_EMAIL)
        app = _app()
        token = _issue(db, app)
        db.tokens[user_id]["expires_at"] = datetime.now(UTC) + timedelta(seconds=1)

        assert _confirm(_client(app), token).status_code == 204

    @pytest.mark.parametrize(
        "password",
        [
            pytest.param("Kq7#vX9!pL2m", id="12-chars"),
            pytest.param("Kq7#vX9!pL2m" * 10 + "Kq7#vX9!", id="128-chars"),
        ],
    )
    def test_password_reset_api_confirm_policy_bounds_are_accepted(
        self, db: FakeDb, password: str
    ) -> None:
        user_id = db.add_account(email=_EMAIL)
        app = _app()
        token = _issue(db, app)

        response = _confirm(_client(app), token, password)

        assert response.status_code == 204
        assert db.users[user_id]["password_hash"] == fake_hash(password)


def _unchanged(db: FakeDb, user_id: uuid.UUID, token: str, session: str) -> None:
    """Nothing was written: old password, token still stored, session row still there."""
    assert db.users[user_id]["password_hash"] == "fake$initial"
    assert db.tokens[user_id]["token_hash"] == sha256(token)
    assert not db.session_revoked(session)
    assert db.audit_rows("password_reset.complete") == []


class TestConfirmRefused:
    """400 with one fixed body; nothing changes."""

    def test_password_reset_api_confirm_unknown_token_is_400(self, db: FakeDb) -> None:
        user_id = db.add_account(email=_EMAIL)
        session = db.open_session(user_id)

        response = _confirm(_client(_app()), _WELL_FORMED_UNKNOWN)

        assert response.status_code == 400
        assert response.json() == _INVALID
        assert db.users[user_id]["password_hash"] == "fake$initial"
        assert not db.session_revoked(session)

    @pytest.mark.parametrize(
        "token",
        [
            pytest.param("not-a-token", id="short"),
            pytest.param("A" * 128, id="128-chars"),
            pytest.param("A" * 42 + "=", id="padding"),
            pytest.param("A" * 42 + chr(0xE9), id="non-ascii"),
        ],
    )
    def test_password_reset_api_confirm_malformed_token_is_400_without_query(
        self, db: FakeDb, token: str
    ) -> None:
        """A token that passes body validation but can't exist: 400 and no token or account
        lookup. GH-157: only the IP throttle's own login_throttle statements run (the
        malformed link counts as a failed attempt)."""
        response = _confirm(_client(_app()), token)

        assert response.status_code == 400
        assert response.json() == _INVALID
        assert [
            call.normalized
            for call in db.calls
            if not re.search(r"\blogin_throttle\b", call.normalized)
        ] == []

    @pytest.mark.parametrize("seconds_ago", [1, 3600])
    def test_password_reset_api_confirm_expired_token_is_400(
        self, db: FakeDb, seconds_ago: int
    ) -> None:
        user_id = db.add_account(email=_EMAIL)
        session = db.open_session(user_id)
        app = _app()
        token = _issue(db, app)
        db.tokens[user_id]["expires_at"] = datetime.now(UTC) - timedelta(seconds=seconds_ago)

        response = _confirm(_client(app), token)

        assert response.status_code == 400
        assert response.json() == _INVALID
        _unchanged(db, user_id, token, session)

    def test_password_reset_api_confirm_is_single_use(self, db: FakeDb) -> None:
        """A second confirm with the same token is 400 and doesn't change the password
        again or log out the new session."""
        user_id = db.add_account(email=_EMAIL)
        app = _app()
        token = _issue(db, app)
        assert _confirm(_client(app), token).status_code == 204
        new_session = db.open_session(user_id)

        response = _confirm(_client(app), token, _OTHER_PASSWORD)

        assert response.status_code == 400
        assert response.json() == _INVALID
        assert db.users[user_id]["password_hash"] == fake_hash(_NEW_PASSWORD)
        assert _me(app, new_session) == 200

    def test_password_reset_api_newer_request_invalidates_older_link(self, db: FakeDb) -> None:
        """After a second request the first link is 400 and the second one works."""
        user_id = db.add_account(email=_EMAIL)
        app = _app()
        first = _issue(db, app)
        second = _issue(db, app)

        refused = _confirm(_client(app), first)
        assert refused.status_code == 400
        assert db.users[user_id]["password_hash"] == "fake$initial"

        assert _confirm(_client(app), second).status_code == 204
        assert db.users[user_id]["password_hash"] == fake_hash(_NEW_PASSWORD)

    @pytest.mark.parametrize(
        "change",
        [
            pytest.param({"status": "deactivated"}, id="deactivated"),
            pytest.param({"deleted_at": _DELETED_AT}, id="deleted"),
            pytest.param({"org_status": "deactivated"}, id="org-deactivated"),
            pytest.param({"org_status": "pending_deletion"}, id="org-pending-deletion"),
        ],
    )
    def test_password_reset_api_confirm_after_deactivation_is_400(
        self, db: FakeDb, change: dict[str, Any]
    ) -> None:
        """An account that may no longer log in can't use a link it requested earlier."""
        user_id = db.add_account(email=_EMAIL)
        session = db.open_session(user_id)
        app = _app()
        token = _issue(db, app)
        db.users[user_id].update(change)

        response = _confirm(_client(app), token)

        assert response.status_code == 400
        assert response.json() == _INVALID
        _unchanged(db, user_id, token, session)

    def test_password_reset_api_confirm_audit_failure_is_500_and_changes_nothing(
        self, db: FakeDb
    ) -> None:
        """Fail closed: the error propagates (500) and the transaction rolls back."""
        user_id = db.add_account(email=_EMAIL)
        session = db.open_session(user_id)
        app = _app()
        token = _issue(db, app)
        db.fail_audit = True

        response = _confirm(_client(app, raise_server_exceptions=False), token)

        assert response.status_code == 500
        assert token not in response.text
        assert _NEW_PASSWORD not in response.text
        _unchanged(db, user_id, token, session)


_POLICY_FAILURES: list[Any] = [
    pytest.param("Kq7#vX9!pL2", "too_short", id="11-chars"),
    pytest.param("Kq7#vX9!pL2m" * 10 + "Kq7#vX9!p", "too_long", id="129-chars"),
    pytest.param("Kq7#vX9!" * 128, "too_long", id="1024-chars"),
    pytest.param("Qwerty123456", "common", id="common"),
    pytest.param(_EMAIL.lower(), "equals_email", id="equals-email"),
]


class TestConfirmPolicy:
    """422 with the policy's message and reason; the link stays usable."""

    @pytest.mark.parametrize(("password", "reason"), _POLICY_FAILURES)
    def test_password_reset_api_confirm_policy_failure_is_422_with_reason(
        self, db: FakeDb, password: str, reason: str
    ) -> None:
        """{"detail": <policy message>, "reason": <reason>}: nothing else, no echo."""
        db.add_account(email=_EMAIL)
        app = _app()
        token = _issue(db, app)

        response = _confirm(_client(app), token, password)

        assert response.status_code == 422
        assert response.json() == _policy_body(reason)
        assert password.casefold() not in response.text.casefold()
        assert token not in response.text

    @pytest.mark.parametrize(("password", "reason"), _POLICY_FAILURES)
    def test_password_reset_api_confirm_policy_failure_changes_nothing(
        self, db: FakeDb, password: str, reason: str
    ) -> None:
        user_id = db.add_account(email=_EMAIL)
        session = db.open_session(user_id)
        app = _app()
        token = _issue(db, app)

        _confirm(_client(app), token, password)

        _unchanged(db, user_id, token, session)

    def test_password_reset_api_link_still_works_after_a_policy_failure(self, db: FakeDb) -> None:
        user_id = db.add_account(email=_EMAIL)
        app = _app()
        token = _issue(db, app)
        assert _confirm(_client(app), token, "short-one").status_code == 422

        response = _confirm(_client(app), token)

        assert response.status_code == 204
        assert db.users[user_id]["password_hash"] == fake_hash(_NEW_PASSWORD)

    def test_password_reset_api_invalid_link_is_reported_before_the_policy(
        self, db: FakeDb
    ) -> None:
        """A bad token with a too-short password is a 400, not a policy 422."""
        response = _confirm(_client(_app()), _WELL_FORMED_UNKNOWN, "short")

        assert response.status_code == 400
        assert response.json() == _INVALID


# ---------------------------------------------------------------------------
# 4. Body validation
# ---------------------------------------------------------------------------

_MARKER_TOKEN = "TOKENmarker" + "x" * 32
_MARKER_PASSWORD = "Zx7SECRETmarkerPw"

_BAD_REQUEST_BODIES: list[Any] = [
    pytest.param({}, id="empty"),
    pytest.param({"email": "ab"}, id="email-too-short"),
    pytest.param({"email": "a" * 250 + "@x.ch"}, id="email-too-long"),
    pytest.param({"email": 12345}, id="email-not-a-string"),
    pytest.param({"email": None}, id="email-null"),
    pytest.param({"email": ["echo.marker@example.test"]}, id="email-list"),
    pytest.param({"email": "echo.marker@example.test", "role": "org_admin"}, id="extra-field"),
    pytest.param({"mail": "echo.marker@example.test"}, id="wrong-field"),
]

_BAD_CONFIRM_BODIES: list[Any] = [
    pytest.param({}, id="empty"),
    pytest.param({"token": _MARKER_TOKEN}, id="no-password"),
    pytest.param({"new_password": _MARKER_PASSWORD}, id="no-token"),
    pytest.param({"token": "", "new_password": _MARKER_PASSWORD}, id="empty-token"),
    pytest.param({"token": _MARKER_TOKEN, "new_password": ""}, id="empty-password"),
    pytest.param(
        {"token": "TOKENmarker" * 12, "new_password": _MARKER_PASSWORD}, id="token-too-long"
    ),
    pytest.param(
        {"token": _MARKER_TOKEN, "new_password": _MARKER_PASSWORD * 61}, id="password-too-long"
    ),
    pytest.param({"token": 12345, "new_password": _MARKER_PASSWORD}, id="token-not-a-string"),
    pytest.param({"token": _MARKER_TOKEN, "new_password": 1234567890123}, id="password-int"),
    pytest.param(
        {"token": _MARKER_TOKEN, "new_password": _MARKER_PASSWORD, "email": "x@example.test"},
        id="extra-field",
    ),
]


class TestValidation:
    """Malformed bodies: 422, a list of errors, no input echoed, no database call."""

    @pytest.mark.parametrize("body", _BAD_REQUEST_BODIES)
    def test_password_reset_api_request_bad_body_is_422_without_echo(
        self, db: FakeDb, body: dict[str, Any]
    ) -> None:
        response = _client(_app()).post(_REQUEST, json=body)

        assert response.status_code == 422
        assert isinstance(response.json()["detail"], list)
        assert "echo.marker" not in response.text
        assert "a" * 40 not in response.text
        assert db.calls == []

    @pytest.mark.parametrize("body", _BAD_CONFIRM_BODIES)
    def test_password_reset_api_confirm_bad_body_is_422_without_echo(
        self, db: FakeDb, body: dict[str, Any]
    ) -> None:
        response = _client(_app()).post(_CONFIRM, json=body)

        assert response.status_code == 422
        assert isinstance(response.json()["detail"], list)
        assert "TOKENmarker" not in response.text
        assert "SECRETmarker" not in response.text
        assert db.calls == []

    @pytest.mark.parametrize("path", [_REQUEST, _CONFIRM])
    def test_password_reset_api_non_json_body_is_422(self, db: FakeDb, path: str) -> None:
        response = _client(_app()).post(
            path,
            content=b"token=" + _MARKER_TOKEN.encode() + b"&new_password=" + b"SECRETmarker",
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 422
        assert "TOKENmarker" not in response.text
        assert "SECRETmarker" not in response.text
        assert db.calls == []


class TestRequestModels:
    """PasswordResetRequest and PasswordResetConfirmRequest in admino.models."""

    @pytest.mark.parametrize("email", ["a@b", "x" * 250 + "@x.c"])
    def test_password_reset_api_request_model_email_bounds_accept(self, email: str) -> None:
        """3 to 254 characters."""
        assert models.PasswordResetRequest(email=email).email == email  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        "data",
        [
            pytest.param({"email": "ab"}, id="2-chars"),
            pytest.param({"email": "x" * 251 + "@x.c"}, id="255-chars"),
            pytest.param({"email": "a@b.ch", "extra": 1}, id="extra"),
        ],
    )
    def test_password_reset_api_request_model_refuses(self, data: dict[str, Any]) -> None:
        with pytest.raises(ValueError, match=r"."):
            models.PasswordResetRequest.model_validate(data)  # type: ignore[attr-defined]

    def test_password_reset_api_confirm_model_bounds_accept(self) -> None:
        """A 128-character token and a 1024-character password pass validation (the
        service and the policy decide)."""
        request = models.PasswordResetConfirmRequest(  # type: ignore[attr-defined]
            token="t" * 128, new_password="p" * 1024
        )

        assert request.token.get_secret_value() == "t" * 128
        assert request.new_password.get_secret_value() == "p" * 1024

    @pytest.mark.parametrize(
        "data",
        [
            pytest.param({"token": "", "new_password": "p"}, id="empty-token"),
            pytest.param({"token": "t" * 129, "new_password": "p"}, id="129-token"),
            pytest.param({"token": "t", "new_password": ""}, id="empty-password"),
            pytest.param({"token": "t", "new_password": "p" * 1025}, id="1025-password"),
            pytest.param({"token": "t", "new_password": "p", "email": "a@b.c"}, id="extra"),
        ],
    )
    def test_password_reset_api_confirm_model_refuses(self, data: dict[str, Any]) -> None:
        with pytest.raises(ValueError, match=r"."):
            models.PasswordResetConfirmRequest.model_validate(data)  # type: ignore[attr-defined]

    def test_password_reset_api_confirm_model_hides_token_and_password(self) -> None:
        """Both are SecretStr: repr() and str() show neither."""
        request = models.PasswordResetConfirmRequest(  # type: ignore[attr-defined]
            token=_MARKER_TOKEN, new_password=_MARKER_PASSWORD
        )

        for rendered in (repr(request), str(request)):
            assert "TOKENmarker" not in rendered
            assert "SECRETmarker" not in rendered


# ---------------------------------------------------------------------------
# 5. Rate limits per client IP
# ---------------------------------------------------------------------------


class TestRateLimits:
    """One bucket per (route, "ip:<host>"): one IP can't throttle another."""

    def test_password_reset_api_request_is_limited_per_ip(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """IP A gets 429 after its burst (and no more emails are queued); IP B still 202."""
        db.add_account(email=_EMAIL)
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _REQUEST, (0.001, 3))

        statuses_a = [_request_reset(_client(app, _IP_A), _EMAIL).status_code for _ in range(4)]
        outbox_after_a = len(db.outbox)
        status_b = _request_reset(_client(app, _IP_B), _EMAIL).status_code

        assert statuses_a == [202, 202, 202, 429]
        assert outbox_after_a == 3
        assert status_b == 202

    def test_password_reset_api_confirm_is_limited_per_ip(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _CONFIRM, (0.001, 2))

        statuses_a = [
            _confirm(_client(app, _IP_A), _WELL_FORMED_UNKNOWN).status_code for _ in range(3)
        ]
        status_b = _confirm(_client(app, _IP_B), _WELL_FORMED_UNKNOWN).status_code

        assert statuses_a == [400, 400, 429]
        assert status_b == 400

    @pytest.mark.parametrize("path", [_REQUEST, _CONFIRM])
    def test_password_reset_api_rate_limit_body(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, path: str
    ) -> None:
        """429 {"detail": "Rate limit exceeded"}."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, path, (0.001, 1))
        body = {"email": _EMAIL} if path == _REQUEST else {"token": "x", "new_password": "y"}
        client = _client(app)

        client.post(path, json=body)
        response = client.post(path, json=body)

        assert response.status_code == 429
        assert response.json() == _RATE_LIMITED

    @pytest.mark.parametrize("path", [_REQUEST, _CONFIRM])
    def test_password_reset_api_buckets_are_keyed_by_client_ip(self, db: FakeDb, path: str) -> None:
        app = _app()
        body = {"email": _EMAIL} if path == _REQUEST else {"token": "x", "new_password": "y"}

        _client(app, _IP_B).post(path, json=body)

        assert (path, f"ip:{_IP_B}") in server._rate_buckets

    def test_password_reset_api_throttled_confirm_consumes_nothing(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A 429 confirm with a valid token doesn't touch the token or the password."""
        user_id = db.add_account(email=_EMAIL)
        session = db.open_session(user_id)
        app = _app()
        token = _issue(db, app)
        monkeypatch.setitem(server._RATE_LIMITS, _CONFIRM, (0.001, 1))
        _confirm(_client(app, _IP_A), _WELL_FORMED_UNKNOWN)

        response = _confirm(_client(app, _IP_A), token)

        assert response.status_code == 429
        _unchanged(db, user_id, token, session)


# ---------------------------------------------------------------------------
# 6. CSRF
# ---------------------------------------------------------------------------

_CROSS_ORIGIN: list[Any] = [
    pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
    pytest.param({"Sec-Fetch-Site": "same-site"}, id="sfs-same-site"),
    pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
    pytest.param({"Origin": "null"}, id="origin-null"),
]


class TestCsrf:
    """Cross-origin POSTs are refused before anything else runs."""

    @pytest.mark.parametrize("headers", _CROSS_ORIGIN)
    @pytest.mark.parametrize("path", [_REQUEST, _CONFIRM])
    def test_password_reset_api_cross_origin_post_is_refused_before_any_query(
        self, db: FakeDb, headers: dict[str, str], path: str
    ) -> None:
        """The reset route exists (the refusal isn't just a missing route), and the
        cross-origin POST to it is a 403 with no database call."""
        db.add_account(email=_EMAIL)
        app = _app()
        _route(app, "POST", path)
        body = (
            {"email": _EMAIL}
            if path == _REQUEST
            else {"token": _WELL_FORMED_UNKNOWN, "new_password": _NEW_PASSWORD}
        )

        response = _client(app).post(path, json=body, headers=headers)

        assert response.status_code == 403
        assert response.json() == _CSRF_REFUSED
        assert db.calls == []

    def test_password_reset_api_cross_origin_confirm_changes_nothing(self, db: FakeDb) -> None:
        """A forged cross-site confirm with a valid token neither consumes it nor changes
        the password."""
        user_id = db.add_account(email=_EMAIL)
        session = db.open_session(user_id)
        app = _app()
        token = _issue(db, app)

        response = _confirm(_client(app), token, headers={"Sec-Fetch-Site": "cross-site"})

        assert response.status_code == 403
        _unchanged(db, user_id, token, session)

    def test_password_reset_api_same_origin_flow_passes(self, db: FakeDb) -> None:
        """What the PWA sends: Sec-Fetch-Site same-origin and a matching Origin."""
        db.add_account(email=_EMAIL)
        app = _app()
        headers = {"Sec-Fetch-Site": "same-origin", "Origin": "http://testserver"}

        requested = _request_reset(_client(app), _EMAIL, headers=headers)
        confirmed = _confirm(_client(app), db.issued_token(), headers=headers)

        assert (requested.status_code, confirmed.status_code) == (202, 204)


# ---------------------------------------------------------------------------
# 7. No email, token, password or link in logs, audit rows or responses
# ---------------------------------------------------------------------------


class TestNoContentLeak:
    """Content-free logs, audit rows and responses across the whole flow."""

    def test_password_reset_api_logs_nothing_sensitive(
        self, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        db.add_account(email=_EMAIL)
        db.add_account(email="Ghost.Marker@Example.test", status="deactivated")
        app = _app()

        _request_reset(_client(app), _EMAIL)
        _request_reset(_client(app), "nobody.marker@example.test")
        _request_reset(_client(app), "Ghost.Marker@Example.test")
        token = db.issued_token()
        _confirm(_client(app), token, "Qwerty123456")
        _confirm(_client(app), token)
        _confirm(_client(app), token, _OTHER_PASSWORD)
        _confirm(_client(app), "not-a-token")

        text = caplog.text.casefold()
        for marker in ("reset.marker", "ghost.marker", "nobody.marker", "@example.test"):
            assert marker not in text
        assert token not in caplog.text
        assert _NEW_PASSWORD.casefold() not in text
        assert _OTHER_PASSWORD.casefold() not in text
        assert "qwerty123456" not in text
        assert "reset-password" not in text

    def test_password_reset_api_responses_never_echo_input(self, db: FakeDb) -> None:
        db.add_account(email=_EMAIL)
        app = _app()
        client = _client(app)

        responses = [_request_reset(client, _EMAIL), _request_reset(client, "nobody@x.test")]
        token = db.issued_token()
        responses += [
            _confirm(client, token, "Kq7#vX9!pL2"),
            _confirm(client, token),
            _confirm(client, token, _OTHER_PASSWORD),
        ]

        for response in responses:
            text = response.text.casefold()
            assert "reset.marker" not in text
            assert "nobody@x.test" not in text
            assert token.casefold() not in text
            assert _NEW_PASSWORD.casefold() not in text
            assert _OTHER_PASSWORD.casefold() not in text
            assert "reset-password" not in text

    def test_password_reset_api_audit_rows_hold_no_content(self, db: FakeDb) -> None:
        db.add_account(email=_EMAIL)
        app = _app()
        _request_reset(_client(app), _EMAIL)
        _request_reset(_client(app), "nobody.marker@example.test")
        token = db.issued_token()
        _confirm(_client(app), token)

        rows = db.audit_rows()
        assert [row["action"] for row in rows] == [
            "password_reset.request",
            "password_reset.request",
            "password_reset.complete",
        ]
        rendered = json.dumps(rows, default=str).casefold()
        assert "marker" not in rendered
        assert "example.test" not in rendered
        assert token.casefold() not in rendered
        assert _NEW_PASSWORD.casefold() not in rendered
        assert re.search(r"reset-password", rendered) is None
