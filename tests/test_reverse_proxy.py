"""HTTP-layer spec for running admino behind the TLS reverse proxy (GH-156).

The FastAPI app from ``create_app()`` gets a real ``AppConfig``: its
``server.public_url`` is the one CORS origin, and its ``server.trusted_proxies``
lists the proxy networks whose forwarded headers count. The database is the
shared in-memory ``tests.db_fakes.FakeDb`` and Argon2 is replaced by a fast
fake, so the real login, audit and rate-limit code runs.

What these tests pin down:
- CORS allows exactly ``server.public_url``. The old hard-coded localhost list
  (``http://localhost:8000``, ``http://127.0.0.1:8000``,
  ``http://localhost:3000``, ``http://127.0.0.1:3000``) is gone, and another
  scheme is another origin.
- A request whose TCP peer is inside ``trusted_proxies`` gets its client
  address from ``X-Forwarded-For`` (the rightmost address that isn't itself a
  trusted proxy, so an entry the client wrote further left can't pick its IP)
  and its scheme from ``X-Forwarded-Proto`` (``http``/``https`` only). Any
  other peer's forwarded headers are ignored. With the default
  ``trusted_proxies=[]`` nobody is trusted, 127.0.0.1 included.
- The resolved client is what the per-IP budgets and the audit events use:
  through the proxy, one client's login lockout doesn't throttle another, and
  from an untrusted peer, rotating X-Forwarded-For doesn't escape the peer's
  bucket.
- The security headers stay on responses through the proxy, and the app never
  sends Strict-Transport-Security (the proxy does). The cross-origin (CSRF)
  check keeps working through the proxy, and X-Forwarded-Host is never trusted.

A probe route, inserted at the front of the router (so the static files
mounted at "/" can't shadow it), reports ``request.client.host`` and
``request.url.scheme`` as the routes see them, through the real middleware
stack of ``create_app``.

Security notes:
- No network: the peer address is set with ``TestClient(client=(ip, port))``.
- Addresses come from the documentation ranges (RFC 5737, RFC 3849) and
  private networks.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse
from starlette.routing import Route

from admino import server
from admino.config import AppConfig
from admino.server import create_app
from tests.db_fakes import FakeDb, fake_hash

if TYPE_CHECKING:
    import httpx
    from fastapi import FastAPI
    from starlette.requests import Request

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# The proxy container on the internal compose network, and its network.
_PROXY_IP = "172.31.0.10"
_PROXY_NET = "172.31.0.0/24"
# A second proxy hop on the same network (trusted only through _PROXY_NET).
_SECOND_PROXY_IP = "172.31.0.11"
_PROXY_V6 = "fd00:31::10"
_PROXY_NET_V6 = "fd00:31::/64"
# A peer that is not a configured proxy.
_UNTRUSTED_IP = "198.51.100.20"
# Browser clients on the internet, as the proxy reports them.
_CLIENT_A = "203.0.113.7"
_CLIENT_B = "203.0.113.8"
_CLIENT_V6 = "2001:db8::7"
# An address a client wrote into its own X-Forwarded-For header.
_SPOOFED_IP = "192.0.2.66"

_PUBLIC_URL = "https://admino.example.ch"
_PUBLIC_HOST = "admino.example.ch"
_DEV_URL = "http://localhost:8000"

_PROBE = "/probe-client"
_LOGIN = "/api/auth/login"
_SESSION_FAILURE_ROUTE = "/api/auth/session"
_COOKIE = "admino_session"
_PASSWORD = "violet-Anchor-93-quartz"
_UNKNOWN_EMAIL = "nobody@example.test"
_CSRF_REFUSED = {"detail": "Cross-origin request refused"}


# ---------------------------------------------------------------------------
# Helpers and fixtures
# ---------------------------------------------------------------------------


def _config(
    *, public_url: str = _PUBLIC_URL, trusted_proxies: list[str] | None = None
) -> AppConfig:
    """A real AppConfig with the given public origin and trusted proxies."""
    return AppConfig.model_validate(
        {"server": {"public_url": public_url, "trusted_proxies": trusted_proxies or []}}
    )


async def _probe(request: Request) -> JSONResponse:
    """Report the client address and the scheme the routes see."""
    client = request.client
    return JSONResponse(
        {"host": client.host if client is not None else "", "scheme": request.url.scheme}
    )


def _app(config: AppConfig) -> FastAPI:
    """create_app with a stub agent, plus the probe route in front of every other route."""
    app = create_app(agent=MagicMock(), config=config)
    app.router.routes.insert(0, Route(_PROBE, _probe, methods=["GET", "POST"]))
    return app


def _client(app: FastAPI, peer: str) -> TestClient:
    """A client whose TCP peer address is ``peer``; no lifespan, no redirects.

    The Host header is the public host: the proxy passes the original Host on.
    """
    return TestClient(
        app, base_url=f"http://{_PUBLIC_HOST}", client=(peer, 50000), follow_redirects=False
    )


def _forwarded(client_ip: str, proto: str = "https") -> dict[str, str]:
    """The headers the proxy adds for a browser client at ``client_ip``."""
    return {"X-Forwarded-For": client_ip, "X-Forwarded-Proto": proto}


def _seen(app: FastAPI, peer: str, headers: dict[str, str] | None = None) -> dict[str, str]:
    """GET the probe from ``peer``; return the client host and scheme the app resolved."""
    response = _client(app, peer).get(_PROBE, headers=headers or {})
    assert response.status_code == 200, response.text
    return dict(response.json())


def _preflight(app: FastAPI, origin: str) -> httpx.Response:
    """A CORS preflight for a JSON POST to /api/message from ``origin``."""
    return _client(app, _UNTRUSTED_IP).options(
        "/api/message",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )


def _login(client: TestClient, email: str, headers: dict[str, str]) -> httpx.Response:
    """POST /api/auth/login with the test password, then drop the client's cookie jar."""
    response = client.post(_LOGIN, json={"email": email, "password": _PASSWORD}, headers=headers)
    client.cookies.clear()
    return response


def _login_burst(monkeypatch: pytest.MonkeyPatch) -> int:
    """The real login burst from ``server._RATE_LIMITS``.

    Only the refill is slowed, so the time a test takes can't add a token.
    """
    _rate, burst = server._RATE_LIMITS[_LOGIN]
    monkeypatch.setitem(server._RATE_LIMITS, _LOGIN, (0.001, burst))
    return burst


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch) -> FakeDb:
    """The fake database the server's get_pool() returns."""
    fake = FakeDb()
    monkeypatch.setattr("admino.database.get_pool", lambda: fake.pool)
    return fake


@pytest.fixture()
def fast_passwords(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace Argon2 with a fast fake (the real hashing is covered by test_passwords)."""
    monkeypatch.setattr(
        "admino.passwords.verify_password", lambda password, encoded: encoded == fake_hash(password)
    )
    monkeypatch.setattr("admino.passwords.needs_rehash", lambda _encoded: False)
    monkeypatch.setattr("admino.passwords.hash_password", fake_hash)


# ---------------------------------------------------------------------------
# 1. CORS allows exactly server.public_url
# ---------------------------------------------------------------------------


class TestCorsPublicOrigin:
    """The one CORS origin is ``server.public_url``; the localhost list is gone."""

    def test_reverse_proxy_cors_allows_the_public_origin(self) -> None:
        response = _preflight(_app(_config()), _PUBLIC_URL)

        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == _PUBLIC_URL

    def test_reverse_proxy_cors_allows_a_public_origin_with_a_port(self) -> None:
        origin = "https://admino.example.ch:8443"

        response = _preflight(_app(_config(public_url=origin)), origin)

        assert response.headers.get("access-control-allow-origin") == origin

    @pytest.mark.parametrize(
        "origin",
        [
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://admino.example.ch",
            "https://admino.example.ch:8443",
            "https://evil.example",
            "https://admino.example.ch.evil.example",
            "null",
        ],
    )
    def test_reverse_proxy_cors_refuses_every_other_origin(self, origin: str) -> None:
        """Localhost origins, another scheme or port, and other hosts get no allow-origin."""
        response = _preflight(_app(_config()), origin)

        assert "access-control-allow-origin" not in response.headers

    def test_reverse_proxy_cors_dev_default_allows_localhost_8000(self) -> None:
        """The dev profile's public URL (the default) is its one allowed origin."""
        response = _preflight(_app(_config(public_url=_DEV_URL)), _DEV_URL)

        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == _DEV_URL

    @pytest.mark.parametrize(
        "origin", ["http://localhost:3000", "http://127.0.0.1:3000", "http://127.0.0.1:8000"]
    )
    def test_reverse_proxy_cors_dev_default_refuses_other_local_origins(self, origin: str) -> None:
        response = _preflight(_app(_config(public_url=_DEV_URL)), origin)

        assert "access-control-allow-origin" not in response.headers

    def test_reverse_proxy_cors_simple_request_allows_the_public_origin_only(self) -> None:
        """A non-preflight request gets allow-origin for the public origin, not localhost."""
        client = _client(_app(_config()), _UNTRUSTED_IP)

        allowed = client.get(_PROBE, headers={"Origin": _PUBLIC_URL})
        refused = client.get(_PROBE, headers={"Origin": "http://localhost:8000"})

        assert allowed.headers.get("access-control-allow-origin") == _PUBLIC_URL
        assert "access-control-allow-origin" not in refused.headers


# ---------------------------------------------------------------------------
# 2. X-Forwarded-For / X-Forwarded-Proto count only from a trusted proxy
# ---------------------------------------------------------------------------


class TestForwardedHeaders:
    """The client address and scheme the routes see, per peer and configuration."""

    def test_reverse_proxy_trusted_peer_client_and_scheme_come_from_forwarded_headers(
        self,
    ) -> None:
        app = _app(_config(trusted_proxies=[_PROXY_IP]))

        seen = _seen(app, _PROXY_IP, _forwarded(_CLIENT_A))

        assert seen == {"host": _CLIENT_A, "scheme": "https"}

    def test_reverse_proxy_trusted_peer_matched_by_a_cidr_network(self) -> None:
        app = _app(_config(trusted_proxies=[_PROXY_NET]))

        seen = _seen(app, _PROXY_IP, _forwarded(_CLIENT_A))

        assert seen == {"host": _CLIENT_A, "scheme": "https"}

    @pytest.mark.parametrize("peer", [_UNTRUSTED_IP, _SECOND_PROXY_IP, "127.0.0.1"])
    def test_reverse_proxy_untrusted_peer_forwarded_headers_are_ignored(self, peer: str) -> None:
        """Only 172.31.0.10/32 is trusted: its neighbour and loopback are not."""
        app = _app(_config(trusted_proxies=[_PROXY_IP]))

        seen = _seen(app, peer, _forwarded(_CLIENT_A))

        assert seen == {"host": peer, "scheme": "http"}

    @pytest.mark.parametrize("peer", ["127.0.0.1", "::1", _PROXY_IP])
    def test_reverse_proxy_default_config_trusts_no_peer(self, peer: str) -> None:
        """trusted_proxies=[] (the default): forwarded headers are ignored from every
        peer, loopback included (no implicit 127.0.0.1 trust)."""
        app = _app(_config(public_url=_DEV_URL))

        seen = _seen(app, peer, _forwarded(_CLIENT_A))

        assert seen == {"host": peer, "scheme": "http"}

    def test_reverse_proxy_trusted_peer_without_forwarded_for_keeps_its_address(self) -> None:
        """No X-Forwarded-For: the client stays the peer; X-Forwarded-Proto still counts."""
        app = _app(_config(trusted_proxies=[_PROXY_IP]))

        seen = _seen(app, _PROXY_IP, {"X-Forwarded-Proto": "https"})

        assert seen == {"host": _PROXY_IP, "scheme": "https"}

    def test_reverse_proxy_forwarded_for_chain_skips_trusted_proxies(self) -> None:
        """Right-hand entries that are trusted proxies are skipped."""
        app = _app(_config(trusted_proxies=[_PROXY_NET]))

        seen = _seen(app, _PROXY_IP, {"X-Forwarded-For": f"{_CLIENT_A}, {_SECOND_PROXY_IP}"})

        assert seen["host"] == _CLIENT_A

    def test_reverse_proxy_client_written_forwarded_for_entry_is_not_the_client(self) -> None:
        """The proxy appends the real peer to the X-Forwarded-For the client sent: the
        rightmost untrusted address is the client, never a forged one further left."""
        app = _app(_config(trusted_proxies=[_PROXY_IP]))

        seen = _seen(app, _PROXY_IP, {"X-Forwarded-For": f"{_SPOOFED_IP}, {_CLIENT_A}"})

        assert seen["host"] == _CLIENT_A

    @pytest.mark.parametrize("proto", ["ftp", "wss", "javascript"])
    def test_reverse_proxy_forwarded_proto_outside_http_https_keeps_the_scheme(
        self, proto: str
    ) -> None:
        app = _app(_config(trusted_proxies=[_PROXY_IP]))

        seen = _seen(app, _PROXY_IP, _forwarded(_CLIENT_A, proto))

        assert seen == {"host": _CLIENT_A, "scheme": "http"}

    def test_reverse_proxy_ipv6_trusted_proxy(self) -> None:
        app = _app(_config(trusted_proxies=[_PROXY_NET_V6]))

        seen = _seen(app, _PROXY_V6, _forwarded(_CLIENT_V6))

        assert seen == {"host": _CLIENT_V6, "scheme": "https"}


# ---------------------------------------------------------------------------
# 3. The resolved client drives the per-IP budgets and the audit events
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("fast_passwords")
class TestForwardedClientInAuditAndLimits:
    """Lockouts and audit events see the browser client, not the proxy."""

    def test_reverse_proxy_failed_login_audit_records_the_forwarded_client(
        self, db: FakeDb
    ) -> None:
        app = _app(_config(trusted_proxies=[_PROXY_IP]))

        response = _login(_client(app, _PROXY_IP), _UNKNOWN_EMAIL, _forwarded(_CLIENT_A))

        assert response.status_code == 401
        assert [row["ip"] for row in db.audit_rows("login.failure")] == [_CLIENT_A]

    def test_reverse_proxy_failed_login_from_untrusted_peer_records_the_peer(
        self, db: FakeDb
    ) -> None:
        app = _app(_config(trusted_proxies=[_PROXY_IP]))

        _login(_client(app, _UNTRUSTED_IP), _UNKNOWN_EMAIL, _forwarded(_CLIENT_A))

        assert [row["ip"] for row in db.audit_rows("login.failure")] == [_UNTRUSTED_IP]

    def test_reverse_proxy_successful_login_records_the_forwarded_client(self, db: FakeDb) -> None:
        """The login.success event and the session row carry the client's address."""
        email = "proxy.user@example.test"
        db.add_account(email=email, password_hash=fake_hash(_PASSWORD))
        app = _app(_config(trusted_proxies=[_PROXY_IP]))

        response = _login(_client(app, _PROXY_IP), email, _forwarded(_CLIENT_A))

        assert response.status_code == 204
        assert [row["ip"] for row in db.audit_rows("login.success")] == [_CLIENT_A]
        assert [session["ip"] for session in db.sessions.values()] == [_CLIENT_A]

    def test_reverse_proxy_login_bucket_is_keyed_by_the_forwarded_client(self, db: FakeDb) -> None:
        app = _app(_config(trusted_proxies=[_PROXY_IP]))

        _login(_client(app, _PROXY_IP), _UNKNOWN_EMAIL, _forwarded(_CLIENT_A))

        assert (_LOGIN, f"ip:{_CLIENT_A}") in server._rate_buckets
        assert (_LOGIN, f"ip:{_PROXY_IP}") not in server._rate_buckets

    def test_reverse_proxy_login_budget_is_per_forwarded_client(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Client A exhausting its login budget through the proxy doesn't lock out B."""
        app = _app(_config(trusted_proxies=[_PROXY_IP]))
        burst = _login_burst(monkeypatch)
        client = _client(app, _PROXY_IP)

        statuses_a = [
            _login(client, _UNKNOWN_EMAIL, _forwarded(_CLIENT_A)).status_code
            for _ in range(burst + 1)
        ]
        status_b = _login(client, _UNKNOWN_EMAIL, _forwarded(_CLIENT_B)).status_code

        assert statuses_a == [401] * burst + [429]
        assert status_b == 401

    def test_reverse_proxy_untrusted_peer_cannot_escape_its_login_budget(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Rotating X-Forwarded-For from an untrusted peer still spends the peer's bucket."""
        app = _app(_config(trusted_proxies=[_PROXY_IP]))
        burst = _login_burst(monkeypatch)
        client = _client(app, _UNTRUSTED_IP)

        statuses = [
            _login(client, _UNKNOWN_EMAIL, _forwarded(f"203.0.113.{100 + attempt}")).status_code
            for attempt in range(burst + 1)
        ]

        assert statuses == [401] * burst + [429]

    def test_reverse_proxy_unresolved_session_budget_is_keyed_by_the_forwarded_client(
        self, db: FakeDb
    ) -> None:
        """A cookie that resolves to no session spends the client's budget, not the proxy's."""
        app = _app(_config(trusted_proxies=[_PROXY_IP]))
        headers = {"Cookie": f"{_COOKIE}={secrets.token_urlsafe(32)}", **_forwarded(_CLIENT_A)}

        response = _client(app, _PROXY_IP).get("/api/auth/me", headers=headers)

        assert response.status_code == 401
        assert (_SESSION_FAILURE_ROUTE, f"ip:{_CLIENT_A}") in server._rate_buckets
        assert (_SESSION_FAILURE_ROUTE, f"ip:{_PROXY_IP}") not in server._rate_buckets


# ---------------------------------------------------------------------------
# 4. Security headers and cross-origin protection through the proxy
# ---------------------------------------------------------------------------


class TestSecurityHeadersThroughProxy:
    """SecurityHeadersMiddleware's headers stay; HSTS is the proxy's job."""

    def test_reverse_proxy_security_headers_stay_and_the_app_sends_no_hsts(self) -> None:
        app = _app(_config(trusted_proxies=[_PROXY_IP]))

        response = _client(app, _PROXY_IP).get(_PROBE, headers=_forwarded(_CLIENT_A))

        assert response.status_code == 200
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "default-src 'self'" in response.headers["content-security-policy"]
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert "camera=()" in response.headers["permissions-policy"]
        assert "strict-transport-security" not in response.headers


class TestCrossOriginProtectionThroughProxy:
    """The CSRF check compares Origin with the Host the proxy passes on."""

    @pytest.mark.parametrize(
        "browser_headers",
        [
            pytest.param({"Origin": _PUBLIC_URL}, id="origin-matches-host"),
            pytest.param({"Sec-Fetch-Site": "same-origin", "Origin": _PUBLIC_URL}, id="fetch-site"),
        ],
    )
    def test_reverse_proxy_same_origin_post_passes(self, browser_headers: dict[str, str]) -> None:
        app = _app(_config(trusted_proxies=[_PROXY_IP]))

        response = _client(app, _PROXY_IP).post(
            _PROBE, headers={**browser_headers, **_forwarded(_CLIENT_A)}
        )

        assert response.status_code == 200

    def test_reverse_proxy_cross_site_post_is_refused(self) -> None:
        app = _app(_config(trusted_proxies=[_PROXY_IP]))

        response = _client(app, _PROXY_IP).post(
            _PROBE,
            headers={
                "Sec-Fetch-Site": "cross-site",
                "Origin": "https://evil.example",
                **_forwarded(_CLIENT_A),
            },
        )

        assert response.status_code == 403
        assert response.json() == _CSRF_REFUSED

    def test_reverse_proxy_forwarded_host_is_never_trusted(self) -> None:
        """X-Forwarded-Host from the trusted proxy doesn't make a foreign Origin match."""
        app = _app(_config(trusted_proxies=[_PROXY_IP]))

        response = _client(app, _PROXY_IP).post(
            _PROBE,
            headers={
                "Origin": "https://evil.example",
                "X-Forwarded-Host": "evil.example",
                **_forwarded(_CLIENT_A),
            },
        )

        assert response.status_code == 403
        assert response.json() == _CSRF_REFUSED
