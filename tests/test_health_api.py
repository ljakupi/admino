"""HTTP spec for health exposure, request IDs and unhandled errors (GH-158).

Pinned here, before the implementation exists:

- ``GET /health`` is public (no session) and answers ``{"status": "ok"}`` (200)
  when ``admino.database.check_health()`` is True, ``{"status": "degraded"}``
  (503, no ``detail``) when it is False. Nothing else: no provider, no model, no
  reachability, and it never probes the LLM (``server._check_llm_reachable`` is
  not awaited). It has a per-IP token bucket (route key ``"/health"``): one
  client IP exhausting it gets 429 before any database check, another IP is
  unaffected.
- ``GET /api/platform/diagnostics`` (Super Admin only, through
  ``access.can(principal, Capability.PLATFORM_DIAGNOSTICS_VIEW)``): 401 without a
  session, 403 for an Org Admin, Editor or Viewer (before any probe), a per-user
  bucket (route key ``"/api/platform/diagnostics"``), and for a Super Admin 200
  with exactly ``{"status", "provider", "model", "llm_reachable"}`` — the DB
  status ("ok"/"degraded"), ``config.llm.provider``,
  ``config.llm.active_model_name`` and the bool from ``_check_llm_reachable()``.
- A request-ID middleware (outermost): every HTTP response — 200, 4xx, 5xx, the
  CSRF 403, a static file — carries ``X-Request-ID`` (``uuid4().hex``: 32
  lowercase hex characters, a new one per request). An incoming
  ``X-Request-ID`` is ignored, never echoed or used. The id is in
  ``logs.request_id_var`` while the request runs (a log line from a handler
  carries it) and reset afterwards.
- An exception escaping a route or a dependency is logged ONCE at ERROR as
  ``"Unhandled exception: <ClassName>"`` (request id via the filter, no
  exc_info, no exception message), and the client gets 500
  ``{"detail": "Internal error"}`` with ``X-Request-ID``. It never propagates
  out of the app: ``ASGITransport`` (``raise_app_exceptions=True`` by default)
  gets a response, not an exception. HTTPExceptions are unchanged.

Logs are captured with ``tests.log_capture.configured_logging`` (the real
``main._configure_logging`` writing JSON lines into a StringIO; root logging is
put back afterwards). Routes that raise or log are Starlette ``Route`` probes
inserted at ``app.router.routes[0]``, plus real routes and dependencies with a
patched collaborator.

Security notes:
- Operator blindness: the diagnostics body carries config metadata and statuses
  only; the public /health tells an anonymous caller nothing but up/degraded.
- The exception message ``zephyr secret 4481`` is a marker that must never
  reach a response or any log line.
- No real database, LLM or network: ``check_health``, ``_check_llm_reachable``,
  ``resolve_session``, ``get_pool`` and ``organizations.list_orgs`` are patched.
"""

from __future__ import annotations

import logging
import re
import uuid
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.responses import JSONResponse
from starlette.routing import Route

from admino import access, server
from admino.access import Capability
from admino.config import AppConfig
from admino.server import create_app
from tests.auth_helpers import (
    TEST_SUPER_ADMIN_ID,
    login,
    member_session,
    resolved_session,
    session_cookie,
    super_admin_session,
)
from tests.log_capture import CapturedLogs, configured_logging

if TYPE_CHECKING:
    from pathlib import Path

    from fastapi import FastAPI
    from httpx import Response
    from starlette.requests import Request

    from admino.sessions import AuthenticatedSession

pytestmark = pytest.mark.asyncio

_IP_A: Final = "203.0.113.5"
_IP_B: Final = "198.51.100.23"
_OTHER_SUPER_ADMIN_ID: Final = uuid.UUID("77777777-6666-4555-8444-333333333333")

_HEALTH: Final = "/health"
_DIAGNOSTICS: Final = "/api/platform/diagnostics"
_MODEL: Final = "org/diag-model-7"

_OK: Final = {"status": "ok"}
_DEGRADED: Final = {"status": "degraded"}
_UNAUTHORIZED: Final = {"detail": "Unauthorized"}
_FORBIDDEN: Final = {"detail": "Forbidden"}
_RATE_LIMITED: Final = {"detail": "Rate limit exceeded"}
_INTERNAL_ERROR: Final = {"detail": "Internal error"}

_REQUEST_ID: Final = re.compile(r"^[0-9a-f]{32}$")
_SECRET: Final = "zephyr secret 4481"
_UNHANDLED_PREFIX: Final = "Unhandled exception"
# Loops that exhaust a bucket stop here (far above any burst the server uses).
_MAX_ATTEMPTS: Final = 300


class _ZephyrError(Exception):
    """A custom exception: the log names its bare class name only."""


class _Clock:
    """A frozen stand-in for ``time.monotonic()`` (buckets never refill)."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _config(provider: str = "vllm", model: str = _MODEL) -> AppConfig:
    """A real AppConfig whose active provider serves ``model``."""
    return AppConfig.model_validate({"llm": {"provider": provider, f"{provider}_model": model}})


def _app(
    *,
    session: AuthenticatedSession | None = None,
    config: AppConfig | None = None,
) -> FastAPI:
    """A fresh app (empty rate buckets); ``session`` logged in, else anonymous."""
    app = create_app(agent=MagicMock(), config=config if config is not None else _config())
    if session is not None:
        login(app, session)
    return app


def _client(app: FastAPI, ip: str = _IP_A) -> AsyncClient:
    """An in-process client whose peer address is ``ip``."""
    return AsyncClient(transport=ASGITransport(app=app, client=(ip, 1234)), base_url="http://test")


def _db(healthy: bool = True) -> Any:
    """Patch the database health check."""
    return patch("admino.database.check_health", new=AsyncMock(return_value=healthy))


def _llm(reachable: bool = True) -> Any:
    """Patch the LLM reachability probe."""
    return patch("admino.server._check_llm_reachable", new=AsyncMock(return_value=reachable))


def _add_probe(app: FastAPI, path: str, endpoint: Any) -> None:
    """Put a plain Starlette route first, so no mount or API route shadows it."""
    app.router.routes.insert(0, Route(path, endpoint, methods=["GET", "POST"]))


async def _raise_runtime_error(request: Request) -> JSONResponse:
    """A route whose handler fails with a secret-bearing message."""
    raise RuntimeError(_SECRET)


async def _raise_zephyr_error(request: Request) -> JSONResponse:
    raise _ZephyrError(_SECRET)


async def _log_probe_line(request: Request) -> JSONResponse:
    """A route that logs one line while the request runs."""
    logging.getLogger("admino.probe").info("probe line")
    return JSONResponse({"ok": True})


def _request_id(response: Response) -> str:
    """The response's X-Request-ID (exactly one header, 32 lowercase hex)."""
    values = response.headers.get_list("x-request-id")
    assert len(values) == 1, values
    assert _REQUEST_ID.match(values[0]), values[0]
    return values[0]


def _lines_with(logs: CapturedLogs, message: str) -> list[dict[str, Any]]:
    """The JSON log lines whose message is exactly ``message``."""
    return [entry for entry in logs.json_lines() if entry.get("message") == message]


def _unhandled_lines(logs: CapturedLogs) -> list[dict[str, Any]]:
    return [
        entry
        for entry in logs.json_lines()
        if str(entry.get("message", "")).startswith(_UNHANDLED_PREFIX)
    ]


async def _exhaust(client: AsyncClient, path: str) -> Response:
    """GET ``path`` until it answers 429 (or give up after ``_MAX_ATTEMPTS``)."""
    response = await client.get(path)
    for _ in range(_MAX_ATTEMPTS):
        if response.status_code == 429:
            break
        response = await client.get(path)
    return response


@pytest.fixture()
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    """Freeze the server's monotonic clock, so buckets never refill during a test."""
    fake = _Clock()
    monkeypatch.setattr("admino.server.time.monotonic", fake)
    return fake


# ---------------------------------------------------------------------------
# 1. Public /health: {status} only
# ---------------------------------------------------------------------------


class TestPublicHealth:
    """GET /health — public, up/degraded only, never probes the LLM."""

    async def test_health_ok_body_is_status_only(self) -> None:
        with _db(True), _llm(True):
            async with _client(_app()) as client:
                response = await client.get(_HEALTH)

        assert (response.status_code, response.json()) == (200, _OK)

    async def test_health_degraded_is_503_with_status_only(self) -> None:
        """No ``detail`` (no "Database unreachable"), only the status."""
        with _db(False), _llm(True):
            async with _client(_app()) as client:
                response = await client.get(_HEALTH)

        assert (response.status_code, response.json()) == (503, _DEGRADED)

    @pytest.mark.parametrize(
        ("healthy", "expected"), [(True, (200, _OK)), (False, (503, _DEGRADED))]
    )
    async def test_health_never_probes_the_llm(
        self, healthy: bool, expected: tuple[int, dict[str, str]]
    ) -> None:
        probe = AsyncMock(return_value=True)
        with _db(healthy), patch("admino.server._check_llm_reachable", new=probe):
            async with _client(_app()) as client:
                response = await client.get(_HEALTH)

        assert (response.status_code, response.json(), probe.await_count) == (*expected, 0)

    @pytest.mark.parametrize("healthy", [True, False])
    async def test_health_never_names_the_provider_or_model(self, healthy: bool) -> None:
        with _db(healthy), _llm(True):
            async with _client(_app(config=_config("vllm", _MODEL))) as client:
                response = await client.get(_HEALTH)

        assert set(response.json()) == {"status"}
        assert "vllm" not in response.text
        assert _MODEL not in response.text

    async def test_health_needs_no_session(self) -> None:
        """Anonymous and cookie-less: 200, and no session is ever looked up."""
        with _db(True), _llm(True), resolved_session(None) as resolve:
            async with _client(_app()) as client:
                response = await client.get(_HEALTH, headers=session_cookie())

        assert (response.status_code, response.json(), resolve.await_count) == (200, _OK, 0)

    async def test_health_rate_limit_is_keyed_by_client_ip(self) -> None:
        with _db(True), _llm(True):
            async with _client(_app(), _IP_A) as client:
                await client.get(_HEALTH)

        assert (_HEALTH, f"ip:{_IP_A}") in server._rate_buckets

    async def test_health_one_ip_exhausting_its_bucket_gets_429(self, clock: _Clock) -> None:
        with _db(True), _llm(True):
            async with _client(_app(), _IP_A) as client:
                response = await _exhaust(client, _HEALTH)

        assert (response.status_code, response.json()) == (429, _RATE_LIMITED)

    async def test_health_another_ip_is_unaffected(self, clock: _Clock) -> None:
        app = _app()
        with _db(True), _llm(True):
            async with _client(app, _IP_A) as client:
                exhausted = await _exhaust(client, _HEALTH)
            async with _client(app, _IP_B) as client:
                other = await client.get(_HEALTH)

        assert (exhausted.status_code, other.status_code, other.json()) == (429, 200, _OK)

    async def test_health_429_comes_before_the_database_check(self, clock: _Clock) -> None:
        """A throttled caller costs no database round trip."""
        check = AsyncMock(return_value=True)
        with patch("admino.database.check_health", new=check), _llm(True):
            async with _client(_app(), _IP_A) as client:
                response = await _exhaust(client, _HEALTH)
                calls_before = check.await_count
                again = await client.get(_HEALTH)

        assert (response.status_code, again.status_code) == (429, 429)
        assert check.await_count == calls_before


# ---------------------------------------------------------------------------
# 2. GET /api/platform/diagnostics (Super Admin)
# ---------------------------------------------------------------------------


class TestPlatformDiagnostics:
    """Provider, model and reachability, for the Super Admin only."""

    async def test_diagnostics_without_a_session_is_401(self) -> None:
        with _db(True), _llm(True):
            async with _client(_app()) as client:
                response = await client.get(_DIAGNOSTICS)

        assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)

    @pytest.mark.parametrize("role", ["org_admin", "editor", "viewer"])
    async def test_diagnostics_member_role_is_403(self, role: Any) -> None:
        with _db(True), _llm(True):
            async with _client(_app(session=member_session(role))) as client:
                response = await client.get(_DIAGNOSTICS)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)

    @pytest.mark.parametrize("role", ["org_admin", "editor", "viewer"])
    async def test_diagnostics_forbidden_caller_triggers_no_probe(self, role: Any) -> None:
        check = AsyncMock(return_value=True)
        probe = AsyncMock(return_value=True)
        with (
            patch("admino.database.check_health", new=check),
            patch("admino.server._check_llm_reachable", new=probe),
        ):
            async with _client(_app(session=member_session(role))) as client:
                response = await client.get(_DIAGNOSTICS)

        assert (response.status_code, check.await_count, probe.await_count) == (403, 0, 0)

    async def test_diagnostics_super_admin_gets_exactly_the_metadata(self) -> None:
        with _db(True), _llm(True):
            async with _client(_app(session=super_admin_session())) as client:
                response = await client.get(_DIAGNOSTICS)

        assert response.status_code == 200
        assert response.json() == {
            "status": "ok",
            "provider": "vllm",
            "model": _MODEL,
            "llm_reachable": True,
        }

    async def test_diagnostics_reports_an_unreachable_llm(self) -> None:
        with _db(True), _llm(False):
            async with _client(_app(session=super_admin_session())) as client:
                response = await client.get(_DIAGNOSTICS)

        body = response.json()
        assert (response.status_code, body["status"], body["llm_reachable"]) == (200, "ok", False)

    async def test_diagnostics_reports_a_degraded_database(self) -> None:
        """The diagnostics call itself succeeds; the body says the DB is degraded."""
        with _db(False), _llm(True):
            async with _client(_app(session=super_admin_session())) as client:
                response = await client.get(_DIAGNOSTICS)

        assert (response.status_code, response.json()["status"]) == (200, "degraded")

    @pytest.mark.parametrize(
        ("provider", "model"),
        [("vllm", "Qwen/Qwen3-8B"), ("infomaniak", "mistral24b"), ("openai", "gpt-4o")],
    )
    async def test_diagnostics_names_the_active_provider_and_model(
        self, provider: str, model: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-diagnostics")
        config = _config(provider, model)
        with _db(True), _llm(True):
            async with _client(_app(session=super_admin_session(), config=config)) as client:
                response = await client.get(_DIAGNOSTICS)

        body = response.json()
        assert (body["provider"], body["model"]) == (provider, model)

    async def test_diagnostics_llm_reachable_comes_from_the_probe(self) -> None:
        probe = AsyncMock(return_value=True)
        with _db(True), patch("admino.server._check_llm_reachable", new=probe):
            async with _client(_app(session=super_admin_session())) as client:
                response = await client.get(_DIAGNOSTICS)

        assert (response.status_code, response.json()["llm_reachable"]) == (200, True)
        probe.assert_awaited_once()

    async def test_diagnostics_works_through_the_real_session_cookie(self) -> None:
        with _db(True), _llm(True), resolved_session(super_admin_session()):
            async with _client(_app()) as client:
                response = await client.get(_DIAGNOSTICS, headers=session_cookie())

        assert (response.status_code, response.json()["status"]) == (200, "ok")

    async def test_diagnostics_authorizes_through_access_can(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The route asks the role matrix: granting the capability to an Editor lets one in."""
        matrix = dict(access._MATRIX)
        matrix[Capability.PLATFORM_DIAGNOSTICS_VIEW] = frozenset({"super_admin", "editor"})
        monkeypatch.setattr(access, "_MATRIX", MappingProxyType(matrix))
        with _db(True), _llm(True):
            async with _client(_app(session=member_session("editor"))) as client:
                response = await client.get(_DIAGNOSTICS)

        assert response.status_code == 200

    async def test_diagnostics_rate_limit_is_keyed_by_user(self) -> None:
        with _db(True), _llm(True):
            async with _client(_app(session=super_admin_session())) as client:
                await client.get(_DIAGNOSTICS)

        assert (_DIAGNOSTICS, f"user:{TEST_SUPER_ADMIN_ID}") in server._rate_buckets

    async def test_diagnostics_one_super_admin_exhausting_the_bucket_gets_429(
        self, clock: _Clock
    ) -> None:
        with _db(True), _llm(True):
            async with _client(_app(session=super_admin_session())) as client:
                response = await _exhaust(client, _DIAGNOSTICS)

        assert (response.status_code, response.json()) == (429, _RATE_LIMITED)

    async def test_diagnostics_another_super_admin_is_unaffected(self, clock: _Clock) -> None:
        app = _app(session=super_admin_session())
        with _db(True), _llm(True):
            async with _client(app) as client:
                exhausted = await _exhaust(client, _DIAGNOSTICS)
                login(app, super_admin_session(user_id=_OTHER_SUPER_ADMIN_ID))
                other = await client.get(_DIAGNOSTICS)

        assert (exhausted.status_code, other.status_code) == (429, 200)


# ---------------------------------------------------------------------------
# 3. X-Request-ID on every response
# ---------------------------------------------------------------------------

_RESPONSE_CASES: Final = [
    "health-200",
    "health-503",
    "unauthorized-401",
    "chat-gate-403",
    "unknown-api-404",
    "invalid-body-422",
    "rate-limited-429",
    "csrf-403",
    "unhandled-500",
    "static-file-200",
]


async def _respond(case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Response:
    """Produce one response of the given kind from a fresh app."""
    if case == "static-file-200":
        site = tmp_path / "site"
        site.mkdir()
        (site / "index.html").write_text("<html>spa</html>", encoding="utf-8")
        (site / "app.js").write_text("console.log(1)", encoding="utf-8")
        monkeypatch.setenv("ADMINO_STATIC_DIR", str(site))
    session = member_session("viewer") if case == "chat-gate-403" else None
    if case == "invalid-body-422":
        session = member_session("editor")
    app = _app(session=session)
    _add_probe(app, "/probe/raise", _raise_runtime_error)
    with _db(case != "health-503"), _llm(True):
        async with _client(app) as client:
            if case in {"health-200", "health-503"}:
                return await client.get(_HEALTH)
            if case == "unauthorized-401":
                return await client.get("/api/auth/me")
            if case == "chat-gate-403":
                return await client.post(
                    "/api/message", json={"message": "hello", "session_id": "chat-1"}
                )
            if case == "unknown-api-404":
                return await client.get("/api/definitely-not-a-route")
            if case == "invalid-body-422":
                return await client.post(
                    "/api/message",
                    content=b"{invalid json",
                    headers={"Content-Type": "application/json"},
                )
            if case == "rate-limited-429":
                for _ in range(_MAX_ATTEMPTS):
                    response = await client.get("/api/oauth/callback")
                    if response.status_code == 429:
                        break
                return response
            if case == "csrf-403":
                return await client.post(
                    "/api/auth/login",
                    json={"email": "a@example.ch", "password": "x"},
                    headers={"Sec-Fetch-Site": "cross-site"},
                )
            if case == "unhandled-500":
                return await client.get("/probe/raise")
            return await client.get("/app.js")


class TestRequestIdHeader:
    """Every response carries a fresh, server-generated X-Request-ID."""

    @pytest.mark.parametrize("case", _RESPONSE_CASES)
    async def test_request_id_header_on_every_response(
        self, case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        response = await _respond(case, tmp_path, monkeypatch)

        expected_status = int(case.rsplit("-", 1)[1])
        assert response.status_code == expected_status
        _request_id(response)

    async def test_request_id_is_a_uuid4_hex(self) -> None:
        with _db(True), _llm(True):
            async with _client(_app()) as client:
                response = await client.get(_HEALTH)

        assert uuid.UUID(hex=_request_id(response)).version == 4

    async def test_request_id_differs_per_request(self) -> None:
        with _db(True), _llm(True):
            async with _client(_app()) as client:
                ids = {_request_id(await client.get(_HEALTH)) for _ in range(5)}

        assert len(ids) == 5

    @pytest.mark.parametrize(
        "incoming", ["attacker-chosen-id-0001", "deadbeef" * 4], ids=["free-text", "hex32"]
    )
    async def test_request_id_incoming_header_is_ignored(self, incoming: str) -> None:
        """Even a well-formed incoming id is never echoed or adopted."""
        app = _app()
        _add_probe(app, "/probe/log", _log_probe_line)
        with configured_logging() as logs:
            async with _client(app) as client:
                response = await client.get("/probe/log", headers={"X-Request-ID": incoming})

        assert _request_id(response) != incoming
        assert [entry["request_id"] for entry in _lines_with(logs, "probe line")] == [
            _request_id(response)
        ]
        assert incoming not in logs.text


class TestRequestIdInLogs:
    """The id is in logs.request_id_var for the request's duration, and only then."""

    async def test_request_id_log_line_inside_a_handler_matches_the_header(self) -> None:
        app = _app()
        _add_probe(app, "/probe/log", _log_probe_line)
        with configured_logging() as logs:
            async with _client(app) as client:
                response = await client.get("/probe/log")

        lines = _lines_with(logs, "probe line")
        assert [entry["request_id"] for entry in lines] == [_request_id(response)]

    async def test_request_id_two_requests_log_two_ids(self) -> None:
        app = _app()
        _add_probe(app, "/probe/log", _log_probe_line)
        with configured_logging() as logs:
            async with _client(app) as client:
                first = await client.get("/probe/log")
                second = await client.get("/probe/log")

        assert [entry["request_id"] for entry in _lines_with(logs, "probe line")] == [
            _request_id(first),
            _request_id(second),
        ]
        assert _request_id(first) != _request_id(second)

    async def test_request_id_is_reset_after_the_request(self) -> None:
        """A line logged after the response has no request id (the var was reset)."""
        from admino import logs as logs_module

        app = _app()
        _add_probe(app, "/probe/log", _log_probe_line)
        with configured_logging() as logs:
            async with _client(app) as client:
                await client.get("/probe/log")
            logging.getLogger("admino.probe").info("after the request")

        assert [entry["request_id"] for entry in _lines_with(logs, "after the request")] == [None]
        assert logs_module.request_id_var.get() is None


# ---------------------------------------------------------------------------
# 4. Unhandled exceptions: type + request id in the log, generic 500 to the client
# ---------------------------------------------------------------------------


async def _unhandled_from_probe(endpoint: Any) -> tuple[Response, CapturedLogs]:
    """GET a probe route whose handler raises; return the response and the logs."""
    app = _app()
    _add_probe(app, "/probe/raise", endpoint)
    with configured_logging() as logs:
        async with _client(app) as client:
            response = await client.get("/probe/raise")
    return response, logs


async def _unhandled_from_route() -> tuple[Response, CapturedLogs]:
    """A real route (GET /api/platform/orgs) whose service call raises."""
    list_orgs = AsyncMock(side_effect=RuntimeError(_SECRET))
    with (
        configured_logging() as logs,
        patch("admino.organizations.list_orgs", new=list_orgs),
        patch("admino.database.get_pool", MagicMock(return_value=MagicMock(name="pool"))),
    ):
        async with _client(_app(session=super_admin_session())) as client:
            response = await client.get("/api/platform/orgs")
    return response, logs


async def _unhandled_from_dependency() -> tuple[Response, CapturedLogs]:
    """The real session dependency, whose session lookup raises."""
    with configured_logging() as logs, resolved_session(None) as resolve:
        resolve.side_effect = RuntimeError(_SECRET)
        async with _client(_app()) as client:
            response = await client.get("/api/auth/me", headers=session_cookie())
    return response, logs


async def _unhandled(source: str) -> tuple[Response, CapturedLogs]:
    if source == "probe-route":
        return await _unhandled_from_probe(_raise_runtime_error)
    if source == "real-route":
        return await _unhandled_from_route()
    return await _unhandled_from_dependency()


_SOURCES: Final = ["probe-route", "real-route", "dependency"]


class TestUnhandledExceptions:
    """An escaping exception is a generic 500 plus one type-only ERROR line."""

    @pytest.mark.parametrize("source", _SOURCES)
    async def test_unhandled_exception_is_a_generic_500(self, source: str) -> None:
        """The exception doesn't propagate out of the app (ASGITransport would re-raise)."""
        response, _ = await _unhandled(source)

        assert (response.status_code, response.json()) == (500, _INTERNAL_ERROR)
        _request_id(response)

    @pytest.mark.parametrize("source", _SOURCES)
    async def test_unhandled_exception_500_carries_the_security_headers(self, source: str) -> None:
        """The crash 500 gets the same security headers as every other response."""
        response, _ = await _unhandled(source)

        assert response.status_code == 500
        assert response.headers.get("x-content-type-options") == "nosniff"
        assert response.headers.get("x-frame-options") == "DENY"
        assert response.headers.get("referrer-policy") == "no-referrer"
        assert "frame-ancestors 'none'" in response.headers.get("content-security-policy", "")
        assert "camera=()" in response.headers.get("permissions-policy", "")

    @pytest.mark.parametrize("source", _SOURCES)
    async def test_unhandled_exception_response_never_echoes_the_message(self, source: str) -> None:
        response, _ = await _unhandled(source)

        assert response.status_code == 500
        assert "zephyr" not in response.text
        assert "4481" not in response.text

    @pytest.mark.parametrize("source", _SOURCES)
    async def test_unhandled_exception_logged_once_by_type(self, source: str) -> None:
        response, logs = await _unhandled(source)

        lines = _unhandled_lines(logs)
        assert len(lines) == 1, lines
        assert (lines[0]["level"], lines[0]["message"]) == (
            "ERROR",
            "Unhandled exception: RuntimeError",
        )
        assert response.status_code == 500

    @pytest.mark.parametrize("source", _SOURCES)
    async def test_unhandled_exception_log_carries_the_request_id(self, source: str) -> None:
        response, logs = await _unhandled(source)

        assert [entry["request_id"] for entry in _unhandled_lines(logs)] == [_request_id(response)]

    @pytest.mark.parametrize("source", _SOURCES)
    async def test_unhandled_exception_logged_without_exc_info(self, source: str) -> None:
        """No exc_info on the record (so no traceback anywhere, and no exc_type key)."""
        _, logs = await _unhandled(source)

        records = [r for r in logs.records if r.getMessage().startswith(_UNHANDLED_PREFIX)]
        assert len(records) == 1
        assert (records[0].exc_info, records[0].stack_info) == (None, None)
        assert "exc_type" not in _unhandled_lines(logs)[0]

    @pytest.mark.parametrize("source", _SOURCES)
    async def test_unhandled_exception_message_never_reaches_any_log(self, source: str) -> None:
        _, logs = await _unhandled(source)

        assert logs.json_lines(), "nothing was captured"
        assert "zephyr" not in logs.text
        assert "4481" not in logs.text
        assert "Traceback" not in logs.text
        assert not any("zephyr" in record.getMessage() for record in logs.records)

    async def test_unhandled_exception_names_the_bare_class(self) -> None:
        response, logs = await _unhandled_from_probe(_raise_zephyr_error)

        assert response.status_code == 500
        assert [entry["message"] for entry in _unhandled_lines(logs)] == [
            "Unhandled exception: _ZephyrError"
        ]

    async def test_http_exceptions_are_unchanged(self) -> None:
        """A 401 is still a 401 with its detail, and it isn't logged as unhandled."""
        with configured_logging() as logs:
            async with _client(_app()) as client:
                response = await client.get("/api/auth/me")

        assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)
        _request_id(response)
        assert _unhandled_lines(logs) == []

    async def test_handled_route_error_keeps_its_own_500(self) -> None:
        """A route that turns a failure into its own 500 (the agent run) isn't double-logged."""
        agent = MagicMock()
        agent.run = AsyncMock(side_effect=ValueError(_SECRET))
        app = create_app(agent=agent, config=_config())
        login(app, member_session("editor"))
        with configured_logging() as logs:
            async with _client(app) as client:
                response = await client.post(
                    "/api/message", json={"message": "hello", "session_id": "chat-1"}
                )

        assert (response.status_code, response.json()) == (500, _INTERNAL_ERROR)
        _request_id(response)
        assert _unhandled_lines(logs) == []
        assert "zephyr" not in logs.text
