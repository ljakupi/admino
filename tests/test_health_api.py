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
  reach a response or any log line. The log checks look, case-insensitively,
  for the whole message and each of its words that no random value can spell
  (``zephyr``, ``secret``), plus a traceback. They never look for a fragment
  such as ``4481`` that a random request id, timestamp or count can also
  contain (GH-274: about one request id in 2,260 held those digits). They are
  not exhaustive: a leak of the digits alone, or of a fragment shorter than a
  whole word (``zeph``), for example, is not seen. On every record of the flow
  they also report a set ``exc_info`` or ``stack_info``, and those probes in
  any ``extra=`` field (an attribute beyond the standard ``LogRecord`` ones):
  what no admino formatter writes, but another handler could (GH-286, #274
  audit I-1).
- No real database, LLM or network: ``check_health``, ``_check_llm_reachable``,
  ``resolve_session``, ``get_pool`` and ``organizations.list_orgs`` are patched.
  The chat route (GH-176: it persists into a chat per user and session id) gets
  the in-memory database of tests/db_fakes.py with the logged-in member stored.
"""

from __future__ import annotations

import logging
import re
import string
import uuid
from contextlib import ExitStack
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, NoReturn
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
    TEST_MEMBER_ID,
    TEST_ORG_ID,
    TEST_SUPER_ADMIN_ID,
    login,
    member_session,
    resolved_session,
    session_cookie,
    super_admin_session,
)
from tests.db_fakes import FakeDb
from tests.log_capture import CapturedLogs, configured_logging

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
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
# The exception message: ASCII with nothing json.dumps escapes, so a leak shows
# up verbatim in the JSON log text. Its digit run is hex-like on purpose (a real
# message can carry one); no leak probe may rely on it.
_SECRET: Final = "zephyr secret 4481"
# Not a leak probe: the hex-only part of _SECRET, which a random request id can
# hold (GH-274). Only the reproduction's preconditions use it.
_SECRET_DIGITS: Final = re.sub(r"[^0-9]", "", _SECRET)
# Every character a random value in a log line is made of: a request id or UUID
# (hex digits, "-"), a timestamp ("2026-10-07T12:34:56.789+00:00", "Z", or
# "2026-10-07 12:34:56,789"), a count or a duration (digits, ".", "-", "e").
_RANDOM_VALUE_CHARS: Final = frozenset(string.hexdigits + "-:.,+TZ ")
# The words of _SECRET that no random value can spell in any case: each holds a
# character outside _RANDOM_VALUE_CHARS, compared casefolded. That is "zephyr"
# and "secret"; the digit run is left out.
_SECRET_WORDS: Final[tuple[str, ...]] = tuple(
    word
    for word in _SECRET.split()
    if not set(word.casefold()) <= {char.casefold() for char in _RANDOM_VALUE_CHARS}
)
# What the log leak checks look for, case-insensitively (GH-274): the whole
# message and each of _SECRET_WORDS in a raw record's message and in the
# formatted text, plus a traceback in the text. Never a fragment that a random
# value could spell on its own. Not exhaustive: the digits alone, or a fragment
# shorter than a whole word ("zeph"), for example, are not seen.
_MESSAGE_PROBES: Final[tuple[str, ...]] = (_SECRET, *_SECRET_WORDS)
_TEXT_PROBES: Final[tuple[str, ...]] = (*_MESSAGE_PROBES, "Traceback")
# The attributes a record has without ``extra=`` (GH-286): Python's own, read off a
# fresh LogRecord (``taskName`` since 3.12), plus the two a Formatter sets
# (``message``, ``asctime``; logging refuses them as ``extra=`` keys). Every other
# attribute came from ``extra=``, or from a filter: admino's ``request_id`` is
# checked too (it is a random value, which no probe can match).
_STANDARD_RECORD_ATTRIBUTES: Final = frozenset(
    {*vars(logging.LogRecord("", logging.INFO, "", 0, "", (), None)), "message", "asctime"}
)
# The record fields that carry a traceback or a stack (GH-286): reported when set.
_TRACE_FIELDS: Final[tuple[str, ...]] = ("exc_info", "stack_info")
# Request ids pinned through admino.server.uuid4 (both valid uuid4 values): one
# whose hex contains _SECRET_DIGITS (the GH-274 flake, made deterministic), and
# one that shares nothing with _SECRET.
_COLLIDING_REQUEST_ID: Final = uuid.UUID("0b5e2c7f-9d3a-4481-a6f0-3c1e8d2b7a95")
_PLAIN_REQUEST_ID: Final = uuid.UUID("5c0f9e2a-7b3d-4e6a-9f1c-2d8b6a0e3f57")
# The logger a planted leak (the positive control) writes the message to.
_LEAK_LOGGER: Final = "admino.probe"
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


def _log_then_raise(form: str) -> Callable[..., NoReturn]:
    """A failing collaborator that logs the exception message, then raises (a planted leak).

    ``"bare-message"`` logs ``_SECRET`` as the whole message; ``"str-of-exception"``
    formats the exception into a sentence (``"%s", exc``); ``"upper-cased"`` logs
    the message upper-cased; ``"first-word-redacted"`` logs only its tail after a
    masked first word (``"*** secret 4481"``); ``"truncated-head"`` logs only its
    first nine characters (``"zephyr se"``). The record-field forms (GH-286) log
    the fixed ``"Lookup failed"`` and put the exception on the record only:
    ``"exc-info"`` as ``exc_info=exc``, ``"stack-info"`` with ``stack_info=True``,
    ``"extra-field"`` as ``extra={"detail": message}``, ``"upper-cased-extra"``
    the same upper-cased, and ``"nested-extra"`` as
    ``extra={"context": {"cause": exc}}`` (its ``str()`` is the exception's
    ``repr``). Each line is written on an ``admino.*`` logger while the request
    runs, through the configured handler.
    """

    def fail(*_args: object, **_kwargs: object) -> NoReturn:
        exc = RuntimeError(_SECRET)
        message = str(exc)
        logger = logging.getLogger(_LEAK_LOGGER)
        if form == "exc-info":
            logger.error("Lookup failed", exc_info=exc)
        elif form == "stack-info":
            logger.error("Lookup failed", stack_info=True)
        elif form == "extra-field":
            logger.error("Lookup failed", extra={"detail": message})
        elif form == "upper-cased-extra":
            logger.error("Lookup failed", extra={"detail": message.upper()})
        elif form == "nested-extra":
            logger.error("Lookup failed", extra={"context": {"cause": exc}})
        elif form == "bare-message":
            logger.error(_SECRET)
        elif form == "str-of-exception":
            logger.error("Lookup failed: %s", exc)
        elif form == "upper-cased":
            logger.error("Lookup failed: %s", message.upper())
        elif form == "first-word-redacted":
            logger.error("Lookup failed: *** %s", message.split(maxsplit=1)[1])
        elif form == "truncated-head":
            logger.error("Lookup failed: %s...", message[:9])
        else:
            raise AssertionError(f"unknown leak form {form!r}")
        raise exc

    return fail


def _endpoint_calling(
    fail: Callable[..., NoReturn],
) -> Callable[[Request], Awaitable[JSONResponse]]:
    """A probe route handler that fails through ``fail``."""

    async def endpoint(request: Request) -> JSONResponse:
        fail()

    return endpoint


def _message_leaks(logs: CapturedLogs) -> list[tuple[str, str]]:
    """Where the exception message (or a traceback) reached the logs; ``[]`` for nowhere.

    Each leak is ``(channel, probe)``: channel ``"text"`` is the formatted output
    an operator sees (checked for ``_TEXT_PROBES``), ``"record"`` a raw record's
    message (checked for ``_MESSAGE_PROBES``). Both compare casefolded, so an
    upper- or title-cased message is still found, and a word probe on its own
    finds a fragment that keeps a whole word (the tail after a redacted first
    word, a truncated head). Not every leak is found: the digits alone, or a
    fragment shorter than a whole word, for example, are not. Every probe holds
    a character that no request id, timestamp or count has in any case, so a
    random value can't match it (GH-274). A test asserts ``== []`` (nothing
    leaked) or the exact leaks of a planted message.

    Two more channels look at what no admino formatter writes but a record
    carries to every handler, on every record of the flow (GH-286, #274 audit
    I-1): ``"record-exc"`` names each of ``_TRACE_FIELDS`` (``exc_info``,
    ``stack_info``) that any record has set, whatever it holds; and
    ``"record-extra"`` the ``_MESSAGE_PROBES`` found, casefolded, in ``str()`` of
    any attribute beyond ``_STANDARD_RECORD_ATTRIBUTES`` (an ``extra=`` field; a
    container's ``str()`` holds the ``repr`` of what it nests).
    """
    text = logs.text.casefold()
    records = logs.records
    messages = [record.getMessage().casefold() for record in records]
    extras = [
        str(value).casefold()
        for record in records
        for name, value in vars(record).items()
        if name not in _STANDARD_RECORD_ATTRIBUTES
    ]
    leaks = [("text", probe) for probe in _TEXT_PROBES if probe.casefold() in text]
    leaks.extend(
        ("record", probe)
        for probe in _MESSAGE_PROBES
        if any(probe.casefold() in message for message in messages)
    )
    leaks.extend(
        ("record-exc", field)
        for field in _TRACE_FIELDS
        if any(getattr(record, field) is not None for record in records)
    )
    leaks.extend(
        ("record-extra", probe)
        for probe in _MESSAGE_PROBES
        if any(probe.casefold() in extra for extra in extras)
    )
    return leaks


async def _unhandled_from_route(
    fail: Callable[..., NoReturn] | None = None,
) -> tuple[Response, CapturedLogs]:
    """A real route (GET /api/platform/orgs) whose service call raises (through ``fail``)."""
    list_orgs = AsyncMock(side_effect=fail if fail is not None else RuntimeError(_SECRET))
    with (
        configured_logging() as logs,
        patch("admino.organizations.list_orgs", new=list_orgs),
        patch("admino.database.get_pool", MagicMock(return_value=MagicMock(name="pool"))),
    ):
        async with _client(_app(session=super_admin_session())) as client:
            response = await client.get("/api/platform/orgs")
    return response, logs


async def _unhandled_from_dependency(
    fail: Callable[..., NoReturn] | None = None,
) -> tuple[Response, CapturedLogs]:
    """The real session dependency, whose session lookup raises (through ``fail``)."""
    with configured_logging() as logs, resolved_session(None) as resolve:
        resolve.side_effect = fail if fail is not None else RuntimeError(_SECRET)
        async with _client(_app()) as client:
            response = await client.get("/api/auth/me", headers=session_cookie())
    return response, logs


async def _unhandled(
    source: str,
    *,
    request_id: uuid.UUID | None = None,
    fail: Callable[..., NoReturn] | None = None,
) -> tuple[Response, CapturedLogs]:
    """Run one unhandled-exception flow; return the response and the logs.

    ``request_id`` pins the UUID the request-ID middleware draws
    (``admino.server.uuid4``); ``fail`` replaces the failing collaborator (the
    probe handler, ``list_orgs`` or ``resolve_session``) and must raise.
    """
    with ExitStack() as stack:
        if request_id is not None:
            stack.enter_context(patch("admino.server.uuid4", return_value=request_id))
        if source == "probe-route":
            endpoint = _raise_runtime_error if fail is None else _endpoint_calling(fail)
            return await _unhandled_from_probe(endpoint)
        if source == "real-route":
            return await _unhandled_from_route(fail)
        return await _unhandled_from_dependency(fail)


_SOURCES: Final = ["probe-route", "real-route", "dependency"]
# The planted leak forms of _log_then_raise and the probes that must report each,
# exactly: every probe for the whole message in any case, and for a fragment the
# one whole word it keeps (so each word probe is proven on its own).
_LEAK_FORMS: Final[dict[str, tuple[str, ...]]] = {
    "bare-message": _MESSAGE_PROBES,
    "str-of-exception": _MESSAGE_PROBES,
    "upper-cased": _MESSAGE_PROBES,
    "first-word-redacted": ("secret",),
    "truncated-head": ("zephyr",),
}
# The record-field forms of _log_then_raise (GH-286) and their exact leaks: the
# message is in no text and no record's message, only on the record, so only the
# record-field channel reports it (every message probe for an extra= field).
_RECORD_FIELD_LEAK_FORMS: Final[dict[str, list[tuple[str, str]]]] = {
    "exc-info": [("record-exc", "exc_info")],
    "stack-info": [("record-exc", "stack_info")],
    "extra-field": [("record-extra", probe) for probe in _MESSAGE_PROBES],
    "upper-cased-extra": [("record-extra", probe) for probe in _MESSAGE_PROBES],
    "nested-extra": [("record-extra", probe) for probe in _MESSAGE_PROBES],
}


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
        assert _message_leaks(logs) == []

    @pytest.mark.parametrize("source", _SOURCES)
    async def test_unhandled_exception_request_id_sharing_the_message_digits_is_no_leak(
        self, source: str
    ) -> None:
        """A request id that happens to contain the message's digits is no leak (GH-274).

        ``uuid4().hex`` is random: about one id in 2,260 contains the four digits
        of ``_SECRET``, and the leak check then failed although nothing leaked.
        The id is pinned to such a value here, so the case runs every time.
        """
        response, logs = await _unhandled(source, request_id=_COLLIDING_REQUEST_ID)

        assert _SECRET_DIGITS in _request_id(response), "the request id wasn't pinned"
        assert _SECRET_DIGITS in logs.text, "the pinned request id reached no log line"
        assert _message_leaks(logs) == []

    @pytest.mark.parametrize("form", list(_LEAK_FORMS))
    @pytest.mark.parametrize("source", _SOURCES)
    async def test_unhandled_exception_message_logged_during_the_request_is_reported(
        self, source: str, form: str
    ) -> None:
        """Positive control: the leak check reports a message that does reach a log line.

        The failing collaborator logs the message, or a case-changed or partial
        form of it, right before it raises. Exactly the probes ``_LEAK_FORMS``
        names report it, in the formatted text and in the raw record: every
        message probe for the whole message in any case (so no probe is blind,
        e.g. to a character the JSON formatter escapes), the surviving word alone
        for a fragment. The request id shares nothing with ``_SECRET``, so only
        the message can be what is found.
        """
        response, logs = await _unhandled(
            source, request_id=_PLAIN_REQUEST_ID, fail=_log_then_raise(form)
        )

        planted = [entry for entry in logs.json_lines() if entry.get("logger") == _LEAK_LOGGER]
        assert response.status_code == 500
        assert [entry["request_id"] for entry in planted] == [_request_id(response)]
        assert _message_leaks(logs) == [
            *(("text", probe) for probe in _LEAK_FORMS[form]),
            *(("record", probe) for probe in _LEAK_FORMS[form]),
        ]

    @pytest.mark.parametrize("form", list(_RECORD_FIELD_LEAK_FORMS))
    @pytest.mark.parametrize("source", _SOURCES)
    async def test_unhandled_exception_record_field_set_during_the_request_is_reported(
        self, source: str, form: str
    ) -> None:
        """Positive control (GH-286, #274 audit I-1): a leak on a record field is reported.

        The failing collaborator logs a fixed message with the exception on the
        record only (``exc_info``, ``stack_info``, an ``extra=`` field: as is,
        upper-cased or nested), right before it raises. No formatter writes
        those, so the text and message channels see nothing; exactly the leaks
        ``_RECORD_FIELD_LEAK_FORMS`` names are reported.
        """
        response, logs = await _unhandled(
            source, request_id=_PLAIN_REQUEST_ID, fail=_log_then_raise(form)
        )

        planted = [entry for entry in logs.json_lines() if entry.get("logger") == _LEAK_LOGGER]
        assert response.status_code == 500
        assert [entry["request_id"] for entry in planted] == [_request_id(response)]
        assert _message_leaks(logs) == _RECORD_FIELD_LEAK_FORMS[form]

    async def test_unhandled_exception_leak_probes_are_never_spelled_by_a_random_value(
        self,
    ) -> None:
        """No random value in a log line can match a leak probe on its own (GH-274).

        A request id, UUID, timestamp, count or duration is made of
        ``_RANDOM_VALUE_CHARS`` only. The checks compare casefolded, so every
        probe must hold another character in any case: a probe is rejected when
        any case of it could be spelled by a random value. The digit run the
        old probe used is made of those characters only, so the check would have
        caught it.
        """
        random_chars = {char.casefold() for char in _RANDOM_VALUE_CHARS}
        spellable = [probe for probe in _TEXT_PROBES if set(probe.casefold()) <= random_chars]

        assert (spellable, set(_SECRET_DIGITS) <= random_chars) == ([], True)

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
        # GH-160: the route reads the platform limits through the settings cache
        # (primed by conftest). GH-161: the run's org policy is stubbed. GH-170: the
        # per-request prompt context load is stubbed the same way. GH-176: the legacy
        # chat (one per user and session id) is persisted, so the pool is the shared
        # in-memory database with the logged-in member stored; the agent run is what
        # fails.
        from admino import models
        from admino.models import ToolPolicy
        from admino.permissions import PermissionsConfig

        prompt_context_cls = getattr(models, "PromptContext", None)
        prompt_context = (
            prompt_context_cls() if prompt_context_cls is not None else MagicMock(name="context")
        )
        db = FakeDb()
        db.add_account(role="editor", org_id=TEST_ORG_ID, user_id=TEST_MEMBER_ID)
        pool = patch("admino.database.get_pool", MagicMock(return_value=db.pool))
        policy = patch(
            "admino.org_permissions.load_tool_policy",
            AsyncMock(return_value=ToolPolicy(permissions=PermissionsConfig())),
        )
        context = patch(
            "admino.scoped_settings.load_prompt_context",
            AsyncMock(return_value=prompt_context),
            create=True,
        )
        with pool, policy, context, configured_logging() as logs:
            async with _client(app) as client:
                response = await client.post(
                    "/api/message", json={"message": "hello", "session_id": "chat-1"}
                )

        assert (response.status_code, response.json()) == (500, _INTERNAL_ERROR)
        _request_id(response)
        assert _unhandled_lines(logs) == []
        assert "zephyr" not in logs.text
