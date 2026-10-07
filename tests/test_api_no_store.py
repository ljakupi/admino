"""``Cache-Control: no-store`` on every API response (GH-278, Decision 2).

The API answers per-user data, so no browser or proxy may keep a copy. Spec:

- Every response to a path that is ``/api`` or starts with ``/api/`` carries
  exactly one ``Cache-Control`` value, ``no-store``, whatever its status or
  content type, replacing any value a route or the static mount set:
  - every row of the route table (``tests/tenancy_world.py`` ``ROUTES``, the
    ``/health`` row aside), once without a session (a protected route's 401)
    and once as an allowed role with the well-formed request of
    ``tests/test_tenancy.py``'s ``_REQUESTS`` (whatever status it answers; the
    OAuth callback's redirect and the attachment download included);
  - every error: the CSRF 403, a role's 403, 404 (an unknown ``/api`` path,
    ``/api`` itself, ``chat_not_found``), 405, 409 ``run_active``, 422, 429,
    503 ``chats_busy`` and the request-ID middleware's 500;
  - the OpenAPI document's path (the app serves no document: ``openapi_url``
    is None, so the path answers a 404, which carries ``no-store`` too);
  - with the PWA mounted: the mount's answers to ``/api`` paths (its 405, and a
    ``404.html`` the mount would send with ``no-cache``).
- Event streams (the streamed turn and the streamed approval) carry
  ``no-store`` instead of ``no-cache`` and keep ``X-Accel-Buffering: no`` and
  ``text/event-stream; charset=utf-8``; their frames still parse, in order.
- Unchanged: the static mount's values (a hashed asset ``public,
  max-age=31536000, immutable``; ``index.html``, a client route and a missing
  file's ``404.html`` ``no-cache``), ``/health`` (no ``Cache-Control``, also on
  its 500) and the security headers. Path matching is case-sensitive and stops
  at a segment boundary: ``/apiary``, ``/API/chats`` and ``/Api/auth/me`` are
  client routes of the PWA, as today.

Each "unchanged" case is checked next to an ``/api`` response of the same app,
so it proves the rule is active *and* excludes that case.

Inputs: the FakeDb world of tests/tenancy_world.py (real session cookies), the
app from ``create_app()`` with a scripted stub agent (tests/test_chat_stream_api.py's
``_Script``), and a Vite-like static dir (tests/test_static_cache_headers.py's
``_write_site``) for the mounted cases. Outputs: assertions only.

Security notes: every id, email and password is a fixed fake value. No test
reaches an LLM, Google or Microsoft: the agent is a stub, the diagnostics probes
are patched and OAuth has fake client credentials.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING, Final
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet

from admino import server
from tests.db_fakes import FakeDb
from tests.tenancy_world import (
    CHAT_NOT_FOUND,
    FORBIDDEN,
    ROUTES,
    UNAUTHORIZED,
    build_world,
    make_app,
    make_client,
    seed_pending_confirmation,
    stub_agent,
    use_attachment_storage,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)
from tests.test_chat_stream_api import (
    _PENDING_CALL,
    _QUICK_S,
    _chat,
    _confirm,
    _parked,
    _parse_sse,
    _post_turn,
    _reply,
    _Script,
)
from tests.test_chat_stream_api import _send as _send_turn
from tests.test_static_cache_headers import INDEX_HTML, _write_site
from tests.test_tenancy import _allowed_caller, _build, _send

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

    import httpx
    from fastapi.testclient import TestClient

    from tests.tenancy_world import RouteSpec, World

_NO_STORE: Final = ["no-store"]
_IMMUTABLE: Final = "public, max-age=31536000, immutable"
_NO_CACHE: Final = "no-cache"
_HASHED_ASSET: Final = "/assets/index-Bwk_qOWV.js"
_UNKNOWN_API_PATH: Final = "/api/does-not-exist-278"
_INTERNAL_ERROR: Final = {"detail": "Internal error"}
_RUN_ACTIVE: Final = {
    "detail": "A message is already running in this chat.",
    "reason": "run_active",
}
_CHATS_BUSY: Final = {"detail": "Too many active chats. Try again shortly.", "reason": "chats_busy"}
_EVENT_STREAM: Final = "text/event-stream; charset=utf-8"

# The security headers every response carries (SecurityHeadersMiddleware), spelled out.
_SECURITY_HEADERS: Final = {
    "content-security-policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
        "object-src 'none'; frame-ancestors 'none'; base-uri 'self'; "
        "form-action 'self'"
    ),
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
}

# Every route-table row under /api (only /health is outside it).
_API_SPECS: Final = [
    spec for spec in ROUTES if spec.path == "/api" or spec.path.startswith("/api/")
]


def _row_id(spec: RouteSpec) -> str:
    """A space-free pytest id: ``"GET:/api/org/settings"``."""
    return f"{spec.method}:{spec.path}"


def _cache_control(response: httpx.Response) -> list[str]:
    """Every ``Cache-Control`` value of the response, one entry per header line."""
    return response.headers.get_list("cache-control")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> World:
    """Orgs A and B (Org Admin, Editor, Viewer each) and a Super Admin, behind the FakeDb.

    As tests/test_tenancy.py's world: fast passwords, roomy rate buckets, an
    attachments root under ``tmp_path`` with a quota for both orgs, fake OAuth
    client credentials and patched diagnostics probes (nothing leaves the host).
    """
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    use_attachment_storage(monkeypatch, built, tmp_path / "attachments")
    monkeypatch.setenv("OAUTH_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "fake-google-client-id-gh278")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "fake-google-client-secret-gh278")
    monkeypatch.setenv("MICROSOFT_CLIENT_ID", "fake-microsoft-client-id-gh278")
    monkeypatch.setenv("MICROSOFT_CLIENT_SECRET", "fake-microsoft-client-secret-gh278")
    monkeypatch.setenv("OAUTH_REDIRECT_URI", "https://admino.example.ch/api/oauth/callback")
    monkeypatch.setattr("admino.database.check_health", AsyncMock(return_value=True))
    monkeypatch.setattr("admino.server._check_llm_reachable", AsyncMock(return_value=True))
    return built


@pytest.fixture()
def script() -> _Script:
    """The stub agent's scripted replies (default: a final ``Done.``)."""
    return _Script()


@pytest.fixture()
def agent(script: _Script) -> MagicMock:
    """A stub agent whose ``run`` (an AsyncMock) plays ``script``."""
    stub = stub_agent()
    stub.run.side_effect = script.run
    return stub


@pytest.fixture()
def client(world: World, agent: MagicMock) -> TestClient:
    """The app (built after the world: create_app clears the server's state) and a client."""
    return make_client(make_app(agent))


@pytest.fixture()
def static_dir(tmp_path: Path) -> Path:
    """A static dir laid out like Vite's output (tests/test_static_cache_headers.py)."""
    return _write_site(tmp_path / "site")


@pytest.fixture()
def mounted_client(
    world: World, agent: MagicMock, static_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> TestClient:
    """The app with the PWA mounted at ``/`` from ``static_dir``, and a client."""
    monkeypatch.setenv("ADMINO_STATIC_DIR", str(static_dir))
    return make_client(make_app(agent))


# ---------------------------------------------------------------------------
# 1. Every row of the route table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spec", _API_SPECS, ids=_row_id)
def test_api_no_store_route_without_a_session_answers_no_store(
    spec: RouteSpec, world: World, client: TestClient
) -> None:
    """The row's well-formed request without a cookie: a protected route's 401 (a public
    route's own answer) carries exactly ``Cache-Control: no-store``."""
    request = _build(world, spec, world.a["org_admin"], client)

    response = _send(client, request)

    if spec.audience != "public":
        assert (response.status_code, response.json()) == (401, UNAUTHORIZED)
    assert _cache_control(response) == _NO_STORE, response.status_code


@pytest.mark.parametrize("spec", _API_SPECS, ids=_row_id)
def test_api_no_store_route_as_an_allowed_role_answers_no_store(
    spec: RouteSpec, world: World, client: TestClient
) -> None:
    """The row's well-formed request as an allowed role (whatever status the route
    answers, the redirect and the file download included) carries exactly one
    ``Cache-Control`` value, ``no-store``."""
    caller = _allowed_caller(world, spec)
    request = _build(world, spec, caller, client)

    response = _send(client, request, caller.cookie)

    assert response.status_code < 500, response.text[:300]
    assert spec.audience == "public" or response.status_code not in {401, 403}, response.text
    assert _cache_control(response) == _NO_STORE, response.status_code


# ---------------------------------------------------------------------------
# 2. Every error answer under /api
# ---------------------------------------------------------------------------


def test_api_no_store_cross_origin_refusal_403(world: World, client: TestClient) -> None:
    """The CSRF middleware's 403 (a cross-site POST, refused before the route)."""
    editor = world.a["editor"]

    response = client.post(
        "/api/chats", json={}, headers={**editor.cookie, "Sec-Fetch-Site": "cross-site"}
    )

    assert (response.status_code, response.json(), _cache_control(response)) == (
        403,
        {"detail": "Cross-origin request refused"},
        _NO_STORE,
    )


def test_api_no_store_role_refusal_403(world: World, client: TestClient) -> None:
    """A Viewer on the chat list (``chat.send`` refused): the 403 ``Forbidden``."""
    viewer = world.a["viewer"]

    response = client.get("/api/chats", headers=viewer.cookie)

    assert (response.status_code, response.json(), _cache_control(response)) == (
        403,
        FORBIDDEN,
        _NO_STORE,
    )


@pytest.mark.parametrize("path", ["/api", _UNKNOWN_API_PATH], ids=["api-root", "unknown-path"])
def test_api_no_store_unknown_api_path_404(world: World, client: TestClient, path: str) -> None:
    """``/api`` itself and an unknown ``/api/`` path: the 404 carries ``no-store``."""
    editor = world.a["editor"]

    response = client.get(path, headers=editor.cookie)

    assert (response.status_code, _cache_control(response)) == (404, _NO_STORE)


def test_api_no_store_chat_not_found_404(world: World, client: TestClient) -> None:
    """A documented error code: the 404 ``chat_not_found`` of an unknown chat id."""
    editor = world.a["editor"]

    response = client.get(f"/api/chats/{uuid.uuid4()}", headers=editor.cookie)

    assert (response.status_code, response.json(), _cache_control(response)) == (
        404,
        CHAT_NOT_FOUND,
        _NO_STORE,
    )


def test_api_no_store_openapi_document_path_answers_no_store(
    world: World, client: TestClient
) -> None:
    """``/api/openapi.json``: the app serves no OpenAPI document (``openapi_url=None``), and
    whatever answers that path carries ``no-store``."""
    editor = world.a["editor"]

    response = client.get("/api/openapi.json", headers=editor.cookie)

    assert _cache_control(response) == _NO_STORE, response.status_code


def test_api_no_store_wrong_method_405(world: World, client: TestClient) -> None:
    """A method the ``/api`` path doesn't serve (PUT on the chat list): the 405."""
    editor = world.a["editor"]

    response = client.put("/api/chats", json={}, headers=editor.cookie)

    assert (response.status_code, _cache_control(response)) == (405, _NO_STORE)


def test_api_no_store_validation_error_422(world: World, client: TestClient) -> None:
    """A login body without its fields: the 422."""
    response = client.post("/api/auth/login", json={})

    assert (response.status_code, _cache_control(response)) == (422, _NO_STORE)


def test_api_no_store_rate_limited_request_429(
    world: World, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Editor's per-user chat-list bucket (burst 1): the second request's 429."""
    monkeypatch.setitem(server._RATE_LIMITS, "/api/chats/list", (0.0001, 1))
    editor = world.a["editor"]

    first = client.get("/api/chats", headers=editor.cookie)
    refused = client.get("/api/chats", headers=editor.cookie)

    assert first.status_code == 200, first.text
    assert (refused.status_code, refused.json(), _cache_control(refused)) == (
        429,
        {"detail": "Rate limit exceeded"},
        _NO_STORE,
    )


async def test_api_no_store_run_active_409(world: World, agent: MagicMock, script: _Script) -> None:
    """While a turn of the chat runs, a streamed send to it is the JSON 409 ``run_active``."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    app = make_app(agent)

    async with _parked(
        app, script, lambda http: _post_turn(http, editor, chat_id, "first", sse=False)
    ) as parked:
        refused = await asyncio.wait_for(
            _post_turn(parked.http, editor, chat_id, "second", sse=True), _QUICK_S
        )

    assert (refused.status_code, refused.json(), _cache_control(refused)) == (
        409,
        _RUN_ACTIVE,
        _NO_STORE,
    )


def test_api_no_store_chats_busy_503(
    world: World, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A full chat runtime with nothing to evict (two other users' chats, each holding a
    pending confirmation): a send to a third chat is the 503 ``chats_busy``."""
    from admino.chat_runtime import ChatRuntime

    monkeypatch.setattr(server, "_chat_runtime", ChatRuntime(max_entries=2, idle_s=900.0))
    for index, owner in enumerate((world.a["org_admin"], world.b["editor"])):
        seed_pending_confirmation(owner, _chat(world.db, owner), f"confirm-278-full-{index}")
    editor = world.a["editor"]

    response = _send_turn(client, editor, _chat(world.db, editor), sse=False)

    assert (response.status_code, response.json(), _cache_control(response)) == (
        503,
        _CHATS_BUSY,
        _NO_STORE,
    )


def test_api_no_store_unhandled_exception_500_on_api_only(
    world: World, agent: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The request-ID middleware's 500 for an escaping exception: on an ``/api`` path it
    carries ``no-store`` beside the security headers; on ``/health`` it carries no
    ``Cache-Control``, as today."""
    monkeypatch.setattr("admino.chats.list_chats", AsyncMock(side_effect=RuntimeError("gh278")))
    monkeypatch.setattr("admino.database.check_health", AsyncMock(side_effect=RuntimeError("x")))
    client = make_client(make_app(agent), raise_server_exceptions=False)
    editor = world.a["editor"]

    api = client.get("/api/chats", headers=editor.cookie)
    health = client.get("/health")

    assert {
        "api": (api.status_code, api.json(), _cache_control(api)),
        "health": (health.status_code, health.json(), _cache_control(health)),
    } == {"api": (500, _INTERNAL_ERROR, _NO_STORE), "health": (500, _INTERNAL_ERROR, [])}
    assert {name: api.headers.get(name) for name in _SECURITY_HEADERS} == _SECURITY_HEADERS


# ---------------------------------------------------------------------------
# 3. Event streams: no-store, still streamed
# ---------------------------------------------------------------------------


def test_api_no_store_event_streams_on_both_routes(
    world: World, client: TestClient, script: _Script
) -> None:
    """A streamed turn (it keeps a confirmation) and the streamed approval: 200,
    ``text/event-stream; charset=utf-8``, exactly ``no-store``, ``X-Accel-Buffering: no``;
    the frames parse, ``run_started`` first and one ``done`` last."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    script.queue(_reply(ask=_PENDING_CALL))

    turn = _send_turn(client, editor, chat_id)
    approval = _confirm(client, editor, chat_id)

    seen = {}
    for name, response in (("turn", turn), ("approval", approval)):
        frames = [event for event, _ in _parse_sse(response.text)]
        seen[name] = (
            response.status_code,
            response.headers.get_list("content-type"),
            _cache_control(response),
            response.headers.get_list("x-accel-buffering"),
            (frames[:1], frames[-1:], frames.count("done")),
        )
    expected = (200, [_EVENT_STREAM], _NO_STORE, ["no"], (["run_started"], ["done"], 1))
    assert seen == {"turn": expected, "approval": expected}


# ---------------------------------------------------------------------------
# 4. What stays as it is: the security headers, /health, the static mount, paths
# ---------------------------------------------------------------------------


def test_api_no_store_keeps_the_security_headers(world: World, client: TestClient) -> None:
    """An ``/api`` JSON answer carries ``no-store`` and still every security header."""
    editor = world.a["editor"]

    response = client.get("/api/auth/me", headers=editor.cookie)

    assert response.status_code == 200, response.text
    assert {name: response.headers.get(name) for name in [*_SECURITY_HEADERS, "cache-control"]} == {
        **_SECURITY_HEADERS,
        "cache-control": "no-store",
    }


def test_api_no_store_health_keeps_no_cache_control(world: World, client: TestClient) -> None:
    """``/health`` answers without ``Cache-Control`` (as today), while an ``/api`` answer of
    the same app carries ``no-store``."""
    editor = world.a["editor"]

    health = client.get("/health")
    api = client.get("/api/auth/me", headers=editor.cookie)

    assert {
        "health": (health.status_code, _cache_control(health)),
        "api": (api.status_code, _cache_control(api)),
    } == {"health": (200, []), "api": (200, _NO_STORE)}


def test_api_no_store_static_mount_keeps_its_cache_values(
    world: World, mounted_client: TestClient
) -> None:
    """With the PWA mounted: a hashed asset stays immutable, ``index.html``, the root and a
    client route stay ``no-cache``; an ``/api`` answer of the same app is ``no-store``."""
    editor = world.a["editor"]
    paths = (_HASHED_ASSET, "/index.html", "/", "/chat", "/api/auth/me")

    seen = {
        path: (response.status_code, _cache_control(response))
        for path in paths
        for response in [mounted_client.get(path, headers=editor.cookie)]
    }

    assert seen == {
        _HASHED_ASSET: (200, [_IMMUTABLE]),
        "/index.html": (200, [_NO_CACHE]),
        "/": (200, [_NO_CACHE]),
        "/chat": (200, [_NO_CACHE]),
        "/api/auth/me": (200, _NO_STORE),
    }


def test_api_no_store_path_matching_is_case_sensitive_and_segment_bounded(
    world: World, mounted_client: TestClient
) -> None:
    """``/apiary``, ``/API/chats`` and ``/Api/auth/me`` aren't API paths: the mount answers
    them with ``index.html`` and ``no-cache``, as today. ``/api`` and an unknown
    ``/api/`` path of the same app are ``no-store``."""
    editor = world.a["editor"]
    client_routes = ("/apiary", "/API/chats", "/Api/auth/me")

    seen = {
        path: (response.status_code, _cache_control(response), response.content == INDEX_HTML)
        for path in (*client_routes, "/api", _UNKNOWN_API_PATH)
        for response in [mounted_client.get(path, headers=editor.cookie)]
    }

    assert seen == {
        **dict.fromkeys(client_routes, (200, [_NO_CACHE], True)),
        "/api": (404, _NO_STORE, False),
        _UNKNOWN_API_PATH: (404, _NO_STORE, False),
    }


def test_api_no_store_replaces_the_static_mount_404_page_value_under_api(
    world: World, mounted_client: TestClient, static_dir: Path
) -> None:
    """A ``404.html`` in the static dir: the mount sends it with ``no-cache`` for a missing
    file, but under ``/api`` (``/api`` itself and an unknown path) ``no-store`` replaces
    that value (one value only)."""
    (static_dir / "404.html").write_bytes(b"<html>gh278 not found</html>")
    paths = ("/missing-file-278.js", "/api", _UNKNOWN_API_PATH)

    seen = {
        path: (response.status_code, _cache_control(response))
        for path in paths
        for response in [mounted_client.get(path)]
    }

    assert seen == {
        "/missing-file-278.js": (404, [_NO_CACHE]),
        "/api": (404, _NO_STORE),
        _UNKNOWN_API_PATH: (404, _NO_STORE),
    }


def test_api_no_store_static_mount_wrong_method_405(
    world: World, mounted_client: TestClient
) -> None:
    """With the PWA mounted, the mount answers a method the ``/api`` path doesn't serve
    (PUT on the chat list): its 405 carries ``no-store``."""
    editor = world.a["editor"]

    response = mounted_client.put("/api/chats", json={}, headers=editor.cookie)

    assert (response.status_code, _cache_control(response)) == (405, _NO_STORE)
