"""SPA fallback for the PWA static mount (GH-155: auth pages and role-aware app shell).

``create_app`` mounts the built PWA at ``/``. The PWA routes on the client
(``/login``, ``/reset-password``, ``/accept-invitation``, ``/chat``, ...), so a
first visit without a service worker yet, e.g. the emailed
``/reset-password#token=...`` or ``/accept-invitation#token=...`` link, or a
reload of ``/login``, must get ``index.html`` instead of a 404. Spec:

- GET/HEAD of a client route (a path whose last segment has no file extension,
  outside ``/api``) answers 200 with the ``index.html`` content.
- Real files are still served as themselves; a missing file whose last segment
  has an extension (``/assets/missing.js``, ``/favicon.ico``) stays 404.
- ``/api``, ``/api/`` and every unknown ``/api/...`` path stay 404 and never get
  the SPA; ``/health`` still answers its JSON payload.
- Other methods (POST, PUT, PATCH, DELETE) get no fallback (405).
- Path traversal never serves a file from outside the static directory.
- Without an ``index.html`` a client route stays 404 (no crash, no 500).

Every negative case is checked next to a client route of the same app, so each
test proves the fallback is active *and* excludes that case.

The app is built with ``ADMINO_STATIC_DIR`` pointing at a ``tmp_path`` static dir;
no database, LLM or session is involved (the static mount is public).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from admino.server import create_app

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from httpx import Response

pytestmark = pytest.mark.asyncio

INDEX_HTML = "<html>spa-index</html>"
APP_JS = "console.log(1)"
SECRET = "outside-static-secret-5b1e9c"

CLIENT_ROUTES = [
    "/login",
    "/forgot-password",
    "/reset-password",
    "/accept-invitation",
    "/chat",
    "/tools",
    "/permissions",
    "/organization",
    "/platform",
    "/settings",
    "/settings/nested/path",
    "/reset-password?x=1",
]


def _make_config() -> Any:
    """Build a minimal mock AppConfig with JSON-serializable /health fields."""
    config = MagicMock()
    del config.auth
    config.limits.max_message_length = 4000
    config.llm.provider = "infomaniak"
    config.llm.active_model_name = "test-model"
    return config


def _write_site(root: Path, *, with_index: bool = True) -> Path:
    """Write a static dir (index.html, assets/app.js) plus a secret file next to it.

    Returns:
        The static directory; ``root / "secret.txt"`` sits outside it.
    """
    static = root / "static"
    (static / "assets").mkdir(parents=True)
    if with_index:
        (static / "index.html").write_text(INDEX_HTML)
    (static / "assets" / "app.js").write_text(APP_JS)
    (root / "secret.txt").write_text(SECRET)
    return static


def _app_serving(static_dir: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Create the app with its static mount on ``static_dir``."""
    monkeypatch.setenv("ADMINO_STATIC_DIR", str(static_dir))
    return create_app(agent=MagicMock(), config=_make_config())


def _is_index(resp: Response) -> bool:
    """Whether a response is the SPA's index.html."""
    return resp.status_code == 200 and resp.text == INDEX_HTML


@pytest_asyncio.fixture
async def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[AsyncClient]:
    """An HTTP client for an app whose static dir has an index.html."""
    app = _app_serving(_write_site(tmp_path), monkeypatch)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# Client routes get index.html
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", CLIENT_ROUTES)
async def test_spa_fallback_client_route_serves_index_html(client: AsyncClient, path: str) -> None:
    """A client-side route answers 200 text/html with the index.html content."""
    resp = await client.get(path)

    assert (resp.status_code, resp.headers.get("content-type", "").split(";")[0], resp.text) == (
        200,
        "text/html",
        INDEX_HTML,
    )


async def test_spa_fallback_dot_in_earlier_segment_still_serves_index(client: AsyncClient) -> None:
    """Only the last segment decides: a dot in an earlier segment is still a client route."""
    resp = await client.get("/organization/v1.2/members")

    assert _is_index(resp)


async def test_spa_fallback_head_client_route_ok(client: AsyncClient) -> None:
    """HEAD of a client route answers 200 with the HTML content type."""
    resp = await client.head("/login")

    assert (resp.status_code, resp.headers.get("content-type", "").split(";")[0]) == (
        200,
        "text/html",
    )


# ---------------------------------------------------------------------------
# Real files and the root
# ---------------------------------------------------------------------------


async def test_spa_fallback_real_asset_served_as_itself(client: AsyncClient) -> None:
    """A real file is served as itself, while a client route of the same app gets the index."""
    asset = await client.get("/assets/app.js")
    route = await client.get("/login")

    assert (asset.status_code, asset.text, _is_index(route)) == (200, APP_JS, True)


async def test_spa_fallback_root_serves_index(client: AsyncClient) -> None:
    """GET / still serves index.html, like every client route."""
    root = await client.get("/")
    route = await client.get("/accept-invitation")

    assert (_is_index(root), _is_index(route)) == (True, True)


@pytest.mark.parametrize(
    "path",
    [
        "/assets/missing.js",
        "/favicon.ico",
        "/assets/deep/missing.css",
        "/robots.txt",
        "/login.html",
    ],
)
async def test_spa_fallback_missing_file_with_extension_404(client: AsyncClient, path: str) -> None:
    """A missing file (last segment has an extension) stays 404 and never gets the index."""
    missing = await client.get(path)
    route = await client.get("/login")

    assert (missing.status_code, INDEX_HTML in missing.text, _is_index(route)) == (404, False, True)


# ---------------------------------------------------------------------------
# The API surface never gets the SPA
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["/api/does-not-exist", "/api/", "/api", "/api/auth/nope", "/api/settings/unknown/deep"],
)
async def test_spa_fallback_unknown_api_path_404_not_index(client: AsyncClient, path: str) -> None:
    """An unknown API path stays 404 and its body is never the index."""
    api = await client.get(path)
    route = await client.get("/settings")

    assert (api.status_code, INDEX_HTML in api.text, _is_index(route)) == (404, False, True)


async def test_spa_fallback_health_still_json(client: AsyncClient) -> None:
    """/health still answers its JSON payload, while client routes get the index."""
    with (
        patch("admino.database.check_health", new=AsyncMock(return_value=True)),
        patch("admino.server._check_llm_reachable", new=AsyncMock(return_value=True)),
    ):
        health = await client.get("/health")
    route = await client.get("/chat")

    assert (health.status_code, health.json()["status"], _is_index(route)) == (200, "ok", True)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_spa_fallback_non_get_method_405_not_index(client: AsyncClient, method: str) -> None:
    """Only GET and HEAD get the fallback: another method on a client route is 405."""
    other = await client.request(method, "/login")
    route = await client.get("/login")

    assert (other.status_code, INDEX_HTML in other.text, _is_index(route)) == (405, False, True)


# ---------------------------------------------------------------------------
# Path traversal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/..%2fsecret.txt",
        "/%2e%2e/secret.txt",
        "/%2e%2e%2fsecret.txt",
        "/assets/..%2f..%2fsecret.txt",
        "/assets/%2e%2e/%2e%2e/secret.txt",
        "/..%5csecret.txt",
        "/settings/..%2f..%2f..%2fsecret.txt",
    ],
)
async def test_spa_fallback_path_traversal_never_serves_outside_file(
    client: AsyncClient, path: str
) -> None:
    """A traversal path never returns the file next to (outside) the static dir."""
    attack = await client.get(path)
    route = await client.get("/reset-password")

    assert (SECRET in attack.text, _is_index(route)) == (False, True)


# ---------------------------------------------------------------------------
# No index.html
# ---------------------------------------------------------------------------


async def test_spa_fallback_without_index_client_route_stays_404(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without an index.html a client route stays 404 (no crash, no 500); with one it is served."""
    bare = _app_serving(_write_site(tmp_path / "bare", with_index=False), monkeypatch)
    async with AsyncClient(transport=ASGITransport(app=bare), base_url="http://test") as c:
        without_index = await c.get("/login")
        asset = await c.get("/assets/app.js")

    full = _app_serving(_write_site(tmp_path / "full"), monkeypatch)
    async with AsyncClient(transport=ASGITransport(app=full), base_url="http://test") as c:
        with_index = await c.get("/login")

    assert (without_index.status_code, asset.status_code, _is_index(with_index)) == (404, 200, True)


# ---------------------------------------------------------------------------
# A 404.html in the static dir (security audit)
# ---------------------------------------------------------------------------


async def test_spa_fallback_with_404_page_client_route_still_gets_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 404.html (which StaticFiles' html mode returns instead of raising) doesn't
    replace the client-route fallback; a missing asset still answers 404."""
    static = _write_site(tmp_path)
    (static / "404.html").write_text("<html>not-found-page</html>")
    app = _app_serving(static, monkeypatch)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        route = await c.get("/reset-password")
        missing = await c.get("/assets/missing.js")

    assert (_is_index(route), missing.status_code) == (True, 404)
