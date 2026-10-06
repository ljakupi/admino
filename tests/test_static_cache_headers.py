"""Cache headers of the PWA static mount (GH-244, decision 5).

``create_app`` mounts the built PWA at ``/`` (``server._SpaStaticFiles``). Vite
names every bundled file ``assets/<name>-<8-char hash>.<ext>``, so such a file
never changes under its name and may be cached for a year. Every other file the
mount serves keeps its name across releases and must be revalidated. Spec:

- A hashed asset (a path that fully matches
  ``assets/[^/]+-[A-Za-z0-9_-]{8}\\.[A-Za-z0-9]+``) answers
  ``Cache-Control: public, max-age=31536000, immutable`` on 200 (GET and HEAD)
  and on the 304 a matching ``If-None-Match`` gets.
- Everything else the mount serves answers ``Cache-Control: no-cache`` (also on
  its 304): ``/``, ``/index.html``, the client-route fallback (``/chat``,
  ``/login``, nested routes), ``service-worker.js`` (the issue's "sw.js"),
  ``registerSW.js``, ``manifest.webmanifest``, ``workbox-<hash>.js`` (hash-shaped
  but outside ``assets/``), fonts, icons, the logo and unhashed files under
  ``assets/``.
- A missing file (404) never gets ``immutable``; neither do ``/health`` nor an
  unknown ``/api`` path (the API is not touched by this change).
- Each file's body and content type are unchanged, and the security headers
  are still sent.

Every negative case is checked next to a hashed asset of the same app, so each
test proves the cache rule is active *and* excludes that case.

The app is built with ``ADMINO_STATIC_DIR`` pointing at a ``tmp_path`` static
dir laid out like Vite's output; no database, LLM or session is involved (the
static mount is public).
"""

from __future__ import annotations

import mimetypes
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

IMMUTABLE = "public, max-age=31536000, immutable"
NO_CACHE = "no-cache"

INDEX_HTML = b"<html>gh244-spa-index</html>"

# The static dir, laid out like Vite + vite-plugin-pwa's output (relative path -> bytes).
_FILES: dict[str, bytes] = {
    "index.html": INDEX_HTML,
    "service-worker.js": b"self.addEventListener('install', () => self.skipWaiting());",
    "registerSW.js": b"navigator.serviceWorker.register('/service-worker.js');",
    "manifest.webmanifest": b'{"name":"admino","start_url":"/","display":"standalone"}',
    "workbox-8c29f6e4.js": b"define(['exports'], function (e) { 'use strict'; });",
    "assets/index-Bwk_qOWV.js": b"import('./ChatPage-C7FiilKt.js');export const entry=1;",
    "assets/ChatPage-B-fjYGjp.css": b".chat-page{display:flex;flex-direction:column}",
    "assets/authFlows-D2_0a0ZU.css": b".auth-flow{margin:0 auto;max-width:28rem}",
    "assets/name-with-dashes-BzLBVthp.js": b"export const nameWithDashes = true;",
    "assets/readme.txt": b"an unhashed file under assets",
    "assets/release-notes.txt": b"an unhashed name with a dash under assets",
    "fonts/Inter_18pt-Regular.ttf": bytes(range(256)) * 4,
    "icons/icon-192.png": b"\x89PNG\r\n\x1a\n" + bytes(range(64)),
    "admino_logo.svg": b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"></svg>',
}

# Vite's hashed names: plain, a dash inside the hash, an underscore inside the
# hash, dashes inside the name.
HASHED_ASSETS = [
    "assets/index-Bwk_qOWV.js",
    "assets/ChatPage-B-fjYGjp.css",
    "assets/authFlows-D2_0a0ZU.css",
    "assets/name-with-dashes-BzLBVthp.js",
]

# Files whose name stays the same across releases.
UNHASHED_FILES = [
    "index.html",
    "service-worker.js",
    "registerSW.js",
    "manifest.webmanifest",
    "workbox-8c29f6e4.js",
    "fonts/Inter_18pt-Regular.ttf",
    "icons/icon-192.png",
    "admino_logo.svg",
    "assets/readme.txt",
    "assets/release-notes.txt",
]

# Paths answered with index.html: the root and client routes (SPA fallback).
INDEX_PATHS = ["/", "/chat", "/login", "/settings/nested/path"]

# The security headers every response keeps (SecurityHeadersMiddleware).
_SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
}


def _make_config() -> Any:
    """Build a minimal mock AppConfig with JSON-serializable /health fields."""
    config = MagicMock()
    del config.auth
    config.limits.max_message_length = 4000
    config.llm.provider = "infomaniak"
    config.llm.active_model_name = "test-model"
    return config


def _write_site(root: Path) -> Path:
    """Write the Vite-like static dir under ``root`` and return it."""
    static = root / "static"
    for rel, content in _FILES.items():
        target = static / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return static


def _media_type(resp: Response) -> str:
    """The response's media type without parameters (charset)."""
    return str(resp.headers.get("content-type", "")).split(";")[0].strip()


def _expected_media_type(rel: str) -> str:
    """The media type StaticFiles has always sent for ``rel`` (unchanged by this issue)."""
    return mimetypes.guess_type(rel)[0] or "text/plain"


def _security_headers_kept(resp: Response) -> bool:
    """Whether the response still carries every security header (CSP included)."""
    simple = all(resp.headers.get(name) == value for name, value in _SECURITY_HEADERS.items())
    csp = resp.headers.get("content-security-policy", "")
    return simple and csp.startswith("default-src 'self'")


def _served(resp: Response) -> tuple[int, str | None, bytes, str, bool]:
    """What a client sees: status, Cache-Control, body, media type, security headers kept."""
    return (
        resp.status_code,
        resp.headers.get("cache-control"),
        resp.content,
        _media_type(resp),
        _security_headers_kept(resp),
    )


def _revalidated(resp: Response) -> tuple[int, str | None, bytes, bool]:
    """A conditional request's outcome: status, Cache-Control, body, security headers kept."""
    return (
        resp.status_code,
        resp.headers.get("cache-control"),
        resp.content,
        _security_headers_kept(resp),
    )


@pytest_asyncio.fixture
async def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[AsyncClient]:
    """An HTTP client for an app whose static dir is laid out like Vite's output."""
    monkeypatch.setenv("ADMINO_STATIC_DIR", str(_write_site(tmp_path)))
    app = create_app(agent=MagicMock(), config=_make_config())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# Hashed assets: cached for a year, immutable
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rel", HASHED_ASSETS)
async def test_static_cache_hashed_asset_get_immutable(client: AsyncClient, rel: str) -> None:
    """A hashed asset answers 200 with the year-long immutable Cache-Control, its body and
    content type unchanged and the security headers kept."""
    resp = await client.get(f"/{rel}")

    assert _served(resp) == (200, IMMUTABLE, _FILES[rel], _expected_media_type(rel), True)


async def test_static_cache_hashed_asset_head_immutable(client: AsyncClient) -> None:
    """HEAD of a hashed asset answers 200 with the immutable Cache-Control and no body."""
    rel = "assets/index-Bwk_qOWV.js"

    resp = await client.head(f"/{rel}")

    assert _served(resp) == (200, IMMUTABLE, b"", _expected_media_type(rel), True)


@pytest.mark.parametrize("method", ["GET", "HEAD"])
async def test_static_cache_hashed_asset_not_modified_keeps_immutable(
    client: AsyncClient, method: str
) -> None:
    """A revalidation with the asset's own ETag is a 304 that keeps the immutable header."""
    first = await client.get("/assets/ChatPage-B-fjYGjp.css")
    etag = first.headers["etag"]

    resp = await client.request(
        method, "/assets/ChatPage-B-fjYGjp.css", headers={"If-None-Match": etag}
    )

    assert _revalidated(resp) == (304, IMMUTABLE, b"", True)


# ---------------------------------------------------------------------------
# Everything else the mount serves: revalidated on every use
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rel", UNHASHED_FILES)
async def test_static_cache_unhashed_file_get_no_cache(client: AsyncClient, rel: str) -> None:
    """A file whose name doesn't change across releases answers 200 with ``no-cache``, its
    body and content type unchanged and the security headers kept."""
    resp = await client.get(f"/{rel}")

    assert _served(resp) == (200, NO_CACHE, _FILES[rel], _expected_media_type(rel), True)


@pytest.mark.parametrize("path", INDEX_PATHS)
async def test_static_cache_index_and_client_route_no_cache(client: AsyncClient, path: str) -> None:
    """The root and every client route (SPA fallback) answer index.html with ``no-cache``."""
    resp = await client.get(path)

    assert _served(resp) == (200, NO_CACHE, INDEX_HTML, "text/html", True)


@pytest.mark.parametrize("path", ["/", "/service-worker.js"])
async def test_static_cache_head_index_and_service_worker_no_cache(
    client: AsyncClient, path: str
) -> None:
    """HEAD of index.html and of the service worker answers 200 with ``no-cache``."""
    resp = await client.head(path)

    assert (resp.status_code, resp.headers.get("cache-control"), resp.content) == (
        200,
        NO_CACHE,
        b"",
    )


@pytest.mark.parametrize("path", ["/", "/chat", "/service-worker.js"])
async def test_static_cache_unhashed_not_modified_keeps_no_cache(
    client: AsyncClient, path: str
) -> None:
    """A revalidation of index.html (also through a client route) or the service worker with
    its own ETag is a 304 that keeps ``no-cache``."""
    first = await client.get(path)
    etag = first.headers["etag"]

    resp = await client.get(path, headers={"If-None-Match": etag})

    assert _revalidated(resp) == (304, NO_CACHE, b"", True)


# ---------------------------------------------------------------------------
# What never gets immutable
# ---------------------------------------------------------------------------


async def test_static_cache_missing_hashed_asset_404_never_immutable(
    client: AsyncClient,
) -> None:
    """A missing file with a hash-shaped name stays 404 without ``immutable``, while a real
    hashed asset of the same app is immutable."""
    missing = await client.get("/assets/missing-ABCDEFGH.js")
    hit = await client.get("/assets/index-Bwk_qOWV.js")

    assert (
        missing.status_code,
        "immutable" in missing.headers.get("cache-control", ""),
        hit.headers.get("cache-control"),
    ) == (404, False, IMMUTABLE)


@pytest.mark.parametrize(("path", "status"), [("/health", 200), ("/api/does-not-exist", 404)])
async def test_static_cache_health_and_api_never_immutable(
    client: AsyncClient, path: str, status: int
) -> None:
    """``/health`` and an unknown API path never get ``immutable`` (the API isn't touched),
    while a hashed asset of the same app is immutable."""
    with (
        patch("admino.database.check_health", new=AsyncMock(return_value=True)),
        patch("admino.server._check_llm_reachable", new=AsyncMock(return_value=True)),
    ):
        resp = await client.get(path)
    hit = await client.get("/assets/name-with-dashes-BzLBVthp.js")

    assert (
        resp.status_code,
        "immutable" in resp.headers.get("cache-control", ""),
        hit.headers.get("cache-control"),
    ) == (status, False, IMMUTABLE)
