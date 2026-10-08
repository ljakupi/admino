"""CORS preflights carry the response headers of their path (GH-286, Decision 1).

The CORS middleware answers a CORS preflight itself: an ``OPTIONS`` request with
``Origin`` and ``Access-Control-Request-Method``. It answers ``200`` when the
preflight is allowed and ``400`` when the origin, the method or a requested header
is not. Spec:

- Under ``/api`` (``/api`` itself or a path starting with ``/api/``): every such
  answer, allowed or refused, carries the headers of every other API response of the
  same app: the five security headers (``Content-Security-Policy``,
  ``X-Content-Type-Options``, ``X-Frame-Options``, ``Referrer-Policy``,
  ``Permissions-Policy``) with the same values, each once, and exactly one
  ``Cache-Control`` value, ``no-store``. Checked on two routes (``/api/message`` and
  ``/api/chats/{chat_id}/messages``), on ``/api`` itself and on an unknown ``/api/``
  path, for an allowed preflight and for one refused for its origin, for its method
  (``PUT``) and for a header (``Authorization``), against a real API answer of the
  same app (the ``401`` of ``/api/auth/me``).
- Other paths (``/``, the client route ``/chat``, ``/health`` and ``/apiary``, which
  is not under ``/api``): the preflight gets the security headers and no
  ``Cache-Control``, like ``/health``'s own answer.
- Unchanged: the CORS headers themselves (the allowed origin is ``server.public_url``
  only, the methods ``GET, POST, PATCH, DELETE``, ``Content-Type`` as the one
  configured request header, ``Authorization`` refused, no credentials), the answer
  to a simple cross-origin request, and an ``OPTIONS`` without
  ``Access-Control-Request-Method`` (not a preflight: the route answers its ``405``,
  with the API headers).
- docs/configuration.md: the ``no-store`` paragraph of ``### Compression and
  caching`` names preflights.

Each unchanged case is checked next to an ``/api`` preflight of the same app, so it
proves the rule is active *and* leaves that case as it is. ``Vary`` is checked only
for ``Origin``: Starlette's other ``Vary`` values differ between its versions.

Inputs: the app from ``create_app()`` (tests/tenancy_world.py's ``make_app``, no
static mount, ``public_url`` = ``tests.db_fakes.PUBLIC_URL``) behind the FakeDb, with
the database health check patched. Outputs: assertions only.

Security notes: every origin, path and id is a fixed fake value. No test reaches the
database, an LLM, Google or Microsoft.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final
from unittest.mock import AsyncMock

import pytest

from tests.db_fakes import PUBLIC_URL, FakeDb
from tests.tenancy_world import (
    UNAUTHORIZED,
    make_app,
    make_client,
    use_fake_database,
    use_roomy_rate_limits,
)
from tests.test_api_no_store import _SECURITY_HEADERS

if TYPE_CHECKING:
    import httpx
    from fastapi.testclient import TestClient

_CONFIGURATION: Final = Path(__file__).resolve().parent.parent / "docs" / "configuration.md"
_CACHING_HEADING: Final = "### Compression and caching"

_OTHER_ORIGIN: Final = "https://attacker.example.net"
_CHAT_MESSAGES_PATH: Final = "/api/chats/28600000-0000-4000-8000-000000000286/messages"
_UNKNOWN_API_PATH: Final = "/api/does-not-exist-286"
# A route, a route with a path parameter, /api itself and a path no route serves.
_API_PATHS: Final = ("/api/message", _CHAT_MESSAGES_PATH, "/api", _UNKNOWN_API_PATH)
# The PWA's root, a client route, the health check and a path that only starts like /api.
_PAGE_PATHS: Final = ("/", "/chat", "/health", "/apiary")

# What every API answer carries: each security header once, and one Cache-Control, no-store.
_API_RESPONSE_HEADERS: Final = {
    **{name: [value] for name, value in _SECURITY_HEADERS.items()},
    "cache-control": ["no-store"],
}
# What every other answer carries: each security header once, and no Cache-Control.
_PAGE_RESPONSE_HEADERS: Final = {
    **{name: [value] for name, value in _SECURITY_HEADERS.items()},
    "cache-control": [],
}

# The CORS configuration's answers today (create_app's CORSMiddleware): the configured
# methods, and Content-Type next to the CORS-safelisted headers Starlette always allows.
_ALLOW_METHODS: Final = ["GET, POST, PATCH, DELETE"]
_ALLOW_HEADERS: Final = ["Accept, Accept-Language, Content-Language, Content-Type"]
_MAX_AGE: Final = ["600"]
_METHOD_NOT_ALLOWED: Final = {"detail": "Method Not Allowed"}


@dataclass(frozen=True)
class _Preflight:
    """A CORS preflight: its ``Origin``, requested method and header, and the status."""

    origin: str
    method: str
    request_headers: str
    status: int


_PREFLIGHTS: Final = {
    "allowed": _Preflight(PUBLIC_URL, "POST", "Content-Type", 200),
    "unknown-origin": _Preflight(_OTHER_ORIGIN, "POST", "Content-Type", 400),
    "method-not-allowed": _Preflight(PUBLIC_URL, "PUT", "Content-Type", 400),
    "header-not-allowed": _Preflight(PUBLIC_URL, "POST", "Authorization", 400),
}


def _send_preflight(client: TestClient, path: str, preflight: _Preflight) -> httpx.Response:
    """``OPTIONS path`` with the preflight's ``Origin`` and ``Access-Control-Request-*``."""
    return client.options(
        path,
        headers={
            "Origin": preflight.origin,
            "Access-Control-Request-Method": preflight.method,
            "Access-Control-Request-Headers": preflight.request_headers,
        },
    )


def _response_headers(response: httpx.Response) -> dict[str, list[str]]:
    """Every value of each security header and of ``Cache-Control``, one entry per line."""
    names = (*_SECURITY_HEADERS, "cache-control")
    return {name: response.headers.get_list(name) for name in names}


def _cors_headers(response: httpx.Response) -> dict[str, object]:
    """The preflight answer's status, CORS headers (every value) and ``Cache-Control``.

    ``Vary`` only as "names ``Origin``": its other values depend on Starlette's version.
    """
    vary = {
        token.strip() for value in response.headers.get_list("vary") for token in value.split(",")
    }
    return {
        "status": response.status_code,
        "allow-origin": response.headers.get_list("access-control-allow-origin"),
        "allow-credentials": response.headers.get_list("access-control-allow-credentials"),
        "allow-methods": response.headers.get_list("access-control-allow-methods"),
        "allow-headers": response.headers.get_list("access-control-allow-headers"),
        "max-age": response.headers.get_list("access-control-max-age"),
        "vary-origin": "Origin" in vary,
        "cache-control": response.headers.get_list("cache-control"),
    }


def _section(text: str, heading: str) -> str:
    """The lines after ``heading`` up to the next heading of level 1 to 3 (outside fences)."""
    lines = text.splitlines()
    start = lines.index(heading) + 1
    in_fence = False
    for offset, line in enumerate(lines[start:]):
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
        elif not in_fence and re.match(r"#{1,3} ", line):
            return "\n".join(lines[start : start + offset])
    return "\n".join(lines[start:])


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """The app (no static mount) behind an empty FakeDb, roomy rate buckets and a
    patched database health check, and a client that doesn't follow redirects."""
    use_fake_database(monkeypatch, FakeDb())
    use_roomy_rate_limits(monkeypatch)
    monkeypatch.setattr("admino.database.check_health", AsyncMock(return_value=True))
    return make_client(make_app())


# ---------------------------------------------------------------------------
# 1. Under /api: the headers of every other API answer
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", list(_PREFLIGHTS))
def test_api_preflight_headers_api_paths_carry_the_api_response_headers(
    client: TestClient, kind: str
) -> None:
    """An allowed preflight (200) and each refused one (400) to a route, a route with a
    path parameter, ``/api`` itself and an unknown ``/api/`` path carry exactly the
    security headers and the ``Cache-Control: no-store`` of a real API answer of the
    same app (the ``401`` of ``/api/auth/me``)."""
    preflight = _PREFLIGHTS[kind]
    reference = client.get("/api/auth/me")

    seen = {
        path: (response.status_code, _response_headers(response))
        for path in _API_PATHS
        for response in [_send_preflight(client, path, preflight)]
    }

    assert (reference.status_code, reference.json(), _response_headers(reference)) == (
        401,
        UNAUTHORIZED,
        _API_RESPONSE_HEADERS,
    )
    assert seen == dict.fromkeys(_API_PATHS, (preflight.status, _response_headers(reference)))


# ---------------------------------------------------------------------------
# 2. Other paths: the security headers, no Cache-Control
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["allowed", "unknown-origin"])
def test_api_preflight_headers_other_paths_carry_the_security_headers_only(
    client: TestClient, kind: str
) -> None:
    """A preflight to ``/``, ``/chat``, ``/health`` and ``/apiary`` carries the security
    headers of ``/health``'s own answer and no ``Cache-Control``, while the same
    preflight to ``/api/message`` carries ``no-store``."""
    preflight = _PREFLIGHTS[kind]
    reference = client.get("/health")
    paths = (*_PAGE_PATHS, "/api/message")

    seen = {
        path: (response.status_code, _response_headers(response))
        for path in paths
        for response in [_send_preflight(client, path, preflight)]
    }

    assert (reference.status_code, _response_headers(reference)) == (200, _PAGE_RESPONSE_HEADERS)
    assert seen == {
        **dict.fromkeys(_PAGE_PATHS, (preflight.status, _response_headers(reference))),
        "/api/message": (preflight.status, _API_RESPONSE_HEADERS),
    }


# ---------------------------------------------------------------------------
# 3. What stays as it is: the CORS headers, simple requests, non-preflight OPTIONS
# ---------------------------------------------------------------------------


def test_api_preflight_headers_keep_the_cors_headers(client: TestClient) -> None:
    """The CORS answers are today's: the allowed origin (``server.public_url``) is echoed
    and an unknown one is not, the methods and the allowed headers (``Content-Type``
    and the safelisted ones, never ``Authorization``) are unchanged, nothing allows
    credentials and ``Vary`` names ``Origin``; ``Cache-Control: no-store`` is added
    under ``/api`` only (``/`` gets none)."""
    common = {
        "allow-credentials": [],
        "allow-methods": _ALLOW_METHODS,
        "allow-headers": _ALLOW_HEADERS,
        "max-age": _MAX_AGE,
        "vary-origin": True,
    }

    seen = {
        kind: _cors_headers(_send_preflight(client, "/api/message", preflight))
        for kind, preflight in _PREFLIGHTS.items()
    }
    seen["page"] = _cors_headers(_send_preflight(client, "/", _PREFLIGHTS["allowed"]))

    assert seen == {
        "allowed": {
            **common,
            "status": 200,
            "allow-origin": [PUBLIC_URL],
            "cache-control": ["no-store"],
        },
        "unknown-origin": {
            **common,
            "status": 400,
            "allow-origin": [],
            "cache-control": ["no-store"],
        },
        "method-not-allowed": {
            **common,
            "status": 400,
            "allow-origin": [PUBLIC_URL],
            "cache-control": ["no-store"],
        },
        "header-not-allowed": {
            **common,
            "status": 400,
            "allow-origin": [PUBLIC_URL],
            "cache-control": ["no-store"],
        },
        "page": {**common, "status": 200, "allow-origin": [PUBLIC_URL], "cache-control": []},
    }


def test_api_preflight_headers_keep_simple_cross_origin_answers(client: TestClient) -> None:
    """A simple request with an ``Origin`` (``GET /api/auth/me``) answers as today: the
    allowed origin is echoed, an unknown one is not, no credentials, and the API
    headers; an ``/api`` preflight of the same app carries the same API headers."""
    seen = {
        name: (
            response.status_code,
            response.headers.get_list("access-control-allow-origin"),
            response.headers.get_list("access-control-allow-credentials"),
            _response_headers(response),
        )
        for name, origin in (("allowed", PUBLIC_URL), ("unknown", _OTHER_ORIGIN))
        for response in [client.get("/api/auth/me", headers={"Origin": origin})]
    }
    control = _send_preflight(client, "/api/message", _PREFLIGHTS["allowed"])
    seen["preflight"] = (
        control.status_code,
        control.headers.get_list("access-control-allow-origin"),
        control.headers.get_list("access-control-allow-credentials"),
        _response_headers(control),
    )

    assert seen == {
        "allowed": (401, [PUBLIC_URL], [], _API_RESPONSE_HEADERS),
        "unknown": (401, [], [], _API_RESPONSE_HEADERS),
        "preflight": (200, [PUBLIC_URL], [], _API_RESPONSE_HEADERS),
    }


def test_api_preflight_headers_options_without_request_method_is_not_a_preflight(
    client: TestClient,
) -> None:
    """An ``OPTIONS`` without ``Access-Control-Request-Method`` (with or without an
    ``Origin``) reaches the route as today: ``405`` with ``Allow: POST`` and the API
    headers, the allowed origin echoed. A real preflight to the same path answers
    ``200`` with the same API headers."""
    seen = {
        name: (
            response.status_code,
            response.json(),
            response.headers.get_list("allow"),
            response.headers.get_list("access-control-allow-origin"),
            _response_headers(response),
        )
        for name, headers in (("no-origin", {}), ("origin", {"Origin": PUBLIC_URL}))
        for response in [client.options("/api/message", headers=headers)]
    }
    control = _send_preflight(client, "/api/message", _PREFLIGHTS["allowed"])

    assert seen == {
        "no-origin": (405, _METHOD_NOT_ALLOWED, ["POST"], [], _API_RESPONSE_HEADERS),
        "origin": (405, _METHOD_NOT_ALLOWED, ["POST"], [PUBLIC_URL], _API_RESPONSE_HEADERS),
    }
    assert (control.status_code, _response_headers(control)) == (200, _API_RESPONSE_HEADERS)


# ---------------------------------------------------------------------------
# 4. Docs
# ---------------------------------------------------------------------------


def test_api_preflight_headers_docs_no_store_paragraph_names_preflights() -> None:
    """docs/configuration.md, ``### Compression and caching``: the paragraph that states
    ``no-store`` for API responses names preflights (case-insensitive)."""
    section = _section(_CONFIGURATION.read_text(encoding="utf-8"), _CACHING_HEADING)
    paragraphs = [block for block in re.split(r"\n[ \t]*\n", section) if "no-store" in block]

    assert paragraphs, "the section has no no-store paragraph"
    assert any("preflight" in block.casefold() for block in paragraphs), paragraphs
