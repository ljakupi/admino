"""The production profile's Caddy proxy: compression and unbuffered streams (GH-244, decision 6).

``deploy/caddy/Caddyfile`` compresses every response with zstd (else gzip),
except a chat event stream: a request with ``Accept: text/event-stream`` is
excluded by a named request matcher, and the reverse proxy flushes every write
at once (``flush_interval -1``), so a streamed answer reaches the browser frame
by frame. Spec:

Part A, always run: a static check of the Caddyfile's text (comments and
whitespace tolerated).
- The ``{$ADMINO_DOMAIN}`` site block has exactly one ``encode``, guarded by a
  named matcher defined as ``not header Accept *text/event-stream*``, with the
  formats ``zstd gzip`` in that order.
- ``reverse_proxy agent:8000`` with ``flush_interval -1``.
- What must stay: no ``log`` directive in the site block (no access log: tokens
  travel in URL paths), the HSTS header, ``-Server`` and ``-Via`` (deferred), and
  the global ``admin off``.

Part B, on demand (``ADMINO_DOCKER_TESTS=1``, ``make test-proxy``): the REPO's
Caddyfile runs in the official ``caddy:2.11.4-alpine`` image (``ADMINO_DOMAIN=localhost``,
Caddy's internal CA) in front of a stub upstream with the network alias ``agent``.
- A ~20 KB JavaScript asset arrives zstd-encoded for ``Accept-Encoding: zstd, gzip``
  and gzip-encoded for ``gzip`` only, with the upstream's Cache-Control kept and the
  decoded body identical; a ~2 KB JSON body is compressed too.
- A chat send with ``Accept: text/event-stream`` (same Accept-Encoding) is not
  encoded, keeps its content type, and its frames, written 1.5 s apart, arrive one
  by one in order. Its first frame is larger than Caddy's 512-byte minimum length,
  so an unguarded ``encode`` would compress it.
Without Docker the part is skipped with its reason (decision 6: the proxy test
needs Docker, so it runs on demand).

Security notes:
- Every Docker object is named ``admino-gh244-proxy-<random>`` and removed in the
  fixture's ``finally``; the developer's own ``admino-*`` stack is never touched.
- Caddy publishes 443 on 127.0.0.1 only; the stub upstream isn't published.
- ``subprocess.run`` with fixed argv lists, never a shell.
"""

from __future__ import annotations

import gzip
import itertools
import json
import os
import secrets
import shlex
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

# The repository the tests run from (so a scratch copy checks its own Caddyfile).
_TREE_ROOT = Path(__file__).resolve().parents[1]
_CADDYFILE = _TREE_ROOT / "deploy" / "caddy" / "Caddyfile"

_SITE_ADDRESS = "{$ADMINO_DOMAIN}"
# The matcher definition that excludes a chat event stream (header name case-insensitive).
_SSE_EXCLUDED = ("not", "header", "accept", "*text/event-stream*")

IMMUTABLE = "public, max-age=31536000, immutable"


# ---------------------------------------------------------------------------
# A small Caddyfile reader: directives with their tokens and sub-blocks
# ---------------------------------------------------------------------------


@dataclass
class _Directive:
    """One Caddyfile line's tokens and, when it opens a block, the block's directives."""

    tokens: list[str]
    children: list[_Directive] = field(default_factory=list)


def _parse(text: str) -> list[_Directive]:
    """Parse Caddyfile text into top-level directives.

    Each line is split like a shell line (quotes kept together, ``#`` comments
    dropped). A line ending in ``{`` opens a block that a line ``}`` closes;
    the top-level global options block is the directive with no tokens.
    """
    root: list[_Directive] = []
    stack: list[list[_Directive]] = [root]
    for line in text.splitlines():
        tokens = shlex.split(line, comments=True)
        if not tokens:
            continue
        if tokens == ["}"]:
            assert len(stack) > 1, "unbalanced '}' in the Caddyfile"
            stack.pop()
            continue
        if tokens[-1] == "{":
            directive = _Directive(tokens[:-1])
            stack[-1].append(directive)
            stack.append(directive.children)
        else:
            stack[-1].append(_Directive(tokens))
    assert len(stack) == 1, "unclosed block in the Caddyfile"
    return root


def _blocks() -> list[_Directive]:
    """The shipped Caddyfile, parsed."""
    return _parse(_CADDYFILE.read_text(encoding="utf-8"))


def _site() -> list[_Directive]:
    """The directives of the ``{$ADMINO_DOMAIN}`` site block (exactly one such block)."""
    sites = [d for d in _blocks() if d.tokens == [_SITE_ADDRESS]]
    assert len(sites) == 1, "the Caddyfile has no single {$ADMINO_DOMAIN} site block"
    assert sites[0].children, "the {$ADMINO_DOMAIN} site block is empty"
    return sites[0].children


def _global_options() -> list[_Directive]:
    """The directives of the global options block (the leading ``{ ... }``)."""
    blocks = [d for d in _blocks() if d.tokens == []]
    assert len(blocks) == 1, "the Caddyfile has no single global options block"
    return blocks[0].children


def _walk(directives: list[_Directive]) -> Iterator[_Directive]:
    """Every directive, nested ones included."""
    for directive in directives:
        yield directive
        yield from _walk(directive.children)


def _flat(directive: _Directive) -> list[str]:
    """A directive's tokens followed by its block's tokens (``@m { not { header ... } }``)."""
    tokens = list(directive.tokens)
    for child in directive.children:
        tokens.extend(_flat(child))
    return tokens


def _named_matchers(site: list[_Directive]) -> dict[str, tuple[str, ...]]:
    """Each named matcher of the site block -> its normalised definition.

    The single-line form ``@m not header Accept x`` and the block forms give the
    same definition; a header field name is compared case-insensitively.
    """
    matchers: dict[str, tuple[str, ...]] = {}
    for directive in site:
        if not directive.tokens[0].startswith("@"):
            continue
        definition = _flat(directive)[1:]
        if len(definition) > 2 and definition[1] == "header":
            definition[2] = definition[2].lower()
        matchers[directive.tokens[0]] = tuple(definition)
    return matchers


def _header_ops(site: list[_Directive]) -> list[tuple[str, ...]]:
    """Every header operation of the site block (inline ``header X v`` or inside ``header {}``)."""
    ops: list[tuple[str, ...]] = []
    for directive in site:
        if directive.tokens[0] != "header":
            continue
        if len(directive.tokens) > 1:
            ops.append(tuple(directive.tokens[1:]))
        ops.extend(tuple(child.tokens) for child in directive.children)
    return ops


# ---------------------------------------------------------------------------
# Part A: the Caddyfile's text
# ---------------------------------------------------------------------------


def test_proxy_profile_caddyfile_encodes_zstd_then_gzip_except_event_streams() -> None:
    """The site block has one ``encode`` with ``zstd gzip`` (zstd first), guarded by a named
    matcher that excludes requests accepting ``text/event-stream``."""
    site = _site()
    matchers = _named_matchers(site)
    encodes = []
    for directive in site:
        if directive.tokens[0] != "encode":
            continue
        args = directive.tokens[1:]
        matcher = args.pop(0) if args and args[0].startswith("@") else None
        formats = args + [
            c.tokens[0] for c in directive.children if c.tokens[0] in {"zstd", "gzip"}
        ]
        encodes.append((matchers.get(matcher) if matcher else None, formats))

    assert encodes == [(_SSE_EXCLUDED, ["zstd", "gzip"])]


def test_proxy_profile_caddyfile_reverse_proxy_flushes_immediately() -> None:
    """The site block proxies to ``agent:8000`` with ``flush_interval -1`` (never buffered)."""
    proxies = [
        (d.tokens[1:], [c.tokens for c in d.children if c.tokens[0] == "flush_interval"])
        for d in _site()
        if d.tokens[0] == "reverse_proxy"
    ]

    assert proxies == [(["agent:8000"], [["flush_interval", "-1"]])]


@pytest.mark.parametrize(
    "guard",
    ["no-site-log", "hsts", "strip-server", "strip-via", "header-defer", "admin-off"],
)
def test_proxy_profile_caddyfile_hardening_kept(guard: str) -> None:
    """The proxy's hardening stays: no access log, HSTS, no Server/Via banner (deferred so it
    wins over the agent's headers), no admin API."""
    site = _site()
    ops = _header_ops(site)
    kept = {
        "no-site-log": not any(d.tokens[0] == "log" for d in _walk(site)),
        "hsts": ("Strict-Transport-Security", "max-age=31536000; includeSubDomains") in ops,
        "strip-server": ("-Server",) in ops,
        "strip-via": ("-Via",) in ops,
        "header-defer": ("defer",) in ops,
        "admin-off": ["admin", "off"] in [d.tokens for d in _global_options()],
    }

    assert kept[guard] is True


# ---------------------------------------------------------------------------
# Part B: a real Caddy in front of a stub upstream (Docker, on demand)
# ---------------------------------------------------------------------------

_DOCKER_ENV = "ADMINO_DOCKER_TESTS"
_CADDY_IMAGE = "caddy:2.11.4-alpine"
_PYTHON_IMAGE = "python:3.12.8-slim"
_NAME_PREFIX = "admino-gh244-proxy-"

_ASSET_PATH = "/assets/index-Bwk_qOWV.js"
_JSON_PATH = "/api/perf-probe"
_SSE_PATH = "/api/chats/5d1c0f7e-6b0a-4c55-9d1e-0c2f6a1b7e42/messages"

# ~20 KB of JavaScript and ~2 KB of JSON: both above Caddy's minimum length.
_ASSET = "".join(
    f"export const gh244Value{i} = {i} * 2; // padding line {i} of the bundle\n" for i in range(300)
).encode()
_JSON = json.dumps(
    {"chats": [{"id": f"chat-{i:04d}", "title": f"Conversation {i}"} for i in range(50)]}
).encode()
# Three chat frames, written 1.5 s apart by the upstream. The first one is larger
# than Caddy's minimum length for encoding (512 bytes), as a long first delta is:
# a small first write is never encoded anyway, so only a large one shows that the
# event stream is excluded from compression.
_FIRST_DELTA = " ".join(f"word{i}" for i in range(150))
_FRAMES = [
    f'event: delta\ndata: {{"text": "{_FIRST_DELTA}"}}\n\n'.encode(),
    b'event: delta\ndata: {"text": " and the second part"}\n\n',
    b'event: final\ndata: {"text": "done"}\n\n',
]
_FRAME_GAP_S = 1.5

# The stub upstream: Python's stdlib http.server on port 8000 (the agent's port).
_UPSTREAM_PY = r'''
"""Stub agent for the proxy test: an asset, a JSON body and a chat event stream."""
import http.server
import json
import pathlib
import re
import time

ROOT = pathlib.Path("/srv")
ASSET = (ROOT / "asset.js").read_bytes()
DATA = (ROOT / "data.json").read_bytes()
SETTINGS = json.loads((ROOT / "settings.json").read_text())


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _body(self, body, content_type, cache_control=None):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if cache_control:
            self.send_header("Cache-Control", cache_control)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        if self.path == SETTINGS["asset_path"]:
            self._body(ASSET, "application/javascript", SETTINGS["asset_cache_control"])
        elif self.path == SETTINGS["json_path"]:
            self._body(DATA, "application/json")
        else:
            self.send_error(404)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if not re.fullmatch(r"/api/chats/[^/]+/messages", self.path):
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        self.wfile.flush()
        for index, frame in enumerate(SETTINGS["frames"]):
            if index:
                time.sleep(SETTINGS["gap_s"])
            data = frame.encode()
            self.wfile.write(b"%x\r\n" % len(data) + data + b"\r\n")
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()


http.server.ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
'''

# Decodes a zstd body from stdin with the image's libzstd (no zstd module on the host).
_UNZSTD_PY = r'''
"""Decode a zstd-encoded body from stdin to stdout with libzstd."""
import ctypes
import sys

lib = ctypes.CDLL("libzstd.so.1")
lib.ZSTD_decompress.restype = ctypes.c_size_t
lib.ZSTD_decompress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
lib.ZSTD_isError.restype = ctypes.c_uint
lib.ZSTD_isError.argtypes = [ctypes.c_size_t]
src = sys.stdin.buffer.read()
capacity = 8 * 1024 * 1024
dst = ctypes.create_string_buffer(capacity)
size = lib.ZSTD_decompress(dst, capacity, src, len(src))
if lib.ZSTD_isError(size):
    sys.exit("not a valid zstd stream")
sys.stdout.buffer.write(dst.raw[:size])
'''


@dataclass(frozen=True)
class _Proxy:
    """The running proxy: its HTTPS base URL and the stub upstream's container."""

    base_url: str
    upstream: str


def _docker(*args: str, timeout: float = 120.0, stdin: bytes | None = None) -> bytes:
    """Run ``docker <args>``; fail the test with docker's message when it fails."""
    result = subprocess.run(  # noqa: S603
        ["docker", *args],  # noqa: S607
        input=stdin,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    assert result.returncode == 0, (
        f"docker {args[0]} failed: {result.stderr.decode(errors='replace')}"
    )
    return result.stdout


def _docker_quiet(*args: str) -> None:
    """Run ``docker <args>`` for cleanup, ignoring failures (the object may not exist)."""
    subprocess.run(  # noqa: S603
        ["docker", *args],  # noqa: S607
        capture_output=True,
        timeout=60,
        check=False,
    )


def _docker_skip_reason() -> str | None:
    """Why the Docker part can't run here, or None when it can."""
    if os.environ.get(_DOCKER_ENV) != "1":
        return f"Docker proxy test runs on demand: set {_DOCKER_ENV}=1 (make test-proxy)"
    if shutil.which("docker") is None:
        return "Docker proxy test needs the docker CLI"
    info = subprocess.run(  # noqa: S603
        ["docker", "info"],  # noqa: S607
        capture_output=True,
        timeout=60,
        check=False,
    )
    if info.returncode != 0:
        return "Docker proxy test needs a running Docker daemon (docker info failed)"
    return None


def _free_port() -> int:
    """A free TCP port on 127.0.0.1 for Caddy's published 443."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _client(base_url: str) -> httpx.Client:
    """An HTTPS client for the proxy (Caddy's internal CA for localhost isn't trusted)."""
    return httpx.Client(base_url=base_url, verify=False, timeout=15.0)  # noqa: S501


def _wait_ready(base_url: str, names: list[str]) -> None:
    """Wait until Caddy answers the upstream's JSON through TLS (60 s at most)."""
    deadline = time.monotonic() + 60.0
    last = "no answer"
    with _client(base_url) as client:
        while time.monotonic() < deadline:
            try:
                resp = client.get(_JSON_PATH)
            except httpx.TransportError as exc:
                last = type(exc).__name__
            else:
                if resp.status_code == 200:
                    return
                last = f"HTTP {resp.status_code}"
            time.sleep(0.5)
    logs = "\n".join(
        subprocess.run(  # noqa: S603
            ["docker", "logs", "--tail", "30", name],  # noqa: S607
            capture_output=True,
            timeout=30,
            check=False,
            text=True,
        ).stderr
        for name in names
    )
    pytest.fail(f"the proxy never answered ({last}); container logs:\n{logs}")


@pytest.fixture(scope="module")
def proxy(tmp_path_factory: pytest.TempPathFactory) -> Iterator[_Proxy]:
    """Caddy (the repo's Caddyfile) in front of the stub upstream, removed afterwards."""
    reason = _docker_skip_reason()
    if reason is not None:
        pytest.skip(reason)

    srv = tmp_path_factory.mktemp("gh244-proxy-upstream").resolve()
    (srv / "upstream.py").write_text(_UPSTREAM_PY, encoding="utf-8")
    (srv / "unzstd.py").write_text(_UNZSTD_PY, encoding="utf-8")
    (srv / "asset.js").write_bytes(_ASSET)
    (srv / "data.json").write_bytes(_JSON)
    settings = {
        "asset_path": _ASSET_PATH,
        "asset_cache_control": IMMUTABLE,
        "json_path": _JSON_PATH,
        "frames": [frame.decode() for frame in _FRAMES],
        "gap_s": _FRAME_GAP_S,
    }
    (srv / "settings.json").write_text(json.dumps(settings), encoding="utf-8")

    suffix = secrets.token_hex(4)
    network = f"{_NAME_PREFIX}{suffix}"
    upstream = f"{_NAME_PREFIX}{suffix}-agent"
    caddy = f"{_NAME_PREFIX}{suffix}-caddy"
    port = _free_port()
    try:
        _docker("network", "create", network)
        _docker(
            "run", "-d", "--name", upstream, "--network", network, "--network-alias", "agent",
            "-v", f"{srv}:/srv:ro", _PYTHON_IMAGE, "python", "-u", "/srv/upstream.py",
        )  # fmt: skip
        _docker(
            "run", "-d", "--name", caddy, "--network", network,
            "-e", "ADMINO_DOMAIN=localhost",
            "-v", f"{_CADDYFILE}:/etc/caddy/Caddyfile:ro",
            "-p", f"127.0.0.1:{port}:443", _CADDY_IMAGE,
        )  # fmt: skip
        base_url = f"https://localhost:{port}"
        _wait_ready(base_url, [caddy, upstream])
        yield _Proxy(base_url=base_url, upstream=upstream)
    finally:
        _docker_quiet("rm", "-f", caddy, upstream)
        _docker_quiet("network", "rm", network)


def _get_raw(proxy: _Proxy, path: str, accept_encoding: str) -> tuple[httpx.Response, bytes]:
    """GET ``path`` through the proxy; the response and its body exactly as sent (still encoded)."""
    with (
        _client(proxy.base_url) as client,
        client.stream("GET", path, headers={"Accept-Encoding": accept_encoding}) as resp,
    ):
        raw = b"".join(resp.iter_raw())
    return resp, raw


def _unzstd(proxy: _Proxy, raw: bytes) -> bytes:
    """Decode a zstd body with libzstd inside the stub upstream's container."""
    return _docker("exec", "-i", proxy.upstream, "python", "/srv/unzstd.py", stdin=raw)


def _media_type(resp: httpx.Response) -> str:
    """The response's media type without parameters."""
    return str(resp.headers.get("content-type", "")).split(";")[0].strip()


def test_proxy_profile_asset_zstd_for_zstd_client(proxy: _Proxy) -> None:
    """A client that accepts zstd and gzip gets the asset zstd-encoded, the upstream's
    Cache-Control kept, and the decoded body identical."""
    resp, raw = _get_raw(proxy, _ASSET_PATH, "zstd, gzip")
    encoding = resp.headers.get("content-encoding")
    decoded = _unzstd(proxy, raw) if encoding == "zstd" else raw

    assert (encoding, resp.headers.get("cache-control"), decoded == _ASSET) == (
        "zstd",
        IMMUTABLE,
        True,
    )


def test_proxy_profile_asset_gzip_for_gzip_only_client(proxy: _Proxy) -> None:
    """A client that accepts only gzip gets the asset gzip-encoded, the upstream's
    Cache-Control kept, and the decoded body identical."""
    resp, raw = _get_raw(proxy, _ASSET_PATH, "gzip")
    encoding = resp.headers.get("content-encoding")
    decoded = gzip.decompress(raw) if encoding == "gzip" else raw

    assert (encoding, resp.headers.get("cache-control"), decoded == _ASSET) == (
        "gzip",
        IMMUTABLE,
        True,
    )


def test_proxy_profile_json_body_compressed(proxy: _Proxy) -> None:
    """A JSON API body is compressed too (zstd for a zstd client), decoded identical."""
    resp, raw = _get_raw(proxy, _JSON_PATH, "zstd, gzip")
    encoding = resp.headers.get("content-encoding")
    decoded = _unzstd(proxy, raw) if encoding == "zstd" else raw

    assert (encoding, _media_type(resp), decoded == _JSON) == ("zstd", "application/json", True)


def test_proxy_profile_event_stream_unencoded_and_streamed_frame_by_frame(proxy: _Proxy) -> None:
    """A chat send that accepts ``text/event-stream`` is never encoded or buffered: no
    Content-Encoding, the event-stream type kept, and each frame arrives when the upstream
    writes it (frame 1 at once, the next ones ~1.5 s apart), in order. A JSON body with the
    same Accept-Encoding is zstd-encoded by the same proxy."""
    headers = {
        "Accept": "text/event-stream",
        "Accept-Encoding": "zstd, gzip",
        "Content-Type": "application/json",
    }
    frames: list[bytes] = []
    arrivals: list[float] = []
    with _client(proxy.base_url) as client:
        start = time.monotonic()
        with client.stream("POST", _SSE_PATH, headers=headers, content=b'{"content":"hi"}') as resp:
            buffer = b""
            for chunk in resp.iter_raw():
                now = time.monotonic() - start
                buffer += chunk
                while b"\n\n" in buffer:
                    frame, buffer = buffer.split(b"\n\n", 1)
                    frames.append(frame + b"\n\n")
                    arrivals.append(now)
    json_resp, _ = _get_raw(proxy, _JSON_PATH, "zstd, gzip")

    gaps = [later - earlier for earlier, later in itertools.pairwise(arrivals)]
    assert (
        resp.status_code,
        resp.headers.get("content-encoding"),
        _media_type(resp),
        frames,
        bool(arrivals) and arrivals[0] < 1.0,
        len(gaps) == 2 and all(gap >= 1.2 for gap in gaps),
        json_resp.headers.get("content-encoding"),
    ) == (200, None, "text/event-stream", _FRAMES, True, True, "zstd")
