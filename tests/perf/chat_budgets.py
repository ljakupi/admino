"""``make perf``: the GH-244 server budgets, measured against a throwaway PostgreSQL.

Usage::

    python -m tests.perf.chat_budgets      # what ``make perf`` runs

Dev only: needs Docker. Not a pytest file (no ``test_`` prefix, never collected).

What it does, in order:

1. Starts a throwaway ``postgres:16`` container named ``admino-perf-<random>``,
   published on ``127.0.0.1:<free port>`` only, with random owner and runtime
   passwords from ``secrets``, and waits until it accepts connections.
2. Runs the migrations as the owner: ``python -m admino.migrate`` in a
   subprocess (``sys.executable``, the same source tree), which also sets the
   runtime role ``admino_app``'s password.
3. Seeds as the owner: one organization (data residency off) with its
   ``org_settings`` row and the default permission matrix
   (``org_permissions.seed_org_permissions``), one active Editor with a
   password hash, and the platform settings row
   (``scoped_settings.seed_platform_settings``, provider infomaniak).
4. Builds the app the way ``admino.main`` does: ``server.create_app`` with the
   real ``Agent`` (tool modules imported, registry frozen) and the real
   tool-call recorder (``main._build_tool_call_recorder``). The app's lifespan
   runs in-process: it connects as ``admino_app`` through
   ``database.init_pool`` (so the statement timing of ``database.TimedPool``
   is installed) and starts the usual background jobs. Requests go through
   ``httpx.ASGITransport`` with a same-origin ``Sec-Fetch-Site`` header (the
   CSRF check) and a session opened with ``sessions.create_session`` on the
   app's pool. The LLM is a fake with a fixed latency whose ``provider`` is
   infomaniak: ``chat`` sleeps and answers, ``chat_stream`` sleeps, then
   yields two deltas and the final response.
5. Creates a chat (``POST /api/chats``) and sends ``PERF_WARMUP`` warm-up
   messages (excluded from the results) and ``PERF_SENDS`` measured ones to
   ``POST /api/chats/{chat_id}/messages``, alternating JSON and SSE (each
   stream read to ``done``), all in that one chat (each turn loads the latest
   ``max_context_messages`` messages). Every send must produce exactly one
   ``chat timings`` line on the ``admino.request_timing`` logger (GH-244
   contract C1.3), captured by a logging handler and parsed here.
6. Fills the user's chats up to 500 (owner SQL, varied ``last_activity_at``),
   then times ``PERF_WARMUP`` warm-up and ``PERF_LISTS`` measured
   ``GET /api/chats`` requests around each request (``time.perf_counter``).
7. Prints the results table. The container is removed in every case: success,
   failure, an error or Ctrl-C.

Measurement conditions (the steady state of contract C3):

- The per-user rate limits of the two measured routes (``/api/message``: 0.5
  per second; ``/api/chats/list``) are lifted for the run, or the benchmark
  would measure the throttle. The limiter itself still runs on every request.
- The session is replaced by a fresh one every 45 s, so the session's
  ``last_seen_at`` touch (at most once a minute, an exception Decision 3
  documents) never falls in a measured send. The cold platform-settings cache
  and the chat's first exchange (its title) fall in the warm-up.

Inputs (environment, all optional): ``PERF_LLM_LATENCY_MS`` (the fake LLM's
latency, default 50), ``PERF_WARMUP`` (default 5), ``PERF_SENDS`` (default
200), ``PERF_LISTS`` (default 200). Docker with the ``postgres:16`` image
(pulled when missing).

Outputs: a table on stdout with the server overhead before the first LLM call
(``llm_start_ms``) p50 and p95, ``llm_first_byte_ms`` p50 and p95, the median
and max ``db_queries_before_llm``, and ``GET /api/chats`` p50 and p95, each
with its budget and PASS/FAIL, then every failure. Exit status: 0 when every
budget holds; 1 when the p95 overhead is above 100 ms, the p95 list time above
150 ms, a send has ``db_queries_before_llm`` above 3, or a send or list failed
or a send produced no timing line (or the setup failed); 2 when Docker isn't
available or a ``PERF_*`` value is invalid; 130 on Ctrl-C.

Security notes:

- The passwords are random per run and are never printed, logged or put on a
  command line: the container reads the owner's password from the ``docker``
  client's environment (``--env POSTGRES_PASSWORD`` without a value), the
  migrate step from its own environment, the app from ``PG_APP_PASSWORD``. No
  DSN is printed; a failure names an exception type, an exit status, or a
  fixed hint. The migrate step's own log lines (printed only when it fails)
  never carry a password or DSN.
- PostgreSQL listens on 127.0.0.1 only and the container is removed at the
  end. Nothing else is contacted: the LLM is a fake, and the ``SMTP_*``
  variables are dropped from the process environment before the app starts,
  so the email outbox sender never runs.
- Nothing from a message, reply, title or timing line beyond its numbers is
  printed: timings, counts, HTTP statuses and error codes only.
- Subprocesses run with fixed argument lists and ``shell=False`` only (the
  absolute ``docker`` path from ``shutil.which``, and ``sys.executable``).
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import quote

import asyncpg
import httpx

from admino.llm import LLMResponse, LLMStreamDelta

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Sequence
    from types import FrameType
    from uuid import UUID

    from fastapi import FastAPI

    from admino.config import AppConfig
    from admino.models import LLMMessage

# ---------------------------------------------------------------------------
# Budgets (GH-244) and fixed settings
# ---------------------------------------------------------------------------

OVERHEAD_P95_BUDGET_MS: Final = 100.0
LIST_P95_BUDGET_MS: Final = 150.0
MAX_STATEMENTS_BEFORE_LLM: Final = 3
LIST_CHAT_COUNT: Final = 500

POSTGRES_IMAGE: Final = "postgres:16"
OWNER_ROLE: Final = "admino"
DATABASE_NAME: Final = "admino"

# server.public_url's default: requests come from the app's own origin.
_BASE_URL: Final = "http://localhost:8000"
_TIMING_LOGGER: Final = "admino.request_timing"
# Contract C1.3, verbatim.
_TIMING_LINE: Final = re.compile(
    r"^chat timings: request_id=([0-9a-f]{32}|-) route=(chat_message|message|confirm) "
    r"status=\d{3} db_queries=\d+ db_queries_before_llm=(\d+|-) db_ms=\d+\.\d "
    r"llm_start_ms=(\d+\.\d|-) llm_first_byte_ms=(\d+\.\d|-) llm_ms=\d+\.\d "
    r"tool_ms=\d+\.\d total_ms=\d+\.\d$"
)
# An error code or reason worth printing: a fixed lower-case identifier, nothing else.
_CODE: Final = re.compile(r"[a-z_]{1,40}")
_SETTING_VALUE: Final = re.compile(r"[0-9]{1,7}")

_SESSION_ROTATE_S: Final = 45.0
_READY_TIMEOUT_S: Final = 90.0
_DOCKER_TIMEOUT_S: Final = 600.0
_MIGRATE_TIMEOUT_S: Final = 300.0
_TIMING_LINE_WAIT_S: Final = 0.5
# The two measured routes' rate-limit keys, lifted for the run.
_UNTHROTTLED_ROUTES: Final = ("/api/message", "/api/chats/list")
_UNTHROTTLED: Final = (1_000_000.0, 1_000_000)

_FAKE_MODEL: Final = "perf-fake-model"
_ANSWER_PIECES: Final = ("Here is ", "a short answer.")
_EDITOR_EMAIL: Final = "perf-editor@example.invalid"

_ORG_SQL: Final = """
    INSERT INTO organizations
        (name, status, seats, monthly_budget_chf, storage_quota_bytes, data_residency)
    VALUES ($1, 'active', 10, 0, 0, false)
    RETURNING id
"""
_ORG_SETTINGS_SQL: Final = "INSERT INTO org_settings (org_id) VALUES ($1)"
_USER_SQL: Final = """
    INSERT INTO users (email, name, password_hash, kind, org_id, role, status)
    VALUES ($1, $2, $3, 'member', $4, 'editor', 'active')
    RETURNING id
"""
_LIVE_CHATS_SQL: Final = (
    "SELECT count(*) FROM chats WHERE owner_user_id = $1 AND deleted_at IS NULL"
)
# Distinct activity times spread over 30 days (7919 is prime to 43200 minutes).
_FILL_CHATS_SQL: Final = """
    INSERT INTO chats (org_id, owner_user_id, title, title_source, created_at, last_activity_at)
    SELECT $1, $2, 'Perf chat ' || g, 'user', now() - interval '60 days',
           now() - make_interval(mins => (g * 7919) % 43200)
    FROM generate_series(1, $3::int) AS g
"""


class PerfError(Exception):
    """A setup step failed; the message is a fixed, content-free description."""


class SettingsError(ValueError):
    """A ``PERF_*`` environment value is invalid."""


@dataclass(frozen=True)
class Settings:
    """The run's sizes, from the ``PERF_*`` environment variables."""

    latency_ms: int
    warmup: int
    sends: int
    lists: int


@dataclass(frozen=True)
class Database:
    """The throwaway container: its name, port and the two random passwords."""

    docker: str
    name: str
    port: int
    owner_password: str = field(repr=False)
    app_password: str = field(repr=False)

    def owner_dsn(self) -> str:
        """The owner's DSN (never printed)."""
        password = quote(self.owner_password, safe="")
        return f"postgresql://{OWNER_ROLE}:{password}@127.0.0.1:{self.port}/{DATABASE_NAME}"


@dataclass(frozen=True)
class SendTiming:
    """The numbers of one measured send's timing line."""

    streamed: bool
    llm_start_ms: float
    llm_first_byte_ms: float
    statements_before_llm: int


@dataclass
class Report:
    """Everything the table is printed from."""

    settings: Settings
    sends: list[SendTiming] = field(default_factory=list)
    send_failures: list[str] = field(default_factory=list)
    list_ms: list[float] = field(default_factory=list)
    list_failures: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Settings, percentiles
# ---------------------------------------------------------------------------


def _env_int(name: str, default: int, minimum: int) -> int:
    """Read a whole-number ``PERF_*`` setting (unset or empty: the default)."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    if not _SETTING_VALUE.fullmatch(raw) or int(raw) < minimum:
        msg = f"{name} must be a whole number of at least {minimum}"
        raise SettingsError(msg)
    return int(raw)


def settings_from_env() -> Settings:
    """The run's settings from the environment.

    Raises:
        SettingsError: For a value that isn't a whole number in range.
    """
    return Settings(
        latency_ms=_env_int("PERF_LLM_LATENCY_MS", 50, 0),
        warmup=_env_int("PERF_WARMUP", 5, 0),
        sends=_env_int("PERF_SENDS", 200, 1),
        lists=_env_int("PERF_LISTS", 200, 1),
    )


def percentile(values: Sequence[float], pct: float) -> float:
    """The nearest-rank percentile (p50 is the lower median, p95 the 95th rank)."""
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100.0 * len(ordered)))
    return ordered[rank - 1]


# ---------------------------------------------------------------------------
# Docker and the migrate step (fixed argv, shell=False)
# ---------------------------------------------------------------------------


def _run(
    argv: Sequence[str], *, timeout: float, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run a fixed argument list without a shell; output captured, never echoed."""
    # Fixed argv (absolute docker path or sys.executable), shell=False.
    return subprocess.run(  # noqa: S603
        list(argv),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        stdin=subprocess.DEVNULL,
        env=env,
    )


def _tail(text: str) -> str:
    """The last non-empty line of a tool's stderr, shortened (for a failure message)."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1][:300] if lines else "no output"


def docker_path() -> str | None:
    """The absolute ``docker`` path when the CLI is installed and its daemon answers."""
    path = shutil.which("docker")
    if path is None:
        return None
    try:
        result = _run([path, "info", "--format", "{{.ServerVersion}}"], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return path if result.returncode == 0 else None


def _free_port() -> int:
    """A currently free TCP port on 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _start_container(db: Database) -> None:
    """Start the throwaway ``postgres:16`` container (the password via the environment)."""
    env = {**os.environ, "POSTGRES_PASSWORD": db.owner_password}
    argv = [
        db.docker,
        "run",
        "--detach",
        "--rm",
        "--name",
        db.name,
        "--label",
        "admino.perf=1",
        "--env",
        f"POSTGRES_USER={OWNER_ROLE}",
        "--env",
        "POSTGRES_PASSWORD",
        "--env",
        f"POSTGRES_DB={DATABASE_NAME}",
        "--publish",
        f"127.0.0.1:{db.port}:5432",
        POSTGRES_IMAGE,
    ]
    result = _run(argv, timeout=_DOCKER_TIMEOUT_S, env=env)
    if result.returncode != 0:
        msg = (
            f"docker run {POSTGRES_IMAGE} failed (exit {result.returncode}): {_tail(result.stderr)}"
        )
        raise PerfError(msg)


def _remove_container(db: Database) -> None:
    """Remove the container (also when it never started); never raises."""
    try:
        _run([db.docker, "rm", "--force", db.name], timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        print(f"WARNING: could not remove the container {db.name}: run docker rm -f {db.name}")


async def _wait_ready(db: Database) -> None:
    """Wait until PostgreSQL accepts the owner's TCP connection (the final server, not initdb's)."""
    deadline = time.monotonic() + _READY_TIMEOUT_S
    while True:
        try:
            conn = await asyncpg.connect(db.owner_dsn(), timeout=5)
        except (OSError, TimeoutError, asyncpg.PostgresError, asyncpg.InterfaceError) as exc:
            if time.monotonic() > deadline:
                msg = (
                    f"PostgreSQL did not accept connections within {_READY_TIMEOUT_S:.0f} s "
                    f"({type(exc).__name__})"
                )
                raise PerfError(msg) from None
            await asyncio.sleep(0.5)
            continue
        try:
            await conn.fetchval("SELECT 1")
        finally:
            await conn.close()
        return


def _source_root() -> str:
    """The directory the running ``admino`` package is imported from (for the subprocess)."""
    import admino

    return str(Path(admino.__file__).resolve().parent.parent)


def _migrate(db: Database) -> None:
    """Run ``python -m admino.migrate`` as the owner (the same interpreter and source tree)."""
    inherited = os.environ.get("PYTHONPATH", "")
    env = {
        **os.environ,
        "PG_HOST": "127.0.0.1",
        "PG_PORT": str(db.port),
        "PG_USER": OWNER_ROLE,
        "PG_PASSWORD": db.owner_password,
        "PG_APP_PASSWORD": db.app_password,
        "PG_DATABASE": DATABASE_NAME,
        "LOG_LEVEL": "WARNING",
        "LOG_FORMAT": "text",
        "PYTHONPATH": os.pathsep.join(p for p in (_source_root(), inherited) if p),
    }
    result = _run([sys.executable, "-m", "admino.migrate"], timeout=_MIGRATE_TIMEOUT_S, env=env)
    if result.returncode != 0:
        msg = (
            f"the migrations failed (admino.migrate exit {result.returncode}): "
            f"{_tail(result.stderr)}"
        )
        raise PerfError(msg)


# ---------------------------------------------------------------------------
# Seed (as the owner)
# ---------------------------------------------------------------------------


async def _seed(conn: asyncpg.Connection, config: AppConfig) -> tuple[UUID, UUID]:
    """One org (residency off) with settings and permissions, an Editor, the platform row.

    Returns:
        The org id and the Editor's user id.
    """
    from admino import org_permissions, passwords, scoped_settings

    password_hash = await asyncio.to_thread(passwords.hash_password, secrets.token_urlsafe(24))
    async with conn.transaction():
        org_id: UUID = await conn.fetchval(_ORG_SQL, "admino perf")
        await conn.execute(_ORG_SETTINGS_SQL, org_id)
        await org_permissions.seed_org_permissions(conn, org_id)
        user_id: UUID = await conn.fetchval(
            _USER_SQL, _EDITOR_EMAIL, "Perf Editor", password_hash, org_id
        )
        await scoped_settings.seed_platform_settings(conn, config)
    return org_id, user_id


async def _fill_chats(conn: asyncpg.Connection, org_id: UUID, user_id: UUID) -> None:
    """Give the user ``LIST_CHAT_COUNT`` live chats in all (the send chat included)."""
    existing: int = await conn.fetchval(_LIVE_CHATS_SQL, user_id)
    missing = LIST_CHAT_COUNT - existing
    if missing > 0:
        await conn.execute(_FILL_CHATS_SQL, org_id, user_id, missing)


# ---------------------------------------------------------------------------
# The app: fake LLM, logging, session, requests
# ---------------------------------------------------------------------------


class FakeLLM:
    """An LLM client with a fixed latency; ``provider`` infomaniak (passes the residency guard)."""

    def __init__(self, latency_s: float) -> None:
        self._latency_s = latency_s

    @property
    def provider(self) -> str:
        """The provider name the model policy reads."""
        return "infomaniak"

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Wait the latency, then answer (the JSON turn and the chat-title call)."""
        await asyncio.sleep(self._latency_s)
        return LLMResponse(content="".join(_ANSWER_PIECES), model=_FAKE_MODEL, done=True)

    async def chat_stream(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AsyncGenerator[LLMStreamDelta | LLMResponse, None]:
        """Wait the latency, then yield two deltas and the final response."""
        await asyncio.sleep(self._latency_s)
        for piece in _ANSWER_PIECES:
            yield LLMStreamDelta(content=piece)
        yield LLMResponse(content="".join(_ANSWER_PIECES), model=_FAKE_MODEL, done=True)

    async def close(self) -> None:
        """Nothing to close."""


class TimingSink(logging.Handler):
    """Collects the messages of the ``admino.request_timing`` logger."""

    def __init__(self) -> None:
        super().__init__(logging.INFO)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        """Keep the formatted message."""
        self.lines.append(record.getMessage())

    async def lines_since(self, start: int) -> list[str]:
        """The lines logged since index ``start``, waiting briefly for the first one."""
        deadline = time.monotonic() + _TIMING_LINE_WAIT_S
        while len(self.lines) <= start and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
        return self.lines[start:]


def _configure_logging() -> TimingSink:
    """Warnings and errors on stderr (admino's formatter); timing lines into the sink only."""
    from admino.logs import RequestIdFilter, TextFormatter

    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RequestIdFilter())
    handler.setFormatter(TextFormatter())
    logging.basicConfig(level=logging.WARNING, handlers=[handler], force=True)
    sink = TimingSink()
    timing = logging.getLogger(_TIMING_LOGGER)
    timing.setLevel(logging.INFO)
    timing.addHandler(sink)
    timing.propagate = False
    return sink


def _app_config() -> AppConfig:
    """The app's config: defaults, provider infomaniak with a fake model name."""
    from admino.config import AppConfig, LLMConfig

    # The LLM is a fake: the missing-token warning of a real Infomaniak setup is noise here.
    config_logger = logging.getLogger("admino.config")
    level = config_logger.level
    config_logger.setLevel(logging.ERROR)
    try:
        return AppConfig(llm=LLMConfig(provider="infomaniak", infomaniak_model=_FAKE_MODEL))
    finally:
        config_logger.setLevel(level)


def _build_app(config: AppConfig, latency_s: float) -> FastAPI:
    """``create_app`` with the real Agent, tool registry and tool-call recorder."""
    from admino import main as admino_main
    from admino import server
    from admino.agent import Agent
    from admino.models import AgentConfig
    from admino.tools.registry import freeze_registry

    admino_main._import_tool_modules()
    freeze_registry()
    agent = Agent(
        llm_client=FakeLLM(latency_s),
        tool_call_recorder=admino_main._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=config.limits.max_tool_calls_per_message,
            max_context_messages=config.limits.max_context_messages,
            confirmation_timeout_s=float(config.limits.confirmation_timeout_s),
        ),
    )
    app = server.create_app(agent=agent, config=config)
    # Read when a bucket is created: lifted before the first request.
    for route in _UNTHROTTLED_ROUTES:
        server._RATE_LIMITS[route] = _UNTHROTTLED
    return app


class Session:
    """The Editor's session cookie, replaced every 45 s (no ``last_seen_at`` touch is due)."""

    def __init__(self, user_id: UUID) -> None:
        self._user_id = user_id
        self._token = ""
        self._opened_at = 0.0

    async def open(self) -> None:
        """Open a fresh session with the app's own code, on the app's pool (``admino_app``)."""
        from admino import database, sessions

        self._token = await sessions.create_session(
            database.get_pool(),
            user_id=self._user_id,
            policy=sessions.SessionPolicy(),
            ip=None,
            user_agent="admino-perf",
        )
        self._opened_at = time.monotonic()

    async def rotate_if_due(self) -> None:
        """Open a new session once the current one is 45 s old."""
        if time.monotonic() - self._opened_at >= _SESSION_ROTATE_S:
            await self.open()

    def headers(self, *, streamed: bool = False) -> dict[str, str]:
        """A same-origin request's headers with the session cookie (and SSE's Accept)."""
        from admino.sessions import SESSION_COOKIE_NAME

        headers = {
            "Cookie": f"{SESSION_COOKIE_NAME}={self._token}",
            "Sec-Fetch-Site": "same-origin",
        }
        if streamed:
            headers["Accept"] = "text/event-stream"
        return headers


def _code(value: object) -> str:
    """An error code or reason to print: a fixed identifier, else ``?``."""
    return value if isinstance(value, str) and _CODE.fullmatch(value) else "?"


def _http_problem(response: httpx.Response) -> str:
    """A refused request: its status and documented reason (never its text)."""
    try:
        body = response.json()
    except ValueError:
        body = None
    reason = body.get("reason") if isinstance(body, dict) else None
    suffix = f" ({_code(reason)})" if reason is not None else ""
    return f"HTTP {response.status_code}{suffix}"


def sse_events(body: str) -> list[tuple[str, Any]]:
    """The ``(event, data)`` frames of an SSE body (data parsed as JSON).

    Raises:
        ValueError: For a frame whose data isn't JSON.
    """
    events: list[tuple[str, Any]] = []
    for block in re.split(r"\r\n\r\n|\n\n|\r\r", body):
        name: str | None = None
        data: list[str] = []
        for line in block.splitlines():
            if line.startswith(":"):
                continue
            key, _, value = line.partition(":")
            value = value.removeprefix(" ")
            if key == "event":
                name = value
            elif key == "data":
                data.append(value)
        if name is not None:
            events.append((name, json.loads("\n".join(data)) if data else None))
    return events


def send_problem(response: httpx.Response, *, streamed: bool) -> str | None:
    """Why a send failed (status, stream shape, turn status), or None when it succeeded."""
    if response.status_code != 200:
        return _http_problem(response)
    if streamed:
        if not response.headers.get("content-type", "").startswith("text/event-stream"):
            return "the answer is not an event stream"
        try:
            events = sse_events(response.text)
        except ValueError:
            return "an event's data is not JSON"
        for name, payload in events:
            if name == "error":
                code = payload.get("code") if isinstance(payload, dict) else None
                return f"error event ({_code(code)})"
        if not events or events[-1][0] != "done":
            return "the stream did not end with done"
        saved = [payload for name, payload in events if name == "message_saved"]
        if not saved or not isinstance(saved[-1], dict) or saved[-1].get("status") != "complete":
            return "no message_saved event with status complete"
        return None
    try:
        body = response.json()
    except ValueError:
        return "the answer is not JSON"
    if not isinstance(body, dict) or body.get("status") != "final":
        status = body.get("status") if isinstance(body, dict) else None
        return f"turn status {_code(status)}"
    if body.get("error_code") is not None:
        return f"error code {_code(body.get('error_code'))}"
    return None


def parse_timing_line(line: str) -> dict[str, str] | None:
    """The fields of a C1.3 line, or None when it doesn't match the contract's format."""
    if _TIMING_LINE.fullmatch(line) is None:
        return None
    pairs = line.removeprefix("chat timings: ").split(" ")
    return dict(pair.split("=", 1) for pair in pairs)


def _timing_problem(fields: dict[str, str]) -> str | None:
    """Why a send's timing line can't be used, or None."""
    if fields["route"] != "chat_message":
        return f"timing line for route {fields['route']}, expected chat_message"
    if fields["status"] != "200":
        return f"timing line with status {fields['status']}"
    if "-" in (
        fields["llm_start_ms"],
        fields["llm_first_byte_ms"],
        fields["db_queries_before_llm"],
    ):
        return "timing line without an LLM call"
    return None


def _message(index: int) -> str:
    """The text of send ``index`` (never printed)."""
    return f"Perf message {index}: what should I prepare for tomorrow's planning meeting?"


async def _create_chat(client: httpx.AsyncClient, session: Session) -> str:
    """``POST /api/chats``: the chat every send goes to."""
    response = await client.post("/api/chats", json={}, headers=session.headers())
    if response.status_code != 201:
        msg = f"POST /api/chats: {_http_problem(response)}"
        raise PerfError(msg)
    chat_id = response.json().get("id")
    if not isinstance(chat_id, str):
        msg = "POST /api/chats: no chat id in the answer"
        raise PerfError(msg)
    return chat_id


async def _run_sends(
    client: httpx.AsyncClient,
    session: Session,
    chat_id: str,
    sink: TimingSink,
    report: Report,
) -> None:
    """Warm-up and measured sends, alternating JSON and SSE; stops at the first failure."""
    settings = report.settings
    path = f"/api/chats/{chat_id}/messages"
    for index in range(settings.warmup + settings.sends):
        measured = index >= settings.warmup
        streamed = index % 2 == 1
        number = index - settings.warmup + 1 if measured else index + 1
        label = (
            f"{'send' if measured else 'warm-up send'} {number} ({'SSE' if streamed else 'JSON'})"
        )
        await session.rotate_if_due()
        start = len(sink.lines)
        try:
            response = await client.post(
                path, json={"message": _message(index)}, headers=session.headers(streamed=streamed)
            )
        except Exception as exc:  # the app raised through the transport
            report.send_failures.append(f"{label}: the request raised {type(exc).__name__}")
            return
        problem = send_problem(response, streamed=streamed)
        if problem is not None:
            report.send_failures.append(f"{label}: {problem}")
            return
        lines = await sink.lines_since(start)
        if not lines:
            report.send_failures.append(
                f"{label}: no timing lines: nothing was logged on the {_TIMING_LOGGER} "
                "logger (the GH-244 request timing is not installed)"
            )
            return
        if len(lines) > 1:
            report.send_failures.append(
                f"{label}: {len(lines)} timing lines for one request (expected exactly one)"
            )
            return
        fields = parse_timing_line(lines[0])
        if fields is None:
            report.send_failures.append(f"{label}: the timing line doesn't match contract C1.3")
            return
        problem = _timing_problem(fields)
        if problem is not None:
            report.send_failures.append(f"{label}: {problem}")
            return
        if measured:
            report.sends.append(
                SendTiming(
                    streamed=streamed,
                    llm_start_ms=float(fields["llm_start_ms"]),
                    llm_first_byte_ms=float(fields["llm_first_byte_ms"]),
                    statements_before_llm=int(fields["db_queries_before_llm"]),
                )
            )


async def _run_lists(client: httpx.AsyncClient, session: Session, report: Report) -> None:
    """Warm-up and measured ``GET /api/chats`` (first page), timed around each request."""
    settings = report.settings
    for index in range(settings.warmup + settings.lists):
        measured = index >= settings.warmup
        number = index - settings.warmup + 1 if measured else index + 1
        label = f"{'list' if measured else 'warm-up list'} {number}"
        await session.rotate_if_due()
        started = time.perf_counter()
        try:
            response = await client.get("/api/chats", headers=session.headers())
        except Exception as exc:  # the app raised through the transport
            report.list_failures.append(f"{label}: the request raised {type(exc).__name__}")
            return
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if response.status_code != 200:
            report.list_failures.append(f"{label}: {_http_problem(response)}")
            return
        page = response.json().get("chats")
        if not isinstance(page, list) or not page:
            report.list_failures.append(f"{label}: an empty page (expected the latest chats)")
            return
        if measured:
            report.list_ms.append(elapsed_ms)


async def measure(db: Database, settings: Settings, sink: TimingSink) -> Report:
    """Seed, build the app, run its lifespan and the two measured phases."""
    report = Report(settings=settings)
    config = _app_config()
    conn = await asyncpg.connect(db.owner_dsn())
    try:
        org_id, user_id = await _seed(conn, config)
        # The lifespan's init_pool connects as admino_app with these (database_url_from_env).
        os.environ.update(
            {
                "PG_HOST": "127.0.0.1",
                "PG_PORT": str(db.port),
                "PG_DATABASE": DATABASE_NAME,
                "PG_APP_PASSWORD": db.app_password,
            }
        )
        # No outbox sender (no SMTP server is ever contacted), and no warning about it.
        for name in [name for name in os.environ if name.startswith("SMTP_")]:
            del os.environ[name]
        logging.getLogger("admino.mailer").setLevel(logging.ERROR)
        app = _build_app(config, settings.latency_ms / 1000.0)
        async with app.router.lifespan_context(app):
            session = Session(user_id)
            await session.open()
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url=_BASE_URL) as client:
                chat_id = await _create_chat(client, session)
                await _run_sends(client, session, chat_id, sink, report)
                await _fill_chats(conn, org_id, user_id)
                await _run_lists(client, session, report)
    finally:
        await conn.close()
    return report


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def _ms(value: float) -> str:
    return f"{value:.1f} ms"


Row = tuple[str, str, str, str, str]


def _p95_row(name: str, values: Sequence[float], budget_ms: float) -> tuple[Row, bool]:
    """A p50/p95 row checked against a p95 budget (no values: FAIL)."""
    budget = f"p95 <= {budget_ms:.0f} ms"
    if not values:
        return (name, "-", "-", budget, "FAIL"), False
    ok = percentile(values, 95) <= budget_ms
    p50, p95 = _ms(percentile(values, 50)), _ms(percentile(values, 95))
    return (name, p50, p95, budget, "PASS" if ok else "FAIL"), ok


def render(report: Report) -> tuple[list[str], bool]:
    """The table lines and whether every budget held and nothing failed."""
    sends, settings = report.sends, report.settings
    overhead_row, overhead_ok = _p95_row(
        "server overhead (llm_start_ms)", [s.llm_start_ms for s in sends], OVERHEAD_P95_BUDGET_MS
    )
    first_byte = [s.llm_first_byte_ms for s in sends]
    first_byte_row: Row = (
        "first LLM byte (llm_first_byte_ms)",
        _ms(percentile(first_byte, 50)) if sends else "-",
        _ms(percentile(first_byte, 95)) if sends else "-",
        "none (overhead + fake latency)",
        "-",
    )
    statements = [s.statements_before_llm for s in sends]
    statements_ok = bool(sends) and max(statements) <= MAX_STATEMENTS_BEFORE_LLM
    statements_row: Row = (
        "statements before the LLM call",
        f"{percentile(statements, 50):.0f} (median)" if sends else "-",
        f"{max(statements)} (max)" if sends else "-",
        f"max <= {MAX_STATEMENTS_BEFORE_LLM}",
        "PASS" if statements_ok else "FAIL",
    )
    list_row, list_ok = _p95_row(
        f"GET /api/chats ({LIST_CHAT_COUNT} chats)", report.list_ms, LIST_P95_BUDGET_MS
    )
    failures = [*report.send_failures, *report.list_failures]
    passed = overhead_ok and statements_ok and list_ok and not failures

    header: Row = ("measure", "p50", "p95 / max", "budget", "result")
    rows = [header, overhead_row, first_byte_row, statements_row, list_row]
    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    table = [
        "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip() for row in rows
    ]
    table.insert(1, "  ".join("-" * width for width in widths))
    streamed = sum(1 for s in sends if s.streamed)
    return [
        f"admino make perf (GH-244): fake LLM latency {settings.latency_ms} ms, "
        f"{settings.warmup} warm-up requests excluded",
        f"sends measured: {len(sends)} of {settings.sends} ({len(sends) - streamed} JSON, "
        f"{streamed} SSE); GET /api/chats measured: {len(report.list_ms)} of {settings.lists}",
        "",
        *table,
        *([""] + [f"FAIL: {failure}" for failure in failures] if failures else []),
        "",
        "RESULT: PASS" if passed else "RESULT: FAIL",
    ], passed


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _interrupt(signum: int, frame: FrameType | None) -> None:
    """SIGTERM / SIGHUP end the run like Ctrl-C, so the container is still removed."""
    raise KeyboardInterrupt


def main() -> int:
    """Run the measurement; see the module docstring for the exit statuses."""
    signal.signal(signal.SIGTERM, _interrupt)
    signal.signal(signal.SIGHUP, _interrupt)
    try:
        settings = settings_from_env()
    except SettingsError as exc:
        print(f"make perf: {exc}", file=sys.stderr)
        return 2
    docker = docker_path()
    if docker is None:
        print(
            "make perf needs Docker (a throwaway postgres:16 container): install or start "
            "Docker, then run it again.",
            file=sys.stderr,
        )
        return 2
    db = Database(
        docker=docker,
        name=f"admino-perf-{secrets.token_hex(4)}",
        port=_free_port(),
        owner_password=secrets.token_urlsafe(24),
        app_password=secrets.token_urlsafe(24),
    )
    sink = _configure_logging()
    print(f"make perf: starting {POSTGRES_IMAGE} as {db.name} on 127.0.0.1:{db.port}", flush=True)
    try:
        _start_container(db)
        asyncio.run(_wait_ready(db))
        print("make perf: migrating as the owner", flush=True)
        _migrate(db)
        print(
            f"make perf: {settings.warmup} + {settings.sends} sends, then "
            f"{settings.warmup} + {settings.lists} GET /api/chats",
            flush=True,
        )
        report = asyncio.run(measure(db, settings, sink))
    except PerfError as exc:
        print(f"make perf: FAIL: {exc}", file=sys.stderr)
        return 1
    except (
        OSError,
        asyncpg.PostgresError,
        asyncpg.InterfaceError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"make perf: FAIL: setup error ({type(exc).__name__})", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("make perf: interrupted", file=sys.stderr)
        return 130
    finally:
        _remove_container(db)
    lines, passed = render(report)
    print("\n".join(lines))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
