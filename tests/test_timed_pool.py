"""Statement-level DB timing: ``admino.database.TimedPool`` (GH-244, contract C2).

Pipeline decision 2: a pool wrapper installed by ``init_pool`` times ``fetch``,
``fetchrow``, ``fetchval``, ``execute`` and ``executemany`` on the pool and on
acquired connections; BEGIN/COMMIT and the pool's connection reset aren't
statements. The counts and durations reach the request's timing line
(``db_queries``, ``db_ms``, contract C1).

Pinned here:
- Inside a request record, each of the five methods, on the pool and on a
  connection from ``async with pool.acquire()``, counts exactly one statement
  and its duration (from the fake ``request_timing._clock``), passes its
  arguments and keywords through and returns the inner result (the same
  object); a failing statement re-raises the very same exception and still
  counts.
- ``conn.transaction()`` works (commit on the FakeDb, the statement inside it)
  and, like acquiring and releasing the connection, adds no statement and no
  time; every other pool or connection attribute passes through untimed
  (``close``, ``terminate``, ``get_size``, ``is_in_transaction``).
- Outside a record the wrapper only delegates, and it never logs (no SQL,
  argument or result).
- ``init_pool`` stores and returns a ``TimedPool`` over the pool
  ``asyncpg.create_pool`` made (still called with exactly ``(url,
  min_size=..., max_size=...)``), ``get_pool()`` returns it and
  ``close_pool()`` closes the inner pool.

The record is opened the production way: ``request_timing.TimingMiddleware``
around a tiny ASGI app on ``POST /api/message`` that runs the statements before
it answers; the counts are read from its timing line. ``admino.request_timing``
and ``TimedPool`` are new, so they are reached lazily: the file collects before
they exist and every test fails on its own.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock, patch

import asyncpg
import pytest

from admino import database
from tests.db_fakes import FakeDb

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

    from starlette.types import Message, Receive, Scope, Send


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LOGGER: Final = "admino.request_timing"
_METHODS: Final = ("fetch", "fetchrow", "fetchval", "execute", "executemany")
_SELECT_NAME: Final = "SELECT name FROM organizations WHERE id = $1"
_SELECT_ROW: Final = "SELECT id, name FROM organizations WHERE id = $1"
_RENAME: Final = "UPDATE organizations SET name = $2 WHERE id = $1"
# The FakeDb statements per method: (sql, extra args after the org id).
_FAKE_DB_STATEMENTS: Final[dict[str, tuple[str, tuple[Any, ...]]]] = {
    "fetch": (_SELECT_ROW, ()),
    "fetchrow": (_SELECT_ROW, ()),
    "fetchval": (_SELECT_NAME, ()),
    "execute": (_RENAME, ("Renamed Org",)),
}
# Content canaries: the wrapper must never log SQL, arguments or results.
_CANARY_SQL: Final = "SELECT 'sqlcanary4410' AS marker WHERE $1 = $2"
_CANARY_ARG: Final = "argcanary7302"
_CANARY_RESULT: Final = "resultcanary1185"


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _Clock:
    """The fake ``request_timing._clock``: seconds, moved only by ``advance``."""

    def __init__(self) -> None:
        self.now = 200.0

    def __call__(self) -> float:
        return self.now

    def advance(self, ms: float) -> None:
        self.now += ms / 1000


class _StubTarget:
    """A pool- or connection-shaped stand-in for slow and failing statements.

    Each statement method records ``(method, args, kwargs)``, advances the clock by
    ``durations_ms[method]``, then raises ``errors[method]`` if set or returns
    ``results[method]`` (a unique object per method).
    """

    def __init__(self, clock: _Clock) -> None:
        self.clock = clock
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.results: dict[str, object] = {method: object() for method in _METHODS}
        self.errors: dict[str, BaseException] = {}
        self.durations_ms: dict[str, float] = dict.fromkeys(_METHODS, 0.0)

    async def _statement(self, method: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        self.calls.append((method, args, kwargs))
        await asyncio.sleep(0)
        self.clock.advance(self.durations_ms[method])
        if method in self.errors:
            raise self.errors[method]
        return self.results[method]

    async def fetch(self, query: str, *args: Any, **kwargs: Any) -> Any:
        return await self._statement("fetch", (query, *args), kwargs)

    async def fetchrow(self, query: str, *args: Any, **kwargs: Any) -> Any:
        return await self._statement("fetchrow", (query, *args), kwargs)

    async def fetchval(self, query: str, *args: Any, **kwargs: Any) -> Any:
        return await self._statement("fetchval", (query, *args), kwargs)

    async def execute(self, query: str, *args: Any, **kwargs: Any) -> Any:
        return await self._statement("execute", (query, *args), kwargs)

    async def executemany(self, command: str, args: Any, **kwargs: Any) -> Any:
        return await self._statement("executemany", (command, args), kwargs)


class _StubConnection(_StubTarget):
    """A connection whose transaction takes 50 ms to begin and 50 ms to commit."""

    def __init__(self, clock: _Clock) -> None:
        super().__init__(clock)
        self.in_transaction = False
        self.commits = 0

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        self.clock.advance(50)  # BEGIN
        self.in_transaction = True
        yield
        self.in_transaction = False
        self.clock.advance(50)  # COMMIT
        self.commits += 1

    def is_in_transaction(self) -> bool:
        return self.in_transaction


class _StubPool(_StubTarget):
    """A pool: acquiring waits 30 ms and the release (connection reset) takes 30 ms."""

    def __init__(self, clock: _Clock) -> None:
        super().__init__(clock)
        self.conn = _StubConnection(clock)
        self.closed = 0
        self.terminated = 0

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[_StubConnection]:
        self.clock.advance(30)  # waiting for a free connection
        yield self.conn
        self.clock.advance(30)  # asyncpg's reset on release

    async def close(self) -> None:
        self.clock.advance(40)
        self.closed += 1

    def terminate(self) -> None:
        self.terminated += 1

    def get_size(self) -> int:
        return 3


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def rt() -> Any:
    """``admino.request_timing`` (new: imported lazily)."""
    from admino import request_timing

    return request_timing


@pytest.fixture()
def clock(rt: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> _Clock:
    fake = _Clock()
    monkeypatch.setattr(rt, "_clock", fake)
    caplog.set_level(logging.DEBUG)
    return fake


@pytest.fixture()
def stub(clock: _Clock) -> _StubPool:
    return _StubPool(clock)


@dataclass
class _TimedFakeDb:
    """A FakeDb whose every statement takes 7 ms, and what each statement returned."""

    db: FakeDb
    returned: list[Any] = field(default_factory=list)


@pytest.fixture()
def fake_db(clock: _Clock, monkeypatch: pytest.MonkeyPatch) -> _TimedFakeDb:
    timed_db = _TimedFakeDb(FakeDb())
    timed_db.db.add_org()
    original = timed_db.db.handle

    def timed_handle(*args: Any) -> Any:
        clock.advance(7)
        result = original(*args)
        timed_db.returned.append(result)
        return result

    monkeypatch.setattr(timed_db.db, "handle", timed_handle)
    return timed_db


@pytest.fixture()
def no_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start without a module pool; the previous value comes back afterwards."""
    monkeypatch.setattr(database, "_pool", None)


def _timed(inner: object) -> Any:
    """``database.TimedPool(inner)`` (new: looked up at call time)."""
    return database.TimedPool(inner)


def _http_scope() -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/message",
        "raw_path": b"/api/message",
        "root_path": "",
        "query_string": b"",
        "headers": [(b"host", b"testserver")],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }


async def _in_record(rt: Any, body: Callable[[], Awaitable[None]]) -> None:
    """Run ``body`` inside a request record (TimingMiddleware on POST /api/message)."""

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await body()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}", "more_body": False})

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message: Message) -> None:
        return None

    await rt.TimingMiddleware(app)(_http_scope(), receive, send)


def _timing_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == _LOGGER]


def _db_fields(caplog: pytest.LogCaptureFixture) -> list[tuple[str, str]]:
    """(db_queries, db_ms) of every timing line, in order."""
    out: list[tuple[str, str]] = []
    for line in _timing_lines(caplog):
        fields = dict(part.split("=", 1) for part in line.split(" ") if "=" in part)
        out.append((fields.get("db_queries", "?"), fields.get("db_ms", "?")))
    return out


# ===========================================================================
# 1. Statements are counted and timed, results and errors unchanged
# ===========================================================================


@pytest.mark.parametrize("via", ["pool", "conn"])
@pytest.mark.parametrize("method", ["fetch", "fetchrow", "fetchval", "execute"])
async def test_timed_pool_fake_db_statement_counts_one_and_returns_the_inner_result(
    rt: Any, fake_db: _TimedFakeDb, caplog: pytest.LogCaptureFixture, method: str, via: str
) -> None:
    db = fake_db.db
    org_id = next(iter(db.orgs))
    sql, extra = _FAKE_DB_STATEMENTS[method]
    timed = _timed(db.pool)
    got: list[Any] = []

    async def body() -> None:
        if via == "pool":
            got.append(await getattr(timed, method)(sql, org_id, *extra))
            return
        async with timed.acquire() as conn:
            got.append(await getattr(conn, method)(sql, org_id, *extra))

    await _in_record(rt, body)

    call = db.calls[-1]
    assert (len(db.calls), call.method, call.sql, call.args) == (
        1,
        method,
        sql,
        (org_id, *extra),
    )
    assert call.via.startswith("conn-" if via == "conn" else "pool")
    assert got[0] is fake_db.returned[0]
    assert _db_fields(caplog) == [("1", "7.0")]


@pytest.mark.parametrize("via", ["pool", "conn"])
async def test_timed_pool_executemany_counts_one_and_passes_args_and_keywords(
    rt: Any, stub: _StubPool, caplog: pytest.LogCaptureFixture, via: str
) -> None:
    target: _StubTarget = stub if via == "pool" else stub.conn
    target.durations_ms["executemany"] = 9.0
    timed = _timed(stub)
    rows = [("a", 1), ("b", 2)]
    got: list[Any] = []

    async def body() -> None:
        if via == "pool":
            got.append(await timed.executemany("INSERT INTO t VALUES ($1, $2)", rows, timeout=2.5))
            return
        async with timed.acquire() as conn:
            got.append(await conn.executemany("INSERT INTO t VALUES ($1, $2)", rows, timeout=2.5))

    await _in_record(rt, body)

    assert target.calls == [
        ("executemany", ("INSERT INTO t VALUES ($1, $2)", rows), {"timeout": 2.5})
    ]
    assert got[0] is target.results["executemany"]
    assert _db_fields(caplog) == [("1", "9.0")]


@pytest.mark.parametrize("via", ["pool", "conn"])
async def test_timed_pool_every_method_passes_keywords_through(
    rt: Any, stub: _StubPool, via: str
) -> None:
    target: _StubTarget = stub if via == "pool" else stub.conn
    timed = _timed(stub)

    async def body() -> None:
        if via == "pool":
            await _call_every_method(timed)
            return
        async with timed.acquire() as conn:
            await _call_every_method(conn)

    await _in_record(rt, body)

    assert target.calls == [
        ("fetch", ("SELECT $1", 1), {"timeout": 1.5}),
        ("fetchrow", ("SELECT $1", 2), {"timeout": 1.5}),
        ("fetchval", ("SELECT $1", 3), {"column": 0, "timeout": 1.5}),
        ("execute", ("SELECT $1", 4), {"timeout": 1.5}),
        ("executemany", ("SELECT $1", [(5,)]), {"timeout": 1.5}),
    ]


async def _call_every_method(target: Any) -> None:
    await target.fetch("SELECT $1", 1, timeout=1.5)
    await target.fetchrow("SELECT $1", 2, timeout=1.5)
    await target.fetchval("SELECT $1", 3, column=0, timeout=1.5)
    await target.execute("SELECT $1", 4, timeout=1.5)
    await target.executemany("SELECT $1", [(5,)], timeout=1.5)


@pytest.mark.parametrize("via", ["pool", "conn"])
async def test_timed_pool_failing_statement_reraises_the_same_exception_and_still_counts(
    rt: Any, stub: _StubPool, caplog: pytest.LogCaptureFixture, via: str
) -> None:
    """Each of the five methods fails (1, 2, 4, 8, 16 ms): five statements, 31 ms."""
    target: _StubTarget = stub if via == "pool" else stub.conn
    errors: dict[str, BaseException] = {
        "fetch": asyncpg.exceptions.UniqueViolationError("duplicate key"),
        "fetchrow": asyncpg.exceptions.DeadlockDetectedError("deadlock detected"),
        "fetchval": ConnectionResetError("connection lost"),
        "execute": TimeoutError(),
        "executemany": asyncpg.exceptions.CheckViolationError("check failed"),
    }
    target.errors = dict(errors)
    target.durations_ms = {
        "fetch": 1,
        "fetchrow": 2,
        "fetchval": 4,
        "execute": 8,
        "executemany": 16,
    }
    timed = _timed(stub)
    raised: dict[str, BaseException] = {}

    async def run_all(on: Any) -> None:
        for method in _METHODS:
            args: tuple[Any, ...] = ([(1,)],) if method == "executemany" else (1,)
            try:
                await getattr(on, method)("SELECT $1", *args)
            except Exception as exc:
                raised[method] = exc

    async def body() -> None:
        if via == "pool":
            await run_all(timed)
            return
        async with timed.acquire() as conn:
            await run_all(conn)

    await _in_record(rt, body)

    assert {
        method: raised.get(method) is error for method, error in errors.items()
    } == dict.fromkeys(_METHODS, True)
    assert _db_fields(caplog) == [("5", "31.0")]


# ===========================================================================
# 2. Transactions, acquire/release and other attributes are not statements
# ===========================================================================


async def test_timed_pool_transaction_acquire_and_release_add_no_statement_or_time(
    rt: Any, stub: _StubPool, caplog: pytest.LogCaptureFixture
) -> None:
    """Acquire 30 ms, BEGIN 50, one 5 ms statement, COMMIT 50, reset 30: 1 statement, 5 ms."""
    stub.conn.durations_ms["fetchval"] = 5.0
    timed = _timed(stub)
    inside: list[bool] = []

    async def body() -> None:
        async with timed.acquire() as conn, conn.transaction():
            inside.append(conn.is_in_transaction())
            await conn.fetchval("SELECT 1")

    await _in_record(rt, body)

    assert (inside, stub.conn.commits) == ([True], 1)
    assert _db_fields(caplog) == [("1", "5.0")]


async def test_timed_pool_fake_db_transaction_commits_with_the_statement_inside(
    rt: Any, fake_db: _TimedFakeDb, caplog: pytest.LogCaptureFixture
) -> None:
    db = fake_db.db
    org_id = next(iter(db.orgs))
    timed = _timed(db.pool)

    async def body() -> None:
        async with timed.acquire() as conn, conn.transaction():
            await conn.execute(_RENAME, org_id, "Renamed In Tx")

    await _in_record(rt, body)

    assert db.transactions == [(1, "commit")]
    assert (db.calls[-1].tx, db.orgs[org_id]["name"]) == (1, "Renamed In Tx")
    assert _db_fields(caplog) == [("1", "7.0")]


async def test_timed_pool_other_pool_attributes_pass_through_untimed(
    rt: Any, stub: _StubPool, caplog: pytest.LogCaptureFixture
) -> None:
    timed = _timed(stub)
    sizes: list[int] = []

    async def body() -> None:
        sizes.append(timed.get_size())
        timed.terminate()
        await timed.close()

    await _in_record(rt, body)

    assert (sizes, stub.terminated, stub.closed) == ([3], 1, 1)
    assert _db_fields(caplog) == [("0", "0.0")]


# ===========================================================================
# 3. Outside a record, and logging
# ===========================================================================


async def test_timed_pool_outside_a_record_only_delegates(
    rt: Any, stub: _StubPool, caplog: pytest.LogCaptureFixture
) -> None:
    """No record: every statement still runs and returns the inner result, nothing is
    logged; a later request's record starts at zero statements."""
    timed = _timed(stub)
    pool_results = [
        await timed.fetch("SELECT 1"),
        await timed.fetchrow("SELECT 1"),
        await timed.fetchval("SELECT 1"),
        await timed.execute("SELECT 1"),
        await timed.executemany("SELECT 1", [()]),
    ]
    async with timed.acquire() as conn:
        conn_results = [
            await conn.fetch("SELECT 1"),
            await conn.fetchrow("SELECT 1"),
            await conn.fetchval("SELECT 1"),
            await conn.execute("SELECT 1"),
            await conn.executemany("SELECT 1", [()]),
        ]
    logged_outside = [r.name for r in caplog.records if r.name.startswith("admino")]

    async def nothing() -> None:
        return None

    await _in_record(rt, nothing)

    assert [
        a is b for a, b in zip(pool_results, [stub.results[m] for m in _METHODS], strict=True)
    ] == [True] * 5
    assert [
        a is b for a, b in zip(conn_results, [stub.conn.results[m] for m in _METHODS], strict=True)
    ] == [True] * 5
    assert logged_outside == []
    assert _db_fields(caplog) == [("0", "0.0")]


async def test_timed_pool_never_logs_sql_arguments_or_results(
    rt: Any, stub: _StubPool, caplog: pytest.LogCaptureFixture
) -> None:
    stub.results["fetchval"] = _CANARY_RESULT
    stub.conn.errors["execute"] = asyncpg.exceptions.UniqueViolationError(_CANARY_ARG)
    timed = _timed(stub)

    async def body() -> None:
        await timed.fetchval(_CANARY_SQL, _CANARY_ARG, _CANARY_ARG)
        async with timed.acquire() as conn:
            await conn.fetch(_CANARY_SQL, _CANARY_ARG, _CANARY_ARG)
            with suppress(asyncpg.exceptions.UniqueViolationError):
                await conn.execute(_CANARY_SQL, _CANARY_ARG, _CANARY_ARG)

    await _in_record(rt, body)

    text = "\n".join(f"{r.name} {r.getMessage()} {r.args!r}" for r in caplog.records).casefold()
    assert [r.name for r in caplog.records if r.name.startswith("admino")] == [_LOGGER]
    assert [c for c in ("sqlcanary4410", _CANARY_ARG, _CANARY_RESULT) if c in text] == []


# ===========================================================================
# 4. init_pool / get_pool / close_pool
# ===========================================================================


async def test_init_pool_installs_a_timed_pool_over_the_created_pool(
    rt: Any, stub: _StubPool, caplog: pytest.LogCaptureFixture, no_pool: None
) -> None:
    create = AsyncMock(return_value=stub)
    stub.durations_ms["fetchval"] = 3.0
    url = "postgresql://admino_app:pw@db.internal:5432/admino"
    with patch("admino.database.asyncpg.create_pool", new=create):
        pool = await database.init_pool(url, min_size=3, max_size=9)
    got: list[Any] = []

    async def body() -> None:
        got.append(await database.get_pool().fetchval("SELECT 1"))

    await _in_record(rt, body)

    assert isinstance(pool, database.TimedPool)
    assert database.get_pool() is pool
    create.assert_awaited_once_with(url, min_size=3, max_size=9)
    assert (stub.calls, got[0] is stub.results["fetchval"]) == (
        [("fetchval", ("SELECT 1",), {})],
        True,
    )
    assert _db_fields(caplog) == [("1", "3.0")]


async def test_close_pool_closes_the_inner_pool_of_the_timed_pool(
    clock: _Clock, stub: _StubPool, no_pool: None
) -> None:
    with patch("admino.database.asyncpg.create_pool", new=AsyncMock(return_value=stub)):
        pool = await database.init_pool("postgresql://admino_app:pw@h:5432/admino")

    await database.close_pool()

    assert isinstance(pool, database.TimedPool)
    assert stub.closed == 1
    with pytest.raises(RuntimeError, match="not initialised"):
        database.get_pool()
