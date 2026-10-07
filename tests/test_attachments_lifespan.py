"""The server lifespan runs the attachment tasks (GH-187, contract §3.7, §3.8, §5).

Two tasks join the lifespan's background jobs once the pool exists:

- the orphan GC, ``asyncio.create_task(attachment_gc.run_gc_job(get_pool()))``:
  an attachment never sent within 24 h is deleted with its files, and stray
  files are removed, now and then hourly (Decision 13). It runs with the module's
  default interval and reads the attachments root itself;
- a one-shot recovery task, ``attachment_processing.recover(get_pool(),
  server._processing, attachments.attachments_root())``: files a restart left
  ``processing`` go back to ``uploaded`` and are queued again (Decision 7). A
  failure is logged by class name (WARNING or above, while the app is up) and
  never stops the startup; startup doesn't wait for it either.

On shutdown both tasks are cancelled and awaited and the processing pool's
``close()`` is awaited, all before ``close_pool()``: no GC pass, recovery or
processing job ever runs against a closed pool. The other jobs (audit
retention, session purge, org purge, throttle purge, confirmation reaper) keep
running. ``create_app`` gives ``server._processing`` a fresh
``attachment_processing.ProcessingPool`` (a restart's state; routes and the
lifespan look the module global up at call time).

The lifespan is driven directly with every database call and background job
replaced by a fake (the pattern of tests/test_org_purge_lifespan.py). The fake
jobs record their call and task, block until cancelled, then finish one loop
turn later, so "awaited before close_pool" is observable. The attachment jobs
are patched WITHOUT a fallback: the real functions must exist.

Security notes:
- A recovery failure's message may carry a path or a database error text: only
  the exception's class name reaches the log, never its message or traceback.
- The attachments root comes from ``attachments.attachments_root()`` (tests
  point it at ``tmp_path``); no task scans the real ``/app/data/attachments``.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from admino import organizations, server
from admino.server import _lifespan, create_app
from tests.lifespan_stubs import patch_login_throttle_purge_job
from tests.log_capture import configured_logging

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

_REAL_SLEEP = asyncio.sleep
_WAIT_S: Final = 5.0

# What a failing recovery carries in its message: a file name and a path. Neither
# may reach a log line.
_LEAK_NAME: Final = "Quarterly-salaries-2026.xlsx"
_LEAK_PATH: Final = "/app/data/attachments/secret-dir-marker"

# The other background jobs of the lifespan (GH-146, GH-152, GH-154, GH-157, GH-24).
_OTHER_JOBS: Final = ("retention", "session-purge", "org-purge", "throttle-purge", "reaper")


class _RecoveryProbeError(Exception):
    """The class name a failing recovery must be logged with."""


def _contract_gc_job(pool: Any, *, interval_seconds: float = 3600.0) -> None:
    """The contract's run_gc_job signature (§3.8), for binding the lifespan's call."""


def _contract_recover(pool: Any, processing: Any, root: Path) -> None:
    """The contract's recover signature (§3.7), for binding the lifespan's call."""


def _bound(
    signature_of: Callable[..., Any], call: tuple[tuple[Any, ...], dict[str, Any]]
) -> dict[str, Any]:
    """The call's arguments by the contract's parameter names (a TypeError on any other
    argument)."""
    args, kwargs = call
    return dict(inspect.signature(signature_of).bind(*args, **kwargs).arguments)


def _make_app_config() -> MagicMock:
    """A minimal mock AppConfig for create_app."""
    config = MagicMock()
    config.limits.max_message_length = 4000
    config.server.host = "0.0.0.0"  # noqa: S104
    config.server.port = 8000
    return config


class _FakeProcessing:
    """Stands in for server._processing: records submit() and close()."""

    def __init__(self, events: list[str]) -> None:
        self._events = events
        self.submitted: list[tuple[Any, ...]] = []
        self.close_calls = 0

    def submit(self, *args: Any, **kwargs: Any) -> None:
        """Record a submitted job (the fake recovery submits none)."""
        self.submitted.append((*args, *kwargs.values()))

    async def close(self) -> None:
        """Record the close, finishing one loop turn later (so awaiting it is observable)."""
        self.close_calls += 1
        self._events.append("processing-close-started")
        await _REAL_SLEEP(0)
        self._events.append("processing-closed")


class _LifespanProbe:
    """Fakes for the lifespan's pool and background jobs; records what happens when."""

    def __init__(self, recover_mode: str = "block") -> None:
        self.events: list[str] = []
        self.pool: Any = MagicMock(name="pool")
        self.processing = _FakeProcessing(self.events)
        self.recover_mode = recover_mode
        self.gc_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.gc_tasks: list[asyncio.Task[Any]] = []
        self.recover_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.recover_tasks: list[asyncio.Task[Any]] = []

    async def _blocking(self, name: str) -> None:
        """Block until cancelled, then finish after one more loop turn."""
        self.events.append(f"{name}-started")
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.events.append(f"{name}-cancelled")
            await _REAL_SLEEP(0)
            self.events.append(f"{name}-finished")
            raise

    def job(self, name: str) -> Callable[..., Any]:
        """A fake background job that blocks until cancelled."""

        async def run(*_args: Any, **_kwargs: Any) -> None:
            await self._blocking(name)

        return run

    async def gc_job(self, *args: Any, **kwargs: Any) -> None:
        """The fake attachment_gc.run_gc_job."""
        task = asyncio.current_task()
        assert task is not None
        self.gc_tasks.append(task)
        self.gc_calls.append((args, kwargs))
        await self._blocking("gc")

    async def recover(self, *args: Any, **kwargs: Any) -> int:
        """The fake attachment_processing.recover: blocks, returns 0 or raises."""
        task = asyncio.current_task()
        assert task is not None
        self.recover_tasks.append(task)
        self.recover_calls.append((args, kwargs))
        if self.recover_mode == "return":
            self.events.append("recover-returned")
            return 0
        if self.recover_mode == "raise":
            await _REAL_SLEEP(0)
            self.events.append("recover-raised")
            msg = f"recovery failed for {_LEAK_NAME} at {_LEAK_PATH}"
            raise _RecoveryProbeError(msg)
        await self._blocking("recover")
        return 0


@contextlib.contextmanager
def _patched_lifespan(probe: _LifespanProbe) -> Iterator[None]:
    """Patch the lifespan's database calls and every background job. get_pool() raises
    until init_pool() ran, like the real one. The attachment jobs are patched WITHOUT
    ``create=True`` or a fallback: they must exist."""
    state: dict[str, Any] = {"pool": None}

    async def fake_init_pool(*_args: Any, **_kwargs: Any) -> Any:
        probe.events.append("init_pool")
        state["pool"] = probe.pool
        return probe.pool

    def fake_get_pool() -> Any:
        if state["pool"] is None:
            msg = "Database pool not initialised"
            raise RuntimeError(msg)
        return state["pool"]

    async def fake_close_pool() -> None:
        probe.events.append("close_pool")
        state["pool"] = None

    with (
        patch("admino.database.init_pool", fake_init_pool),
        patch("admino.database.close_pool", fake_close_pool),
        patch("admino.database.get_pool", fake_get_pool),
        patch("admino.audit_events.run_retention_job", probe.job("retention")),
        patch("admino.sessions.run_session_purge_job", probe.job("session-purge")),
        patch("admino.organizations.run_org_purge_job", probe.job("org-purge")),
        patch_login_throttle_purge_job(probe.job("throttle-purge")),
        patch("admino.mailer.load_smtp_config", MagicMock(return_value=None)),
        patch("admino.email_outbox.run_outbox_sender", AsyncMock()),
        patch("admino.server._run_confirmation_reaper", probe.job("reaper")),
        patch("admino.attachment_gc.run_gc_job", probe.gc_job),
        patch("admino.attachment_processing.recover", probe.recover),
    ):
        yield


async def _let_tasks_run() -> None:
    """Give scheduled tasks a few loop turns to start."""
    for _ in range(10):
        await _REAL_SLEEP(0)


@pytest.fixture()
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The attachments root every caller reads through attachments.attachments_root()."""
    attachments_root = tmp_path / "attachments"
    monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", attachments_root)
    return attachments_root


def _app_with(probe: _LifespanProbe, monkeypatch: pytest.MonkeyPatch) -> Any:
    """An app whose module-global processing pool is the probe's fake (set after
    create_app, which installs a fresh one; raising=True: the global must exist)."""
    app = create_app(agent=MagicMock(), config=_make_app_config())
    monkeypatch.setattr(server, "_processing", probe.processing)
    return app


async def _run_lifespan(probe: _LifespanProbe, app: Any) -> None:
    """Start the app, let its tasks start, shut it down."""
    with _patched_lifespan(probe):
        async with asyncio.timeout(_WAIT_S), _lifespan(app):
            await _let_tasks_run()


# ---------------------------------------------------------------------------
# 1. Startup: the GC job and the recovery task
# ---------------------------------------------------------------------------


class TestLifespanStartsTheAttachmentTasks:
    """After init_pool, the GC job runs in its own task and the recovery runs once."""

    async def test_attachments_lifespan_starts_the_gc_job_with_the_pool_in_its_own_task(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """run_gc_job(get_pool()) with the default interval (no root: the job reads it
        itself), once, after init_pool, in a task of its own that keeps running."""
        probe = _LifespanProbe()
        app = _app_with(probe, monkeypatch)

        with _patched_lifespan(probe):
            async with asyncio.timeout(_WAIT_S), _lifespan(app):
                await _let_tasks_run()
                (call,) = probe.gc_calls
                arguments = _bound(_contract_gc_job, call)
                (task,) = probe.gc_tasks
                own_running_task = task is not asyncio.current_task() and not task.done()

        assert arguments["pool"] is probe.pool
        assert arguments.get("interval_seconds", 3600.0) == 3600.0
        assert own_running_task
        assert probe.events.index("init_pool") < probe.events.index("gc-started")

    async def test_attachments_lifespan_starts_recovery_with_pool_processing_and_root(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """recover(get_pool(), server._processing, attachments.attachments_root()) runs
        after init_pool in a task of its own: startup doesn't wait for it (it is still
        running while the app is up)."""
        probe = _LifespanProbe(recover_mode="block")
        app = _app_with(probe, monkeypatch)

        with _patched_lifespan(probe):
            async with asyncio.timeout(_WAIT_S), _lifespan(app):
                await _let_tasks_run()
                (call,) = probe.recover_calls
                arguments = _bound(_contract_recover, call)
                (task,) = probe.recover_tasks
                own_running_task = task is not asyncio.current_task() and not task.done()

        assert arguments["pool"] is probe.pool
        assert arguments["processing"] is probe.processing
        assert arguments["root"] == root
        assert own_running_task
        assert probe.events.index("init_pool") < probe.events.index("recover-started")

    async def test_attachments_lifespan_runs_recovery_once(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A one-shot task: a recovery that finished is not run again while the app is
        up, and the shutdown still completes (close_pool runs)."""
        probe = _LifespanProbe(recover_mode="return")
        app = _app_with(probe, monkeypatch)

        with _patched_lifespan(probe):
            async with asyncio.timeout(_WAIT_S), _lifespan(app):
                await _let_tasks_run()
                await _let_tasks_run()
                calls_while_up = len(probe.recover_calls)

        assert (calls_while_up, len(probe.recover_calls)) == (1, 1)
        assert probe.events[-1] == "close_pool"


# ---------------------------------------------------------------------------
# 2. A failing recovery never stops the startup and logs its class name only
# ---------------------------------------------------------------------------


class TestLifespanRecoveryFailure:
    """A recovery failure is logged by class name only; the app starts and stops."""

    async def test_attachments_lifespan_recovery_failure_is_logged_by_class_name_only(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """While the app is up, a WARNING-or-above record names the exception class; no
        output line, record message, argument or exc_info carries its message."""
        probe = _LifespanProbe(recover_mode="raise")
        app = _app_with(probe, monkeypatch)

        with configured_logging("DEBUG", "text") as captured, _patched_lifespan(probe):
            async with asyncio.timeout(_WAIT_S), _lifespan(app):
                await _let_tasks_run()
                while_up = [
                    record
                    for record in captured.records
                    if record.levelno >= logging.WARNING
                    and _RecoveryProbeError.__name__ in record.getMessage()
                ]
            records = list(captured.records)
            text = captured.text

        leaked = [
            marker
            for marker in (_LEAK_NAME, _LEAK_PATH)
            if marker in text
            or any(marker in record.getMessage() for record in records)
            or any(
                record.exc_info is not None and marker in str(record.exc_info[1])
                for record in records
            )
        ]
        assert "recover-raised" in probe.events
        assert len(while_up) >= 1
        assert leaked == []

    async def test_attachments_lifespan_recovery_failure_keeps_startup_and_shutdown(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The failing recovery neither aborts the startup nor the shutdown: the other
        jobs and the GC job run, and everything stops before the pool closes."""
        probe = _LifespanProbe(recover_mode="raise")

        await _run_lifespan(probe, _app_with(probe, monkeypatch))

        assert "recover-raised" in probe.events
        for name in (*_OTHER_JOBS, "gc"):
            assert f"{name}-started" in probe.events, name
            assert probe.events.index(f"{name}-finished") < probe.events.index("close_pool")
        assert probe.events[-1] == "close_pool"


# ---------------------------------------------------------------------------
# 3. Shutdown: both tasks cancelled and awaited, the pool closed, before close_pool
# ---------------------------------------------------------------------------


class TestLifespanStopsTheAttachmentTasks:
    """Nothing attachment-related outlives the pool."""

    async def test_attachments_lifespan_cancels_and_awaits_the_gc_job_before_close_pool(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        probe = _LifespanProbe()

        await _run_lifespan(probe, _app_with(probe, monkeypatch))

        (task,) = probe.gc_tasks
        assert task.cancelled()
        assert probe.events.index("gc-finished") < probe.events.index("close_pool")

    async def test_attachments_lifespan_cancels_and_awaits_recovery_before_close_pool(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A recovery still running at shutdown is cancelled and finishes before the pool
        closes."""
        probe = _LifespanProbe(recover_mode="block")

        await _run_lifespan(probe, _app_with(probe, monkeypatch))

        (task,) = probe.recover_tasks
        assert task.cancelled()
        assert probe.events.index("recover-finished") < probe.events.index("close_pool")

    async def test_attachments_lifespan_awaits_processing_close_before_close_pool(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """server._processing.close() is awaited once (to its end) before the pool
        closes, so no processing job runs against a closed pool."""
        probe = _LifespanProbe()

        await _run_lifespan(probe, _app_with(probe, monkeypatch))

        assert probe.processing.close_calls == 1
        assert "processing-closed" in probe.events
        assert probe.events.index("processing-closed") < probe.events.index("close_pool")

    async def test_attachments_lifespan_keeps_the_other_jobs(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The retention, session purge, org purge, throttle purge and reaper still start
        and finish before the pool closes, next to the attachment tasks."""
        probe = _LifespanProbe()

        await _run_lifespan(probe, _app_with(probe, monkeypatch))

        for name in (*_OTHER_JOBS, "gc", "recover"):
            assert f"{name}-started" in probe.events, name
            assert probe.events.index(f"{name}-finished") < probe.events.index("close_pool")


# ---------------------------------------------------------------------------
# 4. create_app installs a fresh processing pool
# ---------------------------------------------------------------------------


class TestCreateAppProcessingPool:
    """server._processing is a fresh attachment_processing.ProcessingPool per app."""

    def test_attachments_create_app_installs_a_fresh_processing_pool(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stale value is replaced, and every create_app gets its own pool (a restart's
        state: no job of an earlier app carries over)."""
        from admino import attachment_processing

        stale = object()
        monkeypatch.setattr(server, "_processing", stale, raising=False)

        create_app(agent=MagicMock(), config=_make_app_config())
        first = server._processing
        create_app(agent=MagicMock(), config=_make_app_config())
        second = server._processing

        assert isinstance(first, attachment_processing.ProcessingPool)
        assert isinstance(second, attachment_processing.ProcessingPool)
        assert first is not stale
        assert second is not first
