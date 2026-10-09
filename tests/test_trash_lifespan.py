"""The server lifespan runs the trash retention purge (GH-194, contract §4, §6 "Lifespan").

Decision 8: the purge job runs at startup and then hourly. Once the pool exists the
lifespan starts ``asyncio.create_task(trash.run_purge_job(get_pool()))`` (the module's
default interval; the job reads the attachments root itself, at each run). On shutdown
the task is cancelled and awaited right after the attachment GC task, before the
attachment processing pool and the database pool close: no purge runs against a closed
pool. The other jobs (audit retention, session purge, org purge, throttle purge,
confirmation reaper, attachment GC and recovery) keep running.

The lifespan is driven directly with every database call and background job replaced by
a fake (the pattern of tests/test_attachments_lifespan.py). The fake jobs record their
call and task, block until cancelled, then finish one loop turn later, so "cancelled
after the GC task" and "awaited before close_pool" are observable. The trash job is
patched WITHOUT ``create=True`` or a fallback: ``admino.trash.run_purge_job`` must exist.

Security notes: the fake pool is a MagicMock; no real purge, database or attachments
root is touched.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from admino import organizations, server
from admino.server import _lifespan, create_app
from tests.lifespan_stubs import patch_login_throttle_purge_job

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

_REAL_SLEEP = asyncio.sleep
_WAIT_S: Final = 5.0

# The other background jobs of the lifespan (GH-146, GH-152, GH-154, GH-157, GH-24, GH-187).
_OTHER_JOBS: Final = (
    "retention",
    "session-purge",
    "org-purge",
    "throttle-purge",
    "reaper",
    "gc",
    "recover",
)


def _contract_purge_job(pool: Any, *, interval_seconds: float = 3600.0) -> None:
    """The contract's run_purge_job signature (§4), for binding the lifespan's call."""


def _make_app_config() -> MagicMock:
    """A minimal mock AppConfig for create_app."""
    config = MagicMock()
    config.limits.max_message_length = 4000
    config.server.host = "0.0.0.0"  # noqa: S104
    config.server.port = 8000
    return config


class _FakeProcessing:
    """Stands in for server._processing: records close() (one loop turn long)."""

    def __init__(self, events: list[str]) -> None:
        self._events = events

    def submit(self, *_args: Any, **_kwargs: Any) -> None:
        """Accept a submitted job (none is submitted here)."""

    async def close(self) -> None:
        """Record the close, finishing one loop turn later."""
        self._events.append("processing-close-started")
        await _REAL_SLEEP(0)
        self._events.append("processing-closed")


class _LifespanProbe:
    """Fakes for the lifespan's pool and background jobs; records what happens when."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.pool: Any = MagicMock(name="pool")
        self.processing = _FakeProcessing(self.events)
        self.purge_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.purge_tasks: list[asyncio.Task[Any]] = []

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

    async def purge_job(self, *args: Any, **kwargs: Any) -> None:
        """The fake trash.run_purge_job."""
        task = asyncio.current_task()
        assert task is not None
        self.purge_tasks.append(task)
        self.purge_calls.append((args, kwargs))
        await self._blocking("trash-purge")


@contextlib.contextmanager
def _patched_lifespan(probe: _LifespanProbe) -> Iterator[None]:
    """Patch the lifespan's database calls and every background job. get_pool() raises
    until init_pool() ran, like the real one. The trash job is patched WITHOUT
    ``create=True`` or a fallback: it must exist."""
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
        patch("admino.attachment_gc.run_gc_job", probe.job("gc")),
        patch("admino.attachment_processing.recover", probe.job("recover")),
        patch("admino.trash.run_purge_job", probe.purge_job),
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
    """An app whose module-global processing pool is the probe's fake."""
    app = create_app(agent=MagicMock(), config=_make_app_config())
    monkeypatch.setattr(server, "_processing", probe.processing)
    return app


async def _run_lifespan(probe: _LifespanProbe, app: Any) -> None:
    """Start the app, let its tasks start, shut it down."""
    with _patched_lifespan(probe):
        async with asyncio.timeout(_WAIT_S), _lifespan(app):
            await _let_tasks_run()


class TestLifespanTrashPurge:
    """The trash purge job lives exactly as long as the pool."""

    async def test_trash_lifespan_starts_the_purge_job_with_the_pool_in_its_own_task(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """run_purge_job(get_pool()) with the default interval (no root: the job reads it
        itself), once, after init_pool, in a task of its own that keeps running while the
        app is up (startup doesn't wait for it)."""
        probe = _LifespanProbe()
        app = _app_with(probe, monkeypatch)

        with _patched_lifespan(probe):
            async with asyncio.timeout(_WAIT_S), _lifespan(app):
                await _let_tasks_run()
                calls = list(probe.purge_calls)
                tasks = list(probe.purge_tasks)
                own_running_task = [
                    task is not asyncio.current_task() and not task.done() for task in tasks
                ]

        assert (len(calls), own_running_task) == (1, [True])
        args, kwargs = calls[0]
        arguments = dict(inspect.signature(_contract_purge_job).bind(*args, **kwargs).arguments)
        assert arguments["pool"] is probe.pool
        assert arguments.get("interval_seconds", 3600.0) == 3600.0
        assert probe.events.index("init_pool") < probe.events.index("trash-purge-started")

    async def test_trash_lifespan_cancels_and_awaits_the_purge_job_before_close_pool(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """At shutdown the task is cancelled and finishes before the pool closes."""
        probe = _LifespanProbe()

        await _run_lifespan(probe, _app_with(probe, monkeypatch))

        (task,) = probe.purge_tasks
        assert task.cancelled()
        assert probe.events.index("trash-purge-finished") < probe.events.index("close_pool")

    async def test_trash_lifespan_stops_the_purge_after_the_gc_and_before_processing_closes(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The purge is cancelled once the attachment GC task has finished, and it has
        finished itself before the processing pool starts closing."""
        probe = _LifespanProbe()

        await _run_lifespan(probe, _app_with(probe, monkeypatch))

        events = probe.events
        assert events.index("gc-finished") < events.index("trash-purge-cancelled")
        assert events.index("trash-purge-finished") < events.index("processing-close-started")

    async def test_trash_lifespan_keeps_the_other_jobs(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The retention, session purge, org purge, throttle purge, reaper, attachment GC
        and recovery still start and finish before the pool closes, next to the purge."""
        probe = _LifespanProbe()

        await _run_lifespan(probe, _app_with(probe, monkeypatch))

        for name in (*_OTHER_JOBS, "trash-purge"):
            assert f"{name}-started" in probe.events, name
            assert probe.events.index(f"{name}-finished") < probe.events.index("close_pool")
        assert probe.events[-1] == "close_pool"
