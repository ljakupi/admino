"""The server lifespan runs the org purge job (GH-154).

Organizations marked for deletion are purged once their grace period is over
(and #147's default organization right after the upgrade: migration 0011 makes
it due immediately). ``admino.organizations.run_org_purge_job`` does that, and
the server lifespan runs it while the app is up, like the audit retention job
and the session purge:
``asyncio.create_task(organizations.run_org_purge_job(get_pool()))``, looked up
at call time on the module (so patching ``admino.organizations.run_org_purge_job``
takes effect), started after the pool exists and cancelled, then awaited,
before the pool closes.

The lifespan is driven directly with every database call and background job
replaced by a fake (the pattern of tests/test_audit_events.py section 15). The
org purge fake records its call and its task, blocks until cancelled, then
finishes one loop turn later, so "awaited before close_pool" is observable.

Security notes:
- The job must never run against a closed pool (a half-finished purge rolls
  back, but a crash loop would hide real failures).
- The files purge uses the default attachments root: the lifespan passes no
  other path.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from admino.server import _lifespan, create_app

if TYPE_CHECKING:
    from collections.abc import Iterator

_REAL_SLEEP = asyncio.sleep


def _make_app_config() -> MagicMock:
    """A minimal mock AppConfig for create_app."""
    config = MagicMock()
    config.limits.max_message_length = 4000
    config.server.host = "0.0.0.0"  # noqa: S104
    config.server.port = 8000
    return config


class _LifespanProbe:
    """Fakes for the lifespan's pool and background jobs; records what happens when."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.pool: Any = MagicMock(name="pool")
        self.org_purge_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.org_purge_tasks: list[asyncio.Task[Any]] = []

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

    async def org_purge(self, *args: Any, **kwargs: Any) -> None:
        """The fake run_org_purge_job."""
        task = asyncio.current_task()
        assert task is not None
        self.org_purge_tasks.append(task)
        self.org_purge_calls.append((args, kwargs))
        await self._blocking("org-purge")

    async def retention(self, *_args: Any, **_kwargs: Any) -> None:
        """The fake run_retention_job."""
        await self._blocking("retention")

    async def session_purge(self, *_args: Any, **_kwargs: Any) -> None:
        """The fake run_session_purge_job."""
        await self._blocking("session-purge")

    async def sender(self, *_args: Any, **_kwargs: Any) -> None:
        """The fake run_outbox_sender."""
        await self._blocking("sender")


@contextlib.contextmanager
def _patched_lifespan(probe: _LifespanProbe, smtp_config: Any = None) -> Iterator[None]:
    """Patch the lifespan's database calls and background jobs. get_pool() raises until
    init_pool() ran, like the real one. run_org_purge_job is patched WITHOUT
    ``create=True``: the real function must exist in admino.organizations."""
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
        patch("admino.database.load_permissions_from_db", AsyncMock(return_value={})),
        patch("admino.database.load_settings_from_db", AsyncMock(return_value={})),
        patch("admino.audit_events.run_retention_job", probe.retention),
        patch("admino.sessions.run_session_purge_job", probe.session_purge),
        patch("admino.mailer.load_smtp_config", MagicMock(return_value=smtp_config)),
        patch("admino.email_outbox.run_outbox_sender", probe.sender),
        patch("admino.organizations.run_org_purge_job", probe.org_purge),
    ):
        yield


async def _let_tasks_run() -> None:
    """Give scheduled tasks a few loop turns to start."""
    for _ in range(5):
        await _REAL_SLEEP(0)


async def _run_lifespan(probe: _LifespanProbe, smtp_config: Any = None) -> None:
    """Start the app, let its tasks start, shut it down."""
    app = create_app(agent=MagicMock(), config=_make_app_config())
    with _patched_lifespan(probe, smtp_config):
        async with asyncio.timeout(5), _lifespan(app):
            await _let_tasks_run()


class TestLifespanRunsTheOrgPurge:
    """The org purge job runs while the app is up, like the audit retention job."""

    async def test_org_purge_lifespan_starts_the_job_with_the_pool(self) -> None:
        """After startup, run_org_purge_job(get_pool()) runs, once."""
        probe = _LifespanProbe()
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()
                assert len(probe.org_purge_calls) == 1
                args, kwargs = probe.org_purge_calls[0]
                pool = args[0] if args else kwargs.get("pool")
                assert pool is probe.pool

    async def test_org_purge_lifespan_uses_the_default_root_and_interval(self) -> None:
        """No other attachments root or interval than the module's defaults."""
        from admino import organizations

        probe = _LifespanProbe()
        await _run_lifespan(probe)

        ((args, kwargs),) = probe.org_purge_calls
        assert args[1:] == ()
        assert kwargs.get("attachments_root", organizations.ATTACHMENTS_ROOT) == (
            organizations.ATTACHMENTS_ROOT
        )
        assert kwargs.get("interval_seconds", organizations.PURGE_INTERVAL_SECONDS) == (
            organizations.PURGE_INTERVAL_SECONDS
        )
        assert set(kwargs) <= {"pool", "attachments_root", "interval_seconds"}

    async def test_org_purge_lifespan_starts_the_job_after_init_pool(self) -> None:
        """The job starts only once the pool exists."""
        probe = _LifespanProbe()
        await _run_lifespan(probe)

        assert "org-purge-started" in probe.events
        assert probe.events.index("init_pool") < probe.events.index("org-purge-started")

    async def test_org_purge_lifespan_runs_the_job_in_its_own_task(self) -> None:
        """A background task: the lifespan doesn't wait for the (endless) job."""
        probe = _LifespanProbe()
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()
                assert len(probe.org_purge_tasks) == 1
                assert probe.org_purge_tasks[0] is not asyncio.current_task()
                assert not probe.org_purge_tasks[0].done()

    async def test_org_purge_lifespan_cancels_the_job_on_shutdown(self) -> None:
        probe = _LifespanProbe()
        await _run_lifespan(probe)

        assert len(probe.org_purge_tasks) == 1
        assert probe.org_purge_tasks[0].cancelled()

    async def test_org_purge_lifespan_awaits_the_job_before_closing_the_pool(self) -> None:
        """The cancelled job finishes before the pool closes, so it never runs against a
        closed pool."""
        probe = _LifespanProbe()
        await _run_lifespan(probe)

        assert "org-purge-finished" in probe.events
        assert "close_pool" in probe.events
        assert probe.events.index("org-purge-finished") < probe.events.index("close_pool")

    @pytest.mark.parametrize(
        "smtp_config", [pytest.param(None, id="no-smtp"), pytest.param(MagicMock(), id="smtp")]
    )
    async def test_org_purge_lifespan_starts_with_or_without_smtp(self, smtp_config: Any) -> None:
        """The purge doesn't depend on email delivery (queued mail waits for SMTP)."""
        probe = _LifespanProbe()
        await _run_lifespan(probe, smtp_config)

        assert len(probe.org_purge_calls) == 1
        assert probe.events.index("org-purge-finished") < probe.events.index("close_pool")

    async def test_org_purge_lifespan_keeps_the_other_jobs(self) -> None:
        """The audit retention job and the session purge still start and stop before
        the pool closes."""
        probe = _LifespanProbe()
        await _run_lifespan(probe)

        for name in ("retention", "session-purge", "org-purge"):
            assert f"{name}-started" in probe.events
            assert probe.events.index(f"{name}-finished") < probe.events.index("close_pool")
