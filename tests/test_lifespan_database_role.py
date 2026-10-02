"""The server lifespan connects as the least-privilege runtime role (GH-220).

The running app must never hold the owner credential: the postgres image's
superuser ``admino`` (POSTGRES_USER, password PG_PASSWORD) can switch off the
append-only trigger on ``audit_events`` (``SET session_replication_role``), drop
it, or run ``COPY ... TO PROGRAM``. Only the one-shot migrate step
(``python -m admino.migrate``) connects as the owner. The server lifespan
connects as ``admino_app`` with PG_APP_PASSWORD, through
``admino.database.database_url_from_env()``: it builds no DSN itself, and
never reads PG_USER or PG_PASSWORD.

Spec (contract section 4):
- ``init_pool`` receives exactly ``database_url_from_env()``'s value:
  ``postgresql://admino_app:{quote(PG_APP_PASSWORD, safe='')}@{PG_HOST}:{PG_PORT}/{PG_DATABASE}``
  (percent-encoding that asyncpg decodes back exactly: it unquotes the DSN
  password with ``urllib.parse.unquote``, so a space must be %20, never '+')
  (defaults localhost, 5432, admino), even when PG_USER/PG_PASSWORD hold the
  owner's values; the owner password never appears in the DSN.
- ``database_url_from_env()`` returning None (PG_APP_PASSWORD unset or empty)
  makes the lifespan raise a RuntimeError naming PG_APP_PASSWORD before
  ``init_pool`` is called, even when PG_PASSWORD is set (no fallback to the
  owner credential).
- server.py contains neither PG_PASSWORD nor PG_USER, and ``_lifespan``
  doesn't build a ``postgresql://`` URL or call ``quote_plus`` itself.

The lifespan is driven directly with the pool functions and every background
job replaced by a fake (the pattern of tests/test_org_purge_lifespan.py).

Security notes:
- Secret markers (the owner password, the runtime password) are asserted
  absent from the DSN and from the error message.
- No real database is touched: ``init_pool`` is a recording fake.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import unquote, urlsplit

import pytest

from admino import database, server
from admino.server import _lifespan, create_app
from tests.lifespan_stubs import patch_login_throttle_purge_job

if TYPE_CHECKING:
    from collections.abc import Iterator

_SERVER_MODULE_PATH = Path(__file__).resolve().parent.parent / "src" / "admino" / "server.py"

_OWNER_USER = "admino"
_OWNER_PASSWORD = "owner-secret"
# "/", "@" and " " would break the DSN unencoded (%2F, %40, %20). A space is %20,
# not quote_plus's "+": asyncpg decodes the password with unquote, so "+" would
# reach PostgreSQL as a literal "+".
_APP_PASSWORD = "app/S3cret@pw word"
_APP_PASSWORD_ENCODED = "app%2FS3cret%40pw%20word"
_PG_LOCATION_VARS = ("PG_HOST", "PG_PORT", "PG_DATABASE")


def _make_app_config() -> MagicMock:
    """A minimal mock AppConfig for create_app."""
    config = MagicMock()
    config.limits.max_message_length = 4000
    config.server.host = "0.0.0.0"  # noqa: S104
    config.server.port = 8000
    return config


class _PoolProbe:
    """Records every init_pool call; the fake pool the lifespan's jobs would get."""

    def __init__(self) -> None:
        self.pool: Any = MagicMock(name="pool")
        self.init_pool_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def dsn(self) -> str:
        """The DSN of the single init_pool call (positional or ``database_url=``)."""
        assert len(self.init_pool_calls) == 1, self.init_pool_calls
        args, kwargs = self.init_pool_calls[0]
        value = args[0] if args else kwargs["database_url"]
        assert isinstance(value, str)
        return value


@contextlib.contextmanager
def _patched_lifespan(probe: _PoolProbe) -> Iterator[None]:
    """Patch the lifespan's pool functions and stub every background job (they finish
    at once). get_pool() raises until init_pool() ran, like the real one."""
    state: dict[str, Any] = {"pool": None}

    async def fake_init_pool(*args: Any, **kwargs: Any) -> Any:
        probe.init_pool_calls.append((args, kwargs))
        state["pool"] = probe.pool
        return probe.pool

    def fake_get_pool() -> Any:
        if state["pool"] is None:
            msg = "Database pool not initialised"
            raise RuntimeError(msg)
        return state["pool"]

    async def fake_close_pool() -> None:
        state["pool"] = None

    with (
        patch("admino.database.init_pool", fake_init_pool),
        patch("admino.database.close_pool", fake_close_pool),
        patch("admino.database.get_pool", fake_get_pool),
        patch("admino.audit_events.run_retention_job", AsyncMock()),
        patch("admino.sessions.run_session_purge_job", AsyncMock()),
        patch("admino.mailer.load_smtp_config", MagicMock(return_value=None)),
        patch("admino.email_outbox.run_outbox_sender", AsyncMock()),
        patch("admino.organizations.run_org_purge_job", AsyncMock()),
        patch_login_throttle_purge_job(AsyncMock()),
    ):
        yield


async def _run_lifespan(probe: _PoolProbe) -> None:
    """Start the app's lifespan and shut it down again."""
    app = create_app(agent=MagicMock(), config=_make_app_config())
    with _patched_lifespan(probe):
        async with asyncio.timeout(5), _lifespan(app):
            pass


@contextlib.contextmanager
def _patched_url_builder(value: str | None) -> Iterator[None]:
    """Make database_url_from_env() return ``value``, whether the lifespan looks it up
    on admino.database at call time or imported it into admino.server."""
    builder = MagicMock(return_value=value)
    with (
        patch("admino.database.database_url_from_env", builder),
        patch("admino.server.database_url_from_env", builder, create=True),
    ):
        yield


def _set_owner_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The owner's variables, as an agent container that wrongly got them would see."""
    monkeypatch.setenv("PG_USER", _OWNER_USER)
    monkeypatch.setenv("PG_PASSWORD", _OWNER_PASSWORD)


class TestLifespanConnectsAsTheRuntimeRole:
    """init_pool gets the runtime DSN: user admino_app, password PG_APP_PASSWORD."""

    @pytest.mark.parametrize(
        "owner_env", [pytest.param(True, id="owner-vars-set"), pytest.param(False, id="no-owner")]
    )
    async def test_lifespan_dsn_uses_admino_app_and_the_encoded_app_password(
        self, monkeypatch: pytest.MonkeyPatch, owner_env: bool
    ) -> None:
        """With PG_HOST/PG_PORT/PG_DATABASE set, the DSN is exactly
        ``postgresql://admino_app:<percent-encoded PG_APP_PASSWORD>@host:port/db``, whether or
        not PG_USER/PG_PASSWORD are set."""
        monkeypatch.setenv("PG_HOST", "db.internal")
        monkeypatch.setenv("PG_PORT", "6543")
        monkeypatch.setenv("PG_DATABASE", "admino_prod")
        monkeypatch.setenv("PG_APP_PASSWORD", _APP_PASSWORD)
        if owner_env:
            _set_owner_env(monkeypatch)
        else:
            monkeypatch.delenv("PG_USER", raising=False)
            monkeypatch.delenv("PG_PASSWORD", raising=False)
        probe = _PoolProbe()

        await _run_lifespan(probe)

        assert probe.dsn() == (
            f"postgresql://admino_app:{_APP_PASSWORD_ENCODED}@db.internal:6543/admino_prod"
        )

    async def test_lifespan_dsn_defaults_to_localhost_5432_admino(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without PG_HOST/PG_PORT/PG_DATABASE the DSN points at localhost:5432/admino,
        still as admino_app with the conftest PG_APP_PASSWORD."""
        for name in _PG_LOCATION_VARS:
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("PG_APP_PASSWORD", "test-suite-app-db-password")
        _set_owner_env(monkeypatch)
        probe = _PoolProbe()

        await _run_lifespan(probe)

        assert probe.dsn() == (
            "postgresql://admino_app:test-suite-app-db-password@localhost:5432/admino"
        )

    async def test_lifespan_dsn_is_exactly_database_url_from_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """init_pool gets the same string database.database_url_from_env() returns for the
        same environment, and that string is the runtime one (not the owner's)."""
        for name in _PG_LOCATION_VARS:
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("PG_APP_PASSWORD", _APP_PASSWORD)
        _set_owner_env(monkeypatch)
        probe = _PoolProbe()

        await _run_lifespan(probe)

        expected = f"postgresql://admino_app:{_APP_PASSWORD_ENCODED}@localhost:5432/admino"
        assert probe.dsn() == expected
        assert database.database_url_from_env() == expected

    async def test_lifespan_dsn_never_carries_the_owner_credential(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The DSN's user is admino_app and its password decodes to PG_APP_PASSWORD (with
        unquote, as asyncpg does); the owner user and the owner password never appear in it."""
        monkeypatch.setenv("PG_APP_PASSWORD", _APP_PASSWORD)
        _set_owner_env(monkeypatch)
        probe = _PoolProbe()

        await _run_lifespan(probe)

        dsn = probe.dsn()
        parts = urlsplit(dsn)
        assert parts.scheme == "postgresql"
        assert parts.username == "admino_app"
        assert unquote(parts.password or "") == _APP_PASSWORD
        assert _OWNER_PASSWORD not in dsn
        assert f"//{_OWNER_USER}:" not in dsn

    async def test_lifespan_passes_on_whatever_database_url_from_env_returns(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The lifespan delegates to database_url_from_env() (no inline DSN building):
        init_pool gets its return value unchanged."""
        _set_owner_env(monkeypatch)
        sentinel = "postgresql://admino_app:sentinel-pw@sentinel-host:6000/sentinel_db"
        probe = _PoolProbe()

        with _patched_url_builder(sentinel):
            await _run_lifespan(probe)

        assert probe.dsn() == sentinel


class TestLifespanWithoutTheAppPassword:
    """No PG_APP_PASSWORD: the lifespan refuses to start, before anything connects."""

    @pytest.mark.parametrize(
        "app_password", [pytest.param(None, id="unset"), pytest.param("", id="empty")]
    )
    async def test_lifespan_without_pg_app_password_raises_before_init_pool(
        self, monkeypatch: pytest.MonkeyPatch, app_password: str | None
    ) -> None:
        """An unset or empty PG_APP_PASSWORD raises a RuntimeError naming it and never
        calls init_pool, even with the owner's PG_USER/PG_PASSWORD set (no fallback to
        the owner credential); the message carries no password."""
        _set_owner_env(monkeypatch)
        if app_password is None:
            monkeypatch.delenv("PG_APP_PASSWORD", raising=False)
        else:
            monkeypatch.setenv("PG_APP_PASSWORD", app_password)
        probe = _PoolProbe()

        with pytest.raises(RuntimeError, match="PG_APP_PASSWORD") as exc_info:
            await _run_lifespan(probe)

        assert probe.init_pool_calls == []
        assert _OWNER_PASSWORD not in str(exc_info.value)

    async def test_lifespan_raises_when_database_url_from_env_returns_none(self) -> None:
        """The missing-password decision is database_url_from_env()'s: when it returns
        None the lifespan raises a RuntimeError naming PG_APP_PASSWORD and never calls
        init_pool (even though the environment has a PG_APP_PASSWORD)."""
        probe = _PoolProbe()

        with (
            _patched_url_builder(None),
            pytest.raises(RuntimeError, match="PG_APP_PASSWORD"),
        ):
            await _run_lifespan(probe)

        assert probe.init_pool_calls == []


class TestServerSourceNeverReadsTheOwnerCredential:
    """Static checks: only admino.migrate knows the owner variables."""

    @pytest.mark.parametrize("name", ["PG_PASSWORD", "PG_USER"])
    def test_server_module_never_mentions_the_owner_variables(self, name: str) -> None:
        """server.py (code, messages and docstrings) contains neither PG_PASSWORD nor
        PG_USER as a word."""
        source = _SERVER_MODULE_PATH.read_text(encoding="utf-8")

        assert re.search(rf"\b{name}\b", source) is None

    def test_lifespan_builds_no_dsn_itself(self) -> None:
        """_lifespan neither assembles a ``postgresql://`` URL nor percent-encodes a
        password: database_url_from_env() is the only DSN builder."""
        source = inspect.getsource(server._lifespan)

        assert "postgresql://" not in source
        assert "quote_plus" not in source
