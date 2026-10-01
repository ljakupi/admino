"""Shared pytest fixtures for the admino test suite.

Provides common mocks for the PostgreSQL connection pool (asyncpg.Pool),
the recorder of the login throttle's progressive delays (GH-157), the primed
platform settings cache (GH-160) and other shared test infrastructure.

Security notes:
- All fixtures use mocks — no real database connections are made.
- No test ever really sleeps for a login delay: a test that can reach one
  (four or more failed attempts sharing an email or an IP) requests
  ``login_delays``.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator


def default_test_platform_settings() -> Any:
    """The StoredPlatformSettings of a default platform row (GH-160).

    Equal to what ``db_fakes.FakeDb.add_platform_settings()`` stores without
    arguments: Infomaniak with its model and vLLM's set, the Anthropic and
    OpenAI models unset, the LimitsConfig defaults (10, 3, 300, 4000, 20) and
    the section defaults of migration 0014.
    """
    from admino import scoped_settings

    return scoped_settings.StoredPlatformSettings.model_validate(
        {
            "llm": {
                "provider": "infomaniak",
                "infomaniak_model": "Qwen/Qwen3.5-397B-A17B-FP8",
                "vllm_model": "Qwen/Qwen3-4B-Instruct-2507",
                "anthropic_model": None,
                "openai_model": None,
            },
            "limits": {
                "max_tool_calls_per_message": 10,
                "max_pending_confirmations": 3,
                "confirmation_timeout_s": 300,
                "max_message_length": 4000,
                "max_context_messages": 20,
            },
        }
    )


@pytest.fixture(autouse=True)
def _platform_settings_cache() -> Generator[None, None, None]:
    """Prime the platform settings cache before every test, restore it after (GH-160).

    Consumers (login, the login throttle, the org deletion schedule, the
    message routes) read the platform settings through
    ``scoped_settings.current_platform_settings``, which answers from
    ``scoped_settings._platform_cache`` without a query. Startup primes it in
    production; here every test starts from ``default_test_platform_settings()``.
    A test of the loading path sets the cache to None first; a test that needs
    other values sets the cache directly, or adds a FakeDb row and sets it to
    None. Plain attribute access (not monkeypatch), like the fixture above.
    """
    from admino import scoped_settings

    previous = getattr(scoped_settings, "_platform_cache", None)
    scoped_settings._platform_cache = default_test_platform_settings()
    try:
        yield
    finally:
        scoped_settings._platform_cache = previous


@pytest.fixture()
def login_delays(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record the progressive delays of the login throttle instead of sleeping (GH-157).

    ``admino.login_throttle`` awaits every delay through its module attribute
    ``sleep`` (an alias of ``asyncio.sleep``); this replaces it with a recorder
    and returns the list of requested delays, in order. Not autouse, and the
    module is imported here, lazily: before it exists only the tests that ask
    for this fixture fail.
    """
    import admino.login_throttle as login_throttle

    delays: list[float] = []

    async def record(delay: float, *_args: Any, **_kwargs: Any) -> None:
        delays.append(float(delay))

    monkeypatch.setattr(login_throttle, "sleep", record)
    return delays


@pytest.fixture(autouse=True)
def _default_anthropic_key() -> Generator[None, None, None]:
    """Provide ANTHROPIC_API_KEY so anthropic-provider tests have a key by default.

    Many tests build ``provider="anthropic"`` configs/clients. Since GH-142 a
    missing key no longer fails validation (it logs a warning and chat explains),
    but tests that exercise the missing/empty-key path still override this with
    ``monkeypatch.delenv`` or ``patch.dict(..., clear=True)``.

    Managed via os.environ directly (not monkeypatch) so this autouse fixture does
    not pull ``monkeypatch`` into an early setup slot, which would reorder other
    fixtures' teardown (e.g. the registry-clearing fixture in test_registry.py).
    """
    previous = os.environ.get("ANTHROPIC_API_KEY")
    os.environ["ANTHROPIC_API_KEY"] = "sk-ant-test-suite-key"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("ANTHROPIC_API_KEY", None)
        else:
            os.environ["ANTHROPIC_API_KEY"] = previous


@pytest.fixture()
def mock_pool() -> MagicMock:
    """Return a MagicMock with spec=asyncpg.Pool and async method stubs.

    Supports:
    - pool.execute (AsyncMock)
    - pool.fetch (AsyncMock)
    - pool.fetchrow (AsyncMock)
    - pool.fetchval (AsyncMock)
    - pool.acquire() as async context manager yielding a mock connection
    - pool.close (AsyncMock)
    """
    pool = MagicMock(spec=["execute", "fetch", "fetchrow", "fetchval", "acquire", "close"])
    pool.execute = AsyncMock()
    pool.fetch = AsyncMock(return_value=[])
    pool.fetchrow = AsyncMock(return_value=None)
    pool.fetchval = AsyncMock(return_value=None)
    pool.close = AsyncMock()

    # Build mock connection with the same async methods.
    mock_conn = MagicMock()
    mock_conn.execute = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=[])
    mock_conn.fetchrow = AsyncMock(return_value=None)
    mock_conn.fetchval = AsyncMock(return_value=None)

    # mock_conn.transaction() returns an async context manager
    mock_txn = AsyncMock()
    mock_txn.__aenter__ = AsyncMock(return_value=mock_txn)
    mock_txn.__aexit__ = AsyncMock(return_value=False)
    mock_conn.transaction = MagicMock(return_value=mock_txn)

    # pool.acquire() returns an async context manager yielding mock_conn
    mock_acquire = AsyncMock()
    mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_acquire.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=mock_acquire)

    # Stash the connection mock for test assertions
    pool._mock_conn = mock_conn

    return pool
