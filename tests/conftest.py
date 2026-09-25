"""Shared pytest fixtures for the admino test suite.

Provides common mocks for the PostgreSQL connection pool (asyncpg.Pool)
and other shared test infrastructure.

Security notes:
- All fixtures use mocks — no real database connections are made.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator


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
