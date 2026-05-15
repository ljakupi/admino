"""Shared pytest fixtures for the admino test suite.

Provides common mocks for the PostgreSQL connection pool (asyncpg.Pool)
and other shared test infrastructure.

Security notes:
- All fixtures use mocks — no real database connections are made.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest


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
