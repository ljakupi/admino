"""Tests for the memory tool (admino.tools.memory) — PostgreSQL-backed.

Covers store/recall/list actions with a mocked asyncpg pool,
Pydantic model validation, and adversarial input handling.

Security notes:
- All database calls are mocked — no real PostgreSQL connections.
- Verifies parameterized queries ($1, $2) are used, not string interpolation.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from admino.models import MemoryListArgs, MemoryRecallArgs, MemoryStoreArgs


@pytest.fixture()
def mock_pool() -> MagicMock:
    """Return a mock asyncpg pool for memory tool tests."""
    pool = MagicMock()
    pool.execute = AsyncMock()
    pool.fetch = AsyncMock(return_value=[])
    pool.fetchrow = AsyncMock(return_value=None)
    pool.fetchval = AsyncMock(return_value=None)
    return pool


# ---------------------------------------------------------------------------
# 1. Store Tests
# ---------------------------------------------------------------------------


class TestMemoryStore:
    """Tests for the memory_store handler."""

    async def test_stores_new_key(self, mock_pool: MagicMock) -> None:
        """memory_store calls pool.execute with INSERT/ON CONFLICT SQL."""
        from admino.tools.memory import memory_store

        with patch("admino.tools.memory.get_pool", return_value=mock_pool):
            result = await memory_store(MemoryStoreArgs(key="greeting", value="hello world"))

        assert "Stored memory: greeting" in result
        mock_pool.execute.assert_awaited_once()

    async def test_store_uses_parameterized_query(self, mock_pool: MagicMock) -> None:
        """memory_store uses $1, $2 placeholders, not string interpolation."""
        from admino.tools.memory import memory_store

        with patch("admino.tools.memory.get_pool", return_value=mock_pool):
            await memory_store(MemoryStoreArgs(key="mykey", value="myval"))

        call_args = mock_pool.execute.call_args
        sql = call_args.args[0]
        assert "$1" in sql
        assert "$2" in sql
        assert call_args.args[1] == "mykey"
        assert call_args.args[2] == "myval"

    async def test_returns_confirmation_message(self, mock_pool: MagicMock) -> None:
        """memory_store returns 'Stored memory: <key>'."""
        from admino.tools.memory import memory_store

        with patch("admino.tools.memory.get_pool", return_value=mock_pool):
            result = await memory_store(MemoryStoreArgs(key="mykey", value="myval"))

        assert result == "Stored memory: mykey"


# ---------------------------------------------------------------------------
# 2. Recall Tests
# ---------------------------------------------------------------------------


class TestMemoryRecall:
    """Tests for the memory_recall handler."""

    async def test_recalls_existing_key(self, mock_pool: MagicMock) -> None:
        """memory_recall returns the value when a row is found."""
        from admino.tools.memory import memory_recall

        mock_pool.fetchrow = AsyncMock(return_value={"value": "admino"})

        with patch("admino.tools.memory.get_pool", return_value=mock_pool):
            result = await memory_recall(MemoryRecallArgs(key="name"))

        assert result == "admino"

    async def test_returns_not_found_for_missing_key(self, mock_pool: MagicMock) -> None:
        """memory_recall returns not-found when fetchrow returns None."""
        from admino.tools.memory import memory_recall

        mock_pool.fetchrow = AsyncMock(return_value=None)

        with patch("admino.tools.memory.get_pool", return_value=mock_pool):
            result = await memory_recall(MemoryRecallArgs(key="nonexistent"))

        assert "No memory found for key: nonexistent" in result

    async def test_recall_uses_parameterized_query(self, mock_pool: MagicMock) -> None:
        """memory_recall uses $1 placeholder for the key."""
        from admino.tools.memory import memory_recall

        mock_pool.fetchrow = AsyncMock(return_value=None)

        with patch("admino.tools.memory.get_pool", return_value=mock_pool):
            await memory_recall(MemoryRecallArgs(key="testkey"))

        call_args = mock_pool.fetchrow.call_args
        sql = call_args.args[0]
        assert "$1" in sql
        assert call_args.args[1] == "testkey"


# ---------------------------------------------------------------------------
# 3. List Tests
# ---------------------------------------------------------------------------


class TestMemoryList:
    """Tests for the memory_list handler."""

    async def test_lists_all_keys(self, mock_pool: MagicMock) -> None:
        """memory_list returns keys from pool.fetch results."""
        from admino.tools.memory import memory_list

        mock_pool.fetch = AsyncMock(
            return_value=[{"key": "alpha"}, {"key": "middle"}, {"key": "zebra"}]
        )

        with patch("admino.tools.memory.get_pool", return_value=mock_pool):
            result = await memory_list(MemoryListArgs())

        lines = result.strip().split("\n")
        assert lines == ["alpha", "middle", "zebra"]

    async def test_empty_returns_no_memories_message(self, mock_pool: MagicMock) -> None:
        """memory_list returns 'No memories stored.' when fetch returns empty."""
        from admino.tools.memory import memory_list

        mock_pool.fetch = AsyncMock(return_value=[])

        with patch("admino.tools.memory.get_pool", return_value=mock_pool):
            result = await memory_list(MemoryListArgs())

        assert result == "No memories stored."


# ---------------------------------------------------------------------------
# 4. Pydantic Model Validation Tests
# ---------------------------------------------------------------------------


class TestMemoryModelValidation:
    """Tests for Pydantic model constraints on memory arg models."""

    @pytest.mark.parametrize(
        "invalid_key",
        [
            "key\x00null",
            "key;DROP TABLE",
            "key' OR '1'='1",
            "key<script>",
            "key\ninjection",
            "",
        ],
    )
    def test_store_args_rejects_special_chars(self, invalid_key: str) -> None:
        """MemoryStoreArgs rejects keys with special characters."""
        with pytest.raises(ValidationError):
            MemoryStoreArgs(key=invalid_key, value="test")

    @pytest.mark.parametrize(
        "invalid_key",
        [
            "key\x00null",
            "key;DROP TABLE",
            "key' OR '1'='1",
            "",
        ],
    )
    def test_recall_args_rejects_special_chars(self, invalid_key: str) -> None:
        """MemoryRecallArgs rejects keys with special characters."""
        with pytest.raises(ValidationError):
            MemoryRecallArgs(key=invalid_key)

    def test_store_args_max_key_length(self) -> None:
        """MemoryStoreArgs rejects keys exceeding max_length."""
        with pytest.raises(ValidationError):
            MemoryStoreArgs(key="a" * 201, value="test")

    def test_store_args_max_value_length(self) -> None:
        """MemoryStoreArgs rejects values exceeding max_length."""
        with pytest.raises(ValidationError):
            MemoryStoreArgs(key="mykey", value="x" * 2001)

    def test_store_args_valid_key(self) -> None:
        """MemoryStoreArgs accepts valid keys."""
        args = MemoryStoreArgs(key="my-key_v2.0", value="test value")
        assert args.key == "my-key_v2.0"

    def test_recall_args_valid_key(self) -> None:
        """MemoryRecallArgs accepts valid keys."""
        args = MemoryRecallArgs(key="my-key_v2.0")
        assert args.key == "my-key_v2.0"

    def test_store_args_key_with_spaces(self) -> None:
        """MemoryStoreArgs accepts keys with spaces."""
        args = MemoryStoreArgs(key="my key", value="val")
        assert args.key == "my key"


# ---------------------------------------------------------------------------
# 5. Adversarial / SQL Injection Tests
# ---------------------------------------------------------------------------


class TestAdversarialInputs:
    """Adversarial tests verifying parameterized queries block SQL injection."""

    async def test_sql_injection_in_value_uses_parameterized_query(
        self, mock_pool: MagicMock
    ) -> None:
        """SQL injection attempts in values are passed as parameters, not interpolated."""
        from admino.tools.memory import memory_store

        malicious_value = "'; DROP TABLE memory; --"
        with patch("admino.tools.memory.get_pool", return_value=mock_pool):
            await memory_store(MemoryStoreArgs(key="safe-key", value=malicious_value))

        call_args = mock_pool.execute.call_args
        sql = call_args.args[0]
        # The malicious value must NOT appear in the SQL string itself
        assert "DROP TABLE" not in sql
        # It must be passed as a separate parameter
        assert call_args.args[2] == malicious_value

    async def test_unicode_values_passed_as_parameters(self, mock_pool: MagicMock) -> None:
        """Unicode content is passed as a parameter to pool.execute."""
        from admino.tools.memory import memory_store

        with patch("admino.tools.memory.get_pool", return_value=mock_pool):
            await memory_store(MemoryStoreArgs(key="emoji-test", value="Hello world!"))

        call_args = mock_pool.execute.call_args
        assert call_args.args[2] == "Hello world!"

    async def test_very_long_valid_value_passed_as_parameter(self, mock_pool: MagicMock) -> None:
        """Values at exactly max_length are passed as parameters."""
        from admino.tools.memory import memory_store

        long_value = "x" * 2000
        with patch("admino.tools.memory.get_pool", return_value=mock_pool):
            await memory_store(MemoryStoreArgs(key="long-val", value=long_value))

        call_args = mock_pool.execute.call_args
        assert call_args.args[2] == long_value

    async def test_recall_sql_injection_key_rejected_by_pydantic(self) -> None:
        """SQL injection in recall key is rejected by Pydantic validation."""
        with pytest.raises(ValidationError):
            MemoryRecallArgs(key="'; DROP TABLE memory; --")
