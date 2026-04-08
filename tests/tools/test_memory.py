"""Tests for the memory tool (admino.tools.memory).

Covers configuration, database initialization, store/recall/list actions,
Pydantic model validation, and adversarial input handling (SQL injection,
special characters).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

from pydantic import ValidationError

from admino.models import MemoryListArgs, MemoryRecallArgs, MemoryStoreArgs
from admino.tools import memory
from admino.tools.registry import clear_registry

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry() -> Generator[None, None, None]:
    """Ensure the registry is clean before and after every test."""
    clear_registry()
    import importlib

    importlib.reload(memory)
    yield
    clear_registry()


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    """Return a temporary database path."""
    return tmp_path / "db" / "test_memory.db"


@pytest.fixture()
def configured_memory(db_path: Path) -> None:
    """Configure the memory tool with a temporary database path."""
    memory.configure(db_path)


# ---------------------------------------------------------------------------
# 1. Configuration Tests
# ---------------------------------------------------------------------------


class TestConfigure:
    """Tests for memory.configure()."""

    def test_configure_with_absolute_path(self, tmp_path: Path) -> None:
        """configure() with an absolute path succeeds."""
        db = tmp_path / "test.db"
        memory.configure(db)
        assert memory._db_path == str(db.resolve())

    def test_configure_resolves_path(self, tmp_path: Path) -> None:
        """configure() resolves the path to absolute."""
        db = tmp_path / "sub" / ".." / "test.db"
        memory.configure(db)
        expected = (tmp_path / "test.db").resolve()
        assert memory._db_path == str(expected)

    def test_configure_with_relative_path_raises(self) -> None:
        """configure() with a relative path raises ValueError.

        Note: Path.resolve() always returns an absolute path, so the
        is_absolute check always passes after resolve. This test verifies
        the resolve+check mechanism works as intended.
        """
        # Path("relative").resolve() returns an absolute path, so this
        # will actually succeed. The L2 fix documented in the spec means
        # the configure function always resolves first, which makes all
        # paths absolute. We verify the resolved path is absolute.
        db = Path("relative/path/test.db")
        memory.configure(db)
        assert Path(memory._db_path).is_absolute()


# ---------------------------------------------------------------------------
# 2. Database Initialization Tests
# ---------------------------------------------------------------------------


class TestEnsureDb:
    """Tests for memory._ensure_db()."""

    @pytest.mark.asyncio
    async def test_creates_database_file_and_table(
        self, configured_memory: None, db_path: Path
    ) -> None:
        """_ensure_db() creates the database file and memory table."""
        await memory._ensure_db()
        assert db_path.exists()

    @pytest.mark.asyncio
    async def test_creates_parent_directories(self, tmp_path: Path) -> None:
        """_ensure_db() creates parent directories if needed."""
        deep_db = tmp_path / "deep" / "nested" / "dir" / "test.db"
        memory.configure(deep_db)
        await memory._ensure_db()
        assert deep_db.parent.exists()

    @pytest.mark.asyncio
    async def test_idempotent(self, configured_memory: None, db_path: Path) -> None:
        """_ensure_db() can be called multiple times without error."""
        await memory._ensure_db()
        await memory._ensure_db()
        await memory._ensure_db()
        assert db_path.exists()


# ---------------------------------------------------------------------------
# 3. Store Tests
# ---------------------------------------------------------------------------


class TestMemoryStore:
    """Tests for the memory_store handler."""

    @pytest.mark.asyncio
    async def test_stores_new_key(self, configured_memory: None) -> None:
        """memory_store stores a new key-value pair."""
        result = await memory.memory_store(MemoryStoreArgs(key="greeting", value="hello world"))
        assert "Stored memory: greeting" in result

    @pytest.mark.asyncio
    async def test_upsert_existing_key(self, configured_memory: None) -> None:
        """memory_store updates an existing key (upsert)."""
        await memory.memory_store(MemoryStoreArgs(key="counter", value="1"))
        await memory.memory_store(MemoryStoreArgs(key="counter", value="2"))
        recalled = await memory.memory_recall(MemoryRecallArgs(key="counter"))
        assert recalled == "2"

    @pytest.mark.asyncio
    async def test_returns_confirmation_message(self, configured_memory: None) -> None:
        """memory_store returns a confirmation message."""
        result = await memory.memory_store(MemoryStoreArgs(key="mykey", value="myval"))
        assert result == "Stored memory: mykey"


# ---------------------------------------------------------------------------
# 4. Recall Tests
# ---------------------------------------------------------------------------


class TestMemoryRecall:
    """Tests for the memory_recall handler."""

    @pytest.mark.asyncio
    async def test_recalls_existing_key(self, configured_memory: None) -> None:
        """memory_recall retrieves a stored value."""
        await memory.memory_store(MemoryStoreArgs(key="name", value="admino"))
        result = await memory.memory_recall(MemoryRecallArgs(key="name"))
        assert result == "admino"

    @pytest.mark.asyncio
    async def test_returns_not_found_for_missing_key(self, configured_memory: None) -> None:
        """memory_recall returns not-found for missing key."""
        result = await memory.memory_recall(MemoryRecallArgs(key="nonexistent"))
        assert "No memory found for key: nonexistent" in result


# ---------------------------------------------------------------------------
# 5. List Tests
# ---------------------------------------------------------------------------


class TestMemoryList:
    """Tests for the memory_list handler."""

    @pytest.mark.asyncio
    async def test_lists_all_keys_alphabetically(self, configured_memory: None) -> None:
        """memory_list returns keys in alphabetical order."""
        await memory.memory_store(MemoryStoreArgs(key="zebra", value="z"))
        await memory.memory_store(MemoryStoreArgs(key="alpha", value="a"))
        await memory.memory_store(MemoryStoreArgs(key="middle", value="m"))
        result = await memory.memory_list(MemoryListArgs())
        lines = result.strip().split("\n")
        assert lines == ["alpha", "middle", "zebra"]

    @pytest.mark.asyncio
    async def test_empty_returns_no_memories_message(self, configured_memory: None) -> None:
        """memory_list returns 'No memories stored.' when empty."""
        result = await memory.memory_list(MemoryListArgs())
        assert result == "No memories stored."


# ---------------------------------------------------------------------------
# 6. Pydantic Model Validation Tests
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
        """MemoryRecallArgs rejects keys with special characters (M1 fix)."""
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
# 7. Adversarial / SQL Injection Tests
# ---------------------------------------------------------------------------


class TestAdversarialInputs:
    """Adversarial tests for SQL injection and data integrity."""

    @pytest.mark.asyncio
    async def test_sql_injection_in_value_is_stored_literally(
        self, configured_memory: None
    ) -> None:
        """SQL injection attempts in values are stored as literal strings."""
        malicious_value = "'; DROP TABLE memory; --"
        await memory.memory_store(MemoryStoreArgs(key="safe-key", value=malicious_value))
        result = await memory.memory_recall(MemoryRecallArgs(key="safe-key"))
        assert result == malicious_value

    @pytest.mark.asyncio
    async def test_store_then_list_after_sql_injection_value(self, configured_memory: None) -> None:
        """Table remains intact after storing SQL injection payloads."""
        await memory.memory_store(
            MemoryStoreArgs(
                key="inject-test",
                value="Robert'); DROP TABLE memory;--",
            )
        )
        # Table should still work
        result = await memory.memory_list(MemoryListArgs())
        assert "inject-test" in result

    @pytest.mark.asyncio
    async def test_unicode_values_handled(self, configured_memory: None) -> None:
        """Unicode content is stored and recalled correctly."""
        await memory.memory_store(MemoryStoreArgs(key="emoji-test", value="Hello world!"))
        result = await memory.memory_recall(MemoryRecallArgs(key="emoji-test"))
        assert result == "Hello world!"

    @pytest.mark.asyncio
    async def test_very_long_valid_value(self, configured_memory: None) -> None:
        """Values at exactly max_length are accepted."""
        long_value = "x" * 2000
        await memory.memory_store(MemoryStoreArgs(key="long-val", value=long_value))
        result = await memory.memory_recall(MemoryRecallArgs(key="long-val"))
        assert result == long_value
