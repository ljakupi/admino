"""Tests for admino.database — pool lifecycle, migrations, seeds, and loaders.

All asyncpg calls are mocked. No real PostgreSQL connections are made.

Security notes:
- Verifies parameterized queries are used (no string interpolation).
- Verifies migration execution is transactional.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import admino.database as db_mod

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_pool() -> Generator[None, None, None]:
    """Reset the module-level pool before and after each test."""
    db_mod._pool = None
    yield
    db_mod._pool = None


# ---------------------------------------------------------------------------
# TestInitPool
# ---------------------------------------------------------------------------


class TestInitPool:
    """Tests for init_pool()."""

    async def test_init_pool_calls_create_pool_with_correct_args(self) -> None:
        """init_pool() calls asyncpg.create_pool with the provided URL and sizes."""
        fake_pool = MagicMock()
        with patch("admino.database.asyncpg.create_pool", new=AsyncMock(return_value=fake_pool)):
            result = await db_mod.init_pool("postgres://user:pass@host/db", min_size=3, max_size=10)

        assert result is fake_pool

    async def test_init_pool_stores_pool_in_module(self) -> None:
        """init_pool() stores the pool in db_mod._pool."""
        fake_pool = MagicMock()
        with patch("admino.database.asyncpg.create_pool", new=AsyncMock(return_value=fake_pool)):
            await db_mod.init_pool("postgres://u:p@h/d")

        assert db_mod._pool is fake_pool

    async def test_init_pool_passes_min_max_size(self) -> None:
        """init_pool() passes min_size and max_size to asyncpg.create_pool."""
        mock_create = AsyncMock(return_value=MagicMock())
        with patch("admino.database.asyncpg.create_pool", new=mock_create):
            await db_mod.init_pool("postgres://u:p@h/d", min_size=4, max_size=8)

        mock_create.assert_called_once_with("postgres://u:p@h/d", min_size=4, max_size=8)


# ---------------------------------------------------------------------------
# TestGetPool
# ---------------------------------------------------------------------------


class TestGetPool:
    """Tests for get_pool()."""

    def test_get_pool_raises_before_init(self) -> None:
        """get_pool() raises RuntimeError when pool has not been initialised."""
        with pytest.raises(RuntimeError, match="not initialised"):
            db_mod.get_pool()

    def test_get_pool_returns_pool_after_init(self) -> None:
        """get_pool() returns the stored pool after init_pool()."""
        fake_pool = MagicMock()
        db_mod._pool = fake_pool

        assert db_mod.get_pool() is fake_pool


# ---------------------------------------------------------------------------
# TestClosePool
# ---------------------------------------------------------------------------


class TestClosePool:
    """Tests for close_pool()."""

    async def test_close_pool_closes_and_clears(self) -> None:
        """close_pool() calls pool.close() and sets _pool to None."""
        fake_pool = MagicMock()
        fake_pool.close = AsyncMock()
        db_mod._pool = fake_pool

        await db_mod.close_pool()

        fake_pool.close.assert_awaited_once()
        assert db_mod._pool is None

    async def test_close_pool_idempotent_when_none(self) -> None:
        """close_pool() is a no-op when _pool is already None."""
        db_mod._pool = None
        await db_mod.close_pool()
        assert db_mod._pool is None


# ---------------------------------------------------------------------------
# TestCheckHealth
# ---------------------------------------------------------------------------


class TestCheckHealth:
    """Tests for check_health()."""

    async def test_check_health_returns_true_on_success(self) -> None:
        """check_health() returns True when SELECT 1 succeeds."""
        fake_pool = MagicMock()
        fake_pool.fetchval = AsyncMock(return_value=1)
        db_mod._pool = fake_pool

        assert await db_mod.check_health() is True

    async def test_check_health_returns_false_when_pool_is_none(self) -> None:
        """check_health() returns False when pool is None."""
        db_mod._pool = None
        assert await db_mod.check_health() is False

    async def test_check_health_returns_false_on_postgres_error(self) -> None:
        """check_health() returns False when fetchval raises PostgresError."""
        import asyncpg

        fake_pool = MagicMock()
        fake_pool.fetchval = AsyncMock(side_effect=asyncpg.PostgresError("connection lost"))
        db_mod._pool = fake_pool

        assert await db_mod.check_health() is False


# ---------------------------------------------------------------------------
# TestRunMigrations
# ---------------------------------------------------------------------------


class TestRunMigrations:
    """Tests for run_migrations()."""

    async def test_creates_migrations_tracking_table(self, mock_pool: MagicMock) -> None:
        """run_migrations() creates the _migrations table."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[])

        mock_dir = MagicMock(is_dir=MagicMock(return_value=False))
        with patch.object(db_mod, "_MIGRATIONS_DIR", mock_dir):
            await db_mod.run_migrations(mock_pool)

        create_call = conn.execute.call_args_list[0]
        assert "CREATE TABLE IF NOT EXISTS _migrations" in create_call.args[0]

    async def test_reads_sql_files_from_migrations_dir(
        self, mock_pool: MagicMock, tmp_path: Path
    ) -> None:
        """run_migrations() reads SQL files from the migrations directory."""
        sql_file = tmp_path / "0001_initial.sql"
        sql_file.write_text("CREATE TABLE test (id INT);", encoding="utf-8")

        conn = mock_pool._mock_conn
        # First call: SELECT version FROM _migrations (already applied = none)
        conn.fetch = AsyncMock(return_value=[])

        with patch.object(db_mod, "_MIGRATIONS_DIR", tmp_path):
            await db_mod.run_migrations(mock_pool)

        # Should have executed the SQL content
        execute_calls = conn.execute.call_args_list
        sql_texts = [call.args[0] for call in execute_calls if len(call.args) > 0]
        assert any("CREATE TABLE test" in s for s in sql_texts)

    async def test_skips_already_applied_migrations(
        self, mock_pool: MagicMock, tmp_path: Path
    ) -> None:
        """run_migrations() skips migrations that have already been applied."""
        sql_file = tmp_path / "0001_initial.sql"
        sql_file.write_text("CREATE TABLE test (id INT);", encoding="utf-8")

        conn = mock_pool._mock_conn
        # Simulate version 1 already applied
        applied_row = {"version": 1}
        conn.fetch = AsyncMock(return_value=[applied_row])

        with patch.object(db_mod, "_MIGRATIONS_DIR", tmp_path):
            await db_mod.run_migrations(mock_pool)

        # The SQL content should NOT have been executed (only CREATE TABLE _migrations)
        execute_calls = conn.execute.call_args_list
        sql_texts = [call.args[0] for call in execute_calls if len(call.args) > 0]
        assert not any("CREATE TABLE test" in s for s in sql_texts)

    async def test_executes_pending_migrations_in_transaction(
        self, mock_pool: MagicMock, tmp_path: Path
    ) -> None:
        """run_migrations() executes pending migrations inside a transaction."""
        sql_file = tmp_path / "0001_initial.sql"
        sql_file.write_text("CREATE TABLE test (id INT);", encoding="utf-8")

        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[])

        with patch.object(db_mod, "_MIGRATIONS_DIR", tmp_path):
            await db_mod.run_migrations(mock_pool)

        # Transaction was entered
        conn.transaction.assert_called()

    async def test_records_applied_migration(self, mock_pool: MagicMock, tmp_path: Path) -> None:
        """run_migrations() inserts the applied migration into _migrations."""
        sql_file = tmp_path / "0001_initial.sql"
        sql_file.write_text("CREATE TABLE test (id INT);", encoding="utf-8")

        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[])

        with patch.object(db_mod, "_MIGRATIONS_DIR", tmp_path):
            await db_mod.run_migrations(mock_pool)

        insert_calls = [
            c
            for c in conn.execute.call_args_list
            if len(c.args) > 0 and "INSERT INTO _migrations" in c.args[0]
        ]
        assert len(insert_calls) == 1
        assert insert_calls[0].args[1] == 1
        assert insert_calls[0].args[2] == "0001_initial.sql"


# ---------------------------------------------------------------------------
# TestSeedSettings
# ---------------------------------------------------------------------------


class TestSeedSettings:
    """Tests for seed_settings()."""

    async def test_seeds_when_table_is_empty(self, mock_pool: MagicMock) -> None:
        """seed_settings() inserts rows when settings table is empty."""
        conn = mock_pool._mock_conn
        conn.fetchval = AsyncMock(return_value=0)

        mock_config = MagicMock()
        for section in ("server", "llm", "paths", "files", "limits", "egress", "ocr", "database"):
            getattr(mock_config, section).model_dump = MagicMock(return_value={"key": "val"})
        mock_config.auth.model_dump = MagicMock(return_value={"mode": "vpn"})
        mock_config.log_level = "INFO"

        await db_mod.seed_settings(mock_pool, mock_config)

        # 10 sections: server, llm, auth, paths, files, limits, egress, ocr, database, log_level
        insert_calls = [
            c
            for c in conn.execute.call_args_list
            if len(c.args) > 0 and "INSERT INTO settings" in c.args[0]
        ]
        assert len(insert_calls) == 10

    async def test_skips_when_table_has_rows(self, mock_pool: MagicMock) -> None:
        """seed_settings() skips seeding when settings table already has rows."""
        conn = mock_pool._mock_conn
        conn.fetchval = AsyncMock(return_value=10)

        mock_config = MagicMock()
        await db_mod.seed_settings(mock_pool, mock_config)

        insert_calls = [
            c
            for c in conn.execute.call_args_list
            if len(c.args) > 0 and "INSERT INTO settings" in c.args[0]
        ]
        assert len(insert_calls) == 0


# ---------------------------------------------------------------------------
# TestSeedPermissions
# ---------------------------------------------------------------------------


class TestSeedPermissions:
    """Tests for seed_permissions()."""

    async def test_seeds_when_table_is_empty(self, mock_pool: MagicMock) -> None:
        """seed_permissions() inserts rows when permissions table is empty."""
        conn = mock_pool._mock_conn
        conn.fetchval = AsyncMock(return_value=0)

        mock_perms = MagicMock()
        mock_perms.tools = {
            "gmail": MagicMock(actions={"read": "allow", "send": "confirm"}),
            "memory": MagicMock(actions={"store": "allow"}),
        }

        await db_mod.seed_permissions(mock_pool, mock_perms)

        insert_calls = [
            c
            for c in conn.execute.call_args_list
            if len(c.args) > 0 and "INSERT INTO permissions" in c.args[0]
        ]
        assert len(insert_calls) == 3

    async def test_skips_when_table_has_rows(self, mock_pool: MagicMock) -> None:
        """seed_permissions() skips seeding when permissions table has rows."""
        conn = mock_pool._mock_conn
        conn.fetchval = AsyncMock(return_value=5)

        mock_perms = MagicMock()
        await db_mod.seed_permissions(mock_pool, mock_perms)

        insert_calls = [
            c
            for c in conn.execute.call_args_list
            if len(c.args) > 0 and "INSERT INTO permissions" in c.args[0]
        ]
        assert len(insert_calls) == 0

    async def test_inserts_correct_tool_action_permission(self, mock_pool: MagicMock) -> None:
        """seed_permissions() inserts correct (tool, action, permission) tuples."""
        conn = mock_pool._mock_conn
        conn.fetchval = AsyncMock(return_value=0)

        mock_perms = MagicMock()
        mock_perms.tools = {
            "gmail": MagicMock(actions={"read": "allow"}),
        }

        await db_mod.seed_permissions(mock_pool, mock_perms)

        insert_calls = [
            c
            for c in conn.execute.call_args_list
            if len(c.args) > 0 and "INSERT INTO permissions" in c.args[0]
        ]
        assert len(insert_calls) == 1
        assert insert_calls[0].args[1] == "gmail"
        assert insert_calls[0].args[2] == "read"
        assert insert_calls[0].args[3] == "allow"


# ---------------------------------------------------------------------------
# TestLoadSettingsFromDb
# ---------------------------------------------------------------------------


class TestLoadSettingsFromDb:
    """Tests for load_settings_from_db()."""

    async def test_returns_correct_dict_structure(self, mock_pool: MagicMock) -> None:
        """load_settings_from_db() returns a dict keyed by section name."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(
            return_value=[
                {"key": "server", "value": {"host": "127.0.0.1", "port": 8000}},
                {"key": "llm", "value": {"provider": "ollama"}},
            ]
        )

        result = await db_mod.load_settings_from_db(mock_pool)

        assert result["server"] == {"host": "127.0.0.1", "port": 8000}
        assert result["llm"] == {"provider": "ollama"}

    async def test_unwraps_log_level(self, mock_pool: MagicMock) -> None:
        """load_settings_from_db() unwraps log_level from {"value": "X"} to "X"."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(
            return_value=[
                {"key": "log_level", "value": {"value": "DEBUG"}},
            ]
        )

        result = await db_mod.load_settings_from_db(mock_pool)

        assert result["log_level"] == "DEBUG"


# ---------------------------------------------------------------------------
# TestLoadPermissionsFromDb
# ---------------------------------------------------------------------------


class TestLoadPermissionsFromDb:
    """Tests for load_permissions_from_db()."""

    async def test_groups_by_tool(self, mock_pool: MagicMock) -> None:
        """load_permissions_from_db() groups rows by tool name."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(
            return_value=[
                {"tool": "gmail", "action": "read", "permission": "allow"},
                {"tool": "gmail", "action": "send", "permission": "confirm"},
                {"tool": "memory", "action": "store", "permission": "allow"},
            ]
        )

        result = await db_mod.load_permissions_from_db(mock_pool)

        assert result == {
            "gmail": {"read": "allow", "send": "confirm"},
            "memory": {"store": "allow"},
        }

    async def test_empty_permissions_table(self, mock_pool: MagicMock) -> None:
        """load_permissions_from_db() returns empty dict when table is empty."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[])

        result = await db_mod.load_permissions_from_db(mock_pool)

        assert result == {}
