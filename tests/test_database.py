"""Tests for admino.database — pool lifecycle, migrations, seeds, and loaders.

GH-159: the settings table helpers (seed_settings, update_setting,
load_settings_from_db) are gone with the table. GH-161: so are the global
permission helpers (seed_permissions, update_permission, load_permissions_from_db);
the org-scoped matrix lives in admino.org_permissions.

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
# The settings table helpers are gone (GH-159)
# ---------------------------------------------------------------------------


class TestSettingsTableHelpersRemoved:
    """GH-159: migration 0013 drops the key/value settings table; its seed, update and
    load helpers go with it (the scopes live in admino.scoped_settings)."""

    @pytest.mark.parametrize("name", ["seed_settings", "update_setting", "load_settings_from_db"])
    def test_database_settings_table_helper_is_removed(self, name: str) -> None:
        assert not hasattr(db_mod, name)


# ---------------------------------------------------------------------------
# TestGlobalPermissionHelpersRemoved (GH-161)
# ---------------------------------------------------------------------------


class TestGlobalPermissionHelpersRemoved:
    """GH-161: the permissions table is org-scoped (migration 0016) and its rows are
    seeded, read and written by admino.org_permissions; the global seed, update and
    load helpers are dead code and gone."""

    @pytest.mark.parametrize(
        "name", ["seed_permissions", "update_permission", "load_permissions_from_db"]
    )
    def test_database_global_permission_helper_is_removed(self, name: str) -> None:
        assert not hasattr(db_mod, name)


# ---------------------------------------------------------------------------
# TestRemoveFilesToolMigration (GH-143)
# ---------------------------------------------------------------------------

_FILES_MIGRATION_NAME = "0003_remove_files_tool.sql"


def _files_migration_sql() -> str:
    """Return the shipped 0003 migration, comments stripped, whitespace collapsed, lowercased."""
    import re

    raw = (db_mod._MIGRATIONS_DIR / _FILES_MIGRATION_NAME).read_text(encoding="utf-8")
    without_comments = re.sub(r"--[^\n]*", " ", raw)
    return re.sub(r"\s+", " ", without_comments).strip().lower()


class TestRemoveFilesToolMigration:
    """Existing installs are cleaned up by a numbered SQL migration (GH-143).

    There is no real PostgreSQL in the suite, so the shipped SQL file itself is
    the spec: it must exist, be discovered by run_migrations as version 3, and
    delete the files permission rows, the files settings row, and the files key
    of the tools settings JSONB — with no parameters or string interpolation.
    """

    def test_migration_file_is_shipped_as_version_3(self) -> None:
        """0003_remove_files_tool.sql exists and matches the numbered-migration regex."""
        assert (db_mod._MIGRATIONS_DIR / _FILES_MIGRATION_NAME).is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_FILES_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == 3

    async def test_run_migrations_applies_it_as_version_3(self, mock_pool: MagicMock) -> None:
        """With 0001/0002 applied, run_migrations executes and records 0003."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": 1}, {"version": 2}])

        await db_mod.run_migrations(mock_pool)

        recorded = [
            (c.args[1], c.args[2])
            for c in conn.execute.call_args_list
            if len(c.args) > 2 and "INSERT INTO _migrations" in c.args[0]
        ]
        assert (3, _FILES_MIGRATION_NAME) in recorded
        assert all(version >= 3 for version, _ in recorded)

    def test_migration_deletes_files_permission_rows(self) -> None:
        """DELETE FROM permissions WHERE tool = 'files'."""
        import re

        sql = _files_migration_sql()
        assert re.search(r"delete from permissions where tool\s*=\s*'files'", sql)

    def test_migration_deletes_files_settings_row(self) -> None:
        """DELETE FROM settings WHERE key = 'files'."""
        import re

        sql = _files_migration_sql()
        assert re.search(r"delete from settings where key\s*=\s*'files'", sql)

    def test_migration_removes_files_key_from_tools_settings(self) -> None:
        """UPDATE settings SET value = value - 'files' WHERE key = 'tools'."""
        import re

        sql = _files_migration_sql()
        assert re.search(
            r"update settings set value\s*=\s*value\s*-\s*'files'[^;]*where key\s*=\s*'tools'",
            sql,
        )

    def test_migration_is_parameter_free(self) -> None:
        """No bind parameters or interpolation placeholders in the migration."""
        import re

        sql = _files_migration_sql()
        assert re.search(r"\$\d", sql) is None
        assert "%s" not in sql
        assert "%(" not in sql


# ---------------------------------------------------------------------------
# TestDatabaseUrlFromEnv (GH-150)
# ---------------------------------------------------------------------------

_PG_ENV_VARS: tuple[str, ...] = ("PG_HOST", "PG_PORT", "PG_USER", "PG_DATABASE", "PG_PASSWORD")


@pytest.fixture()
def clean_pg_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Remove every PG_* variable, so each test sets exactly what it needs."""
    for name in _PG_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


class TestDatabaseUrlFromEnv:
    """database_url_from_env() builds the DSN from PG_* (moved from main, GH-150).

    The server startup and the admin CLI share it. PG_PASSWORD is required;
    the other variables have defaults. The password is URL-encoded with
    quote_plus, so characters like "/" and "@" can't break the DSN.
    """

    def test_database_url_from_env_defaults_when_only_password_set(
        self, clean_pg_env: pytest.MonkeyPatch
    ) -> None:
        """Only PG_PASSWORD set → localhost:5432, user and database 'admino'."""
        clean_pg_env.setenv("PG_PASSWORD", "hunter2hunter2")

        assert db_mod.database_url_from_env() == (
            "postgresql://admino:hunter2hunter2@localhost:5432/admino"
        )

    def test_database_url_from_env_uses_overrides(self, clean_pg_env: pytest.MonkeyPatch) -> None:
        """PG_HOST, PG_PORT, PG_USER and PG_DATABASE override the defaults."""
        clean_pg_env.setenv("PG_HOST", "postgres")
        clean_pg_env.setenv("PG_PORT", "6543")
        clean_pg_env.setenv("PG_USER", "agent")
        clean_pg_env.setenv("PG_DATABASE", "admino_prod")
        clean_pg_env.setenv("PG_PASSWORD", "hunter2hunter2")

        assert db_mod.database_url_from_env() == (
            "postgresql://agent:hunter2hunter2@postgres:6543/admino_prod"
        )

    def test_database_url_from_env_url_encodes_password(
        self, clean_pg_env: pytest.MonkeyPatch
    ) -> None:
        """A password with '/' and '@' is percent-encoded (quote_plus), never verbatim."""
        clean_pg_env.setenv("PG_PASSWORD", "s3cr3t/p@ss")

        url = db_mod.database_url_from_env()

        assert url == "postgresql://admino:s3cr3t%2Fp%40ss@localhost:5432/admino"

    def test_database_url_from_env_url_encodes_colon_and_percent(
        self, clean_pg_env: pytest.MonkeyPatch
    ) -> None:
        """':' and '%' in the password are percent-encoded too."""
        clean_pg_env.setenv("PG_PASSWORD", "a:b%c")

        url = db_mod.database_url_from_env()

        assert url == "postgresql://admino:a%3Ab%25c@localhost:5432/admino"

    def test_database_url_from_env_without_password_returns_none(
        self, clean_pg_env: pytest.MonkeyPatch
    ) -> None:
        """PG_PASSWORD unset → None (the caller reports the missing variable)."""
        clean_pg_env.setenv("PG_HOST", "postgres")

        assert db_mod.database_url_from_env() is None

    def test_database_url_from_env_with_empty_password_returns_none(
        self, clean_pg_env: pytest.MonkeyPatch
    ) -> None:
        """PG_PASSWORD set but empty → None, not a DSN with an empty password."""
        clean_pg_env.setenv("PG_PASSWORD", "")

        assert db_mod.database_url_from_env() is None

    def test_database_url_builder_is_no_longer_duplicated_in_main(self) -> None:
        """The builder moved: admino.main no longer defines its own _build_database_url."""
        import admino.main as main_mod

        assert not hasattr(main_mod, "_build_database_url")
