"""Tests for admino.database — pool lifecycle, migrations, seeds, and loaders.

GH-159: the settings table helpers (seed_settings, update_setting,
load_settings_from_db) are gone with the table. GH-161: so are the global
permission helpers (seed_permissions, update_permission, load_permissions_from_db);
the org-scoped matrix lives in admino.org_permissions.

GH-220 (least-privilege runtime role): ``database_url_from_env()`` now builds the
runtime DSN (user ``admino_app`` = ``RUNTIME_ROLE``, password PG_APP_PASSWORD) and
ignores the owner's PG_USER/PG_PASSWORD entirely; ``pending_migration_versions()``
is the app's read-only "is the schema up to date?" check (the app never migrates).

All asyncpg calls are mocked. No real PostgreSQL connections are made.

Security notes:
- Verifies parameterized queries are used (no string interpolation).
- Verifies migration execution is transactional.
- Verifies the runtime DSN never falls back to, or contains, the owner password, and
  that database.py doesn't mention the owner variables at all.
- Verifies the pending-migrations check is read-only (one SELECT, no DDL/INSERT).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import quote, quote_plus, unquote, urlsplit

import asyncpg
import pytest

import admino.database as db_mod

if TYPE_CHECKING:
    from collections.abc import Generator


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
# TestDatabaseUrlFromEnv (GH-150; GH-220: the runtime role's DSN)
# ---------------------------------------------------------------------------

_PG_ENV_VARS: tuple[str, ...] = (
    "PG_HOST",
    "PG_PORT",
    "PG_USER",
    "PG_DATABASE",
    "PG_PASSWORD",
    "PG_APP_PASSWORD",
)

# A distinctive owner (superuser) password: it must never reach the runtime DSN.
_OWNER_PASSWORD = "0wner-Superuser-Pw-Marker-7731"


@pytest.fixture()
def clean_pg_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Remove every PG_* variable, so each test sets exactly what it needs.

    PG_APP_PASSWORD is cleared too (tests/conftest.py sets it for every test).
    """
    for name in _PG_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


class TestDatabaseUrlFromEnv:
    """database_url_from_env() builds the runtime DSN (GH-150, changed by GH-220).

    The server lifespan, ``_async_startup`` and the admin CLI share it. Since GH-220
    the app connects as the least-privilege runtime role: the user is always
    ``admino_app`` and the password is PG_APP_PASSWORD (required, percent-encoded with
    ``quote(..., safe='')``: asyncpg decodes it with ``unquote``, so a space is %20).
    PG_HOST, PG_PORT and PG_DATABASE keep their defaults. PG_USER and PG_PASSWORD (the
    owner credential, known only to ``admino.migrate``) are ignored: there is no
    fallback to the owner password.
    """

    def test_database_url_from_env_defaults_when_only_app_password_set(
        self, clean_pg_env: pytest.MonkeyPatch
    ) -> None:
        """Only PG_APP_PASSWORD set → admino_app@localhost:5432, database 'admino'."""
        clean_pg_env.setenv("PG_APP_PASSWORD", "hunter2hunter2")

        assert db_mod.database_url_from_env() == (
            "postgresql://admino_app:hunter2hunter2@localhost:5432/admino"
        )

    def test_database_url_from_env_uses_host_port_and_database_overrides(
        self, clean_pg_env: pytest.MonkeyPatch
    ) -> None:
        """PG_HOST, PG_PORT and PG_DATABASE override the defaults; the user stays admino_app."""
        clean_pg_env.setenv("PG_HOST", "postgres")
        clean_pg_env.setenv("PG_PORT", "6543")
        clean_pg_env.setenv("PG_DATABASE", "admino_prod")
        clean_pg_env.setenv("PG_APP_PASSWORD", "hunter2hunter2")

        assert db_mod.database_url_from_env() == (
            "postgresql://admino_app:hunter2hunter2@postgres:6543/admino_prod"
        )

    @pytest.mark.parametrize("pg_user", ["admino", "agent", "postgres", "admino_app", ""])
    def test_database_url_from_env_user_is_always_the_runtime_role(
        self, clean_pg_env: pytest.MonkeyPatch, pg_user: str
    ) -> None:
        """Whatever PG_USER says (the owner's name, another name, empty), the user is admino_app."""
        clean_pg_env.setenv("PG_USER", pg_user)
        clean_pg_env.setenv("PG_APP_PASSWORD", "hunter2hunter2")

        assert db_mod.database_url_from_env() == (
            "postgresql://admino_app:hunter2hunter2@localhost:5432/admino"
        )

    def test_database_url_from_env_ignores_owner_user_and_password(
        self, clean_pg_env: pytest.MonkeyPatch
    ) -> None:
        """PG_USER=admino and PG_PASSWORD=<owner> set → still admino_app + PG_APP_PASSWORD.

        The owner's password appears in no form (raw or percent-encoded) in the DSN.
        """
        clean_pg_env.setenv("PG_USER", "admino")
        clean_pg_env.setenv("PG_PASSWORD", _OWNER_PASSWORD)
        clean_pg_env.setenv("PG_APP_PASSWORD", "app-Runtime-Pw-1290")

        url = db_mod.database_url_from_env()

        assert url == "postgresql://admino_app:app-Runtime-Pw-1290@localhost:5432/admino"
        assert _OWNER_PASSWORD not in url
        assert quote(_OWNER_PASSWORD, safe="") not in url
        assert quote_plus(_OWNER_PASSWORD) not in url

    @pytest.mark.parametrize(
        ("password", "encoded"),
        [
            ("s3cr3t/p@ss", "s3cr3t%2Fp%40ss"),
            ("a:b%c", "a%3Ab%25c"),
            ("p+q#r?s", "p%2Bq%23r%3Fs"),
            ("pw word", "pw%20word"),
        ],
        ids=["slash-at", "colon-percent", "plus-hash-question", "space"],
    )
    def test_database_url_from_env_url_encodes_app_password(
        self, clean_pg_env: pytest.MonkeyPatch, password: str, encoded: str
    ) -> None:
        """PG_APP_PASSWORD is percent-encoded, never put in verbatim; a space is %20."""
        clean_pg_env.setenv("PG_APP_PASSWORD", password)

        url = db_mod.database_url_from_env()

        assert url == f"postgresql://admino_app:{encoded}@localhost:5432/admino"

    def test_database_url_from_env_password_round_trips_through_unquote(
        self, clean_pg_env: pytest.MonkeyPatch
    ) -> None:
        """Every printable ASCII character (all that admino.migrate accepts) survives the
        DSN: decoding the password with ``unquote``, as asyncpg does, gives
        PG_APP_PASSWORD back exactly. quote_plus's '+' for a space would reach
        PostgreSQL as a literal '+' and fail the login."""
        password = "".join(chr(code) for code in range(0x20, 0x7F))
        clean_pg_env.setenv("PG_APP_PASSWORD", password)

        url = db_mod.database_url_from_env()

        assert url is not None
        assert unquote(urlsplit(url).password or "") == password

    @pytest.mark.parametrize("app_password", [None, ""], ids=["unset", "empty"])
    def test_database_url_from_env_without_app_password_returns_none_even_with_owner_password(
        self, clean_pg_env: pytest.MonkeyPatch, app_password: str | None
    ) -> None:
        """PG_APP_PASSWORD unset or empty → None, although PG_USER/PG_PASSWORD are set.

        Never a fallback to the owner credential: the caller reports the missing
        PG_APP_PASSWORD instead of connecting as the superuser.
        """
        clean_pg_env.setenv("PG_HOST", "postgres")
        clean_pg_env.setenv("PG_USER", "admino")
        clean_pg_env.setenv("PG_PASSWORD", _OWNER_PASSWORD)
        if app_password is not None:
            clean_pg_env.setenv("PG_APP_PASSWORD", app_password)

        assert db_mod.database_url_from_env() is None

    def test_database_url_builder_is_no_longer_duplicated_in_main(self) -> None:
        """The builder moved: admino.main no longer defines its own _build_database_url."""
        import admino.main as main_mod

        assert not hasattr(main_mod, "_build_database_url")


# ---------------------------------------------------------------------------
# TestRuntimeRole (GH-220)
# ---------------------------------------------------------------------------


class TestRuntimeRole:
    """database.RUNTIME_ROLE names the least-privilege role the app connects as (GH-220)."""

    def test_database_runtime_role_is_admino_app(self) -> None:
        """The runtime role's name is fixed: admino_app (migration 0018 creates it)."""
        assert db_mod.RUNTIME_ROLE == "admino_app"


# ---------------------------------------------------------------------------
# TestPendingMigrationVersions (GH-220)
# ---------------------------------------------------------------------------

_SHIPPED_FILE_RE = re.compile(r"^(\d{4})_.+\.sql$")
_POOL_QUERY_METHODS: tuple[str, ...] = ("execute", "fetch", "fetchrow", "fetchval")


def _write_migrations(directory: Path, names: list[str]) -> None:
    """Create one placeholder file per name in ``directory``."""
    for name in names:
        (directory / name).write_text("SELECT 1;", encoding="utf-8")


def _answer_applied(
    pool: MagicMock,
    *,
    versions: list[int] | None = None,
    error: BaseException | None = None,
) -> None:
    """Answer ``SELECT version FROM _migrations`` with rows, or raise ``error``.

    Set on the pool and on its connection alike, so the implementation may query
    through either (``pool.fetch`` or ``pool.acquire()`` + ``conn.fetch``).
    """
    rows = [{"version": version} for version in versions or []]
    for target in (pool, pool._mock_conn):
        target.fetch = AsyncMock(return_value=rows, side_effect=error)


def _query_calls(pool: MagicMock) -> list[tuple[str, str]]:
    """Every (method, SQL text) sent through the pool or its connection, in no order."""
    calls: list[tuple[str, str]] = []
    for target in (pool, pool._mock_conn):
        for method in _POOL_QUERY_METHODS:
            for awaited in getattr(target, method).await_args_list:
                sql = awaited.args[0] if awaited.args else awaited.kwargs.get("query", "")
                calls.append((method, str(sql)))
    return calls


def _normalized(sql: str) -> str:
    """Lowercase ``sql``, collapse whitespace, drop a trailing semicolon."""
    return re.sub(r"\s+", " ", sql).strip().rstrip(";").strip().lower()


def _shipped_versions() -> list[int]:
    """The versions of the shipped migration files, read independently of database.py."""
    return sorted(
        int(match.group(1))
        for path in db_mod._MIGRATIONS_DIR.iterdir()
        if (match := _SHIPPED_FILE_RE.match(path.name))
    )


class TestPendingMigrationVersions:
    """pending_migration_versions(pool): which shipped migrations aren't applied (GH-220).

    The app (startup) uses it to refuse to run on an outdated schema instead of
    migrating: the runtime role can't run DDL, only ``admino.migrate`` (as the owner)
    applies migrations. So it is read-only: exactly one ``SELECT version FROM
    _migrations``, no CREATE of the tracking table, no INSERT, no DDL. A database
    without ``_migrations`` (UndefinedTableError) has every shipped migration pending;
    every other database error propagates.
    """

    async def test_pending_migration_versions_returns_sorted_unapplied_versions(
        self, mock_pool: MagicMock, tmp_path: Path
    ) -> None:
        """Files 1, 2, 3, 4, 10 with 1 and 3 applied (and an unknown 99) → [2, 4, 10]."""
        _write_migrations(
            tmp_path,
            ["0010_d.sql", "0002_b.sql", "0004_e.sql", "0001_a.sql", "0003_c.sql"],
        )
        _answer_applied(mock_pool, versions=[3, 99, 1])

        with patch.object(db_mod, "_MIGRATIONS_DIR", tmp_path):
            pending = await db_mod.pending_migration_versions(mock_pool)

        assert pending == [2, 4, 10]

    async def test_pending_migration_versions_all_applied_returns_empty_list(
        self, mock_pool: MagicMock, tmp_path: Path
    ) -> None:
        """Every shipped version recorded in _migrations → []."""
        _write_migrations(tmp_path, ["0001_a.sql", "0002_b.sql", "0003_c.sql"])
        _answer_applied(mock_pool, versions=[1, 2, 3])

        with patch.object(db_mod, "_MIGRATIONS_DIR", tmp_path):
            pending = await db_mod.pending_migration_versions(mock_pool)

        assert pending == []

    async def test_pending_migration_versions_ignores_non_migration_files(
        self, mock_pool: MagicMock, tmp_path: Path
    ) -> None:
        """Only NNNN_<name>.sql files count; READMEs, other suffixes and bad numbers don't."""
        _write_migrations(
            tmp_path,
            [
                "0001_a.sql",
                "0002_b.sql",
                "README.md",
                "__init__.py",
                "0003_c.txt",
                "4_short.sql",
                "abcd_x.sql",
                "0005.sql",
                "00006_five_digits.sql",
                "0007_.sql",
                "0008_x.sql.bak",
            ],
        )
        _answer_applied(mock_pool, versions=[])

        with patch.object(db_mod, "_MIGRATIONS_DIR", tmp_path):
            pending = await db_mod.pending_migration_versions(mock_pool)

        assert pending == [1, 2]

    async def test_pending_migration_versions_without_tracking_table_returns_every_version(
        self, mock_pool: MagicMock, tmp_path: Path
    ) -> None:
        """_migrations doesn't exist (UndefinedTableError) → every shipped version, sorted."""
        _write_migrations(tmp_path, ["0003_c.sql", "0001_a.sql", "0002_b.sql"])
        _answer_applied(
            mock_pool,
            error=asyncpg.UndefinedTableError('relation "_migrations" does not exist'),
        )

        with patch.object(db_mod, "_MIGRATIONS_DIR", tmp_path):
            pending = await db_mod.pending_migration_versions(mock_pool)

        assert pending == [1, 2, 3]

    async def test_pending_migration_versions_without_tracking_table_creates_nothing(
        self, mock_pool: MagicMock, tmp_path: Path
    ) -> None:
        """A missing _migrations table is not created: no execute, no transaction."""
        _write_migrations(tmp_path, ["0001_a.sql"])
        _answer_applied(
            mock_pool,
            error=asyncpg.UndefinedTableError('relation "_migrations" does not exist'),
        )

        with patch.object(db_mod, "_MIGRATIONS_DIR", tmp_path):
            await db_mod.pending_migration_versions(mock_pool)

        mock_pool.execute.assert_not_awaited()
        mock_pool._mock_conn.execute.assert_not_awaited()
        mock_pool._mock_conn.transaction.assert_not_called()
        assert len(_query_calls(mock_pool)) == 1

    async def test_pending_migration_versions_runs_exactly_one_select_on_migrations(
        self, mock_pool: MagicMock, tmp_path: Path
    ) -> None:
        """The only query is one ``SELECT version FROM _migrations`` (a fetch)."""
        _write_migrations(tmp_path, ["0001_a.sql", "0002_b.sql"])
        _answer_applied(mock_pool, versions=[1])

        with patch.object(db_mod, "_MIGRATIONS_DIR", tmp_path):
            await db_mod.pending_migration_versions(mock_pool)

        calls = _query_calls(mock_pool)
        assert len(calls) == 1
        method, sql = calls[0]
        assert method == "fetch"
        assert _normalized(sql) == "select version from _migrations"

    async def test_pending_migration_versions_executes_no_ddl_or_insert(
        self, mock_pool: MagicMock, tmp_path: Path
    ) -> None:
        """Read-only: no execute (CREATE/INSERT/DDL), no transaction, no migration file run."""
        _write_migrations(tmp_path, ["0001_a.sql", "0002_b.sql"])
        _answer_applied(mock_pool, versions=[])

        with patch.object(db_mod, "_MIGRATIONS_DIR", tmp_path):
            await db_mod.pending_migration_versions(mock_pool)

        mock_pool.execute.assert_not_awaited()
        mock_pool._mock_conn.execute.assert_not_awaited()
        mock_pool._mock_conn.transaction.assert_not_called()
        for _method, sql in _query_calls(mock_pool):
            assert not re.search(
                r"\b(create|insert|update|delete|drop|alter|grant|truncate)\b", sql.lower()
            )

    @pytest.mark.parametrize(
        "error_type",
        [
            asyncpg.InsufficientPrivilegeError,
            asyncpg.UndefinedColumnError,
            asyncpg.PostgresError,
        ],
        ids=lambda error_type: error_type.__name__,
    )
    async def test_pending_migration_versions_other_database_errors_propagate(
        self, mock_pool: MagicMock, tmp_path: Path, error_type: type[asyncpg.PostgresError]
    ) -> None:
        """Only UndefinedTableError means 'nothing applied'; other errors are raised."""
        _write_migrations(tmp_path, ["0001_a.sql"])
        _answer_applied(mock_pool, error=error_type("permission denied for table _migrations"))

        with (
            patch.object(db_mod, "_MIGRATIONS_DIR", tmp_path),
            pytest.raises(error_type),
        ):
            await db_mod.pending_migration_versions(mock_pool)

    async def test_pending_migration_versions_shipped_dir_without_tracking_table(
        self, mock_pool: MagicMock
    ) -> None:
        """On a fresh database every shipped migration (1..N, from the real dir) is pending."""
        expected = _shipped_versions()
        _answer_applied(
            mock_pool,
            error=asyncpg.UndefinedTableError('relation "_migrations" does not exist'),
        )

        pending = await db_mod.pending_migration_versions(mock_pool)

        assert expected[:1] == [1]
        assert pending == expected

    async def test_pending_migration_versions_shipped_dir_fully_applied_is_empty(
        self, mock_pool: MagicMock
    ) -> None:
        """With every shipped version recorded, nothing is pending."""
        _answer_applied(mock_pool, versions=_shipped_versions())

        assert await db_mod.pending_migration_versions(mock_pool) == []


# ---------------------------------------------------------------------------
# TestDatabaseNeverReadsOwnerCredentials (GH-220)
# ---------------------------------------------------------------------------


class TestDatabaseNeverReadsOwnerCredentials:
    """database.py is the app's runtime module: the owner credential is not its business.

    Only ``admino.migrate`` reads PG_USER and PG_PASSWORD (GH-220); a mention in
    database.py would mean a code path (or a docstring promising one) that could
    hand the superuser's credential to the running app.
    """

    @pytest.mark.parametrize("variable", ["PG_PASSWORD", "PG_USER"])
    def test_database_source_never_mentions_owner_variable(self, variable: str) -> None:
        """Neither ``PG_PASSWORD`` nor ``PG_USER`` appears as a word in database.py."""
        source = Path(db_mod.__file__).read_text(encoding="utf-8")

        assert re.search(rf"\b{variable}\b", source) is None
