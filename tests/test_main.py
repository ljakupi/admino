"""Comprehensive test suite for admino.main — entry point, config wiring, startup.

Tests the main() entry point, _configure_logging(), and _import_tool_modules(),
covering:
- Happy path: config loaded, dependencies wired, uvicorn.run called correctly
- Config failure paths: ValueError, OSError → sys.exit(1)
- Permissions failure paths: ValueError, FileNotFoundError → sys.exit(1)
- Audit logger failure paths: ValueError, OSError → sys.exit(1)
- Logging configuration: level mapping, invalid fallback
- Tool module imports: missing modules skipped, other errors re-raised
- AgentConfig wiring from config.limits fields
- Security invariants: no eval/exec/compile/shell=True, no secrets in logs

Security notes:
- All external dependencies are mocked — no real Ollama, no real config files,
  no real uvicorn startup.
- Tests verify that error output goes to stderr, not stdout.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from admino.main import _async_startup, _configure_logging, _import_tool_modules, main

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAIN_MODULE_PATH = Path(__file__).resolve().parent.parent / "src" / "admino" / "main.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_config() -> MagicMock:
    """Build a minimal mock AppConfig with all fields main.py accesses."""
    config = MagicMock()
    config.log_level = "INFO"

    # Use a MagicMock for audit_log so .parent is settable
    mock_audit_log = MagicMock()
    mock_audit_log.parent = Path("/tmp")  # noqa: S108
    config.paths.audit_log = mock_audit_log

    config.llm.provider = "ollama"
    config.llm.active_model_name = "test-model:7b"
    config.llm.ollama_url = "http://localhost:11434"
    config.llm.model = "test-model:7b"
    config.limits.max_tool_calls_per_message = 10
    config.limits.max_context_messages = 20
    config.limits.confirmation_timeout_s = 300
    config.server.host = "127.0.0.1"
    config.server.port = 8000
    config.database.min_pool_size = 2
    config.database.max_pool_size = 5
    return config


def _make_mock_permissions() -> MagicMock:
    """Build a minimal mock PermissionsConfig."""
    return MagicMock()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_deps(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Mock all external dependencies that main() uses.

    Returns a dict of all mocks for assertion in tests.
    """
    mock_config = _make_mock_config()
    mock_perms = _make_mock_permissions()
    mock_tools_enabled = {"gmail": False, "memory": True}
    mock_audit_logger = MagicMock()
    mock_ollama_client = MagicMock()
    mock_agent = MagicMock()
    mock_app = MagicMock()

    mock_load_app_config = MagicMock(return_value=mock_config)
    mock_load_permissions_config = MagicMock(return_value=mock_perms)
    mock_audit_cls = MagicMock(return_value=mock_audit_logger)
    mock_ollama_cls = MagicMock(return_value=mock_ollama_client)
    mock_agent_cls = MagicMock(return_value=mock_agent)
    mock_create_app = MagicMock(return_value=mock_app)
    mock_freeze = MagicMock()
    mock_uvicorn_run = MagicMock()
    mock_import_tools = MagicMock()

    # _async_startup is called via asyncio.run() inside main().
    # We mock asyncio.run to return (config, perms, tools_enabled) directly so
    # the DB init path is bypassed without needing real asyncpg. The third
    # element is the persisted per-service enabled state loaded on boot (GH-80).
    # The side_effect CLOSES the coroutine main() passes in so it is not left
    # "never awaited" — a leaked coroutine is GC'd at an arbitrary later point
    # and, when that coincides with another test's patched __import__, surfaces
    # as a spurious PytestUnraisableExceptionWarning failure.
    def _fake_run(coro: Any) -> tuple[Any, Any, Any]:
        if hasattr(coro, "close"):
            coro.close()
        return (mock_config, mock_perms, mock_tools_enabled)

    mock_asyncio = MagicMock()
    mock_asyncio.run = MagicMock(side_effect=_fake_run)

    monkeypatch.setattr("admino.main.load_app_config", mock_load_app_config)
    monkeypatch.setattr("admino.main.load_permissions_config", mock_load_permissions_config)
    monkeypatch.setattr("admino.main._import_tool_modules", mock_import_tools)
    monkeypatch.setattr("admino.main.asyncio", mock_asyncio)

    # These are imported lazily inside main(), so we patch the module paths
    monkeypatch.setattr("admino.audit.AuditLogger", mock_audit_cls)
    monkeypatch.setattr("admino.llm.create_llm_client", mock_ollama_cls)
    monkeypatch.setattr("admino.agent.Agent", mock_agent_cls)
    monkeypatch.setattr("admino.server.create_app", mock_create_app)
    monkeypatch.setattr("admino.tools.registry.freeze_registry", mock_freeze)
    monkeypatch.setattr("admino.main.uvicorn", MagicMock(run=mock_uvicorn_run))

    return {
        "config": mock_config,
        "permissions": mock_perms,
        "tools_enabled": mock_tools_enabled,
        "audit_logger": mock_audit_logger,
        "ollama_client": mock_ollama_client,
        "agent": mock_agent,
        "app": mock_app,
        "load_app_config": mock_load_app_config,
        "load_permissions_config": mock_load_permissions_config,
        "AuditLogger": mock_audit_cls,
        "create_llm_client": mock_ollama_cls,
        "Agent": mock_agent_cls,
        "create_app": mock_create_app,
        "freeze_registry": mock_freeze,
        "uvicorn_run": mock_uvicorn_run,
        "import_tool_modules": mock_import_tools,
        "asyncio": mock_asyncio,
    }


# ---------------------------------------------------------------------------
# Happy path tests
# ---------------------------------------------------------------------------


class TestMainHappyPath:
    """Tests for successful startup through main()."""

    def test_main_calls_uvicorn_run_with_correct_args(self, mock_deps: dict[str, Any]) -> None:
        """main() calls uvicorn.run with single worker, correct host/port, no access log."""
        main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        mock_deps["uvicorn_run"].assert_called_once()
        kw = mock_deps["uvicorn_run"].call_args
        assert kw.kwargs["workers"] == 1
        assert kw.kwargs["host"] == "127.0.0.1"
        assert kw.kwargs["port"] == 8000
        assert kw.kwargs["access_log"] is False

    def test_main_passes_app_to_uvicorn(self, mock_deps: dict[str, Any]) -> None:
        """uvicorn.run receives the app from create_app."""
        main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        positional_args = mock_deps["uvicorn_run"].call_args.args
        assert positional_args[0] is mock_deps["app"]

    def test_main_calls_create_app_with_agent_and_config(self, mock_deps: dict[str, Any]) -> None:
        """create_app is called with the agent instance and config."""
        main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        mock_deps["create_app"].assert_called_once_with(
            agent=mock_deps["agent"],
            config=mock_deps["config"],
        )

    def test_main_calls_freeze_registry_after_import(self, mock_deps: dict[str, Any]) -> None:
        """freeze_registry is called after _import_tool_modules."""
        main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        mock_deps["import_tool_modules"].assert_called_once()
        mock_deps["freeze_registry"].assert_called_once()

    def test_main_loads_config_with_provided_path(self, mock_deps: dict[str, Any]) -> None:
        """load_app_config is called with the config_path argument."""
        test_path = Path("/custom/config.yaml")
        main(config_path=test_path, permissions_path=Path("p.yaml"))

        mock_deps["load_app_config"].assert_called_once_with(test_path)

    def test_main_loads_permissions_with_provided_path(self, mock_deps: dict[str, Any]) -> None:
        """load_permissions_config is called with the permissions_path argument."""
        test_path = Path("/custom/permissions.yaml")
        main(config_path=Path("c.yaml"), permissions_path=test_path)

        mock_deps["load_permissions_config"].assert_called_once_with(test_path)

    def test_main_passes_tools_enabled_to_agent(self, mock_deps: dict[str, Any]) -> None:
        """Agent is constructed with the persisted tools_enabled from startup (GH-80).

        The per-service enabled state loaded from the DB on boot must flow into
        the Agent so toggled-off services stay gated across restarts.
        """
        main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        mock_deps["Agent"].assert_called_once()
        assert mock_deps["Agent"].call_args.kwargs["tools_enabled"] == mock_deps["tools_enabled"]


# ---------------------------------------------------------------------------
# Config failure tests
# ---------------------------------------------------------------------------


class TestMainConfigFailures:
    """Tests for main() behavior when config loading fails."""

    def test_main_exits_1_on_config_value_error(self, mock_deps: dict[str, Any]) -> None:
        """main() exits with code 1 when load_app_config raises ValueError."""
        mock_deps["load_app_config"].side_effect = ValueError("bad config")

        with pytest.raises(SystemExit) as exc_info:
            main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        assert exc_info.value.code == 1

    def test_main_exits_1_on_config_os_error(self, mock_deps: dict[str, Any]) -> None:
        """main() exits with code 1 when load_app_config raises OSError."""
        mock_deps["load_app_config"].side_effect = OSError("permission denied")

        with pytest.raises(SystemExit) as exc_info:
            main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        assert exc_info.value.code == 1

    def test_main_prints_config_error_to_stderr(
        self, mock_deps: dict[str, Any], capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Config errors are printed to stderr, not stdout."""
        mock_deps["load_app_config"].side_effect = ValueError("bad yaml")

        with pytest.raises(SystemExit):
            main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        captured = capsys.readouterr()
        assert "bad yaml" in captured.err
        assert captured.out == ""

    def test_main_does_not_call_uvicorn_on_config_failure(self, mock_deps: dict[str, Any]) -> None:
        """uvicorn.run is never called when config loading fails."""
        mock_deps["load_app_config"].side_effect = ValueError("fail")

        with pytest.raises(SystemExit):
            main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        mock_deps["uvicorn_run"].assert_not_called()


# ---------------------------------------------------------------------------
# Permissions failure tests
# ---------------------------------------------------------------------------


class TestMainPermissionsFailures:
    """Tests for main() behavior when permissions loading fails."""

    def test_main_exits_1_on_permissions_value_error(self, mock_deps: dict[str, Any]) -> None:
        """main() exits with code 1 when load_permissions_config raises ValueError."""
        mock_deps["load_permissions_config"].side_effect = ValueError("bad perms")

        with pytest.raises(SystemExit) as exc_info:
            main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        assert exc_info.value.code == 1

    def test_main_exits_1_on_permissions_file_not_found(self, mock_deps: dict[str, Any]) -> None:
        """main() exits with code 1 when load_permissions_config raises FileNotFoundError."""
        mock_deps["load_permissions_config"].side_effect = FileNotFoundError("missing")

        with pytest.raises(SystemExit) as exc_info:
            main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        assert exc_info.value.code == 1

    def test_main_does_not_call_uvicorn_on_permissions_failure(
        self, mock_deps: dict[str, Any]
    ) -> None:
        """uvicorn.run is never called when permissions loading fails."""
        mock_deps["load_permissions_config"].side_effect = ValueError("fail")

        with pytest.raises(SystemExit):
            main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        mock_deps["uvicorn_run"].assert_not_called()


# ---------------------------------------------------------------------------
# Audit logger failure tests
# ---------------------------------------------------------------------------


class TestMainAuditLoggerFailures:
    """Tests for main() behavior when AuditLogger creation fails."""

    def test_main_exits_1_on_audit_logger_value_error(self, mock_deps: dict[str, Any]) -> None:
        """main() exits with code 1 when AuditLogger raises ValueError."""
        mock_deps["AuditLogger"].side_effect = ValueError("bad path")

        with pytest.raises(SystemExit) as exc_info:
            main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        assert exc_info.value.code == 1

    def test_main_exits_1_on_audit_logger_os_error(self, mock_deps: dict[str, Any]) -> None:
        """main() exits with code 1 when AuditLogger raises OSError."""
        mock_deps["AuditLogger"].side_effect = OSError("disk full")

        with pytest.raises(SystemExit) as exc_info:
            main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        assert exc_info.value.code == 1

    def test_main_does_not_call_uvicorn_on_audit_failure(self, mock_deps: dict[str, Any]) -> None:
        """uvicorn.run is never called when audit logger creation fails."""
        mock_deps["AuditLogger"].side_effect = ValueError("fail")

        with pytest.raises(SystemExit):
            main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        mock_deps["uvicorn_run"].assert_not_called()


# ---------------------------------------------------------------------------
# Logging configuration tests
# ---------------------------------------------------------------------------


class TestConfigureLogging:
    """Tests for _configure_logging() level mapping and fallback."""

    @pytest.mark.parametrize(
        ("level_name", "expected_level"),
        [
            ("DEBUG", logging.DEBUG),
            ("INFO", logging.INFO),
            ("WARNING", logging.WARNING),
            ("ERROR", logging.ERROR),
            ("CRITICAL", logging.CRITICAL),
        ],
    )
    def test_configure_logging_sets_correct_level(
        self, level_name: str, expected_level: int
    ) -> None:
        """_configure_logging sets root logger to the requested level."""
        _configure_logging(level_name)

        root_logger = logging.getLogger()
        assert root_logger.level == expected_level

    def test_configure_logging_invalid_level_falls_back_to_info(self) -> None:
        """Invalid level name falls back to INFO."""
        _configure_logging("NONEXISTENT_LEVEL")

        root_logger = logging.getLogger()
        assert root_logger.level == logging.INFO

    def test_configure_logging_empty_string_falls_back_to_info(self) -> None:
        """Empty string falls back to INFO."""
        _configure_logging("")

        root_logger = logging.getLogger()
        assert root_logger.level == logging.INFO


# ---------------------------------------------------------------------------
# Tool module import tests
# ---------------------------------------------------------------------------


class TestImportToolModules:
    """Tests for _import_tool_modules() behavior."""

    def test_import_tool_modules_skips_missing_with_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Missing tool modules are skipped with a warning log."""
        with (
            patch("builtins.__import__", side_effect=ModuleNotFoundError("missing")),
            caplog.at_level(logging.WARNING),
        ):
            _import_tool_modules()

        assert "not found, skipping" in caplog.text

    def test_import_tool_modules_reraises_non_module_not_found(self) -> None:
        """Non-ModuleNotFoundError exceptions are re-raised."""
        with (
            patch("builtins.__import__", side_effect=RuntimeError("unexpected failure")),
            pytest.raises(RuntimeError, match="unexpected failure"),
        ):
            _import_tool_modules()

    def test_import_tool_modules_reraises_logs_error(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Error log message is emitted before re-raising non-ModuleNotFoundError."""
        with (
            patch("builtins.__import__", side_effect=RuntimeError("kaboom")),
            caplog.at_level(logging.ERROR),
            pytest.raises(RuntimeError),
        ):
            _import_tool_modules()

        assert "Failed to import tool module" in caplog.text

    def test_import_tool_modules_imports_all_tool_modules(self) -> None:
        """All expected tool module names are passed to __import__."""
        imported: list[str] = []
        real_import = __import__

        def _tracking_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name.startswith("admino.tools."):
                imported.append(name)
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_tracking_import):
            _import_tool_modules()

        assert "admino.tools.gmail" in imported
        assert "admino.tools.google_calendar" in imported
        assert "admino.tools.memory" in imported
        # All top-level tool modules must be attempted; transitive imports
        # (e.g. admino.tools.registry from within a tool) may add extras.
        top_level_modules = {
            # Google API tools
            "admino.tools.gmail",
            "admino.tools.google_calendar",
            "admino.tools.google_drive",
            # Microsoft Graph API tools
            "admino.tools.outlook",
            "admino.tools.outlook_calendar",
            "admino.tools.onedrive",
            # Other tools
            "admino.tools.documents",
            "admino.tools.search",
            "admino.tools.files",
            "admino.tools.memory",
        }
        assert top_level_modules.issubset(set(imported))

    def test_import_tool_modules_continues_after_missing_module(self) -> None:
        """After a missing module, remaining modules are still imported."""
        call_count = 0

        def _side_effect(name: str, *args: Any, **kwargs: Any) -> MagicMock:
            nonlocal call_count
            if name.startswith("admino.tools."):
                call_count += 1
                if name == "admino.tools.gmail":
                    raise ModuleNotFoundError(f"No module named '{name}'")
            return MagicMock()

        with patch("builtins.__import__", side_effect=_side_effect):
            _import_tool_modules()

        # All 10 modules attempted despite first one failing
        assert call_count == 10


# ---------------------------------------------------------------------------
# AgentConfig wiring tests
# ---------------------------------------------------------------------------


class TestAgentConfigWiring:
    """Tests that AgentConfig is built from the correct config.limits fields."""

    def test_agent_config_receives_limits_from_config(self, mock_deps: dict[str, Any]) -> None:
        """AgentConfig is constructed with values from config.limits."""
        mock_deps["config"].limits.max_tool_calls_per_message = 15
        mock_deps["config"].limits.max_context_messages = 25
        mock_deps["config"].limits.confirmation_timeout_s = 200

        main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        agent_call_kwargs = mock_deps["Agent"].call_args.kwargs
        agent_config = agent_call_kwargs["agent_config"]
        assert agent_config.max_tool_calls == 15
        assert agent_config.max_context_messages == 25
        assert agent_config.confirmation_timeout_s == 200.0

    def test_agent_receives_correct_model_name(self, mock_deps: dict[str, Any]) -> None:
        """Agent is created with model_name from config.llm.active_model_name."""
        mock_deps["config"].llm.active_model_name = "llama3:8b"

        main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        agent_call_kwargs = mock_deps["Agent"].call_args.kwargs
        assert agent_call_kwargs["model_name"] == "llama3:8b"

    def test_agent_receives_llm_client(self, mock_deps: dict[str, Any]) -> None:
        """Agent is created with the LLM client instance from create_llm_client."""
        main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        agent_call_kwargs = mock_deps["Agent"].call_args.kwargs
        assert agent_call_kwargs["llm_client"] is mock_deps["ollama_client"]

    def test_agent_receives_audit_logger(self, mock_deps: dict[str, Any]) -> None:
        """Agent is created with the AuditLogger instance."""
        main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        agent_call_kwargs = mock_deps["Agent"].call_args.kwargs
        assert agent_call_kwargs["audit_logger"] is mock_deps["audit_logger"]

    def test_agent_receives_permissions_config(self, mock_deps: dict[str, Any]) -> None:
        """Agent is created with the PermissionsConfig instance."""
        main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        agent_call_kwargs = mock_deps["Agent"].call_args.kwargs
        assert agent_call_kwargs["permissions_config"] is mock_deps["permissions"]


# ---------------------------------------------------------------------------
# Uvicorn log_level passthrough
# ---------------------------------------------------------------------------


class TestUvicornLogLevel:
    """Tests for uvicorn log_level derived from config."""

    @pytest.mark.parametrize(
        ("config_level", "expected_uvicorn_level"),
        [
            ("DEBUG", "debug"),
            ("INFO", "info"),
            ("WARNING", "warning"),
            ("ERROR", "error"),
        ],
    )
    def test_uvicorn_receives_lowered_log_level(
        self,
        mock_deps: dict[str, Any],
        config_level: str,
        expected_uvicorn_level: str,
    ) -> None:
        """uvicorn.run receives log_level as lowercase of config.log_level."""
        mock_deps["config"].log_level = config_level

        main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        kw = mock_deps["uvicorn_run"].call_args.kwargs
        assert kw["log_level"] == expected_uvicorn_level

    @pytest.mark.parametrize("host", ["127.0.0.1", "0.0.0.0"])  # noqa: S104
    def test_uvicorn_single_worker_regardless_of_bind_address(
        self,
        mock_deps: dict[str, Any],
        host: str,
    ) -> None:
        """workers=1 is enforced regardless of host (prevents split-brain state)."""
        mock_deps["config"].server.host = host

        main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        kw = mock_deps["uvicorn_run"].call_args.kwargs
        assert kw["workers"] == 1


# ---------------------------------------------------------------------------
# Security invariant tests (AST scan)
# ---------------------------------------------------------------------------


class TestSecurityInvariants:
    """AST-based security scans of main.py source code."""

    @pytest.fixture(autouse=True)
    def _load_ast(self) -> None:
        """Parse main.py AST once for the class."""
        source = _MAIN_MODULE_PATH.read_text(encoding="utf-8")
        self.tree = ast.parse(source, filename=str(_MAIN_MODULE_PATH))
        self.source = source

    def test_no_eval_exec_compile(self) -> None:
        """main.py does not call eval(), exec(), or compile()."""
        forbidden = {"eval", "exec", "compile"}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in forbidden:
                    pytest.fail(f"Forbidden call to {func.id}() found in main.py")

    def test_no_shell_true(self) -> None:
        """main.py does not use shell=True in any call."""
        for node in ast.walk(self.tree):
            if (
                isinstance(node, ast.keyword)
                and node.arg == "shell"
                and isinstance(node.value, ast.Constant)
                and node.value.value is True
            ):
                pytest.fail("shell=True found in main.py")

    def test_no_secret_logging(self) -> None:
        """main.py does not log tokens, passwords, or secrets."""
        secret_keywords = ["AUTH_TOKEN", "FERNET_KEY", "CLIENT_SECRET", "password"]
        attr_secret_words = ["token", "secret", "password", "fernet"]

        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "logger"
                and func.attr in ("info", "debug", "warning", "error")
            ):
                continue

            # Check format string for secret keywords
            if node.args:
                fmt_arg = node.args[0]
                if isinstance(fmt_arg, ast.Constant) and isinstance(fmt_arg.value, str):
                    for keyword in secret_keywords:
                        if keyword in fmt_arg.value:
                            pytest.fail(f"Logger format string contains secret keyword '{keyword}'")

            # Check interpolated attribute arguments for secret-related names
            for arg in node.args[1:]:
                if isinstance(arg, ast.Attribute):
                    attr_chain = _get_attr_chain(arg)
                    for secret_word in attr_secret_words:
                        if secret_word in attr_chain.lower():
                            pytest.fail(f"Logger call may leak secret via attribute '{attr_chain}'")

    def test_no_importlib_anywhere(self) -> None:
        """main.py does not import or use importlib (SEC-20 compliance)."""
        for node in ast.walk(self.tree):
            # Check for `import importlib` or `from importlib import ...`
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "importlib" in alias.name:
                        pytest.fail(f"importlib imported: {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                if "importlib" in node.module:
                    pytest.fail(f"importlib imported: from {node.module}")
            # Check for importlib.xxx() calls
            elif isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "importlib"
                ):
                    pytest.fail("importlib used in a function call")


# ---------------------------------------------------------------------------
# Dependency ordering tests
# ---------------------------------------------------------------------------


class TestStartupOrdering:
    """Tests that verify correct ordering of startup steps."""

    def test_audit_logger_created_before_agent(self, mock_deps: dict[str, Any]) -> None:
        """AuditLogger is created before Agent (Agent depends on it)."""
        call_order: list[str] = []

        def track_audit(*a: Any, **kw: Any) -> MagicMock:
            call_order.append("audit")
            return mock_deps["audit_logger"]

        def track_agent(*a: Any, **kw: Any) -> MagicMock:
            call_order.append("agent")
            return mock_deps["agent"]

        mock_deps["AuditLogger"].side_effect = track_audit
        mock_deps["Agent"].side_effect = track_agent

        main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        assert call_order.index("audit") < call_order.index("agent")

    def test_freeze_registry_called_before_agent(self, mock_deps: dict[str, Any]) -> None:
        """freeze_registry is called before Agent is instantiated."""
        call_order: list[str] = []

        def track_freeze(*a: Any, **kw: Any) -> None:
            call_order.append("freeze")
            return None

        def track_agent(*a: Any, **kw: Any) -> MagicMock:
            call_order.append("agent")
            return mock_deps["agent"]

        mock_deps["freeze_registry"].side_effect = track_freeze
        mock_deps["Agent"].side_effect = track_agent

        main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        assert call_order.index("freeze") < call_order.index("agent")


# ---------------------------------------------------------------------------
# Database startup failure tests
# ---------------------------------------------------------------------------


class TestMainDatabaseStartupFailures:
    """Tests for main() when _async_startup fails via asyncio.run."""

    @pytest.mark.parametrize(
        "exc_type",
        [ValueError, RuntimeError, OSError],
    )
    def test_main_exits_1_on_async_startup_failure(
        self,
        mock_deps: dict[str, Any],
        exc_type: type[Exception],
    ) -> None:
        """main() exits with code 1 when asyncio.run raises ValueError/RuntimeError/OSError."""

        def _close_then_raise(coro: Any) -> None:
            if hasattr(coro, "close"):
                coro.close()
            raise exc_type("db failed")

        mock_deps["asyncio"].run = MagicMock(side_effect=_close_then_raise)

        with pytest.raises(SystemExit) as exc_info:
            main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        assert exc_info.value.code == 1

    def test_main_does_not_call_uvicorn_on_db_failure(self, mock_deps: dict[str, Any]) -> None:
        """uvicorn.run is never called when database startup fails."""

        def _close_then_raise(coro: Any) -> None:
            if hasattr(coro, "close"):
                coro.close()
            raise ValueError("PG_PASSWORD not set")

        mock_deps["asyncio"].run = MagicMock(side_effect=_close_then_raise)

        with pytest.raises(SystemExit):
            main(config_path=Path("c.yaml"), permissions_path=Path("p.yaml"))

        mock_deps["uvicorn_run"].assert_not_called()


# ---------------------------------------------------------------------------
# _async_startup direct tests
# ---------------------------------------------------------------------------


class TestAsyncStartup:
    """Tests for _async_startup() coroutine directly."""

    @pytest.mark.asyncio
    async def test_raises_when_pg_password_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_async_startup raises ValueError when PG_PASSWORD is not set."""
        monkeypatch.delenv("PG_PASSWORD", raising=False)
        with pytest.raises(ValueError, match="PG_PASSWORD"):
            await _async_startup(MagicMock(), MagicMock())

    @pytest.mark.asyncio
    async def test_raises_when_health_check_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_async_startup raises RuntimeError when database is unreachable."""
        monkeypatch.setenv("PG_PASSWORD", "testpass")
        mock_pool = AsyncMock()
        monkeypatch.setattr("admino.database.init_pool", AsyncMock(return_value=mock_pool))
        monkeypatch.setattr("admino.database.check_health", AsyncMock(return_value=False))
        monkeypatch.setattr("admino.database.close_pool", AsyncMock())

        with pytest.raises(RuntimeError, match="health check failed"):
            await _async_startup(MagicMock(), MagicMock())

    @pytest.mark.asyncio
    async def test_happy_path_returns_db_config_and_permissions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_async_startup returns (config, permissions, tools_enabled) from DB.

        GH-80: startup now returns a 3-tuple whose first two elements are the
        DB-loaded config and permissions.
        """
        monkeypatch.setenv("PG_PASSWORD", "testpass")
        mock_pool = AsyncMock()
        mock_db_config = MagicMock()
        mock_db_perms = MagicMock()

        monkeypatch.setattr("admino.database.init_pool", AsyncMock(return_value=mock_pool))
        monkeypatch.setattr("admino.database.check_health", AsyncMock(return_value=True))
        monkeypatch.setattr("admino.database.run_migrations", AsyncMock())
        monkeypatch.setattr("admino.database.seed_settings", AsyncMock())
        monkeypatch.setattr("admino.database.seed_permissions", AsyncMock())
        monkeypatch.setattr("admino.database.update_setting", AsyncMock())
        monkeypatch.setattr("admino.database.load_settings_from_db", AsyncMock(return_value={}))
        monkeypatch.setattr(
            "admino.config.load_app_config_from_db", AsyncMock(return_value=mock_db_config)
        )
        monkeypatch.setattr(
            "admino.config.load_permissions_config_from_db", AsyncMock(return_value=mock_db_perms)
        )

        result = await _async_startup(MagicMock(), MagicMock())
        assert result[0] is mock_db_config
        assert result[1] is mock_db_perms

    @pytest.mark.asyncio
    async def test_returns_tools_enabled_from_persisted_settings(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The 3rd element reflects persisted 'off' state, defaulting others True.

        GH-80: a service toggled off in the DB must come back disabled on the
        next boot. The persisted ``tools`` section is validated through
        ``ToolsSettings`` so the returned dict is a full enabled-state map.
        """
        monkeypatch.setenv("PG_PASSWORD", "testpass")
        mock_pool = AsyncMock()

        monkeypatch.setattr("admino.database.init_pool", AsyncMock(return_value=mock_pool))
        monkeypatch.setattr("admino.database.check_health", AsyncMock(return_value=True))
        monkeypatch.setattr("admino.database.run_migrations", AsyncMock())
        monkeypatch.setattr("admino.database.seed_settings", AsyncMock())
        monkeypatch.setattr("admino.database.seed_permissions", AsyncMock())
        monkeypatch.setattr("admino.database.update_setting", AsyncMock())
        monkeypatch.setattr(
            "admino.database.load_settings_from_db",
            AsyncMock(return_value={"tools": {"gmail": False}}),
        )
        monkeypatch.setattr(
            "admino.config.load_app_config_from_db", AsyncMock(return_value=MagicMock())
        )
        monkeypatch.setattr(
            "admino.config.load_permissions_config_from_db", AsyncMock(return_value=MagicMock())
        )

        from admino.models import ToolsSettings

        result = await _async_startup(MagicMock(), MagicMock())
        tools_enabled = result[2]
        assert tools_enabled == ToolsSettings(gmail=False).model_dump()
        assert tools_enabled["gmail"] is False
        assert tools_enabled["memory"] is True

    @pytest.mark.asyncio
    async def test_tools_enabled_all_true_when_no_tools_section(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When the DB has no 'tools' key, tools_enabled is the all-True default.

        GH-80: absence of persisted state must mean every service is enabled
        (ToolsSettings defaults), never accidentally disabled.
        """
        monkeypatch.setenv("PG_PASSWORD", "testpass")
        mock_pool = AsyncMock()

        monkeypatch.setattr("admino.database.init_pool", AsyncMock(return_value=mock_pool))
        monkeypatch.setattr("admino.database.check_health", AsyncMock(return_value=True))
        monkeypatch.setattr("admino.database.run_migrations", AsyncMock())
        monkeypatch.setattr("admino.database.seed_settings", AsyncMock())
        monkeypatch.setattr("admino.database.seed_permissions", AsyncMock())
        monkeypatch.setattr("admino.database.update_setting", AsyncMock())
        monkeypatch.setattr("admino.database.load_settings_from_db", AsyncMock(return_value={}))
        monkeypatch.setattr(
            "admino.config.load_app_config_from_db", AsyncMock(return_value=MagicMock())
        )
        monkeypatch.setattr(
            "admino.config.load_permissions_config_from_db", AsyncMock(return_value=MagicMock())
        )

        from admino.models import ToolsSettings

        result = await _async_startup(MagicMock(), MagicMock())
        tools_enabled = result[2]
        assert tools_enabled == ToolsSettings().model_dump()
        assert all(tools_enabled.values())

    @pytest.mark.asyncio
    async def test_reapplies_llm_section_from_config_on_boot(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """config.yaml is authoritative: the llm settings row is overwritten from
        config on every boot, so editing config.yaml always takes effect."""
        monkeypatch.setenv("PG_PASSWORD", "testpass")
        mock_pool = AsyncMock()
        mock_update = AsyncMock()

        monkeypatch.setattr("admino.database.init_pool", AsyncMock(return_value=mock_pool))
        monkeypatch.setattr("admino.database.check_health", AsyncMock(return_value=True))
        monkeypatch.setattr("admino.database.run_migrations", AsyncMock())
        monkeypatch.setattr("admino.database.seed_settings", AsyncMock())
        monkeypatch.setattr("admino.database.seed_permissions", AsyncMock())
        monkeypatch.setattr("admino.database.update_setting", mock_update)
        monkeypatch.setattr("admino.database.load_settings_from_db", AsyncMock(return_value={}))
        monkeypatch.setattr(
            "admino.config.load_app_config_from_db", AsyncMock(return_value=MagicMock())
        )
        monkeypatch.setattr(
            "admino.config.load_permissions_config_from_db", AsyncMock(return_value=MagicMock())
        )

        config = MagicMock()
        llm_dump = {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"}
        config.llm.model_dump.return_value = llm_dump

        await _async_startup(config, MagicMock())

        mock_update.assert_awaited_once_with(mock_pool, "llm", llm_dump)

    @pytest.mark.asyncio
    async def test_calls_init_pool_with_config_values(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_async_startup passes pool size from config to init_pool."""
        monkeypatch.setenv("PG_PASSWORD", "testpass")
        mock_init = AsyncMock(return_value=AsyncMock())
        monkeypatch.setattr("admino.database.init_pool", mock_init)
        monkeypatch.setattr("admino.database.check_health", AsyncMock(return_value=True))
        monkeypatch.setattr("admino.database.run_migrations", AsyncMock())
        monkeypatch.setattr("admino.database.seed_settings", AsyncMock())
        monkeypatch.setattr("admino.database.seed_permissions", AsyncMock())
        monkeypatch.setattr("admino.database.update_setting", AsyncMock())
        monkeypatch.setattr("admino.database.load_settings_from_db", AsyncMock(return_value={}))
        monkeypatch.setattr(
            "admino.config.load_app_config_from_db", AsyncMock(return_value=MagicMock())
        )
        monkeypatch.setattr(
            "admino.config.load_permissions_config_from_db", AsyncMock(return_value=MagicMock())
        )

        config = MagicMock()
        config.database.min_pool_size = 3
        config.database.max_pool_size = 10
        await _async_startup(config, MagicMock())

        mock_init.assert_called_once()
        call_args = mock_init.call_args
        assert call_args[0][0].startswith("postgresql://")
        assert call_args[1] == {"min_size": 3, "max_size": 10}


# ---------------------------------------------------------------------------
# Helpers for AST scanning
# ---------------------------------------------------------------------------


def _get_attr_chain(node: ast.Attribute) -> str:
    """Reconstruct a dotted attribute chain from an AST Attribute node."""
    parts: list[str] = [node.attr]
    current = node.value
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))
