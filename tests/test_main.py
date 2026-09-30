"""Comprehensive test suite for admino.main — entry point, config wiring, startup.

Tests the main() entry point, _configure_logging(), and _import_tool_modules(),
covering:
- Happy path: config loaded, dependencies wired, uvicorn.run called correctly
- Config failure paths: ValueError, OSError → sys.exit(1)
- Logging configuration: level mapping, invalid fallback
- Tool module imports: missing modules skipped, other errors re-raised
- AgentConfig wiring from config.limits fields
- Security invariants: no eval/exec/compile/shell=True, no secrets in logs
- GH-142: the provider → egress-host map includes ``api.infomaniak.com``; the
  Infomaniak startup check warns on a missing token and logs (never raises on)
  a product-id resolution failure.
- GH-147: the NDJSON audit logger is gone. main() never reads ``config.paths``
  and wires ``Agent(tool_call_recorder=main._build_tool_call_recorder())``; the
  recorder resolves the pool at call time and awaits
  ``audit_events.record_tool_call`` with the session's chat id
  (``uuid5(_SESSION_CHAT_NAMESPACE, session_id)``); errors propagate.
- GH-149: the default-org bridge is retired. The recorder takes the caller's
  principal and records its org and user (``TenantContext.from_principal``: a
  Super Admin raises, so the agent aborts the run). Startup no longer calls
  ``ensure_default_org`` (an empty database gets no organization), main.py
  doesn't reference ``DEFAULT_ORG_ID``, and startup loads the bundled
  common-password list once, so a missing list stops startup.
- GH-156: uvicorn runs one process (``workers=1``) with ``proxy_headers=False``,
  so its own X-Forwarded-* handling (which trusts 127.0.0.1 or the
  FORWARDED_ALLOW_IPS env var) never runs; the app's ``server.trusted_proxies``
  is the only source of truth.
- GH-159: ``_async_startup`` runs against tests/db_fakes.FakeDb: it seeds the
  ``platform_settings`` row from config.yaml (the llm re-applied on every
  boot, the limits kept), returns the config overlaid with the stored llm and
  limits, and computes the tools gate as the AND over every ``org_settings``
  row. main.py no longer uses the dropped settings table's helpers.
- GH-158: main() calls ``_configure_logging(config.log_level, config.log_format)``
  and runs uvicorn with ``log_config=None`` (and ``access_log=False``), so
  uvicorn's own loggers install no handlers of their own and go through the
  root handler (JSON or text, no tracebacks). A database startup failure is
  logged by exception type only: a DSN or password in the exception message
  never reaches the log.

Security notes:
- All external dependencies are mocked — no real LLM, no real config files,
  no real uvicorn startup.
- Tests verify that error output goes to stderr, not stdout.
"""

from __future__ import annotations

import ast
import inspect
import logging
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import DEFAULT, AsyncMock, MagicMock, patch

import httpx
import pytest
import uvicorn
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

import admino.main as main_module
from admino.config import AppConfig, LLMConfig
from admino.llm import LLMError
from admino.main import _async_startup, _configure_logging, _import_tool_modules, main
from tests.db_fakes import TOOL_NAMES, FakeDb

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
    config.log_format = "text"
    # GH-147: AppConfig has no paths section any more (the NDJSON audit log path
    # was its last field), so main() must never read it.
    del config.paths

    config.llm.provider = "anthropic"
    config.llm.active_model_name = "claude-sonnet-4-6"
    config.llm.anthropic_model = "claude-sonnet-4-6"
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
    mock_llm_client = MagicMock()
    mock_agent = MagicMock()
    mock_app = MagicMock()

    mock_load_app_config = MagicMock(return_value=mock_config)
    mock_build_permissions = MagicMock(return_value=mock_perms)
    mock_llm_cls = MagicMock(return_value=mock_llm_client)
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
    monkeypatch.setattr("admino.main.build_default_permissions_config", mock_build_permissions)
    monkeypatch.setattr("admino.main._import_tool_modules", mock_import_tools)
    monkeypatch.setattr("admino.main.asyncio", mock_asyncio)

    # These are imported lazily inside main(), so we patch the module paths
    monkeypatch.setattr("admino.llm.create_llm_client", mock_llm_cls)
    monkeypatch.setattr("admino.agent.Agent", mock_agent_cls)
    monkeypatch.setattr("admino.server.create_app", mock_create_app)
    monkeypatch.setattr("admino.tools.registry.freeze_registry", mock_freeze)
    monkeypatch.setattr("admino.main.uvicorn", MagicMock(run=mock_uvicorn_run))

    return {
        "config": mock_config,
        "permissions": mock_perms,
        "tools_enabled": mock_tools_enabled,
        "llm_client": mock_llm_client,
        "agent": mock_agent,
        "app": mock_app,
        "load_app_config": mock_load_app_config,
        "build_default_permissions_config": mock_build_permissions,
        "create_llm_client": mock_llm_cls,
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
        main(config_path=Path("c.yaml"))

        mock_deps["uvicorn_run"].assert_called_once()
        kw = mock_deps["uvicorn_run"].call_args
        assert kw.kwargs["workers"] == 1
        assert kw.kwargs["host"] == "127.0.0.1"
        assert kw.kwargs["port"] == 8000
        assert kw.kwargs["access_log"] is False

    def test_main_passes_app_to_uvicorn(self, mock_deps: dict[str, Any]) -> None:
        """uvicorn.run receives the app from create_app."""
        main(config_path=Path("c.yaml"))

        positional_args = mock_deps["uvicorn_run"].call_args.args
        assert positional_args[0] is mock_deps["app"]

    def test_main_calls_create_app_with_agent_and_config(self, mock_deps: dict[str, Any]) -> None:
        """create_app is called with the agent instance and config."""
        main(config_path=Path("c.yaml"))

        mock_deps["create_app"].assert_called_once_with(
            agent=mock_deps["agent"],
            config=mock_deps["config"],
        )

    def test_main_calls_freeze_registry_after_import(self, mock_deps: dict[str, Any]) -> None:
        """freeze_registry is called after _import_tool_modules."""
        main(config_path=Path("c.yaml"))

        mock_deps["import_tool_modules"].assert_called_once()
        mock_deps["freeze_registry"].assert_called_once()

    def test_main_loads_config_with_provided_path(self, mock_deps: dict[str, Any]) -> None:
        """load_app_config is called with the config_path argument."""
        test_path = Path("/custom/config.yaml")
        main(config_path=test_path)

        mock_deps["load_app_config"].assert_called_once_with(test_path)

    def test_main_builds_default_permissions_from_constant(self, mock_deps: dict[str, Any]) -> None:
        """Permissions are seeded from the in-code default, not a YAML file (GH-85)."""
        main(config_path=Path("c.yaml"))

        mock_deps["build_default_permissions_config"].assert_called_once_with()

    def test_main_passes_tools_enabled_to_agent(self, mock_deps: dict[str, Any]) -> None:
        """Agent is constructed with the persisted tools_enabled from startup (GH-80).

        The per-service enabled state loaded from the DB on boot must flow into
        the Agent so toggled-off services stay gated across restarts.
        """
        main(config_path=Path("c.yaml"))

        mock_deps["Agent"].assert_called_once()
        assert mock_deps["Agent"].call_args.kwargs["tools_enabled"] == mock_deps["tools_enabled"]


# ---------------------------------------------------------------------------
# GH-143: the local files tool is removed from startup
# ---------------------------------------------------------------------------


class TestMainWithoutFilesTool:
    """Startup no longer configures the files tool or reads a files config."""

    def test_main_starts_without_a_files_config_section(self, mock_deps: dict[str, Any]) -> None:
        """main() never reads config.files (files_tool.configure is gone)."""
        del mock_deps["config"].files

        main(config_path=Path("c.yaml"))

        mock_deps["create_app"].assert_called_once()
        mock_deps["uvicorn_run"].assert_called_once()

    def test_main_module_never_references_files_tool(self) -> None:
        """main.py neither imports admino.tools.files nor lists it for import."""
        tree = ast.parse(_MAIN_MODULE_PATH.read_text(encoding="utf-8"))
        violations: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "admino.tools":
                violations.extend(
                    f"from admino.tools import {alias.name}"
                    for alias in node.names
                    if alias.name == "files"
                )
            elif isinstance(node, ast.ImportFrom) and node.module == "admino.tools.files":
                violations.append("from admino.tools.files import ...")
            elif isinstance(node, ast.Import):
                violations.extend(
                    f"import {alias.name}"
                    for alias in node.names
                    if alias.name == "admino.tools.files"
                )
            elif isinstance(node, ast.Constant) and node.value == "admino.tools.files":
                violations.append("'admino.tools.files' string literal")
        assert violations == []


class TestBuildSystemPromptWithoutFilesTool:
    """The system prompt no longer advertises local file paths (GH-143)."""

    @staticmethod
    def _legacy_config() -> Any:
        """An AppConfig validated from a dict that still carries a legacy files section."""
        from admino.config import AppConfig

        return AppConfig.model_validate(
            {
                "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
                "auth": {"mode": "vpn"},
                "files": {
                    "allowed_paths": [
                        {
                            "path": "/app/documents",
                            "label": "Documents (~/Downloads/admino)",
                            "access": "readwrite",
                        }
                    ],
                    "max_read_chars": 10000,
                },
            }
        )

    def _prompt(self) -> str:
        from admino.main import _build_system_prompt
        from admino.tools.registry import ToolDescription

        fake_tool = ToolDescription(
            tool="memory",
            action="recall",
            description="Recall a note.",
            parameters_schema={"type": "object", "properties": {}},
        )
        with patch("admino.tools.registry.get_registered_tools", return_value=[fake_tool]):
            return _build_system_prompt(self._legacy_config())

    def test_system_prompt_has_no_file_paths_block(self) -> None:
        """The 'following file paths are available' block is gone."""
        assert "file paths are available" not in self._prompt().lower()

    def test_system_prompt_does_not_leak_legacy_path_or_label(self) -> None:
        """A legacy files.allowed_paths entry never reaches the prompt."""
        prompt = self._prompt()
        assert "/app/documents" not in prompt
        assert "Downloads/admino" not in prompt

    def test_system_prompt_has_no_file_tool_instructions(self) -> None:
        """The 'When using file tools' guidance is gone."""
        assert "file tools" not in self._prompt().lower()

    def test_system_prompt_still_lists_registered_tools(self) -> None:
        """The dynamic tool summary is unaffected by the removal."""
        assert "memory (recall)" in self._prompt()


# ---------------------------------------------------------------------------
# Config failure tests
# ---------------------------------------------------------------------------


class TestMainConfigFailures:
    """Tests for main() behavior when config loading fails."""

    def test_main_exits_1_on_config_value_error(self, mock_deps: dict[str, Any]) -> None:
        """main() exits with code 1 when load_app_config raises ValueError."""
        mock_deps["load_app_config"].side_effect = ValueError("bad config")

        with pytest.raises(SystemExit) as exc_info:
            main(config_path=Path("c.yaml"))

        assert exc_info.value.code == 1

    def test_main_exits_1_on_config_os_error(self, mock_deps: dict[str, Any]) -> None:
        """main() exits with code 1 when load_app_config raises OSError."""
        mock_deps["load_app_config"].side_effect = OSError("permission denied")

        with pytest.raises(SystemExit) as exc_info:
            main(config_path=Path("c.yaml"))

        assert exc_info.value.code == 1

    def test_main_prints_config_error_to_stderr(
        self, mock_deps: dict[str, Any], capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Config errors are printed to stderr, not stdout."""
        mock_deps["load_app_config"].side_effect = ValueError("bad yaml")

        with pytest.raises(SystemExit):
            main(config_path=Path("c.yaml"))

        captured = capsys.readouterr()
        assert "bad yaml" in captured.err
        assert captured.out == ""

    def test_main_does_not_call_uvicorn_on_config_failure(self, mock_deps: dict[str, Any]) -> None:
        """uvicorn.run is never called when config loading fails."""
        mock_deps["load_app_config"].side_effect = ValueError("fail")

        with pytest.raises(SystemExit):
            main(config_path=Path("c.yaml"))

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
            "admino.tools.memory",
        }
        assert top_level_modules.issubset(set(imported))

    def test_import_tool_modules_does_not_attempt_files_tool(self) -> None:
        """The removed local files tool is never imported (GH-143)."""
        attempted: list[str] = []

        def _side_effect(name: str, *args: Any, **kwargs: Any) -> MagicMock:
            if name.startswith("admino.tools."):
                attempted.append(name)
            return MagicMock()

        with patch("builtins.__import__", side_effect=_side_effect):
            _import_tool_modules()

        assert "admino.tools.files" not in attempted

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

        # All 7 modules attempted despite first one failing (GH-143 removed files)
        assert call_count == 7


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

        main(config_path=Path("c.yaml"))

        agent_call_kwargs = mock_deps["Agent"].call_args.kwargs
        agent_config = agent_call_kwargs["agent_config"]
        assert agent_config.max_tool_calls == 15
        assert agent_config.max_context_messages == 25
        assert agent_config.confirmation_timeout_s == 200.0

    @pytest.mark.parametrize("removed", ["audit_logger", "model_name"])
    def test_agent_receives_no_audit_logger_or_model_name(
        self, mock_deps: dict[str, Any], removed: str
    ) -> None:
        """GH-147: the audit logger and the model name (it only fed conversation audit
        entries) are no longer passed to the Agent."""
        main(config_path=Path("c.yaml"))

        assert removed not in mock_deps["Agent"].call_args.kwargs

    def test_agent_receives_llm_client(self, mock_deps: dict[str, Any]) -> None:
        """Agent is created with the LLM client instance from create_llm_client."""
        main(config_path=Path("c.yaml"))

        agent_call_kwargs = mock_deps["Agent"].call_args.kwargs
        assert agent_call_kwargs["llm_client"] is mock_deps["llm_client"]

    def test_agent_receives_tool_call_recorder_from_builder(
        self, mock_deps: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GH-147: Agent(tool_call_recorder=...) gets what _build_tool_call_recorder()
        returns, built once."""
        sentinel = AsyncMock()
        builder = MagicMock(return_value=sentinel)
        monkeypatch.setattr(main_module, "_build_tool_call_recorder", builder, raising=False)

        main(config_path=Path("c.yaml"))

        builder.assert_called_once_with()
        assert mock_deps["Agent"].call_args.kwargs["tool_call_recorder"] is sentinel

    def test_agent_receives_permissions_config(self, mock_deps: dict[str, Any]) -> None:
        """Agent is created with the PermissionsConfig instance."""
        main(config_path=Path("c.yaml"))

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

        main(config_path=Path("c.yaml"))

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

        main(config_path=Path("c.yaml"))

        kw = mock_deps["uvicorn_run"].call_args.kwargs
        assert kw["workers"] == 1


# ---------------------------------------------------------------------------
# GH-156: uvicorn never applies its own X-Forwarded-* trust
# ---------------------------------------------------------------------------


class TestUvicornProxyHeaders:
    """uvicorn runs with ``proxy_headers=False``: the app's ``server.trusted_proxies`` is
    the only source of truth for X-Forwarded-For / X-Forwarded-Proto.

    Left on, uvicorn's own middleware trusts 127.0.0.1 (or whatever the
    FORWARDED_ALLOW_IPS env var says, ``*`` included) before the app sees the
    request.
    """

    def test_uvicorn_proxy_headers_disabled(self, mock_deps: dict[str, Any]) -> None:
        main(config_path=Path("c.yaml"))

        kw = mock_deps["uvicorn_run"].call_args.kwargs
        assert kw["proxy_headers"] is False

    def test_uvicorn_proxy_headers_disabled_with_forwarded_allow_ips_env(
        self, mock_deps: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """FORWARDED_ALLOW_IPS=* in the environment doesn't turn uvicorn's trust back on."""
        monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")

        main(config_path=Path("c.yaml"))

        kw = mock_deps["uvicorn_run"].call_args.kwargs
        assert kw.get("proxy_headers") is False

    def test_uvicorn_config_from_main_leaves_the_app_unwrapped(
        self, mock_deps: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Fed into a real uvicorn.Config, main()'s arguments never wrap the app in uvicorn's
        ProxyHeadersMiddleware, even with FORWARDED_ALLOW_IPS=*."""
        monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")

        main(config_path=Path("c.yaml"))

        async def asgi_app(scope: Any, receive: Any, send: Any) -> None:
            """A stand-in ASGI app (never called)."""

        # No logging setup (the test must not reconfigure the uvicorn loggers), and no
        # websocket protocol import (admino serves none; its import only warns).
        kwargs = {**mock_deps["uvicorn_run"].call_args.kwargs, "log_config": None}
        kwargs["log_level"] = None
        kwargs["ws"] = "none"
        uvicorn_config = uvicorn.Config(asgi_app, **kwargs)
        uvicorn_config.load()
        assert not isinstance(uvicorn_config.loaded_app, ProxyHeadersMiddleware)


# ---------------------------------------------------------------------------
# GH-158: logging wiring (format, uvicorn's loggers)
# ---------------------------------------------------------------------------

_UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access", "uvicorn.asgi")


class TestMainLoggingWiring:
    """main() configures the chosen log format and leaves uvicorn's loggers to the root."""

    @pytest.mark.parametrize("log_format", ["json", "text"])
    def test_main_passes_log_format_to_configure_logging(
        self, mock_deps: dict[str, Any], monkeypatch: pytest.MonkeyPatch, log_format: str
    ) -> None:
        mock_deps["config"].log_level = "WARNING"
        mock_deps["config"].log_format = log_format
        spy = MagicMock()
        monkeypatch.setattr("admino.main._configure_logging", spy)

        main(config_path=Path("c.yaml"))

        spy.assert_called_once()
        bound = inspect.signature(_configure_logging).bind(
            *spy.call_args.args, **spy.call_args.kwargs
        )
        assert (bound.arguments.get("level_name"), bound.arguments.get("log_format")) == (
            "WARNING",
            log_format,
        )

    def test_uvicorn_log_config_is_none(self, mock_deps: dict[str, Any]) -> None:
        """uvicorn's default LOGGING_CONFIG (its own formatter, tracebacks) is never applied."""
        main(config_path=Path("c.yaml"))

        kw = mock_deps["uvicorn_run"].call_args.kwargs
        assert "log_config" in kw
        assert kw["log_config"] is None

    def test_uvicorn_config_from_main_leaves_its_loggers_to_the_root_handler(
        self, mock_deps: dict[str, Any]
    ) -> None:
        """Fed into a real uvicorn.Config, main()'s arguments install no uvicorn handler:
        uvicorn's error logger propagates to the root handler admino configured."""
        main(config_path=Path("c.yaml"))
        kwargs = {**mock_deps["uvicorn_run"].call_args.kwargs, "ws": "none"}
        # Checked first, so uvicorn's dictConfig never runs in this process.
        assert kwargs.get("log_config", "missing") is None

        async def asgi_app(scope: Any, receive: Any, send: Any) -> None:
            """A stand-in ASGI app (never called)."""

        loggers = [logging.getLogger(name) for name in _UVICORN_LOGGERS]
        saved = [(lg.handlers[:], lg.level, lg.propagate, lg.disabled) for lg in loggers]
        try:
            for lg in loggers:
                lg.handlers = []
                lg.propagate = True
            uvicorn.Config(asgi_app, **kwargs)
            state = [
                (lg.name, lg.handlers, lg.propagate)
                for lg in loggers
                if lg.name in {"uvicorn", "uvicorn.error"}
            ]
        finally:
            for lg, (handlers, level, propagate, disabled) in zip(loggers, saved, strict=True):
                lg.handlers = handlers
                lg.setLevel(level)
                lg.propagate = propagate
                lg.disabled = disabled

        assert state == [("uvicorn", [], True), ("uvicorn.error", [], True)]


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

        main(config_path=Path("c.yaml"))

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
            main(config_path=Path("c.yaml"))

        assert exc_info.value.code == 1

    @pytest.mark.parametrize("exc_type", [ValueError, RuntimeError, OSError])
    def test_main_db_startup_failure_logs_the_exception_type_only(
        self,
        mock_deps: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        exc_type: type[Exception],
    ) -> None:
        """GH-158: "Database startup failed" names the exception type, never its message
        (a DSN with the database password, a host name)."""
        # Keep pytest's capture handler on the root logger.
        monkeypatch.setattr("admino.main._configure_logging", MagicMock())

        def _close_then_raise(coro: Any) -> None:
            if hasattr(coro, "close"):
                coro.close()
            raise exc_type("postgres://admino:s3cretpw@db.internal/admino")

        mock_deps["asyncio"].run = MagicMock(side_effect=_close_then_raise)

        with caplog.at_level(logging.DEBUG), pytest.raises(SystemExit):
            main(config_path=Path("c.yaml"))

        failures = [
            record
            for record in caplog.records
            if record.name == "admino.main" and "Database startup failed" in record.getMessage()
        ]
        assert len(failures) == 1
        assert failures[0].levelno == logging.ERROR
        assert exc_type.__name__ in failures[0].getMessage()
        assert failures[0].exc_info is None
        assert "s3cretpw" not in caplog.text
        assert "db.internal" not in caplog.text

    def test_main_does_not_call_uvicorn_on_db_failure(self, mock_deps: dict[str, Any]) -> None:
        """uvicorn.run is never called when database startup fails."""

        def _close_then_raise(coro: Any) -> None:
            if hasattr(coro, "close"):
                coro.close()
            raise ValueError("PG_PASSWORD not set")

        mock_deps["asyncio"].run = MagicMock(side_effect=_close_then_raise)

        with pytest.raises(SystemExit):
            main(config_path=Path("c.yaml"))

        mock_deps["uvicorn_run"].assert_not_called()


# ---------------------------------------------------------------------------
# _async_startup direct tests (GH-159: the platform row and the org tools gate)
# ---------------------------------------------------------------------------

_ALL_TOOLS_ON: dict[str, bool] = dict.fromkeys(TOOL_NAMES, True)
_STORED_LIMITS: dict[str, int] = {
    "max_tool_calls_per_message": 7,
    "max_pending_confirmations": 4,
    "confirmation_timeout_s": 120,
    "max_message_length": 5000,
    "max_context_messages": 30,
}
_REMOVED_STARTUP_HELPERS = (
    "seed_settings",
    "update_setting",
    "load_settings_from_db",
    "load_app_config_from_db",
)


def _startup_config(**limits: int) -> AppConfig:
    """A real config.yaml-shaped AppConfig (Anthropic, pool sizes 3 and 10)."""
    return AppConfig.model_validate(
        {
            "server": {
                "host": "127.0.0.1",
                "port": 8123,
                "public_url": "https://admino.example.ch",
            },
            "llm": {
                "provider": "anthropic",
                "anthropic_model": "claude-sonnet-4-6",
                "openai_model": "gpt-4o",
                "timeout_s": 77,
            },
            "limits": limits,
            "database": {"min_pool_size": 3, "max_pool_size": 10},
            "log_level": "WARNING",
        }
    )


@dataclass
class _Startup:
    """The fake database _async_startup runs on, and its patched steps.

    ``events`` records (step, number of statements run so far) for the patched steps.
    """

    db: FakeDb
    events: list[tuple[str, int]]
    init_pool: AsyncMock
    seed_permissions: AsyncMock
    load_permissions: AsyncMock
    close_pool: AsyncMock
    permissions: MagicMock


def _patch_startup_db(monkeypatch: pytest.MonkeyPatch) -> _Startup:
    """Run _async_startup against tests/db_fakes.FakeDb (GH-159).

    Migrations, the permission seed and load, the health check and the pool's
    close are patched; the settings code (admino.scoped_settings) runs for real
    against the fake's platform_settings and org_settings tables, and any
    statement on the dropped ``settings`` table fails like PostgreSQL.
    """
    monkeypatch.setenv("PG_PASSWORD", "testpass")
    db = FakeDb()
    events: list[tuple[str, int]] = []

    def step(name: str) -> Any:
        def _record(*_args: Any, **_kwargs: Any) -> Any:
            events.append((name, len(db.calls)))
            return DEFAULT

        return _record

    permissions = MagicMock(name="db-permissions")
    init_pool = AsyncMock(return_value=db.pool, side_effect=step("init_pool"))
    seed_permissions = AsyncMock(side_effect=step("seed_permissions"))
    load_permissions = AsyncMock(return_value=permissions, side_effect=step("load_permissions"))
    close_pool = AsyncMock(side_effect=step("close_pool"))
    monkeypatch.setattr("admino.database.init_pool", init_pool)
    monkeypatch.setattr("admino.database.get_pool", lambda: db.pool)
    monkeypatch.setattr("admino.database.check_health", AsyncMock(return_value=True))
    monkeypatch.setattr(
        "admino.database.run_migrations", AsyncMock(side_effect=step("run_migrations"))
    )
    monkeypatch.setattr("admino.database.seed_permissions", seed_permissions)
    monkeypatch.setattr("admino.database.close_pool", close_pool)
    monkeypatch.setattr("admino.config.load_permissions_config_from_db", load_permissions)
    return _Startup(
        db=db,
        events=events,
        init_pool=init_pool,
        seed_permissions=seed_permissions,
        load_permissions=load_permissions,
        close_pool=close_pool,
        permissions=permissions,
    )


def _platform_llm(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": row["llm_provider"],
        **{
            column: row[column]
            for column in ("infomaniak_model", "vllm_model", "anthropic_model", "openai_model")
        },
    }


class TestAsyncStartup:
    """_async_startup: migrations, the platform row seeded from config.yaml and overlaid
    onto the config, permissions, and the interim tools gate over org_settings (GH-159)."""

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
    async def test_async_startup_first_boot_seeds_the_platform_row_from_the_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty platform_settings table gets config.yaml's llm and limits."""
        startup = _patch_startup_db(monkeypatch)
        config = _startup_config(max_message_length=6000)

        await _async_startup(config, MagicMock())

        row = startup.db.platform_row()
        assert row is not None
        assert _platform_llm(row) == {
            "provider": "anthropic",
            "infomaniak_model": config.llm.infomaniak_model,
            "vllm_model": config.llm.vllm_model,
            "anthropic_model": "claude-sonnet-4-6",
            "openai_model": "gpt-4o",
        }
        assert {key: row[key] for key in _STORED_LIMITS} == config.limits.model_dump()

    @pytest.mark.asyncio
    async def test_async_startup_later_boot_reapplies_the_llm_and_keeps_the_limits(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """config.yaml's llm is re-applied on every boot; the stored limits are kept."""
        startup = _patch_startup_db(monkeypatch)
        startup.db.add_platform_settings(
            llm_provider="openai", openai_model="gpt-4.1", **_STORED_LIMITS
        )

        await _async_startup(_startup_config(), MagicMock())

        row = startup.db.platform_row()
        assert row is not None
        assert (row["llm_provider"], row["openai_model"]) == ("anthropic", "gpt-4o")
        assert {key: row[key] for key in _STORED_LIMITS} == _STORED_LIMITS

    @pytest.mark.asyncio
    async def test_async_startup_returns_the_config_overlaid_with_the_platform_row(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The returned config: the stored llm and limits; every other section (server,
        egress, database, log level, the llm timeout) from config.yaml."""
        startup = _patch_startup_db(monkeypatch)
        startup.db.add_platform_settings(**_STORED_LIMITS)
        config = _startup_config()

        result = await _async_startup(config, MagicMock())

        runtime = result[0]
        assert type(runtime) is AppConfig
        assert (runtime.llm.provider, runtime.llm.anthropic_model) == (
            "anthropic",
            "claude-sonnet-4-6",
        )
        assert runtime.limits.model_dump() == _STORED_LIMITS
        assert runtime.server == config.server
        assert runtime.egress == config.egress
        assert runtime.database == config.database
        assert (runtime.log_level, runtime.llm.timeout_s) == ("WARNING", 77)

    @pytest.mark.asyncio
    async def test_async_startup_returns_the_loaded_permissions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Permissions are seeded on the startup pool, then loaded from it."""
        startup = _patch_startup_db(monkeypatch)
        permissions_config = MagicMock(name="default-permissions")

        result = await _async_startup(_startup_config(), permissions_config)

        assert len(result) == 3
        assert result[1] is startup.permissions
        startup.seed_permissions.assert_awaited_once_with(startup.db.pool, permissions_config)
        startup.load_permissions.assert_awaited_once_with(startup.db.pool)

    @pytest.mark.asyncio
    async def test_async_startup_tools_gate_is_the_and_over_every_org(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GH-80 + GH-159: a service one org turned off stays off after a restart, even
        when another org has it on."""
        startup = _patch_startup_db(monkeypatch)
        first = startup.db.add_org()
        second = startup.db.add_org()
        startup.db.add_org_settings(first, gmail=False)
        startup.db.add_org_settings(second, gmail=True, memory=False)

        result = await _async_startup(_startup_config(), MagicMock())

        assert dict(result[2]) == {**_ALL_TOOLS_ON, "gmail": False, "memory": False}

    @pytest.mark.asyncio
    async def test_async_startup_tools_gate_all_on_without_org_rows(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No org_settings row: every service is on (never accidentally disabled)."""
        _patch_startup_db(monkeypatch)

        result = await _async_startup(_startup_config(), MagicMock())

        assert dict(result[2]) == _ALL_TOOLS_ON
        assert all(type(value) is bool for value in result[2].values())

    @pytest.mark.asyncio
    async def test_async_startup_order_migrate_seed_read_then_close(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Migrations run before any statement, the platform row is seeded before it is
        read, and the startup pool is closed after the last statement."""
        startup = _patch_startup_db(monkeypatch)

        await _async_startup(_startup_config(), MagicMock())

        calls = startup.db.calls
        steps = dict(startup.events)
        assert steps["run_migrations"] == 0
        seeds = [
            i
            for i, c in enumerate(calls)
            if c.normalized.startswith("insert into platform_settings")
        ]
        reads = [
            i
            for i, c in enumerate(calls)
            if c.normalized.startswith("select") and "from platform_settings" in c.normalized
        ]
        gates = [i for i, c in enumerate(calls) if "from org_settings" in c.normalized]
        assert seeds and reads and gates
        assert seeds[0] < reads[0]
        assert steps["close_pool"] == len(calls)

    @pytest.mark.asyncio
    async def test_calls_init_pool_with_config_values(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_async_startup passes pool size from config to init_pool."""
        startup = _patch_startup_db(monkeypatch)

        await _async_startup(_startup_config(), MagicMock())

        startup.init_pool.assert_called_once()
        call_args = startup.init_pool.call_args
        assert call_args[0][0].startswith("postgresql://")
        assert call_args[1] == {"min_size": 3, "max_size": 10}

    @pytest.mark.parametrize("name", _REMOVED_STARTUP_HELPERS)
    def test_main_module_no_longer_uses_the_settings_table_helpers(self, name: str) -> None:
        """GH-159: the key/value settings table is gone, and so are its helpers."""
        tree = ast.parse(_MAIN_MODULE_PATH.read_text(encoding="utf-8"))
        used = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }

        assert name not in used


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


# ---------------------------------------------------------------------------
# GH-142: provider egress check
# ---------------------------------------------------------------------------


def _egress_config(provider: str, hosts: list[str]) -> Any:
    """A minimal config exposing llm.provider and egress.allowed_hosts."""
    return SimpleNamespace(
        llm=SimpleNamespace(provider=provider),
        egress=SimpleNamespace(allowed_hosts=hosts),
    )


class TestProviderEgressCheck:
    """The startup check maps each cloud provider to the host it must reach."""

    def test_provider_egress_hosts_include_infomaniak(self) -> None:
        """infomaniak → api.infomaniak.com."""
        assert main_module._PROVIDER_EGRESS_HOSTS["infomaniak"] == "api.infomaniak.com"

    def test_provider_egress_hosts_keep_cloud_providers(self) -> None:
        """anthropic / openai keep their API hosts."""
        hosts = main_module._PROVIDER_EGRESS_HOSTS
        assert hosts["anthropic"] == "api.anthropic.com"
        assert hosts["openai"] == "api.openai.com"

    @pytest.mark.parametrize(
        ("provider", "host"),
        [
            ("infomaniak", "api.infomaniak.com"),
            ("anthropic", "api.anthropic.com"),
            ("openai", "api.openai.com"),
        ],
    )
    def test_warn_missing_provider_egress_warns_when_host_missing(
        self, caplog: pytest.LogCaptureFixture, provider: str, host: str
    ) -> None:
        """A provider whose host is not whitelisted logs a WARNING naming the host."""
        config = _egress_config(provider, ["www.googleapis.com"])
        with caplog.at_level(logging.WARNING):
            main_module._warn_missing_provider_egress(config)
        assert any(
            host in record.getMessage()
            for record in caplog.records
            if record.levelno == logging.WARNING
        )

    def test_warn_missing_provider_egress_silent_when_host_present(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No warning when api.infomaniak.com is whitelisted."""
        config = _egress_config("infomaniak", ["www.googleapis.com", "api.infomaniak.com"])
        with caplog.at_level(logging.WARNING):
            main_module._warn_missing_provider_egress(config)
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

    def test_warn_missing_provider_egress_silent_for_vllm(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """vLLM is internal to the Docker network — no egress warning."""
        config = _egress_config("vllm", [])
        with caplog.at_level(logging.WARNING):
            main_module._warn_missing_provider_egress(config)
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

    def test_main_runs_provider_egress_check(
        self, mock_deps: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """main() delegates the egress warning to _warn_missing_provider_egress(config)."""
        spy = MagicMock()
        monkeypatch.setattr("admino.main._warn_missing_provider_egress", spy)

        main(config_path=Path("c.yaml"))

        spy.assert_called_once_with(mock_deps["config"])


# ---------------------------------------------------------------------------
# GH-142: Infomaniak startup check
# ---------------------------------------------------------------------------

_IK_TOKEN = "ik-startup-token-SECRET-91ab"


@pytest.fixture()
def offline_infomaniak(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Import admino.llm_infomaniak with its HTTP seam failing on any request."""
    from admino import llm_infomaniak

    def _handler(request: httpx.Request) -> httpx.Response:
        pytest.fail(f"unexpected network request to {request.url.host}")

    def _factory(*_args: Any, **_kwargs: Any) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(_handler))

    monkeypatch.setattr(llm_infomaniak, "_new_http_client", _factory)
    monkeypatch.delenv("INFOMANIAK_PRODUCT_ID", raising=False)
    return llm_infomaniak


class TestInfomaniakStartupCheck:
    """_check_infomaniak_startup(client): warn/log only — never raise, never exit."""

    async def test_check_missing_token_warns_and_skips_discovery(
        self,
        offline_infomaniak: Any,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """No token → WARNING naming INFOMANIAK_API_TOKEN; no product discovery attempted."""
        monkeypatch.delenv("INFOMANIAK_API_TOKEN", raising=False)
        client = offline_infomaniak.InfomaniakClient(LLMConfig(provider="infomaniak"))
        resolve = AsyncMock(return_value="7539")
        monkeypatch.setattr(client, "resolve_product_id", resolve)

        with caplog.at_level(logging.DEBUG):
            await main_module._check_infomaniak_startup(client)

        resolve.assert_not_awaited()
        assert any(
            "INFOMANIAK_API_TOKEN" in record.getMessage()
            for record in caplog.records
            if record.levelno == logging.WARNING
        )

    async def test_check_resolution_error_logged_not_raised(
        self,
        offline_infomaniak: Any,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Several products → ERROR asking for INFOMANIAK_PRODUCT_ID; the app keeps booting."""
        monkeypatch.setenv("INFOMANIAK_API_TOKEN", _IK_TOKEN)
        client = offline_infomaniak.InfomaniakClient(LLMConfig(provider="infomaniak"))
        message = (
            "Several Infomaniak AI products were found; set INFOMANIAK_PRODUCT_ID on the server."
        )
        resolve = AsyncMock(side_effect=LLMError(message, None, user_facing=True))
        monkeypatch.setattr(client, "resolve_product_id", resolve)

        with caplog.at_level(logging.DEBUG):
            await main_module._check_infomaniak_startup(client)

        resolve.assert_awaited_once()
        errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
        assert any("INFOMANIAK_PRODUCT_ID" in m for m in errors)
        assert _IK_TOKEN not in caplog.text

    async def test_check_success_logs_no_error(
        self,
        offline_infomaniak: Any,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A resolvable product id → no ERROR/WARNING about Infomaniak setup; token not logged."""
        monkeypatch.setenv("INFOMANIAK_API_TOKEN", _IK_TOKEN)
        client = offline_infomaniak.InfomaniakClient(LLMConfig(provider="infomaniak"))
        resolve = AsyncMock(return_value="7539")
        monkeypatch.setattr(client, "resolve_product_id", resolve)

        with caplog.at_level(logging.DEBUG):
            await main_module._check_infomaniak_startup(client)

        resolve.assert_awaited_once()
        assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
        assert _IK_TOKEN not in caplog.text


class TestMainInfomaniakWiring:
    """main() runs the Infomaniak startup check when that provider is active."""

    @staticmethod
    def _asyncio_run_targets(mock_deps: dict[str, Any]) -> list[str]:
        """Names of the coroutines main() handed to asyncio.run()."""
        return [
            getattr(call.args[0], "__name__", "")
            for call in mock_deps["asyncio"].run.call_args_list
        ]

    def test_main_runs_infomaniak_startup_check(
        self, mock_deps: dict[str, Any], offline_infomaniak: Any
    ) -> None:
        """provider=infomaniak → asyncio.run(_check_infomaniak_startup(client)) after the client."""
        mock_deps["config"].llm.provider = "infomaniak"
        mock_deps["create_llm_client"].return_value = MagicMock(
            spec=offline_infomaniak.InfomaniakClient
        )

        main(config_path=Path("c.yaml"))

        assert "_check_infomaniak_startup" in self._asyncio_run_targets(mock_deps)
        mock_deps["uvicorn_run"].assert_called_once()


# ---------------------------------------------------------------------------
# GH-147 / GH-149: startup creates no organization; tool-call recorder wiring
# ---------------------------------------------------------------------------


class TestAsyncStartupCreatesNoOrganization:
    """GH-149: the default-org bridge is gone; a fresh install has 0 organizations."""

    @pytest.mark.asyncio
    async def test_startup_never_calls_ensure_default_org(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """accounts.ensure_default_org is not called during startup."""
        _patch_startup_db(monkeypatch)
        ensure = AsyncMock()
        monkeypatch.setattr("admino.accounts.ensure_default_org", ensure, raising=False)

        await _async_startup(_startup_config(), MagicMock())

        ensure.assert_not_called()

    @pytest.mark.asyncio
    async def test_startup_on_empty_db_inserts_no_organization(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No statement issued at startup inserts into organizations."""
        startup = _patch_startup_db(monkeypatch)

        await _async_startup(_startup_config(), MagicMock())

        assert startup.db.calls
        assert startup.db.matching(r"\binsert into organizations\b") == []
        assert startup.db.orgs == {}

    def test_main_module_does_not_reference_the_default_org(self) -> None:
        """main.py neither imports DEFAULT_ORG_ID nor calls ensure_default_org."""
        source = _MAIN_MODULE_PATH.read_text(encoding="utf-8")

        assert "DEFAULT_ORG_ID" not in source
        assert "ensure_default_org" not in source

    def test_main_docstring_drops_default_org_and_auth_token(self) -> None:
        """The startup description no longer mentions the default organization step or
        AUTH_TOKEN (the bearer token is gone)."""
        doc = main_module.__doc__ or ""

        assert "default organization" not in doc.lower()
        assert "AUTH_TOKEN" not in doc


class TestStartupLoadsCommonPasswords:
    """GH-149: the bundled common-password list is loaded once, at startup."""

    @pytest.mark.asyncio
    async def test_startup_loads_the_list_once(
        self, mock_deps: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """passwords.common_passwords() is called exactly once across the startup
        (in main() or in _async_startup), before the server starts."""
        events: list[str] = []

        def fake_common_passwords() -> frozenset[str]:
            events.append("common_passwords")
            return frozenset({"qwerty123456"})

        monkeypatch.setattr("admino.passwords.common_passwords", fake_common_passwords)
        mock_deps["uvicorn_run"].side_effect = lambda *_a, **_k: events.append("uvicorn")
        _patch_startup_db(monkeypatch)

        await _async_startup(_startup_config(), MagicMock())
        main()

        assert events.count("common_passwords") == 1
        assert events.index("common_passwords") < events.index("uvicorn")

    @pytest.mark.asyncio
    async def test_missing_list_stops_startup(
        self, mock_deps: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A missing or unreadable list fails startup instead of silently disabling the
        check: the server never starts."""
        monkeypatch.setattr(
            "admino.passwords.common_passwords",
            MagicMock(side_effect=OSError("common_passwords.txt missing")),
        )
        _patch_startup_db(monkeypatch)

        failed = False
        try:
            await _async_startup(_startup_config(), MagicMock())
        except OSError:
            failed = True
        if not failed:
            with pytest.raises((SystemExit, OSError)) as exc_info:
                main()
            if isinstance(exc_info.value, SystemExit):
                assert exc_info.value.code == 1

        mock_deps["uvicorn_run"].assert_not_called()


class TestSessionChatId:
    """GH-147: the audit target for a session until #176 adds chat UUIDs."""

    def test_is_uuid5_of_the_session_in_the_fixed_namespace(self) -> None:
        import uuid

        chat_id = main_module._session_chat_id("s-lz3k-a1b2c3d4")

        assert isinstance(chat_id, uuid.UUID)
        assert chat_id.version == 5
        assert chat_id == uuid.uuid5(main_module._SESSION_CHAT_NAMESPACE, "s-lz3k-a1b2c3d4")

    def test_is_deterministic(self) -> None:
        assert main_module._session_chat_id("s-1") == main_module._session_chat_id("s-1")

    def test_differs_per_session(self) -> None:
        assert main_module._session_chat_id("s-1") != main_module._session_chat_id("s-2")

    def test_namespace_is_a_fixed_uuid(self) -> None:
        import uuid

        assert isinstance(main_module._SESSION_CHAT_NAMESPACE, uuid.UUID)


_RECORDER_USER = uuid.UUID("9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d")
_RECORDER_ORG = uuid.UUID("1f2e3d4c-5b6a-4978-9a8b-7c6d5e4f3a2b")
# #147's default organization (GH-154 removed accounts.DEFAULT_ORG_ID).
_DEFAULT_ORG_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")


def _member_principal() -> Any:
    """An editor of _RECORDER_ORG."""
    from admino.access import Principal

    return Principal(user_id=_RECORDER_USER, kind="member", org_id=_RECORDER_ORG, role="editor")


def _recorder_kwargs(**overrides: Any) -> dict[str, Any]:
    """The seven keywords the agent passes to the recorder."""
    kwargs: dict[str, Any] = {
        "principal": _member_principal(),
        "session_id": "s-abc",
        "tool": "memory",
        "action": "read",
        "decision": "allow",
        "success": True,
        "duration_ms": 12,
    }
    kwargs.update(overrides)
    return kwargs


class TestBuildToolCallRecorder:
    """GH-147/GH-149: the recorder main() injects into the Agent."""

    @pytest.mark.asyncio
    async def test_records_the_principals_org_and_user_on_the_chat(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One call → one record_tool_call on the runtime pool, with the member's org and
        user id and the session's chat."""
        pool = MagicMock(name="runtime-pool")
        record = AsyncMock()
        monkeypatch.setattr("admino.database.get_pool", MagicMock(return_value=pool))
        monkeypatch.setattr("admino.audit_events.record_tool_call", record, raising=False)

        recorder = main_module._build_tool_call_recorder()
        await recorder(**_recorder_kwargs())

        record.assert_awaited_once_with(
            pool,
            org_id=_RECORDER_ORG,
            actor_user_id=_RECORDER_USER,
            chat_id=main_module._session_chat_id("s-abc"),
            tool="memory",
            action="read",
            decision="allow",
            success=True,
            duration_ms=12,
        )

    @pytest.mark.asyncio
    async def test_super_admin_principal_raises_and_records_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A Super Admin has no org (no TenantContext): the recorder raises, so the agent
        aborts the run, and nothing is recorded."""
        from admino.access import Principal
        from admino.tenancy import NoTenantContextError

        record = AsyncMock()
        monkeypatch.setattr("admino.database.get_pool", MagicMock(return_value=MagicMock()))
        monkeypatch.setattr("admino.audit_events.record_tool_call", record, raising=False)

        recorder = main_module._build_tool_call_recorder()
        with pytest.raises(NoTenantContextError):
            await recorder(
                **_recorder_kwargs(principal=Principal(user_id=_RECORDER_USER, kind="super_admin"))
            )

        record.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_never_records_into_the_default_org(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The bridge is retired: the default org id (#147's
        00000000-0000-4000-8000-000000000001) is never passed."""
        record = AsyncMock()
        monkeypatch.setattr("admino.database.get_pool", MagicMock(return_value=MagicMock()))
        monkeypatch.setattr("admino.audit_events.record_tool_call", record, raising=False)

        recorder = main_module._build_tool_call_recorder()
        await recorder(**_recorder_kwargs())

        assert record.await_args is not None
        assert _DEFAULT_ORG_ID not in record.await_args.kwargs.values()

    @pytest.mark.asyncio
    async def test_resolves_the_pool_at_call_time(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The runtime pool only exists once uvicorn's lifespan ran, after main() built
        the recorder, so building it must not touch the pool."""
        get_pool = MagicMock(side_effect=RuntimeError("pool not initialised"))
        monkeypatch.setattr("admino.database.get_pool", get_pool)

        recorder = main_module._build_tool_call_recorder()

        get_pool.assert_not_called()
        with pytest.raises(RuntimeError):
            await recorder(**_recorder_kwargs(duration_ms=1))

    @pytest.mark.asyncio
    async def test_record_errors_propagate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A failed audit write reaches the agent (which aborts the run), never swallowed."""
        from admino.audit_events import AuditRecordError

        monkeypatch.setattr("admino.database.get_pool", MagicMock(return_value=MagicMock()))
        monkeypatch.setattr(
            "admino.audit_events.record_tool_call",
            AsyncMock(side_effect=AuditRecordError()),
            raising=False,
        )

        recorder = main_module._build_tool_call_recorder()
        with pytest.raises(AuditRecordError):
            await recorder(**_recorder_kwargs(decision="deny", success=False, duration_ms=0))


class TestNoAuditLogFile:
    """GH-147: main no longer opens an NDJSON audit log."""

    def test_main_source_has_no_audit_logger(self) -> None:
        source = _MAIN_MODULE_PATH.read_text()
        assert "AuditLogger" not in source
        assert "audit_log" not in source
        assert "admino.audit import" not in source
