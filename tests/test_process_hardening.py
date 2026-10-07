"""The server process is non-dumpable on Linux (GH-188, security-audit fix M-1).

Issue #188, Decision 15: "The server process is non-dumpable on Linux, so a
compromised conversion process (same user) can't read the server's environment
or memory through ``/proc``". Contract §12.7 pins:

- ``admino.process_hardening.make_non_dumpable() -> bool``: on Linux it calls
  ``prctl(PR_SET_DUMPABLE, 0)`` (``prctl(4, 0, 0, 0, 0)``) through
  ``ctypes.CDLL(None, use_errno=True)``, looked up at call time, and returns True
  when prctl returns 0; on any other platform it returns False without touching
  ctypes, and any failure (prctl returning non-zero, ``CDLL`` raising OSError, a
  missing ``prctl`` symbol) returns False instead of raising;
- ``admino.main.main()`` calls it once at startup, before uvicorn serves, and
  logs exactly one WARNING (from ``admino.main``, no errno text, no traceback)
  when it returns False on Linux; nothing when it succeeds or off Linux. The
  server still starts.
- The effect, on a real Linux kernel: a child started like the conversion
  runner (``python -P -s``, empty environment) can't read
  ``/proc/<parent pid>/environ`` once the parent made itself non-dumpable, while
  the same child of a parent that didn't can (the control proves the probe
  bites). Linux-only and not as root (root reads any environ): skipped
  elsewhere.

The unit and ``main()`` tests never call the real prctl: ``sys.platform`` (and
``platform.system``) are patched and ``ctypes.CDLL`` is replaced by a recorder,
so the pytest process itself is never made non-dumpable. ``main()`` runs with
every dependency mocked (as in tests/test_main.py).
"""

from __future__ import annotations

import ctypes
import errno
import json
import logging
import os
import platform
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import MagicMock

import pytest

import admino

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType

_PLATFORM_SYSTEMS: Final = {"linux": "Linux", "darwin": "Darwin", "win32": "Windows"}
_PR_SET_DUMPABLE_OFF: Final = (4, 0, 0, 0, 0)


def _hardening() -> ModuleType:
    """The module under test, imported lazily (it doesn't exist before GH-188's fix)."""
    import admino.process_hardening as module

    return module


# ---------------------------------------------------------------------------
# A recording stand-in for ctypes.CDLL
# ---------------------------------------------------------------------------


def _plain(value: object) -> object:
    """A ctypes scalar (c_int(4)) as its Python value; anything else unchanged."""
    return getattr(value, "value", value)


class _MissingSymbolLibc:
    """A loaded library without ``prctl`` (attribute lookup fails like ctypes')."""

    def __getattr__(self, name: str) -> Any:
        raise AttributeError(f"function {name!r} not found")


@dataclass
class _FakeCtypes:
    """Records every ``CDLL(...)`` and ``prctl(...)`` call.

    ``prctl_result`` is what prctl returns (after setting the ctypes errno to
    ``prctl_errno``), ``cdll_error`` an exception ``CDLL`` raises instead,
    ``missing_symbol`` a library without prctl. ``events`` is shared with the
    ``main()`` harness to order prctl against ``uvicorn.run``.
    """

    prctl_result: int = 0
    prctl_errno: int = 0
    cdll_error: BaseException | None = None
    missing_symbol: bool = False
    cdll_calls: list[tuple[tuple[object, ...], dict[str, object]]] = field(default_factory=list)
    prctl_calls: list[tuple[object, ...]] = field(default_factory=list)
    events: list[str] = field(default_factory=list)

    def cdll(self, *args: object, **kwargs: object) -> object:
        self.cdll_calls.append((args, kwargs))
        if self.cdll_error is not None:
            raise self.cdll_error
        if self.missing_symbol:
            return _MissingSymbolLibc()
        return _Libc(self)


class _Libc:
    def __init__(self, fake: _FakeCtypes) -> None:
        def prctl(*args: object) -> int:
            fake.prctl_calls.append(tuple(_plain(arg) for arg in args))
            fake.events.append("prctl" + repr(tuple(_plain(arg) for arg in args)))
            ctypes.set_errno(fake.prctl_errno)
            return fake.prctl_result

        # A plain function: the implementation may set argtypes/restype on it.
        self.prctl = prctl


def _install(monkeypatch: pytest.MonkeyPatch, fake: _FakeCtypes, platform_name: str) -> None:
    """Patch ``ctypes.CDLL`` (and a module-level ``CDLL`` binding, if any) with the
    recorder, then make the process look like ``platform_name``."""
    module = _hardening()
    monkeypatch.setattr(ctypes, "CDLL", fake.cdll)
    if hasattr(module, "CDLL"):
        monkeypatch.setattr(module, "CDLL", fake.cdll)
    monkeypatch.setattr(platform, "system", lambda: _PLATFORM_SYSTEMS[platform_name])
    monkeypatch.setattr(sys, "platform", platform_name)


# ---------------------------------------------------------------------------
# 1. make_non_dumpable()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("platform_name", ["darwin", "win32"])
def test_process_hardening_off_linux_returns_false_without_touching_ctypes(
    monkeypatch: pytest.MonkeyPatch, platform_name: str
) -> None:
    """Off Linux there is no prctl: the call returns False and never loads a library."""
    fake = _FakeCtypes()
    _install(monkeypatch, fake, platform_name)

    result = _hardening().make_non_dumpable()

    assert (result, fake.cdll_calls, fake.prctl_calls) == (False, [], [])
    assert result is False


def test_process_hardening_linux_sets_dumpable_off_and_returns_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On Linux: one library load, exactly ``prctl(4, 0, 0, 0, 0)`` (PR_SET_DUMPABLE
    = 4, value 0), and True when it returns 0."""
    fake = _FakeCtypes(prctl_result=0)
    _install(monkeypatch, fake, "linux")

    result = _hardening().make_non_dumpable()

    assert (result, len(fake.cdll_calls), fake.prctl_calls) == (True, 1, [_PR_SET_DUMPABLE_OFF])
    assert result is True


_FAILURES: Final[dict[str, dict[str, Any]]] = {
    "prctl_returns_minus_one": {"prctl_result": -1, "prctl_errno": errno.EPERM},
    "cdll_raises_oserror": {"cdll_error": OSError(errno.ENOENT, "no libc here")},
    "prctl_symbol_missing": {"missing_symbol": True},
}


@pytest.mark.parametrize("failure", list(_FAILURES))
def test_process_hardening_linux_failure_returns_false_without_raising(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    """A failing prctl, an unloadable library or a library without prctl: False, no
    exception (startup must go on)."""
    fake = _FakeCtypes(**_FAILURES[failure])
    _install(monkeypatch, fake, "linux")

    result = _hardening().make_non_dumpable()

    assert (result, len(fake.cdll_calls)) == (False, 1)
    assert result is False


# ---------------------------------------------------------------------------
# 2. main(): called once before uvicorn serves; one errno-free WARNING on failure
# ---------------------------------------------------------------------------


@dataclass
class _Startup:
    events: list[str]
    uvicorn_run: MagicMock


def _mock_config() -> MagicMock:
    config = MagicMock()
    config.log_level = "INFO"
    config.log_format = "text"
    config.llm.provider = "anthropic"
    config.llm.active_model_name = "claude-sonnet-4-6"
    config.limits.max_tool_calls_per_message = 10
    config.limits.max_context_messages = 20
    config.limits.confirmation_timeout_s = 300
    config.server.host = "127.0.0.1"
    config.server.port = 8000
    return config


@pytest.fixture()
def startup(monkeypatch: pytest.MonkeyPatch) -> Callable[[_FakeCtypes, str], _Startup]:
    """Run ``main()`` with every dependency mocked (no database, LLM, tools or
    server) and ``fake`` as the ctypes layer on ``platform_name``. Root logging
    stays pytest's (``_configure_logging`` is mocked) so caplog sees every record."""

    def run(fake: _FakeCtypes, platform_name: str) -> _Startup:
        import admino.main as main_module

        config = _mock_config()

        def fake_asyncio_run(coro: Any) -> Any:
            if hasattr(coro, "close"):
                coro.close()
            return config

        uvicorn_run = MagicMock(side_effect=lambda *a, **k: fake.events.append("uvicorn.run"))
        monkeypatch.setattr(main_module, "load_app_config", MagicMock(return_value=config))
        monkeypatch.setattr(main_module, "_configure_logging", MagicMock())
        monkeypatch.setattr(main_module, "_import_tool_modules", MagicMock())
        monkeypatch.setattr(main_module, "_warn_missing_provider_egress", MagicMock())
        monkeypatch.setattr(main_module, "asyncio", MagicMock(run=fake_asyncio_run))
        monkeypatch.setattr(main_module, "uvicorn", MagicMock(run=uvicorn_run))
        monkeypatch.setattr("admino.llm.create_llm_client", MagicMock())
        monkeypatch.setattr("admino.agent.Agent", MagicMock())
        monkeypatch.setattr("admino.server.create_app", MagicMock())
        monkeypatch.setattr("admino.tools.registry.freeze_registry", MagicMock())
        # Every module main() imports is loaded before the platform is faked.
        _install(monkeypatch, fake, platform_name)

        main_module.main()
        return _Startup(events=fake.events, uvicorn_run=uvicorn_run)

    return run


def _warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.levelno >= logging.WARNING]


def test_process_hardening_main_makes_the_server_non_dumpable_once_before_serving(
    startup: Callable[[_FakeCtypes, str], _Startup],
) -> None:
    """main() turns dumpability off exactly once, and before uvicorn.run."""
    fake = _FakeCtypes(prctl_result=0)

    result = startup(fake, "linux")

    assert result.events == ["prctl" + repr(_PR_SET_DUMPABLE_OFF), "uvicorn.run"]


@pytest.mark.parametrize("platform_name", ["linux", "darwin"])
def test_process_hardening_main_logs_no_warning_on_success_or_off_linux(
    startup: Callable[[_FakeCtypes, str], _Startup],
    caplog: pytest.LogCaptureFixture,
    platform_name: str,
) -> None:
    """A successful call on Linux, and the expected False off Linux (no library
    touched), log no warning; the server starts."""
    caplog.set_level(logging.INFO)
    fake = _FakeCtypes(prctl_result=0)

    result = startup(fake, platform_name)

    expected_prctl = [_PR_SET_DUMPABLE_OFF] if platform_name == "linux" else []
    assert (_warnings(caplog), fake.prctl_calls, result.uvicorn_run.call_count) == (
        [],
        expected_prctl,
        1,
    )


# Each failure with the errno/exception texts that must not reach the log.
_LOGGED_FAILURES: Final[dict[str, tuple[dict[str, Any], tuple[str, ...]]]] = {
    "prctl_eperm": (
        {"prctl_result": -1, "prctl_errno": errno.EPERM},
        (os.strerror(errno.EPERM), "EPERM"),
    ),
    "cdll_oserror": (
        {"cdll_error": OSError(errno.ENOENT, "cdll-marker-7c1f")},
        ("cdll-marker-7c1f", os.strerror(errno.ENOENT), "ENOENT"),
    ),
}


@pytest.mark.parametrize("failure", list(_LOGGED_FAILURES))
def test_process_hardening_main_warns_once_without_errno_text_when_it_fails_on_linux(
    startup: Callable[[_FakeCtypes, str], _Startup],
    caplog: pytest.LogCaptureFixture,
    failure: str,
) -> None:
    """On Linux a False result is logged as exactly one WARNING by admino.main, with no
    errno text and no traceback, and the server still starts."""
    caplog.set_level(logging.INFO)
    options, leaked = _LOGGED_FAILURES[failure]
    fake = _FakeCtypes(**options)

    result = startup(fake, "linux")

    warnings = _warnings(caplog)
    assert [(record.levelname, record.name) for record in warnings] == [("WARNING", "admino.main")]
    record = warnings[0]
    text = logging.Formatter("%(message)s").format(record)
    found = [marker for marker in (*leaked, "errno") if marker.lower() in text.lower()]
    assert (found, record.exc_info, record.exc_text, result.uvicorn_run.call_count) == (
        [],
        None,
        None,
        1,
    )


# ---------------------------------------------------------------------------
# 3. The effect on a real Linux kernel (subprocesses only)
# ---------------------------------------------------------------------------

# The conversion child's attack (security audit M-1): read the parent's original
# environment through /proc. Started like the runner's worker: python -P -s, env {}.
_CHILD: Final = """
import sys
try:
    with open(f"/proc/{sys.argv[1]}/environ", "rb") as handle:
        content = handle.read()
except PermissionError:
    print("denied")
else:
    print("read:" + str(sys.argv[2].encode() in content))
"""

# The server stand-in: optionally makes itself non-dumpable, then starts the child.
_PARENT: Final = """
import json, os, subprocess, sys
result = None
if sys.argv[1] == "hardened":
    from admino.process_hardening import make_non_dumpable
    result = make_non_dumpable()
child = subprocess.run(
    [sys.executable, "-P", "-s", "-c", sys.argv[2], str(os.getpid()), sys.argv[3]],
    env={},
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    timeout=60,
    check=False,
)
print(json.dumps({"result": result, "child": child.stdout.decode().strip()}))
"""

_SECRET_MARKER: Final = "gh188-m1-secret-4d2a"


def _run_parent(mode: str) -> dict[str, Any]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(Path(admino.__file__).resolve().parents[1]),
        "ADMINO_TEST_SERVER_SECRET": _SECRET_MARKER,
    }
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-P", "-s", "-c", _PARENT, mode, _CHILD, _SECRET_MARKER],
        env=env,
        capture_output=True,
        timeout=120,
        check=False,
    )
    lines = completed.stdout.decode().strip().splitlines()
    try:
        parsed: dict[str, Any] = json.loads(lines[-1])
    except (IndexError, ValueError):
        return {"returncode": completed.returncode, "stderr": completed.stderr.decode()[-500:]}
    return parsed


@pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() == 0,
    reason="PR_SET_DUMPABLE and /proc/<pid>/environ are Linux-only; root reads any environ",
)
def test_process_hardening_runner_like_child_cannot_read_the_server_environ_on_linux() -> None:
    """After make_non_dumpable() the parent's /proc environ is closed to a same-uid
    child (PermissionError); without the call the same child reads the secret."""
    outcomes = {mode: _run_parent(mode) for mode in ("hardened", "control")}

    assert outcomes == {
        "hardened": {"result": True, "child": "denied"},
        "control": {"result": None, "child": "read:True"},
    }
