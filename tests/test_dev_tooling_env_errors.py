"""``make ttft`` with a ``.env`` it can't use (GH-286, decision 6; #278 audit Info).

Spec, checked against ``tests/perf/ttft.py``:

- ``token_from_env_file(path)``: a MISSING file still gives None (and ``main()``
  still prints the "needs ``INFOMANIAK_API_TOKEN``" message and exits 2). A file
  that exists but can't be read (any other ``OSError``: no permission, a
  directory, an I/O error) or isn't valid UTF-8 (anywhere in the file, also
  after a valid token line) raises the module's ``SettingsError``. Its text is
  fixed (the same for every cause), one line, names ``.env`` and says the file
  can't be read or isn't valid UTF-8; it never holds the exception's text
  (``Errno``, ``Permission denied``, the codec's byte/position), the path, a
  value or any other content of the file.
- ``main()`` prints that error as ONE line on stderr, ``make ttft: <text>``,
  and returns 2: before logging is configured and before anything is measured,
  with stdout empty, no traceback and no token put into ``os.environ``. Run as
  ``python -m tests.perf.ttft`` (what ``make ttft`` runs) the process exits 2
  with that one stderr line and no traceback.
- With a non-blank ``INFOMANIAK_API_TOKEN`` in the environment, ``.env`` isn't
  read at all: a broken ``.env`` changes nothing (as today).

Security notes: every ``.env`` is a tmp file or directory with marker values;
the real ``.env`` is never read (``_ENV_FILE`` is monkeypatched in-process, and
the process check runs a copy of the module whose ``.env`` is a tmp path). The
measuring and the logging setup are stubbed in-process; the process check's
``.env`` holds no token, so it can never reach the network.
"""

from __future__ import annotations

import builtins
import errno
import io
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from tests.test_dev_tooling import _prepare_main, _run_main

if TYPE_CHECKING:
    from types import ModuleType

_TOKEN_KEY = "INFOMANIAK_API_TOKEN"
_TOKEN = "tok-w4e-file-5a1c0ffee0123456"
_ENV_TOKEN = "tok-w4e-env-6543210fedcba987"
_PG_SECRET = "pg-secret-w4e-7f3b9d"

# Text the error must never carry: the file's values, the OS and codec error text,
# exception class names, the bytes that broke the decoding (as hex, escaped or decoded).
_FILE_VALUES = (_TOKEN, _PG_SECRET)
_ERROR_TEXT = (
    "Traceback",
    "Errno",
    "Permission denied",
    "Is a directory",
    "Input/output error",
    "IsADirectoryError",
    "PermissionError",
    "UnicodeDecodeError",
    "OSError",
    "codec",
    "position",
    "invalid start byte",
    "0xff",
    "0xfe",
    "0x80",
    chr(92) + "x",
    chr(0xFFFD),
    chr(0xFF),
    chr(0xFE),
    chr(0x80),
)

_TEXT_LINES = (
    f"# admino .env (marker values)\nPG_APP_PASSWORD={_PG_SECRET}\n{_TOKEN_KEY}={_TOKEN}\n"
).encode()
# A valid token line, then a line that isn't UTF-8: a lenient decode would return the token.
_NON_UTF8_AFTER_TOKEN = (
    f"{_TOKEN_KEY}={_TOKEN}\nPG_APP_PASSWORD={_PG_SECRET}".encode() + bytes([0xFF, 0xFE]) + b"\n"
)
# A lone continuation byte inside the token's own line.
_NON_UTF8_IN_TOKEN = (
    f"PG_APP_PASSWORD={_PG_SECRET}\n{_TOKEN_KEY}={_TOKEN}".encode() + bytes([0x80]) + b"tail\n"
)
# The process check's file: not UTF-8 and no token line, so no fallback can reach the network.
_NON_UTF8_WITHOUT_TOKEN = f"PG_APP_PASSWORD={_PG_SECRET}".encode() + bytes([0xFF, 0xFE]) + b"\n"

_NOT_ROOT = pytest.mark.skipif(
    os.geteuid() == 0,
    reason="root reads a mode-000 file; the io-error case covers the same OSError branch",
)
_CASES = [
    pytest.param("directory", id="directory"),
    pytest.param("no-permission", id="no-permission", marks=_NOT_ROOT),
    pytest.param("io-error", id="io-error"),
    pytest.param("non-utf8-after-token", id="non-utf8-after-token"),
    pytest.param("non-utf8-in-token", id="non-utf8-in-token"),
]
# Deterministic for every user (root included): the fixed-text comparison runs them all.
_PORTABLE_CASES = ("directory", "io-error", "non-utf8-after-token", "non-utf8-in-token")


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def ttft() -> ModuleType:
    """``tests/perf/ttft.py``, imported lazily (the new behaviour is looked up per test)."""
    from tests.perf import ttft as module

    return module


def _fail_reads_of(monkeypatch: pytest.MonkeyPatch, path: Path, error: OSError) -> None:
    """Every ``open`` of ``path`` raises ``error`` (``Path.read_text``/``read_bytes`` too)."""
    real_open = io.open
    target = os.fspath(path)

    def guarded_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(file, str | os.PathLike) and os.fspath(file) == target:
            raise error
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(io, "open", guarded_open)
    monkeypatch.setattr(builtins, "open", guarded_open)


def _broken_env(case: str, root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """``root / ".env"`` in the state ``case`` names; the file holds the marker values."""
    path = root / ".env"
    if case == "directory":
        path.mkdir()
    elif case == "no-permission":
        path.write_bytes(_TEXT_LINES)
        path.chmod(0)
        assert not os.access(path, os.R_OK), "precondition: the mode-000 file is unreadable"
    elif case == "io-error":
        path.write_bytes(_TEXT_LINES)
        # errno EIO maps to no OSError subclass: "any other OSError" of decision 6.
        _fail_reads_of(
            monkeypatch, path, OSError(errno.EIO, os.strerror(errno.EIO), os.fspath(path))
        )
    elif case == "non-utf8-after-token":
        path.write_bytes(_NON_UTF8_AFTER_TOKEN)
    elif case == "non-utf8-in-token":
        path.write_bytes(_NON_UTF8_IN_TOKEN)
    else:  # pragma: no cover - a typo in a case name
        raise AssertionError(case)
    return path


def _call(ttft: ModuleType, path: Path) -> object:
    """``token_from_env_file(path)``'s result, or the exception it raised."""
    try:
        result: object = ttft.token_from_env_file(path)
    except Exception as exc:  # the test inspects whatever escaped
        return exc
    return result


def _outcome(ttft: ModuleType) -> int | str:
    """``main()``'s exit status; an escaping exception (a traceback in ``make ttft``) by name."""
    try:
        return _run_main(ttft)
    except Exception as exc:  # what make ttft would print as a traceback
        return f"raised {type(exc).__name__}"


def _leaks(text: str, env_file: Path) -> list[str]:
    """The probes found in ``text``: values, error text, the path of ``env_file``."""
    probes = (*_FILE_VALUES, *_ERROR_TEXT, os.fspath(env_file.parent))
    return [probe for probe in probes if probe in text]


def _error_text(outcome: object, settings_error: type[Exception]) -> str | None:
    return str(outcome) if isinstance(outcome, settings_error) else None


# ---------------------------------------------------------------------------
# token_from_env_file
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", _CASES)
def test_ttft_env_errors_token_from_env_file_raises_settings_error_without_detail(
    ttft: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """An unreadable or non-UTF-8 ``.env``: the module's ``SettingsError``, no detail in it."""
    env_file = _broken_env(case, tmp_path, monkeypatch)

    outcome = _call(ttft, env_file)

    detail = str(outcome) + repr(getattr(outcome, "args", ()))
    assert (isinstance(outcome, ttft.SettingsError), _leaks(detail, env_file)) == (True, []), type(
        outcome
    ).__name__


def test_ttft_env_errors_token_from_env_file_uses_one_fixed_text_naming_env(
    ttft: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same one-line text for every cause; it names ``.env``, reading and UTF-8."""
    texts: dict[str, str | None] = {}
    for case in _PORTABLE_CASES:
        root = tmp_path / case
        root.mkdir()
        texts[case] = _error_text(
            _call(ttft, _broken_env(case, root, monkeypatch)), ttft.SettingsError
        )
    distinct = set(texts.values())
    text = next(iter(distinct)) or ""

    assert (
        len(distinct),
        None in distinct,
        "\n" in text or "\r" in text,
        ".env" in text,
        "read" in text,
        "UTF-8" in text,
    ) == (1, False, False, True, True, True), texts


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", _CASES)
def test_ttft_env_errors_main_prints_one_line_and_exits_2_before_logging_and_measuring(
    ttft: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    case: str,
) -> None:
    """``make ttft: <text>`` alone on stderr, exit 2, stdout empty, nothing measured or set."""
    env_file = _broken_env(case, tmp_path, monkeypatch)
    measure = _prepare_main(ttft, monkeypatch, env_file, None)
    configured: list[bool] = []
    monkeypatch.setattr(ttft, "_configure_logging", lambda: configured.append(True))
    caplog.set_level(logging.DEBUG)
    text = _error_text(_call(ttft, env_file), ttft.SettingsError)
    before = dict(os.environ)

    status = _outcome(ttft)

    captured = capsys.readouterr()
    assert (
        status,
        captured.out,
        captured.err,
        measure.environs,
        configured,
        dict(os.environ) == before,
    ) == (2, "", f"make ttft: {text}\n", [], [], True)
    assert _leaks(captured.out + captured.err + caplog.text, env_file) == []


@pytest.mark.parametrize("case", _CASES)
def test_ttft_env_errors_main_with_an_environment_token_never_reads_env(
    ttft: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: str,
) -> None:
    """A non-blank environment token: the broken ``.env`` isn't read; without it, it's refused."""
    env_file = _broken_env(case, tmp_path, monkeypatch)
    measure = _prepare_main(ttft, monkeypatch, env_file, _ENV_TOKEN)
    before = dict(os.environ)

    with_token = _outcome(ttft)
    err_with_token = capsys.readouterr().err
    # Control: the same .env without the environment token is the one-line refusal.
    _prepare_main(ttft, monkeypatch, env_file, None)
    without_token = _outcome(ttft)
    err_without_token = capsys.readouterr().err

    assert (
        with_token,
        measure.environs == [before],
        err_with_token,
        without_token,
        err_without_token.startswith("make ttft: "),
    ) == (0, True, "", 2, True)


def test_ttft_env_errors_main_missing_env_keeps_the_needs_token_message(
    ttft: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A missing ``.env`` still asks for the token; an unreadable one gets the new error."""
    missing = tmp_path / "missing" / ".env"
    missing.parent.mkdir()
    _prepare_main(ttft, monkeypatch, missing, None)
    missing_status = _outcome(ttft)
    missing_err = capsys.readouterr().err
    unreadable_root = tmp_path / "unreadable"
    unreadable_root.mkdir()
    _prepare_main(ttft, monkeypatch, _broken_env("directory", unreadable_root, monkeypatch), None)
    unreadable_status = _outcome(ttft)
    unreadable_err = capsys.readouterr().err

    assert (
        missing_status,
        missing_err.startswith(f"make ttft needs {_TOKEN_KEY}"),
        missing_err.count("\n"),
        unreadable_status,
        unreadable_err.startswith("make ttft: "),
        f"needs {_TOKEN_KEY}" in unreadable_err,
    ) == (2, True, 1, 2, True, False)


@pytest.mark.parametrize(
    "case", [pytest.param("directory", id="directory"), pytest.param("non-utf8", id="non-utf8")]
)
def test_ttft_env_errors_make_ttft_process_exits_2_with_one_line_and_no_traceback(
    ttft: ModuleType, tmp_path: Path, case: str
) -> None:
    """``python -m tests.perf.ttft`` (``make ttft``) on a copy whose ``.env`` is broken."""
    import admino

    module_file = ttft.__file__
    assert module_file is not None
    tool = tmp_path / "tool"
    (tool / "tests" / "perf").mkdir(parents=True)
    (tool / "tests" / "__init__.py").write_text("", encoding="utf-8")
    (tool / "tests" / "perf" / "__init__.py").write_text("", encoding="utf-8")
    (tool / "tests" / "perf" / "ttft.py").write_bytes(Path(module_file).read_bytes())
    env_file = tool / ".env"
    if case == "directory":
        env_file.mkdir()
    else:
        env_file.write_bytes(_NON_UTF8_WITHOUT_TOKEN)
    src = Path(admino.__file__).resolve().parents[1]
    # A fresh environment: no INFOMANIAK_API_TOKEN of the developer's shell, no TTFT_RUNS.
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "PYTHONPATH": os.pathsep.join([str(tool), str(src)]),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
    }

    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "tests.perf.ttft"],
        cwd=tool,
        env=env,
        capture_output=True,
        timeout=60,
        check=False,
    )

    out = completed.stdout.decode("utf-8", "replace")
    err = completed.stderr.decode("utf-8", "replace")
    assert (
        completed.returncode,
        out,
        err.count("\n"),
        err.startswith("make ttft: "),
        ".env" in err,
        _leaks(err, env_file),
    ) == (2, "", 1, True, True, []), err[-2000:]
