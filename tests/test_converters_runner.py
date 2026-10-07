"""Running one conversion in a separate worker process (GH-188, contract §5.2, Decision 2).

``admino.converters.runner.run_conversion(path, kind, out_dir, options) ->
ConversionResult`` runs on the server side, in a worker thread of the processing pool.
Pinned here:

- ``CONVERSION_TIMEOUT_S == 120.0`` and ``WORKER_ARGV == (sys.executable, "-P", "-s",
  "-m", "admino.converters.worker")``, both read at call time; ``ConversionResult
  (page_count, token_estimate)`` is a frozen dataclass.
- ``out_dir`` is reset before the child starts: a stale directory is removed as a tree (a
  symlink inside it is never followed), a symlink at ``out_dir`` (to a directory, to a
  file, dangling) is unlinked without touching its target, a file is replaced; the new
  directory is empty with mode 0700.
- The child: ``subprocess.run(list(WORKER_ARGV), input=<job JSON bytes>, stdout=PIPE,
  stderr=DEVNULL, env=..., timeout=CONVERSION_TIMEOUT_S, check=False)``, never
  ``shell=True``. The job ``{path, kind, out_dir, filename, render_dpi, max_pages}``
  travels on stdin, none of it in argv. ``env`` is exactly ``{"PYTHONPATH": <the
  server's>}``, or ``{}`` when the server has none: no API token, password or DSN.
- Outcomes: ``ok: true`` -> ``ConversionResult``, out_dir kept; ``ok: false`` with one of
  the nine codes (``output_too_large`` included, contract §12) -> ``ConversionError`` with
  that code; a timeout -> ``conversion_timeout`` (a real sleeping child is killed and
  reaped, and the call returns long before its sleep ends); a non-zero exit status (even
  with a valid line), stdout that isn't exactly one valid result line, an unknown reason,
  a negative estimate or a page count / estimate above 2**31 - 1 (INTEGER; 2**31 - 1
  itself passes) -> ``processing_error``. out_dir is removed after every failure, and
  nothing is logged.
- Derived bytes (contract §12.4, process M-3): ``ConversionResult(page_count,
  token_estimate, derived_bytes)``; after a successful child the PARENT measures
  ``derived_bytes`` = the sum of the sizes of the regular files directly in out_dir (a
  real child that writes files of known sizes and reports its own numbers: the sizes on
  disk win). A symlink (its outside target is neither followed nor touched), a
  subdirectory or a FIFO in out_dir -> ``processing_error``; more than
  ``common.MAX_DERIVED_BYTES`` (read at call time) -> ``output_too_large``, exactly the
  cap passes; out_dir removed on both failures. A child that replaces out_dir itself
  with a symlink (to another org's directory) or a plain file, then reports success ->
  ``processing_error``; the entry is unlinked without following it (the other org's
  files are neither measured nor touched).
- Real runs with the default argv (PYTHONPATH of the tree under test): a txt and a two-page
  text PDF convert end to end, out_dir keeps the manifest and the parts, and
  ``derived_bytes`` is their size on disk.

``subprocess.run`` is replaced by a recorder for everything but the real runs. New modules
are imported inside the tests, so the file collects before GH-188 exists.
"""

from __future__ import annotations

import dataclasses
import importlib
import json
import logging
import os
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

import admino

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType

# The tree under test, for the real child runs.
_SRC: Final = str(Path(admino.__file__).resolve().parents[1])

_REASONS: Final = (
    "corrupted_file",
    "password_protected",
    "too_many_pages",
    "archive_too_large",
    "image_too_large",
    "text_too_large",
    "output_too_large",
    "conversion_timeout",
    "processing_error",
)

# The largest PostgreSQL INTEGER (page_count, token_estimate).
_INT32_MAX: Final = 2_147_483_647

_ATTACHMENT_ID: Final = "3c9a2f4e-8b71-4d0a-9e65-1f2b3c4d5e6f"
_FILENAME: Final = "Lohnabrechnung März — vertraulich.pdf"
_OK_LINE: Final = b'{"ok": true, "page_count": 2, "token_estimate": 40}\n'

_SLEEPER: Final = (
    "import os, sys, time\n"
    "with open(sys.argv[1], 'w') as handle:\n"
    "    handle.write(str(os.getpid()))\n"
    "time.sleep(120)\n"
)


def _runner() -> ModuleType:
    return importlib.import_module("admino.converters.runner")


def _common() -> ModuleType:
    return importlib.import_module("admino.converters.common")


def _options(filename: str = _FILENAME) -> Any:
    return _common().ConversionOptions(filename=filename, render_dpi=150, max_pages=100)


@dataclass
class _Call:
    """One recorded subprocess.run call, with out_dir as the child would have found it."""

    argv: list[str]
    kwargs: dict[str, Any]
    out_dir_is_dir: bool
    out_dir_is_symlink: bool
    out_dir_mode: int | None
    out_dir_entries: list[str]


@dataclass
class _FakeRun:
    """A subprocess.run stand-in returning a canned CompletedProcess (or raising).

    ``child`` (if given) runs after the call is recorded, with out_dir: what the child
    would have written there before it exited.
    """

    out_dir: Path
    returncode: int = 0
    stdout: bytes = _OK_LINE
    raises: BaseException | None = None
    child: Callable[[Path], None] | None = None
    calls: list[_Call] = field(default_factory=list)

    def __call__(self, *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        argv = args[0] if args else kwargs.pop("args")
        is_dir = self.out_dir.is_dir() and not self.out_dir.is_symlink()
        self.calls.append(
            _Call(
                argv=argv,
                kwargs=kwargs,
                out_dir_is_dir=is_dir,
                out_dir_is_symlink=self.out_dir.is_symlink(),
                out_dir_mode=stat.S_IMODE(os.lstat(self.out_dir).st_mode) if is_dir else None,
                out_dir_entries=sorted(os.listdir(self.out_dir)) if is_dir else [],
            )
        )
        if self.child is not None:
            self.child(self.out_dir)
        if self.raises is not None:
            raise self.raises
        return subprocess.CompletedProcess(argv, self.returncode, stdout=self.stdout)


def _writes(sizes: dict[str, int]) -> Callable[[Path], None]:
    """A child that writes one regular file of each given size into out_dir."""

    def child(out_dir: Path) -> None:
        for name, size in sizes.items():
            (out_dir / name).write_bytes(b"x" * size)

    return child


def _disk_bytes(directory: Path) -> int:
    """The sizes of the regular files directly in ``directory``, measured here."""
    return sum(entry.stat().st_size for entry in directory.iterdir() if entry.is_file())


def _patch_run(monkeypatch: pytest.MonkeyPatch, fake: _FakeRun) -> _FakeRun:
    """Replace subprocess.run (and any reference the runner holds to it)."""
    runner = _runner()
    original = subprocess.run
    monkeypatch.setattr(subprocess, "run", fake)
    for name, value in list(vars(runner).items()):
        if value is original:
            monkeypatch.setattr(runner, name, fake)
    return fake


@pytest.fixture
def stored(tmp_path: Path) -> Path:
    """A stored original under <root>/<org_id>/<id>."""
    path = tmp_path / "attachments" / "5b8e1c2d-7f3a-4e9b-8c6d-2a1b0f9e8d7c" / _ATTACHMENT_ID
    path.parent.mkdir(parents=True)
    path.write_bytes(b"%PDF-1.7 stored bytes")
    return path


@pytest.fixture
def out_dir(stored: Path) -> Path:
    """The derived directory <id>.d (not created: the runner creates it)."""
    return stored.with_name(stored.name + ".d")


def _reason(excinfo: pytest.ExceptionInfo[BaseException]) -> object:
    return getattr(excinfo.value, "reason", None)


# ---------------------------------------------------------------------------
# Constants and the result type
# ---------------------------------------------------------------------------


def test_converters_runner_constants_pinned() -> None:
    """CONVERSION_TIMEOUT_S is 120.0 s; WORKER_ARGV runs the worker module with -P -s."""
    runner = _runner()

    assert (type(runner.CONVERSION_TIMEOUT_S), runner.CONVERSION_TIMEOUT_S) == (float, 120.0)
    assert (sys.executable, "-P", "-s", "-m", "admino.converters.worker") == runner.WORKER_ARGV
    assert type(runner.WORKER_ARGV) is tuple


def test_converters_runner_conversion_result_is_a_frozen_dataclass() -> None:
    """ConversionResult(page_count, token_estimate, derived_bytes), frozen."""
    runner = _runner()
    result = runner.ConversionResult(page_count=None, token_estimate=7, derived_bytes=0)

    assert [item.name for item in dataclasses.fields(result)] == [
        "page_count",
        "token_estimate",
        "derived_bytes",
    ]
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.token_estimate = 8  # type: ignore[misc]


# ---------------------------------------------------------------------------
# The child's command line, stdin and environment
# ---------------------------------------------------------------------------


def test_converters_runner_child_gets_worker_argv_and_the_job_on_stdin(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path
) -> None:
    """argv is list(WORKER_ARGV), nothing of the job in it; the job is JSON bytes on
    stdin with the path, kind, out_dir, file name, render_dpi and max_pages."""
    runner = _runner()
    fake = _patch_run(monkeypatch, _FakeRun(out_dir))
    options = _common().ConversionOptions(filename=_FILENAME, render_dpi=220, max_pages=37)

    runner.run_conversion(stored, "pdf", out_dir, options)

    [call] = fake.calls
    assert call.argv == list(runner.WORKER_ARGV)
    assert not any(_ATTACHMENT_ID in part or "März" in part for part in call.argv)
    assert isinstance(call.kwargs["input"], bytes)
    assert json.loads(call.kwargs["input"]) == {
        "path": str(stored),
        "kind": "pdf",
        "out_dir": str(out_dir),
        "filename": _FILENAME,
        "render_dpi": 220,
        "max_pages": 37,
    }


def test_converters_runner_call_options_pinned_and_read_at_call_time(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path
) -> None:
    """stdout=PIPE, stderr=DEVNULL, check=False, no shell; WORKER_ARGV and
    CONVERSION_TIMEOUT_S are read when the call runs."""
    runner = _runner()
    fake = _patch_run(monkeypatch, _FakeRun(out_dir))
    monkeypatch.setattr(runner, "WORKER_ARGV", ("/opt/python3", "-P", "-m", "worker_stub"))
    monkeypatch.setattr(runner, "CONVERSION_TIMEOUT_S", 7.5)

    runner.run_conversion(stored, "txt", out_dir, _options())

    [call] = fake.calls
    assert call.argv == ["/opt/python3", "-P", "-m", "worker_stub"]
    assert call.kwargs["timeout"] == 7.5
    assert call.kwargs["stdout"] == subprocess.PIPE
    assert call.kwargs["stderr"] == subprocess.DEVNULL
    assert call.kwargs.get("check", False) is False
    assert call.kwargs.get("shell", False) is False


@pytest.mark.parametrize("pythonpath", ["/opt/admino/src", None])
def test_converters_runner_child_env_holds_only_pythonpath(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path, pythonpath: str | None
) -> None:
    """env is exactly {"PYTHONPATH": <server's>} or {}: the server's API token, database
    password and DSN never reach the worker."""
    runner = _runner()
    fake = _patch_run(monkeypatch, _FakeRun(out_dir))
    monkeypatch.setenv("INFOMANIAK_API_TOKEN", "ik-token-gh188-runner")
    monkeypatch.setenv("PG_APP_PASSWORD", "pg-password-gh188-runner")
    monkeypatch.setenv("DATABASE_URL", "postgresql://admino_app:pw-gh188@db:5432/admino")
    if pythonpath is None:
        monkeypatch.delenv("PYTHONPATH", raising=False)
    else:
        monkeypatch.setenv("PYTHONPATH", pythonpath)

    runner.run_conversion(stored, "txt", out_dir, _options())

    [call] = fake.calls
    assert call.kwargs["env"] == ({} if pythonpath is None else {"PYTHONPATH": pythonpath})


# ---------------------------------------------------------------------------
# Resetting out_dir
# ---------------------------------------------------------------------------


def _plant(case: str, out_dir: Path, outside: Path) -> dict[Path, bytes]:
    """Put a leftover at out_dir; returns the files outside it that must survive."""
    outside.mkdir()
    victim = outside / "victim.txt"
    victim.write_bytes(b"outside the derived dir")
    if case == "stale-directory":
        out_dir.mkdir()
        (out_dir / "part-0009.txt").write_bytes(b"stale")
        (out_dir / "manifest.json").write_bytes(b"{}")
        (out_dir / "nested").mkdir()
        (out_dir / "nested" / "old.jpg").write_bytes(b"stale")
        (out_dir / "escape").symlink_to(outside, target_is_directory=True)
    elif case == "symlink-to-directory":
        out_dir.symlink_to(outside, target_is_directory=True)
    elif case == "symlink-to-file":
        out_dir.symlink_to(victim)
    elif case == "dangling-symlink":
        out_dir.symlink_to(outside / "absent")
    elif case == "file":
        out_dir.write_bytes(b"a file where the directory goes")
    return {victim: victim.read_bytes()}


@pytest.mark.parametrize(
    "case",
    [
        "absent",
        "stale-directory",
        "symlink-to-directory",
        "symlink-to-file",
        "dangling-symlink",
        "file",
    ],
)
def test_converters_runner_out_dir_reset_to_an_empty_0700_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stored: Path, out_dir: Path, case: str
) -> None:
    """Before the child starts, out_dir is a real, empty directory with mode 0700; a
    planted symlink (at out_dir or inside a stale tree) is never followed: the files
    outside survive."""
    outside = tmp_path / "outside"
    survivors = _plant(case, out_dir, outside)
    fake = _patch_run(monkeypatch, _FakeRun(out_dir))

    _runner().run_conversion(stored, "pdf", out_dir, _options())

    [call] = fake.calls
    assert (call.out_dir_is_dir, call.out_dir_is_symlink) == (True, False)
    assert (call.out_dir_mode, call.out_dir_entries) == (0o700, [])
    assert {path: path.read_bytes() for path in survivors} == survivors
    assert sorted(os.listdir(outside)) == ["victim.txt"]


# ---------------------------------------------------------------------------
# Outcomes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        (_OK_LINE, (2, 40)),
        (b'{"ok": true, "page_count": null, "token_estimate": 0}\n', (None, 0)),
        (
            b'{"ok": true, "page_count": 2147483647, "token_estimate": 2147483647}\n',
            (_INT32_MAX, _INT32_MAX),
        ),
    ],
    ids=["with-pages", "without-pages", "int32-maximum"],
)
def test_converters_runner_ok_line_returns_the_result_and_keeps_out_dir(
    monkeypatch: pytest.MonkeyPatch,
    stored: Path,
    out_dir: Path,
    stdout: bytes,
    expected: tuple[int | None, int],
) -> None:
    """ok true -> ConversionResult(page_count, token_estimate, derived_bytes); out_dir
    stays (empty here: derived_bytes 0). 2**31 - 1 is still a valid count."""
    runner = _runner()
    _patch_run(monkeypatch, _FakeRun(out_dir, stdout=stdout))

    result = runner.run_conversion(stored, "pdf", out_dir, _options())

    assert type(result) is runner.ConversionResult
    assert (result.page_count, result.token_estimate, result.derived_bytes) == (*expected, 0)
    assert out_dir.is_dir()


@pytest.mark.parametrize("reason", _REASONS)
def test_converters_runner_known_reason_raises_that_conversion_error(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path, reason: str
) -> None:
    """ok false with one of the nine codes -> ConversionError(code); out_dir removed."""
    line = json.dumps({"ok": False, "reason": reason}).encode() + b"\n"
    _patch_run(monkeypatch, _FakeRun(out_dir, stdout=line))

    with pytest.raises(_common().ConversionError) as excinfo:
        _runner().run_conversion(stored, "pdf", out_dir, _options())

    assert _reason(excinfo) == reason
    assert not os.path.lexists(out_dir)


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [
        (1, b""),
        (1, _OK_LINE),
        (-9, b""),
        (137, b""),
        (0, b""),
        (0, b"Traceback (most recent call last):\n"),
        (0, _OK_LINE + _OK_LINE),
        (0, b'{"ok": true, "page_count": 1, "token_estimate": 3, "path": "/srv/a"}\n'),
        (0, b'{"ok": true, "page_count": 1}\n'),
        (0, b'{"ok": false, "reason": "disk_on_fire"}\n'),
        (0, b'{"ok": true, "page_count": 1, "token_estimate": -1}\n'),
        (0, b'{"ok": true, "page_count": 2147483648, "token_estimate": 3}\n'),
        (0, b'{"ok": true, "page_count": null, "token_estimate": 2147483648}\n'),
    ],
    ids=[
        "exit-1",
        "exit-1-after-an-ok-line",
        "killed-by-signal",
        "exit-137",
        "empty-stdout",
        "garbage",
        "two-lines",
        "extra-key",
        "missing-key",
        "unknown-reason",
        "negative-estimate",
        "page-count-over-int32",
        "estimate-over-int32",
    ],
)
def test_converters_runner_bad_exit_or_output_is_processing_error(
    monkeypatch: pytest.MonkeyPatch,
    stored: Path,
    out_dir: Path,
    returncode: int,
    stdout: bytes,
) -> None:
    """A non-zero exit, or stdout that isn't exactly one valid result line (a count above
    PostgreSQL's INTEGER included) -> ConversionError("processing_error"); out_dir
    removed."""
    _patch_run(monkeypatch, _FakeRun(out_dir, returncode=returncode, stdout=stdout))

    with pytest.raises(_common().ConversionError) as excinfo:
        _runner().run_conversion(stored, "pdf", out_dir, _options())

    assert _reason(excinfo) == "processing_error"
    assert not os.path.lexists(out_dir)


def test_converters_runner_timeout_expired_is_conversion_timeout(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path
) -> None:
    """subprocess.TimeoutExpired -> ConversionError("conversion_timeout"); out_dir removed."""
    runner = _runner()
    expired = subprocess.TimeoutExpired(list(runner.WORKER_ARGV), 120.0)
    _patch_run(monkeypatch, _FakeRun(out_dir, raises=expired))

    with pytest.raises(_common().ConversionError) as excinfo:
        runner.run_conversion(stored, "pdf", out_dir, _options())

    assert _reason(excinfo) == "conversion_timeout"
    assert not os.path.lexists(out_dir)


def test_converters_runner_real_timeout_kills_and_reaps_the_child(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stored: Path, out_dir: Path
) -> None:
    """A real child that sleeps past the timeout: conversion_timeout long before its sleep
    ends, and its process is gone (killed and reaped, no zombie)."""
    runner = _runner()
    pid_file = tmp_path / "sleeper.pid"
    monkeypatch.setattr(runner, "WORKER_ARGV", (sys.executable, "-c", _SLEEPER, str(pid_file)))
    monkeypatch.setattr(runner, "CONVERSION_TIMEOUT_S", 2.0)
    started = time.monotonic()

    with pytest.raises(_common().ConversionError) as excinfo:
        runner.run_conversion(stored, "pdf", out_dir, _options())

    elapsed = time.monotonic() - started
    assert _reason(excinfo) == "conversion_timeout"
    assert elapsed < 60
    pid = int(pid_file.read_text(encoding="ascii"))
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    assert not os.path.lexists(out_dir)


def test_converters_runner_failures_log_nothing(
    monkeypatch: pytest.MonkeyPatch,
    stored: Path,
    out_dir: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A timeout, a crash and a known failure: the runner logs nothing at all."""
    runner = _runner()
    common = _common()
    outcomes = [
        _FakeRun(out_dir, raises=subprocess.TimeoutExpired(["worker"], 1.0)),
        _FakeRun(out_dir, returncode=1, stdout=b"Traceback: /srv/x/Lohn.pdf\n"),
        _FakeRun(out_dir, stdout=b'{"ok": false, "reason": "password_protected"}\n'),
    ]
    caplog.set_level(logging.DEBUG)

    for fake in outcomes:
        _patch_run(monkeypatch, fake)
        with pytest.raises(common.ConversionError):
            runner.run_conversion(stored, "pdf", out_dir, _options())

    assert [record.name for record in caplog.records if record.name.startswith("admino")] == []


# ---------------------------------------------------------------------------
# Derived bytes: measured by the parent, capped (contract §12.4, process M-3)
# ---------------------------------------------------------------------------

# A worker stand-in that writes three files of known sizes into the job's out_dir (its
# manifest claims a tiny size) and reports its own numbers: 1 page, 7 tokens.
_SIZED_CHILD: Final = (
    "import json, pathlib, sys\n"
    "job = json.loads(sys.stdin.buffer.read())\n"
    "out = pathlib.Path(job['out_dir'])\n"
    "(out / 'part-0001.txt').write_bytes(b't' * 1500)\n"
    "(out / 'part-0002.jpg').write_bytes(b'j' * 70000)\n"
    "(out / 'manifest.json').write_bytes(b'{\"derived_bytes\": 1}'.ljust(100))\n"
    "sys.stdout.write(json.dumps({'ok': True, 'page_count': 1, 'token_estimate': 7}) + '\\n')\n"
)


def _outcome(run: Callable[[], Any]) -> tuple[str, object]:
    """("result", derived_bytes) or ("error", the ConversionError's reason)."""
    try:
        result = run()
    except _common().ConversionError as exc:
        return ("error", exc.reason)
    return ("result", result.derived_bytes)


def test_converters_runner_derived_bytes_are_the_sizes_on_disk_not_the_childs_claim(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path
) -> None:
    """A real child writes 1500 + 70000 + 100 bytes (its manifest claims 1): the parent
    measures out_dir itself, so derived_bytes is 71600; the child's page count and
    estimate pass through and out_dir keeps the files."""
    runner = _runner()
    monkeypatch.setattr(runner, "WORKER_ARGV", (sys.executable, "-c", _SIZED_CHILD))

    result = runner.run_conversion(stored, "pdf", out_dir, _options())

    assert result == runner.ConversionResult(page_count=1, token_estimate=7, derived_bytes=71600)
    assert (type(result.derived_bytes), _disk_bytes(out_dir)) == (int, 71600)


def _plant_odd_entry(case: str, out_dir: Path, outside: Path) -> None:
    """Something that isn't a regular file, next to a regular part."""
    (out_dir / "part-0001.txt").write_bytes(b"page one")
    if case == "symlink-to-a-large-file":
        (out_dir / "part-0002.jpg").symlink_to(outside / "large.bin")
    elif case == "subdirectory":
        (out_dir / "nested").mkdir()
        (out_dir / "nested" / "part-0009.txt").write_bytes(b"hidden part")
    elif case == "fifo":
        os.mkfifo(out_dir / "part-0002.txt")


@pytest.mark.parametrize("case", ["symlink-to-a-large-file", "subdirectory", "fifo"])
def test_converters_runner_non_regular_entry_in_out_dir_is_processing_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stored: Path, out_dir: Path, case: str
) -> None:
    """After an ok line, a symlink, a subdirectory or a FIFO in out_dir ->
    processing_error, out_dir removed; the symlink's outside target is never followed
    (it would add 1 MiB) and survives untouched."""
    outside = tmp_path / "outside"
    outside.mkdir()
    large = outside / "large.bin"
    large.write_bytes(b"L" * (1024 * 1024))
    _patch_run(
        monkeypatch,
        _FakeRun(out_dir, child=lambda directory: _plant_odd_entry(case, directory, outside)),
    )

    outcome = _outcome(lambda: _runner().run_conversion(stored, "pdf", out_dir, _options()))

    assert (outcome, os.path.lexists(out_dir)) == (("error", "processing_error"), False)
    assert (sorted(os.listdir(outside)), large.stat().st_size) == (["large.bin"], 1024 * 1024)


@pytest.mark.parametrize(
    ("manifest_size", "expected", "kept"),
    [
        (400, ("result", 1000), True),
        (401, ("error", "output_too_large"), False),
    ],
    ids=["exactly-the-cap", "one-byte-over"],
)
def test_converters_runner_derived_bytes_held_against_the_cap(
    monkeypatch: pytest.MonkeyPatch,
    stored: Path,
    out_dir: Path,
    manifest_size: int,
    expected: tuple[str, object],
    kept: bool,
) -> None:
    """common.MAX_DERIVED_BYTES (read at call time, 1000 here): 600 + 400 bytes pass with
    derived_bytes 1000; 600 + 401 -> output_too_large and out_dir removed."""
    monkeypatch.setattr(_common(), "MAX_DERIVED_BYTES", 1000)
    sizes = {"part-0001.txt": 600, "manifest.json": manifest_size}
    _patch_run(monkeypatch, _FakeRun(out_dir, child=_writes(sizes)))

    outcome = _outcome(lambda: _runner().run_conversion(stored, "pdf", out_dir, _options()))

    assert (outcome, os.path.lexists(out_dir)) == (expected, kept)


# A worker stand-in that "converts" (one part in out_dir), then replaces out_dir ITSELF:
# with a symlink to the directory named in argv[2] ("symlink") or with a plain file
# ("file"), and reports success with a valid ok line.
_SWAPPING_CHILD: Final = (
    "import json, os, pathlib, shutil, sys\n"
    "job = json.loads(sys.stdin.buffer.read())\n"
    "out = pathlib.Path(job['out_dir'])\n"
    "(out / 'part-0001.txt').write_bytes(b'converted')\n"
    "shutil.rmtree(out)\n"
    "if sys.argv[1] == 'symlink':\n"
    "    os.symlink(sys.argv[2], out, target_is_directory=True)\n"
    "else:\n"
    "    out.write_bytes(b'f' * 4096)\n"
    "sys.stdout.write(json.dumps({'ok': True, 'page_count': 1, 'token_estimate': 7}) + '\\n')\n"
)


def _files_of(directory: Path) -> dict[str, bytes]:
    """The regular files directly in ``directory`` with their bytes."""
    return {entry.name: entry.read_bytes() for entry in sorted(directory.iterdir())}


@pytest.mark.parametrize(
    "case",
    ["symlink", "file"],
    ids=["symlink-to-another-orgs-directory", "plain-file"],
)
def test_converters_runner_out_dir_replaced_by_the_child_is_processing_error_and_unlinked(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path, case: str
) -> None:
    """Contract §12.4 addendum (a): a real child replaces out_dir itself with a symlink to
    another org's directory (regular files only, so following the link would measure them
    and succeed) or with a plain file, then prints a valid ok line -> processing_error. The
    entry at out_dir is unlinked without following it: afterwards nothing is at out_dir,
    the other org's directory still holds exactly its files with their bytes, and the
    stored original is unchanged."""
    runner = _runner()
    other_org = stored.parent.parent / "9d4c2b1a-6e5f-4a3b-8c7d-0e1f2a3b4c5d"
    other_org.mkdir()
    (other_org / "6f1e2d3c-4b5a-4987-a6b5-c4d3e2f1a0b9").write_bytes(b"O" * 300_000)
    (other_org / "part-0001.txt").write_bytes("[Vertrag.pdf — page 1]\nother org".encode())
    before = _files_of(other_org)
    monkeypatch.setattr(
        runner, "WORKER_ARGV", (sys.executable, "-c", _SWAPPING_CHILD, case, str(other_org))
    )

    try:
        runner.run_conversion(stored, "pdf", out_dir, _options())
    except _common().ConversionError as exc:
        outcome: object = ("error", exc.reason)
    else:
        outcome = ("returned", None)

    assert (outcome, os.path.lexists(out_dir)) == (("error", "processing_error"), False)
    assert (other_org.is_dir(), other_org.is_symlink(), _files_of(other_org)) == (
        True,
        False,
        before,
    )
    assert stored.read_bytes() == b"%PDF-1.7 stored bytes"


# ---------------------------------------------------------------------------
# Real runs with the default worker
# ---------------------------------------------------------------------------


def _text_pdf(pages: list[str]) -> bytes:
    """A minimal PDF with one Helvetica text line per page (ASCII, no parentheses)."""
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        (
            "<< /Type /Pages /Kids ["
            + " ".join(f"{4 + 2 * index} 0 R" for index in range(len(pages)))
            + f"] /Count {len(pages)} >>"
        ).encode(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    for index, text in enumerate(pages):
        content = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
        objects.append(
            (
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                f"/Resources << /Font << /F1 3 0 R >> >> /Contents {5 + 2 * index} 0 R >>"
            ).encode()
        )
        objects.append(b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")
    out = bytearray(b"%PDF-1.7\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref,
    )
    return bytes(out)


def test_converters_runner_real_worker_converts_a_txt(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path
) -> None:
    """The default worker converts a txt: ConversionResult(None, the text's estimate, the
    bytes on disk), the part and a manifest that agrees with the result."""
    runner = _runner()
    common = _common()
    tokens = importlib.import_module("admino.tokens")
    monkeypatch.setenv("PYTHONPATH", _SRC)
    text = "Agenda 2026\n1. Budget\n2. Hiring\n"
    stored.write_bytes(text.encode("utf-8"))

    result = runner.run_conversion(stored, "txt", out_dir, _options("Agenda.txt"))

    assert result == runner.ConversionResult(
        page_count=None,
        token_estimate=tokens.estimate_text_tokens(text),
        derived_bytes=_disk_bytes(out_dir),
    )
    assert sorted(os.listdir(out_dir)) == ["manifest.json", "part-0001.txt"]
    assert (out_dir / "part-0001.txt").read_bytes() == text.encode("utf-8")
    manifest = common.Manifest.model_validate_json((out_dir / "manifest.json").read_bytes())
    assert (manifest.page_count, manifest.token_estimate) == (None, result.token_estimate)


def test_converters_runner_real_worker_converts_a_two_page_text_pdf(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path
) -> None:
    """The default worker converts a two-page text PDF: page_count 2, the manifest's
    estimate, the bytes on disk, one marked text part per page."""
    runner = _runner()
    common = _common()
    monkeypatch.setenv("PYTHONPATH", _SRC)
    stored.write_bytes(
        _text_pdf(["Quarterly revenue grew in every region", "Second page lists the open risks"])
    )

    result = runner.run_conversion(stored, "pdf", out_dir, _options("Quarterly report.pdf"))

    manifest = common.Manifest.model_validate_json((out_dir / "manifest.json").read_bytes())
    assert result == runner.ConversionResult(
        page_count=2, token_estimate=manifest.token_estimate, derived_bytes=_disk_bytes(out_dir)
    )
    assert result.token_estimate > 0
    assert [(part.type, part.page) for part in manifest.parts] == [("text", 1), ("text", 2)]
    assert sorted(os.listdir(out_dir)) == ["manifest.json", "part-0001.txt", "part-0002.txt"]
    first = (out_dir / "part-0001.txt").read_text(encoding="utf-8")
    assert first.startswith("[Quarterly report.pdf — page 1]\nQuarterly revenue grew")
