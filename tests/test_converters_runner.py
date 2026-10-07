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
  the eight codes -> ``ConversionError`` with that code; a timeout -> ``conversion_timeout``
  (a real sleeping child is killed and reaped, and the call returns long before its
  sleep ends); a non-zero exit status (even with a valid line), stdout that isn't exactly
  one valid result line, an unknown reason or a negative estimate -> ``processing_error``.
  out_dir is removed after every failure, and nothing is logged.
- Real runs with the default argv (PYTHONPATH of the tree under test): a txt and a two-page
  text PDF convert end to end, out_dir keeps the manifest and the parts.

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
    "conversion_timeout",
    "processing_error",
)

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
    """A subprocess.run stand-in returning a canned CompletedProcess (or raising)."""

    out_dir: Path
    returncode: int = 0
    stdout: bytes = _OK_LINE
    raises: BaseException | None = None
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
        if self.raises is not None:
            raise self.raises
        return subprocess.CompletedProcess(argv, self.returncode, stdout=self.stdout)


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
    """ConversionResult(page_count, token_estimate), frozen."""
    runner = _runner()
    result = runner.ConversionResult(page_count=None, token_estimate=7)

    assert [item.name for item in dataclasses.fields(result)] == ["page_count", "token_estimate"]
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
    ],
    ids=["with-pages", "without-pages"],
)
def test_converters_runner_ok_line_returns_the_result_and_keeps_out_dir(
    monkeypatch: pytest.MonkeyPatch,
    stored: Path,
    out_dir: Path,
    stdout: bytes,
    expected: tuple[int | None, int],
) -> None:
    """ok true -> ConversionResult(page_count, token_estimate); out_dir stays."""
    runner = _runner()
    _patch_run(monkeypatch, _FakeRun(out_dir, stdout=stdout))

    result = runner.run_conversion(stored, "pdf", out_dir, _options())

    assert type(result) is runner.ConversionResult
    assert (result.page_count, result.token_estimate) == expected
    assert out_dir.is_dir()


@pytest.mark.parametrize("reason", _REASONS)
def test_converters_runner_known_reason_raises_that_conversion_error(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path, reason: str
) -> None:
    """ok false with one of the eight codes -> ConversionError(code); out_dir removed."""
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
    ],
)
def test_converters_runner_bad_exit_or_output_is_processing_error(
    monkeypatch: pytest.MonkeyPatch,
    stored: Path,
    out_dir: Path,
    returncode: int,
    stdout: bytes,
) -> None:
    """A non-zero exit, or stdout that isn't exactly one valid result line ->
    ConversionError("processing_error"); out_dir removed."""
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
    """The default worker converts a txt: ConversionResult(None, the text's estimate), the
    part and a manifest that agrees with the result."""
    runner = _runner()
    common = _common()
    tokens = importlib.import_module("admino.tokens")
    monkeypatch.setenv("PYTHONPATH", _SRC)
    text = "Agenda 2026\n1. Budget\n2. Hiring\n"
    stored.write_bytes(text.encode("utf-8"))

    result = runner.run_conversion(stored, "txt", out_dir, _options("Agenda.txt"))

    assert result == runner.ConversionResult(
        page_count=None, token_estimate=tokens.estimate_text_tokens(text)
    )
    assert sorted(os.listdir(out_dir)) == ["manifest.json", "part-0001.txt"]
    assert (out_dir / "part-0001.txt").read_bytes() == text.encode("utf-8")
    manifest = common.Manifest.model_validate_json((out_dir / "manifest.json").read_bytes())
    assert (manifest.page_count, manifest.token_estimate) == (None, result.token_estimate)


def test_converters_runner_real_worker_converts_a_two_page_text_pdf(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path
) -> None:
    """The default worker converts a two-page text PDF: page_count 2, the manifest's
    estimate, one marked text part per page."""
    runner = _runner()
    common = _common()
    monkeypatch.setenv("PYTHONPATH", _SRC)
    stored.write_bytes(
        _text_pdf(["Quarterly revenue grew in every region", "Second page lists the open risks"])
    )

    result = runner.run_conversion(stored, "pdf", out_dir, _options("Quarterly report.pdf"))

    manifest = common.Manifest.model_validate_json((out_dir / "manifest.json").read_bytes())
    assert result == runner.ConversionResult(page_count=2, token_estimate=manifest.token_estimate)
    assert result.token_estimate > 0
    assert [(part.type, part.page) for part in manifest.parts] == [("text", 1), ("text", 2)]
    assert sorted(os.listdir(out_dir)) == ["manifest.json", "part-0001.txt", "part-0002.txt"]
    first = (out_dir / "part-0001.txt").read_text(encoding="utf-8")
    assert first.startswith("[Quarterly report.pdf — page 1]\nQuarterly revenue grew")
