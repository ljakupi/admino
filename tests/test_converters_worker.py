"""The conversion worker's child entry point (GH-188, contract §5.1, Decision 2).

``admino.converters.worker.main(stdin, stdout) -> int`` runs in a short-lived child
process started by the runner. Pinned here, in process with ``BytesIO`` streams:

- First, on Linux, the child makes itself the OOM killer's first choice: ``"1000"`` is
  written to ``OOM_SCORE_ADJ_PATH`` (``Path("/proc/self/oom_score_adj")``, read at call
  time), even for a job that turns out malformed; a missing directory, a read-only file
  or a directory at that path is ignored.
- The job is one JSON object ``{path, kind, out_dir, filename, render_dpi, max_pages}`` on
  stdin; it reaches ``dispatch.convert`` as ``Path``s, the kind and
  ``ConversionOptions(filename, render_dpi, max_pages)``.
- Success: exactly one JSON object + ``"\\n"`` on stdout, ``{"ok": true, "page_count",
  "token_estimate"}`` from the manifest; returns 0.
- ``ConversionError(r)``: ``{"ok": false, "reason": r}`` + ``"\\n"``; returns 0 (each of
  the eight codes, and a real corrupted txt).
- A malformed job (bad JSON, empty input, not an object, a missing or extra key, an unknown
  kind, a non-integer dpi) or any other exception (``MemoryError`` included): nothing on
  stdout, returns 1; dispatch never runs for a malformed job; an exception's message (a
  path, a file name) never reaches stdout.
- Two real child runs (``python -P -s -m admino.converters.worker`` with the PYTHONPATH of
  the tree under test): a txt job converts end to end with exit status 0, and a malformed
  job exits with status 1 and writes nothing (``sys.exit(main(...))``).

Every in-process test points ``OOM_SCORE_ADJ_PATH`` at a tmp file, so no test touches the
real ``/proc`` entry of the test runner. New modules are imported inside the tests.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import io
import json
import os
import subprocess
import sys
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
    "conversion_timeout",
    "processing_error",
)

# A path and a file name an unexpected error message might carry.
_SECRET_PATH: Final = "/srv/admino/attachments/7f1e/Gehaltsliste-Vertraulich-2026.xlsx"


def _worker() -> ModuleType:
    return importlib.import_module("admino.converters.worker")


def _common() -> ModuleType:
    return importlib.import_module("admino.converters.common")


def _job(tmp_path: Path, **overrides: object) -> dict[str, object]:
    job: dict[str, object] = {
        "path": str(tmp_path / "stored"),
        "kind": "txt",
        "out_dir": str(tmp_path / "stored.d"),
        "filename": "Notes 2026.txt",
        "render_dpi": 150,
        "max_pages": 100,
    }
    job.update(overrides)
    return job


def _encode(job: dict[str, object]) -> bytes:
    return json.dumps(job).encode("utf-8")


def _run(worker: ModuleType, stdin: bytes) -> tuple[int, bytes]:
    stdout = io.BytesIO()
    code = worker.main(io.BytesIO(stdin), stdout)
    return code, stdout.getvalue()


def _one_line(output: bytes) -> Any:
    """The single JSON object of a result line (exactly one line ending in a newline)."""
    assert output.endswith(b"\n")
    assert output.count(b"\n") == 1
    return json.loads(output)


def _manifest(page_count: int | None = 3, token_estimate: int = 12) -> Any:
    common = _common()
    return common.Manifest(
        version=1,
        kind="pdf",
        page_count=page_count,
        token_estimate=token_estimate,
        parts=[common.TextPart(type="text", file="part-0001.txt", page=1, tokens=token_estimate)],
    )


def _patch_convert(
    monkeypatch: pytest.MonkeyPatch, fake: Callable[..., Any]
) -> list[dict[str, object]]:
    """Replace dispatch.convert (and the worker's own reference, if it holds one); every
    call's arguments are recorded by name."""
    dispatch = importlib.import_module("admino.converters.dispatch")
    worker = _worker()
    original = dispatch.convert
    calls: list[dict[str, object]] = []
    signature = inspect.Signature(
        [
            inspect.Parameter(name, inspect.Parameter.POSITIONAL_OR_KEYWORD)
            for name in ("path", "kind", "out_dir", "options")
        ]
    )

    def recorder(*args: object, **kwargs: object) -> Any:
        calls.append(dict(signature.bind(*args, **kwargs).arguments))
        return fake(*args, **kwargs)

    monkeypatch.setattr(dispatch, "convert", recorder)
    for name, value in list(vars(worker).items()):
        if value is original:
            monkeypatch.setattr(worker, name, recorder)
    return calls


@pytest.fixture
def oom_path(tmp_path: Path) -> Path:
    """A stand-in for /proc/self/oom_score_adj holding the default score."""
    path = tmp_path / "oom_score_adj"
    path.write_text("0", encoding="ascii")
    return path


@pytest.fixture
def worker(monkeypatch: pytest.MonkeyPatch, oom_path: Path) -> ModuleType:
    """The worker module with OOM_SCORE_ADJ_PATH pointed at the tmp stand-in."""
    module = _worker()
    monkeypatch.setattr(module, "OOM_SCORE_ADJ_PATH", oom_path)
    return module


# ---------------------------------------------------------------------------
# Results on stdout
# ---------------------------------------------------------------------------


def test_converters_worker_txt_job_converts_and_writes_one_result_line(
    worker: ModuleType, tmp_path: Path
) -> None:
    """A real txt job (in process): exit 0, one JSON line with page_count null and the
    text's estimate, the part and the manifest in out_dir."""
    tokens = importlib.import_module("admino.tokens")
    text = "Quarterly notes 2026\nline two\n"
    job = _job(tmp_path)
    Path(str(job["path"])).write_bytes(text.encode("utf-8"))
    out_dir = Path(str(job["out_dir"]))
    out_dir.mkdir(mode=0o700)

    code, output = _run(worker, _encode(job))

    result = _one_line(output)
    assert code == 0
    assert result == {
        "ok": True,
        "page_count": None,
        "token_estimate": tokens.estimate_text_tokens(text),
    }
    assert result["ok"] is True
    assert (out_dir / "part-0001.txt").read_bytes() == text.encode("utf-8")
    assert (out_dir / "manifest.json").is_file()


def test_converters_worker_job_fields_reach_dispatch_and_manifest_numbers_are_reported(
    worker: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """dispatch.convert gets Path(path), the kind, Path(out_dir) and ConversionOptions
    from the job; the line carries the manifest's page_count and token_estimate."""
    common = _common()
    calls = _patch_convert(monkeypatch, lambda *args, **kwargs: _manifest(3, 12))
    job = _job(tmp_path, kind="pdf", filename="Q3 Plan [draft].pdf", render_dpi=200, max_pages=40)

    code, output = _run(worker, _encode(job))

    assert calls == [
        {
            "path": Path(str(job["path"])),
            "kind": "pdf",
            "out_dir": Path(str(job["out_dir"])),
            "options": common.ConversionOptions(
                filename="Q3 Plan [draft].pdf", render_dpi=200, max_pages=40
            ),
        }
    ]
    assert code == 0
    assert _one_line(output) == {"ok": True, "page_count": 3, "token_estimate": 12}


@pytest.mark.parametrize("reason", _REASONS)
def test_converters_worker_conversion_error_reported_as_its_reason(
    worker: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reason: str
) -> None:
    """ConversionError(r) -> {"ok": false, "reason": r} on one line, exit 0."""
    common = _common()

    def failing(*args: object, **kwargs: object) -> Any:
        raise common.ConversionError(reason)

    _patch_convert(monkeypatch, failing)

    code, output = _run(worker, _encode(_job(tmp_path, kind="pdf")))

    result = _one_line(output)
    assert code == 0
    assert result == {"ok": False, "reason": reason}
    assert result["ok"] is False


def test_converters_worker_real_corrupted_txt_reports_corrupted_file(
    worker: ModuleType, tmp_path: Path
) -> None:
    """A txt that isn't UTF-8, converted for real: the corrupted_file line, exit 0, no
    manifest."""
    job = _job(tmp_path)
    Path(str(job["path"])).write_bytes(b"caf\xe9 au lait\n")
    out_dir = Path(str(job["out_dir"]))
    out_dir.mkdir(mode=0o700)

    code, output = _run(worker, _encode(job))

    assert code == 0
    assert _one_line(output) == {"ok": False, "reason": "corrupted_file"}
    assert not (out_dir / "manifest.json").exists()


# ---------------------------------------------------------------------------
# Malformed jobs and unexpected errors
# ---------------------------------------------------------------------------


def _malformed(tmp_path: Path, case: str) -> bytes:
    job = _job(tmp_path)
    if case == "bad-json":
        return b'{"path": "/srv/x", '
    if case == "empty":
        return b""
    if case == "not-an-object":
        return b'["/srv/x", "txt"]'
    if case == "missing-key":
        del job["max_pages"]
    elif case == "extra-key":
        job["shell"] = "rm -rf /"
    elif case == "unknown-kind":
        job["kind"] = "exe"
    elif case == "non-int-dpi":
        job["render_dpi"] = 1.5
    return _encode(job)


@pytest.mark.parametrize(
    "case",
    [
        "bad-json",
        "empty",
        "not-an-object",
        "missing-key",
        "extra-key",
        "unknown-kind",
        "non-int-dpi",
    ],
)
def test_converters_worker_malformed_job_returns_1_and_writes_nothing(
    worker: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, case: str
) -> None:
    """A malformed job: exit 1, nothing on stdout, dispatch never runs."""
    calls = _patch_convert(monkeypatch, lambda *args, **kwargs: _manifest())

    code, output = _run(worker, _malformed(tmp_path, case))

    assert (code, output, calls) == (1, b"", [])


@pytest.mark.parametrize("error", ["runtime-error", "memory-error", "os-error"])
def test_converters_worker_unexpected_exception_returns_1_and_writes_nothing(
    worker: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    error: str,
) -> None:
    """Any other exception (MemoryError included): exit 1, nothing on stdout; its message
    (a path and a file name) reaches neither the result stream nor the process stdout."""
    raised: BaseException = {
        "runtime-error": RuntimeError(f"cannot parse {_SECRET_PATH}"),
        "memory-error": MemoryError(f"while reading {_SECRET_PATH}"),
        "os-error": OSError(5, "Input/output error", _SECRET_PATH),
    }[error]

    def failing(*args: object, **kwargs: object) -> Any:
        raise raised

    _patch_convert(monkeypatch, failing)

    code, output = _run(worker, _encode(_job(tmp_path, kind="xlsx")))

    assert (code, output) == (1, b"")
    assert "Gehaltsliste" not in capsys.readouterr().out


# ---------------------------------------------------------------------------
# OOM score
# ---------------------------------------------------------------------------


def test_converters_worker_oom_score_path_constant_pinned() -> None:
    """OOM_SCORE_ADJ_PATH is /proc/self/oom_score_adj."""
    assert Path("/proc/self/oom_score_adj") == _worker().OOM_SCORE_ADJ_PATH


@pytest.mark.parametrize("job", ["valid", "malformed"])
def test_converters_worker_oom_score_1000_written_before_the_job_counts(
    worker: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    oom_path: Path,
    job: str,
) -> None:
    """ "1000" is written to OOM_SCORE_ADJ_PATH (read at call time) for a valid job and for
    a malformed one alike: it comes first."""
    _patch_convert(monkeypatch, lambda *args, **kwargs: _manifest())
    stdin = _encode(_job(tmp_path)) if job == "valid" else b"{"

    code, _ = _run(worker, stdin)

    assert code == (0 if job == "valid" else 1)
    assert oom_path.read_text(encoding="ascii") in ("1000", "1000\n")


@pytest.mark.parametrize("case", ["missing-directory", "read-only-file", "directory"])
def test_converters_worker_unusable_oom_path_is_ignored(
    worker: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, case: str
) -> None:
    """A missing directory, a read-only file or a directory at OOM_SCORE_ADJ_PATH: the
    error is ignored and the job still converts."""
    target = tmp_path / "proc" / "oom_score_adj"
    if case == "read-only-file":
        target.parent.mkdir()
        target.write_text("0", encoding="ascii")
        target.chmod(0o400)
    elif case == "directory":
        target.mkdir(parents=True)
    monkeypatch.setattr(worker, "OOM_SCORE_ADJ_PATH", target)
    _patch_convert(monkeypatch, lambda *args, **kwargs: _manifest(None, 5))

    try:
        code, output = _run(worker, _encode(_job(tmp_path)))
    finally:
        if case == "read-only-file":
            target.chmod(0o600)

    assert code == 0
    assert _one_line(output) == {"ok": True, "page_count": None, "token_estimate": 5}
    if case == "read-only-file":
        assert target.read_text(encoding="ascii") == "0"


# ---------------------------------------------------------------------------
# Real child processes
# ---------------------------------------------------------------------------


def _child(stdin: bytes) -> subprocess.CompletedProcess[bytes]:
    """``python -P -s -m admino.converters.worker`` with only the tree's PYTHONPATH."""
    # A fixed argv (this interpreter, the worker module); the job travels on stdin.
    return subprocess.run(  # noqa: S603
        [sys.executable, "-P", "-s", "-m", "admino.converters.worker"],
        input=stdin,
        capture_output=True,
        env={"PYTHONPATH": _SRC},
        timeout=120,
        check=False,
    )


def test_converters_worker_real_child_converts_a_txt(tmp_path: Path) -> None:
    """The module run as a child converts a txt end to end: exit status 0, one result line,
    the part and the manifest on disk."""
    tokens = importlib.import_module("admino.tokens")
    text = "Projektplan 2026 — Phase 1\nZiele und Risiken\n"
    job = _job(tmp_path, filename="Projektplan.txt")
    Path(str(job["path"])).write_bytes(text.encode("utf-8"))
    out_dir = Path(str(job["out_dir"]))
    out_dir.mkdir(mode=0o700)

    completed = _child(_encode(job))

    assert completed.returncode == 0
    assert _one_line(completed.stdout) == {
        "ok": True,
        "page_count": None,
        "token_estimate": tokens.estimate_text_tokens(text),
    }
    assert (out_dir / "part-0001.txt").read_bytes() == text.encode("utf-8")
    assert (out_dir / "manifest.json").is_file()


def test_converters_worker_real_child_malformed_job_exits_1_with_empty_stdout(
    tmp_path: Path,
) -> None:
    """main's return value is the child's exit status: a malformed job exits with 1 and
    writes nothing (the worker module must exist, else this proves nothing)."""
    assert importlib.util.find_spec("admino.converters") is not None
    assert importlib.util.find_spec("admino.converters.worker") is not None

    completed = _child(_encode(_job(tmp_path, kind="exe")))

    assert (completed.returncode, completed.stdout) == (1, b"")
    assert os.listdir(tmp_path) == []
