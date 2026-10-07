"""Run one attachment conversion in a short-lived worker process (GH-188, server side).

The processing pool calls ``run_conversion`` in a worker thread. It resets the
derived directory, starts ``python -m admino.converters.worker`` with the job on
stdin and reads the child's single result line.

Inputs: the stored file, its kind, the derived directory (``<id>.d``) and the
``ConversionOptions``.
Outputs: ``ConversionResult(page_count, token_estimate)``; the derived
directory then holds the parts and the manifest the child wrote.
Errors: ``ConversionError`` with a contract code: ``conversion_timeout`` after
``CONVERSION_TIMEOUT_S``, ``processing_error`` for a crash or a malformed
result, else the child's own code. ``OSError`` when the directory can't be
reset or the child can't be started.

Security notes:
- The parsers load only in the child: a crafted file that crashes, hangs or
  exhausts memory takes the child down, never the server, and the child is
  killed (and reaped) once the timeout passes.
- The argv is fixed (``WORKER_ARGV``, no shell); the job (the path and the
  file name) travels on stdin, never in the argv a process listing shows.
- The child's environment holds only the server's ``PYTHONPATH``: no API
  token, database password or DSN reaches the code that parses untrusted
  files.
- The child's stderr is discarded unread, and its stdout must be exactly one
  known result object, else ``processing_error``. Nothing here logs.
- The derived directory is reset without following a symlink planted at it
  or inside it, created 0700, and removed after every failure.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, TypeGuard

from admino.converters.common import CONVERSION_FAILURES, ConversionError

if TYPE_CHECKING:
    from pathlib import Path

    from admino.converters.common import ConversionFailure, ConversionOptions
    from admino.models import AttachmentKind

CONVERSION_TIMEOUT_S: Final = 120.0
WORKER_ARGV: Final[tuple[str, ...]] = (
    sys.executable,
    "-P",
    "-s",
    "-m",
    "admino.converters.worker",
)

_DIRECTORY_MODE: Final = 0o700
_CONVERTED_KEYS: Final = frozenset({"ok", "page_count", "token_estimate"})
_REFUSED_KEYS: Final = frozenset({"ok", "reason"})


@dataclass(frozen=True)
class ConversionResult:
    """A converted file: its page count (None for kinds without pages) and token estimate."""

    page_count: int | None
    token_estimate: int


def run_conversion(
    path: Path, kind: AttachmentKind, out_dir: Path, options: ConversionOptions
) -> ConversionResult:
    """Convert ``path`` into ``out_dir`` in a worker process and return its numbers.

    ``WORKER_ARGV`` and ``CONVERSION_TIMEOUT_S`` are read at call time.
    Synchronous: it waits for the child, so it runs in a worker thread.

    Args:
        path: The stored file.
        kind: Its recorded kind.
        out_dir: The derived directory; whatever is there is replaced.
        options: The file name and the platform's render and page settings.

    Returns:
        The page count and the token estimate the child reported; ``out_dir``
        keeps the parts and the manifest.

    Raises:
        ConversionError: A conversion failure code; ``out_dir`` is removed.
        OSError: ``out_dir`` can't be reset or the child can't be started.
    """
    _remove(out_dir)
    out_dir.mkdir(mode=_DIRECTORY_MODE)
    try:
        return _run_worker(path, kind, out_dir, options)
    except BaseException:
        # A failed conversion leaves no partial artifacts. A removal error is
        # dropped: the processing step removes the directory again after its
        # failed outcome (and logs it there).
        with contextlib.suppress(OSError):
            _remove(out_dir)
        raise


def _remove(out_dir: Path) -> None:
    """Remove whatever is at ``out_dir``; a missing entry is fine.

    lstat: a symlink is unlinked itself, never followed; rmtree never follows
    a link inside the tree either.
    """
    try:
        mode = os.lstat(out_dir).st_mode
    except FileNotFoundError:
        return
    if stat.S_ISDIR(mode):
        shutil.rmtree(out_dir)
    else:
        os.unlink(out_dir)


def _run_worker(
    path: Path, kind: AttachmentKind, out_dir: Path, options: ConversionOptions
) -> ConversionResult:
    """Start the child with the job on stdin and parse its outcome."""
    job = json.dumps(
        {
            "path": str(path),
            "kind": kind,
            "out_dir": str(out_dir),
            "filename": options.filename,
            "render_dpi": options.render_dpi,
            "max_pages": options.max_pages,
        }
    ).encode("utf-8")
    pythonpath = os.environ.get("PYTHONPATH")
    env = {} if pythonpath is None else {"PYTHONPATH": pythonpath}
    try:
        # A fixed argv (this interpreter and the worker module), no shell; the
        # job travels on stdin.
        completed = subprocess.run(  # noqa: S603
            list(WORKER_ARGV),
            input=job,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            timeout=CONVERSION_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        # subprocess.run has already killed and reaped the child.
        raise ConversionError("conversion_timeout") from None
    if completed.returncode != 0:
        raise ConversionError("processing_error")
    return _parse_result(completed.stdout)


def _parse_result(stdout: bytes) -> ConversionResult:
    """The child's stdout: exactly one JSON result object followed by a newline.

    Raises:
        ConversionError: The child's known failure code; ``processing_error``
            for anything else (no line, two lines, not JSON, a missing or
            extra key, a wrong type, a negative number, an unknown code).
    """
    line, newline, rest = stdout.partition(b"\n")
    try:
        # Any: whatever JSON the child wrote; every use below checks it.
        result = json.loads(line) if newline and not rest else None
    except (ValueError, RecursionError):
        result = None
    if isinstance(result, dict):
        if result.keys() == _CONVERTED_KEYS and result["ok"] is True:
            page_count = result["page_count"]
            token_estimate = result["token_estimate"]
            if (page_count is None or _is_count(page_count)) and _is_count(token_estimate):
                return ConversionResult(page_count=page_count, token_estimate=token_estimate)
        elif result.keys() == _REFUSED_KEYS and result["ok"] is False:
            reason = result["reason"]
            if _is_failure(reason):
                raise ConversionError(reason)
    raise ConversionError("processing_error")


def _is_count(value: object) -> bool:
    """A JSON integer >= 0 (a bool, a float or a string is not)."""
    return type(value) is int and value >= 0


def _is_failure(value: object) -> TypeGuard[ConversionFailure]:
    """One of the contract's failure codes (an unhashable value is not)."""
    return isinstance(value, str) and value in CONVERSION_FAILURES
