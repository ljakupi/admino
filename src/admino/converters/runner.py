"""Run one attachment conversion in a short-lived worker process (GH-188, server side).

The processing pool calls ``run_conversion`` in a worker thread. It resets the
derived directory, starts ``python -m admino.converters.worker`` with the job on
stdin and reads the child's single result line (at most ``MAX_RESULT_BYTES``).

Inputs: the stored file, its kind, the derived directory (``<id>.d``) and the
``ConversionOptions``.
Outputs: ``ConversionResult(page_count, token_estimate, derived_bytes)``;
the derived directory then holds the parts and the manifest the child wrote,
and ``derived_bytes`` is their size as measured here (never the child's
claim).
Errors: ``ConversionError`` with a contract code: ``conversion_timeout`` after
``CONVERSION_TIMEOUT_S``, ``processing_error`` for a crash, more than
``MAX_RESULT_BYTES`` of stdout, a malformed result (a count beyond
PostgreSQL's INTEGER included) or a derived directory that holds anything
but regular files, ``output_too_large`` past
``common.MAX_DERIVED_BYTES``, else the child's own code. ``OSError`` when the
directory can't be reset or the child can't be started.

Security notes:
- The parsers load only in the child: a crafted file that crashes, hangs or
  exhausts memory takes the child down, never the server. One deadline
  (``CONVERSION_TIMEOUT_S``) covers writing the job, reading the result and
  the child's exit; once it passes the child is killed (SIGKILL) and reaped.
- The child's stdout is read incrementally and never buffered past
  ``MAX_RESULT_BYTES`` + 1 bytes: as soon as more than the cap has arrived,
  the child is killed and reaped at once (``processing_error``), so a child
  flooding its stdout can't fill the server's memory.
- The child leads its own session and process group
  (``start_new_session=True``), which the processes it starts inherit.
  However the call ends (an error, the deadline, the stdout cap, a
  KeyboardInterrupt), while the child is still unreaped its whole group is
  SIGKILLed, then the child is killed and reaped. A child that exited by
  itself and was reaped gets no group kill: its pid may name another
  process by then. What remains runs until it exits, and the container's
  init (``init: true``) reaps it then: a process that left the group with
  ``setsid``, and one left behind by a child that exited by itself once it
  no longer holds the child's stdout.
- The argv is fixed (``WORKER_ARGV``, ``subprocess.Popen`` without a shell);
  the job (the path and the file name) travels on stdin, never in the argv
  a process listing shows.
- The child's environment holds only the server's ``PYTHONPATH``: no API
  token, database password or DSN reaches the code that parses untrusted
  files.
- The child's stderr is discarded unread, and its stdout must be exactly one
  known result object, else ``processing_error``. Nothing here logs.
- The derived directory is reset without following a symlink planted at it
  or inside it, created 0700, and removed after every failure.
- The child's output is measured by this process: the derived directory
  must still be a real directory holding regular files only (opened and
  listed without following a link, so a child can't point the measurement,
  or the cleanup, at another org's files), and their total is capped.
"""

from __future__ import annotations

import contextlib
import json
import os
import select
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import IO, TYPE_CHECKING, Final, TypeGuard, cast

from admino.converters import common
from admino.converters.common import ConversionError

if TYPE_CHECKING:
    from pathlib import Path

    from admino.converters.common import ConversionFailure, ConversionOptions
    from admino.models import AttachmentKind

CONVERSION_TIMEOUT_S: Final = 120.0
# The most stdout bytes a child may write: a valid result line is under 100.
MAX_RESULT_BYTES: Final = 4096
WORKER_ARGV: Final[tuple[str, ...]] = (
    sys.executable,
    "-P",
    "-s",
    "-m",
    "admino.converters.worker",
)

_DIRECTORY_MODE: Final = 0o700
# Opens the derived directory itself: a symlink (O_NOFOLLOW) or anything else
# (O_DIRECTORY, checked before a FIFO could block the open) put there fails.
_OPEN_DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# The largest PostgreSQL INTEGER (the page_count and token_estimate columns).
_INT32_MAX: Final = 2_147_483_647
_CONVERTED_KEYS: Final = frozenset({"ok", "page_count", "token_estimate"})
_REFUSED_KEYS: Final = frozenset({"ok", "reason"})


@dataclass(frozen=True)
class ConversionResult:
    """A converted file: its page count (None for kinds without pages), token estimate
    and the bytes of its derived files (measured by the parent)."""

    page_count: int | None
    token_estimate: int
    derived_bytes: int


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
        The page count and the token estimate the child reported, and the
        bytes of the files in ``out_dir``, which keeps the parts and the
        manifest.

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
    deadline = time.monotonic() + CONVERSION_TIMEOUT_S
    # A fixed argv (this interpreter and the worker module), no shell; the job
    # travels on stdin. The child leads a new session and process group (its
    # pid), so whatever it starts can be killed with it.
    with subprocess.Popen(  # noqa: S603
        list(WORKER_ARGV),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
        start_new_session=True,
    ) as child:
        try:
            stdout = _exchange(child, job, deadline)
            returncode = child.wait(timeout=max(deadline - time.monotonic(), 0.0))
        except subprocess.TimeoutExpired:
            raise ConversionError("conversion_timeout") from None
        finally:
            # However the call ends (the cap, the deadline, a KeyboardInterrupt),
            # the child's group is SIGKILLed while the child is still unreaped:
            # an unreaped pid (running or a zombie) can't be reused, so the
            # group id still names this child's group. A child the wait above
            # reaped gets no group kill, its pid may belong to another process
            # by now. A missing group is fine, and macOS answers EPERM when every
            # process left in the group is a zombie. A process that left the
            # group with setsid isn't reached; init reaps it once it exits.
            if child.returncode is None:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(child.pid, signal.SIGKILL)
            # Then the child is SIGKILLed if still running and reaped here:
            # Popen's own exit waits only briefly after an interrupt. kill()
            # polls first, so it never signals a pid that was already reaped.
            child.kill()
            child.wait()
    if returncode != 0:
        raise ConversionError("processing_error")
    page_count, token_estimate = _parse_result(stdout)
    derived_bytes = _measure(out_dir)
    if derived_bytes > common.MAX_DERIVED_BYTES:
        raise ConversionError("output_too_large")
    return ConversionResult(
        page_count=page_count, token_estimate=token_estimate, derived_bytes=derived_bytes
    )


def _exchange(child: subprocess.Popen[bytes], job: bytes, deadline: float) -> bytes:
    """Write ``job`` to the child's stdin (then close it) and read its stdout to EOF.

    One loop does both before ``deadline``, so neither a child that never
    reads its job nor one that writes before reading it can block the other
    side. Each read asks for at most what still fits under
    ``MAX_RESULT_BYTES`` (read at call time) plus one byte: no more than the
    cap + 1 bytes are ever held.

    Returns:
        The child's stdout, at most ``MAX_RESULT_BYTES`` bytes.

    Raises:
        ConversionError: ``processing_error`` as soon as more than the cap
            has arrived (the caller kills the child, without waiting for EOF);
            ``conversion_timeout`` once the deadline passes.
    """
    cap = MAX_RESULT_BYTES
    # Both were requested as pipes when the child started: never None.
    stdin, stdout = cast("IO[bytes]", child.stdin), cast("IO[bytes]", child.stdout)
    unsent = memoryview(job)
    held = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(stdin, selectors.EVENT_WRITE)
        selector.register(stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ConversionError("conversion_timeout")
            for key, _ in selector.select(remaining):
                if key.fileobj is stdin:
                    try:
                        # A writable pipe takes PIPE_BUF bytes without blocking.
                        unsent = unsent[os.write(key.fd, unsent[: select.PIPE_BUF]) :]
                    except BrokenPipeError:
                        # The child closed its stdin unread: its stdout and exit
                        # status decide the outcome.
                        unsent = unsent[:0]
                    if not unsent:
                        selector.unregister(stdin)
                        stdin.close()
                    continue
                chunk = os.read(key.fd, cap + 1 - len(held))
                if not chunk:
                    selector.unregister(stdout)
                held += chunk
                if len(held) > cap:
                    raise ConversionError("processing_error")
    return bytes(held)


def _measure(out_dir: Path) -> int:
    """The total size of the regular files directly in ``out_dir``.

    The directory is opened without following a link and listed through that
    descriptor, each entry stat'ed without following it: whatever the child
    put at or in ``out_dir``, nothing outside it is measured.

    Raises:
        ConversionError: ``processing_error`` when ``out_dir`` is no longer a
            real directory or holds anything but regular files (a symlink, a
            subdirectory, a FIFO).
    """
    try:
        directory = os.open(out_dir, _OPEN_DIRECTORY_FLAGS)
    except OSError:
        raise ConversionError("processing_error") from None
    try:
        total = 0
        with os.scandir(directory) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    raise ConversionError("processing_error")
                total += info.st_size
        return total
    finally:
        os.close(directory)


def _parse_result(stdout: bytes) -> tuple[int | None, int]:
    """The child's stdout: exactly one JSON result object followed by a newline.

    Returns:
        The reported page count and token estimate.

    Raises:
        ConversionError: The child's known failure code; ``processing_error``
            for anything else (no line, two lines, not JSON, a missing or
            extra key, a wrong type, a negative number or one beyond INTEGER,
            an unknown code).
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
                return page_count, token_estimate
        elif result.keys() == _REFUSED_KEYS and result["ok"] is False:
            reason = result["reason"]
            if _is_failure(reason):
                raise ConversionError(reason)
    raise ConversionError("processing_error")


def _is_count(value: object) -> bool:
    """A JSON integer within PostgreSQL's INTEGER, >= 0 (a bool, a float or a string is not)."""
    return type(value) is int and 0 <= value <= _INT32_MAX


def _is_failure(value: object) -> TypeGuard[ConversionFailure]:
    """One of the contract's failure codes (an unhashable value is not)."""
    return isinstance(value, str) and value in common.CONVERSION_FAILURES
