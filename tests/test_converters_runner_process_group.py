"""The conversion runner kills the child's whole process group (GH-286, Decision 5).

Issue #286: "The conversion runner starts the child in its own session and, on timeout
or output overflow, kills the whole process group, so no grandchild outlives the
conversion". Testing: "a child that spawns a grandchild and then times out or floods its
output". Pinned here:

- The child starts with ``start_new_session=True`` (the recorded ``Popen`` call), so a
  real child leads its own session and process group: in the child ``os.getsid(0) ==
  os.getpgid(0) == os.getpid()``. The processes it starts inherit both.
- Whenever the call ends with the child not yet reaped by the runner, the runner sends
  SIGKILL to the whole group (``os.killpg(child.pid, signal.SIGKILL)``) before it reaps
  the child: the deadline passes (``conversion_timeout``) while the child and its
  grandchild hold stdout, during the exit wait after EOF (child and grandchild closed
  their stdout), or after the child exited by itself while its grandchild still holds
  stdout (the read runs to the deadline); the child writes more than
  ``MAX_RESULT_BYTES`` (``processing_error``); any other exception is raised while the
  runner waits (a KeyboardInterrupt, a RuntimeError). In each case the exception or code
  is unchanged, the child is reaped when the call returns, its grandchild is gone shortly
  after (dead, or a zombie waiting for init) and nothing is logged.
- The group is signalled while the child is still unreaped (its ``Popen.returncode`` is
  None and its pid still exists, running or as a zombie), so the group id can't have been
  reused. A child that exited by itself and was reaped (a result, a refusal, a crash with
  a non-zero exit) gets no group kill at all. A child that floods its stdout and has
  already exited when the runner reads past the cap is an unreaped zombie: its group is
  still killed before it is reaped and the outcome stays ``processing_error`` (macOS
  answers ``killpg`` of a group holding only zombies with EPERM, Linux with success). A
  ``ProcessLookupError`` from ``killpg`` is ignored: the call still ends with its code and
  the child reaped.
- docs/SECURITY.md: a block names the process group, says in one sentence that the group
  is killed on a timeout and an output overflow, and names ``setsid`` (the way out of the
  group, what remains); no sentence still says the grandchildren "are not killed".

The children are real ``python -c`` stand-ins: started through ``WORKER_ARGV`` (they fork
the grandchild and write both pids to files), or through the recording ``Popen`` of
tests/test_converters_runner.py (the recorded call, and the ``Popen`` object the runner
holds). Every test kills what a call left behind. ``os.killpg`` is wrapped in every test:
each call is recorded, and a call for the test runner's own group (or 0, or 1) is
refused, so a wrong implementation can't kill pytest. New names are looked up when the
tests run, so the file collects before GH-286 exists.
"""

from __future__ import annotations

import contextlib
import errno
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from tests.test_converters_runner import (
    _OK_LINE,
    _REAL_POPEN,
    _admino_records,
    _alive,
    _common,
    _FakeChild,
    _kill_leftover,
    _options,
    _patch_popen,
    _popen_class,
    _read_pid,
    _runner,
)
from tests.test_docs_attachments_root import _SECURITY, _SENTENCE_END_RE, _blocks

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import FrameType

_ATTACHMENT_ID: Final = "0d2f6a4b-91c3-4e7d-8a5b-6c1e9f3a2b70"

# The real os.killpg, captured before any test wraps it.
_REAL_KILLPG: Final = os.killpg
_PS: Final = shutil.which("ps") or "/bin/ps"

# How long a killed grandchild may take to disappear (dead, or a zombie waiting for
# init to reap it) after the call returned: generous, for loaded CI machines.
_GONE_BUDGET_S: Final = 5.0

# A worker stand-in that reads its job, forks a grandchild and writes the child's pid to
# argv[1] and the grandchild's to argv[2] (each file complete when it appears). The
# grandchild sleeps 60 s, holding the child's stdout unless the mode is "eof". Then, by
# argv[3]:
# - "sleep": the child sleeps 60 s with its stdout open;
# - "eof": the grandchild points its stdout at /dev/null, the child closes its stdout
#   (the runner sees EOF) and sleeps 60 s without exiting;
# - "flood": the child writes 8192 bytes (over the 4096-byte cap, under a pipe's
#   capacity) and sleeps 60 s;
# - "exit": the child writes a valid ok line and exits 0 by itself (its grandchild still
#   holds the stdout pipe open).
_FAMILY: Final = (
    "import os, sys, time\n"
    "child_file, grandchild_file, mode = sys.argv[1:4]\n"
    "sys.stdin.buffer.read()\n"
    "grandchild = os.fork()\n"
    "if grandchild == 0:\n"
    "    if mode == 'eof':\n"
    "        os.dup2(os.open(os.devnull, os.O_WRONLY), 1)\n"
    "    time.sleep(60)\n"
    "    os._exit(0)\n"
    "for path, pid in ((child_file, os.getpid()), (grandchild_file, grandchild)):\n"
    "    with open(path + '.tmp', 'w', encoding='ascii') as handle:\n"
    "        handle.write(str(pid))\n"
    "    os.replace(path + '.tmp', path)\n"
    "if mode == 'eof':\n"
    "    os.close(1)\n"
    "elif mode == 'flood':\n"
    "    os.write(1, b'x' * 8192)\n"
    "elif mode == 'exit':\n"
    f"    os.write(1, {_OK_LINE!r})\n"
    "    os._exit(0)\n"
    "time.sleep(60)\n"
)

# A worker stand-in that reads its job, writes its pid, process group id and session id
# to argv[1] (JSON) and a valid ok line to stdout, then exits 0.
_SESSION_REPORTER: Final = (
    "import json, os, sys\n"
    "sys.stdin.buffer.read()\n"
    "with open(sys.argv[1], 'w', encoding='ascii') as handle:\n"
    "    json.dump({'pid': os.getpid(), 'pgid': os.getpgid(0), 'sid': os.getsid(0)}, handle)\n"
    f"sys.stdout.buffer.write({_OK_LINE!r})\n"
)

_REFUSAL_LINE: Final = b'{"ok": false, "reason": "password_protected"}\n'


class _InterruptedError(RuntimeError):
    """An exception other than a KeyboardInterrupt, raised while the runner waits."""


@dataclass(frozen=True)
class _GroupKill:
    """One ``os.killpg`` call as the runner made it."""

    pgid: int
    signal: int
    # The started child's Popen.returncode at that moment (None: not reaped yet), or
    # "untracked" when the test doesn't hold that child's Popen object.
    child_returncode: object
    # The pgid still named a process then (running, or a zombie nobody reaped).
    pid_existed: bool


@dataclass
class _Killpg:
    """``os.killpg`` for the tests: records each call, then sends the real signal.

    A call for the test runner's own group (or 0, or 1) is refused. With
    ``lookup_error`` the group is gone instead: the child (the call's pgid) is killed
    directly, then the call raises ProcessLookupError.
    """

    started: list[subprocess.Popen[bytes]] = field(default_factory=list)
    calls: list[_GroupKill] = field(default_factory=list)
    lookup_error: bool = False

    def __call__(self, pgid: int, signum: int) -> None:
        if pgid <= 1 or pgid == os.getpgrp():
            self.calls.append(_GroupKill(pgid, signum, "untracked", False))
            msg = "refused: os.killpg for the test runner's own group"
            raise AssertionError(msg)
        tracked = {child.pid: child for child in self.started}
        returncode = tracked[pgid].returncode if pgid in tracked else "untracked"
        self.calls.append(_GroupKill(pgid, signum, returncode, _alive(pgid)))
        if self.lookup_error:
            os.kill(pgid, signal.SIGKILL)
            raise ProcessLookupError(errno.ESRCH, os.strerror(errno.ESRCH))
        _REAL_KILLPG(pgid, signum)

    def seen_by(self, child: subprocess.Popen[bytes]) -> list[tuple[bool, int, object, bool]]:
        """The calls as (aimed at ``child``'s pid, signal, its returncode then, it existed)."""
        return [
            (call.pgid == child.pid, call.signal, call.child_returncode, call.pid_existed)
            for call in self.calls
        ]


@pytest.fixture(autouse=True)
def killpg(monkeypatch: pytest.MonkeyPatch) -> _Killpg:
    """Every test: ``os.killpg`` (and any reference the runner holds to it) is the spy."""
    spy = _Killpg()
    runner = _runner()
    for name, value in list(vars(runner).items()):
        if value is _REAL_KILLPG:
            monkeypatch.setattr(runner, name, spy)
    monkeypatch.setattr(os, "killpg", spy)
    return spy


@pytest.fixture
def stored(tmp_path: Path) -> Path:
    """A stored original under <root>/<org_id>/<id>."""
    path = tmp_path / "attachments" / "7e4c2a19-5d3b-4f86-9a0e-2b7c1d8f6e53" / _ATTACHMENT_ID
    path.parent.mkdir(parents=True)
    path.write_bytes(b"%PDF-1.7 stored bytes")
    return path


@pytest.fixture
def out_dir(stored: Path) -> Path:
    """The derived directory <id>.d (not created: the runner creates it)."""
    return stored.with_name(stored.name + ".d")


def _state(pid: int) -> str:
    """The process's state letter ("Z" for a zombie), or "" once it no longer exists."""
    if not _alive(pid):
        return ""
    if sys.platform == "linux":
        try:
            text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
        except OSError:
            return ""
        fields = text.rpartition(")")[2].split()
        return fields[0] if fields else ""
    # The real Popen: a test may have replaced subprocess.Popen by a recorder.
    with _REAL_POPEN(
        [_PS, "-o", "stat=", "-p", str(pid)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    ) as probe:
        output, _ = probe.communicate(timeout=10)
    return output.decode("ascii", "replace").strip()[:1]


def _running(pid: int) -> bool:
    """The process exists and isn't dead (a zombie only waits to be reaped)."""
    return _state(pid) not in ("", "Z", "X")


def _gone_within(pid: int, budget: float) -> bool:
    """The process is dead (or a zombie) within ``budget`` seconds."""
    deadline = time.monotonic() + budget
    while _running(pid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)
    return True


def _wait_for_zombie(pid: int) -> None:
    """Wait (at most 10 s) until the child has exited, without reaping it."""
    deadline = time.monotonic() + 10.0
    while _state(pid) not in ("Z", "") and time.monotonic() < deadline:
        time.sleep(0.01)


def _outcome_of(run: Callable[[], Any]) -> tuple[str, object]:
    """("result", the result), ("error", the ConversionError's reason) or ("raised",
    the name of any other exception the call raised)."""
    try:
        result = run()
    except _common().ConversionError as exc:
        return ("error", exc.reason)
    except BaseException as exc:  # KeyboardInterrupt included: the test reports it
        return ("raised", type(exc).__name__)
    return ("result", result)


def _track_popen(
    monkeypatch: pytest.MonkeyPatch,
    spy: _Killpg,
    fake: _FakeChild,
    *,
    zombie_first: bool = False,
) -> None:
    """Replace subprocess.Popen (and any reference the runner holds to it) by the recorder
    of tests/test_converters_runner.py, keeping each started Popen object in ``spy``.
    With ``zombie_first`` the start returns only once the stand-in has exited (a zombie,
    not reaped)."""
    recorder = _popen_class(fake)

    def start(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        child = recorder(*args, **kwargs)
        spy.started.append(child)
        if zombie_first:
            _wait_for_zombie(child.pid)
        return child

    runner = _runner()
    current = subprocess.Popen
    for name, value in list(vars(runner).items()):
        if value is _REAL_POPEN or value is current:
            monkeypatch.setattr(runner, name, start)
    monkeypatch.setattr(subprocess, "Popen", start)


def _kill_family(child_file: Path, grandchild_file: Path) -> None:
    """Test cleanup only: kill a grandchild still running, kill and reap the child."""
    grandchild = _read_pid(grandchild_file)
    if grandchild is not None and _running(grandchild):
        with contextlib.suppress(OSError):
            os.kill(grandchild, signal.SIGKILL)
    _kill_leftover(child_file)


@dataclass(frozen=True)
class _FamilyRun:
    """What one run of the ``_FAMILY`` stand-in left behind."""

    outcome: tuple[str, object]
    elapsed: float
    child_seen: bool
    child_left: bool
    grandchild_seen: bool
    grandchild_left: bool


def _run_family(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stored: Path,
    out_dir: Path,
    *,
    mode: str,
    timeout_s: float,
    interrupt: type[BaseException] | None = None,
) -> _FamilyRun:
    """Run one conversion with the ``_FAMILY`` stand-in as the worker.

    With ``interrupt``, that exception is raised (from SIGALRM) in the runner's thread
    once the grandchild's pid has been written (the child has read its job; the runner
    waits for its output). Right after the call: the child must be reaped already; the
    grandchild gets ``_GONE_BUDGET_S`` to disappear.
    """
    runner = _runner()
    child_file, grandchild_file = tmp_path / "child.pid", tmp_path / "grandchild.pid"
    monkeypatch.setattr(
        runner,
        "WORKER_ARGV",
        (sys.executable, "-c", _FAMILY, str(child_file), str(grandchild_file), mode),
    )
    monkeypatch.setattr(runner, "CONVERSION_TIMEOUT_S", timeout_s)

    def raise_once_started(signum: int, frame: FrameType | None) -> None:
        if interrupt is not None and _read_pid(grandchild_file) is not None:
            raise interrupt("raised by the test while the runner waits")
        signal.setitimer(signal.ITIMER_REAL, 0.05)

    previous = signal.signal(signal.SIGALRM, raise_once_started)
    started = time.monotonic()
    try:
        if interrupt is not None:
            signal.setitimer(signal.ITIMER_REAL, 0.05)
        try:
            outcome = _outcome_of(lambda: runner.run_conversion(stored, "pdf", out_dir, _options()))
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        elapsed = time.monotonic() - started
        child, grandchild = _read_pid(child_file), _read_pid(grandchild_file)
        child_left = child is not None and _alive(child)
        grandchild_left = grandchild is not None and not _gone_within(grandchild, _GONE_BUDGET_S)
    finally:
        _kill_family(child_file, grandchild_file)
    return _FamilyRun(
        outcome=outcome,
        elapsed=elapsed,
        child_seen=child is not None,
        child_left=child_left,
        grandchild_seen=grandchild is not None,
        grandchild_left=grandchild_left,
    )


# ---------------------------------------------------------------------------
# The child's own session and process group
# ---------------------------------------------------------------------------


def test_converters_runner_process_group_child_started_with_start_new_session(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path
) -> None:
    """The child's start carries ``start_new_session=True`` (the bool itself), and the
    conversion still returns the child's result."""
    runner = _runner()
    fake = _patch_popen(monkeypatch, _FakeChild(out_dir))

    result = runner.run_conversion(stored, "pdf", out_dir, _options())

    [call] = fake.calls
    assert (call.kwargs.get("start_new_session") is True, result) == (
        True,
        runner.ConversionResult(page_count=2, token_estimate=40, derived_bytes=0),
    )


def test_converters_runner_process_group_real_child_leads_its_own_session_and_group(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stored: Path, out_dir: Path
) -> None:
    """A real child started by the runner finds itself the leader of a new session and of
    a new process group: its session id and its group id are its own pid."""
    runner = _runner()
    report = tmp_path / "session.json"
    monkeypatch.setattr(
        runner, "WORKER_ARGV", (sys.executable, "-c", _SESSION_REPORTER, str(report))
    )

    result = runner.run_conversion(stored, "pdf", out_dir, _options())

    ids = json.loads(report.read_text(encoding="ascii"))
    assert (result, ids) == (
        runner.ConversionResult(page_count=2, token_estimate=40, derived_bytes=0),
        {"pid": ids["pid"], "pgid": ids["pid"], "sid": ids["pid"]},
    )


# ---------------------------------------------------------------------------
# A grandchild never outlives a timeout, an overflow or an exception
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mode",
    ["sleep", "eof", "exit"],
    ids=[
        "child-and-grandchild-hold-stdout",
        "exit-wait-after-eof",
        "child-exited-grandchild-holds-stdout",
    ],
)
def test_converters_runner_process_group_timeout_kills_the_grandchild(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stored: Path,
    out_dir: Path,
    caplog: pytest.LogCaptureFixture,
    mode: str,
) -> None:
    """A child that forks a grandchild sleeping 60 s, then runs past CONVERSION_TIMEOUT_S
    (2 s here): while both hold stdout (the read deadline), after both closed it (the exit
    wait after EOF), or after the child wrote a valid line and exited by itself while the
    grandchild holds stdout (the read runs to the deadline). conversion_timeout long
    before the sleeps end; the child is reaped, the grandchild is gone shortly after,
    nothing is logged."""
    caplog.set_level(logging.DEBUG)

    run = _run_family(monkeypatch, tmp_path, stored, out_dir, mode=mode, timeout_s=2.0)

    assert (
        run.outcome,
        run.elapsed < 30.0,
        run.child_seen,
        run.child_left,
        run.grandchild_seen,
        run.grandchild_left,
        _admino_records(caplog),
    ) == (("error", "conversion_timeout"), True, True, False, True, False, [])


def test_converters_runner_process_group_overflow_kills_the_grandchild(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stored: Path,
    out_dir: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A child that forks a grandchild sleeping 60 s (holding stdout), then writes more
    than MAX_RESULT_BYTES and sleeps: processing_error at once (long before the 30 s
    CONVERSION_TIMEOUT_S), the child reaped, the grandchild gone shortly after, nothing
    logged."""
    caplog.set_level(logging.DEBUG)

    run = _run_family(monkeypatch, tmp_path, stored, out_dir, mode="flood", timeout_s=30.0)

    assert (
        run.outcome,
        run.elapsed < 15.0,
        run.child_seen,
        run.child_left,
        run.grandchild_seen,
        run.grandchild_left,
        _admino_records(caplog),
    ) == (("error", "processing_error"), True, True, False, True, False, [])


@pytest.mark.parametrize(
    "interrupt", [KeyboardInterrupt, _InterruptedError], ids=["keyboard-interrupt", "runtime-error"]
)
def test_converters_runner_process_group_exception_while_waiting_kills_the_grandchild(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stored: Path,
    out_dir: Path,
    caplog: pytest.LogCaptureFixture,
    interrupt: type[BaseException],
) -> None:
    """A KeyboardInterrupt, or any other exception (a RuntimeError), raised while the
    runner waits for a child that forked a grandchild (both sleep 60 s holding stdout;
    CONVERSION_TIMEOUT_S 30 s): the exception propagates unchanged, the child is reaped,
    the grandchild is gone shortly after, nothing is logged."""
    caplog.set_level(logging.DEBUG)

    run = _run_family(
        monkeypatch,
        tmp_path,
        stored,
        out_dir,
        mode="sleep",
        timeout_s=30.0,
        interrupt=interrupt,
    )

    assert (
        run.outcome,
        run.elapsed < 15.0,
        run.child_seen,
        run.child_left,
        run.grandchild_seen,
        run.grandchild_left,
        _admino_records(caplog),
    ) == (("raised", interrupt.__name__), True, True, False, True, False, [])


# ---------------------------------------------------------------------------
# The group is killed only while the child is unreaped
# ---------------------------------------------------------------------------


def test_converters_runner_process_group_killed_only_while_the_child_is_unreaped(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path, killpg: _Killpg
) -> None:
    """A child that exits by itself and is reaped (a valid result, a refusal, a crash with
    exit status 1) gets no ``os.killpg`` at all. A child still running at
    CONVERSION_TIMEOUT_S (2 s; it sleeps 60 s) gets exactly ``os.killpg(child.pid,
    SIGKILL)`` while its Popen.returncode is still None and its pid still exists. Every
    child is reaped when the call returns; the outcome codes are unchanged."""
    runner = _runner()
    monkeypatch.setattr(runner, "CONVERSION_TIMEOUT_S", 2.0)
    fakes = {
        "result": _FakeChild(out_dir),
        "refusal": _FakeChild(out_dir, stdout=_REFUSAL_LINE),
        "crash": _FakeChild(out_dir, returncode=1, stdout=b"Traceback: /srv/x/Lohn.pdf\n"),
        "timeout": _FakeChild(out_dir, sleep=60.0),
    }
    seen: dict[str, tuple[object, ...]] = {}

    try:
        for case, fake in fakes.items():
            killpg.started.clear()
            killpg.calls.clear()
            _track_popen(monkeypatch, killpg, fake)
            outcome = _outcome_of(lambda: runner.run_conversion(stored, "pdf", out_dir, _options()))
            [child] = killpg.started
            reaped = child.returncode is not None and not _alive(child.pid)
            seen[case] = (outcome, killpg.seen_by(child), reaped)
    finally:
        for fake in fakes.values():
            _kill_leftover(fake.pid_file())

    assert seen == {
        "result": (
            ("result", runner.ConversionResult(page_count=2, token_estimate=40, derived_bytes=0)),
            [],
            True,
        ),
        "refusal": (("error", "password_protected"), [], True),
        "crash": (("error", "processing_error"), [], True),
        "timeout": (("error", "conversion_timeout"), [(True, signal.SIGKILL, None, True)], True),
    }


def test_converters_runner_process_group_overflow_by_an_exited_child_kills_its_group_first(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path, killpg: _Killpg
) -> None:
    """A child that writes 8192 bytes (over the cap) and exits 0 before the runner reads
    anything (it never reads its job): when the runner passes the cap the child is an
    unreaped zombie, so its group gets ``os.killpg(child.pid, SIGKILL)`` (returncode still
    None, the pid still there) before it is reaped. The real signal goes out: on macOS a
    group holding only zombies answers EPERM, and the outcome must still be
    processing_error, the child reaped."""
    runner = _runner()
    fake = _FakeChild(out_dir, read_stdin=False, stdout=b"x" * 8192)
    _track_popen(monkeypatch, killpg, fake, zombie_first=True)

    try:
        outcome = _outcome_of(lambda: runner.run_conversion(stored, "pdf", out_dir, _options()))
        [child] = killpg.started
        reaped = child.returncode is not None and not _alive(child.pid)
    finally:
        _kill_leftover(fake.pid_file())

    assert (outcome, killpg.seen_by(child), reaped) == (
        ("error", "processing_error"),
        [(True, signal.SIGKILL, None, True)],
        True,
    )


def test_converters_runner_process_group_process_lookup_error_is_ignored(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path, killpg: _Killpg
) -> None:
    """``os.killpg`` raising ProcessLookupError (the group is gone: the child died just
    before) on a timeout: the call still ends with conversion_timeout, not the lookup
    error, and the child is reaped."""
    runner = _runner()
    monkeypatch.setattr(runner, "CONVERSION_TIMEOUT_S", 2.0)
    killpg.lookup_error = True
    fake = _FakeChild(out_dir, sleep=60.0)
    _track_popen(monkeypatch, killpg, fake)

    try:
        outcome = _outcome_of(lambda: runner.run_conversion(stored, "pdf", out_dir, _options()))
        [child] = killpg.started
        reaped = child.returncode is not None and not _alive(child.pid)
    finally:
        _kill_leftover(fake.pid_file())

    assert (outcome, [call[:2] for call in killpg.seen_by(child)], reaped) == (
        ("error", "conversion_timeout"),
        [(True, signal.SIGKILL)],
        True,
    )


# ---------------------------------------------------------------------------
# docs/SECURITY.md
# ---------------------------------------------------------------------------

_PROCESS_GROUP_RE: Final = re.compile(r"\bprocess[\s-]+group\b", re.IGNORECASE)
_SETSID_RE: Final = re.compile(r"\bsetsid\b")
_DESCENDANTS_RE: Final = re.compile(r"\b(?:grandchild\w*|orphan\w*)", re.IGNORECASE)
_KILL_RE: Final = re.compile(r"\b(?:sig)?kill\w*", re.IGNORECASE)
_GROUP_RE: Final = re.compile(r"\bgroups?\b", re.IGNORECASE)
_TIMEOUT_RE: Final = re.compile(
    r"\btime[\s-]?outs?\b|\btimes\s+out\b|\bconversion_timeout\b|\bdeadline\b", re.IGNORECASE
)
_OVERFLOW_RE: Final = re.compile(
    r"\boverflow\w*|\bflood\w*|\bcap\b|\boutput\b|\bstdout\b|\bprocessing_error\b",
    re.IGNORECASE,
)
_STALE_RE: Final = re.compile(
    r"\bgrandchildren\b(?:\s+of\s+a\s+killed\s+conversion)?\s+"
    r"(?:are\s+not|aren['" + chr(0x2019) + r"]t|are\s+never)\s+killed\b",
    re.IGNORECASE,
)


def test_converters_runner_process_group_security_doc_says_the_group_is_killed() -> None:
    """A SECURITY.md block names the process group and the grandchildren, says in one
    sentence that the group is killed on a timeout and an output overflow, and names
    ``setsid`` (a process that leaves the group keeps running); no sentence anywhere in
    SECURITY.md still says the grandchildren are not killed."""
    blocks = _blocks(_SECURITY)
    stated = [
        block
        for block in blocks
        if _PROCESS_GROUP_RE.search(block)
        and _DESCENDANTS_RE.search(block)
        and _SETSID_RE.search(block)
        and any(
            _KILL_RE.search(sentence)
            and _GROUP_RE.search(sentence)
            and _TIMEOUT_RE.search(sentence)
            and _OVERFLOW_RE.search(sentence)
            for sentence in _SENTENCE_END_RE.split(block)
        )
    ]
    stale = [
        sentence
        for block in blocks
        for sentence in _SENTENCE_END_RE.split(" ".join(block.split()))
        if _STALE_RE.search(sentence)
    ]

    assert (stated != [], stale) == (True, [])
