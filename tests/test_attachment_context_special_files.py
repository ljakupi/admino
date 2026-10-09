"""Tests for ``admino.attachment_context``: a part that isn't a regular file (GH-294).

Issue #294, test gap (#189 review note 3, Decision 10): the attachment reader refuses
a part name that isn't a regular file, a directory or a FIFO planted at the part's
path, without reading it. ``read_content`` opens every file of ``<id>.d`` with
``O_NONBLOCK`` (a planted FIFO never blocks the open) and refuses anything but a
regular file before its first read.

What these tests pin down:

- A FIFO or a directory planted at a text part's name (the second of two):
  ``read_content`` raises ``AttachmentUnavailableError`` with the fixed message.
- Nothing is read from the planted object: every ``read`` of a file the reader opened
  (a spy on ``os.fdopen``'s file objects) is a regular file's (the manifest's and the
  first part's, so the spy is live), and the bytes a writer left in the FIFO are all
  still in it after the call.
- The same files with a regular second part read fine first (the control).

These pass on the current code by design (Decision 10). The FIFO case is proven
against the mutant that drops the ``S_ISREG`` check in ``_read_file``: the FIFO's
pending text then becomes a part (or is consumed). A directory is refused before any
read with or without that check (a file object on a directory's descriptor raises
``IsADirectoryError`` when it is made), so the directory case guards the outcome.

Decision 12, the reader leaks no descriptor on a refusal: a directory or a FIFO planted
at the manifest's or at a part's name, read ``_READS`` times, is refused every time,
and the process's open-descriptor count (the entries of ``/proc/self/fd`` on Linux,
``/dev/fd`` on macOS) is the same after those reads as before them. The baseline is
taken after one warm-up refusal (anything opened once, lazily, is open by then), with
the cycle collector run first and kept off until the second count, so no unrelated
object's descriptor closes in between. Today a file object made on a directory's
descriptor raises without closing it, so each refused directory leaks the descriptor
``os.open`` returned (RED). A FIFO is closed by the reader's ``with`` block today: its
two cells guard a fix that checks the raw descriptor and forgets to close it.
"""

from __future__ import annotations

import gc
import json
import os
import stat
import sys
import uuid
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import attachment_context, chats, models
from admino.converters import common
from tests.db_fakes import ORG_ID

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

_UNAVAILABLE: Final = "Attachment content unavailable."
_FIRST: Final = "part-0001.txt"
_PLANTED: Final = "part-0002.txt"
_FIRST_TEXT: Final = "Quarterly figures, first part."
_SECOND_TEXT: Final = "Quarterly figures, second part."
# What a writer left in the planted FIFO: the reader must never take it.
_FIFO_BYTES: Final = b"PLANTED-fifo-text-5c1e"
# One entry per descriptor the process has open (the listing's own included).
_FD_DIR: Final = "/proc/self/fd" if sys.platform.startswith("linux") else "/dev/fd"
# Refused reads per leak check: a leak of one descriptor per read shows as +20.
_READS: Final = 20


def _file_type(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISDIR(mode):
        return "directory"
    return "other"


class _ReadSpy:
    """Wraps a file object ``os.fdopen`` made: records the file type at every read."""

    def __init__(self, file: Any, reads: list[str]) -> None:
        self._file = file
        self._reads = reads

    def __enter__(self) -> _ReadSpy:
        self._file.__enter__()
        return self

    def __exit__(self, *exc_info: Any) -> Any:
        return self._file.__exit__(*exc_info)

    def fileno(self) -> int:
        fd: int = self._file.fileno()
        return fd

    def read(self, *args: Any) -> Any:
        self._reads.append(_file_type(os.fstat(self._file.fileno()).st_mode))
        return self._file.read(*args)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._file, name)


def _pending(fd: int) -> bytes:
    """What is still in the FIFO (non-blocking: nothing left is b"")."""
    try:
        return os.read(fd, 4096)
    except BlockingIOError:
        return b""


def _spy_reads(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record the file type of every read through ``os.fdopen``'s file objects."""
    reads: list[str] = []
    real = os.fdopen

    def spying(fd: int, *args: Any, **kwargs: Any) -> _ReadSpy:
        return _ReadSpy(real(fd, *args, **kwargs), reads)

    monkeypatch.setattr(os, "fdopen", spying)
    return reads


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    path = tmp_path / "attachments"
    (path / str(ORG_ID)).mkdir(parents=True)
    return path


@pytest.fixture()
def fds() -> Iterator[list[int]]:
    """File descriptors a test opened (the FIFO's ends), closed afterwards."""
    opened: list[int] = []
    yield opened
    for fd in opened:
        os.close(fd)


def _attachment() -> chats.ActiveAttachment:
    return chats.ActiveAttachment(
        id=uuid.uuid4(), filename="figures.txt", kind="txt", page_count=None, token_estimate=12
    )


def _write_derived(root: Path, attachment: chats.ActiveAttachment) -> Path:
    """``<root>/<org>/<id>.d`` with a valid two-part text manifest and both part files."""
    directory = root / str(ORG_ID) / f"{attachment.id}.d"
    directory.mkdir()
    manifest = common.Manifest(
        version=1,
        kind="txt",
        page_count=None,
        token_estimate=12,
        parts=[
            common.TextPart(type="text", file=_FIRST, page=None, tokens=6),
            common.TextPart(type="text", file=_PLANTED, page=None, tokens=6),
        ],
    )
    (directory / _FIRST).write_text(_FIRST_TEXT, encoding="utf-8")
    (directory / _PLANTED).write_text(_SECOND_TEXT, encoding="utf-8")
    raw = json.dumps(json.loads(manifest.model_dump_json())).encode("utf-8")
    (directory / common.MANIFEST_NAME).write_bytes(raw)
    return directory


def _control(root: Path, attachment: chats.ActiveAttachment) -> None:
    """With a regular second part, the files read: both parts, in order."""
    content = attachment_context.read_content(root, ORG_ID, attachment)
    assert content.parts == (
        models.TextContent(text=_FIRST_TEXT),
        models.TextContent(text=_SECOND_TEXT),
    )


def test_attachment_context_fifo_at_a_part_name_is_refused_unread(
    root: Path, fds: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A FIFO at the second part's name, its writer open with bytes pending: refused,
    no read on anything but a regular file, and the pending bytes are all still there."""
    attachment = _attachment()
    directory = _write_derived(root, attachment)
    _control(root, attachment)
    fifo = directory / _PLANTED
    fifo.unlink()
    os.mkfifo(fifo)
    holder = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    fds.append(holder)
    writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
    fds.append(writer)
    os.write(writer, _FIFO_BYTES)
    reads = _spy_reads(monkeypatch)

    with pytest.raises(attachment_context.AttachmentUnavailableError) as caught:
        attachment_context.read_content(root, ORG_ID, attachment)

    assert (str(caught.value), set(reads), _pending(holder)) == (
        _UNAVAILABLE,
        {"regular"},
        _FIFO_BYTES,
    )


def test_attachment_context_directory_at_a_part_name_is_refused_unread(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory (holding a readable file) at the second part's name: refused, and no
    read on anything but a regular file."""
    attachment = _attachment()
    directory = _write_derived(root, attachment)
    _control(root, attachment)
    planted = directory / _PLANTED
    planted.unlink()
    planted.mkdir()
    (planted / "inner.txt").write_text(_SECOND_TEXT, encoding="utf-8")
    reads = _spy_reads(monkeypatch)

    with pytest.raises(attachment_context.AttachmentUnavailableError) as caught:
        attachment_context.read_content(root, ORG_ID, attachment)

    assert (str(caught.value), set(reads)) == (_UNAVAILABLE, {"regular"})


# --- Decision 12: no descriptor leaks on a refusal --------------------------------

# The names a planted object takes: the manifest's, and the second text part's.
_NAMES: Final = [
    pytest.param(common.MANIFEST_NAME, id="manifest"),
    pytest.param(_PLANTED, id="part"),
]


def _plant(path: Path, planted: str) -> None:
    """Replace the regular file at ``path`` with a directory or a FIFO (no writer)."""
    path.unlink()
    if planted == "directory":
        path.mkdir()
    else:
        os.mkfifo(path)


def _descriptor_count() -> int:
    """How many descriptors the process has open (the listing's own counts each time)."""
    return len(os.listdir(_FD_DIR))


def _refusal(root: Path, attachment: chats.ActiveAttachment) -> str:
    """One ``read_content`` call that must be refused: the refusal's message."""
    with pytest.raises(attachment_context.AttachmentUnavailableError) as caught:
        attachment_context.read_content(root, ORG_ID, attachment)
    return str(caught.value)


def _count_around_refusals(
    root: Path, attachment: chats.ActiveAttachment
) -> tuple[list[str], int, int]:
    """The ``_READS`` refusals' messages and the descriptor counts before and after them.

    One warm-up refusal comes first, so anything opened lazily on the first read is open
    for both counts. The cycle collector runs before the baseline and stays off until the
    second count, so no unrelated object's descriptor is closed in between; nothing but
    the refusals runs between the two counts.
    """
    _refusal(root, attachment)
    gc.collect()
    collecting = gc.isenabled()
    gc.disable()
    try:
        before = _descriptor_count()
        messages = [_refusal(root, attachment) for _ in range(_READS)]
        after = _descriptor_count()
    finally:
        if collecting:
            gc.enable()
    return messages, before, after


@pytest.mark.parametrize("name", _NAMES)
def test_attachment_context_directory_refusal_leaks_no_descriptor(root: Path, name: str) -> None:
    """A directory at the manifest's or a part's name, read 20 times: every read is
    refused and the process's open-descriptor count is unchanged."""
    attachment = _attachment()
    directory = _write_derived(root, attachment)
    _control(root, attachment)
    _plant(directory / name, "directory")

    messages, before, after = _count_around_refusals(root, attachment)

    assert (messages, after) == ([_UNAVAILABLE] * _READS, before)


@pytest.mark.parametrize("name", _NAMES)
def test_attachment_context_fifo_refusal_leaks_no_descriptor(root: Path, name: str) -> None:
    """A FIFO at the manifest's or a part's name, read 20 times: every read is refused
    and the process's open-descriptor count is unchanged."""
    attachment = _attachment()
    directory = _write_derived(root, attachment)
    _control(root, attachment)
    _plant(directory / name, "fifo")

    messages, before, after = _count_around_refusals(root, attachment)

    assert (messages, after) == ([_UNAVAILABLE] * _READS, before)
