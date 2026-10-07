"""Tests for ``admino.attachment_processing`` (GH-187 contract §2 P1 to P5, §3.7;
GH-188 contract §6).

Issue #187, "Processing": status ``uploaded -> processing -> ready | failed(reason)``,
processed asynchronously on a bounded worker pool (Decision 7: 2 workers, after the
upload answered 201; at startup, files a restart left ``processing`` go back to
``uploaded`` and are queued again). Decision 6: a processor that reports more pages
than the platform's ``files.max_pages_per_file`` fails the file with
``too_many_pages``. Issue #188 ("Token estimate & storage", "From #187 — Page
limit", Decisions 2, 3, 11, 12): the default processor converts the stored file in
a worker process (``convert_stored_file``), the estimated token count is stored
with the ``ready`` outcome, and the derived artifacts (``<id>.d``) go whenever the
file doesn't end ``ready``.

What these tests pin down:

- Names: ``MAX_WORKERS == 2``; ``ProcessedFile`` a frozen dataclass whose
  ``page_count`` and ``token_estimate`` default to None; ``ProcessingJob`` a
  frozen dataclass ``(filename, render_dpi, max_pages)``;
  ``ProcessingFailedError(reason)`` keeps its ``reason``; ``convert_stored_file``
  is the default processor of ``process_attachment`` and of ``ProcessingPool``
  (whose ``workers`` defaults to ``MAX_WORKERS``).
- ``process_attachment(pool, root, attachment_id, org_id, *, processor)``:
  - P1' is a compare-and-set (``RETURNING kind, filename``): a row that isn't
    ``uploaded`` (processing, ready, failed), another org's id and a row that is
    gone return None after P1' alone; the processor never runs, the platform
    settings aren't read and the row is unchanged.
  - The processor runs in a worker thread (not the event loop's thread) with
    ``<root>/<org_id>/<attachment_id>``, the kind P1' returned and a
    ``ProcessingJob`` whose filename is the one P1' returned and whose
    ``render_dpi`` / ``max_pages`` come from the STORED platform settings
    (``files.render_dpi``, ``files.max_pages_per_file``), read exactly once and
    before the processor runs; the row is ``processing`` meanwhile.
  - Success: P2', ``ready`` with the processor's ``page_count`` and
    ``token_estimate`` (None stays NULL, 0 stays 0). ``ProcessingFailedError(code)``:
    P3 with that code. Any other exception: P3 ``processing_error``, logged at
    WARNING or above by class name only (the exception's message, holding a file
    name and a path, reaches no record, no traceback). A page count above the
    platform limit (the same settings read): P3 ``too_many_pages``; equal to it:
    ready.
  - Derived artifacts: after every P3 (a ProcessingFailedError, another
    exception, the too_many_pages post-check) and after a P2' that matched no row
    (the row was deleted while the processor ran), ``<id>.d`` is gone and the
    stored ``<id>`` is kept; a stored ``ready`` keeps ``<id>.d``.
  - A row deleted while the processor runs: no error, nothing re-created.
  - The exact statements: [P1', P2'] or [P1', P3] with their bind values; the
    return value is the final status.
- ``convert_stored_file(path, kind, job)``: ``verify_stored_file`` first (a
  missing, corrupted or password-protected stored file fails with its code and
  ``runner.run_conversion`` is never called, so no worker starts); then
  ``runner.run_conversion(path, kind, <path>.d, ConversionOptions(filename,
  render_dpi, max_pages))`` with the job's values; ``ConversionError(code)``
  becomes ``ProcessingFailedError(code)`` for each of the eight codes; the
  ``ConversionResult`` becomes ``ProcessedFile(page_count, token_estimate)``.
- ``verify_stored_file(path, kind)``: a missing file fails with
  ``file_missing``; a stored file ``detect_kind`` refuses fails with that
  refusal's reason (a stored ``txt`` holding the C1 control NEL U+0085 is
  ``unsupported_type``); bytes of another kind fail with ``corrupted_file``; every
  kind's valid bytes pass with ``ProcessedFile(page_count=None)``. The stored
  file has no extension (it is named by its id): the recorded kind's canonical
  extension picks among the text kinds (csv, md, txt).
- ``ProcessingPool``: ``submit`` returns None at once without running anything
  and never raises (a broken pool object included, the pool keeps working);
  at most ``workers`` processor calls run at once (default 2); ``join()`` waits
  for every submitted job and also returns when called in the loop turn in which
  the last job ended; ``close()`` cancels pending and running jobs (no
  pending job's processor runs afterwards, a cancelled running job writes no
  outcome); the given processor is the one used; without one, the pool converts
  the stored file.
- ``recover(pool, processing, root)``: P4 then P5, then one ``submit(pool, root,
  id, org_id)`` per ``uploaded`` row in ``created_at, id`` order (any org);
  returns the count; ``ready`` and ``failed`` rows are untouched; a row left
  ``processing`` is processed again.

The module is imported lazily (fixture ``ap``), so this file collects before it
exists and every test fails on its own; ``admino.converters`` (common, runner) is
imported inside the tests too. ``runner.run_conversion`` is replaced by a recorder
here (no worker process starts in this file; the real worker runs in
tests/test_attachment_conversion_flow.py). Fixture files are built in ``tmp_path``
with the stdlib only (struct, zlib, zipfile): no binary in the repo. Threads that
block in a processor wait on a ``threading.Event`` with a timeout and are always
released in ``finally``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import inspect
import io
import logging
import os
import re
import struct
import threading
import time
import uuid
import zipfile
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import scoped_settings
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, norm

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType

_REAL_SLEEP = asyncio.sleep
_WAIT_S: Final = 5.0
# A blocked processor thread outlives every wait above, so a pool that waits for it
# instead of cancelling it fails the wait.
_GATE_S: Final = 10.0

# What a crashing processor's message carries: a file name and a path. Neither may
# reach a log record.
_LEAK_NAME: Final = "Quarterly-salaries-2026.xlsx"
_LEAK_DIR: Final = "/srv/private-share-marker"

# The eight conversion failure codes (GH-188 contract §3, Decision 12).
_CONVERSION_FAILURES: Final = (
    "corrupted_file",
    "password_protected",
    "too_many_pages",
    "archive_too_large",
    "image_too_large",
    "text_too_large",
    "conversion_timeout",
    "processing_error",
)

# --- Contract forms (GH-187 §2; P1' and P2' from GH-188 §6) ------------------------

_P1: Final = norm(
    "UPDATE attachments SET status = 'processing', updated_at = now() "
    "WHERE id = $1 AND org_id = $2 AND status = 'uploaded' RETURNING kind, filename"
)
_P2: Final = norm(
    "UPDATE attachments SET status = 'ready', page_count = $3, token_estimate = $4, "
    "updated_at = now() WHERE id = $1 AND org_id = $2 AND status = 'processing'"
)
_P3: Final = norm(
    "UPDATE attachments SET status = 'failed', failure_reason = $3, updated_at = now() "
    "WHERE id = $1 AND org_id = $2 AND status = 'processing'"
)
_P4: Final = norm(
    "UPDATE attachments SET status = 'uploaded', updated_at = now() WHERE status = 'processing'"
)
_P5: Final = norm(
    "SELECT id, org_id FROM attachments WHERE status = 'uploaded' ORDER BY created_at, id"
)

# --- Fixture bytes -----------------------------------------------------------------

_PDF_HEAD: Final = (
    b"%PDF-1.7\n%"
    + bytes([0xE2, 0xE3, 0xCF, 0xD3])
    + b"\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
)
_PDF: Final = _PDF_HEAD + b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
_PDF_ENCRYPTED: Final = _PDF_HEAD + b"trailer\n<< /Root 1 0 R /Encrypt 5 0 R >>\n%%EOF\n"
_PDF_TRUNCATED: Final = _PDF_HEAD + b"2 0 obj\n<< /Type /Pages"
_JPEG: Final = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"
_CFB: Final = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504
_EXECUTABLE: Final = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + b"\x00" * 48
_CSV: Final = b"name,amount\nalpha,1\nbeta,2\n"
_MD: Final = b"# Notes\n\n- one\n- two\n"
_TXT: Final = b"plain text, nothing else\n"
# Text with a C1 control: NEL (U+0085, UTF-8 0xC2 0x85) between two lines.
_TXT_NEL: Final = b"line one" + chr(0x85).encode("utf-8") + b"line two\n"


def _png() -> bytes:
    """A 33-byte PNG: signature plus an IHDR chunk (1x1, RGB)."""
    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    chunk = b"IHDR" + header
    return (
        b"\x89PNG\r\n\x1a\n"
        + struct.pack(">I", len(header))
        + chunk
        + struct.pack(">I", zlib.crc32(chunk))
    )


def _webp() -> bytes:
    """A RIFF/WEBP whose RIFF size matches the file."""
    payload = b"WEBP" + b"VP8 " + struct.pack("<I", 4) + b"\x00" * 4
    return b"RIFF" + struct.pack("<I", len(payload)) + payload


def _ooxml(part: str) -> bytes:
    """A minimal OOXML package: [Content_Types].xml plus one part (word/ or xl/)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as package:
        package.writestr("[Content_Types].xml", "<Types/>")
        package.writestr(part, "<document/>")
    return buffer.getvalue()


_VALID: Final[dict[str, bytes]] = {
    "pdf": _PDF,
    "docx": _ooxml("word/document.xml"),
    "xlsx": _ooxml("xl/workbook.xml"),
    "csv": _CSV,
    "txt": _TXT,
    "md": _MD,
    "png": _png(),
    "jpeg": _JPEG,
    "webp": _webp(),
}


# --- Fixtures and helpers ----------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _World:
    """Two orgs, each with a member and a chat."""

    chat_id: uuid.UUID
    other_chat_id: uuid.UUID


@pytest.fixture()
def ap() -> ModuleType:
    """The module under test, imported lazily (it doesn't exist before GH-187)."""
    import admino.attachment_processing as module

    return module


@pytest.fixture()
def db() -> FakeDb:
    return FakeDb()


@pytest.fixture()
def world(db: FakeDb) -> _World:
    user_id = db.add_account(org_id=ORG_ID)
    other_user_id = db.add_account(org_id=OTHER_ORG_ID)
    return _World(chat_id=db.add_chat(user_id), other_chat_id=db.add_chat(other_user_id))


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    path = tmp_path / "attachments"
    path.mkdir()
    return path


def _canonical(value: Any) -> Any:
    """A plain uuid.UUID for any UUID (asyncpg's subclass included); others unchanged."""
    return uuid.UUID(int=value.int) if isinstance(value, uuid.UUID) else value


def _store(
    db: FakeDb,
    root: Path,
    chat_id: uuid.UUID,
    data: bytes = _PDF,
    *,
    kind: str = "pdf",
    filename: str = "a.pdf",
    status: str = "uploaded",
    failure_reason: str | None = None,
    page_count: int | None = None,
    created_at: datetime | None = None,
    attachment_id: uuid.UUID | None = None,
    write: bool = True,
) -> uuid.UUID:
    """Seed an attachments row and (unless ``write`` is False) its file on disk."""
    stamp = created_at if created_at is not None else datetime.now(UTC) - timedelta(minutes=5)
    attachment_id = db.add_attachment(
        chat_id,
        attachment_id=attachment_id,
        filename=filename,
        kind=kind,
        size_bytes=max(len(data), 1),
        status=status,
        failure_reason=failure_reason,
        page_count=page_count,
        created_at=stamp,
    )
    if write:
        path = _path_of(db, root, attachment_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return attachment_id


def _org_of(db: FakeDb, attachment_id: uuid.UUID) -> uuid.UUID:
    row = db.attachment_row(attachment_id)
    assert row is not None
    return uuid.UUID(int=row["org_id"].int)


def _path_of(db: FakeDb, root: Path, attachment_id: uuid.UUID) -> Path:
    """Where the contract stores an attachment: <root>/<org_id>/<attachment_id>."""
    return _path_of_id(root, _org_of(db, attachment_id), attachment_id)


def _path_of_id(root: Path, org_id: uuid.UUID, attachment_id: uuid.UUID) -> Path:
    """The same path without a row to read the org from (a deleted row)."""
    return root / str(org_id) / str(attachment_id)


def _state(db: FakeDb, attachment_id: uuid.UUID) -> tuple[Any, Any, Any]:
    """(status, failure_reason, page_count) of a stored row."""
    row = db.attachment_row(attachment_id)
    assert row is not None
    return row["status"], row["failure_reason"], row["page_count"]


def _estimate(db: FakeDb, attachment_id: uuid.UUID) -> Any:
    """The stored row's token_estimate (GH-188, migration 0028)."""
    row = db.attachment_row(attachment_id)
    assert row is not None
    return row["token_estimate"]


def _derived_dir(db: FakeDb, root: Path, attachment_id: uuid.UUID) -> Path:
    """Where the derived artifacts live (GH-188 Decision 3): <root>/<org_id>/<id>.d."""
    return _path_of(db, root, attachment_id).with_name(f"{attachment_id}.d")


def _plant_derived(directory: Path) -> None:
    """A derived-artifacts directory as a conversion leaves it: one part and a manifest."""
    directory.mkdir()
    (directory / "part-0001.txt").write_text("[a.pdf — page 1]\nplanted", encoding="utf-8")
    (directory / "manifest.json").write_text("{}", encoding="utf-8")


def _gone(path: Path) -> bool:
    """True when nothing (no file, directory or symlink) is left at ``path``."""
    return not path.exists() and not path.is_symlink()


def _attachment_calls(db: FakeDb) -> list[tuple[str, tuple[Any, ...]]]:
    """(normalized SQL, canonical args) of every recorded statement naming attachments."""
    return [
        (call.normalized, tuple(_canonical(arg) for arg in call.args))
        for call in db.calls
        if re.search(r"\battachments\b", call.normalized)
    ]


class _Processor:
    """A sync processor that records each call (path, kind, job, thread) and returns or
    raises. GH-188: a processor takes ``(path, kind, job)``."""

    def __init__(
        self,
        result: Any = None,
        *,
        raises: BaseException | None = None,
        on_call: Callable[[], None] | None = None,
    ) -> None:
        self.result = result
        self.raises = raises
        self.on_call = on_call
        self.calls: list[tuple[Path, str, Any]] = []
        self.threads: list[int] = []

    def __call__(self, path: Path, kind: str, job: Any) -> Any:
        self.calls.append((Path(path), kind, job))
        self.threads.append(threading.get_ident())
        if self.on_call is not None:
            self.on_call()
        if self.raises is not None:
            raise self.raises
        return self.result


class _GatedProcessor:
    """A processor that blocks on a threading.Event; counts active, peak and total calls.

    Built on the event loop's thread: a call made on that thread (a processor run on
    the loop instead of in a worker thread) returns at once instead of blocking the
    loop, so such an implementation fails these tests quickly rather than hanging.
    """

    def __init__(self, result: Any) -> None:
        self.result = result
        self.gate = threading.Event()
        self._lock = threading.Lock()
        self._loop_thread = threading.get_ident()
        self.active = 0
        self.peak = 0
        self.calls = 0
        self.paths: list[Path] = []

    def __call__(self, path: Path, kind: str, job: Any) -> Any:
        with self._lock:
            self.active += 1
            self.calls += 1
            self.peak = max(self.peak, self.active)
            self.paths.append(Path(path))
        try:
            if threading.get_ident() != self._loop_thread:
                self.gate.wait(timeout=_GATE_S)
        finally:
            with self._lock:
                self.active -= 1
        return self.result


async def _until(condition: Callable[[], bool], what: str) -> None:
    """Poll (real sleeps) until the condition holds; fail after _WAIT_S."""
    deadline = time.monotonic() + _WAIT_S
    while not condition():
        if time.monotonic() > deadline:
            pytest.fail(f"timed out waiting for {what}")
        await _REAL_SLEEP(0.01)


def _log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured record, formatted with its traceback (exc_info) if any."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(formatter.format(record) for record in caplog.records)


def _platform_pages_limit(monkeypatch: pytest.MonkeyPatch, db: FakeDb, limit: int) -> None:
    """Seed the platform row with this pages limit; empty the cache so it is read."""
    _platform_settings(monkeypatch, db, max_pages_per_file=limit)


def _platform_settings(monkeypatch: pytest.MonkeyPatch, db: FakeDb, **columns: Any) -> None:
    """Seed the platform row with these columns; empty the cache so it is read."""
    db.add_platform_settings(**columns)
    monkeypatch.setattr(scoped_settings, "_platform_cache", None)


class _SettingsReads:
    """Wraps ``scoped_settings.current_platform_settings`` (the contract's one read):
    counts the calls and answers like the original."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.count = 0
        original = scoped_settings.current_platform_settings

        async def counted(executor: Any) -> Any:
            self.count += 1
            return await original(executor)

        monkeypatch.setattr(scoped_settings, "current_platform_settings", counted)


class _RunConversion:
    """Stands in for ``runner.run_conversion(path, kind, out_dir, options)``: records each
    call, then returns ``result`` or raises ``raises``. No worker process starts."""

    def __init__(self, result: Any = None, *, raises: BaseException | None = None) -> None:
        self.result = result
        self.raises = raises
        self.calls: list[tuple[Path, str, Path, Any]] = []

    def __call__(self, path: Path, kind: str, out_dir: Path, options: Any) -> Any:
        self.calls.append((Path(path), kind, Path(out_dir), options))
        if self.raises is not None:
            raise self.raises
        return self.result


def _patch_run_conversion(monkeypatch: pytest.MonkeyPatch, recorder: _RunConversion) -> None:
    """Replace ``admino.converters.runner.run_conversion`` (looked up at call time)."""
    from admino.converters import runner

    monkeypatch.setattr(runner, "run_conversion", recorder)


def _conversion_result(page_count: int | None, token_estimate: int) -> Any:
    """A ``runner.ConversionResult`` (imported lazily: it doesn't exist before GH-188)."""
    from admino.converters import runner

    return runner.ConversionResult(page_count=page_count, token_estimate=token_estimate)


class _ProcessorCrashError(Exception):
    """An unexpected processor failure: its message names a file and a path."""


# ---------------------------------------------------------------------------
# 1. Names and defaults
# ---------------------------------------------------------------------------


class TestNames:
    def test_attachment_processing_max_workers_is_two(self, ap: ModuleType) -> None:
        assert ap.MAX_WORKERS == 2

    def test_attachment_processing_processed_file_is_frozen_with_no_pages_or_estimate_by_default(
        self, ap: ModuleType
    ) -> None:
        processed = ap.ProcessedFile()
        with pytest.raises(dataclasses.FrozenInstanceError):
            processed.token_estimate = 3  # type: ignore[misc]

        assert (
            dataclasses.is_dataclass(processed),
            [field.name for field in dataclasses.fields(processed)],
            processed.page_count,
            processed.token_estimate,
        ) == (True, ["page_count", "token_estimate"], None, None)

    def test_attachment_processing_processing_job_is_frozen_with_its_three_fields(
        self, ap: ModuleType
    ) -> None:
        job = ap.ProcessingJob(filename="a.pdf", render_dpi=150, max_pages=100)
        with pytest.raises(dataclasses.FrozenInstanceError):
            job.render_dpi = 72  # type: ignore[misc]

        assert (
            [field.name for field in dataclasses.fields(job)],
            (job.filename, job.render_dpi, job.max_pages),
        ) == (["filename", "render_dpi", "max_pages"], ("a.pdf", 150, 100))

    def test_attachment_processing_failed_error_keeps_its_reason(self, ap: ModuleType) -> None:
        error = ap.ProcessingFailedError("x_code")

        assert (isinstance(error, Exception), error.reason) == (True, "x_code")

    def test_attachment_processing_defaults_use_convert_stored_file(self, ap: ModuleType) -> None:
        process = inspect.signature(ap.process_attachment).parameters
        pool = inspect.signature(ap.ProcessingPool).parameters

        assert (
            process["processor"].kind,
            process["processor"].default,
            pool["workers"].kind,
            pool["workers"].default,
            pool["processor"].default,
        ) == (
            inspect.Parameter.KEYWORD_ONLY,
            ap.convert_stored_file,
            inspect.Parameter.KEYWORD_ONLY,
            ap.MAX_WORKERS,
            ap.convert_stored_file,
        )


# ---------------------------------------------------------------------------
# 2. process_attachment: the compare-and-set (P1)
# ---------------------------------------------------------------------------


class TestCompareAndSet:
    @pytest.mark.parametrize(
        ("status", "failure_reason"),
        [
            pytest.param("processing", None, id="processing"),
            pytest.param("ready", None, id="ready"),
            pytest.param("failed", "corrupted_file", id="failed"),
        ],
    )
    async def test_attachment_processing_row_not_uploaded_is_left_alone(
        self,
        ap: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        status: str,
        failure_reason: str | None,
    ) -> None:
        attachment_id = _store(
            db, root, world.chat_id, status=status, failure_reason=failure_reason
        )
        before = db.attachment_row(attachment_id)
        processor = _Processor(ap.ProcessedFile())
        db.calls.clear()

        result = await ap.process_attachment(
            db.pool, root, attachment_id, ORG_ID, processor=processor
        )

        assert (result, processor.calls, db.attachment_row(attachment_id)) == (None, [], before)
        assert [call.normalized for call in db.calls] == [_P1]

    async def test_attachment_processing_other_orgs_id_is_left_alone(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        """The other org's uploaded row, asked for under this org: P1 matches nothing."""
        attachment_id = _store(db, root, world.other_chat_id)
        before = db.attachment_row(attachment_id)
        processor = _Processor(ap.ProcessedFile())
        db.calls.clear()

        result = await ap.process_attachment(
            db.pool, root, attachment_id, ORG_ID, processor=processor
        )

        assert (result, processor.calls, db.attachment_row(attachment_id)) == (None, [], before)
        assert [call.normalized for call in db.calls] == [_P1]

    async def test_attachment_processing_deleted_row_returns_none(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        attachment_id = _store(db, root, world.chat_id)
        del db.attachments[attachment_id]
        processor = _Processor(ap.ProcessedFile())
        db.calls.clear()

        result = await ap.process_attachment(
            db.pool, root, attachment_id, ORG_ID, processor=processor
        )

        assert (result, processor.calls, db.attachment_row(attachment_id)) == (None, [], None)
        assert [call.normalized for call in db.calls] == [_P1]


# ---------------------------------------------------------------------------
# 3. process_attachment: running the processor and the outcome (P2, P3)
# ---------------------------------------------------------------------------


class TestProcess:
    async def test_attachment_processing_success_marks_ready(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        attachment_id = _store(db, root, world.chat_id)

        result = await ap.process_attachment(
            db.pool, root, attachment_id, ORG_ID, processor=_Processor(ap.ProcessedFile())
        )

        assert (result, _state(db, attachment_id)) == ("ready", ("ready", None, None))

    async def test_attachment_processing_page_count_is_stored(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        attachment_id = _store(db, root, world.chat_id)

        result = await ap.process_attachment(
            db.pool,
            root,
            attachment_id,
            ORG_ID,
            processor=_Processor(ap.ProcessedFile(page_count=7)),
        )

        assert (result, _state(db, attachment_id)) == ("ready", ("ready", None, 7))

    async def test_attachment_processing_processor_gets_stored_path_and_kind_in_a_thread(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        """The path is <root>/<org>/<id>, the kind is the row's (P1' RETURNING kind), the
        job carries the row's filename and the (default) platform settings, and the call
        runs in a worker thread, not on the event loop's thread."""
        attachment_id = _store(db, root, world.chat_id, _CSV, kind="csv", filename="ledger.csv")
        processor = _Processor(ap.ProcessedFile())

        await ap.process_attachment(db.pool, root, attachment_id, ORG_ID, processor=processor)

        assert processor.calls == [
            (
                root / str(ORG_ID) / str(attachment_id),
                "csv",
                ap.ProcessingJob(filename="ledger.csv", render_dpi=150, max_pages=100),
            )
        ]
        assert processor.threads[0] != threading.get_ident()

    async def test_attachment_processing_job_comes_from_p1_filename_and_stored_platform_settings(
        self,
        ap: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The stored platform row (not a constant, not the defaults) gives render_dpi
        and max_pages; the filename is the row's, as P1' returned it."""
        _platform_settings(monkeypatch, db, render_dpi=217, max_pages_per_file=37)
        filename = "Bilanz 2026 — Entwurf (v2) é.pdf"
        attachment_id = _store(db, root, world.chat_id, filename=filename)
        processor = _Processor(ap.ProcessedFile())

        await ap.process_attachment(db.pool, root, attachment_id, ORG_ID, processor=processor)

        assert [job for _, _, job in processor.calls] == [
            ap.ProcessingJob(filename=filename, render_dpi=217, max_pages=37)
        ]

    async def test_attachment_processing_platform_settings_read_once_before_the_processor(
        self,
        ap: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A row P1' doesn't claim reads no settings. A claimed row: exactly one read,
        made before the processor runs; the page check after it reuses that read (a
        page count over the limit doesn't read again)."""
        _platform_pages_limit(monkeypatch, db, 3)
        reads = _SettingsReads(monkeypatch)
        not_uploaded = _store(db, root, world.chat_id, status="ready")
        attachment_id = _store(db, root, world.chat_id)
        seen: list[int] = []
        processor = _Processor(
            ap.ProcessedFile(page_count=4, token_estimate=1),
            on_call=lambda: seen.append(reads.count),
        )

        await ap.process_attachment(db.pool, root, not_uploaded, ORG_ID, processor=processor)
        after_not_uploaded = reads.count
        result = await ap.process_attachment(
            db.pool, root, attachment_id, ORG_ID, processor=processor
        )

        assert (after_not_uploaded, seen, reads.count, result, _state(db, attachment_id)) == (
            0,
            [1],
            1,
            "failed",
            ("failed", "too_many_pages", None),
        )

    @pytest.mark.parametrize(
        ("processed", "expected"),
        [
            pytest.param({"page_count": 7, "token_estimate": 1234}, (7, 1234), id="both"),
            pytest.param({"token_estimate": 0}, (None, 0), id="zero-estimate-stays-zero"),
            pytest.param({}, (None, None), id="none-stays-null"),
        ],
    )
    async def test_attachment_processing_token_estimate_is_stored_with_ready(
        self,
        ap: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        processed: dict[str, int],
        expected: tuple[Any, Any],
    ) -> None:
        attachment_id = _store(db, root, world.chat_id)

        result = await ap.process_attachment(
            db.pool,
            root,
            attachment_id,
            ORG_ID,
            processor=_Processor(ap.ProcessedFile(**processed)),
        )

        assert (result, _state(db, attachment_id)[2], _estimate(db, attachment_id)) == (
            "ready",
            *expected,
        )

    async def test_attachment_processing_row_is_processing_while_the_processor_runs(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        attachment_id = _store(db, root, world.chat_id)
        seen: list[Any] = []
        processor = _Processor(
            ap.ProcessedFile(), on_call=lambda: seen.append(_state(db, attachment_id))
        )

        await ap.process_attachment(db.pool, root, attachment_id, ORG_ID, processor=processor)

        assert seen == [("processing", None, None)]

    async def test_attachment_processing_failed_error_marks_failed_with_its_reason(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        attachment_id = _store(db, root, world.chat_id)
        processor = _Processor(raises=ap.ProcessingFailedError("x_code"))

        result = await ap.process_attachment(
            db.pool, root, attachment_id, ORG_ID, processor=processor
        )

        assert (result, _state(db, attachment_id)) == ("failed", ("failed", "x_code", None))

    async def test_attachment_processing_unexpected_error_marks_processing_error(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        attachment_id = _store(db, root, world.chat_id)
        processor = _Processor(raises=_ProcessorCrashError(f"{_LEAK_DIR}/{_LEAK_NAME}"))

        result = await ap.process_attachment(
            db.pool, root, attachment_id, ORG_ID, processor=processor
        )

        assert (result, _state(db, attachment_id)) == (
            "failed",
            ("failed", "processing_error", None),
        )

    async def test_attachment_processing_unexpected_error_logged_by_class_name_only(
        self,
        ap: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        attachment_id = _store(db, root, world.chat_id)
        message = f"cannot read {root / _LEAK_NAME} or {_LEAK_DIR}/{_LEAK_NAME}"
        processor = _Processor(raises=_ProcessorCrashError(message))

        await ap.process_attachment(db.pool, root, attachment_id, ORG_ID, processor=processor)

        named = [
            record
            for record in caplog.records
            if record.levelno >= logging.WARNING and "_ProcessorCrashError" in record.getMessage()
        ]
        text = _log_text(caplog)
        assert named, "the failure is logged at WARNING or above with the class name"
        assert (_LEAK_NAME in text, _LEAK_DIR in text, str(root) in text) == (False, False, False)

    @pytest.mark.parametrize(
        ("limit", "pages", "expected"),
        [
            pytest.param(3, 4, ("failed", "too_many_pages", None), id="above-limit"),
            pytest.param(3, 3, ("ready", None, 3), id="equal-to-limit"),
            pytest.param(500, 101, ("ready", None, 101), id="limit-read-from-platform"),
        ],
    )
    async def test_attachment_processing_page_count_checked_against_platform_limit(
        self,
        ap: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        monkeypatch: pytest.MonkeyPatch,
        limit: int,
        pages: int,
        expected: tuple[Any, Any, Any],
    ) -> None:
        _platform_pages_limit(monkeypatch, db, limit)
        attachment_id = _store(db, root, world.chat_id)

        result = await ap.process_attachment(
            db.pool,
            root,
            attachment_id,
            ORG_ID,
            processor=_Processor(ap.ProcessedFile(page_count=pages)),
        )

        assert (result, _state(db, attachment_id)) == (expected[0], expected)

    @pytest.mark.parametrize("outcome", ["returns", "raises"])
    async def test_attachment_processing_row_deleted_while_processing_is_no_error(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path, outcome: str
    ) -> None:
        attachment_id = _store(db, root, world.chat_id)

        def delete_row() -> None:
            del db.attachments[attachment_id]

        processor = _Processor(
            ap.ProcessedFile(page_count=2),
            raises=ap.ProcessingFailedError("x_code") if outcome == "raises" else None,
            on_call=delete_row,
        )

        await ap.process_attachment(db.pool, root, attachment_id, ORG_ID, processor=processor)

        assert db.attachment_row(attachment_id) is None


# ---------------------------------------------------------------------------
# 3b. process_attachment: the derived artifacts (<id>.d, GH-188 Decision 3)
# ---------------------------------------------------------------------------


class TestDerivedArtifacts:
    @pytest.mark.parametrize(
        ("outcome", "reason"),
        [
            pytest.param("failed-error", "corrupted_file", id="processing-failed-error"),
            pytest.param("unexpected-error", "processing_error", id="other-exception"),
            pytest.param("too-many-pages", "too_many_pages", id="page-count-post-check"),
        ],
    )
    async def test_attachment_processing_failure_removes_derived_and_keeps_the_original(
        self,
        ap: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        monkeypatch: pytest.MonkeyPatch,
        outcome: str,
        reason: str,
    ) -> None:
        """Every P3 path: the <id>.d tree the conversion left is removed, the stored
        <id> file stays as it was, and no estimate is stored."""
        _platform_pages_limit(monkeypatch, db, 3)
        attachment_id = _store(db, root, world.chat_id)
        derived = _derived_dir(db, root, attachment_id)
        _plant_derived(derived)
        processor = {
            "failed-error": _Processor(raises=ap.ProcessingFailedError("corrupted_file")),
            "unexpected-error": _Processor(raises=_ProcessorCrashError("boom")),
            "too-many-pages": _Processor(ap.ProcessedFile(page_count=4, token_estimate=9)),
        }[outcome]

        result = await ap.process_attachment(
            db.pool, root, attachment_id, ORG_ID, processor=processor
        )

        assert (
            result,
            _state(db, attachment_id)[:2],
            _estimate(db, attachment_id),
            _gone(derived),
            _path_of(db, root, attachment_id).read_bytes(),
        ) == ("failed", ("failed", reason), None, True, _PDF)

    @pytest.mark.parametrize(
        "outcome",
        [
            pytest.param("returns", id="ready-matched-no-row"),
            pytest.param("raises", id="failed-matched-no-row"),
        ],
    )
    async def test_attachment_processing_row_deleted_while_processing_removes_derived(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path, outcome: str
    ) -> None:
        """The row goes while the processor runs: P2' (or P3) matches nothing, the
        <id>.d tree is removed, nothing is re-created and <id> is left to its deleter."""
        attachment_id = _store(db, root, world.chat_id)
        derived = _derived_dir(db, root, attachment_id)
        _plant_derived(derived)

        def delete_row() -> None:
            del db.attachments[attachment_id]

        processor = _Processor(
            ap.ProcessedFile(page_count=2, token_estimate=5),
            raises=ap.ProcessingFailedError("x_code") if outcome == "raises" else None,
            on_call=delete_row,
        )

        await ap.process_attachment(db.pool, root, attachment_id, ORG_ID, processor=processor)

        assert (
            db.attachment_row(attachment_id),
            _gone(derived),
            _path_of_id(root, ORG_ID, attachment_id).exists(),
        ) == (None, True, True)

    async def test_attachment_processing_ready_keeps_derived(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        attachment_id = _store(db, root, world.chat_id)
        derived = _derived_dir(db, root, attachment_id)
        _plant_derived(derived)

        result = await ap.process_attachment(
            db.pool,
            root,
            attachment_id,
            ORG_ID,
            processor=_Processor(ap.ProcessedFile(page_count=2, token_estimate=40)),
        )

        assert (
            result,
            _state(db, attachment_id),
            _estimate(db, attachment_id),
            sorted(os.listdir(derived)),
        ) == ("ready", ("ready", None, 2), 40, ["manifest.json", "part-0001.txt"])


class TestStatements:
    async def test_attachment_processing_success_issues_p1_then_p2(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        attachment_id = _store(db, root, world.chat_id)
        db.calls.clear()

        await ap.process_attachment(
            db.pool,
            root,
            attachment_id,
            ORG_ID,
            processor=_Processor(ap.ProcessedFile(page_count=7, token_estimate=99)),
        )

        assert _attachment_calls(db) == [
            (_P1, (attachment_id, ORG_ID)),
            (_P2, (attachment_id, ORG_ID, 7, 99)),
        ]

    async def test_attachment_processing_failure_issues_p1_then_p3(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        attachment_id = _store(db, root, world.chat_id)
        db.calls.clear()

        await ap.process_attachment(
            db.pool,
            root,
            attachment_id,
            ORG_ID,
            processor=_Processor(raises=ap.ProcessingFailedError("x_code")),
        )

        assert _attachment_calls(db) == [
            (_P1, (attachment_id, ORG_ID)),
            (_P3, (attachment_id, ORG_ID, "x_code")),
        ]

    async def test_attachment_processing_default_processor_verifies_then_converts_the_stored_file(
        self,
        ap: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Without a processor (convert_stored_file): a valid stored PNG is converted
        (into <id>.d) and ready with the conversion's estimate; a PNG recorded as pdf
        fails verification (corrupted_file) and is never converted."""
        recorder = _RunConversion(_conversion_result(None, 12))
        _patch_run_conversion(monkeypatch, recorder)
        good = _store(db, root, world.chat_id, _png(), kind="png", filename="photo.png")
        bad = _store(db, root, world.chat_id, _png(), kind="pdf")

        results = [
            await ap.process_attachment(db.pool, root, good, ORG_ID),
            await ap.process_attachment(db.pool, root, bad, ORG_ID),
        ]

        assert (results, _state(db, good), _estimate(db, good), _state(db, bad)) == (
            ["ready", "failed"],
            ("ready", None, None),
            12,
            ("failed", "corrupted_file", None),
        )
        assert [(path, kind, out_dir) for path, kind, out_dir, _ in recorder.calls] == [
            (_path_of(db, root, good), "png", _derived_dir(db, root, good))
        ]


# ---------------------------------------------------------------------------
# 4. convert_stored_file (GH-188's default processor)
# ---------------------------------------------------------------------------


class TestConvertStoredFile:
    @pytest.mark.parametrize(
        ("data", "kind", "reason"),
        [
            pytest.param(None, "pdf", "file_missing", id="missing-file"),
            pytest.param(_png(), "pdf", "corrupted_file", id="other-kind"),
            pytest.param(_PDF_ENCRYPTED, "pdf", "password_protected", id="encrypted-pdf"),
        ],
    )
    def test_attachment_processing_convert_verifies_before_any_conversion(
        self,
        ap: ModuleType,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        data: bytes | None,
        kind: str,
        reason: str,
    ) -> None:
        """The stored file is re-checked first: a refusal fails with its code and
        run_conversion (the worker process) is never started."""
        recorder = _RunConversion(_conversion_result(None, 1))
        _patch_run_conversion(monkeypatch, recorder)
        path = tmp_path / str(uuid.uuid4()) if data is None else _stored_file(tmp_path, data)
        job = ap.ProcessingJob(filename="a.pdf", render_dpi=150, max_pages=100)

        with pytest.raises(ap.ProcessingFailedError) as caught:
            ap.convert_stored_file(path, kind, job)

        assert (caught.value.reason, recorder.calls) == (reason, [])

    def test_attachment_processing_convert_runs_the_conversion_with_the_jobs_values(
        self, ap: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """run_conversion(path, kind, <path>.d, ConversionOptions(filename, render_dpi,
        max_pages)), the options carrying the job's values."""
        from admino.converters import common

        recorder = _RunConversion(_conversion_result(None, 6))
        _patch_run_conversion(monkeypatch, recorder)
        path = _stored_file(tmp_path, _TXT)
        filename = "Notizen — Entwurf (v2).txt"
        job = ap.ProcessingJob(filename=filename, render_dpi=217, max_pages=33)

        ap.convert_stored_file(path, "txt", job)

        assert recorder.calls == [
            (
                path,
                "txt",
                tmp_path / f"{path.name}.d",
                common.ConversionOptions(filename=filename, render_dpi=217, max_pages=33),
            )
        ]

    @pytest.mark.parametrize(
        ("data", "kind", "page_count", "token_estimate"),
        [
            pytest.param(_PDF, "pdf", 3, 1234, id="pdf-with-pages"),
            pytest.param(_TXT, "txt", None, 0, id="text-without-pages"),
        ],
    )
    def test_attachment_processing_convert_maps_the_result_to_processed_file(
        self,
        ap: ModuleType,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        data: bytes,
        kind: str,
        page_count: int | None,
        token_estimate: int,
    ) -> None:
        _patch_run_conversion(
            monkeypatch, _RunConversion(_conversion_result(page_count, token_estimate))
        )
        job = ap.ProcessingJob(filename="a", render_dpi=150, max_pages=100)

        processed = ap.convert_stored_file(_stored_file(tmp_path, data), kind, job)

        assert processed == ap.ProcessedFile(page_count=page_count, token_estimate=token_estimate)

    @pytest.mark.parametrize("reason", _CONVERSION_FAILURES)
    def test_attachment_processing_convert_maps_conversion_error_to_its_code(
        self, ap: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason: str
    ) -> None:
        from admino.converters import common

        _patch_run_conversion(monkeypatch, _RunConversion(raises=common.ConversionError(reason)))
        job = ap.ProcessingJob(filename="a.txt", render_dpi=150, max_pages=100)

        with pytest.raises(ap.ProcessingFailedError) as caught:
            ap.convert_stored_file(_stored_file(tmp_path, _TXT), "txt", job)

        assert caught.value.reason == reason


# ---------------------------------------------------------------------------
# 4b. verify_stored_file (#187's processor, now convert_stored_file's first step)
# ---------------------------------------------------------------------------


def _stored_file(tmp_path: Path, data: bytes) -> Path:
    """A file named like a stored attachment: a bare id, no extension."""
    path = tmp_path / str(uuid.uuid4())
    path.write_bytes(data)
    return path


class TestVerifyStoredFile:
    @pytest.mark.parametrize("kind", list(_VALID))
    def test_attachment_processing_verify_accepts_each_kind(
        self, ap: ModuleType, tmp_path: Path, kind: str
    ) -> None:
        path = _stored_file(tmp_path, _VALID[kind])

        assert ap.verify_stored_file(path, kind) == ap.ProcessedFile(page_count=None)

    def test_attachment_processing_verify_missing_file_fails_file_missing(
        self, ap: ModuleType, tmp_path: Path
    ) -> None:
        with pytest.raises(ap.ProcessingFailedError) as caught:
            ap.verify_stored_file(tmp_path / str(uuid.uuid4()), "pdf")

        assert caught.value.reason == "file_missing"

    @pytest.mark.parametrize(
        ("data", "kind", "reason"),
        [
            pytest.param(_PDF_ENCRYPTED, "pdf", "password_protected", id="encrypted-pdf"),
            pytest.param(_PDF_TRUNCATED, "pdf", "corrupted_file", id="truncated-pdf"),
            pytest.param(_EXECUTABLE, "txt", "unsupported_type", id="binary-as-txt"),
            pytest.param(_TXT_NEL, "txt", "unsupported_type", id="c1-control-as-txt"),
            pytest.param(_CFB, "docx", "legacy_office", id="legacy-office-as-docx"),
        ],
    )
    def test_attachment_processing_verify_refused_bytes_fail_with_refusal_reason(
        self, ap: ModuleType, tmp_path: Path, data: bytes, kind: str, reason: str
    ) -> None:
        with pytest.raises(ap.ProcessingFailedError) as caught:
            ap.verify_stored_file(_stored_file(tmp_path, data), kind)

        assert caught.value.reason == reason

    @pytest.mark.parametrize(
        ("data", "kind"),
        [
            pytest.param(_png(), "pdf", id="png-recorded-as-pdf"),
            pytest.param(_ooxml("word/document.xml"), "xlsx", id="docx-recorded-as-xlsx"),
            pytest.param(_TXT, "png", id="text-recorded-as-png"),
        ],
    )
    def test_attachment_processing_verify_other_kind_fails_corrupted(
        self, ap: ModuleType, tmp_path: Path, data: bytes, kind: str
    ) -> None:
        with pytest.raises(ap.ProcessingFailedError) as caught:
            ap.verify_stored_file(_stored_file(tmp_path, data), kind)

        assert caught.value.reason == "corrupted_file"

    @pytest.mark.parametrize("kind", ["csv", "md", "txt"])
    def test_attachment_processing_verify_text_kind_comes_from_recorded_kind(
        self, ap: ModuleType, tmp_path: Path, kind: str
    ) -> None:
        """The same CSV bytes pass as csv, md or txt: the recorded kind's canonical
        extension picks the text kind, not the stored file's (extension-less) name."""
        path = _stored_file(tmp_path, _CSV)

        assert ap.verify_stored_file(path, kind) == ap.ProcessedFile()


# ---------------------------------------------------------------------------
# 5. ProcessingPool
# ---------------------------------------------------------------------------


class TestProcessingPool:
    async def test_attachment_processing_submit_returns_at_once_and_runs_later(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        attachment_id = _store(db, root, world.chat_id)
        processor = _GatedProcessor(ap.ProcessedFile())
        processing = ap.ProcessingPool(processor=processor)
        try:
            result = processing.submit(db.pool, root, attachment_id, ORG_ID)
            at_return = (result, processor.calls, _state(db, attachment_id)[0])
        finally:
            processor.gate.set()
        await asyncio.wait_for(processing.join(), _WAIT_S)

        assert at_return == (None, 0, "uploaded")
        assert _state(db, attachment_id) == ("ready", None, None)

    async def test_attachment_processing_submit_with_broken_pool_never_raises(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        """A job whose pool object is broken fails inside the pool: submit and join
        don't raise, and the next job still runs."""
        attachment_id = _store(db, root, world.chat_id)
        processing = ap.ProcessingPool(processor=_Processor(ap.ProcessedFile()))

        result = processing.submit(object(), root, attachment_id, ORG_ID)
        await asyncio.wait_for(processing.join(), _WAIT_S)
        processing.submit(db.pool, root, attachment_id, ORG_ID)
        await asyncio.wait_for(processing.join(), _WAIT_S)

        assert (result, _state(db, attachment_id)) == (None, ("ready", None, None))

    @pytest.mark.parametrize(
        ("workers", "expected"),
        [pytest.param(None, 2, id="default-workers"), pytest.param(3, 3, id="three-workers")],
    )
    async def test_attachment_processing_pool_bounds_concurrent_processor_calls(
        self,
        ap: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        workers: int | None,
        expected: int,
    ) -> None:
        ids = [_store(db, root, world.chat_id) for _ in range(5)]
        processor = _GatedProcessor(ap.ProcessedFile())
        processing = (
            ap.ProcessingPool(processor=processor)
            if workers is None
            else ap.ProcessingPool(workers=workers, processor=processor)
        )
        try:
            for attachment_id in ids:
                processing.submit(db.pool, root, attachment_id, ORG_ID)
            await _until(lambda: processor.active >= expected, f"{expected} running calls")
            # Time for any call beyond the bound to start.
            await _REAL_SLEEP(0.2)
            peak_while_blocked = processor.peak
        finally:
            processor.gate.set()
        await asyncio.wait_for(processing.join(), _WAIT_S)

        assert (peak_while_blocked, processor.peak, processor.calls) == (expected, expected, 5)
        assert [_state(db, attachment_id)[0] for attachment_id in ids] == ["ready"] * 5

    async def test_attachment_processing_join_waits_for_every_job(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        ids = [_store(db, root, world.chat_id) for _ in range(3)]
        processor = _GatedProcessor(ap.ProcessedFile())
        processing = ap.ProcessingPool(processor=processor)
        try:
            for attachment_id in ids:
                processing.submit(db.pool, root, attachment_id, ORG_ID)
            joiner = asyncio.create_task(processing.join())
            await _until(lambda: processor.calls >= 1, "a running call")
            await _REAL_SLEEP(0.1)
            done_while_blocked = joiner.done()
        finally:
            processor.gate.set()
        await asyncio.wait_for(joiner, _WAIT_S)

        assert (done_while_blocked, processor.calls) == (False, 3)
        assert [_state(db, attachment_id)[0] for attachment_id in ids] == ["ready"] * 3

    async def test_attachment_processing_join_without_jobs_returns(self, ap: ModuleType) -> None:
        await asyncio.wait_for(ap.ProcessingPool().join(), _WAIT_S)

    async def test_attachment_processing_join_right_after_last_job_ended_returns(
        self, ap: ModuleType, root: Path
    ) -> None:
        """join() called in the loop turn in which the last job ended (the job fails at
        once on a broken pool object; its completion callbacks haven't run yet) still
        returns. A join that never yields there (e.g. re-gathering done tasks, which
        Python 3.12 completes eagerly) would freeze its loop, so the scenario runs on a
        private loop in a daemon thread and this test fails instead of hanging."""
        outcome: list[str] = []

        async def scenario() -> None:
            processing = ap.ProcessingPool(processor=_Processor(ap.ProcessedFile()))
            processing.submit(object(), root, uuid.uuid4(), ORG_ID)
            await _REAL_SLEEP(0)
            await processing.join()
            outcome.append("joined")

        def run() -> None:
            try:
                asyncio.run(scenario())
            except BaseException as exc:  # reported through the outcome
                outcome.append(type(exc).__name__)

        threading.Thread(target=run, daemon=True).start()
        await _until(lambda: bool(outcome), "join() to return")

        assert outcome == ["joined"]

    async def test_attachment_processing_close_cancels_pending_and_running_jobs(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        """One worker: the first job blocks in its processor, two wait. close() returns
        without waiting for the blocked call; no pending job's processor runs after it
        and the cancelled running job writes no outcome."""
        ids = [_store(db, root, world.chat_id) for _ in range(3)]
        processor = _GatedProcessor(ap.ProcessedFile())
        processing = ap.ProcessingPool(workers=1, processor=processor)
        try:
            for attachment_id in ids:
                processing.submit(db.pool, root, attachment_id, ORG_ID)
            await _until(lambda: processor.calls >= 1, "the first call")
            await asyncio.wait_for(processing.close(), _WAIT_S)
        finally:
            processor.gate.set()
        # Time for a job that survived close() to run.
        await _REAL_SLEEP(0.3)

        statuses = [_state(db, attachment_id)[0] for attachment_id in ids]
        assert processor.calls == 1
        assert all(status in {"uploaded", "processing"} for status in statuses), statuses

    async def test_attachment_processing_pool_uses_given_processor_on_stored_path(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        first = _store(db, root, world.chat_id)
        second = _store(db, root, world.other_chat_id)
        processor = _Processor(ap.ProcessedFile(page_count=1))
        processing = ap.ProcessingPool(processor=processor)

        processing.submit(db.pool, root, first, ORG_ID)
        processing.submit(db.pool, root, second, OTHER_ORG_ID)
        await asyncio.wait_for(processing.join(), _WAIT_S)

        assert sorted(path for path, _, _ in processor.calls) == sorted(
            [root / str(ORG_ID) / str(first), root / str(OTHER_ORG_ID) / str(second)]
        )
        assert (_state(db, first), _state(db, second)) == (("ready", None, 1),) * 2

    async def test_attachment_processing_pool_default_processor_converts_the_stored_file(
        self,
        ap: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ProcessingPool() converts with convert_stored_file: a valid WEBP is ready with
        the conversion's estimate, a WEBP recorded as png fails verification unconverted."""
        recorder = _RunConversion(_conversion_result(None, 21))
        _patch_run_conversion(monkeypatch, recorder)
        good = _store(db, root, world.chat_id, _webp(), kind="webp")
        bad = _store(db, root, world.chat_id, _webp(), kind="png")
        processing = ap.ProcessingPool()

        processing.submit(db.pool, root, good, ORG_ID)
        processing.submit(db.pool, root, bad, ORG_ID)
        await asyncio.wait_for(processing.join(), _WAIT_S)

        assert (_state(db, good), _estimate(db, good), _state(db, bad)) == (
            ("ready", None, None),
            21,
            ("failed", "corrupted_file", None),
        )
        assert [(path, kind) for path, kind, _, _ in recorder.calls] == [
            (_path_of(db, root, good), "webp")
        ]


# ---------------------------------------------------------------------------
# 6. recover (startup)
# ---------------------------------------------------------------------------


class _SubmitRecorder:
    """Stands in for a ProcessingPool: records each submit by the contract's names."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, Path, uuid.UUID, uuid.UUID]] = []

    def submit(self, pool: Any, root: Path, attachment_id: Any, org_id: Any) -> None:
        self.calls.append((pool, root, _canonical(attachment_id), _canonical(org_id)))


@dataclasses.dataclass(frozen=True)
class _RecoveryRows:
    ready: uuid.UUID
    failed: uuid.UUID
    expected_order: list[tuple[uuid.UUID, uuid.UUID]]


def _recovery_rows(db: FakeDb, root: Path, world: _World) -> _RecoveryRows:
    """ready, failed, processing and uploaded rows (two with the same created_at, the
    higher id stored first) in two orgs; the expected (id, org) submit order."""
    base = datetime.now(UTC) - timedelta(hours=6)
    ready = _store(
        db, root, world.chat_id, status="ready", page_count=2, created_at=base, write=False
    )
    failed = _store(
        db,
        root,
        world.chat_id,
        status="failed",
        failure_reason="corrupted_file",
        created_at=base + timedelta(hours=1),
        write=False,
    )
    newest_uploaded = _store(
        db, root, world.other_chat_id, created_at=base + timedelta(hours=4), write=False
    )
    tie = base + timedelta(hours=3)
    tie_high = _store(
        db,
        root,
        world.chat_id,
        created_at=tie,
        attachment_id=uuid.UUID("ffffffff-0000-4000-8000-000000000002"),
        write=False,
    )
    tie_low = _store(
        db,
        root,
        world.chat_id,
        created_at=tie,
        attachment_id=uuid.UUID("00000000-0000-4000-8000-000000000001"),
        write=False,
    )
    left_processing = _store(
        db,
        root,
        world.chat_id,
        status="processing",
        created_at=base + timedelta(hours=2),
        write=False,
    )
    return _RecoveryRows(
        ready=ready,
        failed=failed,
        expected_order=[
            (left_processing, ORG_ID),
            (tie_low, ORG_ID),
            (tie_high, ORG_ID),
            (newest_uploaded, OTHER_ORG_ID),
        ],
    )


class TestRecover:
    async def test_attachment_processing_recover_requeues_uploaded_rows_in_order(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        rows = _recovery_rows(db, root, world)
        recorder = _SubmitRecorder()

        count = await ap.recover(db.pool, recorder, root)

        assert recorder.calls == [
            (db.pool, root, attachment_id, org_id) for attachment_id, org_id in rows.expected_order
        ]
        assert count == 4

    async def test_attachment_processing_recover_issues_p4_then_p5(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        _recovery_rows(db, root, world)
        db.calls.clear()

        await ap.recover(db.pool, _SubmitRecorder(), root)

        assert _attachment_calls(db) == [(_P4, ()), (_P5, ())]

    async def test_attachment_processing_recover_leaves_ready_and_failed_untouched(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        rows = _recovery_rows(db, root, world)
        before = (db.attachment_row(rows.ready), db.attachment_row(rows.failed))

        await ap.recover(db.pool, _SubmitRecorder(), root)

        assert (db.attachment_row(rows.ready), db.attachment_row(rows.failed)) == before

    async def test_attachment_processing_recover_processes_a_row_left_processing(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        """End to end with a real pool: the row a restart left 'processing' ends ready,
        and the processor never sees the ready or failed rows."""
        rows = _recovery_rows(db, root, world)
        left_processing = rows.expected_order[0][0]
        processor = _Processor(ap.ProcessedFile())
        processing = ap.ProcessingPool(processor=processor)

        await ap.recover(db.pool, processing, root)
        await asyncio.wait_for(processing.join(), _WAIT_S)

        assert _state(db, left_processing) == ("ready", None, None)
        assert sorted(path.name for path, _, _ in processor.calls) == sorted(
            str(attachment_id) for attachment_id, _ in rows.expected_order
        )
