"""Tests for ``admino.attachment_processing`` (GH-187 contract §2 P1 to P5, §3.7).

Issue #187, "Processing": status ``uploaded -> processing -> ready | failed(reason)``,
processed asynchronously on a bounded worker pool (Decision 7: 2 workers, after the
upload answered 201; at startup, files a restart left ``processing`` go back to
``uploaded`` and are queued again). Decision 6: a processor that reports more pages
than the platform's ``files.max_pages_per_file`` fails the file with
``too_many_pages``; #187's own processor only re-checks the stored file.

What these tests pin down:

- Names: ``MAX_WORKERS == 2``; ``ProcessedFile`` a frozen dataclass whose
  ``page_count`` defaults to None; ``ProcessingFailedError(reason)`` keeps its
  ``reason``; ``verify_stored_file`` is the default processor of
  ``process_attachment`` and of ``ProcessingPool`` (whose ``workers`` defaults to
  ``MAX_WORKERS``).
- ``process_attachment(pool, root, attachment_id, org_id, *, processor)``:
  - P1 is a compare-and-set: a row that isn't ``uploaded`` (processing, ready,
    failed), another org's id and a row that is gone return None after P1 alone;
    the processor never runs and the row is unchanged.
  - The processor runs in a worker thread (not the event loop's thread) with
    ``<root>/<org_id>/<attachment_id>`` and the kind P1 returned; the row is
    ``processing`` meanwhile.
  - Success: P2, ``ready`` with the processor's ``page_count`` (None stays NULL).
    ``ProcessingFailedError(code)``: P3 with that code. Any other exception: P3
    ``processing_error``, logged at WARNING or above by class name only (the
    exception's message, holding a file name and a path, reaches no record, no
    traceback). A page count above the platform limit (read from the platform
    settings, not a constant): P3 ``too_many_pages``; equal to it: ready.
  - A row deleted while the processor runs: no error, nothing re-created.
  - The exact statements: [P1, P2] or [P1, P3] with their bind values; the
    return value is the final status.
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
  outcome); the given processor is the one used.
- ``recover(pool, processing, root)``: P4 then P5, then one ``submit(pool, root,
  id, org_id)`` per ``uploaded`` row in ``created_at, id`` order (any org);
  returns the count; ``ready`` and ``failed`` rows are untouched; a row left
  ``processing`` is processed again.

The module is imported lazily (fixture ``ap``), so this file collects before it
exists and every test fails on its own. Fixture files are built in ``tmp_path``
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

# --- Contract §2 forms -----------------------------------------------------------

_P1: Final = norm(
    "UPDATE attachments SET status = 'processing', updated_at = now() "
    "WHERE id = $1 AND org_id = $2 AND status = 'uploaded' RETURNING kind"
)
_P2: Final = norm(
    "UPDATE attachments SET status = 'ready', page_count = $3, updated_at = now() "
    "WHERE id = $1 AND org_id = $2 AND status = 'processing'"
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
    return root / str(_org_of(db, attachment_id)) / str(attachment_id)


def _state(db: FakeDb, attachment_id: uuid.UUID) -> tuple[Any, Any, Any]:
    """(status, failure_reason, page_count) of a stored row."""
    row = db.attachment_row(attachment_id)
    assert row is not None
    return row["status"], row["failure_reason"], row["page_count"]


def _attachment_calls(db: FakeDb) -> list[tuple[str, tuple[Any, ...]]]:
    """(normalized SQL, canonical args) of every recorded statement naming attachments."""
    return [
        (call.normalized, tuple(_canonical(arg) for arg in call.args))
        for call in db.calls
        if re.search(r"\battachments\b", call.normalized)
    ]


class _Processor:
    """A sync processor that records each call (path, kind, thread) and returns or raises."""

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
        self.calls: list[tuple[Path, str]] = []
        self.threads: list[int] = []

    def __call__(self, path: Path, kind: str) -> Any:
        self.calls.append((Path(path), kind))
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

    def __call__(self, path: Path, kind: str) -> Any:
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
    db.add_platform_settings(max_pages_per_file=limit)
    monkeypatch.setattr(scoped_settings, "_platform_cache", None)


class _ProcessorCrashError(Exception):
    """An unexpected processor failure: its message names a file and a path."""


# ---------------------------------------------------------------------------
# 1. Names and defaults
# ---------------------------------------------------------------------------


class TestNames:
    def test_attachment_processing_max_workers_is_two(self, ap: ModuleType) -> None:
        assert ap.MAX_WORKERS == 2

    def test_attachment_processing_processed_file_is_frozen_with_no_pages_by_default(
        self, ap: ModuleType
    ) -> None:
        processed = ap.ProcessedFile()
        with pytest.raises(dataclasses.FrozenInstanceError):
            processed.page_count = 3  # type: ignore[misc]

        assert (dataclasses.is_dataclass(processed), processed.page_count) == (True, None)

    def test_attachment_processing_failed_error_keeps_its_reason(self, ap: ModuleType) -> None:
        error = ap.ProcessingFailedError("x_code")

        assert (isinstance(error, Exception), error.reason) == (True, "x_code")

    def test_attachment_processing_defaults_use_verify_stored_file(self, ap: ModuleType) -> None:
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
            ap.verify_stored_file,
            inspect.Parameter.KEYWORD_ONLY,
            ap.MAX_WORKERS,
            ap.verify_stored_file,
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
        """The path is <root>/<org>/<id>, the kind is the row's (P1 RETURNING kind), and
        the call runs in a worker thread, not on the event loop's thread."""
        attachment_id = _store(db, root, world.chat_id, _CSV, kind="csv")
        processor = _Processor(ap.ProcessedFile())

        await ap.process_attachment(db.pool, root, attachment_id, ORG_ID, processor=processor)

        assert processor.calls == [(root / str(ORG_ID) / str(attachment_id), "csv")]
        assert processor.threads[0] != threading.get_ident()

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
            processor=_Processor(ap.ProcessedFile(page_count=7)),
        )

        assert _attachment_calls(db) == [
            (_P1, (attachment_id, ORG_ID)),
            (_P2, (attachment_id, ORG_ID, 7)),
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

    async def test_attachment_processing_default_processor_verifies_the_stored_file(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        """Without a processor: a valid stored PNG is ready, a PNG recorded as pdf failed."""
        good = _store(db, root, world.chat_id, _png(), kind="png")
        bad = _store(db, root, world.chat_id, _png(), kind="pdf")

        results = [
            await ap.process_attachment(db.pool, root, good, ORG_ID),
            await ap.process_attachment(db.pool, root, bad, ORG_ID),
        ]

        assert (results, _state(db, good), _state(db, bad)) == (
            ["ready", "failed"],
            ("ready", None, None),
            ("failed", "corrupted_file", None),
        )


# ---------------------------------------------------------------------------
# 4. verify_stored_file (#187's processor)
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

        assert sorted(path for path, _ in processor.calls) == sorted(
            [root / str(ORG_ID) / str(first), root / str(OTHER_ORG_ID) / str(second)]
        )
        assert (_state(db, first), _state(db, second)) == (("ready", None, 1),) * 2

    async def test_attachment_processing_pool_default_processor_verifies_stored_file(
        self, ap: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        good = _store(db, root, world.chat_id, _webp(), kind="webp")
        bad = _store(db, root, world.chat_id, _webp(), kind="png")
        processing = ap.ProcessingPool()

        processing.submit(db.pool, root, good, ORG_ID)
        processing.submit(db.pool, root, bad, ORG_ID)
        await asyncio.wait_for(processing.join(), _WAIT_S)

        assert (_state(db, good), _state(db, bad)) == (
            ("ready", None, None),
            ("failed", "corrupted_file", None),
        )


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
        assert sorted(path.name for path, _ in processor.calls) == sorted(
            str(attachment_id) for attachment_id, _ in rows.expected_order
        )
