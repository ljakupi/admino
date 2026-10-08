"""Background processing of uploaded attachments (GH-187 Decisions 6 and 7, GH-188).

An uploaded file moves ``uploaded -> processing -> ready | failed(reason)``
after the upload answered 201. Jobs run on the event loop through a bounded
``ProcessingPool`` (two workers by default); the processor itself is
synchronous and runs in a worker thread. The default processor
(``convert_stored_file``) re-checks the stored bytes against the recorded
kind (#187's ``verify_stored_file``), then converts the file in a separate
worker process (``converters.runner``) into its derived artifacts
``<id>.d/`` (text and image parts plus a manifest). It reports the page
count, held against the platform's ``files.max_pages_per_file``, the
token estimate and the bytes of the derived files stored with the
``ready`` outcome; those bytes count toward the org's storage quota.

Inputs: the database pool, the attachments root, an attachment id and its
org id, a processor ``(path, kind, ProcessingJob) -> ProcessedFile``; the
job carries the row's file name as the prompt shows it
(``prompt_assembly.prompt_filename``, GH-189: for the PDF page markers and
the image labels) and the platform's ``render_dpi`` and
``max_pages_per_file``, read once per file.
Outputs: the row's final status (``process_attachment``), the number of
files queued again at startup (``recover``).

Statements (contract forms P1'/P2''/P3-P5): P1' is a compare-and-set from
``uploaded`` to ``processing`` (only one job ever processes a row); P2''/P3
write the outcome only while the row is still ``processing``, so a row
deleted meanwhile is never re-created or overwritten. With derived bytes,
the ready outcome is one transaction: the org row locked and the org's
used bytes summed (``attachments.lock_org_storage``, A3/A4'), then P2'', or
P3 ``storage_quota_exceeded`` when the derived files don't fit. A file that
doesn't end ``ready`` (P3, a P2'' that matched no row, an org deleted
meanwhile) loses its ``<id>.d``. At startup ``recover`` puts rows a restart
left ``processing`` back to ``uploaded`` (P4) and queues every ``uploaded``
row again (P5).

Fairness: ``ProcessingPool`` runs at most one job per org at a time (then
one of its global workers), so one org's queue never holds back another
org's files.

Security notes:
- Tenancy: P1'-P3 bind the attachment's org id; P4/P5 are the system's
  startup recovery across all orgs and never return content (ids only).
- Shared storage: a conversion's derived files count toward its org's quota
  (checked under the org row lock, like an upload's), and the pool's per-org
  slot keeps one org from starving the others' conversions.
- The parsers (PDF, Office, image libraries) never load in this process:
  this module imports only ``converters.runner`` and ``converters.common``.
  The conversion runs in a short-lived child without secrets in its
  environment, killed after ``runner.CONVERSION_TIMEOUT_S``.
- Failure reasons are fixed codes (``^[a-z][a-z0-9_]{0,63}$``), never an
  exception's message. An unexpected processor error is logged with its
  class name only (its message can hold a file name or a path), never with
  a traceback.
- Logs carry attachment ids (through ``safe_log``), statuses and reason
  codes only: no file name, path or file content.
- The converter's display name is the prompt name (GH-189, Decision 6):
  default-ignorable and format characters of the stored name never reach a
  page marker or an image label, which go to the model.
- Parameterized SQL only. Imports nothing from the server, agent, LLM or
  tools layers; no LLM tool reaches this module.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from admino import attachment_types, prompt_assembly, scoped_settings
from admino.attachment_types import AttachmentRefusedError
from admino.attachments import attachment_path, lock_org_storage, remove_derived
from admino.converters import runner
from admino.converters.common import ConversionError, ConversionOptions
from admino.logs import safe_log

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from uuid import UUID

    import asyncpg

    from admino.models import AttachmentKind, AttachmentStatus

logger = logging.getLogger(__name__)

MAX_WORKERS: Final = 2

_REASON_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,63}")

# P1': claim an uploaded row; None when it isn't this org's uploaded row.
_START_SQL: Final = """
    UPDATE attachments SET status = 'processing', updated_at = now()
    WHERE id = $1 AND org_id = $2 AND status = 'uploaded'
    RETURNING kind, filename
"""
# P2'': the success outcome, only while the row is still processing.
_READY_SQL: Final = """
    UPDATE attachments SET status = 'ready', page_count = $3, token_estimate = $4,
        derived_bytes = $5, updated_at = now()
    WHERE id = $1 AND org_id = $2 AND status = 'processing'
"""
# P3: the failure outcome with its reason code, only while still processing.
_FAILED_SQL: Final = """
    UPDATE attachments SET status = 'failed', failure_reason = $3, updated_at = now()
    WHERE id = $1 AND org_id = $2 AND status = 'processing'
"""
# P4: rows a restart interrupted go back to the queue.
_RESET_SQL: Final = (
    "UPDATE attachments SET status = 'uploaded', updated_at = now() WHERE status = 'processing'"
)
# P5: every queued row, oldest first.
_QUEUED_SQL: Final = (
    "SELECT id, org_id FROM attachments WHERE status = 'uploaded' ORDER BY created_at, id"
)
# The status tag of an UPDATE that matched no row (the row is gone).
_NO_ROW: Final = "UPDATE 0"
# The failure code of derived files that don't fit the org's quota.
_QUOTA_EXCEEDED: Final = "storage_quota_exceeded"


@dataclass(frozen=True)
class ProcessingJob:
    """What a processor needs besides the stored file and its kind.

    ``filename`` is the row's name as the prompt shows it
    (``prompt_assembly.prompt_filename``; the PDF page markers and image
    labels name it);
    ``render_dpi`` and ``max_pages`` are the platform's ``files`` settings.
    """

    filename: str
    render_dpi: int
    max_pages: int


@dataclass(frozen=True)
class ProcessedFile:
    """What a processor found in a stored file: its page count, token estimate and
    the bytes of the derived files it wrote (None: none to count)."""

    page_count: int | None = None
    token_estimate: int | None = None
    derived_bytes: int | None = None


class ProcessingFailedError(Exception):
    """A processor refused the stored file; ``reason`` is the row's failure code."""

    def __init__(self, reason: str) -> None:
        # The code is stored in failure_reason (a CHECK'd column): a malformed
        # one would leave the row 'processing' until the next restart.
        if _REASON_RE.fullmatch(reason) is None:
            msg = "A processing failure reason must be a short snake_case code."
            raise ValueError(msg)
        super().__init__(reason)
        self.reason = reason


type Processor = Callable[[Path, AttachmentKind, ProcessingJob], ProcessedFile]


def verify_stored_file(path: Path, kind: AttachmentKind) -> ProcessedFile:
    """Check that the stored file still is a valid file of the recorded ``kind`` (#187).

    The stored file is named by its id; the kind's canonical extension stands
    in for the name, so it picks among the text kinds. Synchronous: it reads
    the whole file, so it runs in a worker thread (``convert_stored_file``'s
    first step).

    Args:
        path: The stored file, ``<root>/<org_id>/<attachment_id>``.
        kind: The kind recorded at upload.

    Returns:
        ``ProcessedFile()`` (no page count).

    Raises:
        ProcessingFailedError: ``file_missing``, a detection refusal's reason,
            or ``corrupted_file`` when the bytes are of another kind.
        OSError: The file exists but can't be read.
    """
    try:
        detected = attachment_types.detect_kind(path, "file" + attachment_types.EXTENSIONS[kind][0])
    except FileNotFoundError:
        raise ProcessingFailedError("file_missing") from None
    except AttachmentRefusedError as exc:
        raise ProcessingFailedError(exc.reason) from None
    if detected != kind:
        raise ProcessingFailedError("corrupted_file")
    return ProcessedFile()


def convert_stored_file(path: Path, kind: AttachmentKind, job: ProcessingJob) -> ProcessedFile:
    """Verify the stored file, then convert it in a worker process (the default processor).

    The derived artifacts go to ``<path>.d`` (``attachments.derived_path``).
    Synchronous: it waits for the worker process, so it runs in a worker
    thread.

    Args:
        path: The stored file, ``<root>/<org_id>/<attachment_id>``.
        kind: The kind recorded at upload.
        job: The row's file name and the platform's render and page settings.

    Returns:
        The converter's page count (None for kinds without pages), the
        file's token estimate and the bytes of its derived files.

    Raises:
        ProcessingFailedError: ``verify_stored_file``'s codes (no worker
            starts then) or a conversion failure code.
        OSError: The derived directory can't be prepared or the worker
            can't be started.
    """
    verify_stored_file(path, kind)
    options = ConversionOptions(
        filename=job.filename, render_dpi=job.render_dpi, max_pages=job.max_pages
    )
    try:
        result = runner.run_conversion(path, kind, path.with_name(path.name + ".d"), options)
    except ConversionError as exc:
        raise ProcessingFailedError(exc.reason) from None
    return ProcessedFile(
        page_count=result.page_count,
        token_estimate=result.token_estimate,
        derived_bytes=result.derived_bytes,
    )


async def _fail(
    pool: asyncpg.Pool, root: Path, attachment_id: UUID, org_id: UUID, reason: str
) -> None:
    """Write the failed outcome (P3) with its reason code; drop the derived artifacts."""
    await pool.execute(_FAILED_SQL, attachment_id, org_id, reason)
    logger.info("Attachment %s failed processing (%s).", safe_log(attachment_id), reason)
    await remove_derived(root, org_id, attachment_id)


async def _store_ready(
    pool: asyncpg.Pool, attachment_id: UUID, org_id: UUID, processed: ProcessedFile
) -> tuple[AttachmentStatus, bool]:
    """Write the ready outcome (P2''); derived bytes are first held against the org's quota.

    A processor that reports no derived bytes gets P2'' alone, with NULL.
    Otherwise one transaction locks the org row and sums the org's used bytes
    (A3, A4'), then writes P2'', or P3 ``storage_quota_exceeded`` when the
    derived files don't fit. The org row lock serializes this check with the
    org's uploads and other conversions; it is the only row locked.

    Returns:
        The final status, and whether the row now owns ``<id>.d`` (False when
        the quota refused it, or the org or the row was deleted meanwhile).
    """
    values = (
        attachment_id,
        org_id,
        processed.page_count,
        processed.token_estimate,
        processed.derived_bytes,
    )
    if processed.derived_bytes is None:
        return "ready", await pool.execute(_READY_SQL, *values) != _NO_ROW
    async with pool.acquire() as conn, conn.transaction():
        storage = await lock_org_storage(conn, org_id)
        if storage is None:
            # The org (and with it the row) was deleted meanwhile.
            return "ready", False
        quota, used = storage
        if used + processed.derived_bytes > quota:
            await conn.execute(_FAILED_SQL, attachment_id, org_id, _QUOTA_EXCEEDED)
            logger.info(
                "Attachment %s failed processing (%s).", safe_log(attachment_id), _QUOTA_EXCEEDED
            )
            return "failed", False
        status = await conn.execute(_READY_SQL, *values)
    return "ready", status != _NO_ROW


async def process_attachment(
    pool: asyncpg.Pool,
    root: Path,
    attachment_id: UUID,
    org_id: UUID,
    *,
    processor: Processor = convert_stored_file,
) -> AttachmentStatus | None:
    """Process one uploaded attachment and store the outcome.

    The platform settings are read once, after the row is claimed and before
    the processor runs; the page check reuses that read, before the derived
    bytes are held against the org's quota. A file that doesn't end ``ready``
    (a failure, or its row or org deleted meanwhile) loses its derived
    artifacts; the stored original is never touched here.

    Args:
        pool: The database pool.
        root: The attachments root.
        attachment_id: The attachment to process.
        org_id: Its org.
        processor: Runs in a worker thread on the stored file, its kind and
            the job.

    Returns:
        ``ready`` or ``failed``; None when the row isn't this org's
        ``uploaded`` row (nothing else runs then).

    Raises:
        Exception: A database error of P1'-P3, A3/A4' or of the platform
            settings lookup (the processor's own errors become a failed
            outcome).
    """
    row = await pool.fetchrow(_START_SQL, attachment_id, org_id)
    if row is None:
        return None
    files = (await scoped_settings.current_platform_settings(pool)).files
    job = ProcessingJob(
        filename=prompt_assembly.prompt_filename(row["filename"]),
        render_dpi=files.render_dpi,
        max_pages=files.max_pages_per_file,
    )
    path = attachment_path(root, org_id, attachment_id)
    try:
        processed = await asyncio.to_thread(processor, path, row["kind"], job)
    except ProcessingFailedError as exc:
        await _fail(pool, root, attachment_id, org_id, exc.reason)
        return "failed"
    except Exception as exc:
        # The class name only: the message can name the file or its path.
        logger.warning(
            "Attachment %s processor error (%s).", safe_log(attachment_id), type(exc).__name__
        )
        await _fail(pool, root, attachment_id, org_id, "processing_error")
        return "failed"
    page_count = processed.page_count
    if page_count is not None and page_count > files.max_pages_per_file:
        await _fail(pool, root, attachment_id, org_id, "too_many_pages")
        return "failed"
    status, owned = await _store_ready(pool, attachment_id, org_id, processed)
    if not owned:
        # Refused by the quota, or the row was deleted while the processor ran:
        # nothing owns the artifacts.
        await remove_derived(root, org_id, attachment_id)
    return status


class ProcessingPool:
    """A bounded, per-org fair pool of processing jobs on the running event loop.

    ``submit`` schedules a job and returns at once. A job first takes its
    org's turn (one job per org at a time, in submission order), then one of
    the ``workers`` global slots: at most ``workers`` jobs (and so processor
    calls) run at once, and one org's queue holds at most one of them, so
    another org's job never waits behind it. An org's turn exists while it
    has a pending or running job. The pool binds to the event loop it is
    first used on and starts afresh on a new loop (an app restarted in the
    same process), since a loop's tasks and semaphores can't be awaited from
    another loop.
    """

    def __init__(
        self, *, workers: int = MAX_WORKERS, processor: Processor = convert_stored_file
    ) -> None:
        """Create an idle pool; nothing is bound to an event loop yet."""
        self._workers = workers
        self._processor = processor
        self._loop: asyncio.AbstractEventLoop | None = None
        self._slots = asyncio.Semaphore(workers)
        self._tasks: set[asyncio.Task[None]] = set()
        # org id -> its turn (one job at a time) and its pending and running jobs.
        self._orgs: dict[UUID, tuple[asyncio.Semaphore, int]] = {}

    def _bind(self) -> asyncio.AbstractEventLoop:
        """Return the running loop, resetting the pool's state when the loop changed."""
        loop = asyncio.get_running_loop()
        if loop is not self._loop:
            self._loop = loop
            self._slots = asyncio.Semaphore(self._workers)
            self._tasks = set()
            self._orgs = {}
        return loop

    def submit(self, pool: asyncpg.Pool, root: Path, attachment_id: UUID, org_id: UUID) -> None:
        """Queue ``process_attachment`` for one attachment; never blocks or raises.

        Must be called on the event loop. A job's failure (a database error,
        a broken pool) is logged by class name inside the pool.
        """
        loop = self._bind()
        turn, jobs = self._orgs.get(org_id) or (asyncio.Semaphore(1), 0)
        self._orgs[org_id] = (turn, jobs + 1)
        task = loop.create_task(self._run(turn, self._slots, pool, root, attachment_id, org_id))
        self._tasks.add(task)
        # A done callback, not a finally: a job cancelled before it started
        # never runs its body, but still leaves its org.
        task.add_done_callback(functools.partial(_leave, self._orgs, org_id))
        task.add_done_callback(self._tasks.discard)

    async def _run(
        self,
        turn: asyncio.Semaphore,
        slots: asyncio.Semaphore,
        pool: asyncpg.Pool,
        root: Path,
        attachment_id: UUID,
        org_id: UUID,
    ) -> None:
        """One job: wait for its org's turn, then a free slot of its loop, process,
        log a failure by class name."""
        async with turn, slots:
            try:
                await process_attachment(
                    pool, root, attachment_id, org_id, processor=self._processor
                )
            except Exception as exc:
                logger.warning(
                    "Attachment %s processing job failed (%s).",
                    safe_log(attachment_id),
                    type(exc).__name__,
                )

    async def join(self) -> None:
        """Wait until every submitted job has ended."""
        self._bind()
        while self._tasks:
            # asyncio.wait always yields to the loop, so the done callbacks
            # that empty the set get to run (re-gathering finished tasks
            # wouldn't, and would spin).
            await asyncio.wait(list(self._tasks))

    async def close(self) -> None:
        """Cancel every pending and running job and wait for them to end.

        A running processor call can't be interrupted in its thread, but its
        job ends at once and writes no outcome; a pending job never runs.
        """
        self._bind()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait(tasks)


def _leave(
    orgs: dict[UUID, tuple[asyncio.Semaphore, int]], org_id: UUID, _task: asyncio.Task[None]
) -> None:
    """Count an ended job out of its org; an org without jobs is dropped.

    ``orgs`` is the state of the loop the job ran on (a later loop's is
    another dict, never touched here).
    """
    turn, jobs = orgs[org_id]
    if jobs > 1:
        orgs[org_id] = (turn, jobs - 1)
    else:
        del orgs[org_id]


async def recover(pool: asyncpg.Pool, processing: ProcessingPool, root: Path) -> int:
    """Queue again every file a restart left unprocessed (startup).

    Rows left ``processing`` go back to ``uploaded`` (P4); every ``uploaded``
    row is then submitted, oldest first (P5).

    Args:
        pool: The database pool.
        processing: The app's processing pool.
        root: The attachments root.

    Returns:
        How many attachments were submitted.
    """
    await pool.execute(_RESET_SQL)
    rows = await pool.fetch(_QUEUED_SQL)
    for row in rows:
        processing.submit(pool, root, row["id"], row["org_id"])
    return len(rows)
