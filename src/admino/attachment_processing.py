"""Background processing of uploaded attachments (GH-187, Decisions 6 and 7).

An uploaded file moves ``uploaded -> processing -> ready | failed(reason)``
after the upload answered 201. Jobs run on the event loop through a bounded
``ProcessingPool`` (two workers by default); the processor itself is
synchronous and runs in a worker thread. #187's processor
(``verify_stored_file``) re-checks the stored bytes against the recorded
kind; #188 brings converters that also report a page count, which is held
against the platform's ``files.max_pages_per_file``.

Inputs: the database pool, the attachments root, an attachment id and its
org id, a processor ``(path, kind) -> ProcessedFile``.
Outputs: the row's final status (``process_attachment``), the number of
files queued again at startup (``recover``).

Statements (contract forms P1-P5): P1 is a compare-and-set from
``uploaded`` to ``processing`` (only one job ever processes a row); P2/P3
write the outcome only while the row is still ``processing``, so a row
deleted meanwhile is never re-created or overwritten. At startup ``recover``
puts rows a restart left ``processing`` back to ``uploaded`` (P4) and queues
every ``uploaded`` row again (P5).

Security notes:
- Tenancy: P1-P3 bind the attachment's org id; P4/P5 are the system's
  startup recovery across all orgs and never return content (ids only).
- Failure reasons are fixed codes (``^[a-z][a-z0-9_]{0,63}$``), never an
  exception's message. An unexpected processor error is logged with its
  class name only (its message can hold a file name or a path), never with
  a traceback.
- Logs carry attachment ids (through ``safe_log``), statuses and reason
  codes only: no file name, path or file content.
- Parameterized SQL only. Imports nothing from the server, agent, LLM or
  tools layers; no LLM tool reaches this module.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from admino import attachment_types, scoped_settings
from admino.attachment_types import AttachmentRefusedError
from admino.attachments import attachment_path
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

# P1: claim an uploaded row; None when it isn't this org's uploaded row.
_START_SQL: Final = """
    UPDATE attachments SET status = 'processing', updated_at = now()
    WHERE id = $1 AND org_id = $2 AND status = 'uploaded'
    RETURNING kind
"""
# P2: the success outcome, only while the row is still processing.
_READY_SQL: Final = """
    UPDATE attachments SET status = 'ready', page_count = $3, updated_at = now()
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


@dataclass(frozen=True)
class ProcessedFile:
    """What a processor found in a stored file (#188 adds the page count)."""

    page_count: int | None = None


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


type Processor = Callable[[Path, AttachmentKind], ProcessedFile]


def verify_stored_file(path: Path, kind: AttachmentKind) -> ProcessedFile:
    """Check that the stored file still is a valid file of the recorded ``kind`` (#187).

    The stored file is named by its id; the kind's canonical extension stands
    in for the name, so it picks among the text kinds. Synchronous: it reads
    the whole file, so it runs in a worker thread.

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


async def _fail(pool: asyncpg.Pool, attachment_id: UUID, org_id: UUID, reason: str) -> None:
    """Write the failed outcome (P3) with its reason code."""
    await pool.execute(_FAILED_SQL, attachment_id, org_id, reason)
    logger.info("Attachment %s failed processing (%s).", safe_log(attachment_id), reason)


async def process_attachment(
    pool: asyncpg.Pool,
    root: Path,
    attachment_id: UUID,
    org_id: UUID,
    *,
    processor: Processor = verify_stored_file,
) -> AttachmentStatus | None:
    """Process one uploaded attachment and store the outcome.

    Args:
        pool: The database pool.
        root: The attachments root.
        attachment_id: The attachment to process.
        org_id: Its org.
        processor: Runs in a worker thread on the stored file and its kind.

    Returns:
        ``ready`` or ``failed``; None when the row isn't this org's
        ``uploaded`` row (nothing else runs then).

    Raises:
        Exception: A database error of P1-P3 or of the platform settings
            lookup (the processor's own errors become a failed outcome).
    """
    kind = await pool.fetchval(_START_SQL, attachment_id, org_id)
    if kind is None:
        return None
    path = attachment_path(root, org_id, attachment_id)
    try:
        processed = await asyncio.to_thread(processor, path, kind)
    except ProcessingFailedError as exc:
        await _fail(pool, attachment_id, org_id, exc.reason)
        return "failed"
    except Exception as exc:
        # The class name only: the message can name the file or its path.
        logger.warning(
            "Attachment %s processor error (%s).", safe_log(attachment_id), type(exc).__name__
        )
        await _fail(pool, attachment_id, org_id, "processing_error")
        return "failed"
    page_count = processed.page_count
    if page_count is not None:
        settings = await scoped_settings.current_platform_settings(pool)
        if page_count > settings.files.max_pages_per_file:
            await _fail(pool, attachment_id, org_id, "too_many_pages")
            return "failed"
    await pool.execute(_READY_SQL, attachment_id, org_id, page_count)
    return "ready"


class ProcessingPool:
    """A bounded pool of processing jobs on the running event loop.

    ``submit`` schedules a job and returns at once; at most ``workers`` jobs
    (and so processor calls) run at once, the others wait their turn. The
    pool binds to the event loop it is first used on and starts afresh on a
    new loop (an app restarted in the same process), since a loop's tasks and
    semaphore can't be awaited from another loop.
    """

    def __init__(
        self, *, workers: int = MAX_WORKERS, processor: Processor = verify_stored_file
    ) -> None:
        """Create an idle pool; nothing is bound to an event loop yet."""
        self._workers = workers
        self._processor = processor
        self._loop: asyncio.AbstractEventLoop | None = None
        self._slots = asyncio.Semaphore(workers)
        self._tasks: set[asyncio.Task[None]] = set()

    def _bind(self) -> asyncio.AbstractEventLoop:
        """Return the running loop, resetting the pool's state when the loop changed."""
        loop = asyncio.get_running_loop()
        if loop is not self._loop:
            self._loop = loop
            self._slots = asyncio.Semaphore(self._workers)
            self._tasks = set()
        return loop

    def submit(self, pool: asyncpg.Pool, root: Path, attachment_id: UUID, org_id: UUID) -> None:
        """Queue ``process_attachment`` for one attachment; never blocks or raises.

        Must be called on the event loop. A job's failure (a database error,
        a broken pool) is logged by class name inside the pool.
        """
        loop = self._bind()
        task = loop.create_task(self._run(self._slots, pool, root, attachment_id, org_id))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _run(
        self,
        slots: asyncio.Semaphore,
        pool: asyncpg.Pool,
        root: Path,
        attachment_id: UUID,
        org_id: UUID,
    ) -> None:
        """One job: wait for a free slot of its loop, process, log a failure by class name."""
        async with slots:
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
