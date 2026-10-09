"""Chat attachments: repository, disk storage and the upload service (GH-187, migration 0027).

A member uploads a file into one of their chats; it is stored on the
attachments volume as ``<root>/<org_id>/<attachment_id>`` and described by an
``attachments`` row. The row is linked to the user message that sends it
(``chats.append_messages``) and processed in the background
(``attachment_processing``), whose conversion writes the derived artifacts
into ``<root>/<org_id>/<attachment_id>.d/`` (``derived_path``, GH-188) and
stores the file's token estimate and derived bytes (migration 0028). The
org's storage quota counts the originals and their derived files. GH-190
(migration 0030): a member excludes a file from the context or includes it
again (``set_active``, the ``active`` flag; an excluded file stays linked to
its message and listed), lists their chat's files (``list_chat_attachments``)
and the context budget counts the chat's ready, active files
(``ready_active_attachments``). GH-194 (migration 0031): a member moves one
of their live files to the trash on its own (``trash_attachment``: the file
is its own trash group, its files stay on disk); listing, restoring and
purging the trash are ``admino.trash``, which imports this module.

Inputs: the pool or an executor, the caller's ``TenantContext``, a chat id,
an attachment id, the already sanitized file name, the declared
``Content-Length``, the request body as an async iterator of chunks, the
attachments root, the platform's maximum file size, the new ``active`` flag,
a page size, an opaque cursor and the list filters (status, flag), and the
client IP (for the audit events).
Outputs: ``AttachmentRecord``s, an ``AttachmentPage`` (oldest first, with
the next page's cursor), ``(file_count, used_bytes)`` of an org, its
``(quota_bytes, used_bytes)`` under its row lock (``lock_org_storage``, for
the upload's commit check and the processing step's ready outcome), the
number of disk entries removed (``remove_files``; ``remove_derived`` removes
one attachment's ``<id>.d`` only), the active files a message may send as
``chats.ActiveAttachment``s (``check_sendable``, GH-189; GH-190: with their
stored estimate and derived bytes) and the chat's ready, active files
(``ready_active_attachments``). Errors: ``AttachmentRefusedError`` (with a
reason code), ``chats.ChatNotFoundError``, ``chats.InvalidCursorError``,
``AttachmentNotFoundError``, ``AttachmentAlreadySentError``,
``AttachmentNotReadyError``, ``audit_events.AuditRecordError`` and the
driver's errors.

Upload order (``upload_attachment``): the size checks, the chat's owner
check, a quota pre-check that counts the org's stored rows (originals and
derived files) plus the bytes reserved by its uploads in progress (all
before the body is read), the declared length reserved for the org, the
body streamed to ``<id>.part``
(each chunk within ``STALL_TIMEOUT_S``, the whole body within
``UPLOAD_GRACE_S`` plus the declared length at ``UPLOAD_MIN_RATE_BYTES_S``),
type detection in a worker thread (at most ``DETECT_CONCURRENCY`` at once
across uploads), then one transaction: the chat row locked ``FOR SHARE``
(it must still be live), the org row locked ``FOR NO KEY UPDATE`` (the
quota checked again against the stored rows, so concurrent uploads can't
overrun it), the INSERT, the ``file.upload`` event and the rename of
``<id>.part`` to ``<id>`` before the commit. The reservation is released
when the upload ends, however it ends. The lock order (chat, then org) is
the one user deletion, the org notice and the org purge take.

Security notes:
- Tenancy: every statement binds the caller's org (and, for one member's
  data, their user id); another org's, a colleague's, a trashed and an
  unknown attachment raise the same ``AttachmentNotFoundError`` with a fixed
  text. The composite foreign key of migration 0027 makes an attachment of
  someone else's chat impossible in the database too. The chat list runs the
  chat's owner check first (``chats.ChatNotFoundError`` for any chat but the
  caller's live one) and decodes its cursor only then; a cursor carries a
  position (``created_at``, ``id``), never a scope.
- Exclusion (GH-190): ``set_active`` locks the caller's live attachment
  (``FOR UPDATE``) and changes only its ``active`` column (migration 0030
  grants the runtime role UPDATE on it), and records ``file.exclude`` or
  ``file.include`` (ids only, no metadata) in the same transaction, so the
  change never happens unaudited; the same value again writes and records
  nothing. ``check_sendable`` refuses over every id, excluded ones included,
  and returns the active ones only, so an excluded file never reaches the
  slot.
- Trash (GH-194): ``trash_attachment`` sets only ``deleted_at`` and
  ``trash_group_id`` (migration 0031 grants the runtime role UPDATE on the
  group) of the caller's live file and records ``file.delete`` (the file's
  id, no metadata) in the same transaction, so a failed audit write rolls it
  back.
- The file is named by its id only; the original name lives in the row.
  Directories are created 0700 (a missing root too; an existing root's
  mode is left alone), files 0600; the partial file is created
  exclusively and never through a symlink. ``remove_files`` and
  ``remove_derived`` unlink a symlink instead of following it.
- A refused or failed upload leaves no row, no file and no audit event: the
  partial (or renamed) file is removed on every failure before the commit,
  cancellation included, and on a COMMIT the server refuses. After the
  commit, a later exception (a cancelled connection release) never removes
  the stored file; neither does a cancellation, a lost connection, a
  socket error or an asyncpg protocol failure (``InternalClientError``)
  during the COMMIT itself, whose outcome is unknown (a file
  left without a row is removed by the GC's stray-file sweep, a row left
  without its file would stay broken).
  A disk error is ``storage_unavailable``, never its message.
- The body is never read past the declared length. Uploads in progress
  can't fill the volume past the org's quota (their declared lengths are
  reserved in this process, which runs as a single worker), a stalled or
  trickled body can't hold its reservation and partial file open (a
  per-chunk and a total deadline), and type detection (the
  ZIP directory parse grows with the file) is bounded across uploads.
- No content in logs: nothing here logs a file name, a path or file bytes;
  ``remove_files`` and ``remove_derived`` log ids and an exception's class
  name only. No audit event carries a file name.
- Parameterized SQL only (the contract's forms A1-A4', A5'/A6', A7', A8'',
  A10a/A10b, A11/A11', A12 and A13), every value a bind parameter (the list
  filters bind NULL for "any"). Imports nothing from the server, agent, LLM
  or tools layers.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
import os
import shutil
import stat
import uuid
from datetime import datetime  # noqa: TC003 — Pydantic resolves field annotations at runtime
from typing import TYPE_CHECKING, Any, BinaryIO, Final, Literal
from uuid import UUID

import asyncpg

from admino import attachment_types, audit_events, chats, organizations
from admino.access import PlainUUID, SealedModel
from admino.attachment_types import AttachmentRefusedError
from admino.audit_events import AuditAction, TargetType
from admino.logs import safe_log
from admino.models import (  # noqa: TC001 — Pydantic resolves field annotations at runtime
    AttachmentKind,
    AttachmentStatus,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterable, Iterator, Sequence
    from pathlib import Path

    from admino.chats import Executor
    from admino.tenancy import TenantContext

logger = logging.getLogger(__name__)

# A body chunk that doesn't arrive within this many seconds ends the upload
# (content_length_mismatch).
STALL_TIMEOUT_S: Final = 30.0
# The whole body must arrive within UPLOAD_GRACE_S + declared_length /
# UPLOAD_MIN_RATE_BYTES_S (else content_length_mismatch): a trickled body
# that never stalls can't pin its reservation, upload slot, fd and socket.
UPLOAD_GRACE_S: Final = 120.0
UPLOAD_MIN_RATE_BYTES_S: Final = 32 * 1024
# At most this many detect_kind calls run at once, across all uploads.
DETECT_CONCURRENCY: Final = 2

# The errors that can interrupt a COMMIT the server may already have applied
# (its answer is lost): the cancellation, the connection's loss (asyncpg's own
# ConnectionDoesNotExistError is a PostgresConnectionError), a socket error,
# TimeoutError included, and a failure of asyncpg's own protocol layer while
# reading the answer (InternalClientError, ProtocolError included; GH-281).
# The stored file is kept then: a file without a row is removed by the
# stray-file sweep, a row without its file would never heal.
_UNKNOWN_COMMIT_OUTCOME: Final = (
    asyncio.CancelledError,
    OSError,
    asyncpg.InterfaceError,
    asyncpg.InternalClientError,
    asyncpg.exceptions.PostgresConnectionError,
)

_DIRECTORY_MODE: Final = 0o700
_FILE_MODE: Final = 0o600
# Exclusive creation that never follows a symlink planted at the name.
_PART_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC

# A1: the org's quota, for the pre-check before the body is read.
_QUOTA_SQL: Final = "SELECT storage_quota_bytes FROM organizations WHERE id = $1"
# A2: the caller's live chat, locked against a concurrent trash or deletion.
_LOCK_CHAT_SQL: Final = """
    SELECT id FROM chats
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
    FOR SHARE
"""
# A3: the org's quota under the org row lock (compatible with the KEY SHARE
# lock a message insert takes through its foreign key).
_LOCK_QUOTA_SQL: Final = (
    "SELECT storage_quota_bytes FROM organizations WHERE id = $1 FOR NO KEY UPDATE"
)
# A4': the org's used storage: the originals and their derived files (a NULL
# derived_bytes counts 0), trashed files included (numeric: int() it).
_USED_SQL: Final = (
    "SELECT coalesce(sum(size_bytes + coalesce(derived_bytes, 0)), 0)"
    " FROM attachments WHERE org_id = $1"
)
# A5': the new row (status, reason, page count, estimate, flag and timestamps by default).
_INSERT_SQL: Final = """
    INSERT INTO attachments (id, org_id, chat_id, owner_user_id, filename, kind, size_bytes)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING id, chat_id, message_id, filename, kind, size_bytes, status, failure_reason,
              page_count, token_estimate, active, created_at
"""
# A6': the caller's live attachment.
_GET_SQL: Final = """
    SELECT id, chat_id, message_id, filename, kind, size_bytes, status, failure_reason,
           page_count, token_estimate, active, created_at
    FROM attachments
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
"""
# A7': the org's file count and used bytes, derived files included as in A4'
# (numeric: int() it).
_STORAGE_SQL: Final = """
    SELECT count(*) AS file_count,
           coalesce(sum(size_bytes + coalesce(derived_bytes, 0)), 0) AS used_bytes
    FROM attachments WHERE org_id = $1
"""
# A8'' (GH-189, GH-190): which of the given ids are the caller's live attachments of the
# chat, with what the send rules, the budget and slot 4 need, in upload order. Excluded
# files are read too: the refusals hold for every id, the slot takes the active ones only.
_SENDABLE_SQL: Final = """
    SELECT id, message_id, status, filename, kind, page_count, token_estimate, derived_bytes, active
    FROM attachments
    WHERE id = ANY($1::uuid[]) AND chat_id = $2 AND org_id = $3 AND owner_user_id = $4
      AND deleted_at IS NULL
    ORDER BY created_at, id
"""
# A13 (GH-194): the caller's live attachment goes to the trash as its own group.
_TRASH_SQL: Final = """
    UPDATE attachments SET deleted_at = now(), trash_group_id = id
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
    RETURNING id
"""
# A10a (GH-190): the caller's live attachment, locked for the flag's compare-and-set ...
_LOCK_SQL: Final = """
    SELECT id, chat_id, message_id, filename, kind, size_bytes, status, failure_reason,
           page_count, token_estimate, active, created_at
    FROM attachments
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
    FOR UPDATE
"""
# ... and A10b, its new flag (the row A10a locked: the owner was checked there).
_SET_ACTIVE_SQL: Final = "UPDATE attachments SET active = $3 WHERE id = $1 AND org_id = $2"
# A11 (GH-190, Decision 11): the caller's live attachments of the chat, oldest first, with
# the optional status and active filters (NULL: any): the first page ...
_LIST_SQL: Final = """
    SELECT id, chat_id, message_id, filename, kind, size_bytes, status, failure_reason,
           page_count, token_estimate, active, created_at
    FROM attachments
    WHERE chat_id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
      AND status = coalesce($4, status) AND active = coalesce($5, active)
    ORDER BY created_at, id
    LIMIT $6
"""
# ... and A11', the page after a cursor's position.
_LIST_AFTER_SQL: Final = """
    SELECT id, chat_id, message_id, filename, kind, size_bytes, status, failure_reason,
           page_count, token_estimate, active, created_at
    FROM attachments
    WHERE chat_id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
      AND status = coalesce($4, status) AND active = coalesce($5, active)
      AND (created_at, id) > ($6, $7)
    ORDER BY created_at, id
    LIMIT $8
"""
# A12 (GH-190, Decision 7): the chat's live, ready, active files (sent or not) with their
# stored estimate and derived bytes, in upload order: what the context report counts.
_READY_ACTIVE_SQL: Final = """
    SELECT id, filename, kind, page_count, token_estimate, derived_bytes
    FROM attachments
    WHERE chat_id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
      AND status = 'ready' AND active
    ORDER BY created_at, id
"""


# org id -> the declared bytes of its uploads in progress (between the quota
# pre-check and the upload's end). In-process state: one worker serves all orgs.
_reserved: dict[UUID, int] = {}
# The detection semaphore and the event loop it belongs to (a semaphore can't
# be shared across loops; an app restarted in the same process gets a new one).
_detect_slots: tuple[asyncio.AbstractEventLoop, asyncio.Semaphore] | None = None


class AttachmentRecord(SealedModel):
    """One attachments row as the application reads it (no org, owner or trash timestamp)."""

    id: PlainUUID
    chat_id: PlainUUID
    message_id: PlainUUID | None
    filename: str
    kind: AttachmentKind
    size_bytes: int
    status: AttachmentStatus
    failure_reason: str | None
    page_count: int | None
    token_estimate: int | None
    # GH-190 (migration 0030): False for a file the user excluded from the context.
    active: bool
    created_at: datetime


class AttachmentPage(SealedModel):
    """One page of a chat's attachments, oldest first; ``next_cursor`` None on the last page."""

    attachments: list[AttachmentRecord]
    next_cursor: str | None


class _AttachmentCursor(SealedModel):
    """The position after the last attachment of a list page."""

    kind: Literal["attachments"] = "attachments"
    created_at: chats.CursorStamp
    id: UUID


class AttachmentNotFoundError(LookupError):
    """Unknown id, another org's or user's attachment, or a trashed one (one error for all)."""

    def __init__(self) -> None:
        super().__init__("Attachment not found.")


class AttachmentAlreadySentError(Exception):
    """The attachment was already sent with a message."""

    def __init__(self) -> None:
        super().__init__("Attachment already sent.")


class AttachmentNotReadyError(Exception):
    """The attachment isn't ``ready`` yet (``uploaded``, ``processing``) or failed."""

    def __init__(self) -> None:
        super().__init__("Attachment not ready.")


def attachments_root() -> Path:
    """The attachments root: ``organizations.ATTACHMENTS_ROOT``, read at call time.

    ``main()`` sets it from ``ADMINO_ATTACHMENTS_ROOT`` before the database
    startup (GH-281). Every caller (routes, lifespan, GC job, user deletion)
    goes through it, so the uploads and the org purge always agree on the root.
    """
    return organizations.ATTACHMENTS_ROOT


def attachment_path(root: Path, org_id: UUID, attachment_id: UUID) -> Path:
    """Where an attachment's file lives: ``root/<org_id>/<attachment_id>``."""
    return root / str(org_id) / str(attachment_id)


def derived_path(root: Path, org_id: UUID, attachment_id: UUID) -> Path:
    """Where an attachment's derived artifacts live: ``root/<org_id>/<attachment_id>.d``."""
    return root / str(org_id) / f"{attachment_id}.d"


@contextlib.contextmanager
def _disk_errors() -> Iterator[None]:
    """Turn an ``OSError`` of the file work into ``storage_unavailable`` (its text dropped)."""
    try:
        yield
    except OSError:
        raise AttachmentRefusedError("storage_unavailable") from None


def _create_part(org_dir: Path, part: Path) -> BinaryIO:
    """Create the root and the org's directory (0700) if needed and ``part`` exclusively (0600).

    Only a missing root gets 0700 (its parents keep the default mode); an
    existing root's mode is the operator's and is left alone.
    """
    org_dir.parent.mkdir(parents=True, exist_ok=True, mode=_DIRECTORY_MODE)
    org_dir.mkdir(exist_ok=True, mode=_DIRECTORY_MODE)
    return os.fdopen(os.open(part, _PART_FLAGS, _FILE_MODE), "wb")


async def _receive(file: BinaryIO, body: AsyncIterator[bytes], declared_length: int) -> None:
    """Write ``body`` to ``file`` and close it; never read past ``declared_length``.

    Each wait for a chunk ends at the earlier of ``STALL_TIMEOUT_S`` from now
    and the upload's total deadline (``UPLOAD_GRACE_S`` plus the declared
    length at ``UPLOAD_MIN_RATE_BYTES_S``, from the first wait).

    Raises:
        AttachmentRefusedError: ``content_length_mismatch`` when the body runs
            past the declared length (no further chunk is pulled), ends
            short, a chunk doesn't come within ``STALL_TIMEOUT_S`` or the
            body isn't complete by the total deadline;
            ``storage_unavailable`` on a write error.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + UPLOAD_GRACE_S + declared_length / UPLOAD_MIN_RATE_BYTES_S
    received = 0
    while True:
        try:
            async with asyncio.timeout_at(min(loop.time() + STALL_TIMEOUT_S, deadline)):
                chunk = await anext(body)
        except StopAsyncIteration:
            break
        except TimeoutError:
            raise AttachmentRefusedError("content_length_mismatch") from None
        received += len(chunk)
        if received > declared_length:
            raise AttachmentRefusedError("content_length_mismatch")
        with _disk_errors():
            await asyncio.to_thread(file.write, chunk)
    if received < declared_length:
        raise AttachmentRefusedError("content_length_mismatch")
    with _disk_errors():
        await asyncio.to_thread(file.close)


def _detect_semaphore() -> asyncio.Semaphore:
    """The running loop's detection semaphore (``DETECT_CONCURRENCY`` slots)."""
    global _detect_slots
    loop = asyncio.get_running_loop()
    if _detect_slots is None or _detect_slots[0] is not loop:
        _detect_slots = (loop, asyncio.Semaphore(DETECT_CONCURRENCY))
    return _detect_slots[1]


def _free_slot(slots: asyncio.Semaphore, work: asyncio.Future[AttachmentKind]) -> None:
    """Release a detection slot once its thread ended (its outcome counts as retrieved)."""
    slots.release()
    if not work.cancelled():
        work.exception()


async def _detect(part: Path, filename: str) -> AttachmentKind:
    """``attachment_types.detect_kind`` in a worker thread, at most ``DETECT_CONCURRENCY`` at once.

    The slot is held until the thread ends: a cancelled upload doesn't stop
    its thread, so releasing on cancellation would let more run at once.
    """
    slots = _detect_semaphore()
    await slots.acquire()
    work = asyncio.ensure_future(asyncio.to_thread(attachment_types.detect_kind, part, filename))
    work.add_done_callback(functools.partial(_free_slot, slots))
    return await asyncio.shield(work)


def _discard(file: BinaryIO, *paths: Path) -> None:
    """Close ``file`` and remove ``paths`` after a failed upload; errors are dropped.

    A leftover entry is an orphan the GC's stray-file sweep removes later.
    """
    with contextlib.suppress(OSError):
        file.close()
    for path in paths:
        with contextlib.suppress(OSError):
            os.unlink(path)


async def upload_attachment(
    pool: asyncpg.Pool,
    tenant: TenantContext,
    chat_id: UUID,
    *,
    filename: str,
    declared_length: int,
    body: AsyncIterator[bytes],
    root: Path,
    max_bytes: int,
    ip: str | None,
) -> AttachmentRecord:
    """Store an uploaded file in the caller's chat and record ``file.upload``.

    The declared length is reserved for the org from the quota pre-check
    until the upload ends (stored, refused, failed or cancelled), so uploads
    in progress count against the quota of the next one.

    Args:
        pool: The database pool.
        tenant: The caller's org scope; the caller owns the chat and the file.
        chat_id: The chat the file is uploaded into.
        filename: The sanitized name (``attachment_types.sanitize_filename``).
        declared_length: The request's ``Content-Length``.
        body: The request body, chunk by chunk.
        root: The attachments root (``attachments_root()``).
        max_bytes: The platform's maximum file size in bytes.
        ip: The client IP, for the audit event.

    Returns:
        The stored attachment (status ``uploaded``).

    Raises:
        AttachmentRefusedError: ``empty_file``, ``file_too_large``,
            ``storage_quota_exceeded`` (stored plus reserved bytes before the
            body, stored bytes at the commit), ``content_length_mismatch``
            (also a stalled body or one past the total deadline), a
            detection refusal or ``storage_unavailable``; nothing is stored.
        chats.ChatNotFoundError: Unless the chat is the caller's and live,
            before the body is read or at the commit.
        AuditRecordError: If the event can't be recorded; nothing is stored.
    """
    if declared_length == 0:
        raise AttachmentRefusedError("empty_file")
    if declared_length > max_bytes:
        raise AttachmentRefusedError("file_too_large")
    await chats.get_chat(pool, tenant, chat_id)
    quota = await pool.fetchval(_QUOTA_SQL, tenant.org_id)
    used = await pool.fetchval(_USED_SQL, tenant.org_id)
    # No await from the check to the reservation: a concurrent upload's
    # pre-check always sees it.
    reserved = _reserved.get(tenant.org_id, 0)
    if int(used) + reserved + declared_length > quota:
        raise AttachmentRefusedError("storage_quota_exceeded")
    _reserved[tenant.org_id] = reserved + declared_length
    try:
        return await _store(
            pool,
            tenant,
            chat_id,
            filename=filename,
            declared_length=declared_length,
            body=body,
            root=root,
            ip=ip,
        )
    finally:
        _release(tenant.org_id, declared_length)


def _release(org_id: UUID, size: int) -> None:
    """Return ``size`` reserved bytes of ``org_id``; an org with none left is dropped."""
    left = _reserved.get(org_id, 0) - size
    if left > 0:
        _reserved[org_id] = left
    else:
        _reserved.pop(org_id, None)


async def _store(
    pool: asyncpg.Pool,
    tenant: TenantContext,
    chat_id: UUID,
    *,
    filename: str,
    declared_length: int,
    body: AsyncIterator[bytes],
    root: Path,
    ip: str | None,
) -> AttachmentRecord:
    """Stream, detect and commit one upload whose bytes are reserved (``upload_attachment``)."""
    attachment_id = uuid.uuid4()
    org_dir = root / str(tenant.org_id)
    part = org_dir / f"{attachment_id}.part"
    final = attachment_path(root, tenant.org_id, attachment_id)
    # Creation and the rename below are single metadata calls made on the
    # loop's thread: a cancelled worker thread could otherwise still create
    # or rename a file after the cleanup ran.
    with _disk_errors():
        file = _create_part(org_dir, part)
    committed = False
    commit_pending = False
    try:
        await _receive(file, body, declared_length)
        with _disk_errors():
            kind = await _detect(part, filename)
        async with pool.acquire() as conn:
            async with conn.transaction():
                locked = await conn.fetchval(_LOCK_CHAT_SQL, chat_id, tenant.org_id, tenant.user_id)
                if locked is None:
                    raise chats.ChatNotFoundError
                storage = await lock_org_storage(conn, tenant.org_id)
                if storage is None or storage[1] + declared_length > storage[0]:
                    raise AttachmentRefusedError("storage_quota_exceeded")
                row = await conn.fetchrow(
                    _INSERT_SQL,
                    attachment_id,
                    tenant.org_id,
                    chat_id,
                    tenant.user_id,
                    filename,
                    kind,
                    declared_length,
                )
                await audit_events.record(
                    conn,
                    action=AuditAction.FILE_UPLOAD,
                    actor_kind="member",
                    actor_user_id=tenant.user_id,
                    org_id=tenant.org_id,
                    target_type=TargetType.FILE,
                    target_ids=(attachment_id,),
                    ip=ip,
                    metadata={"size_bytes": declared_length},
                )
                # Before the commit: a failed rename rolls the row back.
                with _disk_errors():
                    os.replace(part, final)
                # The last statement of the block: what fails from here on
                # failed at the COMMIT itself.
                commit_pending = True
            # The transaction block exited normally: the row is committed, and
            # its file stays whatever happens next (a cancelled release).
            committed = True
    except BaseException as exc:
        if committed or (commit_pending and isinstance(exc, _UNKNOWN_COMMIT_OUTCOME)):
            _discard(file, part)
        else:
            _discard(file, part, final)
        raise
    return _record(row)


# Any: asyncpg returns untyped Records.
def _record(row: Any) -> AttachmentRecord:
    """The AttachmentRecord of an attachments row (the R columns)."""
    return AttachmentRecord.model_validate(dict(row))


async def get_attachment(
    executor: Executor, tenant: TenantContext, attachment_id: UUID
) -> AttachmentRecord:
    """Return the caller's live attachment.

    Raises:
        AttachmentNotFoundError: Unless the attachment is the caller's (their
            org, their own) and not trashed.
    """
    row = await executor.fetchrow(_GET_SQL, attachment_id, tenant.org_id, tenant.user_id)
    if row is None:
        raise AttachmentNotFoundError
    return _record(row)


async def lock_org_storage(conn: Executor, org_id: UUID) -> tuple[int, int] | None:
    """Lock the org's row and return its ``(quota_bytes, used_bytes)`` (A3, then A4').

    Runs inside the caller's transaction: the org row stays locked ``FOR NO
    KEY UPDATE`` until it ends, so the org's uploads and conversions check
    the quota one after the other. ``used_bytes`` counts the originals and
    their derived files, trashed ones included.

    Returns:
        The quota and the used bytes; None when the org doesn't exist (any
        more): nothing else is read then.
    """
    quota = await conn.fetchval(_LOCK_QUOTA_SQL, org_id)
    if quota is None:
        return None
    return int(quota), int(await conn.fetchval(_USED_SQL, org_id))


async def org_storage(executor: Executor, org_id: UUID) -> tuple[int, int]:
    """Return the org's ``(file_count, used_bytes)``: every row of the org, trashed included.

    ``used_bytes`` counts the originals and their derived files (A7').
    """
    row = await executor.fetchrow(_STORAGE_SQL, org_id)
    return int(row["file_count"]), int(row["used_bytes"])


async def check_sendable(
    executor: Executor, tenant: TenantContext, chat_id: UUID, attachment_ids: Sequence[UUID]
) -> list[chats.ActiveAttachment]:
    """Check that every id is the caller's live, unsent, ``ready`` attachment of the chat.

    One statement (A8''); none for no ids. The refusals come in this order,
    each for any of the files, excluded ones included: not found, already
    sent, not ready.

    Returns:
        The active files (GH-190: an excluded one is sent, linked, but never
        in the slot) as slot 4 and the budget need them, with their stored
        estimate and derived bytes, in upload order (``created_at``, then
        ``id``); ``[]`` for no ids or only excluded ones.

    Raises:
        AttachmentNotFoundError: An id that isn't the caller's live
            attachment of this chat.
        AttachmentAlreadySentError: An attachment another message carried.
        AttachmentNotReadyError: An attachment whose status isn't ``ready``.
    """
    if not attachment_ids:
        return []
    rows = await executor.fetch(
        _SENDABLE_SQL, list(attachment_ids), chat_id, tenant.org_id, tenant.user_id
    )
    # Compared by value: asyncpg returns its own UUID subclass.
    found = {row["id"].int for row in rows}
    if any(attachment_id.int not in found for attachment_id in attachment_ids):
        raise AttachmentNotFoundError
    if any(row["message_id"] is not None for row in rows):
        raise AttachmentAlreadySentError
    if any(row["status"] != "ready" for row in rows):
        raise AttachmentNotReadyError
    return [_active_attachment(row) for row in rows if row["active"]]


# Any: asyncpg returns untyped Records.
def _active_attachment(row: Any) -> chats.ActiveAttachment:
    """The ActiveAttachment of an A8'' or A12 row."""
    return chats.ActiveAttachment(
        id=row["id"],
        filename=row["filename"],
        kind=row["kind"],
        page_count=row["page_count"],
        token_estimate=row["token_estimate"],
        derived_bytes=row["derived_bytes"],
    )


async def set_active(
    pool: asyncpg.Pool, tenant: TenantContext, attachment_id: UUID, active: bool, *, ip: str | None
) -> AttachmentRecord:
    """Include the caller's attachment in the context or exclude it, and audit the change.

    One transaction: the caller's live attachment is locked (A10a), whatever
    its status and whether it was sent; the same value again returns it with
    nothing written and nothing recorded (idempotent). Otherwise the flag is
    set (A10b) and ``file.exclude`` or ``file.include`` is recorded on the
    same connection (the member, the file as the target, no metadata), so a
    failed audit write rolls the change back. An excluded file stays linked
    to its message and listed.

    Args:
        pool: The database pool.
        tenant: The caller's org scope; the caller owns the file.
        attachment_id: The attachment.
        active: True to include it, False to exclude it.
        ip: The client IP, for the audit event.

    Returns:
        The attachment with its flag as it now is.

    Raises:
        AttachmentNotFoundError: Unless the attachment is the caller's (their
            org, their own) and not trashed; nothing is written.
        AuditRecordError: If the event can't be recorded; the flag is rolled
            back.
    """
    async with pool.acquire() as conn, conn.transaction():
        row = await conn.fetchrow(_LOCK_SQL, attachment_id, tenant.org_id, tenant.user_id)
        if row is None:
            raise AttachmentNotFoundError
        if row["active"] == active:
            return _record(row)
        await conn.execute(_SET_ACTIVE_SQL, attachment_id, tenant.org_id, active)
        await audit_events.record(
            conn,
            action=AuditAction.FILE_INCLUDE if active else AuditAction.FILE_EXCLUDE,
            actor_kind="member",
            actor_user_id=tenant.user_id,
            org_id=tenant.org_id,
            target_type=TargetType.FILE,
            target_ids=(attachment_id,),
            ip=ip,
        )
    return _record({**dict(row), "active": active})


async def trash_attachment(
    pool: asyncpg.Pool, tenant: TenantContext, attachment_id: UUID, *, ip: str | None
) -> None:
    """Move the caller's live attachment to the trash and record ``file.delete``.

    One transaction: the file's ``deleted_at`` with the file as its own trash
    group (A13), then the audit event. Its files stay on disk until it is
    purged (``admino.trash``).

    Args:
        pool: The database pool.
        tenant: The caller's org scope.
        attachment_id: The attachment.
        ip: The client IP, for the audit event.

    Raises:
        AttachmentNotFoundError: Unless the attachment is the caller's (in
            the caller's org, their own) and not trashed; nothing is written.
        AuditRecordError: If the event can't be recorded; the trash is rolled
            back.
    """
    async with pool.acquire() as conn, conn.transaction():
        if await conn.fetchval(_TRASH_SQL, attachment_id, tenant.org_id, tenant.user_id) is None:
            raise AttachmentNotFoundError
        await audit_events.record(
            conn,
            action=AuditAction.FILE_DELETE,
            actor_kind="member",
            actor_user_id=tenant.user_id,
            org_id=tenant.org_id,
            target_type=TargetType.FILE,
            target_ids=(attachment_id,),
            ip=ip,
        )


async def list_chat_attachments(
    executor: Executor,
    tenant: TenantContext,
    chat_id: UUID,
    *,
    limit: int,
    cursor: str | None,
    status: AttachmentStatus | None,
    active: bool | None,
) -> AttachmentPage:
    """Return one page of the caller's live attachments of their chat, oldest first.

    The chat's owner check (S2) runs first: a chat the caller can't reach
    runs nothing else, and the cursor is decoded only after it (A11, or A11'
    after a cursor). Trashed files are never listed; excluded ones are.

    Args:
        executor: The pool or a connection.
        tenant: The caller's org scope; the caller owns the chat.
        chat_id: The chat.
        limit: The page size (at least 1).
        cursor: The previous page's ``next_cursor``, or None for the first page.
        status: Only files with this status, or None for any.
        active: Only included (True) or excluded (False) files, or None for both.

    Returns:
        The attachments by ``created_at`` then ``id``, and the cursor of the
        next page (None on the last one).

    Raises:
        chats.ChatNotFoundError: Unless the chat is the caller's and not trashed.
        chats.InvalidCursorError: If the cursor isn't an attachment-list cursor.
    """
    await chats.get_chat(executor, tenant, chat_id)
    scope = (chat_id, tenant.org_id, tenant.user_id, status, active)
    if cursor is None:
        rows = await executor.fetch(_LIST_SQL, *scope, limit + 1)
    else:
        after = chats.decode_cursor(cursor, _AttachmentCursor)
        rows = await executor.fetch(_LIST_AFTER_SQL, *scope, after.created_at, after.id, limit + 1)
    records = [_record(row) for row in rows[:limit]]
    next_cursor = None
    if len(rows) > limit:
        last = records[-1]
        next_cursor = chats.encode_cursor(_AttachmentCursor(created_at=last.created_at, id=last.id))
    return AttachmentPage(attachments=records, next_cursor=next_cursor)


async def ready_active_attachments(
    executor: Executor, tenant: TenantContext, chat_id: UUID
) -> list[chats.ActiveAttachment]:
    """Return the chat's live, ``ready``, active attachments, sent or not (A12).

    What the upload rejection's context report counts (Decision 7). A
    colleague's or another org's chat gives ``[]`` (every row binds the
    caller's org and the caller).

    Returns:
        The files with their stored estimate and derived bytes (None for
        NULL), in upload order (``created_at``, then ``id``).
    """
    rows = await executor.fetch(_READY_ACTIVE_SQL, chat_id, tenant.org_id, tenant.user_id)
    return [_active_attachment(row) for row in rows]


def _remove_entry(path: Path, attachment_id: UUID) -> bool:
    """Remove one disk entry of ``attachment_id``; True when something was removed.

    A missing entry is False; an ``OSError`` is logged with its class name and
    the id only (its message holds the path) and is False too.
    """
    try:
        # lstat: a symlink is unlinked itself, never followed; rmtree never
        # follows a link inside the tree either.
        if stat.S_ISDIR(os.lstat(path).st_mode):
            shutil.rmtree(path)
        else:
            os.unlink(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        logger.warning(
            "Attachment file %s couldn't be removed (%s).",
            safe_log(attachment_id),
            type(exc).__name__,
        )
        return False
    return True


def _remove_entries(org_dir: Path, attachment_ids: list[UUID]) -> int:
    """Remove ``<id>``, ``<id>.part`` and the ``<id>.d`` tree of each id; count them."""
    removed = 0
    for attachment_id in attachment_ids:
        for name in (str(attachment_id), f"{attachment_id}.part", f"{attachment_id}.d"):
            if _remove_entry(org_dir / name, attachment_id):
                removed += 1
    return removed


async def remove_files(root: Path, org_id: UUID, attachment_ids: Iterable[UUID]) -> int:
    """Remove the files of ``attachment_ids`` under ``root/<org_id>``, in a worker thread.

    Each id's ``<id>``, ``<id>.part`` and ``<id>.d`` tree go; a missing entry
    is fine. Never raises: an ``OSError`` is logged with its class name only
    and the other entries are still removed.

    Returns:
        How many entries were removed (a tree counts once).
    """
    return await asyncio.to_thread(_remove_entries, root / str(org_id), list(attachment_ids))


async def remove_derived(root: Path, org_id: UUID, attachment_id: UUID) -> None:
    """Remove the attachment's derived artifacts (``<id>.d``), in a worker thread.

    A directory goes as a tree; a symlink or a file at that name is unlinked,
    never followed. A missing entry is fine. The original ``<id>`` is never
    touched. Never raises: an ``OSError`` is logged with its class name and
    the id only.
    """
    await asyncio.to_thread(_remove_entry, derived_path(root, org_id, attachment_id), attachment_id)
