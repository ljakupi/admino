"""Chat attachments: repository, disk storage and the upload service (GH-187, migration 0027).

A member uploads a file into one of their chats; it is stored on the
attachments volume as ``<root>/<org_id>/<attachment_id>`` and described by an
``attachments`` row. The row is linked to the user message that sends it
(``chats.append_messages``) and processed in the background
(``attachment_processing``).

Inputs: the pool or an executor, the caller's ``TenantContext``, a chat id,
the already sanitized file name, the declared ``Content-Length``, the request
body as an async iterator of chunks, the attachments root, the platform's
maximum file size and the client IP (for the audit event).
Outputs: ``AttachmentRecord``s, ``(file_count, used_bytes)`` of an org, the
number of disk entries removed. Errors: ``AttachmentRefusedError`` (with a
reason code), ``chats.ChatNotFoundError``, ``AttachmentNotFoundError``,
``AttachmentAlreadySentError``, ``audit_events.AuditRecordError`` and the
driver's errors.

Upload order (``upload_attachment``): the size checks, the chat's owner
check, a quota pre-check (all before the body is read), the body streamed to
``<id>.part``, type detection in a worker thread, then one transaction: the
chat row locked ``FOR SHARE`` (it must still be live), the org row locked
``FOR NO KEY UPDATE`` (the quota checked again, so concurrent uploads can't
overrun it), the INSERT, the ``file.upload`` event and the rename of
``<id>.part`` to ``<id>`` before the commit. The lock order (chat, then org)
is the one user deletion, the org notice and the org purge take.

Security notes:
- Tenancy: every statement binds the caller's org (and, for one member's
  data, their user id); another org's, a colleague's, a trashed and an
  unknown attachment raise the same ``AttachmentNotFoundError`` with a fixed
  text. The composite foreign key of migration 0027 makes an attachment of
  someone else's chat impossible in the database too.
- The file is named by its id only; the original name lives in the row.
  Directories are created 0700, files 0600; the partial file is created
  exclusively and never through a symlink. ``remove_files`` unlinks a
  symlink instead of following it.
- A refused or failed upload leaves no row, no file and no audit event: the
  partial (or renamed) file is removed on every failure, cancellation
  included. A disk error is ``storage_unavailable``, never its message.
- The body is never read past the declared length.
- No content in logs: nothing here logs a file name, a path or file bytes;
  ``remove_files`` logs ids and an exception's class name only.
- Parameterized SQL only (the contract's forms A1-A8), every value a bind
  parameter. Imports nothing from the server, agent, LLM or tools layers.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import shutil
import stat
import uuid
from datetime import datetime  # noqa: TC003 — Pydantic resolves field annotations at runtime
from typing import TYPE_CHECKING, Any, BinaryIO, Final

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
    from uuid import UUID

    import asyncpg

    from admino.chats import Executor
    from admino.tenancy import TenantContext

logger = logging.getLogger(__name__)

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
# A4: the org's used storage, trashed files included (numeric: int() it).
_USED_SQL: Final = "SELECT coalesce(sum(size_bytes), 0) FROM attachments WHERE org_id = $1"
# A5: the new row (status, reason, page count and timestamps by default).
_INSERT_SQL: Final = """
    INSERT INTO attachments (id, org_id, chat_id, owner_user_id, filename, kind, size_bytes)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING id, chat_id, message_id, filename, kind, size_bytes, status, failure_reason,
              page_count, created_at
"""
# A6: the caller's live attachment.
_GET_SQL: Final = """
    SELECT id, chat_id, message_id, filename, kind, size_bytes, status, failure_reason,
           page_count, created_at
    FROM attachments
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
"""
# A7: the org's file count and used bytes (numeric: int() it).
_STORAGE_SQL: Final = """
    SELECT count(*) AS file_count, coalesce(sum(size_bytes), 0) AS used_bytes
    FROM attachments WHERE org_id = $1
"""
# A8: which of the given ids are the caller's live attachments of the chat.
_SENDABLE_SQL: Final = """
    SELECT id, message_id FROM attachments
    WHERE id = ANY($1::uuid[]) AND chat_id = $2 AND org_id = $3 AND owner_user_id = $4
      AND deleted_at IS NULL
"""


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
    created_at: datetime


class AttachmentNotFoundError(LookupError):
    """Unknown id, another org's or user's attachment, or a trashed one (one error for all)."""

    def __init__(self) -> None:
        super().__init__("Attachment not found.")


class AttachmentAlreadySentError(Exception):
    """The attachment was already sent with a message."""

    def __init__(self) -> None:
        super().__init__("Attachment already sent.")


def attachments_root() -> Path:
    """The attachments volume: ``organizations.ATTACHMENTS_ROOT``, read at call time.

    Every caller (routes, lifespan, GC job, user deletion) goes through it, so
    the uploads and the org purge always agree on the root.
    """
    return organizations.ATTACHMENTS_ROOT


def attachment_path(root: Path, org_id: UUID, attachment_id: UUID) -> Path:
    """Where an attachment's file lives: ``root/<org_id>/<attachment_id>``."""
    return root / str(org_id) / str(attachment_id)


@contextlib.contextmanager
def _disk_errors() -> Iterator[None]:
    """Turn an ``OSError`` of the file work into ``storage_unavailable`` (its text dropped)."""
    try:
        yield
    except OSError:
        raise AttachmentRefusedError("storage_unavailable") from None


def _create_part(org_dir: Path, part: Path) -> BinaryIO:
    """Create the org's directory (0700) if needed and ``part`` exclusively (0600)."""
    org_dir.mkdir(parents=True, exist_ok=True, mode=_DIRECTORY_MODE)
    return os.fdopen(os.open(part, _PART_FLAGS, _FILE_MODE), "wb")


async def _receive(file: BinaryIO, body: AsyncIterator[bytes], declared_length: int) -> None:
    """Write ``body`` to ``file`` and close it; never read past ``declared_length``.

    Raises:
        AttachmentRefusedError: ``content_length_mismatch`` when the body runs
            past the declared length (no further chunk is pulled) or ends
            short; ``storage_unavailable`` on a write error.
    """
    received = 0
    async for chunk in body:
        received += len(chunk)
        if received > declared_length:
            raise AttachmentRefusedError("content_length_mismatch")
        with _disk_errors():
            await asyncio.to_thread(file.write, chunk)
    if received < declared_length:
        raise AttachmentRefusedError("content_length_mismatch")
    with _disk_errors():
        await asyncio.to_thread(file.close)


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
            ``storage_quota_exceeded``, ``content_length_mismatch``, a
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
    if int(used) + declared_length > quota:
        raise AttachmentRefusedError("storage_quota_exceeded")

    attachment_id = uuid.uuid4()
    org_dir = root / str(tenant.org_id)
    part = org_dir / f"{attachment_id}.part"
    final = attachment_path(root, tenant.org_id, attachment_id)
    # Creation and the rename below are single metadata calls made on the
    # loop's thread: a cancelled worker thread could otherwise still create
    # or rename a file after the cleanup ran.
    with _disk_errors():
        file = _create_part(org_dir, part)
    try:
        await _receive(file, body, declared_length)
        with _disk_errors():
            kind = await asyncio.to_thread(attachment_types.detect_kind, part, filename)
        async with pool.acquire() as conn, conn.transaction():
            locked = await conn.fetchval(_LOCK_CHAT_SQL, chat_id, tenant.org_id, tenant.user_id)
            if locked is None:
                raise chats.ChatNotFoundError
            quota = await conn.fetchval(_LOCK_QUOTA_SQL, tenant.org_id)
            used = await conn.fetchval(_USED_SQL, tenant.org_id)
            if int(used) + declared_length > quota:
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
    except BaseException:
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


async def org_storage(executor: Executor, org_id: UUID) -> tuple[int, int]:
    """Return the org's ``(file_count, used_bytes)``: every row of the org, trashed included."""
    row = await executor.fetchrow(_STORAGE_SQL, org_id)
    return int(row["file_count"]), int(row["used_bytes"])


async def check_sendable(
    executor: Executor, tenant: TenantContext, chat_id: UUID, attachment_ids: Sequence[UUID]
) -> None:
    """Check that every id is the caller's live, unsent attachment of the chat.

    No statement runs for no ids.

    Raises:
        AttachmentNotFoundError: An id that isn't the caller's live
            attachment of this chat (checked first).
        AttachmentAlreadySentError: An attachment another message carried.
    """
    if not attachment_ids:
        return
    rows = await executor.fetch(
        _SENDABLE_SQL, list(attachment_ids), chat_id, tenant.org_id, tenant.user_id
    )
    # Compared by value: asyncpg returns its own UUID subclass.
    message_ids = {row["id"].int: row["message_id"] for row in rows}
    if any(attachment_id.int not in message_ids for attachment_id in attachment_ids):
        raise AttachmentNotFoundError
    if any(message_id is not None for message_id in message_ids.values()):
        raise AttachmentAlreadySentError


def _remove_entries(org_dir: Path, attachment_ids: list[UUID]) -> int:
    """Remove ``<id>``, ``<id>.part`` and the ``<id>.d`` tree of each id; count them."""
    removed = 0
    for attachment_id in attachment_ids:
        for name in (str(attachment_id), f"{attachment_id}.part", f"{attachment_id}.d"):
            path = org_dir / name
            try:
                # lstat: a symlink is unlinked itself, never followed; rmtree
                # never follows a link inside the tree either.
                if stat.S_ISDIR(os.lstat(path).st_mode):
                    shutil.rmtree(path)
                else:
                    os.unlink(path)
            except FileNotFoundError:
                continue
            except OSError as exc:
                logger.warning(
                    "Attachment file %s couldn't be removed (%s).",
                    safe_log(attachment_id),
                    type(exc).__name__,
                )
                continue
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
