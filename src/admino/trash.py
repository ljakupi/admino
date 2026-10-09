"""The member's trash: list, restore, delete forever, empty, and the retention purge (GH-194).

Migration 0031 gives chats and attachments a ``trash_group_id`` next to
``deleted_at``: a trashed chat is its own group, the live files its deletion
moved carry the chat's id, and a file deleted on its own is its own group.
An item of the trash is a row whose group is its own id. Restoring a chat
restores exactly its group (a file deleted on its own before stays an item);
purging a chat deletes its row, and with it by cascade its messages and every
attachment row of the chat, then the files on disk after the commit.

Inputs: the pool, the caller's ``TenantContext``, item ids, a page size, an
opaque cursor and an item type filter, the attachments root
(``attachments.attachments_root()``, passed in), the client IP and an
injectable ``now`` (default ``datetime.now(UTC)``).
Outputs: ``TrashPage``, the restored ``chats.ChatRecord`` /
``attachments.AttachmentRecord``, ``EmptiedTrash``, whether a delete purged
at once, the number of items the retention purge removed.
Errors: ``chats.ChatNotFoundError``, ``attachments.AttachmentNotFoundError``,
``chats.InvalidCursorError``, ``ChatInTrashError``, ``RestoreConflictError``,
``audit_events.AuditRecordError`` and the driver's errors.

Behaviour:
- The effective retention is ``scoped_settings.trash_retention_days`` (the
  org setting clamped into the platform bounds), read on each call. An item
  expires once ``deleted_at <= now - retention``: it is no longer listed or
  restorable, but delete forever and empty still remove it. With retention 0
  the cutoff is ``now``: ``delete_chat`` / ``delete_attachment`` trash the
  item and purge it in the same call.
- The list reads chats and files with one keyset statement each (``limit +
  1`` rows) and merges them by ``(deleted_at, id)`` descending; the cursor is
  tagged ``trash``, so another list's cursor never decodes here, and an
  undecodable one raises before any statement.
- ``empty_trash`` purges the chats first, so a file deleted on its own inside
  a trashed chat goes with its chat (counted in that chat's ``file_count``).
- ``run_purge_job`` runs ``purge_expired`` at startup and hourly: per org
  (each with its own retention), each expired chat and then each expired file
  of its own in its own transaction; an item restored or purged meanwhile is
  skipped.

Security notes:
- Tenancy per statement: every statement binds the caller's org and, for one
  member's trash, the caller's user (the job binds each org). Another org's,
  a colleague's (an Org Admin's request included) and an unknown item raise
  the same not-found errors and change nothing.
- One item per transaction, its audit event on the same connection: a failed
  audit write rolls the change back. A purge removes the files (``<id>``,
  ``<id>.part``, ``<id>.d/`` under ``root/<org_id>/``) of exactly the rows its
  transaction deleted, only after the commit, so a rolled-back purge never
  loses a file.
- Logs carry ids (``safe_log``) and exception class names only, never a
  title, a file name, a path, an email or an exception's message; audit
  events carry ids and a file count only.
- Parameterized SQL only (contract section 5). Imports nothing from the
  server, agent, LLM or tools layers.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, Literal
from uuid import UUID  # noqa: TC003 - Pydantic resolves field annotations at runtime

import asyncpg

from admino import attachments, audit_events, chats, scoped_settings
from admino.access import PlainUUID, SealedModel
from admino.audit_events import AuditAction, TargetType
from admino.logs import safe_log
from admino.models import TrashItemType  # noqa: TC001 - Pydantic resolves field annotations

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from admino.tenancy import TenantContext

logger = logging.getLogger(__name__)

PURGE_INTERVAL_SECONDS: Final = 3600.0

_LEGACY_SESSION_KEY: Final = "chats_legacy_session_key"

# T1c / T1c': the caller's unexpired trashed chats (items only), newest deletion first.
_LIST_CHATS_SQL: Final = """
    SELECT id, title, deleted_at FROM chats
    WHERE org_id = $1 AND owner_user_id = $2 AND deleted_at > $3 AND trash_group_id = id
    ORDER BY deleted_at DESC, id DESC LIMIT $4
"""
_LIST_CHATS_AFTER_SQL: Final = """
    SELECT id, title, deleted_at FROM chats
    WHERE org_id = $1 AND owner_user_id = $2 AND deleted_at > $3 AND trash_group_id = id
      AND (deleted_at, id) < ($4, $5)
    ORDER BY deleted_at DESC, id DESC LIMIT $6
"""
# T1a / T1a': the caller's unexpired files trashed on their own.
_LIST_FILES_SQL: Final = """
    SELECT id, filename, chat_id, deleted_at FROM attachments
    WHERE org_id = $1 AND owner_user_id = $2 AND deleted_at > $3 AND trash_group_id = id
    ORDER BY deleted_at DESC, id DESC LIMIT $4
"""
_LIST_FILES_AFTER_SQL: Final = """
    SELECT id, filename, chat_id, deleted_at FROM attachments
    WHERE org_id = $1 AND owner_user_id = $2 AND deleted_at > $3 AND trash_group_id = id
      AND (deleted_at, id) < ($4, $5)
    ORDER BY deleted_at DESC, id DESC LIMIT $6
"""
# T2: the caller's unexpired trashed chat comes back (the chat record columns).
_RESTORE_CHAT_SQL: Final = """
    UPDATE chats SET deleted_at = NULL, trash_group_id = NULL
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at > $4
      AND trash_group_id = id
    RETURNING id, org_id, owner_user_id, title, title_source, external_content,
        created_at, last_activity_at
"""
# T3: exactly the restored chat's group: a file trashed on its own stays in the trash.
_RESTORE_CHAT_FILES_SQL: Final = """
    UPDATE attachments SET deleted_at = NULL, trash_group_id = NULL
    WHERE chat_id = $1 AND org_id = $2 AND trash_group_id = $1
"""
# T4: the chat of the caller's unexpired file trashed on its own.
_FILE_CHAT_SQL: Final = """
    SELECT chat_id FROM attachments
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at > $4
      AND trash_group_id = id
"""
# A2: the file's chat is live (held until the commit, so it can't be trashed meanwhile).
_LIVE_CHAT_SQL: Final = """
    SELECT id FROM chats
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL FOR SHARE
"""
# T6: the file comes back (the attachment record columns).
_RESTORE_FILE_SQL: Final = """
    UPDATE attachments SET deleted_at = NULL, trash_group_id = NULL
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at > $4
      AND trash_group_id = id
    RETURNING id, chat_id, message_id, filename, kind, size_bytes, status,
        failure_reason, page_count, token_estimate, active, created_at
"""
# T7: the caller's trashed chat (expired too), locked for its deletion.
_LOCK_TRASHED_CHAT_SQL: Final = """
    SELECT id FROM chats
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NOT NULL
    FOR UPDATE
"""
# T8: every attachment row of the chat, any state: the cascade deletes them all.
_CHAT_FILES_SQL: Final = "SELECT id FROM attachments WHERE chat_id = $1 AND org_id = $2"
# T9: the chat goes; its messages and attachment rows go by cascade (as the table owner).
_DELETE_CHAT_SQL: Final = "DELETE FROM chats WHERE id = $1 AND org_id = $2"
# T10: the caller's trashed file of its own (expired too).
_DELETE_FILE_SQL: Final = """
    DELETE FROM attachments
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NOT NULL
      AND trash_group_id = id
    RETURNING id
"""
# E1: every trashed chat of the caller (expired too).
_TRASHED_CHATS_SQL: Final = """
    SELECT id FROM chats
    WHERE org_id = $1 AND owner_user_id = $2 AND deleted_at IS NOT NULL ORDER BY id
"""
# E2: every file of the caller trashed on its own (expired too).
_TRASHED_FILES_SQL: Final = """
    SELECT id FROM attachments
    WHERE org_id = $1 AND owner_user_id = $2 AND deleted_at IS NOT NULL
      AND trash_group_id = id
    ORDER BY id
"""
# J1: the orgs with anything in the trash.
_TRASH_ORGS_SQL: Final = """
    SELECT org_id FROM chats WHERE deleted_at IS NOT NULL
    UNION SELECT org_id FROM attachments WHERE deleted_at IS NOT NULL
    ORDER BY org_id
"""
# J2: the org's expired chats, oldest deletion first.
_EXPIRED_CHATS_SQL: Final = """
    SELECT id FROM chats WHERE org_id = $1 AND deleted_at <= $2 ORDER BY deleted_at, id
"""
# J3: the chat is still expired (not restored meanwhile), locked for its deletion.
_LOCK_EXPIRED_CHAT_SQL: Final = """
    SELECT id FROM chats WHERE id = $1 AND org_id = $2 AND deleted_at <= $3 FOR UPDATE
"""
# J4: the org's expired files of their own, oldest deletion first.
_EXPIRED_FILES_SQL: Final = """
    SELECT id FROM attachments
    WHERE org_id = $1 AND trash_group_id = id AND deleted_at <= $2
    ORDER BY deleted_at, id
"""
# J5: the file goes unless it was restored or purged meanwhile.
_DELETE_EXPIRED_FILE_SQL: Final = """
    DELETE FROM attachments
    WHERE id = $1 AND org_id = $2 AND trash_group_id = id AND deleted_at <= $3
    RETURNING id
"""


class TrashItemRecord(SealedModel):
    """One item of the caller's trash: metadata only.

    ``name`` is the chat's title or the file's name; ``chat_id`` is the
    file's chat and None for a chat; ``expires_at`` is ``deleted_at`` plus
    the org's effective retention.
    """

    item_type: TrashItemType
    id: PlainUUID
    name: str
    chat_id: PlainUUID | None
    deleted_at: datetime
    expires_at: datetime


class TrashPage(SealedModel):
    """One page of the caller's trash, latest deletion first, and the retention it used."""

    items: list[TrashItemRecord]
    next_cursor: str | None
    retention_days: int


class EmptiedTrash(SealedModel):
    """How many chats and files of their own emptying the trash purged."""

    chats: int
    attachments: int


class ChatInTrashError(Exception):
    """The file's chat is in the trash: the file can't come back before its chat."""

    def __init__(self) -> None:
        super().__init__("The file's chat is in the trash.")


class RestoreConflictError(Exception):
    """A legacy chat can't come back while its session has a live chat."""

    def __init__(self) -> None:
        super().__init__("A live chat already uses this chat's session.")


class _TrashCursor(SealedModel):
    """The position after the last item of a trash page."""

    kind: Literal["trash"] = "trash"
    deleted_at: chats.CursorStamp
    id: UUID


async def _retention_cutoff(
    pool: asyncpg.Pool, org_id: UUID, now: datetime | None
) -> tuple[int, datetime]:
    """The org's effective retention in days and the cutoff it gives at ``now``."""
    retention = await scoped_settings.trash_retention_days(pool, org_id)
    return retention, (datetime.now(UTC) if now is None else now) - timedelta(days=retention)


async def list_trash(
    pool: asyncpg.Pool,
    tenant: TenantContext,
    *,
    limit: int,
    cursor: str | None,
    item_type: TrashItemType | None,
    now: datetime | None = None,
) -> TrashPage:
    """Return one page of the caller's unexpired trash items, latest deletion first.

    Args:
        pool: The database pool.
        tenant: The caller's org scope; only the caller's items are listed.
        limit: The page size (the route bounds it to 1-100).
        cursor: The previous page's ``next_cursor``, or None for the first page.
        item_type: Only chats or only files, or None for both.
        now: The current time (default: ``datetime.now(UTC)``).

    Returns:
        At most ``limit`` items, the next cursor when there are more, and the
        retention the expiry times were computed with.

    Raises:
        chats.InvalidCursorError: If the cursor isn't a trash cursor; raised
            before any statement.
    """
    after = None if cursor is None else chats.decode_cursor(cursor, _TrashCursor)
    retention, cutoff = await _retention_cutoff(pool, tenant.org_id, now)
    lifetime = timedelta(days=retention)
    # One more row of each kind than the page holds tells whether a next page exists.
    args: Sequence[object] = (
        (tenant.org_id, tenant.user_id, cutoff, limit + 1)
        if after is None
        else (tenant.org_id, tenant.user_id, cutoff, after.deleted_at, after.id, limit + 1)
    )
    items: list[TrashItemRecord] = []
    if item_type in (None, "chat"):
        rows = await pool.fetch(_LIST_CHATS_SQL if after is None else _LIST_CHATS_AFTER_SQL, *args)
        items.extend(
            TrashItemRecord(
                item_type="chat",
                id=row["id"],
                name=row["title"],
                chat_id=None,
                deleted_at=row["deleted_at"],
                expires_at=row["deleted_at"] + lifetime,
            )
            for row in rows
        )
    if item_type in (None, "attachment"):
        rows = await pool.fetch(_LIST_FILES_SQL if after is None else _LIST_FILES_AFTER_SQL, *args)
        items.extend(
            TrashItemRecord(
                item_type="attachment",
                id=row["id"],
                name=row["filename"],
                chat_id=row["chat_id"],
                deleted_at=row["deleted_at"],
                expires_at=row["deleted_at"] + lifetime,
            )
            for row in rows
        )
    # The same order as each statement's keyset, so the cursor resumes both.
    items.sort(key=lambda item: (item.deleted_at, item.id), reverse=True)
    page = items[:limit]
    next_cursor = None
    if len(items) > limit:
        last = page[-1]
        next_cursor = chats.encode_cursor(_TrashCursor(deleted_at=last.deleted_at, id=last.id))
    return TrashPage(items=page, next_cursor=next_cursor, retention_days=retention)


async def restore_chat(
    pool: asyncpg.Pool,
    tenant: TenantContext,
    chat_id: UUID,
    *,
    ip: str | None,
    now: datetime | None = None,
) -> chats.ChatRecord:
    """Restore the caller's unexpired trashed chat and exactly its group; record ``chat.restore``.

    One transaction after the retention read: the chat (T2), its group's
    files (T3), the event. Restoring a chat that is live already returns it
    and records nothing.

    Args:
        pool: The database pool.
        tenant: The caller's org scope.
        chat_id: The chat.
        ip: The client IP, for the audit event.
        now: The current time (default: ``datetime.now(UTC)``).

    Returns:
        The restored (or already live) chat.

    Raises:
        chats.ChatNotFoundError: Unless the chat is the caller's and live or
            trashed and unexpired; nothing is written.
        RestoreConflictError: If the chat is a legacy session's and that
            session has a live chat; nothing is written.
        AuditRecordError: If the event can't be recorded; rolled back.
    """
    _, cutoff = await _retention_cutoff(pool, tenant.org_id, now)
    try:
        async with pool.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(
                _RESTORE_CHAT_SQL, chat_id, tenant.org_id, tenant.user_id, cutoff
            )
            if row is None:
                # Idempotent: a chat restored already is the caller's live chat (S2).
                return await chats.get_chat(conn, tenant, chat_id)
            await conn.execute(_RESTORE_CHAT_FILES_SQL, chat_id, tenant.org_id)
            await audit_events.record(
                conn,
                action=AuditAction.CHAT_RESTORE,
                actor_kind="member",
                actor_user_id=tenant.user_id,
                org_id=tenant.org_id,
                target_type=TargetType.CHAT,
                target_ids=(chat_id,),
                ip=ip,
            )
    except asyncpg.UniqueViolationError as exc:
        if exc.constraint_name == _LEGACY_SESSION_KEY:
            # The driver's error quotes the row: only the fixed text goes on.
            raise RestoreConflictError from None
        raise
    return chats.ChatRecord.model_validate(dict(row))


async def restore_attachment(
    pool: asyncpg.Pool,
    tenant: TenantContext,
    attachment_id: UUID,
    *,
    ip: str | None,
    now: datetime | None = None,
) -> attachments.AttachmentRecord:
    """Restore the caller's unexpired file trashed on its own; record ``file.restore``.

    One transaction after the retention read: the file's chat (T4), which
    must be live (A2, held until the commit), the file (T6), the event.
    Restoring a file that is live already returns it and records nothing.

    Args:
        pool: The database pool.
        tenant: The caller's org scope.
        attachment_id: The file.
        ip: The client IP, for the audit event.
        now: The current time (default: ``datetime.now(UTC)``).

    Returns:
        The restored (or already live) file.

    Raises:
        attachments.AttachmentNotFoundError: Unless the file is the caller's
            and live or trashed on its own and unexpired; nothing is written.
        ChatInTrashError: If the file's chat is in the trash; nothing is
            written.
        AuditRecordError: If the event can't be recorded; rolled back.
    """
    _, cutoff = await _retention_cutoff(pool, tenant.org_id, now)
    async with pool.acquire() as conn, conn.transaction():
        chat_id = await conn.fetchval(
            _FILE_CHAT_SQL, attachment_id, tenant.org_id, tenant.user_id, cutoff
        )
        if chat_id is None:
            # Idempotent: a file restored already is the caller's live file (A6').
            return await attachments.get_attachment(conn, tenant, attachment_id)
        if await conn.fetchval(_LIVE_CHAT_SQL, chat_id, tenant.org_id, tenant.user_id) is None:
            raise ChatInTrashError
        row = await conn.fetchrow(
            _RESTORE_FILE_SQL, attachment_id, tenant.org_id, tenant.user_id, cutoff
        )
        if row is None:
            raise attachments.AttachmentNotFoundError
        await audit_events.record(
            conn,
            action=AuditAction.FILE_RESTORE,
            actor_kind="member",
            actor_user_id=tenant.user_id,
            org_id=tenant.org_id,
            target_type=TargetType.FILE,
            target_ids=(attachment_id,),
            ip=ip,
        )
    return attachments.AttachmentRecord.model_validate(dict(row))


async def _delete_chat_rows(conn: chats.Executor, chat_id: UUID, org_id: UUID) -> list[UUID]:
    """Delete a locked chat (T9, cascading) and return its attachment ids (T8) for the files."""
    file_ids: list[UUID] = [row["id"] for row in await conn.fetch(_CHAT_FILES_SQL, chat_id, org_id)]
    await conn.execute(_DELETE_CHAT_SQL, chat_id, org_id)
    return file_ids


async def purge_chat(
    pool: asyncpg.Pool, tenant: TenantContext, chat_id: UUID, *, root: Path, ip: str | None
) -> None:
    """Delete the caller's trashed chat for good and record ``chat.purge``.

    One transaction: the lock (T7; an expired chat included), its attachment
    ids (T8), the deletion (T9: its messages and every attachment row go by
    cascade), the event with the file count. After the commit, the files of
    those attachments.

    Args:
        pool: The database pool.
        tenant: The caller's org scope.
        chat_id: The chat.
        root: The attachments root.
        ip: The client IP, for the audit event.

    Raises:
        chats.ChatNotFoundError: Unless the chat is the caller's and trashed
            (a live chat is not found here); nothing is removed.
        AuditRecordError: If the event can't be recorded; rolled back, no
            file is removed.
    """
    async with pool.acquire() as conn, conn.transaction():
        if (
            await conn.fetchval(_LOCK_TRASHED_CHAT_SQL, chat_id, tenant.org_id, tenant.user_id)
            is None
        ):
            raise chats.ChatNotFoundError
        file_ids = await _delete_chat_rows(conn, chat_id, tenant.org_id)
        await audit_events.record(
            conn,
            action=AuditAction.CHAT_PURGE,
            actor_kind="member",
            actor_user_id=tenant.user_id,
            org_id=tenant.org_id,
            target_type=TargetType.CHAT,
            target_ids=(chat_id,),
            ip=ip,
            metadata={"file_count": len(file_ids)},
        )
    await attachments.remove_files(root, tenant.org_id, file_ids)


async def purge_attachment(
    pool: asyncpg.Pool, tenant: TenantContext, attachment_id: UUID, *, root: Path, ip: str | None
) -> None:
    """Delete the caller's file trashed on its own for good and record ``file.purge``.

    One transaction: the deletion (T10; an expired file included), the event.
    After the commit, the file's entries on disk.

    Args:
        pool: The database pool.
        tenant: The caller's org scope.
        attachment_id: The file.
        root: The attachments root.
        ip: The client IP, for the audit event.

    Raises:
        attachments.AttachmentNotFoundError: Unless the file is the caller's
            and trashed on its own (a file of a trashed chat goes with its
            chat); nothing is removed.
        AuditRecordError: If the event can't be recorded; rolled back, no
            file is removed.
    """
    async with pool.acquire() as conn, conn.transaction():
        if (
            await conn.fetchval(_DELETE_FILE_SQL, attachment_id, tenant.org_id, tenant.user_id)
            is None
        ):
            raise attachments.AttachmentNotFoundError
        await audit_events.record(
            conn,
            action=AuditAction.FILE_PURGE,
            actor_kind="member",
            actor_user_id=tenant.user_id,
            org_id=tenant.org_id,
            target_type=TargetType.FILE,
            target_ids=(attachment_id,),
            ip=ip,
        )
    await attachments.remove_files(root, tenant.org_id, (attachment_id,))


async def empty_trash(
    pool: asyncpg.Pool, tenant: TenantContext, *, root: Path, ip: str | None
) -> EmptiedTrash:
    """Purge every trashed chat, then every file trashed on its own, of the caller.

    Expired items included. Each item is purged in its own transaction
    (``purge_chat`` / ``purge_attachment``); one restored or purged meanwhile
    is skipped and not counted. The chats go first, so a file of a trashed
    chat goes with it (counted in the chat's ``file_count``).

    Args:
        pool: The database pool.
        tenant: The caller's org scope.
        root: The attachments root.
        ip: The client IP, for the audit events.

    Returns:
        How many chats and files of their own were purged.

    Raises:
        AuditRecordError: And the driver's errors; the items purged before
            the failure stay purged.
    """
    purged_chats = 0
    for row in await pool.fetch(_TRASHED_CHATS_SQL, tenant.org_id, tenant.user_id):
        try:
            await purge_chat(pool, tenant, row["id"], root=root, ip=ip)
        except chats.ChatNotFoundError:
            continue
        purged_chats += 1
    purged_files = 0
    for row in await pool.fetch(_TRASHED_FILES_SQL, tenant.org_id, tenant.user_id):
        try:
            await purge_attachment(pool, tenant, row["id"], root=root, ip=ip)
        except attachments.AttachmentNotFoundError:
            continue
        purged_files += 1
    return EmptiedTrash(chats=purged_chats, attachments=purged_files)


async def delete_chat(
    pool: asyncpg.Pool, tenant: TenantContext, chat_id: UUID, *, root: Path, ip: str | None
) -> bool:
    """Move the caller's chat to the trash; with a retention of 0, purge it at once.

    The retention is read first (a failure there changes nothing), then
    ``chats.trash_chat`` records ``chat.delete``; with retention 0
    ``purge_chat`` follows and records ``chat.purge``. A failing purge is
    logged (the id and the exception's class name) and the chat stays in the
    trash: the deletion itself succeeded.

    Args:
        pool: The database pool.
        tenant: The caller's org scope.
        chat_id: The chat.
        root: The attachments root.
        ip: The client IP, for the audit events.

    Returns:
        True when the chat was purged at once, False when it is in the trash.

    Raises:
        chats.ChatNotFoundError: Unless the chat is the caller's and live.
    """
    retention = await scoped_settings.trash_retention_days(pool, tenant.org_id)
    await chats.trash_chat(pool, tenant, chat_id, ip=ip)
    if retention > 0:
        return False
    try:
        await purge_chat(pool, tenant, chat_id, root=root, ip=ip)
    except Exception as exc:
        # The trash stands; the retention purge removes the chat on its next run.
        logger.warning(
            "Chat %s stays in the trash: its purge failed (%s).",
            safe_log(chat_id),
            type(exc).__name__,
        )
        return False
    return True


async def delete_attachment(
    pool: asyncpg.Pool, tenant: TenantContext, attachment_id: UUID, *, root: Path, ip: str | None
) -> bool:
    """Move the caller's file to the trash; with a retention of 0, purge it at once.

    The same as ``delete_chat`` with ``attachments.trash_attachment``
    (``file.delete``) and ``purge_attachment`` (``file.purge``).

    Args:
        pool: The database pool.
        tenant: The caller's org scope.
        attachment_id: The file.
        root: The attachments root.
        ip: The client IP, for the audit events.

    Returns:
        True when the file was purged at once, False when it is in the trash.

    Raises:
        attachments.AttachmentNotFoundError: Unless the file is the caller's
            and live.
    """
    retention = await scoped_settings.trash_retention_days(pool, tenant.org_id)
    await attachments.trash_attachment(pool, tenant, attachment_id, ip=ip)
    if retention > 0:
        return False
    try:
        await purge_attachment(pool, tenant, attachment_id, root=root, ip=ip)
    except Exception as exc:
        # The trash stands; the retention purge removes the file on its next run.
        logger.warning(
            "Attachment %s stays in the trash: its purge failed (%s).",
            safe_log(attachment_id),
            type(exc).__name__,
        )
        return False
    return True


async def _purge_expired_chat(
    pool: asyncpg.Pool, root: Path, org_id: UUID, chat_id: UUID, cutoff: datetime
) -> bool:
    """Purge one expired chat by the system (J3, T8, T9, ``chat.purge``), then its files.

    Returns:
        False when the chat was restored, purged or is no longer expired.
    """
    async with pool.acquire() as conn, conn.transaction():
        if await conn.fetchval(_LOCK_EXPIRED_CHAT_SQL, chat_id, org_id, cutoff) is None:
            return False
        file_ids = await _delete_chat_rows(conn, chat_id, org_id)
        await audit_events.record(
            conn,
            action=AuditAction.CHAT_PURGE,
            actor_kind="system",
            actor_user_id=None,
            org_id=org_id,
            target_type=TargetType.CHAT,
            target_ids=(chat_id,),
            metadata={"file_count": len(file_ids)},
        )
    await attachments.remove_files(root, org_id, file_ids)
    return True


async def _purge_expired_file(
    pool: asyncpg.Pool, root: Path, org_id: UUID, attachment_id: UUID, cutoff: datetime
) -> bool:
    """Purge one expired file of its own by the system (J5, ``file.purge``), then its files.

    Returns:
        False when the file was restored, purged or is no longer expired.
    """
    async with pool.acquire() as conn, conn.transaction():
        if await conn.fetchval(_DELETE_EXPIRED_FILE_SQL, attachment_id, org_id, cutoff) is None:
            return False
        await audit_events.record(
            conn,
            action=AuditAction.FILE_PURGE,
            actor_kind="system",
            actor_user_id=None,
            org_id=org_id,
            target_type=TargetType.FILE,
            target_ids=(attachment_id,),
        )
    await attachments.remove_files(root, org_id, (attachment_id,))
    return True


async def purge_expired(pool: asyncpg.Pool, root: Path, *, now: datetime | None = None) -> int:
    """Purge every org's expired trash items by the system (the retention purge).

    For each org with a trashed row (J1, in id order), with that org's own
    effective retention: each expired chat (J2) and then each expired file of
    its own (J4), one transaction per item recording ``chat.purge`` /
    ``file.purge`` by the system, its files removed after the commit. An item
    restored or purged meanwhile is skipped.

    Args:
        pool: The database pool.
        root: The attachments root.
        now: The current time (default: ``datetime.now(UTC)``).

    Returns:
        The number of items purged.

    Raises:
        Exception: A database error of J1. An item's failure is logged and the
            next item goes on; a failure of an org's retention read or J2
            skips the org for this run, one of J4 keeps the org's chats
            purged before it.
    """
    purged = 0
    for org_row in await pool.fetch(_TRASH_ORGS_SQL):
        org_id = org_row["org_id"]
        try:
            _, cutoff = await _retention_cutoff(pool, org_id, now)
            chat_ids = [row["id"] for row in await pool.fetch(_EXPIRED_CHATS_SQL, org_id, cutoff)]
        except Exception as exc:
            # The org waits for the next run; the other orgs go on.
            logger.warning(
                "Trash purge of org %s failed (%s).", safe_log(org_id), type(exc).__name__
            )
            continue
        for chat_id in chat_ids:
            try:
                if await _purge_expired_chat(pool, root, org_id, chat_id, cutoff):
                    purged += 1
            except Exception as exc:
                logger.warning(
                    "Trash purge of chat %s failed (%s).", safe_log(chat_id), type(exc).__name__
                )
        try:
            file_ids = [row["id"] for row in await pool.fetch(_EXPIRED_FILES_SQL, org_id, cutoff)]
        except Exception as exc:
            # The chats purged above stay purged; the files wait for the next run.
            logger.warning(
                "Trash purge of org %s failed (%s).", safe_log(org_id), type(exc).__name__
            )
            continue
        for attachment_id in file_ids:
            try:
                if await _purge_expired_file(pool, root, org_id, attachment_id, cutoff):
                    purged += 1
            except Exception as exc:
                logger.warning(
                    "Trash purge of attachment %s failed (%s).",
                    safe_log(attachment_id),
                    type(exc).__name__,
                )
    return purged


async def run_purge_job(
    pool: asyncpg.Pool, *, interval_seconds: float = PURGE_INTERVAL_SECONDS
) -> None:
    """Run the retention purge now and then once per interval, until cancelled.

    Each run reads the root through ``attachments.attachments_root()``. A
    failed run is logged (class name only) and retried at the next interval;
    cancellation stops the job.

    Args:
        pool: The database pool.
        interval_seconds: Seconds between runs (default: one hour).
    """
    while True:
        try:
            await purge_expired(pool, attachments.attachments_root())
        except Exception as exc:
            logger.warning("Trash purge failed (%s); retrying next interval.", type(exc).__name__)
        await asyncio.sleep(interval_seconds)
