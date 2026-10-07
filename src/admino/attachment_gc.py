"""Orphan attachment garbage collection (GH-187, Decision 13).

An attachment never sent with a message within ``ORPHAN_AGE`` (24 h) is an
orphan: its row and files are deleted and a ``file.delete`` event is recorded
by the system with ``{"orphan": true}``. Leftover disk entries older than
``ORPHAN_AGE`` without a row (an interrupted upload's ``.part``, a failed
removal) are deleted too. The job runs at startup and then hourly.

Inputs: the database pool, the attachments root (``<root>/<org_id>/`` holds
``<id>``, ``<id>.part`` and the derived ``<id>.d/`` of each attachment), the
current time.
Outputs: the number of orphan rows plus stray entries removed.

Order: G1 selects the orphans; each one is deleted (G2, which re-checks
``message_id IS NULL`` so a file sent meanwhile is kept) and audited in its
own transaction, and its files are removed after the commit (a rolled-back
deletion never loses files). Then each org directory is swept: an old
``.part`` always goes (no upload runs for a day); an old ``<id>`` or
``<id>.d`` goes unless G3 finds the org's row (trashed rows included: their
files wait for the trash purge of #194).

Security notes:
- Never follows a symlink: org directories that are symlinks are skipped,
  entries are inspected with ``lstat`` and a symlink is unlinked itself;
  only canonical UUID names are touched (anything else is skipped).
- G3 is scoped to the directory's org, so another org's row never keeps an
  entry alive.
- One failing row or directory is logged and the rest continues. Logs carry
  ids (through ``safe_log``) and exception class names only: never a file
  name, a path or an exception's message.
- Parameterized SQL only (contract forms G1-G3). Imports nothing from the
  server, agent, LLM or tools layers; no LLM tool reaches this module.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import stat
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, NamedTuple

from admino import attachments, audit_events
from admino.audit_events import AuditAction, TargetType
from admino.logs import safe_log

if TYPE_CHECKING:
    from pathlib import Path

    import asyncpg

logger = logging.getLogger(__name__)

ORPHAN_AGE: Final = timedelta(hours=24)
GC_INTERVAL_SECONDS: Final = 3600.0

_PART_SUFFIX: Final = ".part"
_DERIVED_SUFFIX: Final = ".d"

# G1: unsent rows created before the cutoff, oldest first.
_ORPHANS_SQL: Final = """
    SELECT id, org_id FROM attachments
    WHERE message_id IS NULL AND created_at < $1
    ORDER BY created_at, id
"""
# G2: delete the orphan unless a message took it since G1.
_DELETE_ORPHAN_SQL: Final = """
    DELETE FROM attachments WHERE id = $1 AND org_id = $2 AND message_id IS NULL
    RETURNING id
"""
# G3: which of the candidate ids still have a row in this org (trashed included).
_KNOWN_SQL: Final = "SELECT id FROM attachments WHERE org_id = $1 AND id = ANY($2::uuid[])"


class _Entry(NamedTuple):
    """An old candidate entry of an org directory."""

    name: str
    attachment_id: uuid.UUID
    is_part: bool


def _canonical_uuid(text: str) -> uuid.UUID | None:
    """The UUID ``text`` names in its canonical form (as the app writes it), else None."""
    try:
        value = uuid.UUID(text)
    except ValueError:
        return None
    return value if str(value) == text else None


def _parse_name(name: str) -> tuple[uuid.UUID, bool] | None:
    """``(id, is_part)`` for ``<uuid>``, ``<uuid>.part`` or ``<uuid>.d``; None otherwise."""
    for suffix in (_PART_SUFFIX, _DERIVED_SUFFIX):
        if name.endswith(suffix):
            attachment_id = _canonical_uuid(name.removesuffix(suffix))
            return None if attachment_id is None else (attachment_id, suffix == _PART_SUFFIX)
    attachment_id = _canonical_uuid(name)
    return None if attachment_id is None else (attachment_id, False)


def _org_dirs(root: Path) -> list[tuple[uuid.UUID, Path]]:
    """The real (non-symlink) directories directly under ``root`` named as an org id."""
    found: list[tuple[uuid.UUID, Path]] = []
    with os.scandir(root) as entries:
        for entry in entries:
            org_id = _canonical_uuid(entry.name)
            if org_id is not None and entry.is_dir(follow_symlinks=False):
                found.append((org_id, root / entry.name))
    return found


def _old_entries(org_dir: Path, cutoff: float) -> list[_Entry]:
    """The attachment-named entries of ``org_dir`` whose own mtime is before ``cutoff``."""
    found: list[_Entry] = []
    with os.scandir(org_dir) as entries:
        for entry in entries:
            parsed = _parse_name(entry.name)
            if parsed is None:
                continue
            try:
                mtime = entry.stat(follow_symlinks=False).st_mtime
            except FileNotFoundError:
                continue
            if mtime < cutoff:
                found.append(_Entry(entry.name, *parsed))
    return found


def _remove_entries(org_dir: Path, entries: list[_Entry]) -> int:
    """Remove the given entries of ``org_dir`` (a tree counts once); count the removals."""
    removed = 0
    for entry in entries:
        path = org_dir / entry.name
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
                "Stray attachment entry %s couldn't be removed (%s).",
                safe_log(entry.attachment_id),
                type(exc).__name__,
            )
            continue
        removed += 1
    return removed


async def _delete_orphan(pool: asyncpg.Pool, attachment_id: uuid.UUID, org_id: uuid.UUID) -> bool:
    """Delete one orphan row and record its ``file.delete`` in one transaction.

    Returns:
        False when a message took the row since it was selected (nothing done).
    """
    async with pool.acquire() as conn, conn.transaction():
        if await conn.fetchval(_DELETE_ORPHAN_SQL, attachment_id, org_id) is None:
            return False
        await audit_events.record(
            conn,
            action=AuditAction.FILE_DELETE,
            actor_kind="system",
            actor_user_id=None,
            org_id=org_id,
            target_type=TargetType.FILE,
            target_ids=(attachment_id,),
            metadata={"orphan": True},
        )
    return True


async def _collect_orphans(pool: asyncpg.Pool, root: Path, cutoff: datetime) -> int:
    """Delete every orphan row created before ``cutoff`` and its files; count the rows."""
    collected = 0
    for row in await pool.fetch(_ORPHANS_SQL, cutoff):
        attachment_id, org_id = row["id"], row["org_id"]
        try:
            deleted = await _delete_orphan(pool, attachment_id, org_id)
        except Exception as exc:
            logger.warning(
                "Orphan attachment %s couldn't be collected (%s).",
                safe_log(attachment_id),
                type(exc).__name__,
            )
            continue
        if deleted:
            # After the commit: a rolled-back deletion keeps its files.
            await attachments.remove_files(root, org_id, (attachment_id,))
            collected += 1
    return collected


async def _sweep_org_dir(
    pool: asyncpg.Pool, org_id: uuid.UUID, org_dir: Path, cutoff: float
) -> int:
    """Remove the old stray entries of one org directory; count them."""
    candidates = await asyncio.to_thread(_old_entries, org_dir, cutoff)
    checked = {entry.attachment_id for entry in candidates if not entry.is_part}
    known: set[int] = set()
    if checked:
        rows = await pool.fetch(_KNOWN_SQL, org_id, list(checked))
        # Compared by value: asyncpg returns its own UUID subclass.
        known = {row["id"].int for row in rows}
    doomed = [
        entry for entry in candidates if entry.is_part or entry.attachment_id.int not in known
    ]
    if not doomed:
        return 0
    return await asyncio.to_thread(_remove_entries, org_dir, doomed)


async def _sweep_strays(pool: asyncpg.Pool, root: Path, cutoff: datetime) -> int:
    """Remove the old entries without a row in every org directory; count them."""
    try:
        org_dirs = await asyncio.to_thread(_org_dirs, root)
    except FileNotFoundError:
        # Nothing was ever uploaded.
        return 0
    except OSError as exc:
        logger.warning("Attachments root couldn't be listed (%s).", type(exc).__name__)
        return 0
    removed = 0
    for org_id, org_dir in org_dirs:
        try:
            removed += await _sweep_org_dir(pool, org_id, org_dir, cutoff.timestamp())
        except Exception as exc:
            logger.warning(
                "Attachment directory of org %s couldn't be swept (%s).",
                safe_log(org_id),
                type(exc).__name__,
            )
    return removed


async def collect_garbage(pool: asyncpg.Pool, root: Path, *, now: datetime | None = None) -> int:
    """Delete the orphan attachments and the stray disk entries older than ``ORPHAN_AGE``.

    Args:
        pool: The database pool.
        root: The attachments root (``attachments.attachments_root()``).
        now: The current time (default: ``datetime.now(UTC)``); rows created
            and entries modified before ``now - ORPHAN_AGE`` are old.

    Returns:
        The number of orphan rows plus stray entries removed.

    Raises:
        Exception: A database error of G1 (per-row and per-directory
            failures are logged and skipped).
    """
    cutoff = (now if now is not None else datetime.now(UTC)) - ORPHAN_AGE
    collected = await _collect_orphans(pool, root, cutoff)
    return collected + await _sweep_strays(pool, root, cutoff)


async def run_gc_job(pool: asyncpg.Pool, *, interval_seconds: float = GC_INTERVAL_SECONDS) -> None:
    """Collect garbage now and then once per interval, until cancelled.

    Each run reads the root through ``attachments.attachments_root()``. A
    failed run is logged (class name only) and retried at the next interval;
    cancellation stops the job.

    Args:
        pool: The database pool.
        interval_seconds: Seconds between runs (default: one hour).
    """
    while True:
        try:
            await collect_garbage(pool, attachments.attachments_root())
        except Exception as exc:
            logger.warning(
                "Attachment garbage collection failed (%s); retrying next interval.",
                type(exc).__name__,
            )
        await asyncio.sleep(interval_seconds)
