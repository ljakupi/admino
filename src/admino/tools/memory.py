"""Persistent key-value memory tool (SQLite-backed).

Provides store, recall, and list actions for the agent's long-term memory.
Data persists across sessions and container restarts via Docker volume mount.

Security notes:
- All SQL is parameterized. No string interpolation in queries.
- No DELETE capability. memory.delete is a hardcoded deny in permissions.py.
- Does not import from agent.py, llm.py, or server.py.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import aiosqlite

from admino.models import MemoryListArgs, MemoryRecallArgs, MemoryStoreArgs
from admino.tools.registry import register_tool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level configuration
# ---------------------------------------------------------------------------

_db_path: str = os.path.join(os.environ.get("DATA_DIR", "/app/data"), "db", "admino.db")


def configure(db_path: str | Path) -> None:
    """Set the database path for the memory tool.

    Called by main.py during startup to override the default path
    with the value from AppConfig.paths.database.

    Args:
        db_path: Absolute path to the SQLite database file.

    Raises:
        ValueError: If db_path is not an absolute path.
    """
    resolved = Path(db_path).resolve()
    if not resolved.is_absolute():
        msg = f"db_path must be an absolute path, got: {str(db_path)[:100]}"
        raise ValueError(msg)
    global _db_path
    _db_path = str(resolved)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

_CREATE_TABLE_SQL = """\
CREATE TABLE IF NOT EXISTS memory (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
)
"""


async def _ensure_db() -> None:
    """Create the memory table if it does not exist.

    Also ensures the parent directory exists so that aiosqlite can
    create the database file on first use.
    """
    db_dir = Path(_db_path).parent
    db_dir.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(_db_path) as db:
        await db.execute(_CREATE_TABLE_SQL)
        await db.commit()


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


@register_tool(
    tool="memory",
    action="store",
    description="Store a key-value note in persistent memory. Updates existing key if present.",
    args_schema=MemoryStoreArgs,
)
async def memory_store(args: MemoryStoreArgs, **kwargs: object) -> str:
    """Upsert a key-value pair in the memory table.

    If the key already exists, updates the value and updated_at timestamp.
    If the key is new, inserts a new row.

    Args:
        args: Validated store arguments (key, value).

    Returns:
        A confirmation message.
    """
    await _ensure_db()
    async with aiosqlite.connect(_db_path) as db:
        await db.execute(
            """
            INSERT INTO memory (key, value, created_at, updated_at)
            VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'),
                    strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
            """,
            (args.key, args.value),
        )
        await db.commit()
    return f"Stored memory: {args.key}"


@register_tool(
    tool="memory",
    action="recall",
    description="Recall a value from persistent memory by key.",
    args_schema=MemoryRecallArgs,
)
async def memory_recall(args: MemoryRecallArgs, **kwargs: object) -> str:
    """Retrieve a value from the memory table by key.

    Args:
        args: Validated recall arguments (key).

    Returns:
        The stored value, or a not-found message.
    """
    await _ensure_db()
    async with aiosqlite.connect(_db_path) as db:
        cursor = await db.execute(
            "SELECT value FROM memory WHERE key = ?",
            (args.key,),
        )
        row = await cursor.fetchone()
    if row is None:
        return f"No memory found for key: {args.key}"
    return str(row[0])


@register_tool(
    tool="memory",
    action="list",
    description="List all keys stored in persistent memory.",
    args_schema=MemoryListArgs,
)
async def memory_list(args: MemoryListArgs, **kwargs: object) -> str:
    """List all keys in the memory table.

    Args:
        args: Empty args model (no arguments needed).

    Returns:
        A newline-separated list of keys, or a message if memory is empty.
    """
    await _ensure_db()
    async with aiosqlite.connect(_db_path) as db:
        cursor = await db.execute("SELECT key FROM memory ORDER BY key")
        rows = await cursor.fetchall()
    if not rows:
        return "No memories stored."
    keys = [str(row[0]) for row in rows]
    return "\n".join(keys)
