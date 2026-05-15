"""Persistent key-value memory tool (PostgreSQL-backed).

Provides store, recall, and list actions for the agent's long-term memory.
Data persists across sessions and container restarts via PostgreSQL.

Security notes:
- All SQL uses parameterized queries ($1, $2). No string interpolation.
- No DELETE capability. memory.delete is a hardcoded deny in permissions.py.
- Does not import from agent.py, llm.py, or server.py.
"""

from __future__ import annotations

import logging

from admino.database import get_pool
from admino.models import MemoryListArgs, MemoryRecallArgs, MemoryStoreArgs
from admino.tools.registry import register_tool

logger = logging.getLogger(__name__)


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
    pool = get_pool()
    await pool.execute(
        """
        INSERT INTO memory (key, value)
        VALUES ($1, $2)
        ON CONFLICT (key) DO UPDATE SET
            value = EXCLUDED.value,
            updated_at = now()
        """,
        args.key,
        args.value,
    )
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
    pool = get_pool()
    row = await pool.fetchrow("SELECT value FROM memory WHERE key = $1", args.key)
    if row is None:
        return f"No memory found for key: {args.key}"
    return str(row["value"])


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
    pool = get_pool()
    rows = await pool.fetch("SELECT key FROM memory ORDER BY key")
    if not rows:
        return "No memories stored."
    return "\n".join(str(row["key"]) for row in rows)
