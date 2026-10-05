"""Persistent key-value memory tool: each user's own notes (PostgreSQL-backed).

Provides store, recall, and list actions for the agent's long-term memory.
Data persists across sessions and container restarts via PostgreSQL, in the
``memory`` table of migration 0017 (GH-162): one row per (user_id, key),
each naming the user's org.

Inputs: the validated args (``MemoryStoreArgs``, ``MemoryRecallArgs``,
``MemoryListArgs``) and the required keyword ``tenant`` (the run's
``TenantContext``, passed by ``registry.dispatch_tool_call``). Outputs: a
confirmation ("Stored memory: <key>"), the stored value wrapped as untrusted
memory content or "No memory found for key: <key>", the newline-joined sorted
keys wrapped as untrusted memory content or "No memories stored.".

Security notes:
- Tenant isolation: every statement binds the tenant's user_id AND org_id,
  so a user only stores, recalls and lists their own notes in their own org.
  The tenant comes from the server-side session, never from LLM arguments.
- All SQL uses parameterized queries ($1, $2, ...). No string interpolation.
- No DELETE capability. memory.delete is a hardcoded deny in permissions.py.
- No content in logs: keys and values are never logged.
- Untrusted content (GH-243): a note may have been planted by an earlier
  email ("remember ..."), so a recalled value and the key list reach the
  model only through ``untrusted.wrap`` (kind ``memory``), and the agent
  escalates the run's later side effects to confirmation. The store
  confirmation and the not-found messages carry no stored text and stay
  unwrapped.
- Does not import from agent.py, llm.py, or server.py.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from admino import untrusted
from admino.database import get_pool
from admino.models import MemoryListArgs, MemoryRecallArgs, MemoryStoreArgs
from admino.tools.registry import register_tool

if TYPE_CHECKING:
    from admino.tenancy import TenantContext

_STORE_SQL: Final = """
    INSERT INTO memory (user_id, org_id, key, value) VALUES ($1, $2, $3, $4)
    ON CONFLICT (user_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
"""
_RECALL_SQL: Final = "SELECT value FROM memory WHERE user_id = $1 AND org_id = $2 AND key = $3"
_LIST_SQL: Final = "SELECT key FROM memory WHERE user_id = $1 AND org_id = $2 ORDER BY key"


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


@register_tool(
    tool="memory",
    action="store",
    description="Store a key-value note in persistent memory. Updates existing key if present.",
    args_schema=MemoryStoreArgs,
    side_effect=True,
)
async def memory_store(args: MemoryStoreArgs, *, tenant: TenantContext, **_: object) -> str:
    """Upsert one of the caller's notes.

    If the caller already has a note under the key, its value and updated_at
    change; otherwise a new row is inserted.

    Args:
        args: Validated store arguments (key, value).
        tenant: The caller's tool context (owner of the note).

    Returns:
        A confirmation message.
    """
    await get_pool().execute(_STORE_SQL, tenant.user_id, tenant.org_id, args.key, args.value)
    return f"Stored memory: {args.key}"


@register_tool(
    tool="memory",
    action="recall",
    description="Recall a value from persistent memory by key.",
    args_schema=MemoryRecallArgs,
    side_effect=False,
)
async def memory_recall(args: MemoryRecallArgs, *, tenant: TenantContext, **_: object) -> str:
    """Retrieve one of the caller's notes by key.

    Args:
        args: Validated recall arguments (key).
        tenant: The caller's tool context.

    Returns:
        The stored value, wrapped as untrusted memory content, or a not-found
        message.
    """
    row = await get_pool().fetchrow(_RECALL_SQL, tenant.user_id, tenant.org_id, args.key)
    if row is None:
        return f"No memory found for key: {args.key}"
    return untrusted.wrap("memory", f"memory note {args.key}", str(row["value"]))


@register_tool(
    tool="memory",
    action="list",
    description="List all keys stored in persistent memory.",
    args_schema=MemoryListArgs,
    side_effect=False,
)
async def memory_list(args: MemoryListArgs, *, tenant: TenantContext, **_: object) -> str:
    """List the keys of the caller's notes.

    Args:
        args: Empty args model (no arguments needed).
        tenant: The caller's tool context.

    Returns:
        A newline-separated, sorted list of keys, wrapped as untrusted memory
        content, or a message if the caller has no notes.
    """
    rows = await get_pool().fetch(_LIST_SQL, tenant.user_id, tenant.org_id)
    if not rows:
        return "No memories stored."
    return untrusted.wrap("memory", "memory keys", "\n".join(str(row["key"]) for row in rows))
