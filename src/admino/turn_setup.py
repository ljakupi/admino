"""The send path's turn setup: a run's policy, prompt inputs and owner check, one read (GH-244).

``POST /api/chats/{chat_id}/messages`` makes at most 3 database statements
before its LLM call: the session lookup, this turn setup, and the chat with
its latest messages (``chats.load_turn``). ``load_turn_setup`` reads, in ONE
statement, what the run otherwise needs four reads for: the org's permission
rows, tool switches and residency flag (``org_permissions.load_tool_policy``),
the caller's prompt inputs (``scoped_settings.load_prompt_context``) and
whether the chat is the caller's live chat (the owner check of
``chats.get_chat``). It converts them with the old loaders' own pure helpers
(``org_permissions.policy_from_rows``, ``scoped_settings.switches_from_row``,
``residency_from_value``, ``prompt_context_from_row``), so for every database
state both paths give the same policy and prompt context. The old loaders
stay for the legacy and confirm routes and the settings pages.

Inputs: an executor (the pool or a connection), the run's ``TenantContext``
and the chat id from the path.
Outputs: a frozen ``TurnSetup``: the org's ``ToolPolicy``, the caller's
``PromptContext`` and ``chat_found``.

Security notes:
- Tenant isolation: the organizations row is the tenant's (``o.id = $1``);
  the settings, permission rows, user and chat are joined to it, the user
  only as a live member of that org, the chat only as that user's live chat
  of that org. Another org's chat, a colleague's, a trashed and an unknown
  one read ``chat_found`` False, exactly as ``chats.get_chat`` refuses them,
  and the chat named never changes the policy or the prompt context.
- Fail closed: a tenant org without an organizations row gives no row,
  which reads as residency on (every ``RESIDENCY_BLOCKED_TOOLS`` tool off, so
  no non-Swiss provider or Google/Microsoft tool), an empty matrix
  (default-deny), ``PromptContext()`` and no chat.
- One read: nothing is written, no transaction is opened, and nothing is
  logged (the instructions are content).
- Parameterized SQL only: one constant statement, every value a bind
  parameter. Imports only org_permissions and scoped_settings from admino
  (and models and tenancy for types): never the server, agent, LLM, tools or
  database modules.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Protocol

from admino import org_permissions, scoped_settings

if TYPE_CHECKING:
    from uuid import UUID

    from admino.models import PromptContext, ToolPolicy
    from admino.tenancy import TenantContext

# T1 (contract C3): one statement instead of four, because the send path may make at most
# 3 statements before its LLM call. The org's row anchors it: no row when the org is
# missing; NULL settings columns without an org_settings row; NULL user columns unless the
# user is a live member of the org; a NULL chat_id unless the chat is that user's live chat
# of the org. The permission rows come as a list of [tool, action, permission] arrays.
_TURN_SETUP_SQL: Final = """
    SELECT o.data_residency, o.default_response_language,
           s.gmail_enabled AS gmail, s.google_calendar_enabled AS google_calendar,
           s.google_drive_enabled AS google_drive, s.outlook_enabled AS outlook,
           s.outlook_calendar_enabled AS outlook_calendar, s.onedrive_enabled AS onedrive,
           s.memory_enabled AS memory, s.instructions AS org_instructions,
           u.id AS user_id, u.response_language, u.timezone, u.personal_instructions,
           c.id AS chat_id,
           ARRAY(
               SELECT ARRAY[p.tool, p.action, p.permission]
               FROM permissions p
               WHERE p.org_id = o.id
           ) AS permission_rows
    FROM organizations o
    LEFT JOIN org_settings s ON s.org_id = o.id
    LEFT JOIN users u ON u.id = $2 AND u.org_id = o.id AND u.deleted_at IS NULL
    LEFT JOIN chats c
        ON c.id = $3 AND c.org_id = o.id AND c.owner_user_id = $2 AND c.deleted_at IS NULL
    WHERE o.id = $1
"""


class Executor(Protocol):
    """What the turn setup runs through: an asyncpg pool or connection."""

    # Any: asyncpg returns an untyped Record (or None).
    async def fetchrow(self, query: str, *args: object) -> Any:
        """Run one query and return its first row, or None."""
        ...


@dataclass(frozen=True)
class TurnSetup:
    """What a chat run needs before its chat is loaded, from one statement."""

    policy: ToolPolicy
    prompt_context: PromptContext
    # Whether the chat is the caller's live chat (chats.get_chat would return it).
    chat_found: bool


async def load_turn_setup(executor: Executor, tenant: TenantContext, chat_id: UUID) -> TurnSetup:
    """Return the run's tool policy, prompt context and owner check, in one statement.

    Args:
        executor: The pool, or a connection.
        tenant: The org scope and user of the run.
        chat_id: The chat the message is sent to.

    Returns:
        The ``TurnSetup``: ``policy`` equals ``org_permissions.load_tool_policy``
        and ``prompt_context`` equals ``scoped_settings.load_prompt_context``
        for the tenant; ``chat_found`` is True only for the caller's own live
        chat. A missing org row fails closed (residency on, an empty matrix,
        ``PromptContext()``, no chat).
    """
    row = await executor.fetchrow(_TURN_SETUP_SQL, tenant.org_id, tenant.user_id, chat_id)
    # No row: the tenant's org has no organizations row. Each helper reads None as its
    # missing-row value, which for the policy is the fail-closed one.
    org_found = row is not None
    policy = org_permissions.policy_from_rows(
        row["permission_rows"] if org_found else (),
        enabled_tools=scoped_settings.switches_from_row(row),
        data_residency=scoped_settings.residency_from_value(
            row["data_residency"] if org_found else None
        ),
    )
    member = org_found and row["user_id"] is not None
    return TurnSetup(
        policy=policy,
        prompt_context=scoped_settings.prompt_context_from_row(row if member else None),
        chat_found=org_found and row["chat_id"] is not None,
    )
