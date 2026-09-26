"""Account repository: organizations and users, including the last-admin guard (GH-145).

Organizations and users are account metadata, not org content, so the
functions here take an explicit org_id instead of a TenantContext: the Super
Admin platform routes (#167) use them as well as the org routes (#164).

``ensure_not_last_active_admin`` is the single last-admin guard: an
organization always keeps at least one active Org Admin. #164 and #167 call it
before demoting, deactivating or deleting a user.

Inputs: an asyncpg connection inside the caller's transaction, plus the org_id
and user_id of the account being changed. Output: None, LastAdminError, or
UserNotInOrgError when the user isn't a member of that org.

Concurrency: the caller must hold a transaction. The guard locks the target's
row and the org's active Org Admin rows with SELECT ... FOR UPDATE, in id order
so concurrent guards can't deadlock. Concurrent demotions serialize: under READ
COMMITTED the second transaction waits for the first, then re-checks the locked
rows after it commits and sees the demoted admin gone, so both can't pass.

Security notes:
- Tenant isolation: the target must belong to org_id. A user of another org
  raises UserNotInOrgError (callers answer 404), so a mismatched
  (org_id, user_id) pair can't slip past the guard.
- Parameterized SQL only: org_id and user_id travel as the $1 and $2 bind
  parameters.
- No content in errors: the guard's errors carry no IDs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from uuid import UUID

    import asyncpg

# The target's row (only when it belongs to the org) plus the org's active Org
# Admins, each flagged, locked in id order.
_TARGET_AND_ACTIVE_ADMINS_SQL: Final = """
    SELECT id,
           (role = 'org_admin' AND status = 'active' AND deleted_at IS NULL)
               AS is_active_admin
    FROM users
    WHERE org_id = $1
      AND (id = $2 OR (role = 'org_admin' AND status = 'active' AND deleted_at IS NULL))
    ORDER BY id
    FOR UPDATE
"""


class LastAdminError(Exception):
    """Raised when a change would leave an organization without an active Org Admin."""

    def __init__(self) -> None:
        super().__init__("An organization must keep at least one active Org Admin.")


class UserNotInOrgError(Exception):
    """Raised when the user being changed isn't a member of the given organization."""

    def __init__(self) -> None:
        super().__init__("The user is not a member of this organization.")


async def ensure_not_last_active_admin(
    conn: asyncpg.Connection, *, org_id: UUID, user_id: UUID
) -> None:
    """Refuse to demote, deactivate or delete the org's last active Org Admin.

    Must run inside the caller's transaction, before the change: the target's
    row and the org's active Org Admin rows stay locked (FOR UPDATE) until that
    transaction ends.

    Args:
        conn: An asyncpg connection inside the caller's transaction.
        org_id: The organization the user belongs to.
        user_id: The user about to be demoted, deactivated or deleted.

    Raises:
        RuntimeError: If conn is not inside a transaction (no query is issued).
        UserNotInOrgError: If user_id isn't a member of org_id.
        LastAdminError: If user_id is the org's only active Org Admin.
    """
    if not conn.is_in_transaction():
        msg = "The last-admin guard must run inside a transaction."
        raise RuntimeError(msg)
    rows = await conn.fetch(_TARGET_AND_ACTIVE_ADMINS_SQL, org_id, user_id)
    target = next((row for row in rows if row["id"] == user_id), None)
    if target is None:
        raise UserNotInOrgError
    active_admins = sum(1 for row in rows if row["is_active_admin"])
    if target["is_active_admin"] and active_admins == 1:
        raise LastAdminError
