"""Account repository: organizations, users, the last-admin guard and the Super Admin bootstrap.

Organizations and users are account metadata, not org content, so the
functions here take an explicit org_id instead of a TenantContext: the Super
Admin platform routes (#167) use them as well as the org routes (#164).

``ensure_not_last_active_admin`` is the single last-admin guard (GH-145): an
organization always keeps at least one active Org Admin. ``admino.org_users``
(#164) and #167 call it before demoting, deactivating or deleting a user.

``org_user_ids`` lists the ids of an organization's users: the server delivers
a completed critical permission promotion's notice to that org's in-memory chats
only (GH-161).

``email_exists`` and ``create_super_admin`` back the create-superadmin CLI (GH-150,
``admino.admin_cli``). ``email_exists`` is a case-insensitive lookup, like the
users_email_lower_key unique index. ``create_super_admin`` inserts an active
Super Admin (no org, no role) and records its ``user.activate`` audit event
(actor ``operator``, no org) on the same connection, inside the caller's
transaction, so a failed audit write leaves no account behind.

Inputs: an asyncpg connection inside the caller's transaction, plus the org_id
and user_id of the account being changed (the guard) or the new Super Admin's
email, name and password hash; or the pool (the email and org user lookups).
Outputs: None, LastAdminError, or UserNotInOrgError when the user
isn't a member of that org (the guard); the org's user ids (``org_user_ids``);
whether the email is taken (``email_exists``); the new user's id, or
DuplicateEmailError when the email is already taken (``create_super_admin``).

Concurrency: the caller must hold a transaction. The guard locks the target's
row and the org's active Org Admin rows with SELECT ... FOR UPDATE, in id order
so concurrent guards can't deadlock. Concurrent demotions serialize: under READ
COMMITTED the second transaction waits for the first, then re-checks the locked
rows after it commits and sees the demoted admin gone, so both can't pass. Two
concurrent Super Admin creates with the same email collide on the unique
index: the second gets DuplicateEmailError.

Security notes:
- Tenant isolation: the target must belong to org_id. A user of another org
  raises UserNotInOrgError (callers answer 404), so a mismatched
  (org_id, user_id) pair can't slip past the guard.
- Parameterized SQL only: org_id and user_id travel as the $1 and $2 bind
  parameters, and the email, name and password hash as the $1, $2 and $3 bind
  parameters.
- ``org_user_ids`` reads the ids of the given org's users only (org_id is its
  single bind parameter), nothing else of the rows.
- Content-free audit: the user.activate event names the new user's id only,
  never the email, the name or the hash.
- No content in errors: the guard's errors carry no IDs, and
  DuplicateEmailError is raised ``from None`` with a fixed message, so the
  driver's detail (which repeats the email) doesn't travel with it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final
from uuid import UUID

import asyncpg

from admino import audit_events
from admino.audit_events import AuditAction, TargetType

if TYPE_CHECKING:
    from asyncpg.pool import PoolConnectionProxy

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

_ORG_USER_IDS_SQL: Final = "SELECT id FROM users WHERE org_id = $1"

# Case-insensitive, like the users_email_lower_key unique index.
_EMAIL_EXISTS_SQL: Final = "SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = lower($1))"

# A Super Admin has no org and no role (org_id and role stay NULL).
_CREATE_SUPER_ADMIN_SQL: Final = """
    INSERT INTO users (email, name, password_hash, kind, status)
    VALUES ($1, $2, $3, 'super_admin', 'active')
    RETURNING id
"""


class LastAdminError(Exception):
    """Raised when a change would leave an organization without an active Org Admin."""

    def __init__(self) -> None:
        super().__init__("An organization must keep at least one active Org Admin.")


class UserNotInOrgError(Exception):
    """Raised when the user being changed isn't a member of the given organization."""

    def __init__(self) -> None:
        super().__init__("The user is not a member of this organization.")


class DuplicateEmailError(Exception):
    """Raised when a user with the email (in any capitalization) already exists."""

    def __init__(self) -> None:
        super().__init__("A user with this email already exists.")


async def org_user_ids(
    executor: asyncpg.Pool | asyncpg.Connection, org_id: UUID
) -> frozenset[UUID]:
    """Return the ids of every user of an organization, whatever their status.

    Args:
        executor: The pool or a connection to read through.
        org_id: The organization (the single bind parameter).

    Returns:
        The users' ids as plain ``uuid.UUID`` values (asyncpg's UUID type is
        normalized, so they compare and hash like any other UUID).
    """
    rows = await executor.fetch(_ORG_USER_IDS_SQL, org_id)
    return frozenset(UUID(str(row["id"])) for row in rows)


async def email_exists(executor: asyncpg.Pool | asyncpg.Connection, email: str) -> bool:
    """Return whether a user with this email exists, ignoring capitalization.

    Args:
        executor: The pool or a connection to read through.
        email: The email to look up (the single bind parameter).

    Returns:
        True if a user (of any org, or a Super Admin) has this email.
    """
    return bool(await executor.fetchval(_EMAIL_EXISTS_SQL, email))


async def create_super_admin(
    conn: asyncpg.Connection | PoolConnectionProxy,
    *,
    email: str,
    name: str,
    password_hash: str,
) -> UUID:
    """Insert an active Super Admin and record its user.activate audit event.

    Must run inside the caller's transaction: the insert and the audit event
    commit or roll back together.

    Args:
        conn: An asyncpg connection inside the caller's transaction.
        email: The Super Admin's email address.
        name: The display name.
        password_hash: The Argon2id PHC string of the password.

    Returns:
        The new user's id.

    Raises:
        RuntimeError: If conn is not inside a transaction (no query is issued).
        DuplicateEmailError: If a user with this email already exists (nothing
            is audited).
        AuditRecordError: If the audit event can't be recorded; the caller's
            transaction must roll back.
    """
    if not conn.is_in_transaction():
        msg = "A Super Admin must be created inside a transaction."
        raise RuntimeError(msg)
    try:
        user_id: UUID = await conn.fetchval(_CREATE_SUPER_ADMIN_SQL, email, name, password_hash)
    except asyncpg.UniqueViolationError:
        raise DuplicateEmailError from None
    await audit_events.record(
        conn,
        action=AuditAction.USER_ACTIVATE,
        actor_kind="operator",
        actor_user_id=None,
        org_id=None,
        target_type=TargetType.USER,
        target_ids=[user_id],
    )
    return user_id


async def ensure_not_last_active_admin(
    conn: asyncpg.Connection | PoolConnectionProxy, *, org_id: UUID, user_id: UUID
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
