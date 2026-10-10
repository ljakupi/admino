"""Account self-service: a signed-in user's own profile and password (GH-166).

Every user, the Super Admin included, manages their own account from
Settings -> My account: their name, UI language, preferred response language
(or the org default), timezone and personal instructions (``get_account``,
``update_account``), and their password (``change_password``). Changing the
password ends every session of the user, the current one included, through
``sessions.revoke_user_sessions`` (#151's revoke-all service), so the user
logs in again with the new password. It also stores when the password
changed (``password_changed_at``, GH-307), which the profile carries: None
until the first change (a password change or a completed reset,
``admino.password_reset``). The session list with revoke is
``admino.session_management`` (#152).

Inputs: the database pool and the caller's ``Principal`` (from the session);
a validated ``models.MyAccountPatch`` (a profile change); the current and the
new password and the client IP (a password change).
Outputs: ``models.MyAccountResponse`` (the stored profile, read or changed);
the number of sessions a password change ended. ``AccountNotFoundError`` for
a deleted or missing account, ``WrongPasswordError`` for a wrong current
password (or a locked account or IP), ``passwords.PasswordPolicyError`` for a
new password the policy refuses, ``PermissionError`` without
``Capability.ACCOUNT_MANAGE``.

Security notes:
- Own row only: every statement is bound to ``principal.user_id`` (never a
  request value) and states ``deleted_at IS NULL``, so no other account, of
  the same org or another, is ever read or written.
- ``Capability.ACCOUNT_MANAGE`` (``access.can``, every role and the Super
  Admin) is checked before any query; anything that isn't a well-formed
  ``Principal`` is refused.
- A profile change is one ``UPDATE ... RETURNING`` (no read-then-write race).
  It isn't audited: the fields are the user's own preferences, like their
  settings (decision D2).
- A password change runs the cheapest check first: the password policy
  (nothing written, nothing counted, no Argon2 work), then the current
  password through ``auth.reauthenticate`` (a wrong one counts in the login
  throttle like a failed login; a locked account or IP is refused without a
  check). Argon2 hashing runs in a worker thread, outside the transaction.
  The hash with its change time (the transaction clock, ``now()``), the
  revocation of every session and the ``password.change`` audit event share
  one transaction: a failed audit write rolls everything back (fail closed),
  so the password never changes unaudited and a refused change leaves the
  change time as it was.
- Content-free audit (tracker #139 §5): the actor, their org (none for the
  Super Admin), the user as target, the client IP and the number of sessions
  ended. No password, hash, email, name, timezone or instructions reaches an
  audit row, an error or a log line (this module logs nothing); the only
  password value bound to a statement is the new hash. Errors carry no IDs.
- Parameterized SQL only: static statements, values travel as bind
  parameters.
- Imports nothing from the server, agent, LLM or tool layers; the permission
  engine is untouched.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Final

from admino import audit_events, auth, passwords, sessions
from admino.access import Capability, can
from admino.audit_events import AuditAction, TargetType
from admino.models import MyAccountResponse

if TYPE_CHECKING:
    import asyncpg

    from admino.access import Principal
    from admino.models import MyAccountPatch

ACCOUNT_NOT_FOUND_MESSAGE: Final = "Account not found"

_PROFILE_SQL: Final = """
    SELECT email, name, ui_language, response_language, timezone, personal_instructions,
           password_changed_at
    FROM users
    WHERE id = $1 AND deleted_at IS NULL
"""

# One statement: only the given fields change. $4 tells whether
# response_language was given, so a null stores NULL (the org default) while
# an absent one keeps the stored value.
_UPDATE_PROFILE_SQL: Final = """
    UPDATE users
    SET name = coalesce($2, name),
        ui_language = coalesce($3, ui_language),
        response_language = CASE WHEN $4 THEN $5 ELSE response_language END,
        timezone = coalesce($6, timezone),
        personal_instructions = coalesce($7, personal_instructions)
    WHERE id = $1 AND deleted_at IS NULL
    RETURNING email, name, ui_language, response_language, timezone, personal_instructions,
              password_changed_at
"""

_EMAIL_SQL: Final = "SELECT email FROM users WHERE id = $1 AND deleted_at IS NULL"

# Only an account that is still active and not deleted: one deactivated or
# deleted after the re-authentication keeps its password (nothing matches).
# GH-307: the change time is the transaction clock, stored with the hash.
_UPDATE_HASH_SQL: Final = """
    UPDATE users SET password_hash = $1, password_changed_at = now()
    WHERE id = $2 AND deleted_at IS NULL AND status = 'active'
    RETURNING id
"""


class AccountNotFoundError(Exception):
    """Raised when the caller's account is deleted or missing; carries no IDs."""

    def __init__(self) -> None:
        super().__init__(ACCOUNT_NOT_FOUND_MESSAGE)


class WrongPasswordError(Exception):
    """Raised when the current password is wrong (or the account or IP is locked).

    Carries no IDs and no password.
    """

    def __init__(self) -> None:
        super().__init__("Wrong current password")


def _require_account_manage(principal: Principal) -> None:
    """Raise PermissionError unless the principal may manage their own account."""
    if not can(principal, Capability.ACCOUNT_MANAGE):
        msg = "Forbidden"
        raise PermissionError(msg)


def _account_response(row: Any) -> MyAccountResponse:
    """Build the response of a users row (the profile SELECT's or UPDATE's columns)."""
    return MyAccountResponse(
        email=row["email"],
        name=row["name"],
        ui_language=row["ui_language"],
        response_language=row["response_language"],
        timezone=row["timezone"],
        personal_instructions=row["personal_instructions"],
        password_changed_at=row["password_changed_at"],
    )


async def get_account(pool: asyncpg.Pool, *, principal: Principal) -> MyAccountResponse:
    """Return the caller's own account.

    Args:
        pool: The database pool.
        principal: The caller (from the session).

    Returns:
        MyAccountResponse with the stored values.

    Raises:
        PermissionError: Without ``Capability.ACCOUNT_MANAGE``; no query is
            issued.
        AccountNotFoundError: If the account is deleted or missing.
    """
    _require_account_manage(principal)
    row = await pool.fetchrow(_PROFILE_SQL, principal.user_id)
    if row is None:
        raise AccountNotFoundError
    return _account_response(row)


async def update_account(
    pool: asyncpg.Pool, *, principal: Principal, patch: MyAccountPatch
) -> MyAccountResponse:
    """Change the caller's own name, languages, timezone or personal instructions.

    Only the fields given in the patch change. Not audited, nothing logged.

    Args:
        pool: The database pool.
        principal: The caller (from the session).
        patch: The validated change (at least one field given).

    Returns:
        MyAccountResponse with the stored values after the change.

    Raises:
        PermissionError: Without ``Capability.ACCOUNT_MANAGE``; no query is
            issued.
        AccountNotFoundError: If the account is deleted or missing; nothing is
            written.
    """
    _require_account_manage(principal)
    row = await pool.fetchrow(
        _UPDATE_PROFILE_SQL,
        principal.user_id,
        patch.name,
        patch.ui_language,
        "response_language" in patch.model_fields_set,
        patch.response_language,
        patch.timezone,
        patch.personal_instructions,
    )
    if row is None:
        raise AccountNotFoundError
    return _account_response(row)


async def change_password(
    pool: asyncpg.Pool,
    *,
    principal: Principal,
    current_password: str,
    new_password: str,
    ip: str | None,
) -> int:
    """Set the caller's new password and end every one of their sessions.

    The policy is checked first, then the current password (through the
    login throttle). The new hash with its change time
    (``password_changed_at``), the deletion of every session of the user (the
    current one included) and the ``password.change`` audit event share one
    transaction.

    Args:
        pool: The database pool.
        principal: The caller (from the session).
        current_password: The password the user typed as their current one.
        new_password: The new password.
        ip: The client address, if known.

    Returns:
        The number of sessions ended.

    Raises:
        PermissionError: Without ``Capability.ACCOUNT_MANAGE``; no query is
            issued.
        AccountNotFoundError: If the account is deleted or missing (nothing
            is checked or written), or was deactivated or deleted after the
            current password was checked (nothing is written).
        PasswordPolicyError: If the policy refuses the new password; nothing
            is written or counted.
        WrongPasswordError: If the current password is wrong, or the account
            or IP is locked; nothing is written (a wrong password counts in
            the login throttle).
        AuditRecordError: If the audit event can't be recorded; the password
            and the sessions are unchanged.
    """
    _require_account_manage(principal)
    email = await pool.fetchval(_EMAIL_SQL, principal.user_id)
    if email is None:
        raise AccountNotFoundError
    passwords.check_password_policy(new_password, email=email)
    if not await auth.reauthenticate(pool, principal=principal, password=current_password, ip=ip):
        raise WrongPasswordError
    new_hash = await asyncio.to_thread(passwords.hash_password, new_password)

    async with pool.acquire() as conn, conn.transaction():
        if await conn.fetchval(_UPDATE_HASH_SQL, new_hash, principal.user_id) is None:
            # Deactivated or deleted since the re-authentication: roll back.
            raise AccountNotFoundError
        revoked = await sessions.revoke_user_sessions(conn, principal.user_id)
        await audit_events.record(
            conn,
            action=AuditAction.PASSWORD_CHANGE,
            actor_kind=principal.kind,
            actor_user_id=principal.user_id,
            org_id=principal.org_id,
            target_type=TargetType.USER,
            target_ids=(principal.user_id,),
            ip=ip,
            metadata={"sessions_revoked": revoked},
        )
    return revoked
