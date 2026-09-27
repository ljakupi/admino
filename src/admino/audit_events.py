"""Content-free, append-only audit event store: action catalog, record(), retention purge (GH-146).

Every security-relevant action (logins and lockouts, password resets,
invitations, role changes, activations, sharing changes, deletions and
restores, exports, Org Admin access to other users' projects, org and platform
settings, Super Admin actions, residency policy, break-glass sessions, agent
tool calls) is written through ``record()`` as one row of the ``audit_events``
table (migration 0005).

Inputs: ``record()`` takes a database executor (the caller's connection, or
the pool) plus the event: an ``AuditAction``, the actor, the org scope,
optional targets, the client IP and a small metadata dict.
``record_tool_call()`` takes an executor, the acting member's org and user
IDs, the chat ID and one agent tool dispatch's outcome (GH-147, GH-149). ``purge_expired()`` and
``run_retention_job()`` take the pool and a retention in months.
Outputs: one INSERT per event; the purge returns the number of rows removed.

Security notes:
- No content: an event holds IDs, counts, sizes and statuses only (tracker
  #139 §5). ``AuditEvent`` refuses free text: targets are UUIDs, and metadata
  values are bools, safe-range ints, None, UUIDs or tokens from a closed
  vocabulary (member roles, permission decisions, tool names and actions).
  A tool.call row stores a tool or action name the LLM chose only when it is
  a vocabulary token; anything else is stored as None, never as text.
  Errors and log lines carry no IDs or values either: ``AuditRecordError`` is
  raised ``from None`` with a generic message, so neither Pydantic's error
  (which echoes input) nor the driver's (which echoes the failing row)
  travels with it, and failures log the exception class name only.
- Append-only: the database trigger of migration 0005 refuses UPDATE,
  TRUNCATE and every DELETE except the retention purge's. The app never sets
  id or occurred_at, so it can't backdate an event.
- Fail closed: a failed record raises, so the caller's action aborts instead of
  proceeding unaudited. Callers that change data pass the connection of their
  own transaction, so a failed record rolls the change back.
- Parameterized SQL only: values travel as bind parameters.
- Pure apart from the executor it is given. Imports nothing from the server,
  agent, LLM, tools or OAuth layers. It reads the tool vocabulary
  from ``admino.permissions`` (pure); the permission engine never imports this
  module.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import Mapping
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Literal, Protocol, get_args
from uuid import UUID

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from admino.access import MemberRole, SealedModel
from admino.permissions import DEFAULT_PERMISSIONS, HARDCODED_DENIALS, PermissionState

if TYPE_CHECKING:
    import asyncpg

logger = logging.getLogger(__name__)

ActorKind = Literal["member", "super_admin", "system", "operator"]
ActionScope = Literal["org", "platform", "any"]
MetadataValue = str | int | bool | None


class AuditAction(StrEnum):
    """The closed catalog of auditable actions."""

    # Logins (success and failure) and lockouts
    LOGIN_SUCCESS = "login.success"
    LOGIN_FAILURE = "login.failure"
    LOGIN_LOCKOUT = "login.lockout"
    # Password resets (action names, not secrets: S105 matches the member names)
    PASSWORD_RESET_REQUEST = "password_reset.request"  # noqa: S105
    PASSWORD_RESET_COMPLETE = "password_reset.complete"  # noqa: S105
    # Invitations
    INVITATION_CREATE = "invitation.create"
    INVITATION_REVOKE = "invitation.revoke"
    INVITATION_ACCEPT = "invitation.accept"
    # Role changes, activations, deactivations, account deletion
    USER_ROLE_CHANGE = "user.role_change"
    USER_ACTIVATE = "user.activate"
    USER_DEACTIVATE = "user.deactivate"
    USER_DELETE = "user.delete"
    # Project sharing changes
    PROJECT_SHARE = "project.share"
    PROJECT_UNSHARE = "project.unshare"
    PROJECT_MEMBER_ROLE_CHANGE = "project.member_role_change"
    PROJECT_TRANSFER = "project.transfer"
    # Deletions and restores
    PROJECT_DELETE = "project.delete"
    PROJECT_RESTORE = "project.restore"
    CHAT_DELETE = "chat.delete"
    CHAT_RESTORE = "chat.restore"
    FILE_DELETE = "file.delete"
    FILE_RESTORE = "file.restore"
    # Org Admin access to other users' projects
    PROJECT_ADMIN_ACCESS = "project.admin_access"
    # Exports
    EXPORT_CREATE = "export.create"
    # Org settings changes
    ORG_SETTINGS_CHANGE = "org.settings_change"
    # Super Admin actions (org lifecycle, platform settings, model registry)
    ORG_CREATE = "org.create"
    ORG_LIMITS_CHANGE = "org.limits_change"
    ORG_DEACTIVATE = "org.deactivate"
    ORG_REACTIVATE = "org.reactivate"
    ORG_DELETION_SCHEDULE = "org.deletion_schedule"
    ORG_DELETION_CANCEL = "org.deletion_cancel"
    ORG_PURGE = "org.purge"
    PLATFORM_SETTINGS_CHANGE = "platform.settings_change"
    MODEL_REGISTRY_CHANGE = "model.registry_change"
    # Residency policy changes
    ORG_RESIDENCY_CHANGE = "org.residency_change"
    # Break-glass sessions
    BREAKGLASS_START = "breakglass.start"
    BREAKGLASS_END = "breakglass.end"
    # Agent tool calls
    TOOL_CALL = "tool.call"
    # The retention purge itself
    AUDIT_PURGE = "audit.purge"


class TargetType(StrEnum):
    """The kinds of object an event's target_ids refer to."""

    ORGANIZATION = "organization"
    USER = "user"
    INVITATION = "invitation"
    PROJECT = "project"
    CHAT = "chat"
    FILE = "file"
    MODEL = "model"


# "org": the event belongs to one org's log, so org_id is required (a Super
# Admin action affecting an org lands where that org's admins see it).
# "platform": org_id must be None (org.purge outlives the org). "any": logins
# and account lifecycle, for members (org) and Super Admins (no org) alike.
ACTION_SCOPES: Final[Mapping[AuditAction, ActionScope]] = MappingProxyType(
    {
        AuditAction.LOGIN_SUCCESS: "any",
        AuditAction.LOGIN_FAILURE: "any",
        AuditAction.LOGIN_LOCKOUT: "any",
        AuditAction.PASSWORD_RESET_REQUEST: "any",
        AuditAction.PASSWORD_RESET_COMPLETE: "any",
        AuditAction.INVITATION_CREATE: "org",
        AuditAction.INVITATION_REVOKE: "org",
        AuditAction.INVITATION_ACCEPT: "org",
        AuditAction.USER_ROLE_CHANGE: "org",
        AuditAction.USER_ACTIVATE: "any",
        AuditAction.USER_DEACTIVATE: "any",
        AuditAction.USER_DELETE: "any",
        AuditAction.PROJECT_SHARE: "org",
        AuditAction.PROJECT_UNSHARE: "org",
        AuditAction.PROJECT_MEMBER_ROLE_CHANGE: "org",
        AuditAction.PROJECT_TRANSFER: "org",
        AuditAction.PROJECT_DELETE: "org",
        AuditAction.PROJECT_RESTORE: "org",
        AuditAction.CHAT_DELETE: "org",
        AuditAction.CHAT_RESTORE: "org",
        AuditAction.FILE_DELETE: "org",
        AuditAction.FILE_RESTORE: "org",
        AuditAction.PROJECT_ADMIN_ACCESS: "org",
        AuditAction.EXPORT_CREATE: "org",
        AuditAction.ORG_SETTINGS_CHANGE: "org",
        AuditAction.ORG_CREATE: "org",
        AuditAction.ORG_LIMITS_CHANGE: "org",
        AuditAction.ORG_DEACTIVATE: "org",
        AuditAction.ORG_REACTIVATE: "org",
        AuditAction.ORG_DELETION_SCHEDULE: "org",
        AuditAction.ORG_DELETION_CANCEL: "org",
        AuditAction.ORG_PURGE: "platform",
        AuditAction.PLATFORM_SETTINGS_CHANGE: "platform",
        AuditAction.MODEL_REGISTRY_CHANGE: "platform",
        AuditAction.ORG_RESIDENCY_CHANGE: "org",
        AuditAction.BREAKGLASS_START: "org",
        AuditAction.BREAKGLASS_END: "org",
        AuditAction.TOOL_CALL: "org",
        AuditAction.AUDIT_PURGE: "platform",
    }
)

# The only strings metadata may hold: member roles, permission decisions, and
# every tool name and tool action the permission engine knows.
METADATA_VOCABULARY: Final[frozenset[str]] = frozenset(
    {
        *get_args(MemberRole),
        *get_args(PermissionState),
        *DEFAULT_PERMISSIONS,
        *(action for actions in DEFAULT_PERMISSIONS.values() for action in actions),
        *(token for denial in HARDCODED_DENIALS for token in denial),
    }
)

_DECISIONS: Final[frozenset[str]] = frozenset(get_args(PermissionState))

DEFAULT_RETENTION_MONTHS: Final[int] = 12
MIN_RETENTION_MONTHS: Final[int] = 6
MAX_RETENTION_MONTHS: Final[int] = 84
PURGE_INTERVAL_SECONDS: Final[int] = 86400

_MAX_TARGETS: Final = 100
_MAX_METADATA_KEYS: Final = 16
_MAX_SAFE_INT: Final = 2**53 - 1  # Largest int a JSON consumer reads exactly.
_METADATA_KEY_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,39}")

# id and occurred_at are left to their database defaults: no backdating.
_INSERT_SQL: Final = """
    INSERT INTO audit_events
        (org_id, actor_user_id, actor_kind, action, target_type, target_ids, ip, metadata)
    VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::inet, $8::jsonb)
"""
_PURGE_SQL: Final = "SELECT purge_audit_events($1)"


class AuditRecordError(Exception):
    """Raised when an audit event can't be recorded; the caller's action must abort."""

    def __init__(self, message: str = "The audit event could not be recorded.") -> None:
        super().__init__(message)


class Executor(Protocol):
    """What record() writes through: an asyncpg connection, pool or pooled connection."""

    async def execute(self, query: str, *args: object) -> str:
        """Run one statement with bind parameters."""
        ...


def _canonical_uuid(value: object) -> UUID:
    """Return a plain UUID for a UUID object; refuse anything else.

    UUID subclasses (asyncpg returns its own) are rebuilt from their 128 bits,
    so no subclass behavior survives. Strings and bytes are refused: lax
    parsing would turn 16 bytes of text into a UUID carrying that text.
    """
    if not isinstance(value, UUID):
        msg = "IDs must be UUID objects."
        raise ValueError(msg)
    return UUID(int=value.int)


def _metadata_value(value: object) -> MetadataValue:
    """Return an allowed metadata value (a UUID becomes its canonical string); refuse the rest.

    Exact type checks: a str subclass (an enum member) is no vocabulary token,
    and a bool stays a bool instead of passing as an int.
    """
    if value is None or type(value) is bool:
        return value
    if type(value) is int and abs(value) <= _MAX_SAFE_INT:
        return value
    if type(value) is str and value in METADATA_VOCABULARY:
        return value
    if isinstance(value, UUID):
        return str(_canonical_uuid(value))
    msg = "Metadata values must be bools, safe-range ints, None, UUIDs or vocabulary tokens."
    raise ValueError(msg)


class AuditEvent(SealedModel):
    """One validated, content-free audit event, ready to insert."""

    # Validation errors never repeat the rejected input.
    model_config = ConfigDict(hide_input_in_errors=True)

    org_id: UUID | None
    actor_kind: ActorKind
    actor_user_id: UUID | None
    action: AuditAction
    target_type: TargetType | None = None
    target_ids: tuple[UUID, ...] = ()
    ip: IPv4Address | IPv6Address | None = None
    metadata: dict[str, MetadataValue] = Field(default_factory=dict)

    @field_validator("org_id", "actor_user_id", mode="before")
    @classmethod
    def _check_id(cls, value: object) -> UUID | None:
        """Accept a UUID object or None only."""
        return None if value is None else _canonical_uuid(value)

    @field_validator("target_ids", mode="before")
    @classmethod
    def _check_target_ids(cls, value: object) -> tuple[UUID, ...]:
        """Accept a list or tuple of at most 100 UUID objects."""
        if not isinstance(value, list | tuple):
            msg = "target_ids must be a list or tuple of UUIDs."
            raise ValueError(msg)
        if len(value) > _MAX_TARGETS:
            msg = "Too many target IDs."
            raise ValueError(msg)
        return tuple(_canonical_uuid(item) for item in value)

    @field_validator("ip", mode="before")
    @classmethod
    def _normalize_ip(cls, value: object) -> IPv4Address | IPv6Address | None:
        """Normalize an IP address; a string that isn't one (e.g. 'testclient') becomes None.

        The address is rebuilt from its packed bytes, which drops an IPv6 scope
        ID ('fe80::1%<any text>') so no text rides along.
        """
        if value is None:
            return None
        if isinstance(value, IPv4Address | IPv6Address):
            return ip_address(value.packed)
        if isinstance(value, str):
            try:
                return ip_address(ip_address(value).packed)
            except ValueError:
                return None
        msg = "ip must be an IP address, a string or None."
        raise ValueError(msg)

    @field_validator("metadata", mode="before")
    @classmethod
    def _check_metadata(cls, value: object) -> dict[str, MetadataValue]:
        """Accept a flat mapping of at most 16 snake_case keys to non-content values."""
        if value is None:
            return {}
        if not isinstance(value, Mapping):
            msg = "metadata must be a mapping."
            raise ValueError(msg)
        items = list(value.items())
        if len(items) > _MAX_METADATA_KEYS:
            msg = "Too many metadata keys."
            raise ValueError(msg)
        checked: dict[str, MetadataValue] = {}
        for key, item in items:
            if type(key) is not str or _METADATA_KEY_RE.fullmatch(key) is None:
                msg = "Metadata keys must be short lowercase snake_case."
                raise ValueError(msg)
            checked[key] = _metadata_value(item)
        return checked

    @model_validator(mode="after")
    def _check_consistency(self) -> AuditEvent:
        """Enforce the actor rules, the action's org scope and the target pairing."""
        if (self.actor_kind in ("member", "super_admin")) != (self.actor_user_id is not None):
            msg = "Members and Super Admins name their user id; system and operator don't."
            raise ValueError(msg)
        if self.actor_kind == "member" and self.org_id is None:
            msg = "A member always acts inside an org."
            raise ValueError(msg)
        scope = ACTION_SCOPES[self.action]
        if scope == "org" and self.org_id is None:
            msg = "This action belongs to an org's log and needs its org_id."
            raise ValueError(msg)
        if scope == "platform" and self.org_id is not None:
            msg = "This platform action takes no org_id."
            raise ValueError(msg)
        if (self.target_type is None) != (not self.target_ids):
            msg = "A target type and target IDs come together."
            raise ValueError(msg)
        return self


async def record(
    executor: Executor,
    *,
    action: AuditAction,
    actor_kind: ActorKind,
    actor_user_id: UUID | None,
    org_id: UUID | None,
    target_type: TargetType | None = None,
    target_ids: list[UUID] | tuple[UUID, ...] = (),
    ip: IPv4Address | IPv6Address | str | None = None,
    metadata: Mapping[str, MetadataValue | UUID] | None = None,
) -> None:
    """Validate an audit event and insert it with one parameterized statement.

    A caller that changes data must pass the connection of its own
    transaction: a failed record then propagates out of the transaction block
    and rolls the change back, so the action never happens unaudited. Events
    outside a data change (e.g. a failed login) may pass the pool.

    Args:
        executor: The caller's connection (inside its transaction) or the pool.
        action: What happened.
        actor_kind: Who acted: a member, a Super Admin, the system or an operator.
        actor_user_id: The acting account; None for system and operator actors.
        org_id: The org whose log the event belongs to; None for platform events.
        target_type: The kind of object acted on, if any.
        target_ids: The IDs of the objects acted on (UUID objects, at most 100).
        ip: The client address; a peer that isn't an IP address is stored as NULL.
        metadata: Non-content details (roles, decisions, counts, IDs).

    Raises:
        AuditRecordError: If the event is invalid (nothing is written) or the
            write fails. It carries no IDs or values.
    """
    try:
        # model_validate: the raw inputs (a list, an IP string, UUID metadata
        # values) are what the validators normalize into the field types.
        event = AuditEvent.model_validate(
            {
                "org_id": org_id,
                "actor_kind": actor_kind,
                "actor_user_id": actor_user_id,
                "action": action,
                "target_type": target_type,
                "target_ids": target_ids,
                "ip": ip,
                "metadata": metadata,
            }
        )
    except ValidationError:
        raise AuditRecordError from None
    try:
        await executor.execute(
            _INSERT_SQL,
            event.org_id,
            event.actor_user_id,
            event.actor_kind,
            event.action.value,
            None if event.target_type is None else event.target_type.value,
            json.dumps([str(target) for target in event.target_ids]),
            event.ip,
            json.dumps(event.metadata),
        )
    except Exception as exc:
        # The class name only: the driver's message can contain the failing row.
        logger.error("Audit event write failed (%s).", type(exc).__name__)
        raise AuditRecordError from None


async def record_tool_call(
    executor: Executor,
    *,
    org_id: UUID,
    actor_user_id: UUID,
    chat_id: UUID,
    tool: str,
    action: str,
    decision: str,
    success: bool,
    duration_ms: int,
) -> None:
    """Record one agent tool dispatch as the acting member's ``tool.call`` event on its chat.

    The metadata holds exactly ``tool``, ``action``, ``decision``, ``success``
    and ``duration_ms`` — never argument values, tool output or error text.

    Args:
        executor: The pool or a connection to write through.
        org_id: The acting member's org (the log the event belongs to).
        actor_user_id: The acting member's user id.
        chat_id: The chat the tool call ran in (the event's target).
        tool: The tool name the LLM asked for; stored only if it is a
            vocabulary token, otherwise as None.
        action: The action name the LLM asked for; same rule as ``tool``.
        decision: The final permission decision: allow, confirm or deny.
        success: Whether the tool ran and returned a result.
        duration_ms: How long the dispatch took, in milliseconds.

    Raises:
        AuditRecordError: If ``decision`` is not a permission decision or the
            event is otherwise invalid, e.g. a missing org or user id (nothing
            is written), or the write fails.
    """
    # Explicit: the vocabulary also holds tool names and roles, which are no
    # decision.
    if type(decision) is not str or decision not in _DECISIONS:
        raise AuditRecordError
    await record(
        executor,
        action=AuditAction.TOOL_CALL,
        actor_kind="member",
        actor_user_id=actor_user_id,
        org_id=org_id,
        target_type=TargetType.CHAT,
        target_ids=(chat_id,),
        metadata={
            "tool": _vocabulary_token(tool),
            "action": _vocabulary_token(action),
            "decision": decision,
            "success": success,
            "duration_ms": duration_ms,
        },
    )


def _vocabulary_token(value: str) -> str | None:
    """Return ``value`` if it is an exact vocabulary token, else None (never free text)."""
    return value if type(value) is str and value in METADATA_VOCABULARY else None


async def purge_expired(
    pool: asyncpg.Pool, retention_months: int = DEFAULT_RETENTION_MONTHS
) -> int:
    """Delete the audit events older than the retention and record the purge.

    The purge and its audit.purge event run in one transaction: if the event
    can't be written, the purge rolls back.

    Args:
        pool: The database pool.
        retention_months: How many months of events to keep (6 to 84).

    Returns:
        The number of events removed.

    Raises:
        ValueError: If retention_months isn't an int from 6 to 84 (the pool
            isn't touched).
        AuditRecordError: If the audit.purge event can't be recorded.
    """
    if (
        type(retention_months) is not int
        or not MIN_RETENTION_MONTHS <= retention_months <= MAX_RETENTION_MONTHS
    ):
        msg = "The audit retention must be a whole number of months from 6 to 84."
        raise ValueError(msg)
    async with pool.acquire() as conn, conn.transaction():
        purged: int = await conn.fetchval(_PURGE_SQL, retention_months)
        if purged > 0:
            await record(
                conn,
                action=AuditAction.AUDIT_PURGE,
                actor_kind="system",
                actor_user_id=None,
                org_id=None,
                metadata={"retention_months": retention_months, "purged_count": purged},
            )
    return purged


async def run_retention_job(
    pool: asyncpg.Pool,
    *,
    retention_months: int = DEFAULT_RETENTION_MONTHS,
    interval_seconds: float = PURGE_INTERVAL_SECONDS,
) -> None:
    """Purge expired audit events now and then once per interval, until cancelled.

    A failed purge is logged (class name only) and retried at the next
    interval; cancellation stops the job.

    Args:
        pool: The database pool.
        retention_months: How many months of events to keep (6 to 84).
        interval_seconds: Seconds between purges (default: one day).
    """
    while True:
        try:
            await purge_expired(pool, retention_months)
        except Exception as exc:
            logger.warning(
                "Audit retention purge failed (%s); retrying next interval.", type(exc).__name__
            )
        await asyncio.sleep(interval_seconds)
