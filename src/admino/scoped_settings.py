"""The settings scopes: platform, organization and user settings (GH-159, GH-160).

Migration 0013 replaced the old key/value ``settings`` table with one table per
owner, and this module is the service behind their routes and the startup:

- ``user_settings`` (each user, the Super Admin included): theme and
  notifications (the tool-approval and, GH-35, the task-done pings).
  ``get_user_settings`` / ``update_user_settings`` read and change the
  caller's own row and ``reset_user_settings`` deletes it, so it reads as the
  defaults again (``Capability.ACCOUNT_MANAGE``). Not audited: the user scope
  is not in the audit catalog.
- ``org_settings`` (each organization, its Org Admin): the enabled tool
  services. ``get_org_settings`` / ``update_org_settings`` read and change the
  caller's own org's row (``Capability.ORG_SETTINGS_MANAGE``); each real
  change is an ``org.settings_change`` audit event. ``org_tools_enabled``
  (GH-161) reads a tenant org's switches for a chat run, without a
  capability check (an internal read: every member's run needs it); it
  returns the stored switches, residency not applied. ``org_residency``
  (GH-162) reads the org's ``data_residency`` policy the same way; both org
  settings responses carry it, read-only (a Google or Microsoft switch can
  still be stored while it is on).
- ``platform_settings`` (one row, the Super Admin): the LLM provider, one
  model per provider, the limits and (GH-160) the files, retention and
  security defaults. ``seed_platform_settings`` stores config.yaml's llm and
  limits on the first boot and re-applies its llm on every later boot (the
  stored limits are kept; the other defaults start from migration 0014's
  column defaults); ``apply_platform_settings`` overlays the LLM and limits
  onto the config; ``update_platform_settings`` changes any of the five
  sections (``Capability.PLATFORM_DEFAULTS_MANAGE``), each changed section a
  ``platform.settings_change`` audit event.
- One in-process cache of the platform row (``_platform_cache``, GH-160):
  ``current_platform_settings`` answers from it (reading the row once when it
  is empty), ``load_platform_settings`` (startup, the platform settings page)
  reads the row and replaces it, and a successful update replaces it after
  its commit. Consumers read every platform default through it;
  ``session_policy_for`` picks a new session's policy (a member: the org
  default until #169; a Super Admin: the stored platform policy).

A missing user or org row reads as the defaults (theme light, tool-approval
pings on, task-done pings off, every tool on) and a read writes nothing; an
update creates the row from the column defaults first.

Inputs: the database pool (or a connection, for the platform reads); the
acting ``Principal`` (from the session), the validated patch models
(``UserSettingsPatch``, ``OrgSettingsPatch``, ``PlatformSettingsPatch``) and
the client IP; the ``AppConfig`` (startup); an account kind.
Outputs: ``UserSettingsResponse``, ``OrgSettingsResponse``,
``StoredPlatformSettings``, an org's switches (tool name -> bool) and its
residency flag, the
overlaid ``AppConfig`` and a ``SessionPolicy``. Errors: ``PermissionError``,
``AuditRecordError``, ``InvalidPlatformSettingsError`` (the merged trash
minimum exceeds the maximum), ``RuntimeError`` (no platform row: startup
always seeds it first), ``ValueError`` (no session policy for the kind).

Security notes:
- Authorization through ``access.can`` before any statement: a refused actor
  gets ``PermissionError`` and nothing is read or written. The Super Admin
  reaches no org's settings; member roles never reach a platform default.
- Tenant isolation: the org is always ``TenantContext.from_principal(actor)``
  and the user always ``actor.user_id``, both bind parameters; never a
  request value.
- Fail closed: an org without an organizations row reads as residency on.
  An org or platform change, its row lock (``FOR UPDATE``) and
  its audit events share one transaction on one connection, so a failed audit
  write rolls the change back (for the platform, the re-timed Super Admin
  sessions too). A no-op writes nothing and records nothing; an invalid
  merged retention is refused before any write. The cache only takes values
  that were committed: an update replaces it after its commit, and a read
  that began before an update committed never overwrites the update's value.
- A Super Admin session-policy change applies to the open Super Admin
  sessions in the same transaction (``sessions.apply_super_admin_policy``):
  a session older than the new lifetime, or idle past the new timeout, ends.
- No content in audit rows: org events carry one ``<tool>_old`` /
  ``<tool>_new`` bool pair per changed tool; the platform llm event carries
  the names of the changed fields mapped to True, never a provider or model
  value; the other platform events carry ``<field>_old`` / ``<field>_new``
  ints (and ``sessions_updated``, a count). Nothing is logged here.
- Parameterized SQL only: every statement is a constant, every value a bind
  parameter.
- Imports only access, tenancy, audit_events, models, config and sessions
  from admino: never the server, agent, LLM, tools, OAuth, database or
  permission engine modules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from admino import audit_events, sessions
from admino.access import Capability, Principal, can
from admino.audit_events import AuditAction, TargetType
from admino.config import AppConfig, LimitsConfig, LLMConfig
from admino.models import (
    OrgSettingsResponse,
    PlatformFiles,
    PlatformLimits,
    PlatformRetention,
    PlatformSecurity,
    SettingsAppearance,
    SettingsNotifications,
    ToolsSettings,
    UserSettingsResponse,
)
from admino.tenancy import TenantContext

if TYPE_CHECKING:
    import asyncpg
    from asyncpg import Record

    from admino.audit_events import MetadataValue
    from admino.models import OrgSettingsPatch, PlatformSettingsPatch, UserSettingsPatch

# The tool names in the column order of the org statements below.
_TOOLS: Final = tuple(ToolsSettings.model_fields)
_NO_PLATFORM_ROW: Final = "The platform settings are missing; startup seeds them."

_USER_SQL: Final = """
    SELECT theme, notifications_enabled, notifications_task_done
    FROM user_settings
    WHERE user_id = $1
"""
# The column defaults of migrations 0013 and 0015 fill a new row.
_USER_ENSURE_SQL: Final = """
    INSERT INTO user_settings (user_id) VALUES ($1)
    ON CONFLICT (user_id) DO NOTHING
"""
# A NULL parameter keeps the stored value.
_USER_UPDATE_SQL: Final = """
    UPDATE user_settings
    SET theme = coalesce($2, theme),
        notifications_enabled = coalesce($3, notifications_enabled),
        notifications_task_done = coalesce($4, notifications_task_done),
        updated_at = now()
    WHERE user_id = $1
    RETURNING theme, notifications_enabled, notifications_task_done
"""
# No row reads as the defaults, so future columns reset too.
_USER_RESET_SQL: Final = "DELETE FROM user_settings WHERE user_id = $1"

_ORG_SQL: Final = """
    SELECT gmail_enabled AS gmail, google_calendar_enabled AS google_calendar,
           google_drive_enabled AS google_drive, outlook_enabled AS outlook,
           outlook_calendar_enabled AS outlook_calendar, onedrive_enabled AS onedrive,
           memory_enabled AS memory
    FROM org_settings
    WHERE org_id = $1
"""
# GH-162: the org's data residency policy (the Super Admin's switch).
_ORG_RESIDENCY_SQL: Final = "SELECT data_residency FROM organizations WHERE id = $1"
_ORG_ENSURE_SQL: Final = """
    INSERT INTO org_settings (org_id) VALUES ($1)
    ON CONFLICT (org_id) DO NOTHING
"""
# Locked until the transaction ends: concurrent changes of one org serialize.
_ORG_LOCK_SQL: Final = """
    SELECT gmail_enabled AS gmail, google_calendar_enabled AS google_calendar,
           google_drive_enabled AS google_drive, outlook_enabled AS outlook,
           outlook_calendar_enabled AS outlook_calendar, onedrive_enabled AS onedrive,
           memory_enabled AS memory
    FROM org_settings
    WHERE org_id = $1
    FOR UPDATE
"""
# $2 to $8 follow _TOOLS; a NULL parameter keeps the stored value.
_ORG_UPDATE_SQL: Final = """
    UPDATE org_settings
    SET gmail_enabled = coalesce($2, gmail_enabled),
        google_calendar_enabled = coalesce($3, google_calendar_enabled),
        google_drive_enabled = coalesce($4, google_drive_enabled),
        outlook_enabled = coalesce($5, outlook_enabled),
        outlook_calendar_enabled = coalesce($6, outlook_calendar_enabled),
        onedrive_enabled = coalesce($7, onedrive_enabled),
        memory_enabled = coalesce($8, memory_enabled),
        updated_at = now()
    WHERE org_id = $1
    RETURNING gmail_enabled AS gmail, google_calendar_enabled AS google_calendar,
              google_drive_enabled AS google_drive, outlook_enabled AS outlook,
              outlook_calendar_enabled AS outlook_calendar, onedrive_enabled AS onedrive,
              memory_enabled AS memory
"""

# The singleton row (id defaults to true). On a later boot config.yaml's llm
# replaces the stored one; the stored limits are kept.
_PLATFORM_SEED_SQL: Final = """
    INSERT INTO platform_settings (
        llm_provider, infomaniak_model, vllm_model, anthropic_model, openai_model,
        max_tool_calls_per_message, max_pending_confirmations, confirmation_timeout_s,
        max_message_length, max_context_messages
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    ON CONFLICT (id) DO UPDATE
    SET llm_provider = EXCLUDED.llm_provider,
        infomaniak_model = EXCLUDED.infomaniak_model,
        vllm_model = EXCLUDED.vllm_model,
        anthropic_model = EXCLUDED.anthropic_model,
        openai_model = EXCLUDED.openai_model,
        updated_at = now()
"""
_PLATFORM_SQL: Final = """
    SELECT llm_provider, infomaniak_model, vllm_model, anthropic_model, openai_model,
           max_tool_calls_per_message, max_pending_confirmations, confirmation_timeout_s,
           max_message_length, max_context_messages,
           max_file_size_mb, max_files_per_message, max_pages_per_file, render_dpi,
           trash_min_days, trash_max_days, audit_months, org_deletion_grace_days,
           rate_limit_per_minute, lockout_after_failures, lockout_window_minutes,
           lockout_minutes, session_idle_timeout_minutes, session_max_lifetime_hours
    FROM platform_settings
    WHERE id
"""
# Locked until the transaction ends: concurrent platform changes serialize.
_PLATFORM_LOCK_SQL: Final = """
    SELECT llm_provider, infomaniak_model, vllm_model, anthropic_model, openai_model,
           max_tool_calls_per_message, max_pending_confirmations, confirmation_timeout_s,
           max_message_length, max_context_messages,
           max_file_size_mb, max_files_per_message, max_pages_per_file, render_dpi,
           trash_min_days, trash_max_days, audit_months, org_deletion_grace_days,
           rate_limit_per_minute, lockout_after_failures, lockout_window_minutes,
           lockout_minutes, session_idle_timeout_minutes, session_max_lifetime_hours
    FROM platform_settings
    WHERE id
    FOR UPDATE
"""
# $1 to $24 follow _UPDATE_FIELDS; a NULL parameter keeps the stored value.
_PLATFORM_UPDATE_SQL: Final = """
    UPDATE platform_settings
    SET llm_provider = coalesce($1, llm_provider),
        infomaniak_model = coalesce($2, infomaniak_model),
        vllm_model = coalesce($3, vllm_model),
        anthropic_model = coalesce($4, anthropic_model),
        openai_model = coalesce($5, openai_model),
        max_tool_calls_per_message = coalesce($6, max_tool_calls_per_message),
        max_pending_confirmations = coalesce($7, max_pending_confirmations),
        confirmation_timeout_s = coalesce($8, confirmation_timeout_s),
        max_message_length = coalesce($9, max_message_length),
        max_context_messages = coalesce($10, max_context_messages),
        max_file_size_mb = coalesce($11, max_file_size_mb),
        max_files_per_message = coalesce($12, max_files_per_message),
        max_pages_per_file = coalesce($13, max_pages_per_file),
        render_dpi = coalesce($14, render_dpi),
        trash_min_days = coalesce($15, trash_min_days),
        trash_max_days = coalesce($16, trash_max_days),
        audit_months = coalesce($17, audit_months),
        org_deletion_grace_days = coalesce($18, org_deletion_grace_days),
        rate_limit_per_minute = coalesce($19, rate_limit_per_minute),
        lockout_after_failures = coalesce($20, lockout_after_failures),
        lockout_window_minutes = coalesce($21, lockout_window_minutes),
        lockout_minutes = coalesce($22, lockout_minutes),
        session_idle_timeout_minutes = coalesce($23, session_idle_timeout_minutes),
        session_max_lifetime_hours = coalesce($24, session_max_lifetime_hours),
        updated_at = now()
    WHERE id
    RETURNING llm_provider, infomaniak_model, vllm_model, anthropic_model, openai_model,
              max_tool_calls_per_message, max_pending_confirmations, confirmation_timeout_s,
              max_message_length, max_context_messages,
              max_file_size_mb, max_files_per_message, max_pages_per_file, render_dpi,
              trash_min_days, trash_max_days, audit_months, org_deletion_grace_days,
              rate_limit_per_minute, lockout_after_failures, lockout_window_minutes,
              lockout_minutes, session_idle_timeout_minutes, session_max_lifetime_hours
"""


class StoredPlatformLLM(BaseModel):
    """The platform LLM as stored: the provider and one model per provider (None: unset)."""

    model_config = ConfigDict(frozen=True)

    provider: Literal["infomaniak", "vllm", "anthropic", "openai"]
    infomaniak_model: str | None = Field(max_length=200)
    vllm_model: str | None = Field(max_length=200)
    anthropic_model: str | None = Field(max_length=200)
    openai_model: str | None = Field(max_length=200)


class StoredPlatformSettings(BaseModel):
    """The ``platform_settings`` row: the LLM, the limits and the GH-160 defaults.

    The files, retention and security sections default to migration 0014's
    column defaults.
    """

    model_config = ConfigDict(frozen=True)

    llm: StoredPlatformLLM
    limits: PlatformLimits
    files: PlatformFiles = Field(default_factory=PlatformFiles)
    retention: PlatformRetention = Field(default_factory=PlatformRetention)
    security: PlatformSecurity = Field(default_factory=PlatformSecurity)


class InvalidPlatformSettingsError(ValueError):
    """The patch merged into the stored values is invalid (trash minimum above maximum)."""


# The int sections; each field is its platform_settings column.
_INT_SECTIONS: Final = (
    ("limits", PlatformLimits),
    ("files", PlatformFiles),
    ("retention", PlatformRetention),
    ("security", PlatformSecurity),
)
# The audit event order of the sections.
_SECTIONS: Final = ("llm", *(section for section, _ in _INT_SECTIONS))
# (section, field) in the parameter order of _PLATFORM_UPDATE_SQL.
_UPDATE_FIELDS: Final = (
    *(("llm", field) for field in StoredPlatformLLM.model_fields),
    *((section, field) for section, model in _INT_SECTIONS for field in model.model_fields),
)
_SESSION_FIELDS: Final = frozenset({"session_idle_timeout_minutes", "session_max_lifetime_hours"})
_TRASH_ORDER_ERROR: Final = "The trash retention minimum can't exceed the maximum."
_NO_SESSION_POLICY: Final = "No session policy for this account kind."

# The one in-process cache of the platform row (a single process, #139 §4.6).
_platform_cache: StoredPlatformSettings | None = None
# Bumped when an update replaces the cache: a read that began earlier doesn't
# overwrite the newer value.
_cache_generation: int = 0


def _require(actor: Principal, capability: Capability) -> None:
    """Raise PermissionError unless the actor has the capability (before any query)."""
    if not can(actor, capability):
        msg = "Forbidden"
        raise PermissionError(msg)


def _user_response(row: Record) -> UserSettingsResponse:
    """The UserSettingsResponse of a user_settings row."""
    return UserSettingsResponse(
        appearance=SettingsAppearance(theme=row["theme"]),
        notifications=SettingsNotifications(
            enabled=row["notifications_enabled"], task_done=row["notifications_task_done"]
        ),
    )


def _stored_platform(row: Record) -> StoredPlatformSettings:
    """The StoredPlatformSettings of a platform_settings row."""
    return StoredPlatformSettings.model_validate(
        {
            "llm": {
                "provider": row["llm_provider"],
                "infomaniak_model": row["infomaniak_model"],
                "vllm_model": row["vllm_model"],
                "anthropic_model": row["anthropic_model"],
                "openai_model": row["openai_model"],
            },
            **{
                section: {field: row[field] for field in model.model_fields}
                for section, model in _INT_SECTIONS
            },
        }
    )


async def _fetch_platform(executor: sessions.Executor, sql: str) -> StoredPlatformSettings:
    """Read (or, with the lock statement, lock) the platform row.

    Raises:
        RuntimeError: If there is no platform row (startup always seeds it).
    """
    row: Record | None = await executor.fetchrow(sql)
    if row is None:
        raise RuntimeError(_NO_PLATFORM_ROW)
    return _stored_platform(row)


async def _read_into_cache(executor: sessions.Executor) -> StoredPlatformSettings:
    """Read the platform row and cache it, unless an update replaced the cache meanwhile."""
    global _platform_cache
    generation = _cache_generation
    stored = await _fetch_platform(executor, _PLATFORM_SQL)
    if generation == _cache_generation:
        _platform_cache = stored
    return stored


def _super_admin_policy(security: PlatformSecurity) -> sessions.SessionPolicy:
    """The SessionPolicy of the stored Super Admin session fields."""
    return sessions.SessionPolicy(
        idle_timeout_minutes=security.session_idle_timeout_minutes,
        max_lifetime_hours=security.session_max_lifetime_hours,
    )


async def get_user_settings(pool: asyncpg.Pool, *, actor: Principal) -> UserSettingsResponse:
    """Return the actor's own theme and notifications (the defaults without a row).

    Args:
        pool: The database pool.
        actor: The logged-in account (any role, the Super Admin included).

    Returns:
        The UserSettingsResponse. A missing row reads as the defaults and
        nothing is written.

    Raises:
        PermissionError: Without ``Capability.ACCOUNT_MANAGE``; no query is
            issued.
    """
    _require(actor, Capability.ACCOUNT_MANAGE)
    row: Record | None = await pool.fetchrow(_USER_SQL, actor.user_id)
    if row is None:
        return UserSettingsResponse(
            appearance=SettingsAppearance(), notifications=SettingsNotifications()
        )
    return _user_response(row)


async def update_user_settings(
    pool: asyncpg.Pool, *, actor: Principal, patch: UserSettingsPatch
) -> UserSettingsResponse:
    """Change the given fields of the actor's own row (created from the defaults if missing).

    Not audited: the user scope is not in the audit catalog.

    Args:
        pool: The database pool.
        actor: The logged-in account (any role, the Super Admin included).
        patch: The validated theme and/or notifications to set.

    Returns:
        The stored UserSettingsResponse after the change.

    Raises:
        PermissionError: Without ``Capability.ACCOUNT_MANAGE``; no query is
            issued.
    """
    _require(actor, Capability.ACCOUNT_MANAGE)
    theme = None if patch.appearance is None else patch.appearance.theme
    enabled = None if patch.notifications is None else patch.notifications.enabled
    task_done = None if patch.notifications is None else patch.notifications.task_done
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute(_USER_ENSURE_SQL, actor.user_id)
        # The row exists now: the UPDATE ... RETURNING yields exactly one row.
        (row,) = await conn.fetch(_USER_UPDATE_SQL, actor.user_id, theme, enabled, task_done)
    return _user_response(row)


async def reset_user_settings(pool: asyncpg.Pool, *, actor: Principal) -> UserSettingsResponse:
    """Revert the actor's own theme and notifications to the defaults (GH-35).

    Deletes the actor's ``user_settings`` row: a missing row reads as the
    defaults. Idempotent (no row: nothing to delete). Not audited: the user
    scope is not in the audit catalog.

    Args:
        pool: The database pool.
        actor: The logged-in account (any role, the Super Admin included).

    Returns:
        The default UserSettingsResponse.

    Raises:
        PermissionError: Without ``Capability.ACCOUNT_MANAGE``; no query is
            issued.

    Security notes:
        Only the actor's own row (``actor.user_id``, a bind parameter) is
        touched: never the account row (names, languages), the connected
        accounts, another user's settings or the org and platform settings.
    """
    _require(actor, Capability.ACCOUNT_MANAGE)
    await pool.execute(_USER_RESET_SQL, actor.user_id)
    return UserSettingsResponse(
        appearance=SettingsAppearance(), notifications=SettingsNotifications()
    )


async def get_org_settings(pool: asyncpg.Pool, *, actor: Principal) -> OrgSettingsResponse:
    """Return the tool services of the actor's own org (every tool on without a row).

    Args:
        pool: The database pool.
        actor: The Org Admin asking.

    Returns:
        The OrgSettingsResponse: the stored switches (a missing row reads as
        every tool enabled and nothing is written) and the org's residency
        policy (``org_residency``).

    Raises:
        PermissionError: Without ``Capability.ORG_SETTINGS_MANAGE``; no query
            is issued.
    """
    _require(actor, Capability.ORG_SETTINGS_MANAGE)
    tenant = TenantContext.from_principal(actor)
    row: Record | None = await pool.fetchrow(_ORG_SQL, tenant.org_id)
    tools = ToolsSettings() if row is None else ToolsSettings.model_validate(dict(row))
    return OrgSettingsResponse(tools=tools, data_residency=await org_residency(pool, tenant))


async def update_org_settings(
    pool: asyncpg.Pool, *, actor: Principal, patch: OrgSettingsPatch, ip: str | None
) -> OrgSettingsResponse:
    """Switch the given tool services of the actor's own org; audit the real changes.

    One transaction: the org's row is created from the defaults if missing and
    locked, only the tools whose value changes are written, and
    ``org.settings_change`` records one ``<tool>_old`` / ``<tool>_new`` pair
    per changed tool. A patch that changes nothing writes and records nothing.

    Args:
        pool: The database pool.
        actor: The Org Admin changing them.
        patch: The validated tools to switch.
        ip: The client address, if known.

    Returns:
        The org's OrgSettingsResponse after the change, with the org's
        residency policy (read-only: a Google or Microsoft switch is stored
        even while residency is on; the run's policy applies residency).

    Raises:
        PermissionError: Without ``Capability.ORG_SETTINGS_MANAGE``; no query
            is issued.
        AuditRecordError: If the audit event can't be recorded; nothing
            changes.
    """
    _require(actor, Capability.ORG_SETTINGS_MANAGE)
    tenant = TenantContext.from_principal(actor)
    org_id = tenant.org_id
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute(_ORG_ENSURE_SQL, org_id)
        # The row exists now: the locking SELECT yields exactly one row.
        (locked,) = await conn.fetch(_ORG_LOCK_SQL, org_id)
        old = ToolsSettings.model_validate(dict(locked))
        residency = await org_residency(conn, tenant)
        changed: dict[str, bool] = {
            tool: enabled
            for tool, enabled in patch.tools.model_dump(exclude_none=True).items()
            if getattr(old, tool) != enabled
        }
        if not changed:
            return OrgSettingsResponse(tools=old, data_residency=residency)
        (row,) = await conn.fetch(_ORG_UPDATE_SQL, org_id, *(changed.get(tool) for tool in _TOOLS))
        metadata: dict[str, MetadataValue] = {}
        for tool in _TOOLS:
            if tool in changed:
                metadata |= {f"{tool}_old": getattr(old, tool), f"{tool}_new": changed[tool]}
        actor_kind, actor_user_id = audit_events.actor_columns(actor)
        await audit_events.record(
            conn,
            action=AuditAction.ORG_SETTINGS_CHANGE,
            actor_kind=actor_kind,
            actor_user_id=actor_user_id,
            org_id=org_id,
            target_type=TargetType.ORGANIZATION,
            target_ids=(org_id,),
            ip=ip,
            metadata=metadata,
        )
    return OrgSettingsResponse(
        tools=ToolsSettings.model_validate(dict(row)), data_residency=residency
    )


async def org_residency(executor: sessions.Executor, tenant: TenantContext) -> bool:
    """Return whether the tenant org's data residency policy is on (GH-162).

    No capability check: an internal read (a chat run's tool policy, the
    OAuth routes, the org settings responses). Only the tenant's org row is
    read; nothing is written.

    Args:
        executor: The pool, or a connection.
        tenant: The org scope.

    Returns:
        The org's ``data_residency`` flag; True when the org row is missing
        (fail closed: the Google and Microsoft tools stay off).
    """
    row: Record | None = await executor.fetchrow(_ORG_RESIDENCY_SQL, tenant.org_id)
    return True if row is None else row["data_residency"] is not False


async def org_tools_enabled(executor: sessions.Executor, tenant: TenantContext) -> dict[str, bool]:
    """Return the tenant org's tool switches, for a chat run (every tool on without a row).

    No capability check: an internal read (every member's run needs its org's
    switches). Only the tenant's org row is read; nothing is written.

    Args:
        executor: The pool, or a connection.
        tenant: The org scope of the run.

    Returns:
        Every tool name mapped to whether the org enabled its service.
    """
    row: Record | None = await executor.fetchrow(_ORG_SQL, tenant.org_id)
    tools = ToolsSettings() if row is None else ToolsSettings.model_validate(dict(row))
    return tools.model_dump()


async def seed_platform_settings(pool: asyncpg.Pool, config: AppConfig) -> None:
    """Store config.yaml's llm and limits in the platform row (one upsert statement).

    The first boot stores both; a later boot re-applies the llm (provider and
    the four models; an empty model is stored as NULL) and keeps the stored
    limits.

    Args:
        pool: The database pool.
        config: The config.yaml-loaded application config (env overrides applied).
    """
    llm = config.llm
    limits = config.limits
    await pool.execute(
        _PLATFORM_SEED_SQL,
        llm.provider,
        llm.infomaniak_model or None,
        llm.vllm_model or None,
        llm.anthropic_model or None,
        llm.openai_model or None,
        limits.max_tool_calls_per_message,
        limits.max_pending_confirmations,
        limits.confirmation_timeout_s,
        limits.max_message_length,
        limits.max_context_messages,
    )


async def load_platform_settings(executor: sessions.Executor) -> StoredPlatformSettings:
    """Read the platform row (every section) and replace the cache with it.

    Used at startup, which primes the cache, and by the platform settings
    page, which shows the row as stored.

    Args:
        executor: The pool or a connection.

    Returns:
        The StoredPlatformSettings.

    Raises:
        RuntimeError: If there is no platform row (startup always seeds it);
            the cache is unchanged.
    """
    return await _read_into_cache(executor)


async def current_platform_settings(executor: sessions.Executor) -> StoredPlatformSettings:
    """Return the cached platform settings; read the row once if the cache is empty.

    Every consumer of a platform default reads it here. A cache hit issues no
    query; a miss reads the row with one statement and caches it.

    Args:
        executor: The pool or a connection (inside the caller's transaction).

    Returns:
        The StoredPlatformSettings.

    Raises:
        RuntimeError: If the cache is empty and there is no platform row; the
            cache stays empty.
    """
    cached = _platform_cache
    if cached is not None:
        return cached
    return await _read_into_cache(executor)


async def session_policy_for(executor: sessions.Executor, kind: str) -> sessions.SessionPolicy:
    """Return the policy a new session of an account kind gets.

    Args:
        executor: The pool or a connection (read only on a cache miss).
        kind: The account's kind: "member" (the org default until #169, no
            query) or "super_admin" (the stored platform policy).

    Returns:
        The SessionPolicy, read when called.

    Raises:
        ValueError: For any other kind (there is no default policy); no query
            is issued.
        RuntimeError: If a Super Admin's policy can't be read (no platform row).
    """
    if kind == "member":
        return sessions.DEFAULT_ORG_SESSION_POLICY
    if kind == "super_admin":
        return _super_admin_policy((await current_platform_settings(executor)).security)
    raise ValueError(_NO_SESSION_POLICY)


def apply_platform_settings(config: AppConfig, stored: StoredPlatformSettings) -> AppConfig:
    """Overlay the stored platform LLM and limits onto the config (pure).

    Args:
        config: The config.yaml-loaded application config; left unchanged.
        stored: The platform row.

    Returns:
        A copy of ``config`` whose ``llm.provider``, the four ``llm.*_model``
        fields and the five limits come from ``stored`` (both sections
        validated again). Every other llm field (timeout, vLLM URL and
        context length, response tokens) and every other section stay.
    """
    llm = LLMConfig.model_validate({**config.llm.model_dump(), **stored.llm.model_dump()})
    limits = LimitsConfig.model_validate(stored.limits.model_dump())
    return config.model_copy(update={"llm": llm, "limits": limits})


def _changes(
    stored: StoredPlatformSettings, patch: PlatformSettingsPatch
) -> dict[str, dict[str, str | int]]:
    """Per section (in event order), the given fields whose value differs from the stored one."""
    changes: dict[str, dict[str, str | int]] = {}
    for section in _SECTIONS:
        given: BaseModel | None = getattr(patch, section)
        if given is None:
            continue
        current = getattr(stored, section)
        changed = {
            field: value
            for field, value in given.model_dump(exclude_none=True).items()
            if getattr(current, field) != value
        }
        if changed:
            changes[section] = changed
    return changes


def _check_retention(stored: PlatformRetention, changed: dict[str, str | int]) -> None:
    """Validate the retention patch merged into the stored values.

    Raises:
        InvalidPlatformSettingsError: If the merged trash minimum exceeds the
            maximum.
    """
    try:
        PlatformRetention.model_validate({**stored.model_dump(), **changed})
    except ValidationError:
        raise InvalidPlatformSettingsError(_TRASH_ORDER_ERROR) from None


def _event_metadata(
    section: str, old: BaseModel, changed: dict[str, str | int], sessions_updated: int | None
) -> dict[str, MetadataValue]:
    """The metadata of one section's ``platform.settings_change`` event.

    llm: the changed field names mapped to True (never a provider or model
    value). An int section: ``<field>_old`` / ``<field>_new`` per changed
    field; security adds ``sessions_updated`` when the session policy changed.
    """
    if section == "llm":
        return dict.fromkeys(changed, True)
    metadata: dict[str, MetadataValue] = {}
    for field, value in changed.items():
        metadata |= {f"{field}_old": getattr(old, field), f"{field}_new": value}
    if section == "security" and sessions_updated is not None:
        metadata["sessions_updated"] = sessions_updated
    return metadata


async def update_platform_settings(
    pool: asyncpg.Pool, *, actor: Principal, patch: PlatformSettingsPatch, ip: str | None
) -> StoredPlatformSettings:
    """Change the given platform defaults; audit each changed section; re-time sessions.

    One transaction: the platform row is locked, the patch is merged into it
    (a trash minimum above the maximum is refused before any write), and only
    the fields whose value changes are written, with one UPDATE. A changed
    Super Admin session policy applies to every open Super Admin session.
    Each changed section records one ``platform.settings_change`` event, in
    the order llm, limits, files, retention, security: the llm event names
    the changed fields (``{<field>: True}``, never a provider or model
    value), the others carry ``<field>_old`` / ``<field>_new`` ints, and the
    security event adds ``sessions_updated`` when a session field changed. A
    patch that changes nothing writes and records nothing. After the commit
    the cache holds the new settings.

    Args:
        pool: The database pool.
        actor: The Super Admin changing them.
        patch: The validated sections to change.
        ip: The client address, if known.

    Returns:
        The StoredPlatformSettings after the change (the new cache value).

    Raises:
        PermissionError: Without ``Capability.PLATFORM_DEFAULTS_MANAGE``; no
            query is issued.
        InvalidPlatformSettingsError: If the merged trash minimum exceeds the
            maximum; nothing changes.
        AuditRecordError: If an audit event can't be recorded; nothing
            changes (the sessions and the cache included).
        RuntimeError: If there is no platform row.
    """
    global _platform_cache, _cache_generation
    _require(actor, Capability.PLATFORM_DEFAULTS_MANAGE)
    async with pool.acquire() as conn, conn.transaction():
        stored = await _fetch_platform(conn, _PLATFORM_LOCK_SQL)
        changes = _changes(stored, patch)
        if "retention" in changes:
            _check_retention(stored.retention, changes["retention"])
        if not changes:
            return stored
        (row,) = await conn.fetch(
            _PLATFORM_UPDATE_SQL,
            *(changes.get(section, {}).get(field) for section, field in _UPDATE_FIELDS),
        )
        updated = _stored_platform(row)
        sessions_updated: int | None = None
        if _SESSION_FIELDS & changes.get("security", {}).keys():
            sessions_updated = await sessions.apply_super_admin_policy(
                conn, _super_admin_policy(updated.security)
            )
        actor_kind, actor_user_id = audit_events.actor_columns(actor)
        # _changes keeps the event order: llm, limits, files, retention, security.
        for section, changed in changes.items():
            await audit_events.record(
                conn,
                action=AuditAction.PLATFORM_SETTINGS_CHANGE,
                actor_kind=actor_kind,
                actor_user_id=actor_user_id,
                org_id=None,
                ip=ip,
                metadata=_event_metadata(
                    section, getattr(stored, section), changed, sessions_updated
                ),
            )
    _cache_generation += 1
    _platform_cache = updated
    return updated
