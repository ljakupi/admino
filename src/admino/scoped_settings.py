"""The settings scopes: platform, organization and user settings (GH-159).

Migration 0013 replaced the old key/value ``settings`` table with one table per
owner, and this module is the service behind their routes and the startup:

- ``user_settings`` (each user, the Super Admin included): theme and
  notifications. ``get_user_settings`` / ``update_user_settings`` read and
  change the caller's own row (``Capability.ACCOUNT_MANAGE``). Not audited:
  the user scope is not in the audit catalog.
- ``org_settings`` (each organization, its Org Admin): the enabled tool
  services. ``get_org_settings`` / ``update_org_settings`` read and change the
  caller's own org's row (``Capability.ORG_SETTINGS_MANAGE``); each real
  change is an ``org.settings_change`` audit event.
- ``platform_settings`` (one row, the Super Admin): the LLM provider, one
  model per provider and the limits. ``seed_platform_settings`` stores
  config.yaml's llm and limits on the first boot and re-applies its llm on
  every later boot (the stored limits are kept); ``load_platform_settings``
  reads the row; ``apply_platform_settings`` overlays it onto the config;
  ``update_platform_llm`` changes the LLM (``Capability.PLATFORM_DEFAULTS_MANAGE``),
  each real change a ``platform.settings_change`` audit event. The limits are
  read-only until #160 makes them editable.
- ``all_orgs_tools_gate`` is the INTERIM enabled-services gate, retired by
  #161 (per-org tool gating): the agent keeps one global gate, and a service
  is off when ANY org turned it off (no org rows: every service on).

A missing user or org row reads as the defaults (theme light, notifications
on, every tool on) and a read writes nothing; an update creates the row from
the column defaults first.

Inputs: the database pool; the acting ``Principal`` (from the session), the
validated patch models (``UserSettingsPatch``, ``OrgSettingsPatch``,
``SettingsPatchLLM``) and the client IP; the ``AppConfig`` (startup).
Outputs: ``UserSettingsResponse``, ``OrgSettingsResponse``,
``StoredPlatformSettings``, the gate (tool name -> bool) and the overlaid
``AppConfig``. Errors: ``PermissionError``, ``AuditRecordError``,
``RuntimeError`` (no platform row: startup always seeds it first).

Security notes:
- Authorization through ``access.can`` before any statement: a refused actor
  gets ``PermissionError`` and nothing is read or written. The Super Admin
  reaches no org's settings; member roles never reach the platform LLM.
- Tenant isolation: the org is always ``TenantContext.from_principal(actor)``
  and the user always ``actor.user_id``, both bind parameters; never a
  request value.
- Fail closed: an org or platform change, its row lock (``FOR UPDATE``) and
  its audit event share one transaction on one connection, so a failed audit
  write rolls the change back. A no-op writes nothing and records nothing.
- No content in audit rows: org events carry one ``<tool>_old`` /
  ``<tool>_new`` bool pair per changed tool; platform events carry the names
  of the changed fields mapped to True, never a provider or model value.
  Nothing is logged here.
- Parameterized SQL only: every statement is a constant, every value a bind
  parameter.
- Imports only access, tenancy, audit_events, models and config from admino:
  never the server, agent, LLM, tools, OAuth, database or permission engine
  modules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from admino import audit_events
from admino.access import Capability, Principal, can
from admino.audit_events import AuditAction, TargetType
from admino.config import AppConfig, LimitsConfig, LLMConfig
from admino.models import (
    OrgSettingsResponse,
    PlatformLimits,
    SettingsAppearance,
    SettingsNotifications,
    ToolsSettings,
    UserSettingsResponse,
)
from admino.tenancy import TenantContext

if TYPE_CHECKING:
    import asyncpg
    from asyncpg import Record
    from asyncpg.pool import PoolConnectionProxy

    from admino.audit_events import MetadataValue
    from admino.models import OrgSettingsPatch, SettingsPatchLLM, UserSettingsPatch

# The tool names in the column order of the org statements below.
_TOOLS: Final = tuple(ToolsSettings.model_fields)
_NO_PLATFORM_ROW: Final = "The platform settings are missing; startup seeds them."

_USER_SQL: Final = """
    SELECT theme, notifications_enabled
    FROM user_settings
    WHERE user_id = $1
"""
# The column defaults of migration 0013 fill a new row.
_USER_ENSURE_SQL: Final = """
    INSERT INTO user_settings (user_id) VALUES ($1)
    ON CONFLICT (user_id) DO NOTHING
"""
# A NULL parameter keeps the stored value.
_USER_UPDATE_SQL: Final = """
    UPDATE user_settings
    SET theme = coalesce($2, theme),
        notifications_enabled = coalesce($3, notifications_enabled),
        updated_at = now()
    WHERE user_id = $1
    RETURNING theme, notifications_enabled
"""

_ORG_SQL: Final = """
    SELECT gmail_enabled AS gmail, google_calendar_enabled AS google_calendar,
           google_drive_enabled AS google_drive, outlook_enabled AS outlook,
           outlook_calendar_enabled AS outlook_calendar, onedrive_enabled AS onedrive,
           memory_enabled AS memory
    FROM org_settings
    WHERE org_id = $1
"""
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
# Interim gate (retired by #161): a tool is on only if no org turned it off.
_GATE_SQL: Final = """
    SELECT coalesce(bool_and(gmail_enabled), true) AS gmail,
           coalesce(bool_and(google_calendar_enabled), true) AS google_calendar,
           coalesce(bool_and(google_drive_enabled), true) AS google_drive,
           coalesce(bool_and(outlook_enabled), true) AS outlook,
           coalesce(bool_and(outlook_calendar_enabled), true) AS outlook_calendar,
           coalesce(bool_and(onedrive_enabled), true) AS onedrive,
           coalesce(bool_and(memory_enabled), true) AS memory
    FROM org_settings
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
           max_message_length, max_context_messages
    FROM platform_settings
    WHERE id
"""
# Locked until the transaction ends: concurrent LLM changes serialize.
_PLATFORM_LOCK_SQL: Final = """
    SELECT llm_provider, infomaniak_model, vllm_model, anthropic_model, openai_model,
           max_tool_calls_per_message, max_pending_confirmations, confirmation_timeout_s,
           max_message_length, max_context_messages
    FROM platform_settings
    WHERE id
    FOR UPDATE
"""
# A NULL parameter keeps the stored value.
_PLATFORM_LLM_UPDATE_SQL: Final = """
    UPDATE platform_settings
    SET llm_provider = coalesce($1, llm_provider),
        infomaniak_model = coalesce($2, infomaniak_model),
        vllm_model = coalesce($3, vllm_model),
        anthropic_model = coalesce($4, anthropic_model),
        openai_model = coalesce($5, openai_model),
        updated_at = now()
    WHERE id
    RETURNING llm_provider, infomaniak_model, vllm_model, anthropic_model, openai_model,
              max_tool_calls_per_message, max_pending_confirmations, confirmation_timeout_s,
              max_message_length, max_context_messages
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
    """The ``platform_settings`` row: the LLM and the limits (read-only until #160)."""

    model_config = ConfigDict(frozen=True)

    llm: StoredPlatformLLM
    limits: PlatformLimits


def _require(actor: Principal, capability: Capability) -> None:
    """Raise PermissionError unless the actor has the capability (before any query)."""
    if not can(actor, capability):
        msg = "Forbidden"
        raise PermissionError(msg)


def _user_response(row: Record) -> UserSettingsResponse:
    """The UserSettingsResponse of a user_settings row."""
    return UserSettingsResponse(
        appearance=SettingsAppearance(theme=row["theme"]),
        notifications=SettingsNotifications(enabled=row["notifications_enabled"]),
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
            "limits": {field: row[field] for field in PlatformLimits.model_fields},
        }
    )


async def _fetch_platform(
    executor: asyncpg.Pool | PoolConnectionProxy, sql: str
) -> StoredPlatformSettings:
    """Read (or, with the lock statement, lock) the platform row.

    Raises:
        RuntimeError: If there is no platform row (startup always seeds it).
    """
    row: Record | None = await executor.fetchrow(sql)
    if row is None:
        raise RuntimeError(_NO_PLATFORM_ROW)
    return _stored_platform(row)


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
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute(_USER_ENSURE_SQL, actor.user_id)
        # The row exists now: the UPDATE ... RETURNING yields exactly one row.
        (row,) = await conn.fetch(_USER_UPDATE_SQL, actor.user_id, theme, enabled)
    return _user_response(row)


async def get_org_settings(pool: asyncpg.Pool, *, actor: Principal) -> OrgSettingsResponse:
    """Return the tool services of the actor's own org (every tool on without a row).

    Args:
        pool: The database pool.
        actor: The Org Admin asking.

    Returns:
        The OrgSettingsResponse. A missing row reads as every tool enabled and
        nothing is written.

    Raises:
        PermissionError: Without ``Capability.ORG_SETTINGS_MANAGE``; no query
            is issued.
    """
    _require(actor, Capability.ORG_SETTINGS_MANAGE)
    org_id = TenantContext.from_principal(actor).org_id
    row: Record | None = await pool.fetchrow(_ORG_SQL, org_id)
    tools = ToolsSettings() if row is None else ToolsSettings.model_validate(dict(row))
    return OrgSettingsResponse(tools=tools)


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
        The org's OrgSettingsResponse after the change.

    Raises:
        PermissionError: Without ``Capability.ORG_SETTINGS_MANAGE``; no query
            is issued.
        AuditRecordError: If the audit event can't be recorded; nothing
            changes.
    """
    _require(actor, Capability.ORG_SETTINGS_MANAGE)
    org_id = TenantContext.from_principal(actor).org_id
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute(_ORG_ENSURE_SQL, org_id)
        # The row exists now: the locking SELECT yields exactly one row.
        (locked,) = await conn.fetch(_ORG_LOCK_SQL, org_id)
        old = ToolsSettings.model_validate(dict(locked))
        changed: dict[str, bool] = {
            tool: enabled
            for tool, enabled in patch.tools.model_dump(exclude_none=True).items()
            if getattr(old, tool) != enabled
        }
        if not changed:
            return OrgSettingsResponse(tools=old)
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
    return OrgSettingsResponse(tools=ToolsSettings.model_validate(dict(row)))


async def all_orgs_tools_gate(pool: asyncpg.Pool) -> dict[str, bool]:
    """Return the INTERIM global enabled-services gate (retired by #161).

    One aggregate statement over every ``org_settings`` row: a service is off
    when ANY org turned it off; without rows every service is on.

    Args:
        pool: The database pool.

    Returns:
        Every tool name mapped to whether the agent may dispatch it.
    """
    # An aggregate without GROUP BY always yields exactly one row.
    (row,) = await pool.fetch(_GATE_SQL)
    return ToolsSettings.model_validate(dict(row)).model_dump()


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


async def load_platform_settings(pool: asyncpg.Pool) -> StoredPlatformSettings:
    """Return the platform row: the LLM and the limits.

    Args:
        pool: The database pool.

    Returns:
        The StoredPlatformSettings.

    Raises:
        RuntimeError: If there is no platform row (startup always seeds it).
    """
    return await _fetch_platform(pool, _PLATFORM_SQL)


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


async def update_platform_llm(
    pool: asyncpg.Pool, *, actor: Principal, patch: SettingsPatchLLM, ip: str | None
) -> StoredPlatformSettings:
    """Change the given platform LLM fields; audit the names of the changed ones.

    One transaction: the platform row is locked, only the fields whose value
    changes are written, and ``platform.settings_change`` records
    ``{<changed field>: True}`` (field names only, never a provider or model
    value). A patch that changes nothing writes and records nothing.

    Args:
        pool: The database pool.
        actor: The Super Admin changing it.
        patch: The validated provider and/or model names to set.
        ip: The client address, if known.

    Returns:
        The StoredPlatformSettings after the change.

    Raises:
        PermissionError: Without ``Capability.PLATFORM_DEFAULTS_MANAGE``; no
            query is issued.
        AuditRecordError: If the audit event can't be recorded; nothing
            changes.
        RuntimeError: If there is no platform row.
    """
    _require(actor, Capability.PLATFORM_DEFAULTS_MANAGE)
    async with pool.acquire() as conn, conn.transaction():
        stored = await _fetch_platform(conn, _PLATFORM_LOCK_SQL)
        current = stored.llm.model_dump()
        changed = {
            field: value
            for field, value in patch.model_dump(exclude_none=True).items()
            if current[field] != value
        }
        if not changed:
            return stored
        (row,) = await conn.fetch(
            _PLATFORM_LLM_UPDATE_SQL,
            changed.get("provider"),
            changed.get("infomaniak_model"),
            changed.get("vllm_model"),
            changed.get("anthropic_model"),
            changed.get("openai_model"),
        )
        actor_kind, actor_user_id = audit_events.actor_columns(actor)
        await audit_events.record(
            conn,
            action=AuditAction.PLATFORM_SETTINGS_CHANGE,
            actor_kind=actor_kind,
            actor_user_id=actor_user_id,
            org_id=None,
            ip=ip,
            metadata=dict.fromkeys(changed, True),
        )
    return _stored_platform(row)
