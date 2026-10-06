"""The settings scopes: platform, organization and user settings (GH-159, GH-160, GH-169).

Migration 0013 replaced the old key/value ``settings`` table with one table per
owner, and this module is the service behind their routes and the startup:

- ``user_settings`` (each user, the Super Admin included): theme and
  notifications (the tool-approval and, GH-35, the task-done pings).
  ``get_user_settings`` / ``update_user_settings`` read and change the
  caller's own row and ``reset_user_settings`` deletes it, so it reads as the
  defaults again (``Capability.ACCOUNT_MANAGE``). Not audited: the user scope
  is not in the audit catalog.
- ``org_settings`` (each organization, its Org Admin): the enabled tool
  services and (GH-169, migration 0023) the org instructions, the session
  policy and the trash retention; the org's profile (``organizations.name``
  and ``default_response_language``) is edited with them.
  ``get_org_settings`` / ``update_org_settings`` read and change the caller's
  own org's rows (``Capability.ORG_SETTINGS_MANAGE`` and
  ``Capability.ORG_INSTRUCTIONS_MANAGE``: every response carries the
  instructions); each changed section is an ``org.settings_change`` audit
  event. The responses also carry, read-only, the org's ``data_residency``
  (a Google or Microsoft switch can still be stored while it is on), its
  plan (seats, storage quota) and the platform's trash bounds; a changed
  trash retention must lie within them (``InvalidOrgSettingsError``), and
  the retention shown is the stored one clamped into them. A changed session
  policy re-times the org's live sessions (``sessions.apply_org_policy``).
  ``org_tools_enabled`` (GH-161) reads a tenant org's switches for a chat
  run, without a capability check (an internal read: every member's run
  needs it); it returns the stored switches, residency not applied.
  ``org_residency`` (GH-162) reads the org's ``data_residency`` policy the
  same way, and ``load_prompt_context`` (GH-170) a chat run's prompt
  inputs: the org's instructions and default response language and the
  user's response language, timezone and personal instructions, in one
  read of a live user of the tenant's org. Their pure row conversions
  (``switches_from_row``, ``residency_from_value``,
  ``prompt_context_from_row``) are shared with the send path's
  one-statement turn setup (``turn_setup.load_turn_setup``, GH-244).
- ``platform_settings`` (one row, the Super Admin): the LLM provider, one
  model per provider, (GH-242, migration 0022) the active model's
  capabilities (``max_input_tokens``, ``image_input``) and the LLM retry
  limit (``max_retries``, column ``llm_max_retries``), the limits and
  (GH-160) the files, retention and security defaults.
  ``seed_platform_settings`` stores config.yaml's llm and limits on the first
  boot and re-applies its llm (provider, models, model capabilities) on
  every later boot (the stored limits are kept; the retry limit is never
  seeded, so it starts from its column default and a stored value is kept;
  the other defaults start from migration 0014's column defaults);
  ``apply_platform_settings`` overlays the LLM (all but the retry limit,
  which is no ``LLMConfig`` field) and limits onto the config;
  ``update_platform_settings`` changes any of the five sections
  (``Capability.PLATFORM_DEFAULTS_MANAGE``), each changed section a
  ``platform.settings_change`` audit event. ``count_residency_orgs``
  (GH-242) counts the orgs with data residency on; an update given the count
  the route confirmed for a non-Swiss switch counts again under its row lock
  and raises ``ResidencyConfirmationError`` when it changed.
- One in-process cache of the platform row (``_platform_cache``, GH-160):
  ``current_platform_settings`` answers from it (reading the row once when it
  is empty), ``load_platform_settings`` (startup, the platform settings page)
  reads the row and replaces it, and a successful update replaces it after
  its commit. Consumers read every platform default through it;
  ``session_policy_for`` picks a new session's policy (a member: their org's
  stored policy, read from org_settings on every call; a Super Admin: the
  stored platform policy).

A missing user or org_settings row reads as the column defaults (theme
light, tool-approval pings on, task-done pings off; every tool on, no
instructions, 60 minutes idle, 12 hours lifetime, 30 days trash) and a read
writes nothing; an update creates the row from the column defaults first.

Inputs: the database pool (or a connection, for the platform reads); the
acting ``Principal`` (from the session), the validated patch models
(``UserSettingsPatch``, ``OrgSettingsPatch``, ``PlatformSettingsPatch``) and
the client IP; the ``AppConfig`` (startup); an account kind and, for a
member, their org id; a chat run's ``TenantContext``.
Outputs: ``UserSettingsResponse``, ``OrgSettingsResponse``,
``StoredPlatformSettings``, an org's switches (tool name -> bool) and its
residency flag, a run's ``PromptContext``, the
overlaid ``AppConfig`` and a ``SessionPolicy``. Errors: ``PermissionError``,
``AuditRecordError``, ``InvalidPlatformSettingsError`` (the merged trash
minimum exceeds the maximum), ``InvalidOrgSettingsError`` (a changed org trash
retention outside the platform's trash bounds), ``ResidencyConfirmationError``
(the confirmed residency-org count changed before the write), ``LookupError``
(the org settings of an org without an organizations row), ``RuntimeError``
(no platform row: startup always seeds it first), ``ValueError`` (no session
policy for the kind, or a member without an org id).

Security notes:
- Authorization through ``access.can`` before any statement: a refused actor
  gets ``PermissionError`` and nothing is read or written. The Super Admin
  reaches no org's settings; member roles never reach a platform default.
- Tenant isolation: the org is always ``TenantContext.from_principal(actor)``
  and the user always ``actor.user_id``, both bind parameters; never a
  request value. The internal reads take the run's ``TenantContext``: the
  prompt inputs only match a live user whose org is the tenant's org.
- The org and personal instructions are content: they are read for the
  prompt and never logged or audited by the prompt-context read.
- Fail closed: an org without an organizations row reads as residency on.
  An org or platform change, its row locks (``FOR UPDATE``; for an org both
  its org_settings and its organizations row) and its audit events share one
  transaction on one connection, so a failed audit write rolls the change
  back (the re-timed sessions too). A no-op changes no value and records
  nothing (an org no-op may still create the org's missing org_settings row
  from the column defaults, which read the same as no row); an invalid
  merged platform retention, or a changed org retention
  outside the platform's bounds, is refused before any write. The cache only
  takes values that were committed: an update replaces it after its commit,
  and a read that began before an update committed never overwrites the
  update's value.
- A session-policy change applies to the open sessions it governs in the
  same transaction: the Super Admin's to every open Super Admin session
  (``sessions.apply_super_admin_policy``), an org's to the live sessions of
  that org's users only (``sessions.apply_org_policy``). A session older than
  the new lifetime, or idle past the new timeout, ends.
- No content in audit rows: the org profile event names the changed fields
  only (never the org name or language), the instructions event is
  ``{"instructions": True}`` (never the text, its length or a hash), the org
  security and retention events carry ``<field>_old`` / ``<field>_new`` ints
  (security adds ``sessions_updated``, a count) and the tools event one
  ``<tool>_old`` / ``<tool>_new`` bool pair per changed tool; the platform llm
  event carries the names of the changed fields mapped to True
  (``max_retries``, never the column name), never a provider, model, input
  window or retry value; the other platform events carry ``<field>_old`` /
  ``<field>_new`` ints (and ``sessions_updated``, a count). Nothing is logged
  here.
- Parameterized SQL only: every statement is a constant, every value a bind
  parameter.
- Imports only access, tenancy, audit_events, models, config and sessions
  from admino: never the server, agent, LLM, tools, OAuth, database or
  permission engine modules.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, Literal

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
    PromptContext,
    SettingsAppearance,
    SettingsNotifications,
    ToolsSettings,
    UserSettingsResponse,
)
from admino.tenancy import TenantContext

if TYPE_CHECKING:
    from collections.abc import Mapping
    from uuid import UUID

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
# GH-242: the number of orgs with data residency on (every status).
_RESIDENCY_ORGS_SQL: Final = (
    "SELECT count(*) AS residency_orgs FROM organizations WHERE data_residency"
)
_ORG_ENSURE_SQL: Final = """
    INSERT INTO org_settings (org_id) VALUES ($1)
    ON CONFLICT (org_id) DO NOTHING
"""
# GH-169: the org settings page reads the whole row (the tools by tool name).
_ORG_SETTINGS_SQL: Final = """
    SELECT gmail_enabled AS gmail, google_calendar_enabled AS google_calendar,
           google_drive_enabled AS google_drive, outlook_enabled AS outlook,
           outlook_calendar_enabled AS outlook_calendar, onedrive_enabled AS onedrive,
           memory_enabled AS memory, instructions, session_idle_timeout_minutes,
           session_max_lifetime_hours, trash_retention_days
    FROM org_settings
    WHERE org_id = $1
"""
# Locked until the transaction ends: concurrent changes of one org serialize.
_ORG_LOCK_SQL: Final = """
    SELECT gmail_enabled AS gmail, google_calendar_enabled AS google_calendar,
           google_drive_enabled AS google_drive, outlook_enabled AS outlook,
           outlook_calendar_enabled AS outlook_calendar, onedrive_enabled AS onedrive,
           memory_enabled AS memory, instructions, session_idle_timeout_minutes,
           session_max_lifetime_hours, trash_retention_days
    FROM org_settings
    WHERE org_id = $1
    FOR UPDATE
"""
# $2 to $12 follow _ORG_SETTINGS_FIELDS; a NULL parameter keeps the stored value.
_ORG_UPDATE_SQL: Final = """
    UPDATE org_settings
    SET gmail_enabled = coalesce($2, gmail_enabled),
        google_calendar_enabled = coalesce($3, google_calendar_enabled),
        google_drive_enabled = coalesce($4, google_drive_enabled),
        outlook_enabled = coalesce($5, outlook_enabled),
        outlook_calendar_enabled = coalesce($6, outlook_calendar_enabled),
        onedrive_enabled = coalesce($7, onedrive_enabled),
        memory_enabled = coalesce($8, memory_enabled),
        instructions = coalesce($9, instructions),
        session_idle_timeout_minutes = coalesce($10, session_idle_timeout_minutes),
        session_max_lifetime_hours = coalesce($11, session_max_lifetime_hours),
        trash_retention_days = coalesce($12, trash_retention_days),
        updated_at = now()
    WHERE org_id = $1
    RETURNING gmail_enabled AS gmail, google_calendar_enabled AS google_calendar,
              google_drive_enabled AS google_drive, outlook_enabled AS outlook,
              outlook_calendar_enabled AS outlook_calendar, onedrive_enabled AS onedrive,
              memory_enabled AS memory, instructions, session_idle_timeout_minutes,
              session_max_lifetime_hours, trash_retention_days
"""
# GH-169: the org's profile and its read-only residency and plan.
_ORG_PROFILE_SQL: Final = """
    SELECT name AS display_name, default_response_language, data_residency, seats,
           storage_quota_bytes
    FROM organizations
    WHERE id = $1
"""
# Locked with the org_settings row: a concurrent profile change waits.
_ORG_PROFILE_LOCK_SQL: Final = """
    SELECT name AS display_name, default_response_language, data_residency, seats,
           storage_quota_bytes
    FROM organizations
    WHERE id = $1
    FOR UPDATE
"""
# A NULL parameter keeps the stored value.
_ORG_PROFILE_UPDATE_SQL: Final = """
    UPDATE organizations
    SET name = coalesce($2, name),
        default_response_language = coalesce($3, default_response_language),
        updated_at = now()
    WHERE id = $1
"""
# GH-170: a chat run's prompt inputs; only a live user of the tenant's org matches.
_PROMPT_CONTEXT_SQL: Final = """
    SELECT u.response_language, u.timezone, u.personal_instructions,
           o.default_response_language, s.instructions AS org_instructions
    FROM users u
    JOIN organizations o ON o.id = u.org_id
    LEFT JOIN org_settings s ON s.org_id = o.id
    WHERE u.id = $1 AND u.org_id = $2 AND u.deleted_at IS NULL
"""
# GH-169: a member's new session takes their org's stored policy.
_MEMBER_POLICY_SQL: Final = """
    SELECT session_idle_timeout_minutes, session_max_lifetime_hours
    FROM org_settings
    WHERE org_id = $1
"""

# The singleton row (id defaults to true). On a later boot config.yaml's llm
# (provider, models, model capabilities) replaces the stored one; the stored
# limits are kept. The retry limit is never written here (column default 2).
_PLATFORM_SEED_SQL: Final = """
    INSERT INTO platform_settings (
        llm_provider, infomaniak_model, vllm_model, anthropic_model, openai_model,
        max_input_tokens, image_input,
        max_tool_calls_per_message, max_pending_confirmations, confirmation_timeout_s,
        max_message_length, max_context_messages
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    ON CONFLICT (id) DO UPDATE
    SET llm_provider = EXCLUDED.llm_provider,
        infomaniak_model = EXCLUDED.infomaniak_model,
        vllm_model = EXCLUDED.vllm_model,
        anthropic_model = EXCLUDED.anthropic_model,
        openai_model = EXCLUDED.openai_model,
        max_input_tokens = EXCLUDED.max_input_tokens,
        image_input = EXCLUDED.image_input,
        updated_at = now()
"""
_PLATFORM_SQL: Final = """
    SELECT llm_provider, infomaniak_model, vllm_model, anthropic_model, openai_model,
           max_input_tokens, image_input, llm_max_retries,
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
           max_input_tokens, image_input, llm_max_retries,
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
# $1 to $27 follow _UPDATE_FIELDS; a NULL parameter keeps the stored value.
_PLATFORM_UPDATE_SQL: Final = """
    UPDATE platform_settings
    SET llm_provider = coalesce($1, llm_provider),
        infomaniak_model = coalesce($2, infomaniak_model),
        vllm_model = coalesce($3, vllm_model),
        anthropic_model = coalesce($4, anthropic_model),
        openai_model = coalesce($5, openai_model),
        max_input_tokens = coalesce($6, max_input_tokens),
        image_input = coalesce($7, image_input),
        llm_max_retries = coalesce($8, llm_max_retries),
        max_tool_calls_per_message = coalesce($9, max_tool_calls_per_message),
        max_pending_confirmations = coalesce($10, max_pending_confirmations),
        confirmation_timeout_s = coalesce($11, confirmation_timeout_s),
        max_message_length = coalesce($12, max_message_length),
        max_context_messages = coalesce($13, max_context_messages),
        max_file_size_mb = coalesce($14, max_file_size_mb),
        max_files_per_message = coalesce($15, max_files_per_message),
        max_pages_per_file = coalesce($16, max_pages_per_file),
        render_dpi = coalesce($17, render_dpi),
        trash_min_days = coalesce($18, trash_min_days),
        trash_max_days = coalesce($19, trash_max_days),
        audit_months = coalesce($20, audit_months),
        org_deletion_grace_days = coalesce($21, org_deletion_grace_days),
        rate_limit_per_minute = coalesce($22, rate_limit_per_minute),
        lockout_after_failures = coalesce($23, lockout_after_failures),
        lockout_window_minutes = coalesce($24, lockout_window_minutes),
        lockout_minutes = coalesce($25, lockout_minutes),
        session_idle_timeout_minutes = coalesce($26, session_idle_timeout_minutes),
        session_max_lifetime_hours = coalesce($27, session_max_lifetime_hours),
        updated_at = now()
    WHERE id
    RETURNING llm_provider, infomaniak_model, vllm_model, anthropic_model, openai_model,
              max_input_tokens, image_input, llm_max_retries,
              max_tool_calls_per_message, max_pending_confirmations, confirmation_timeout_s,
              max_message_length, max_context_messages,
              max_file_size_mb, max_files_per_message, max_pages_per_file, render_dpi,
              trash_min_days, trash_max_days, audit_months, org_deletion_grace_days,
              rate_limit_per_minute, lockout_after_failures, lockout_window_minutes,
              lockout_minutes, session_idle_timeout_minutes, session_max_lifetime_hours
"""


class StoredPlatformLLM(BaseModel):
    """The platform LLM as stored.

    The provider, one model per provider (None: unset) and (GH-242, migration
    0022) the active model's capabilities and the LLM retry limit, whose
    defaults and bounds are the column's. ``max_retries`` is stored in the
    column ``llm_max_retries``.
    """

    model_config = ConfigDict(frozen=True)

    provider: Literal["infomaniak", "vllm", "anthropic", "openai"]
    infomaniak_model: str | None = Field(max_length=200)
    vllm_model: str | None = Field(max_length=200)
    anthropic_model: str | None = Field(max_length=200)
    openai_model: str | None = Field(max_length=200)
    max_input_tokens: int = Field(default=200_000, ge=1000, le=2_000_000)
    image_input: bool = True
    max_retries: int = Field(default=2, ge=0, le=5)


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


class InvalidOrgSettingsError(ValueError):
    """A changed org trash retention is outside the platform's trash bounds (GH-169)."""


class ResidencyConfirmationError(Exception):
    """The residency-org count the route confirmed changed before the write (GH-242).

    Attributes:
        residency_orgs: The count inside the write transaction (a count only).
    """

    def __init__(self, residency_orgs: int) -> None:
        self.residency_orgs = residency_orgs
        super().__init__("The number of organizations with data residency changed.")


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

# GH-169: every org settings response carries the org instructions, so reading
# or changing any org setting needs both capabilities (both the Org Admin's).
_ORG_SETTINGS_CAPABILITIES: Final = (
    Capability.ORG_SETTINGS_MANAGE,
    Capability.ORG_INSTRUCTIONS_MANAGE,
)
# The org_settings fields in the parameter order of _ORG_UPDATE_SQL ($2 on).
_ORG_SETTINGS_FIELDS: Final = (
    *_TOOLS,
    "instructions",
    "session_idle_timeout_minutes",
    "session_max_lifetime_hours",
    "trash_retention_days",
)
# What a missing org_settings row reads as: the column defaults of migrations
# 0013 (every tool on) and 0023.
_ORG_SETTINGS_DEFAULTS: Final = MappingProxyType(
    {
        **ToolsSettings().model_dump(),
        "instructions": "",
        "session_idle_timeout_minutes": sessions.DEFAULT_IDLE_TIMEOUT_MINUTES,
        "session_max_lifetime_hours": sessions.DEFAULT_LIFETIME_HOURS,
        "trash_retention_days": 30,
    }
)
# The org sections whose events name the changed fields only: never a name, a
# language or the instructions (nor their length).
_NAMES_ONLY_ORG_SECTIONS: Final = frozenset({"profile", "instructions"})
_NO_ORG_ROW: Final = "The organization doesn't exist."
_TRASH_BOUNDS_ERROR: Final = "The trash retention must be within the platform's bounds."

# The one in-process cache of the platform row (a single process, #139 §4.6).
_platform_cache: StoredPlatformSettings | None = None
# Bumped when an update replaces the cache: a read that began earlier doesn't
# overwrite the newer value.
_cache_generation: int = 0


def _require(actor: Principal, *capabilities: Capability) -> None:
    """Raise PermissionError unless the actor has every capability (before any query)."""
    if not all(can(actor, capability) for capability in capabilities):
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
                "max_input_tokens": row["max_input_tokens"],
                "image_input": row["image_input"],
                "max_retries": row["llm_max_retries"],
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


# Any (here and in the org helpers below): the stored values are asyncpg
# record values, each of its column's type.
def _org_response(stored: Mapping[str, Any], bounds: PlatformRetention) -> OrgSettingsResponse:
    """The OrgSettingsResponse of an org's stored values (org_settings and organizations).

    The trash retention shown is the stored value clamped into the platform's
    trash bounds, which come along read-only.
    """
    retention = min(
        max(stored["trash_retention_days"], bounds.trash_min_days), bounds.trash_max_days
    )
    return OrgSettingsResponse.model_validate(
        {
            "profile": {
                "display_name": stored["display_name"],
                "default_response_language": stored["default_response_language"],
            },
            "instructions": stored["instructions"],
            "security": {
                "session_idle_timeout_minutes": stored["session_idle_timeout_minutes"],
                "session_max_lifetime_hours": stored["session_max_lifetime_hours"],
            },
            "retention": {
                "trash_retention_days": retention,
                "trash_min_days": bounds.trash_min_days,
                "trash_max_days": bounds.trash_max_days,
            },
            "tools": {tool: stored[tool] for tool in _TOOLS},
            "data_residency": stored["data_residency"],
            "plan": {"seats": stored["seats"], "storage_quota": stored["storage_quota_bytes"]},
        }
    )


async def get_org_settings(pool: asyncpg.Pool, *, actor: Principal) -> OrgSettingsResponse:
    """Return the actor's own org's settings (the column defaults without an org_settings row).

    The effective trash retention is the stored ``trash_retention_days``
    clamped into the platform's trash bounds (``min(max(stored, min_days),
    max_days)``): a stored value may lie outside bounds the Super Admin
    narrowed after it was set. Any later consumer of the stored retention
    (a trash purge job) must apply the same clamp, never the raw column.

    Args:
        pool: The database pool.
        actor: The Org Admin asking.

    Returns:
        The OrgSettingsResponse: the profile (the organizations row), the
        instructions, the session policy, the trash retention (clamped into
        the platform's bounds, which come along) and the tool switches (the
        org_settings row; a missing row reads as the column defaults and
        nothing is written), and the read-only residency and plan.

    Raises:
        PermissionError: Without ``Capability.ORG_SETTINGS_MANAGE`` and
            ``Capability.ORG_INSTRUCTIONS_MANAGE``; no query is issued.
        LookupError: If the org has no organizations row.
    """
    _require(actor, *_ORG_SETTINGS_CAPABILITIES)
    org_id = TenantContext.from_principal(actor).org_id
    org: Record | None = await pool.fetchrow(_ORG_PROFILE_SQL, org_id)
    if org is None:
        raise LookupError(_NO_ORG_ROW)
    settings: Record | None = await pool.fetchrow(_ORG_SETTINGS_SQL, org_id)
    stored = {**(_ORG_SETTINGS_DEFAULTS if settings is None else settings), **org}
    return _org_response(stored, (await current_platform_settings(pool)).retention)


def _given(section: BaseModel | None) -> dict[str, Any]:
    """The values a patch section gives (a null section or field gives none)."""
    return {} if section is None else section.model_dump(exclude_none=True)


def _org_changes(stored: Mapping[str, Any], patch: OrgSettingsPatch) -> dict[str, dict[str, Any]]:
    """Per section (in event order), the given values that differ from the stored ones.

    The display name is compared as the model stripped it, the instructions
    verbatim.
    """
    given = {
        "profile": _given(patch.profile),
        "instructions": {} if patch.instructions is None else {"instructions": patch.instructions},
        "security": _given(patch.security),
        "retention": _given(patch.retention),
        "tools": _given(patch.tools),
    }
    changes: dict[str, dict[str, Any]] = {}
    for section, values in given.items():
        changed = {field: value for field, value in values.items() if stored[field] != value}
        if changed:
            changes[section] = changed
    return changes


async def update_org_settings(
    pool: asyncpg.Pool, *, actor: Principal, patch: OrgSettingsPatch, ip: str | None
) -> OrgSettingsResponse:
    """Change the given settings of the actor's own org; audit each changed section.

    One transaction on one connection: the org's org_settings row is created
    from the defaults if missing and locked, the organizations row is locked,
    and only the values that differ from the stored ones are written (one
    UPDATE per table, the organizations row only for a profile change). A
    changed trash retention outside the platform's trash bounds is refused
    before any write. A changed session policy re-times the org's live
    sessions (``sessions.apply_org_policy``) with the merged policy. Each
    changed section records one ``org.settings_change`` event, in the order
    profile, instructions, security, retention, tools: the profile and
    instructions events name the changed fields only (``{<field>: True}``),
    the others carry ``<field>_old`` / ``<field>_new`` values, and the
    security event adds ``sessions_updated``. A patch that changes nothing
    changes no value and records nothing; it may create the org's missing
    org_settings row from the column defaults (which read the same as no
    row). Only a changed trash retention is checked against the platform's
    bounds: a stored one may lie outside bounds narrowed later, so the
    response clamps it (see ``get_org_settings``).

    Args:
        pool: The database pool.
        actor: The Org Admin changing them.
        patch: The validated settings to change.
        ip: The client address, if known.

    Returns:
        The org's OrgSettingsResponse after the change (as ``get_org_settings``
        reads it).

    Raises:
        PermissionError: Without ``Capability.ORG_SETTINGS_MANAGE`` and
            ``Capability.ORG_INSTRUCTIONS_MANAGE``; no query is issued.
        InvalidOrgSettingsError: If a changed trash retention is outside the
            platform's trash bounds; nothing changes.
        AuditRecordError: If an audit event can't be recorded; nothing
            changes (the sessions included).
    """
    _require(actor, *_ORG_SETTINGS_CAPABILITIES)
    org_id = TenantContext.from_principal(actor).org_id
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute(_ORG_ENSURE_SQL, org_id)
        # The row exists now (its foreign key needs the organizations row):
        # each locking SELECT yields exactly one row.
        (locked,) = await conn.fetch(_ORG_LOCK_SQL, org_id)
        (org,) = await conn.fetch(_ORG_PROFILE_LOCK_SQL, org_id)
        bounds = (await current_platform_settings(conn)).retention
        old = {**locked, **org}
        changes = _org_changes(old, patch)
        trash = changes.get("retention", {}).get("trash_retention_days")
        if trash is not None and not bounds.trash_min_days <= trash <= bounds.trash_max_days:
            raise InvalidOrgSettingsError(_TRASH_BOUNDS_ERROR)
        if not changes:
            return _org_response(old, bounds)
        new = dict(old)
        settings = {
            field: value
            for section, changed in changes.items()
            if section != "profile"
            for field, value in changed.items()
        }
        if settings:
            (row,) = await conn.fetch(
                _ORG_UPDATE_SQL, org_id, *(settings.get(field) for field in _ORG_SETTINGS_FIELDS)
            )
            new |= row
        if profile := changes.get("profile"):
            await conn.execute(
                _ORG_PROFILE_UPDATE_SQL,
                org_id,
                profile.get("display_name"),
                profile.get("default_response_language"),
            )
            new |= profile
        sessions_updated: int | None = None
        if "security" in changes:
            sessions_updated = await sessions.apply_org_policy(
                conn,
                org_id,
                sessions.SessionPolicy(
                    idle_timeout_minutes=new["session_idle_timeout_minutes"],
                    max_lifetime_hours=new["session_max_lifetime_hours"],
                ),
            )
        actor_kind, actor_user_id = audit_events.actor_columns(actor)
        # _org_changes keeps the event order: profile, instructions, security,
        # retention, tools.
        for section, changed in changes.items():
            await audit_events.record(
                conn,
                action=AuditAction.ORG_SETTINGS_CHANGE,
                actor_kind=actor_kind,
                actor_user_id=actor_user_id,
                org_id=org_id,
                target_type=TargetType.ORGANIZATION,
                target_ids=(org_id,),
                ip=ip,
                metadata=_event_metadata(
                    old,
                    changed,
                    names_only=section in _NAMES_ONLY_ORG_SECTIONS,
                    sessions_updated=sessions_updated if section == "security" else None,
                ),
            )
    return _org_response(new, bounds)


async def org_residency(executor: sessions.Executor, tenant: TenantContext) -> bool:
    """Return whether the tenant org's data residency policy is on (GH-162).

    No capability check: an internal read (a chat run's tool policy, the
    OAuth routes). Only the tenant's org row is read; nothing is written.

    Args:
        executor: The pool, or a connection.
        tenant: The org scope.

    Returns:
        The org's ``data_residency`` flag; True when the org row is missing
        (fail closed: the Google and Microsoft tools stay off).
    """
    row: Record | None = await executor.fetchrow(_ORG_RESIDENCY_SQL, tenant.org_id)
    return residency_from_value(None if row is None else row["data_residency"])


def residency_from_value(data_residency: bool | None) -> bool:
    """Return the residency flag of a stored ``organizations.data_residency`` value.

    Pure: shared by ``org_residency`` and the send path's turn setup (GH-244).

    Args:
        data_residency: The stored value, or None when the org row is missing.

    Returns:
        False only for a stored False; True otherwise (fail closed: a missing
        org row keeps the Google and Microsoft tools off).
    """
    return data_residency is not False


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
    return switches_from_row(row)


def switches_from_row(row: Record | None) -> dict[str, bool]:
    """Return an org's tool switches from its org_settings columns (named by tool).

    Pure: shared by ``org_tools_enabled`` and the send path's turn setup
    (GH-244), whose LEFT JOIN gives a missing row as NULL switch columns.

    Args:
        row: A row with one column per tool name (other columns are
            ignored), or None.

    Returns:
        Every tool name mapped to whether the org enabled its service; every
        tool on for a missing row (None, or every switch NULL: the columns are
        NOT NULL, so only a LEFT JOIN without an org_settings row gives that).

    Raises:
        ValidationError: For any other non-boolean value (``ToolsSettings`` is
            strict), so a broken row never switches a service on.
    """
    if row is None or all(row[tool] is None for tool in _TOOLS):
        return ToolsSettings().model_dump()
    return ToolsSettings.model_validate({tool: row[tool] for tool in _TOOLS}).model_dump()


async def load_prompt_context(executor: sessions.Executor, tenant: TenantContext) -> PromptContext:
    """Return the tenant user's prompt inputs, for a chat run's system prompt (GH-170).

    One read of the user's row (response language, timezone, personal
    instructions), their org's row (default response language) and the org's
    settings row (instructions). No capability check: an internal read (every
    member's run needs it). Only a live user of the tenant's org matches;
    nothing is written or logged.

    Args:
        executor: The pool, or a connection.
        tenant: The org scope and user of the run.

    Returns:
        The ``PromptContext``; ``PromptContext()`` when the user is deleted,
        unknown or not in the tenant's org. A missing org_settings row reads as
        no org instructions.
    """
    row: Record | None = await executor.fetchrow(_PROMPT_CONTEXT_SQL, tenant.user_id, tenant.org_id)
    return prompt_context_from_row(row)


def prompt_context_from_row(row: Record | None) -> PromptContext:
    """Return a run's ``PromptContext`` from its prompt-input columns.

    Pure: shared by ``load_prompt_context`` and the send path's turn setup
    (GH-244). Nothing is logged: the instructions are content.

    Args:
        row: A row with ``org_instructions``, ``personal_instructions``,
            ``response_language``, ``default_response_language`` and
            ``timezone`` (other columns are ignored), or None when no live
            user of the tenant's org matched.

    Returns:
        The ``PromptContext``; ``PromptContext()`` for None. NULL
        instructions read as none.
    """
    if row is None:
        return PromptContext()
    return PromptContext(
        org_instructions=row["org_instructions"] or "",
        personal_instructions=row["personal_instructions"] or "",
        response_language=row["response_language"],
        default_response_language=row["default_response_language"],
        timezone=row["timezone"],
    )


async def count_residency_orgs(executor: sessions.Executor) -> int:
    """Return how many organizations have their data residency policy on (GH-242).

    Every status counts. No capability check: the platform settings route
    checks ``Capability.PLATFORM_DEFAULTS_MANAGE`` first, and
    ``update_platform_settings`` counts again inside its write. One read;
    nothing is written.

    Args:
        executor: The pool, or a connection.

    Returns:
        The number of organizations whose ``data_residency`` is on.
    """
    row: Record = await executor.fetchrow(_RESIDENCY_ORGS_SQL)
    return int(row["residency_orgs"])


async def seed_platform_settings(pool: asyncpg.Pool, config: AppConfig) -> None:
    """Store config.yaml's llm and limits in the platform row (one upsert statement).

    The first boot stores both; a later boot re-applies the llm (provider,
    the four models, an empty model stored as NULL, and the GH-242 model
    capabilities ``max_input_tokens`` and ``image_input``) and keeps the
    stored limits. The LLM retry limit is never written here: the first boot
    takes the column default (2) and a later boot keeps the stored value.

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
        llm.max_input_tokens,
        llm.image_input,
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


async def session_policy_for(
    executor: sessions.Executor, kind: str, org_id: UUID | None = None
) -> sessions.SessionPolicy:
    """Return the policy a new session of an account gets.

    Args:
        executor: The pool or a connection.
        kind: The account's kind: "member" (their org's stored policy, read
            with one org_settings query; GH-169) or "super_admin" (the stored
            platform policy, read only on a cache miss).
        org_id: The member's org (a bind parameter); ignored for a Super
            Admin.

    Returns:
        The SessionPolicy, read when called. A member's org without an
        org_settings row gets ``SessionPolicy()`` (the column defaults, 60
        minutes / 12 hours).

    Raises:
        ValueError: For a member without an org id, or any other kind (there
            is no default policy); no query is issued.
        RuntimeError: If a Super Admin's policy can't be read (no platform row).
    """
    if kind == "member":
        if org_id is None:
            raise ValueError(_NO_SESSION_POLICY)
        row: Record | None = await executor.fetchrow(_MEMBER_POLICY_SQL, org_id)
        if row is None:
            return sessions.SessionPolicy()
        return sessions.SessionPolicy(
            idle_timeout_minutes=row["session_idle_timeout_minutes"],
            max_lifetime_hours=row["session_max_lifetime_hours"],
        )
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
        fields, ``llm.max_input_tokens``, ``llm.image_input`` and the five
        limits come from ``stored`` (both sections validated again). Every
        other llm field (timeout, vLLM URL and context length, response
        tokens) and every other section stay. The stored retry limit is no
        ``LLMConfig`` field and is not overlaid (a run reads it from the
        stored settings).
    """
    # The retry limit is no LLMConfig field.
    overlay = stored.llm.model_dump(exclude={"max_retries"})
    llm = LLMConfig.model_validate({**config.llm.model_dump(), **overlay})
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


# Any: the stored values of a section (a platform model dump or org record values).
def _event_metadata(
    old: Mapping[str, Any],
    changed: Mapping[str, MetadataValue],
    *,
    names_only: bool,
    sessions_updated: int | None,
) -> dict[str, MetadataValue]:
    """The content-free metadata of one changed section's settings-change event.

    ``names_only`` (the platform llm, the org profile and instructions): the
    changed field names mapped to True, never a value. Otherwise
    ``<field>_old`` / ``<field>_new`` per changed field, plus
    ``sessions_updated`` (a count) when given.
    """
    if names_only:
        return dict.fromkeys(changed, True)
    metadata: dict[str, MetadataValue] = {}
    for field, value in changed.items():
        metadata |= {f"{field}_old": old[field], f"{field}_new": value}
    if sessions_updated is not None:
        metadata["sessions_updated"] = sessions_updated
    return metadata


async def update_platform_settings(
    pool: asyncpg.Pool,
    *,
    actor: Principal,
    patch: PlatformSettingsPatch,
    ip: str | None,
    expected_residency_orgs: int | None = None,
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

    GH-242: when the route confirmed a switch to a non-Swiss provider, it
    passes the residency-org count it confirmed. The count is read again
    right after the row lock, in this transaction: if it changed, nothing is
    written. A residency change that commits after that read never reads
    the provider, so it is as if it came after the switch (the per-run guard
    blocks that org's chats).

    Args:
        pool: The database pool.
        actor: The Super Admin changing them.
        patch: The validated sections to change.
        ip: The client address, if known.
        expected_residency_orgs: The residency-org count the route confirmed,
            or None when the patch needs no confirmation (nothing is counted).

    Returns:
        The StoredPlatformSettings after the change (the new cache value).

    Raises:
        PermissionError: Without ``Capability.PLATFORM_DEFAULTS_MANAGE``; no
            query is issued.
        InvalidPlatformSettingsError: If the merged trash minimum exceeds the
            maximum; nothing changes.
        AuditRecordError: If an audit event can't be recorded; nothing
            changes (the sessions and the cache included).
        ResidencyConfirmationError: If ``expected_residency_orgs`` no longer
            matches the count; nothing changes.
        RuntimeError: If there is no platform row.
    """
    global _platform_cache, _cache_generation
    _require(actor, Capability.PLATFORM_DEFAULTS_MANAGE)
    async with pool.acquire() as conn, conn.transaction():
        stored = await _fetch_platform(conn, _PLATFORM_LOCK_SQL)
        if expected_residency_orgs is not None:
            residency_orgs = await count_residency_orgs(conn)
            if residency_orgs != expected_residency_orgs:
                raise ResidencyConfirmationError(residency_orgs)
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
                    getattr(stored, section).model_dump(),
                    changed,
                    names_only=section == "llm",
                    sessions_updated=sessions_updated if section == "security" else None,
                ),
            )
    _cache_generation += 1
    _platform_cache = updated
    return updated
