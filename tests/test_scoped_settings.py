"""Tests for admino.scoped_settings — the platform, org and user settings scopes
(GH-159), the cached, editable platform defaults (GH-160) and the task-done pings
and "reset my settings" of the Settings page (GH-35).

The old key/value ``settings`` table is dropped (migration 0013). Each value
now has an owner: ``user_settings`` (each user: theme and notifications),
``org_settings`` (each org: the enabled tool services) and one
``platform_settings`` row (the Super Admin: the LLM provider and models, the
limits and, since migration 0014, the files, retention and security
defaults). ``admino.scoped_settings`` is the service behind the three routes,
the startup and every consumer of a platform default.

What these tests pin down (the GH-159 and GH-160 implementation contracts):
- Surface: ``get_user_settings`` / ``update_user_settings`` /
  ``get_org_settings`` / ``update_org_settings`` / ``all_orgs_tools_gate`` /
  ``seed_platform_settings`` / ``load_platform_settings`` /
  ``current_platform_settings`` / ``session_policy_for`` /
  ``update_platform_settings`` are coroutines, ``apply_platform_settings`` is
  pure; ``actor``, ``patch`` and ``ip`` are keyword-only;
  ``update_platform_llm`` is gone (GH-160); ``InvalidPlatformSettingsError``
  is a ValueError; ``StoredPlatformSettings`` (``llm``, ``limits``,
  ``files``, ``retention``, ``security``, the last three defaulting to the
  table defaults) is importable from the module; the module imports only
  access, tenancy, audit_events, models, config and sessions from admino.
- The cache (GH-160): ``current_platform_settings`` answers from
  ``_platform_cache`` without a query; on a miss it reads the row once (one
  fetchrow, through a pool or a connection) and caches it; no row is a
  RuntimeError and the cache stays empty. ``load_platform_settings`` always
  reads the row (every column) and replaces the cache.
- ``update_platform_settings`` (GH-160, replacing ``update_platform_llm``):
  ``platform.defaults.manage`` before any statement; one transaction that
  locks the row, writes only the changed fields in one UPDATE (the patch
  merged into the stored row), applies a changed session policy to every
  open Super Admin session (``sessions.apply_super_admin_policy``, members
  untouched, an old or idle session ends at once) and records one
  ``platform.settings_change`` event per changed section in the order llm,
  limits, files, retention, security (llm: field names only; the others:
  ``<field>_old`` / ``<field>_new`` ints, security adding
  ``sessions_updated`` iff a session field changed). Retention is validated
  on the merged values (trash min <= max) before any write
  (``InvalidPlatformSettingsError``). A no-op writes nothing; an audit failure
  rolls the row and the sessions back and keeps the cache; the cache takes
  the new settings only after the commit and equals the return value.
- ``session_policy_for``: "member" is ``sessions.DEFAULT_ORG_SESSION_POLICY``
  (read at call time, no query), "super_admin" is the stored security
  policy (cached), anything else a ValueError without a query.
- Authorization through ``access.can`` before any statement:
  ``account.manage`` for the user scope (every role, the Super Admin
  included), ``org.settings.manage`` for the org scope (Org Admin only),
  ``platform.defaults.manage`` for the platform LLM (Super Admin only). A
  refused actor gets ``PermissionError`` and nothing is read or written.
- Scoping: a user's row is always the actor's own (``user_id`` a bind
  parameter); an org's row is always the principal's own org. Another user's
  or org's id is never bound.
- A missing user or org row reads as the defaults (theme light,
  notifications on, every tool on) and a read writes nothing. Updates change
  only the given fields (creating the row when it's missing) and return the
  stored result.
- ``update_org_settings``: one transaction that locks the org's row
  (``FOR UPDATE``), then records ``org.settings_change`` (the member actor,
  the org, the org as target, the client IP, one ``<tool>_old`` /
  ``<tool>_new`` bool pair per CHANGED tool). A no-op records nothing; an
  audit failure raises ``AuditRecordError`` and rolls the change back.
- ``update_platform_settings`` with an llm patch: the same for
  ``platform.settings_change`` (actor super_admin, no org, no target,
  metadata ``{<changed field>: True}`` with field names only, never a
  provider or model value).
- ``all_orgs_tools_gate``: one aggregate statement; a tool is off when ANY
  org turned it off; no rows means all seven on.
- ``seed_platform_settings``: one upsert; the first boot stores config.yaml's
  llm and limits; later boots re-apply the llm (an empty model is NULL) and
  keep the stored limits. ``load_platform_settings`` raises RuntimeError
  without a row. ``apply_platform_settings`` overlays the stored provider,
  models and limits onto the config and nothing else.
- The acceptance criterion "each scope is seeded with defaults after the
  migration": migration 0013's own INSERT statements run against the fake,
  then the platform seed; every org, every user and the platform have their
  defaults.
- The org purge removes an org's org_settings and its users' user_settings
  (ON DELETE CASCADE).
- No email, name or model name in any log record; no provider or model value
  in any audit row.
- GH-35, task-done pings: ``user_settings.notifications_task_done`` (default
  false, migration 0015) is ``notifications.task_done`` of the response. A
  read returns the stored value (False without a row) and writes nothing; a
  patch changes only the fields it gives (a task_done-only patch keeps the
  theme and ``enabled``, a theme or ``enabled`` patch keeps task_done:
  neither switch is a master of the other); a later read (the "reload")
  returns the stored value; another user's row is never touched.
- GH-35, ``reset_user_settings(pool, *, actor)``: ``account.manage`` (every
  role) before any statement; reverts only the actor's own ``user_settings``
  row (afterwards absent or exactly the column defaults; the actor's id a
  bind parameter, the statements constants) and returns the defaults. It is
  idempotent, records no audit event, logs no email or name, and every
  statement it issues names ``user_settings`` and no other table: other
  users' rows, every org_settings row, the platform row, the actor's users
  row (languages, name, email), sessions and audit events stay as they were.

All database calls go to tests/db_fakes.FakeDb (which models migration
0013's columns, defaults, CHECKs, keys and cascades). ``admino.scoped_settings``
is imported per test through the ``svc`` fixture, so each test fails on its
own until the module exists.

Security notes:
- Least privilege: an Editor can't change org settings, an Org Admin can't
  change any platform default, and the Super Admin reaches no org's settings.
- Fail closed: every org or platform change shares one transaction with its
  audit events (and the Super Admin sessions it re-times); an invalid merge
  writes nothing.
- No content in audit rows or logs: IDs, bools and field names only.
"""

from __future__ import annotations

import ast
import copy
import inspect
import json
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

import admino.database as db_mod
from admino.access import Capability, Principal
from admino.audit_events import AuditRecordError
from admino.config import AppConfig
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, TOOL_NAMES, FakeDb, plain

if TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP = "203.0.113.7"
_MIGRATION = "0013_settings_scopes.sql"
_ALL_ON: dict[str, bool] = dict.fromkeys(TOOL_NAMES, True)
# GH-35: the notifications gain task_done (default off) — the response shape.
_USER_DEFAULTS = {
    "appearance": {"theme": "light"},
    "notifications": {"enabled": True, "task_done": False},
}
# The user_settings column defaults (migrations 0013 and 0015), without the key and
# updated_at: what a reset row may hold.
_USER_COLUMN_DEFAULTS: dict[str, Any] = {
    "theme": "light",
    "notifications_enabled": True,
    "notifications_task_done": False,
}
# A user_settings row where every setting differs from its default.
_CUSTOM_USER_ROW: dict[str, Any] = {
    "theme": "dark",
    "notifications_enabled": False,
    "notifications_task_done": True,
}
# Rows where exactly one setting differs from its default (a reset reverts each one).
_ONE_CUSTOM_SETTING = [
    pytest.param({"theme": "dark"}, id="theme-dark"),
    pytest.param({"theme": "system"}, id="theme-system"),
    pytest.param({"notifications_enabled": False}, id="enabled-off"),
    pytest.param({"notifications_task_done": True}, id="task_done-on"),
]
_ROLES = ["super_admin", "org_admin", "editor", "viewer"]
_MODEL_MARKER = "Zephyrmarker/Model-77"
_EMAIL_MARKER = "zephyr.marker.person@example.ch"
_NAME_MARKER = "Zephyrmarker Person"
_OLD = datetime(2025, 1, 2, 3, 4, 5, tzinfo=UTC)
_LLM_FIELDS = ("provider", "infomaniak_model", "vllm_model", "anthropic_model", "openai_model")
_LIMIT_FIELDS = (
    "max_tool_calls_per_message",
    "max_pending_confirmations",
    "confirmation_timeout_s",
    "max_message_length",
    "max_context_messages",
)
# The limits _platform() stores (GH-159).
_STORED_LIMITS: dict[str, int] = {
    "max_tool_calls_per_message": 7,
    "max_pending_confirmations": 4,
    "confirmation_timeout_s": 120,
    "max_message_length": 5000,
    "max_context_messages": 30,
}
# GH-160: the sections of migration 0014 and their defaults (the issue's Decisions).
_DEFAULT_SECTIONS = ("files", "retention", "security")
_SECTION_DEFAULTS: dict[str, dict[str, int]] = {
    "files": {
        "max_file_size_mb": 50,
        "max_files_per_message": 10,
        "max_pages_per_file": 100,
        "render_dpi": 150,
    },
    "retention": {
        "trash_min_days": 0,
        "trash_max_days": 90,
        "audit_months": 12,
        "org_deletion_grace_days": 30,
    },
    "security": {
        "rate_limit_per_minute": 20,
        "lockout_after_failures": 10,
        "lockout_window_minutes": 15,
        "lockout_minutes": 15,
        "session_idle_timeout_minutes": 60,
        "session_max_lifetime_hours": 12,
    },
}
# What _platform() stores in each int section.
_STORED_SECTIONS: dict[str, dict[str, int]] = {"limits": _STORED_LIMITS, **_SECTION_DEFAULTS}
# Non-default values (inside the bounds, trash min <= max) for every GH-160 column.
_CUSTOM_SECTIONS: dict[str, dict[str, int]] = {
    "files": {
        "max_file_size_mb": 200,
        "max_files_per_message": 20,
        "max_pages_per_file": 500,
        "render_dpi": 300,
    },
    "retention": {
        "trash_min_days": 7,
        "trash_max_days": 60,
        "audit_months": 24,
        "org_deletion_grace_days": 14,
    },
    "security": {
        "rate_limit_per_minute": 90,
        "lockout_after_failures": 5,
        "lockout_window_minutes": 30,
        "lockout_minutes": 45,
        "session_idle_timeout_minutes": 120,
        "session_max_lifetime_hours": 24,
    },
}
_CUSTOM_COLUMNS: dict[str, int] = {
    column: value for section in _CUSTOM_SECTIONS.values() for column, value in section.items()
}
# (section, patch, {changed field: (old, new)}) against _platform(): each patch also
# repeats one stored value, which is no change.
_SECTION_CHANGES = [
    pytest.param(
        "limits",
        {
            "max_tool_calls_per_message": 25,
            "max_pending_confirmations": 4,
            "confirmation_timeout_s": 900,
        },
        {"max_tool_calls_per_message": (7, 25), "confirmation_timeout_s": (120, 900)},
        id="limits",
    ),
    pytest.param(
        "files",
        {"max_file_size_mb": 200, "render_dpi": 150, "max_pages_per_file": 1000},
        {"max_file_size_mb": (50, 200), "max_pages_per_file": (100, 1000)},
        id="files",
    ),
    pytest.param(
        "retention",
        {"audit_months": 24, "org_deletion_grace_days": 30, "trash_min_days": 7},
        {"audit_months": (12, 24), "trash_min_days": (0, 7)},
        id="retention",
    ),
    pytest.param(
        "security",
        {"rate_limit_per_minute": 60, "lockout_minutes": 15, "lockout_after_failures": 5},
        {"rate_limit_per_minute": (20, 60), "lockout_after_failures": (10, 5)},
        id="security",
    ),
]
# One change per int section (security: a session field).
_ONE_CHANGE: dict[str, dict[str, int]] = {
    "limits": {"max_context_messages": 50},
    "files": {"render_dpi": 300},
    "retention": {"audit_months": 24},
    "security": {"session_idle_timeout_minutes": 30},
}
_SESSION_POLICY_CHANGE = {"session_idle_timeout_minutes": 30, "session_max_lifetime_hours": 4}
_ORG_FUNCTIONS = ["get_org_settings", "update_org_settings"]
_USER_FUNCTIONS = ["get_user_settings", "update_user_settings", "reset_user_settings"]
_CAPABILITIES: dict[str, Capability] = {
    "get_user_settings": Capability.ACCOUNT_MANAGE,
    "update_user_settings": Capability.ACCOUNT_MANAGE,
    # GH-35: "reset my settings" is the user scope too (every role).
    "reset_user_settings": Capability.ACCOUNT_MANAGE,
    "get_org_settings": Capability.ORG_SETTINGS_MANAGE,
    "update_org_settings": Capability.ORG_SETTINGS_MANAGE,
    "update_platform_settings": Capability.PLATFORM_DEFAULTS_MANAGE,
}
# (function, role) pairs that must be refused before any statement.
_REFUSED = [
    *(
        pytest.param(name, role, id=f"{name}-{role}")
        for name in _ORG_FUNCTIONS
        for role in ("editor", "viewer", "super_admin")
    ),
    *(
        pytest.param("update_platform_settings", role, id=f"update_platform_settings-{role}")
        for role in ("org_admin", "editor", "viewer")
    ),
]
_ALLOWED = [
    *(pytest.param(name, role, id=f"{name}-{role}") for name in _USER_FUNCTIONS for role in _ROLES),
    *(pytest.param(name, "org_admin", id=f"{name}-org_admin") for name in _ORG_FUNCTIONS),
    pytest.param(
        "update_platform_settings", "super_admin", id="update_platform_settings-super_admin"
    ),
]


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def svc() -> ModuleType:
    """admino.scoped_settings, imported per test so each test fails on its own until it
    exists."""
    from admino import scoped_settings

    return scoped_settings


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database with two active orgs."""
    fake = FakeDb()
    fake.add_org(ORG_ID)
    fake.add_org(OTHER_ORG_ID)
    return fake


def _principal(db: FakeDb, user_id: uuid.UUID) -> Principal:
    """The Principal a resolved session of this stored account would carry."""
    account = db.users[user_id]
    if account["kind"] == "super_admin":
        return Principal(user_id=user_id, kind="super_admin")
    return Principal(user_id=user_id, kind="member", org_id=account["org_id"], role=account["role"])


def _actor(db: FakeDb, role: str, org_id: uuid.UUID = ORG_ID, **fields: Any) -> Principal:
    """A stored account with this role (or a Super Admin) and its Principal."""
    if role == "super_admin":
        return _principal(db, db.add_account(kind="super_admin", role=None, **fields))
    return _principal(db, db.add_account(role=role, org_id=org_id, **fields))


def _user_patch(body: dict[str, Any]) -> Any:
    from admino.models import UserSettingsPatch

    return UserSettingsPatch.model_validate(body)


def _org_patch(**tools: bool) -> Any:
    from admino.models import OrgSettingsPatch

    return OrgSettingsPatch.model_validate({"tools": tools})


def _settings_patch(**sections: dict[str, Any]) -> Any:
    """A PlatformSettingsPatch of these sections (llm, limits, files, retention, security)."""
    from admino.models import PlatformSettingsPatch

    return PlatformSettingsPatch.model_validate(sections)


def _llm_patch(**fields: str) -> Any:
    """A PlatformSettingsPatch that names only these llm fields."""
    return _settings_patch(llm=fields)


def _config(
    *, llm: dict[str, Any] | None = None, limits: dict[str, int] | None = None
) -> AppConfig:
    """A real AppConfig: Anthropic by default, with every provider's model set."""
    llm_section: dict[str, Any] = {
        "provider": "anthropic",
        "anthropic_model": "claude-sonnet-4-6",
        "openai_model": "gpt-4o",
        "infomaniak_model": "Qwen/Qwen3.5-397B-A17B-FP8",
        "vllm_model": "Qwen/Qwen3-4B-Instruct-2507",
        "timeout_s": 77,
        "vllm_base_url": "http://vllm-test:8000/v1",
        "vllm_max_model_len": 4096,
        "max_response_tokens": 1234,
    }
    llm_section.update(llm or {})
    return AppConfig.model_validate(
        {
            "server": {
                "host": "127.0.0.1",
                "port": 8123,
                "public_url": "https://admino.example.ch",
            },
            "llm": llm_section,
            "limits": limits or {},
            "log_level": "WARNING",
        }
    )


def _stored(svc: ModuleType, **overrides: Any) -> Any:
    """A StoredPlatformSettings: OpenAI with its model, the others NULL but vllm; limits
    7/4/120/5000/30 unless overridden."""
    llm = {
        "provider": "openai",
        "infomaniak_model": None,
        "vllm_model": "org/served-model",
        "anthropic_model": None,
        "openai_model": "gpt-4.1",
    }
    limits = {
        "max_tool_calls_per_message": 7,
        "max_pending_confirmations": 4,
        "confirmation_timeout_s": 120,
        "max_message_length": 5000,
        "max_context_messages": 30,
    }
    llm.update(overrides.pop("llm", {}))
    limits.update(overrides.pop("limits", {}))
    # GH-160: files / retention / security only when given (the defaults otherwise).
    sections = {name: overrides.pop(name) for name in _DEFAULT_SECTIONS if name in overrides}
    assert not overrides
    return svc.StoredPlatformSettings.model_validate({"llm": llm, "limits": limits, **sections})


def _platform(db: FakeDb, **columns: Any) -> dict[str, Any]:
    """The platform row: Anthropic with its model, OpenAI's set, limits 7/4/120/5000/30."""
    values: dict[str, Any] = {
        "llm_provider": "anthropic",
        "anthropic_model": "claude-sonnet-4-6",
        "openai_model": "gpt-4o",
        "infomaniak_model": "Qwen/Qwen3.5-397B-A17B-FP8",
        "vllm_model": "Qwen/Qwen3-4B-Instruct-2507",
        "max_tool_calls_per_message": 7,
        "max_pending_confirmations": 4,
        "confirmation_timeout_s": 120,
        "max_message_length": 5000,
        "max_context_messages": 30,
    }
    values.update(columns)
    return db.add_platform_settings(**values)


async def _invoke(svc: ModuleType, db: FakeDb, name: str, actor: Principal) -> Any:
    """Call one of the authorized functions with a valid argument set."""
    pool = db.pool
    if name == "get_user_settings":
        return await svc.get_user_settings(pool, actor=actor)
    if name == "update_user_settings":
        return await svc.update_user_settings(
            pool, actor=actor, patch=_user_patch({"appearance": {"theme": "dark"}})
        )
    if name == "reset_user_settings":
        return await svc.reset_user_settings(pool, actor=actor)
    if name == "get_org_settings":
        return await svc.get_org_settings(pool, actor=actor)
    if name == "update_org_settings":
        return await svc.update_org_settings(
            pool, actor=actor, patch=_org_patch(gmail=False), ip=_IP
        )
    assert name == "update_platform_settings"
    return await svc.update_platform_settings(
        pool, actor=actor, patch=_llm_patch(provider="openai"), ip=_IP
    )


def _state(db: FakeDb) -> dict[str, Any]:
    """A deep copy of the tables these functions may touch, for "nothing changed" checks."""
    return copy.deepcopy(
        {
            "users": db.users,
            "orgs": db.orgs,
            "platform_settings": db.platform_settings,
            "org_settings": db.org_settings,
            "user_settings": db.user_settings,
            "audit": db.audit,
        }
    )


def _one(items: list[Any]) -> Any:
    assert len(items) == 1, items
    return items[0]


def _bound(db: FakeDb, value: uuid.UUID) -> bool:
    """True when any recorded statement bound this id (as a UUID or its string)."""
    for call in db.calls:
        for arg in call.args:
            if isinstance(arg, uuid.UUID) and plain(arg) == value:
                return True
            if isinstance(arg, str) and arg == str(value):
                return True
    return False


def _tools(result: Any) -> dict[str, bool]:
    """The tools of an OrgSettingsResponse as a plain dict."""
    return {tool: getattr(result.tools, tool) for tool in TOOL_NAMES}


def _user_values(result: Any) -> tuple[str, bool]:
    return result.appearance.theme, result.notifications.enabled


def _user_all(result: Any) -> tuple[str, bool, bool]:
    """(theme, enabled, task_done) of a UserSettingsResponse (GH-35)."""
    return result.appearance.theme, result.notifications.enabled, result.notifications.task_done


def _user_row(db: FakeDb, user_id: uuid.UUID) -> tuple[str, bool, bool]:
    """(theme, notifications_enabled, notifications_task_done) of a stored user_settings row."""
    row = db.user_settings[user_id]
    return row["theme"], row["notifications_enabled"], row["notifications_task_done"]


def _custom_user_row(db: FakeDb, user_id: uuid.UUID) -> dict[str, Any]:
    """Store a user_settings row where every setting differs from its default."""
    return db.add_user_settings(user_id, **_CUSTOM_USER_ROW)


def _assert_reset_row(db: FakeDb, user_id: uuid.UUID) -> None:
    """After a reset (GH-35) the user's row is gone or holds exactly the column defaults."""
    row = db.user_settings.get(user_id)
    if row is None:
        return
    values = {
        column: value for column, value in row.items() if column not in {"user_id", "updated_at"}
    }
    assert values == _USER_COLUMN_DEFAULTS


def _migration_tables() -> set[str]:
    """Every table a shipped migration creates (lowercase)."""
    pattern = re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?(\w+)", re.IGNORECASE)
    tables: set[str] = set()
    for path in sorted(db_mod._MIGRATIONS_DIR.glob("*.sql")):
        tables |= {name.lower() for name in pattern.findall(path.read_text(encoding="utf-8"))}
    return tables


def _tables_named(sql: str, tables: set[str]) -> set[str]:
    """The tables whose name appears as a whole word in this (normalized) SQL."""
    return {table for table in tables if re.search(rf"\b{table}\b", sql)}


def _settings_calls(db: FakeDb, table: str) -> list[Any]:
    return [call for call in db.calls if re.search(rf"\b{table}\b", call.normalized)]


def _assert_locked_in_one_transaction(db: FakeDb, table: str) -> None:
    """Every statement on ``table`` and the audit insert ran in one committed transaction,
    and the row was locked (FOR UPDATE) before the audit event was written."""
    calls = _settings_calls(db, table)
    audit = db.matching(r"^insert into audit_events\b")
    assert calls, f"no statement on {table}"
    transactions = {call.tx for call in [*calls, *audit]}
    assert len(transactions) == 1 and None not in transactions, transactions
    (tx,) = transactions
    assert (tx, "commit") in db.transactions
    locks = [
        i for i, call in enumerate(db.calls) if call in calls and "for update" in call.normalized
    ]
    assert locks, f"{table} was never locked FOR UPDATE"
    if audit:
        assert locks[0] < db.calls.index(audit[0])


def _uuid(value: Any) -> uuid.UUID | None:
    return None if value is None else plain(value)


def _log_text(caplog: pytest.LogCaptureFixture) -> str:
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(formatter.format(record) for record in caplog.records)


def _section(stored: Any, name: str) -> dict[str, Any]:
    """One section of a StoredPlatformSettings as a plain dict."""
    return dict(getattr(stored, name).model_dump())


def _without_updated_at(row: dict[str, Any] | None) -> dict[str, Any]:
    """A platform_settings row (it must exist) without its updated_at."""
    assert row is not None
    return {column: value for column, value in row.items() if column != "updated_at"}


def _platform_updates(db: FakeDb) -> list[Any]:
    """The UPDATE platform_settings statements."""
    return db.matching(r"^update platform_settings\b")


def _session_updates(db: FakeDb) -> list[Any]:
    """The UPDATE sessions statements (the Super Admin policy statement among them)."""
    return db.matching(r"^update sessions\b")


def _old_new(changed: dict[str, tuple[int, int]]) -> dict[str, int]:
    """The audit metadata of changed int fields: ``<field>_old`` / ``<field>_new``."""
    metadata: dict[str, int] = {}
    for field, (old, new) in changed.items():
        metadata[f"{field}_old"] = old
        metadata[f"{field}_new"] = new
    return metadata


def _new_values(changed: dict[str, tuple[int, int]]) -> dict[str, int]:
    return {field: new for field, (_, new) in changed.items()}


def _super_admin_sessions(db: FakeDb, actor: Principal) -> tuple[list[str], str]:
    """Open three Super Admin sessions (the actor's and two of another Super Admin) and
    one member session; return the Super Admin tokens and the member token."""
    other = db.add_account(kind="super_admin", role=None)
    member = db.add_account(role="org_admin")
    tokens = [db.open_session(actor.user_id), db.open_session(other), db.open_session(other)]
    return tokens, db.open_session(member)


class _CanSpy:
    """Wraps admino.access.can wherever the service looks it up; records the capabilities
    asked for and refuses the chosen ones."""

    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        svc: ModuleType,
        deny: frozenset[Capability] = frozenset(),
    ) -> None:
        from admino import access

        real = access.can
        self.capabilities: list[Capability] = []

        def spy(principal: Any, capability: Any) -> bool:
            self.capabilities.append(capability)
            if capability in deny:
                return False
            return real(principal, capability)

        monkeypatch.setattr(access, "can", spy)
        if hasattr(svc, "can"):
            monkeypatch.setattr(svc, "can", spy)


def _migration_inserts() -> list[str]:
    """The INSERT statements of the shipped migration 0013, comments removed."""
    raw = (db_mod._MIGRATIONS_DIR / _MIGRATION).read_text(encoding="utf-8")
    sql = re.sub(r"--[^\n]*", " ", raw)
    return [
        statement.strip()
        for statement in sql.split(";")
        if re.match(r"\s*insert\s+into\b", statement, re.IGNORECASE)
    ]


# ---------------------------------------------------------------------------
# 1. The module's surface
# ---------------------------------------------------------------------------


class TestModuleSurface:
    """Coroutines, keyword-only arguments, the StoredPlatformSettings model, the imports."""

    @pytest.mark.parametrize(
        "name",
        [
            "get_user_settings",
            "update_user_settings",
            "get_org_settings",
            "update_org_settings",
            "all_orgs_tools_gate",
            "seed_platform_settings",
            "load_platform_settings",
            "update_platform_settings",
            "current_platform_settings",
            "session_policy_for",
            "reset_user_settings",
        ],
    )
    def test_scoped_settings_function_is_a_coroutine(self, svc: ModuleType, name: str) -> None:
        assert inspect.iscoroutinefunction(getattr(svc, name))

    def test_scoped_settings_update_platform_llm_is_gone(self, svc: ModuleType) -> None:
        """GH-160: update_platform_settings replaces the LLM-only update."""
        assert not hasattr(svc, "update_platform_llm")

    def test_scoped_settings_invalid_platform_settings_error_is_a_value_error(
        self, svc: ModuleType
    ) -> None:
        assert issubclass(svc.InvalidPlatformSettingsError, ValueError)

    def test_scoped_settings_stored_platform_settings_sections_default_to_the_table_defaults(
        self, svc: ModuleType
    ) -> None:
        """StoredPlatformSettings gains files, retention and security; each defaults to
        migration 0014's defaults (a StoredPlatformSettings of llm + limits only)."""
        from admino.models import PlatformFiles, PlatformRetention, PlatformSecurity

        stored = _stored(svc)

        assert isinstance(stored.files, PlatformFiles)
        assert isinstance(stored.retention, PlatformRetention)
        assert isinstance(stored.security, PlatformSecurity)
        assert {name: _section(stored, name) for name in _DEFAULT_SECTIONS} == _SECTION_DEFAULTS

    def test_scoped_settings_stored_platform_settings_keeps_given_sections(
        self, svc: ModuleType
    ) -> None:
        stored = _stored(svc, **_CUSTOM_SECTIONS)

        assert {name: _section(stored, name) for name in _DEFAULT_SECTIONS} == _CUSTOM_SECTIONS

    def test_scoped_settings_apply_platform_settings_is_pure_and_sync(
        self, svc: ModuleType
    ) -> None:
        assert callable(svc.apply_platform_settings)
        assert not inspect.iscoroutinefunction(svc.apply_platform_settings)

    @pytest.mark.parametrize(
        ("name", "keywords"),
        [
            ("get_user_settings", {"actor"}),
            ("update_user_settings", {"actor", "patch"}),
            ("reset_user_settings", {"actor"}),
            ("get_org_settings", {"actor"}),
            ("update_org_settings", {"actor", "patch", "ip"}),
            ("update_platform_settings", {"actor", "patch", "ip"}),
        ],
    )
    def test_scoped_settings_actor_patch_and_ip_are_keyword_only(
        self, svc: ModuleType, name: str, keywords: set[str]
    ) -> None:
        parameters = inspect.signature(getattr(svc, name)).parameters
        found = {key for key, p in parameters.items() if p.kind is inspect.Parameter.KEYWORD_ONLY}
        assert found == keywords

    def test_scoped_settings_stored_platform_settings_has_llm_and_limits(
        self, svc: ModuleType
    ) -> None:
        """StoredPlatformSettings(llm: provider + four models, limits: the five ints)."""
        stored = _stored(svc)

        assert {field: getattr(stored.llm, field) for field in _LLM_FIELDS} == {
            "provider": "openai",
            "infomaniak_model": None,
            "vllm_model": "org/served-model",
            "anthropic_model": None,
            "openai_model": "gpt-4.1",
        }
        assert {field: getattr(stored.limits, field) for field in _LIMIT_FIELDS} == {
            "max_tool_calls_per_message": 7,
            "max_pending_confirmations": 4,
            "confirmation_timeout_s": 120,
            "max_message_length": 5000,
            "max_context_messages": 30,
        }

    def test_scoped_settings_imports_only_the_allowed_admino_modules(self, svc: ModuleType) -> None:
        """access, tenancy, audit_events, models, config and (GH-160, for the Super Admin
        session policy) sessions: never the server, agent, LLM, tools, OAuth, database or
        permission engine modules."""
        tree = ast.parse(inspect.getsource(svc))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {
                    alias.name.split(".")[1]
                    for alias in node.names
                    if alias.name.startswith("admino.")
                }
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                if node.module == "admino":
                    imported |= {alias.name for alias in node.names}
                elif node.module.startswith("admino."):
                    imported.add(node.module.split(".")[1])

        allowed = {"access", "tenancy", "audit_events", "models", "config", "sessions"}
        assert imported <= allowed, imported

    def test_scoped_settings_module_docstring_has_security_notes(self, svc: ModuleType) -> None:
        assert svc.__doc__ is not None
        assert "security" in svc.__doc__.lower()


# ---------------------------------------------------------------------------
# 2. Authorization: access.can before any statement
# ---------------------------------------------------------------------------


class TestAuthorization:
    """Org settings: Org Admin only; the platform LLM: Super Admin only; the user scope:
    every role. A refusal reads and writes nothing."""

    @pytest.mark.parametrize(("name", "role"), _REFUSED)
    async def test_scoped_settings_refused_role_gets_permission_error_before_any_query(
        self, svc: ModuleType, db: FakeDb, name: str, role: str
    ) -> None:
        _platform(db)
        actor = _actor(db, role)
        before = _state(db)

        with pytest.raises(PermissionError):
            await _invoke(svc, db, name, actor)

        assert db.calls == []
        assert _state(db) == before

    async def test_scoped_settings_editor_cant_update_org_settings(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """The issue's AC at the service layer: an Editor can't change org settings."""
        editor = _actor(db, "editor")

        with pytest.raises(PermissionError):
            await svc.update_org_settings(
                db.pool, actor=editor, patch=_org_patch(gmail=False), ip=_IP
            )

        assert db.org_settings == {}
        assert db.audit == []

    async def test_scoped_settings_org_admin_cant_update_the_platform_llm(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """The issue's AC at the service layer: an Org Admin can't change platform settings."""
        row = copy.deepcopy(_platform(db))
        admin = _actor(db, "org_admin")

        with pytest.raises(PermissionError):
            await svc.update_platform_settings(
                db.pool, actor=admin, patch=_llm_patch(provider="vllm"), ip=_IP
            )

        assert db.platform_row() == row
        assert db.audit == []

    @pytest.mark.parametrize(("name", "role"), _ALLOWED)
    async def test_scoped_settings_allowed_role_reaches_the_database(
        self, svc: ModuleType, db: FakeDb, name: str, role: str
    ) -> None:
        """No PermissionError: the call runs its statements (the user scope for every role,
        the Super Admin included)."""
        _platform(db)
        actor = _actor(db, role)

        await _invoke(svc, db, name, actor)

        assert db.calls

    @pytest.mark.parametrize("name", list(_CAPABILITIES))
    async def test_scoped_settings_asks_can_for_its_capability(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch, name: str
    ) -> None:
        _platform(db)
        role = "super_admin" if name == "update_platform_settings" else "org_admin"
        actor = _actor(db, role)
        spy = _CanSpy(monkeypatch, svc)

        await _invoke(svc, db, name, actor)

        assert _CAPABILITIES[name] in spy.capabilities

    @pytest.mark.parametrize("name", list(_CAPABILITIES))
    async def test_scoped_settings_capability_refused_by_can_is_a_permission_error(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch, name: str
    ) -> None:
        """When can() refuses the function's capability, even the right role is refused
        before any statement."""
        _platform(db)
        role = "super_admin" if name == "update_platform_settings" else "org_admin"
        actor = _actor(db, role)
        _CanSpy(monkeypatch, svc, deny=frozenset({_CAPABILITIES[name]}))

        with pytest.raises(PermissionError):
            await _invoke(svc, db, name, actor)

        assert db.calls == []


# ---------------------------------------------------------------------------
# 3. The user scope
# ---------------------------------------------------------------------------


class TestUserSettings:
    """Each user reads and changes their own theme and notifications only."""

    async def test_scoped_settings_missing_user_row_reads_as_the_defaults(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        from admino.models import UserSettingsResponse

        actor = _actor(db, "editor")

        result = await svc.get_user_settings(db.pool, actor=actor)

        assert isinstance(result, UserSettingsResponse)
        assert result.model_dump() == _USER_DEFAULTS
        assert db.user_settings == {}

    async def test_scoped_settings_get_user_returns_the_stored_row(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        actor = _actor(db, "viewer")
        db.add_user_settings(actor.user_id, theme="dark", notifications_enabled=False)

        result = await svc.get_user_settings(db.pool, actor=actor)

        assert _user_values(result) == ("dark", False)

    async def test_scoped_settings_get_user_reads_only_the_actors_row(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """The actor's id is bound; another user's is never."""
        actor = _actor(db, "editor")
        other = _actor(db, "org_admin")
        db.add_user_settings(actor.user_id, theme="system")
        db.add_user_settings(other.user_id, theme="dark", notifications_enabled=False)

        result = await svc.get_user_settings(db.pool, actor=actor)

        assert _user_values(result) == ("system", True)
        assert _bound(db, actor.user_id)
        assert not _bound(db, other.user_id)
        assert all(str(actor.user_id) not in call.sql for call in db.calls)

    async def test_scoped_settings_update_theme_keeps_the_notifications(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        actor = _actor(db, "editor")
        db.add_user_settings(actor.user_id, theme="dark", notifications_enabled=False)

        result = await svc.update_user_settings(
            db.pool, actor=actor, patch=_user_patch({"appearance": {"theme": "system"}})
        )

        row = db.user_settings[actor.user_id]
        assert (row["theme"], row["notifications_enabled"]) == ("system", False)
        assert _user_values(result) == ("system", False)

    async def test_scoped_settings_update_notifications_keeps_the_theme(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        actor = _actor(db, "viewer")
        db.add_user_settings(actor.user_id, theme="dark", notifications_enabled=True)

        result = await svc.update_user_settings(
            db.pool, actor=actor, patch=_user_patch({"notifications": {"enabled": False}})
        )

        row = db.user_settings[actor.user_id]
        assert (row["theme"], row["notifications_enabled"]) == ("dark", False)
        assert _user_values(result) == ("dark", False)

    async def test_scoped_settings_update_creates_a_missing_row_with_the_defaults(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Only the given field differs from the defaults."""
        actor = _actor(db, "editor")

        result = await svc.update_user_settings(
            db.pool, actor=actor, patch=_user_patch({"notifications": {"enabled": False}})
        )

        row = db.user_settings[actor.user_id]
        assert (row["theme"], row["notifications_enabled"]) == ("light", False)
        assert _user_values(result) == ("light", False)

    async def test_scoped_settings_update_both_fields(self, svc: ModuleType, db: FakeDb) -> None:
        from admino.models import UserSettingsResponse

        actor = _actor(db, "org_admin")

        result = await svc.update_user_settings(
            db.pool,
            actor=actor,
            patch=_user_patch(
                {"appearance": {"theme": "dark"}, "notifications": {"enabled": False}}
            ),
        )

        assert isinstance(result, UserSettingsResponse)
        assert _user_values(result) == ("dark", False)
        row = db.user_settings[actor.user_id]
        assert (row["theme"], row["notifications_enabled"]) == ("dark", False)

    async def test_scoped_settings_update_never_touches_another_user(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        actor = _actor(db, "editor")
        other = _actor(db, "editor")
        other_row = copy.deepcopy(db.add_user_settings(other.user_id, theme="system"))

        await svc.update_user_settings(
            db.pool, actor=actor, patch=_user_patch({"appearance": {"theme": "dark"}})
        )

        assert db.user_settings[other.user_id] == other_row
        assert not _bound(db, other.user_id)
        assert set(db.user_settings) == {actor.user_id, other.user_id}

    async def test_scoped_settings_super_admin_has_their_own_user_settings(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        actor = _actor(db, "super_admin")

        await svc.update_user_settings(
            db.pool, actor=actor, patch=_user_patch({"appearance": {"theme": "dark"}})
        )
        result = await svc.get_user_settings(db.pool, actor=actor)

        assert _user_values(result) == ("dark", True)
        assert set(db.user_settings) == {actor.user_id}

    async def test_scoped_settings_user_update_records_no_audit_event(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        actor = _actor(db, "editor")

        await svc.update_user_settings(
            db.pool, actor=actor, patch=_user_patch({"notifications": {"enabled": False}})
        )

        assert db.audit == []


# ---------------------------------------------------------------------------
# 3b. Task-done pings (GH-35): notifications.task_done in the user scope
# ---------------------------------------------------------------------------


class TestUserTaskDone:
    """``notifications.task_done`` (``user_settings.notifications_task_done``, default off)
    is read, patched and kept like the other user settings, independent of ``enabled``."""

    async def test_scoped_settings_get_user_without_a_row_has_task_done_off_and_writes_nothing(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        actor = _actor(db, "editor")

        result = await svc.get_user_settings(db.pool, actor=actor)

        assert result.notifications.task_done is False
        assert db.user_settings == {}
        assert db.matching(r"^(?:insert|update|delete)\b") == []

    @pytest.mark.parametrize("stored", [True, False], ids=["stored-on", "stored-off"])
    async def test_scoped_settings_get_user_returns_the_stored_task_done(
        self, svc: ModuleType, db: FakeDb, stored: bool
    ) -> None:
        actor = _actor(db, "viewer")
        db.add_user_settings(
            actor.user_id,
            theme="system",
            notifications_enabled=False,
            notifications_task_done=stored,
        )

        result = await svc.get_user_settings(db.pool, actor=actor)

        assert _user_all(result) == ("system", False, stored)
        assert db.matching(r"^(?:insert|update|delete)\b") == []

    async def test_scoped_settings_get_user_response_has_the_full_notifications_shape(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """The response is {appearance: {theme}, notifications: {enabled, task_done}}."""
        actor = _actor(db, "org_admin")
        _custom_user_row(db, actor.user_id)

        result = await svc.get_user_settings(db.pool, actor=actor)

        assert result.model_dump() == {
            "appearance": {"theme": "dark"},
            "notifications": {"enabled": False, "task_done": True},
        }

    @pytest.mark.parametrize("value", [True, False], ids=["switch-on", "switch-off"])
    @pytest.mark.parametrize(
        ("theme", "enabled"),
        [("dark", False), ("system", True)],
        ids=["dark-enabled-off", "system-enabled-on"],
    )
    async def test_scoped_settings_update_task_done_only_keeps_theme_and_enabled(
        self, svc: ModuleType, db: FakeDb, theme: str, enabled: bool, value: bool
    ) -> None:
        """A task_done-only patch persists task_done; the theme and ``enabled`` stay."""
        actor = _actor(db, "editor")
        db.add_user_settings(
            actor.user_id,
            theme=theme,
            notifications_enabled=enabled,
            notifications_task_done=not value,
        )

        result = await svc.update_user_settings(
            db.pool, actor=actor, patch=_user_patch({"notifications": {"task_done": value}})
        )

        assert _user_row(db, actor.user_id) == (theme, enabled, value)
        assert _user_all(result) == (theme, enabled, value)

    async def test_scoped_settings_update_theme_keeps_a_stored_task_done(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        actor = _actor(db, "viewer")
        db.add_user_settings(actor.user_id, theme="dark", notifications_task_done=True)

        result = await svc.update_user_settings(
            db.pool, actor=actor, patch=_user_patch({"appearance": {"theme": "system"}})
        )

        assert _user_row(db, actor.user_id) == ("system", True, True)
        assert _user_all(result) == ("system", True, True)

    @pytest.mark.parametrize("enabled", [True, False], ids=["enabled-on", "enabled-off"])
    async def test_scoped_settings_update_enabled_keeps_a_stored_task_done(
        self, svc: ModuleType, db: FakeDb, enabled: bool
    ) -> None:
        """``enabled`` is no master switch: changing it leaves task_done as stored."""
        actor = _actor(db, "editor")
        db.add_user_settings(
            actor.user_id, notifications_enabled=not enabled, notifications_task_done=True
        )

        result = await svc.update_user_settings(
            db.pool, actor=actor, patch=_user_patch({"notifications": {"enabled": enabled}})
        )

        assert _user_row(db, actor.user_id) == ("light", enabled, True)
        assert _user_all(result) == ("light", enabled, True)

    async def test_scoped_settings_task_done_on_with_enabled_off_both_persist(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Neither switch is a master of the other: task_done on with ``enabled`` off is
        stored and returned as given."""
        actor = _actor(db, "org_admin")

        result = await svc.update_user_settings(
            db.pool,
            actor=actor,
            patch=_user_patch({"notifications": {"enabled": False, "task_done": True}}),
        )

        assert _user_row(db, actor.user_id) == ("light", False, True)
        assert _user_all(result) == ("light", False, True)

    async def test_scoped_settings_update_all_three_settings_at_once(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        from admino.models import UserSettingsResponse

        actor = _actor(db, "super_admin")

        result = await svc.update_user_settings(
            db.pool,
            actor=actor,
            patch=_user_patch(
                {
                    "appearance": {"theme": "dark"},
                    "notifications": {"enabled": False, "task_done": True},
                }
            ),
        )

        assert isinstance(result, UserSettingsResponse)
        assert result.model_dump() == {
            "appearance": {"theme": "dark"},
            "notifications": {"enabled": False, "task_done": True},
        }
        assert _user_row(db, actor.user_id) == ("dark", False, True)

    async def test_scoped_settings_update_task_done_creates_a_missing_row_with_the_defaults(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Only task_done differs from the column defaults."""
        actor = _actor(db, "viewer")

        result = await svc.update_user_settings(
            db.pool, actor=actor, patch=_user_patch({"notifications": {"task_done": True}})
        )

        assert _user_row(db, actor.user_id) == ("light", True, True)
        assert _user_all(result) == ("light", True, True)

    async def test_scoped_settings_task_done_survives_a_reload(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """The issue's AC "persists across reload": a later read returns the stored value,
        also after another setting changed."""
        actor = _actor(db, "editor")

        await svc.update_user_settings(
            db.pool, actor=actor, patch=_user_patch({"notifications": {"task_done": True}})
        )
        reloaded = await svc.get_user_settings(db.pool, actor=actor)
        await svc.update_user_settings(
            db.pool, actor=actor, patch=_user_patch({"appearance": {"theme": "dark"}})
        )
        reloaded_again = await svc.get_user_settings(db.pool, actor=actor)

        assert _user_all(reloaded) == ("light", True, True)
        assert _user_all(reloaded_again) == ("dark", True, True)

    async def test_scoped_settings_task_done_update_never_touches_another_user(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Neither a colleague in the same org nor a user of another org is touched."""
        actor = _actor(db, "editor")
        colleague = _actor(db, "editor")
        stranger = _actor(db, "viewer", OTHER_ORG_ID)
        db.add_user_settings(actor.user_id)
        others = {
            colleague.user_id: copy.deepcopy(db.add_user_settings(colleague.user_id)),
            stranger.user_id: copy.deepcopy(_custom_user_row(db, stranger.user_id)),
        }

        await svc.update_user_settings(
            db.pool, actor=actor, patch=_user_patch({"notifications": {"task_done": True}})
        )

        assert {user_id: db.user_settings[user_id] for user_id in others} == others
        assert not _bound(db, colleague.user_id)
        assert not _bound(db, stranger.user_id)
        assert _user_row(db, actor.user_id) == ("light", True, True)

    async def test_scoped_settings_task_done_update_statements_are_constants(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Switching task_done on or off issues the same SQL text: the value is a bind
        parameter, never part of the statement."""
        first = _actor(db, "editor")
        second = _actor(db, "editor")
        db.add_user_settings(first.user_id)
        db.add_user_settings(second.user_id, notifications_task_done=True)

        await svc.update_user_settings(
            db.pool, actor=first, patch=_user_patch({"notifications": {"task_done": True}})
        )
        on_count = len(db.calls)
        await svc.update_user_settings(
            db.pool, actor=second, patch=_user_patch({"notifications": {"task_done": False}})
        )

        on_sql = [call.sql for call in db.calls[:on_count]]
        off_sql = [call.sql for call in db.calls[on_count:]]
        assert on_sql == off_sql
        assert _user_row(db, first.user_id)[2] is True
        assert _user_row(db, second.user_id)[2] is False

    async def test_scoped_settings_task_done_update_records_no_audit_event(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        actor = _actor(db, "editor")

        await svc.update_user_settings(
            db.pool, actor=actor, patch=_user_patch({"notifications": {"task_done": True}})
        )

        assert db.audit == []


# ---------------------------------------------------------------------------
# 3c. Reset my settings (GH-35): reset_user_settings
# ---------------------------------------------------------------------------


class TestResetUserSettings:
    """``reset_user_settings(pool, *, actor)`` reverts the actor's own user_settings row to
    the defaults (every role) and touches nothing else."""

    def test_scoped_settings_reset_takes_only_the_pool_and_the_actor(self, svc: ModuleType) -> None:
        parameters = inspect.signature(svc.reset_user_settings).parameters

        assert list(parameters) == ["pool", "actor"]
        assert parameters["actor"].kind is inspect.Parameter.KEYWORD_ONLY

    @pytest.mark.parametrize("role", _ROLES)
    async def test_scoped_settings_reset_reverts_the_actors_row_for_every_role(
        self, svc: ModuleType, db: FakeDb, role: str
    ) -> None:
        """Every role (the Super Admin included) resets their own row and gets the
        defaults back."""
        from admino.models import UserSettingsResponse

        actor = _actor(db, role)
        _custom_user_row(db, actor.user_id)

        result = await svc.reset_user_settings(db.pool, actor=actor)

        assert isinstance(result, UserSettingsResponse)
        assert result.model_dump() == _USER_DEFAULTS
        _assert_reset_row(db, actor.user_id)

    @pytest.mark.parametrize("custom", _ONE_CUSTOM_SETTING)
    async def test_scoped_settings_reset_reverts_each_setting(
        self, svc: ModuleType, db: FakeDb, custom: dict[str, Any]
    ) -> None:
        """Every column is reverted, task_done included, not only some of them."""
        actor = _actor(db, "editor")
        db.add_user_settings(actor.user_id, **custom)

        await svc.reset_user_settings(db.pool, actor=actor)

        _assert_reset_row(db, actor.user_id)

    @pytest.mark.parametrize("role", _ROLES)
    async def test_scoped_settings_reset_then_get_returns_the_defaults(
        self, svc: ModuleType, db: FakeDb, role: str
    ) -> None:
        """The following read (a reload of the Settings page) shows the defaults."""
        actor = _actor(db, role)
        _custom_user_row(db, actor.user_id)

        await svc.reset_user_settings(db.pool, actor=actor)
        result = await svc.get_user_settings(db.pool, actor=actor)

        assert result.model_dump() == _USER_DEFAULTS
        assert _user_all(result) == ("light", True, False)

    async def test_scoped_settings_reset_without_a_row_returns_the_defaults(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Idempotent: no row is no error; the row stays absent or holds the defaults."""
        actor = _actor(db, "viewer")

        result = await svc.reset_user_settings(db.pool, actor=actor)

        assert result.model_dump() == _USER_DEFAULTS
        _assert_reset_row(db, actor.user_id)
        assert set(db.user_settings) <= {actor.user_id}

    async def test_scoped_settings_reset_twice_returns_the_defaults_both_times(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        actor = _actor(db, "org_admin")
        _custom_user_row(db, actor.user_id)

        first = await svc.reset_user_settings(db.pool, actor=actor)
        second = await svc.reset_user_settings(db.pool, actor=actor)

        assert first.model_dump() == _USER_DEFAULTS
        assert second.model_dump() == _USER_DEFAULTS
        _assert_reset_row(db, actor.user_id)

    async def test_scoped_settings_update_after_reset_starts_from_the_defaults(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """After a reset only the newly given setting differs from the defaults."""
        actor = _actor(db, "editor")
        _custom_user_row(db, actor.user_id)

        await svc.reset_user_settings(db.pool, actor=actor)
        result = await svc.update_user_settings(
            db.pool, actor=actor, patch=_user_patch({"appearance": {"theme": "system"}})
        )

        assert _user_all(result) == ("system", True, False)
        assert _user_row(db, actor.user_id) == ("system", True, False)

    @pytest.mark.parametrize("role", _ROLES)
    async def test_scoped_settings_reset_refused_by_can_is_a_permission_error_before_any_query(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch, role: str
    ) -> None:
        """``account.manage`` is checked first: refused, nothing is read or written."""
        actor = _actor(db, role)
        _custom_user_row(db, actor.user_id)
        before = _state(db)
        spy = _CanSpy(monkeypatch, svc, deny=frozenset({Capability.ACCOUNT_MANAGE}))

        with pytest.raises(PermissionError):
            await svc.reset_user_settings(db.pool, actor=actor)

        assert Capability.ACCOUNT_MANAGE in spy.capabilities
        assert db.calls == []
        assert _state(db) == before

    async def test_scoped_settings_reset_asks_can_for_account_manage(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        actor = _actor(db, "viewer")
        spy = _CanSpy(monkeypatch, svc)

        await svc.reset_user_settings(db.pool, actor=actor)

        assert spy.capabilities == [Capability.ACCOUNT_MANAGE]

    @pytest.mark.parametrize("has_row", [True, False], ids=["with-row", "without-row"])
    async def test_scoped_settings_reset_touches_nothing_but_the_actors_row(
        self, svc: ModuleType, db: FakeDb, has_row: bool
    ) -> None:
        """Other users' rows (same org, another org, a Super Admin), every org_settings row,
        the platform row, the actor's account row (languages, name, email), the sessions
        and the audit events stay exactly as they were."""
        _platform(db)
        db.add_org_settings(ORG_ID, gmail=False)
        db.add_org_settings(OTHER_ORG_ID, **{TOOL_NAMES[-1]: False})
        actor = _actor(db, "editor", email=_EMAIL_MARKER, name=_NAME_MARKER, ui_language="fr")
        db.users[actor.user_id]["response_language"] = "it"
        if has_row:
            _custom_user_row(db, actor.user_id)
        others = [_actor(db, "org_admin"), _actor(db, "viewer", OTHER_ORG_ID)]
        others.append(_actor(db, "super_admin"))
        for other in others:
            _custom_user_row(db, other.user_id)
        for user_id in [actor.user_id, *(other.user_id for other in others)]:
            db.open_session(user_id)
        before = _state(db)
        sessions_before = copy.deepcopy(db.sessions)

        await svc.reset_user_settings(db.pool, actor=actor)

        after = _state(db)
        user_settings_before = before.pop("user_settings")
        user_settings_after = after.pop("user_settings")
        assert after == before
        assert db.sessions == sessions_before
        assert {key: row for key, row in user_settings_after.items() if key != actor.user_id} == {
            key: row for key, row in user_settings_before.items() if key != actor.user_id
        }
        _assert_reset_row(db, actor.user_id)

    @pytest.mark.parametrize("has_row", [True, False], ids=["with-row", "without-row"])
    async def test_scoped_settings_reset_statements_name_only_user_settings(
        self, svc: ModuleType, db: FakeDb, has_row: bool
    ) -> None:
        """No statement of the reset names users, sessions, audit_events, oauth_tokens,
        org_settings, platform_settings or any other table: user_settings only."""
        tables = _migration_tables()
        assert {"user_settings", "users", "sessions", "oauth_tokens"} <= tables
        actor = _actor(db, "org_admin")
        if has_row:
            _custom_user_row(db, actor.user_id)

        await svc.reset_user_settings(db.pool, actor=actor)

        assert db.calls
        for call in db.calls:
            assert _tables_named(call.normalized, tables) == {"user_settings"}, call.sql

    async def test_scoped_settings_reset_binds_only_the_actors_id(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """The actor's id is a bind parameter, never part of the SQL; another user's id is
        never bound."""
        actor = _actor(db, "editor")
        other = _actor(db, "editor")
        _custom_user_row(db, actor.user_id)
        _custom_user_row(db, other.user_id)

        await svc.reset_user_settings(db.pool, actor=actor)

        assert _bound(db, actor.user_id)
        assert not _bound(db, other.user_id)
        for call in db.calls:
            assert str(actor.user_id) not in call.sql
            assert actor.user_id.hex not in call.sql

    async def test_scoped_settings_reset_statements_are_constants(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Two users' resets issue the same SQL text: only the bind arguments differ."""
        first = _actor(db, "editor")
        second = _actor(db, "viewer", OTHER_ORG_ID)
        _custom_user_row(db, first.user_id)
        _custom_user_row(db, second.user_id)

        await svc.reset_user_settings(db.pool, actor=first)
        first_count = len(db.calls)
        await svc.reset_user_settings(db.pool, actor=second)

        assert first_count > 0
        assert [call.sql for call in db.calls[:first_count]] == [
            call.sql for call in db.calls[first_count:]
        ]

    async def test_scoped_settings_reset_records_no_audit_event(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Like a user settings PATCH, the reset is not audited (the user scope is not in
        the audit catalog)."""
        actor = _actor(db, "org_admin")
        _custom_user_row(db, actor.user_id)

        await svc.reset_user_settings(db.pool, actor=actor)

        assert db.audit == []
        assert db.matching(r"\baudit_events\b") == []


# ---------------------------------------------------------------------------
# 4. The org scope
# ---------------------------------------------------------------------------


class TestOrgSettings:
    """The Org Admin reads and changes their own org's tool services; changes are audited."""

    async def test_scoped_settings_missing_org_row_reads_as_all_tools_enabled(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        from admino.models import OrgSettingsResponse

        admin = _actor(db, "org_admin")

        result = await svc.get_org_settings(db.pool, actor=admin)

        assert isinstance(result, OrgSettingsResponse)
        assert _tools(result) == _ALL_ON
        assert db.org_settings == {}

    async def test_scoped_settings_get_org_returns_the_stored_row(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        admin = _actor(db, "org_admin")
        db.add_org_settings(ORG_ID, gmail=False, onedrive=False)

        result = await svc.get_org_settings(db.pool, actor=admin)

        assert _tools(result) == {**_ALL_ON, "gmail": False, "onedrive": False}

    async def test_scoped_settings_get_org_reads_only_the_principals_org(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Org A's admin sees A's row; B's id is never bound."""
        admin = _actor(db, "org_admin", ORG_ID)
        db.add_org_settings(ORG_ID, memory=False)
        db.add_org_settings(OTHER_ORG_ID, gmail=False)

        result = await svc.get_org_settings(db.pool, actor=admin)

        assert _tools(result) == {**_ALL_ON, "memory": False}
        assert _bound(db, ORG_ID)
        assert not _bound(db, OTHER_ORG_ID)

    async def test_scoped_settings_update_org_changes_only_the_given_tools(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        admin = _actor(db, "org_admin")
        db.add_org_settings(ORG_ID, outlook=False)

        result = await svc.update_org_settings(
            db.pool, actor=admin, patch=_org_patch(gmail=False), ip=_IP
        )

        expected = {**_ALL_ON, "gmail": False, "outlook": False}
        assert db.org_tools(ORG_ID) == expected
        assert _tools(result) == expected

    async def test_scoped_settings_update_org_creates_a_missing_row(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        from admino.models import OrgSettingsResponse

        admin = _actor(db, "org_admin")

        result = await svc.update_org_settings(
            db.pool, actor=admin, patch=_org_patch(memory=False), ip=_IP
        )

        assert isinstance(result, OrgSettingsResponse)
        assert db.org_tools(ORG_ID) == {**_ALL_ON, "memory": False}

    async def test_scoped_settings_update_org_locks_the_row_in_one_transaction(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        admin = _actor(db, "org_admin")
        db.add_org_settings(ORG_ID)

        await svc.update_org_settings(db.pool, actor=admin, patch=_org_patch(gmail=False), ip=_IP)

        _assert_locked_in_one_transaction(db, "org_settings")

    async def test_scoped_settings_update_org_records_the_exact_audit_event(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """org.settings_change: the member actor, the org's log, the org as target, the
        client IP, and one old/new pair for the changed tool."""
        admin = _actor(db, "org_admin")

        await svc.update_org_settings(db.pool, actor=admin, patch=_org_patch(gmail=False), ip=_IP)

        row = _one(db.audit)
        assert row["action"] == "org.settings_change"
        assert (row["actor_kind"], _uuid(row["actor_user_id"])) == ("member", admin.user_id)
        assert _uuid(row["org_id"]) == ORG_ID
        assert (row["target_type"], row["target_ids"]) == ("organization", [str(ORG_ID)])
        assert row["ip"] == _IP
        assert row["metadata"] == {"gmail_old": True, "gmail_new": False}
        assert all(type(value) is bool for value in row["metadata"].values())

    async def test_scoped_settings_update_org_audit_names_only_the_changed_tools(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Given but unchanged tools get no pair; every changed one gets exactly one."""
        admin = _actor(db, "org_admin")
        db.add_org_settings(ORG_ID, outlook=False, onedrive=False)

        await svc.update_org_settings(
            db.pool,
            actor=admin,
            patch=_org_patch(gmail=False, outlook=False, onedrive=True, memory=True),
            ip=_IP,
        )

        assert _one(db.audit)["metadata"] == {
            "gmail_old": True,
            "gmail_new": False,
            "onedrive_old": False,
            "onedrive_new": True,
        }

    async def test_scoped_settings_update_org_noop_records_nothing(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        admin = _actor(db, "org_admin")
        db.add_org_settings(ORG_ID, gmail=False)

        result = await svc.update_org_settings(
            db.pool, actor=admin, patch=_org_patch(gmail=False, memory=True), ip=_IP
        )

        assert db.audit == []
        assert db.org_tools(ORG_ID) == {**_ALL_ON, "gmail": False}
        assert _tools(result) == {**_ALL_ON, "gmail": False}

    async def test_scoped_settings_update_org_audit_failure_rolls_the_change_back(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        admin = _actor(db, "org_admin")
        db.add_org_settings(ORG_ID)
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await svc.update_org_settings(
                db.pool, actor=admin, patch=_org_patch(gmail=False), ip=_IP
            )

        assert _state(db) == before
        assert any(outcome.startswith("rollback") for _, outcome in db.transactions)

    async def test_scoped_settings_update_org_never_touches_another_org(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """The org comes from the principal only: org B's row and id are never touched."""
        admin = _actor(db, "org_admin", ORG_ID)
        other_row = copy.deepcopy(db.add_org_settings(OTHER_ORG_ID, memory=False))

        await svc.update_org_settings(db.pool, actor=admin, patch=_org_patch(gmail=False), ip=_IP)

        assert db.org_settings[OTHER_ORG_ID] == other_row
        assert not _bound(db, OTHER_ORG_ID)
        assert _uuid(_one(db.audit)["org_id"]) == ORG_ID

    async def test_scoped_settings_update_org_without_ip_records_no_ip(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        admin = _actor(db, "org_admin")

        await svc.update_org_settings(db.pool, actor=admin, patch=_org_patch(memory=False), ip=None)

        assert _one(db.audit)["ip"] is None


# ---------------------------------------------------------------------------
# 5. The interim enabled-services gate (until #161)
# ---------------------------------------------------------------------------


class TestToolsGate:
    """A tool is off when ANY org turned it off; no org row means every tool is on."""

    async def test_scoped_settings_gate_without_rows_enables_every_tool(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        gate = await svc.all_orgs_tools_gate(db.pool)

        assert dict(gate) == _ALL_ON
        assert all(type(value) is bool for value in gate.values())

    async def test_scoped_settings_gate_one_org_disabling_wins_over_another_enabling(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_org_settings(ORG_ID, gmail=False)
        db.add_org_settings(OTHER_ORG_ID, gmail=True)

        gate = await svc.all_orgs_tools_gate(db.pool)

        assert dict(gate) == {**_ALL_ON, "gmail": False}

    async def test_scoped_settings_gate_ands_every_tool_across_orgs(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        third = db.add_org()
        db.add_org_settings(ORG_ID, outlook=False)
        db.add_org_settings(OTHER_ORG_ID, memory=False, onedrive=False)
        db.add_org_settings(third)

        gate = await svc.all_orgs_tools_gate(db.pool)

        assert dict(gate) == {**_ALL_ON, "outlook": False, "memory": False, "onedrive": False}

    async def test_scoped_settings_gate_all_rows_enabled_is_all_on(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_org_settings(ORG_ID)
        db.add_org_settings(OTHER_ORG_ID)

        assert dict(await svc.all_orgs_tools_gate(db.pool)) == _ALL_ON

    async def test_scoped_settings_gate_is_one_aggregate_statement(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_org_settings(ORG_ID, gmail=False)

        await svc.all_orgs_tools_gate(db.pool)

        call = _one(db.calls)
        assert re.search(r"\bbool_and\b", call.normalized), call.sql
        assert re.search(r"\bfrom org_settings\b", call.normalized), call.sql

    async def test_scoped_settings_gate_follows_an_org_update(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        admin = _actor(db, "org_admin", OTHER_ORG_ID)
        db.add_org_settings(ORG_ID, memory=False)

        await svc.update_org_settings(db.pool, actor=admin, patch=_org_patch(gmail=False), ip=_IP)

        assert dict(await svc.all_orgs_tools_gate(db.pool)) == {
            **_ALL_ON,
            "gmail": False,
            "memory": False,
        }


# ---------------------------------------------------------------------------
# 6. The platform row: seed, load, overlay, change
# ---------------------------------------------------------------------------


def _platform_llm(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": row["llm_provider"],
        **{column: row[column] for column in _LLM_FIELDS[1:]},
    }


def _platform_limits(row: dict[str, Any]) -> dict[str, int]:
    return {column: row[column] for column in _LIMIT_FIELDS}


class TestSeedPlatformSettings:
    """config.yaml seeds the row on first boot; its llm is re-applied on every boot."""

    async def test_scoped_settings_first_boot_stores_the_config_llm_and_limits(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        limits = {
            "max_tool_calls_per_message": 12,
            "max_pending_confirmations": 5,
            "confirmation_timeout_s": 600,
            "max_message_length": 8000,
            "max_context_messages": 40,
        }
        config = _config(limits=limits)

        await svc.seed_platform_settings(db.pool, config)

        row = db.platform_row()
        assert row is not None
        assert _platform_llm(row) == {
            "provider": "anthropic",
            "infomaniak_model": "Qwen/Qwen3.5-397B-A17B-FP8",
            "vllm_model": "Qwen/Qwen3-4B-Instruct-2507",
            "anthropic_model": "claude-sonnet-4-6",
            "openai_model": "gpt-4o",
        }
        assert _platform_limits(row) == limits

    @pytest.mark.parametrize("empty", [None, ""])
    async def test_scoped_settings_seed_stores_an_empty_model_as_null(
        self, svc: ModuleType, db: FakeDb, empty: str | None
    ) -> None:
        config = _config(llm={"openai_model": empty, "vllm_model": empty})

        await svc.seed_platform_settings(db.pool, config)

        row = db.platform_row()
        assert row is not None
        assert (row["openai_model"], row["vllm_model"]) == (None, None)
        assert row["anthropic_model"] == "claude-sonnet-4-6"

    async def test_scoped_settings_later_boot_reapplies_the_llm_and_keeps_the_limits(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        stored = _platform(
            db,
            llm_provider="openai",
            openai_model="gpt-4.1",
            anthropic_model=None,
            updated_at=_OLD,
        )
        stored_limits = _platform_limits(stored)
        config = _config(llm={"provider": "infomaniak", "infomaniak_model": "mistralai/Small-3.2"})

        await svc.seed_platform_settings(db.pool, config)

        row = db.platform_row()
        assert row is not None
        assert len(db.platform_settings) == 1
        assert _platform_llm(row) == {
            "provider": "infomaniak",
            "infomaniak_model": "mistralai/Small-3.2",
            "vllm_model": "Qwen/Qwen3-4B-Instruct-2507",
            "anthropic_model": "claude-sonnet-4-6",
            "openai_model": "gpt-4o",
        }
        assert _platform_limits(row) == stored_limits
        assert _platform_limits(row) != config.limits.model_dump()
        assert row["updated_at"] > _OLD

    async def test_scoped_settings_seed_is_one_upsert_statement(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        await svc.seed_platform_settings(db.pool, _config())

        call = _one(db.calls)
        assert call.normalized.startswith("insert into platform_settings")
        assert " on conflict " in call.normalized


class TestLoadPlatformSettings:
    """The singleton row as a StoredPlatformSettings; no row is a startup error."""

    async def test_scoped_settings_load_without_a_row_raises_runtime_error(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        with pytest.raises(RuntimeError):
            await svc.load_platform_settings(db.pool)

    async def test_scoped_settings_load_returns_the_stored_row(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _platform(db, llm_provider="vllm", vllm_model="org/served-model", anthropic_model=None)

        stored = await svc.load_platform_settings(db.pool)

        assert isinstance(stored, svc.StoredPlatformSettings)
        assert {field: getattr(stored.llm, field) for field in _LLM_FIELDS} == {
            "provider": "vllm",
            "infomaniak_model": "Qwen/Qwen3.5-397B-A17B-FP8",
            "vllm_model": "org/served-model",
            "anthropic_model": None,
            "openai_model": "gpt-4o",
        }
        assert stored.limits.model_dump() == {
            "max_tool_calls_per_message": 7,
            "max_pending_confirmations": 4,
            "confirmation_timeout_s": 120,
            "max_message_length": 5000,
            "max_context_messages": 30,
        }

    async def test_scoped_settings_load_limits_is_a_platform_limits_model(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        from admino.models import PlatformLimits

        _platform(db)

        stored = await svc.load_platform_settings(db.pool)

        assert isinstance(stored.limits, PlatformLimits)


class TestLoadPlatformDefaults:
    """GH-160: the row's files, retention and security columns are read too."""

    async def test_scoped_settings_load_reads_every_platform_default(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _platform(db, **_CUSTOM_COLUMNS)

        stored = await svc.load_platform_settings(db.pool)

        assert {name: _section(stored, name) for name in _DEFAULT_SECTIONS} == _CUSTOM_SECTIONS

    async def test_scoped_settings_load_default_row_reads_as_the_section_defaults(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """A row that only took migration 0014's column defaults."""
        _platform(db)

        stored = await svc.load_platform_settings(db.pool)

        assert {name: _section(stored, name) for name in _DEFAULT_SECTIONS} == _SECTION_DEFAULTS

    async def test_scoped_settings_load_sections_are_their_models(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        from admino.models import PlatformFiles, PlatformRetention, PlatformSecurity

        _platform(db)

        stored = await svc.load_platform_settings(db.pool)

        assert isinstance(stored.files, PlatformFiles)
        assert isinstance(stored.retention, PlatformRetention)
        assert isinstance(stored.security, PlatformSecurity)


# ---------------------------------------------------------------------------
# 6b. The in-process cache (GH-160)
# ---------------------------------------------------------------------------


class TestPlatformCache:
    """current_platform_settings answers from the cache; a miss reads the row once;
    load_platform_settings always reads and replaces the cache."""

    async def test_scoped_settings_current_hit_issues_no_query(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cached = _stored(svc)
        monkeypatch.setattr(svc, "_platform_cache", cached)
        _platform(db)

        result = await svc.current_platform_settings(db.pool)

        assert result is cached
        assert db.calls == []

    async def test_scoped_settings_current_miss_reads_the_row_once_and_caches_it(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(svc, "_platform_cache", None)
        _platform(db, llm_provider="vllm", **_CUSTOM_COLUMNS)

        first = await svc.current_platform_settings(db.pool)
        second = await svc.current_platform_settings(db.pool)

        assert isinstance(first, svc.StoredPlatformSettings)
        assert first.llm.provider == "vllm"
        assert first.limits.model_dump() == _STORED_LIMITS
        assert {name: _section(first, name) for name in _DEFAULT_SECTIONS} == _CUSTOM_SECTIONS
        assert second == first
        assert svc._platform_cache == first
        call = _one(db.calls)
        assert call.method == "fetchrow"
        assert re.search(r"\bfrom platform_settings\b", call.normalized)

    async def test_scoped_settings_current_without_a_row_raises_and_keeps_the_cache_empty(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(svc, "_platform_cache", None)

        with pytest.raises(RuntimeError):
            await svc.current_platform_settings(db.pool)

        assert svc._platform_cache is None

    async def test_scoped_settings_current_reads_through_a_connection(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The executor may be a connection (inside another service's transaction)."""
        monkeypatch.setattr(svc, "_platform_cache", None)
        _platform(db)

        async with db.pool.acquire() as conn:
            result = await svc.current_platform_settings(conn)

        assert result.limits.model_dump() == _STORED_LIMITS
        assert _one(db.calls).via == conn.name
        assert svc._platform_cache == result

    async def test_scoped_settings_load_always_reads_and_replaces_the_cache(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A primed (stale) cache doesn't stop the read; the cache then holds the row."""
        monkeypatch.setattr(svc, "_platform_cache", _stored(svc))
        _platform(db, llm_provider="vllm", render_dpi=300)

        loaded = await svc.load_platform_settings(db.pool)

        assert (loaded.llm.provider, loaded.files.render_dpi) == ("vllm", 300)
        assert _one(db.calls).method == "fetchrow"
        assert svc._platform_cache == loaded

    async def test_scoped_settings_current_after_load_issues_no_query(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(svc, "_platform_cache", _stored(svc))
        _platform(db, llm_provider="vllm")
        loaded = await svc.load_platform_settings(db.pool)
        calls = len(db.calls)

        current = await svc.current_platform_settings(db.pool)

        assert current == loaded
        assert len(db.calls) == calls


class TestApplyPlatformSettings:
    """The stored provider, four models and five limits replace the config's; nothing else."""

    def test_scoped_settings_apply_overlays_the_llm_and_the_limits(self, svc: ModuleType) -> None:
        config = _config()

        result = svc.apply_platform_settings(config, _stored(svc))

        assert type(result) is AppConfig
        assert {field: getattr(result.llm, field) for field in _LLM_FIELDS} == {
            "provider": "openai",
            "infomaniak_model": None,
            "vllm_model": "org/served-model",
            "anthropic_model": None,
            "openai_model": "gpt-4.1",
        }
        assert result.limits.model_dump() == {
            "max_tool_calls_per_message": 7,
            "max_pending_confirmations": 4,
            "confirmation_timeout_s": 120,
            "max_message_length": 5000,
            "max_context_messages": 30,
        }

    def test_scoped_settings_apply_keeps_the_other_llm_fields(self, svc: ModuleType) -> None:
        config = _config()

        result = svc.apply_platform_settings(config, _stored(svc))

        assert (
            result.llm.timeout_s,
            result.llm.vllm_base_url,
            result.llm.vllm_max_model_len,
            result.llm.max_response_tokens,
        ) == (77, "http://vllm-test:8000/v1", 4096, 1234)

    def test_scoped_settings_apply_keeps_every_other_section(self, svc: ModuleType) -> None:
        config = _config()

        result = svc.apply_platform_settings(config, _stored(svc))

        assert result.server == config.server
        assert result.egress == config.egress
        assert result.database == config.database
        assert (result.log_level, result.log_format) == (config.log_level, config.log_format)

    def test_scoped_settings_apply_leaves_the_input_config_unchanged(self, svc: ModuleType) -> None:
        config = _config()
        before = config.model_dump()

        svc.apply_platform_settings(config, _stored(svc))

        assert config.model_dump() == before


class TestUpdatePlatformLlm:
    """The Super Admin changes the platform LLM through update_platform_settings with an
    llm patch (GH-160; update_platform_llm is gone); each change is audited by field
    name, as in #159."""

    async def test_scoped_settings_update_llm_changes_only_the_given_fields(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        before = copy.deepcopy(_platform(db))
        admin = _actor(db, "super_admin")

        result = await svc.update_platform_settings(
            db.pool,
            actor=admin,
            patch=_llm_patch(provider="infomaniak", infomaniak_model="mistralai/Small-3.2"),
            ip=_IP,
        )

        row = db.platform_row()
        assert row is not None
        assert _platform_llm(row) == {
            **_platform_llm(before),
            "provider": "infomaniak",
            "infomaniak_model": "mistralai/Small-3.2",
        }
        assert _platform_limits(row) == _platform_limits(before)
        assert isinstance(result, svc.StoredPlatformSettings)
        assert (result.llm.provider, result.llm.infomaniak_model) == (
            "infomaniak",
            "mistralai/Small-3.2",
        )
        assert result.llm.anthropic_model == "claude-sonnet-4-6"

    async def test_scoped_settings_update_llm_locks_the_row_in_one_transaction(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _platform(db)
        admin = _actor(db, "super_admin")

        await svc.update_platform_settings(
            db.pool, actor=admin, patch=_llm_patch(provider="vllm"), ip=_IP
        )

        _assert_locked_in_one_transaction(db, "platform_settings")

    async def test_scoped_settings_update_llm_records_the_exact_audit_event(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """platform.settings_change: the Super Admin, no org, no target, the client IP,
        {"provider": True}."""
        _platform(db)
        admin = _actor(db, "super_admin")

        await svc.update_platform_settings(
            db.pool, actor=admin, patch=_llm_patch(provider="vllm"), ip=_IP
        )

        row = _one(db.audit)
        assert row["action"] == "platform.settings_change"
        assert (row["actor_kind"], _uuid(row["actor_user_id"])) == ("super_admin", admin.user_id)
        assert row["org_id"] is None
        assert (row["target_type"], row["target_ids"]) == (None, [])
        assert row["ip"] == _IP
        assert row["metadata"] == {"provider": True}

    async def test_scoped_settings_update_llm_audit_names_only_the_changed_fields(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _platform(db)
        admin = _actor(db, "super_admin")

        await svc.update_platform_settings(
            db.pool,
            actor=admin,
            patch=_llm_patch(
                provider="anthropic",
                anthropic_model="claude-opus-4-1",
                openai_model="gpt-4o",
                vllm_model="org/other-model",
            ),
            ip=_IP,
        )

        metadata = _one(db.audit)["metadata"]
        assert metadata == {"anthropic_model": True, "vllm_model": True}
        assert all(value is True for value in metadata.values())

    async def test_scoped_settings_update_llm_noop_records_nothing(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        row = copy.deepcopy(_platform(db))
        admin = _actor(db, "super_admin")

        await svc.update_platform_settings(
            db.pool,
            actor=admin,
            patch=_llm_patch(provider="anthropic", anthropic_model="claude-sonnet-4-6"),
            ip=_IP,
        )

        assert db.audit == []
        current = db.platform_row()
        assert current is not None
        assert _platform_llm(current) == _platform_llm(row)
        assert current == row
        assert _platform_updates(db) == []

    async def test_scoped_settings_update_llm_audit_failure_rolls_the_change_back(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cached = _stored(svc)
        monkeypatch.setattr(svc, "_platform_cache", cached)
        _platform(db)
        admin = _actor(db, "super_admin")
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await svc.update_platform_settings(
                db.pool, actor=admin, patch=_llm_patch(provider="openai"), ip=_IP
            )

        assert _state(db) == before
        assert svc._platform_cache is cached

    async def test_scoped_settings_update_llm_replaces_the_cache(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(svc, "_platform_cache", _stored(svc))
        _platform(db)
        admin = _actor(db, "super_admin")

        result = await svc.update_platform_settings(
            db.pool, actor=admin, patch=_llm_patch(provider="vllm"), ip=_IP
        )

        assert result.llm.provider == "vllm"
        assert svc._platform_cache == result
        assert result == await svc.load_platform_settings(db.pool)

    async def test_scoped_settings_update_llm_audit_row_holds_no_provider_or_model(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _platform(db)
        admin = _actor(db, "super_admin")

        await svc.update_platform_settings(
            db.pool,
            actor=admin,
            patch=_llm_patch(provider="infomaniak", infomaniak_model=_MODEL_MARKER),
            ip=_IP,
        )

        row = _one(db.audit)
        stored = json.dumps(row, default=str).lower()
        assert "zephyrmarker" not in stored
        assert all(value is True for value in row["metadata"].values())
        assert "infomaniak" not in json.dumps(list(row["metadata"].values()))


# ---------------------------------------------------------------------------
# 6d. update_platform_settings: the limits, files, retention and security sections (GH-160)
# ---------------------------------------------------------------------------


class TestUpdatePlatformSections:
    """Each int section: only the changed fields are written, the stored result is cached
    and returned, and one old/new event names the changed fields."""

    @pytest.mark.parametrize(("section", "patch", "changed"), _SECTION_CHANGES)
    async def test_scoped_settings_update_section_stores_the_patch_merged_into_the_row(
        self,
        svc: ModuleType,
        db: FakeDb,
        section: str,
        patch: dict[str, int],
        changed: dict[str, tuple[int, int]],
    ) -> None:
        before = _without_updated_at(copy.deepcopy(_platform(db, updated_at=_OLD)))
        admin = _actor(db, "super_admin")

        await svc.update_platform_settings(
            db.pool, actor=admin, patch=_settings_patch(**{section: patch}), ip=_IP
        )

        row = db.platform_row()
        assert _without_updated_at(row) == {**before, **_new_values(changed)}
        assert row is not None
        assert row["updated_at"] > _OLD

    @pytest.mark.parametrize(("section", "patch", "changed"), _SECTION_CHANGES)
    async def test_scoped_settings_update_section_binds_only_the_changed_values(
        self,
        svc: ModuleType,
        db: FakeDb,
        section: str,
        patch: dict[str, int],
        changed: dict[str, tuple[int, int]],
    ) -> None:
        """One UPDATE; a field given with its stored value is no change and isn't written
        (its parameter is NULL, which keeps the stored column)."""
        _platform(db)
        admin = _actor(db, "super_admin")

        await svc.update_platform_settings(
            db.pool, actor=admin, patch=_settings_patch(**{section: patch}), ip=_IP
        )

        call = _one(_platform_updates(db))
        bound = [arg for arg in call.args if arg is not None and not isinstance(arg, bool)]
        assert sorted(bound) == sorted(_new_values(changed).values())

    @pytest.mark.parametrize(("section", "patch", "changed"), _SECTION_CHANGES)
    async def test_scoped_settings_update_section_returns_and_caches_the_stored_settings(
        self,
        svc: ModuleType,
        db: FakeDb,
        monkeypatch: pytest.MonkeyPatch,
        section: str,
        patch: dict[str, int],
        changed: dict[str, tuple[int, int]],
    ) -> None:
        monkeypatch.setattr(svc, "_platform_cache", None)
        _platform(db)
        admin = _actor(db, "super_admin")

        result = await svc.update_platform_settings(
            db.pool, actor=admin, patch=_settings_patch(**{section: patch}), ip=_IP
        )

        assert isinstance(result, svc.StoredPlatformSettings)
        assert _section(result, section) == {
            **_STORED_SECTIONS[section],
            **_new_values(changed),
        }
        assert svc._platform_cache == result
        assert result == await svc.load_platform_settings(db.pool)

    @pytest.mark.parametrize(("section", "patch", "changed"), _SECTION_CHANGES)
    async def test_scoped_settings_update_section_records_one_old_new_event(
        self,
        svc: ModuleType,
        db: FakeDb,
        section: str,
        patch: dict[str, int],
        changed: dict[str, tuple[int, int]],
    ) -> None:
        """platform.settings_change: the Super Admin, no org, no target, the client IP,
        ``<field>_old`` / ``<field>_new`` for each changed field only."""
        _platform(db)
        admin = _actor(db, "super_admin")

        await svc.update_platform_settings(
            db.pool, actor=admin, patch=_settings_patch(**{section: patch}), ip=_IP
        )

        row = _one(db.audit)
        assert row["action"] == "platform.settings_change"
        assert (row["actor_kind"], _uuid(row["actor_user_id"])) == ("super_admin", admin.user_id)
        assert row["org_id"] is None
        assert (row["target_type"], row["target_ids"]) == (None, [])
        assert row["ip"] == _IP
        assert row["metadata"] == _old_new(changed)

    @pytest.mark.parametrize(("section", "patch", "changed"), _SECTION_CHANGES)
    async def test_scoped_settings_update_section_locks_the_row_in_one_transaction(
        self,
        svc: ModuleType,
        db: FakeDb,
        section: str,
        patch: dict[str, int],
        changed: dict[str, tuple[int, int]],
    ) -> None:
        _platform(db)
        admin = _actor(db, "super_admin")

        await svc.update_platform_settings(
            db.pool, actor=admin, patch=_settings_patch(**{section: patch}), ip=_IP
        )

        _assert_locked_in_one_transaction(db, "platform_settings")

    @pytest.mark.parametrize(("section", "patch", "changed"), _SECTION_CHANGES)
    async def test_scoped_settings_update_section_noop_writes_nothing(
        self,
        svc: ModuleType,
        db: FakeDb,
        section: str,
        patch: dict[str, int],
        changed: dict[str, tuple[int, int]],
    ) -> None:
        """The patch repeats the stored values: no UPDATE, no sessions statement, no audit
        row; the stored settings are returned."""
        _platform(db)
        admin = _actor(db, "super_admin")
        _super_admin_sessions(db, admin)
        stored = _STORED_SECTIONS[section]
        noop = {field: stored[field] for field in patch}
        before = _state(db)
        sessions_before = copy.deepcopy(db.sessions)

        result = await svc.update_platform_settings(
            db.pool, actor=admin, patch=_settings_patch(**{section: noop}), ip=_IP
        )

        assert _platform_updates(db) == []
        assert _session_updates(db) == []
        assert _state(db) == before
        assert db.sessions == sessions_before
        assert _section(result, section) == stored

    @pytest.mark.parametrize(("section", "patch", "changed"), _SECTION_CHANGES)
    async def test_scoped_settings_update_section_audit_failure_changes_nothing(
        self,
        svc: ModuleType,
        db: FakeDb,
        monkeypatch: pytest.MonkeyPatch,
        section: str,
        patch: dict[str, int],
        changed: dict[str, tuple[int, int]],
    ) -> None:
        cached = _stored(svc)
        monkeypatch.setattr(svc, "_platform_cache", cached)
        _platform(db)
        admin = _actor(db, "super_admin")
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await svc.update_platform_settings(
                db.pool, actor=admin, patch=_settings_patch(**{section: patch}), ip=_IP
            )

        assert _state(db) == before
        assert svc._platform_cache is cached

    async def test_scoped_settings_update_replaces_the_cache_only_after_the_commit(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """While the transaction is still open (its audit INSERT, the last statement
        before the commit) the cache holds the old settings; after it, the new ones."""
        cached = _stored(svc)
        monkeypatch.setattr(svc, "_platform_cache", cached)
        _platform(db)
        admin = _actor(db, "super_admin")
        seen: list[tuple[Any, int]] = []

        def watch(_row: dict[str, Any]) -> bool:
            seen.append((svc._platform_cache, db.open_transactions))
            return False

        db.fail_audit_when = watch

        result = await svc.update_platform_settings(
            db.pool, actor=admin, patch=_settings_patch(files={"render_dpi": 300}), ip=_IP
        )

        assert len(seen) == 1
        assert seen[0][0] is cached
        assert seen[0][1] == 1
        assert result.files.render_dpi == 300
        assert svc._platform_cache == result

    async def test_scoped_settings_update_compares_with_the_locked_row_not_the_cache(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stale cache that already shows the new value doesn't hide the change."""
        monkeypatch.setattr(svc, "_platform_cache", _stored(svc, files={"max_file_size_mb": 200}))
        _platform(db)
        admin = _actor(db, "super_admin")

        await svc.update_platform_settings(
            db.pool, actor=admin, patch=_settings_patch(files={"max_file_size_mb": 200}), ip=_IP
        )

        row = db.platform_row()
        assert row is not None
        assert row["max_file_size_mb"] == 200
        assert _one(db.audit)["metadata"] == {
            "max_file_size_mb_old": 50,
            "max_file_size_mb_new": 200,
        }


class TestUpdatePlatformEvents:
    """One platform.settings_change per changed section, in the order llm, limits, files,
    retention, security; an unchanged section records nothing; any failure undoes all."""

    async def test_scoped_settings_update_records_one_event_per_section_in_order(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        before = _without_updated_at(copy.deepcopy(_platform(db)))
        admin = _actor(db, "super_admin")
        db.open_session(admin.user_id)
        patch = _settings_patch(
            security={"lockout_minutes": 30, "session_idle_timeout_minutes": 90},
            retention={"org_deletion_grace_days": 60},
            files={"render_dpi": 300},
            limits={"max_context_messages": 50},
            llm={"provider": "vllm"},
        )

        await svc.update_platform_settings(db.pool, actor=admin, patch=patch, ip=_IP)

        assert [row["metadata"] for row in db.audit] == [
            {"provider": True},
            {"max_context_messages_old": 30, "max_context_messages_new": 50},
            {"render_dpi_old": 150, "render_dpi_new": 300},
            {"org_deletion_grace_days_old": 30, "org_deletion_grace_days_new": 60},
            {
                "lockout_minutes_old": 15,
                "lockout_minutes_new": 30,
                "session_idle_timeout_minutes_old": 60,
                "session_idle_timeout_minutes_new": 90,
                "sessions_updated": 1,
            },
        ]
        assert {row["action"] for row in db.audit} == {"platform.settings_change"}
        assert all(row["org_id"] is None and row["ip"] == _IP for row in db.audit)
        assert _without_updated_at(db.platform_row()) == {
            **before,
            "llm_provider": "vllm",
            "max_context_messages": 50,
            "render_dpi": 300,
            "org_deletion_grace_days": 60,
            "lockout_minutes": 30,
            "session_idle_timeout_minutes": 90,
        }
        assert len(_platform_updates(db)) == 1
        _assert_locked_in_one_transaction(db, "platform_settings")

    async def test_scoped_settings_update_unchanged_sections_record_no_event(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _platform(db)
        admin = _actor(db, "super_admin")
        _super_admin_sessions(db, admin)
        patch = _settings_patch(
            llm={"provider": "anthropic"},
            limits={"max_tool_calls_per_message": 7},
            files={"max_files_per_message": 25},
            retention={"audit_months": 12},
            security={"rate_limit_per_minute": 20, "session_max_lifetime_hours": 12},
        )

        await svc.update_platform_settings(db.pool, actor=admin, patch=patch, ip=_IP)

        assert [row["metadata"] for row in db.audit] == [
            {"max_files_per_message_old": 10, "max_files_per_message_new": 25}
        ]
        assert _session_updates(db) == []

    async def test_scoped_settings_update_later_event_failure_rolls_everything_back(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The security event fails after the limits and files events were written: the
        row, those events and the re-timed sessions are all rolled back."""
        cached = _stored(svc)
        monkeypatch.setattr(svc, "_platform_cache", cached)
        _platform(db)
        admin = _actor(db, "super_admin")
        _super_admin_sessions(db, admin)
        before = _state(db)
        sessions_before = copy.deepcopy(db.sessions)
        db.fail_audit_when = lambda row: "session_idle_timeout_minutes_new" in row["metadata"]

        with pytest.raises(AuditRecordError):
            await svc.update_platform_settings(
                db.pool,
                actor=admin,
                patch=_settings_patch(
                    limits={"max_context_messages": 50},
                    files={"render_dpi": 300},
                    security=_SESSION_POLICY_CHANGE,
                ),
                ip=_IP,
            )

        assert _state(db) == before
        assert db.sessions == sessions_before
        assert svc._platform_cache is cached

    async def test_scoped_settings_update_audit_rows_hold_field_names_and_ints_only(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """No provider or model value in any row; the int sections hold ints (never a
        bool or a string) under ``<field>_old`` / ``<field>_new`` / ``sessions_updated``."""
        _platform(db)
        admin = _actor(db, "super_admin")

        await svc.update_platform_settings(
            db.pool,
            actor=admin,
            patch=_settings_patch(
                llm={"provider": "infomaniak", "infomaniak_model": _MODEL_MARKER},
                **_ONE_CHANGE,
            ),
            ip=_IP,
        )

        rows = db.audit
        assert len(rows) == 5
        assert "zephyrmarker" not in json.dumps(rows, default=str).lower()
        assert rows[0]["metadata"] == {"provider": True, "infomaniak_model": True}
        values = json.dumps([list(row["metadata"].values()) for row in rows])
        assert "infomaniak" not in values
        for row in rows[1:]:
            metadata = row["metadata"]
            assert all(type(value) is int for value in metadata.values()), metadata
            assert all(
                re.fullmatch(r"[a-z_]+_(?:old|new)|sessions_updated", key) for key in metadata
            ), metadata


# (stored trash columns, retention patch): the merged minimum exceeds the maximum.
_INVALID_TRASH = [
    pytest.param({"trash_max_days": 30}, {"trash_min_days": 60}, id="min-above-the-stored-max"),
    pytest.param({"trash_min_days": 40}, {"trash_max_days": 20}, id="max-below-the-stored-min"),
    pytest.param({}, {"trash_min_days": 50, "trash_max_days": 10}, id="both-given"),
]


class TestRetentionMergedValidation:
    """trash_min_days <= trash_max_days is checked on the patch merged into the stored
    row, before any write."""

    @pytest.mark.parametrize(("stored", "patch"), _INVALID_TRASH)
    async def test_scoped_settings_update_trash_min_above_max_is_refused_before_any_write(
        self,
        svc: ModuleType,
        db: FakeDb,
        monkeypatch: pytest.MonkeyPatch,
        stored: dict[str, int],
        patch: dict[str, int],
    ) -> None:
        """InvalidPlatformSettingsError (a ValueError); no UPDATE, no sessions statement,
        no audit row, the cache unchanged, even with valid changes in other sections."""
        cached = _stored(svc)
        monkeypatch.setattr(svc, "_platform_cache", cached)
        _platform(db, **stored)
        admin = _actor(db, "super_admin")
        _super_admin_sessions(db, admin)
        before = _state(db)
        sessions_before = copy.deepcopy(db.sessions)

        with pytest.raises(svc.InvalidPlatformSettingsError) as caught:
            await svc.update_platform_settings(
                db.pool,
                actor=admin,
                patch=_settings_patch(
                    llm={"provider": "vllm"},
                    files={"render_dpi": 300},
                    retention=patch,
                    security=_SESSION_POLICY_CHANGE,
                ),
                ip=_IP,
            )

        assert isinstance(caught.value, ValueError)
        assert _platform_updates(db) == []
        assert _session_updates(db) == []
        assert _state(db) == before
        assert db.sessions == sessions_before
        assert svc._platform_cache is cached

    async def test_scoped_settings_update_trash_min_equal_to_max_is_accepted(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _platform(db, trash_max_days=30)
        admin = _actor(db, "super_admin")

        result = await svc.update_platform_settings(
            db.pool, actor=admin, patch=_settings_patch(retention={"trash_min_days": 30}), ip=_IP
        )

        row = db.platform_row()
        assert row is not None
        assert (row["trash_min_days"], row["trash_max_days"]) == (30, 30)
        assert (result.retention.trash_min_days, result.retention.trash_max_days) == (30, 30)
        assert _one(db.audit)["metadata"] == {"trash_min_days_old": 0, "trash_min_days_new": 30}

    async def test_scoped_settings_update_trash_bounds_checked_on_the_merged_values(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """A new minimum above the stored maximum is fine when the same patch raises the
        maximum."""
        _platform(db, trash_max_days=30)
        admin = _actor(db, "super_admin")

        await svc.update_platform_settings(
            db.pool,
            actor=admin,
            patch=_settings_patch(retention={"trash_min_days": 60, "trash_max_days": 80}),
            ip=_IP,
        )

        row = db.platform_row()
        assert row is not None
        assert (row["trash_min_days"], row["trash_max_days"]) == (60, 80)
        assert _one(db.audit)["metadata"] == {
            "trash_min_days_old": 0,
            "trash_min_days_new": 60,
            "trash_max_days_old": 30,
            "trash_max_days_new": 80,
        }


# ---------------------------------------------------------------------------
# 6e. Open Super Admin sessions follow a session-policy change (GH-160)
# ---------------------------------------------------------------------------


class TestSuperAdminSessionsFollowThePolicy:
    """A changed idle timeout or lifetime reaches every open Super Admin session in the
    same transaction; members' sessions keep theirs."""

    async def test_scoped_settings_session_policy_change_retimes_every_super_admin_session(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _platform(db)
        admin = _actor(db, "super_admin")
        tokens, member_token = _super_admin_sessions(db, admin)
        member_before = copy.deepcopy(db.session(member_token))

        await svc.update_platform_settings(
            db.pool, actor=admin, patch=_settings_patch(security=_SESSION_POLICY_CHANGE), ip=_IP
        )

        for token in tokens:
            row = db.session(token)
            assert row["idle_timeout_minutes"] == 30
            assert row["expires_at"] == row["created_at"] + timedelta(hours=4)
        assert db.session(member_token) == member_before

    async def test_scoped_settings_session_policy_change_counts_the_sessions(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _platform(db)
        admin = _actor(db, "super_admin")
        _super_admin_sessions(db, admin)

        await svc.update_platform_settings(
            db.pool, actor=admin, patch=_settings_patch(security=_SESSION_POLICY_CHANGE), ip=_IP
        )

        assert _one(db.audit)["metadata"] == {
            "session_idle_timeout_minutes_old": 60,
            "session_idle_timeout_minutes_new": 30,
            "session_max_lifetime_hours_old": 12,
            "session_max_lifetime_hours_new": 4,
            "sessions_updated": 3,
        }

    @pytest.mark.parametrize(
        ("change", "policy"),
        [
            pytest.param({"session_idle_timeout_minutes": 90}, (90, 12), id="idle-only"),
            pytest.param({"session_max_lifetime_hours": 24}, (60, 24), id="lifetime-only"),
        ],
    )
    async def test_scoped_settings_one_session_field_applies_the_whole_new_policy(
        self, svc: ModuleType, db: FakeDb, change: dict[str, int], policy: tuple[int, int]
    ) -> None:
        """$1 = the new idle timeout, $2 = the new lifetime (the stored one when unchanged)."""
        _platform(db)
        admin = _actor(db, "super_admin")
        tokens, _ = _super_admin_sessions(db, admin)
        idle, hours = policy

        await svc.update_platform_settings(
            db.pool, actor=admin, patch=_settings_patch(security=change), ip=_IP
        )

        assert _one(_session_updates(db)).args == policy
        for token in tokens:
            row = db.session(token)
            assert row["idle_timeout_minutes"] == idle
            assert row["expires_at"] == row["created_at"] + timedelta(hours=hours)
        assert _one(db.audit)["metadata"]["sessions_updated"] == 3

    async def test_scoped_settings_session_statement_shares_the_update_transaction(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _platform(db)
        admin = _actor(db, "super_admin")
        _super_admin_sessions(db, admin)

        await svc.update_platform_settings(
            db.pool, actor=admin, patch=_settings_patch(security=_SESSION_POLICY_CHANGE), ip=_IP
        )

        statement = _one(_session_updates(db))
        update = _one(_platform_updates(db))
        audit = _one(db.matching(r"^insert into audit_events\b"))
        assert statement.tx is not None
        assert statement.tx == update.tx == audit.tx
        assert (statement.tx, "commit") in db.transactions

    async def test_scoped_settings_other_security_change_leaves_the_sessions_alone(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """No session field changed: no sessions statement, no ``sessions_updated``."""
        _platform(db)
        admin = _actor(db, "super_admin")
        _super_admin_sessions(db, admin)
        sessions_before = copy.deepcopy(db.sessions)

        await svc.update_platform_settings(
            db.pool,
            actor=admin,
            patch=_settings_patch(security={"lockout_minutes": 30, "rate_limit_per_minute": 60}),
            ip=_IP,
        )

        assert _session_updates(db) == []
        assert db.sessions == sessions_before
        assert "sessions_updated" not in _one(db.audit)["metadata"]

    async def test_scoped_settings_unchanged_session_policy_writes_nothing(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _platform(db)
        admin = _actor(db, "super_admin")
        _super_admin_sessions(db, admin)
        sessions_before = copy.deepcopy(db.sessions)

        await svc.update_platform_settings(
            db.pool,
            actor=admin,
            patch=_settings_patch(
                security={"session_idle_timeout_minutes": 60, "session_max_lifetime_hours": 12}
            ),
            ip=_IP,
        )

        assert _session_updates(db) == []
        assert _platform_updates(db) == []
        assert db.audit == []
        assert db.sessions == sessions_before

    async def test_scoped_settings_session_policy_change_without_super_admin_sessions(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """``sessions_updated`` is 0; a member's session is untouched."""
        _platform(db)
        admin = _actor(db, "super_admin")
        member_token = db.open_session(db.add_account(role="editor"))
        member_before = copy.deepcopy(db.session(member_token))

        await svc.update_platform_settings(
            db.pool, actor=admin, patch=_settings_patch(security=_SESSION_POLICY_CHANGE), ip=_IP
        )

        assert _one(db.audit)["metadata"]["sessions_updated"] == 0
        assert db.session(member_token) == member_before

    async def test_scoped_settings_super_admin_session_older_than_the_new_lifetime_ends(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        from admino import sessions

        _platform(db)
        admin = _actor(db, "super_admin")
        token = db.open_session(admin.user_id)
        row = db.session(token)
        row["created_at"] = datetime.now(UTC) - timedelta(hours=5)
        row["expires_at"] = row["created_at"] + timedelta(hours=12)
        assert await sessions.resolve_session(db.pool, token) is not None

        await svc.update_platform_settings(
            db.pool,
            actor=admin,
            patch=_settings_patch(security={"session_max_lifetime_hours": 4}),
            ip=_IP,
        )

        assert db.session(token)["expires_at"] <= datetime.now(UTC)
        assert await sessions.resolve_session(db.pool, token) is None

    async def test_scoped_settings_super_admin_session_idle_past_the_new_timeout_ends(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Seen 40 minutes ago: live under 60 minutes, gone under 30; a member seen as
        long ago keeps their session."""
        from admino import sessions

        _platform(db)
        admin = _actor(db, "super_admin")
        token = db.open_session(admin.user_id, last_seen_ago=timedelta(minutes=40))
        member_token = db.open_session(
            db.add_account(role="editor"), last_seen_ago=timedelta(minutes=40)
        )

        await svc.update_platform_settings(
            db.pool,
            actor=admin,
            patch=_settings_patch(security={"session_idle_timeout_minutes": 30}),
            ip=_IP,
        )

        assert db.session(token)["idle_timeout_minutes"] == 30
        assert await sessions.resolve_session(db.pool, token) is None
        assert await sessions.resolve_session(db.pool, member_token) is not None


# ---------------------------------------------------------------------------
# 6f. session_policy_for (GH-160: moved here from sessions)
# ---------------------------------------------------------------------------


class TestSessionPolicyFor:
    """Members: the org default (until #169); Super Admins: the stored platform policy."""

    async def test_scoped_settings_policy_for_member_is_the_org_default_without_a_query(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from admino import sessions

        monkeypatch.setattr(svc, "_platform_cache", None)

        policy = await svc.session_policy_for(db.pool, "member")

        assert policy is sessions.DEFAULT_ORG_SESSION_POLICY
        assert db.calls == []

    async def test_scoped_settings_policy_for_member_reads_the_org_default_at_call_time(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from admino import sessions

        custom = sessions.SessionPolicy(idle_timeout_minutes=20, max_lifetime_hours=2)
        monkeypatch.setattr(sessions, "DEFAULT_ORG_SESSION_POLICY", custom)

        assert await svc.session_policy_for(db.pool, "member") is custom

    async def test_scoped_settings_policy_for_super_admin_is_the_cached_platform_policy(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from admino import sessions

        stored = _stored(
            svc,
            security={"session_idle_timeout_minutes": 45, "session_max_lifetime_hours": 8},
        )
        monkeypatch.setattr(svc, "_platform_cache", stored)

        policy = await svc.session_policy_for(db.pool, "super_admin")

        assert type(policy) is sessions.SessionPolicy
        assert (policy.idle_timeout_minutes, policy.max_lifetime_hours) == (45, 8)
        assert db.calls == []

    async def test_scoped_settings_policy_for_super_admin_reads_the_row_on_a_cache_miss(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(svc, "_platform_cache", None)
        _platform(db, session_idle_timeout_minutes=90, session_max_lifetime_hours=24)

        policy = await svc.session_policy_for(db.pool, "super_admin")

        assert (policy.idle_timeout_minutes, policy.max_lifetime_hours) == (90, 24)
        assert _one(db.calls).method == "fetchrow"

    async def test_scoped_settings_policy_for_super_admin_follows_an_update(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """After a change the next Super Admin login gets the new policy, from the cache."""
        _platform(db)
        admin = _actor(db, "super_admin")
        await svc.update_platform_settings(
            db.pool,
            actor=admin,
            patch=_settings_patch(
                security={"session_idle_timeout_minutes": 120, "session_max_lifetime_hours": 48}
            ),
            ip=_IP,
        )
        calls = len(db.calls)

        policy = await svc.session_policy_for(db.pool, "super_admin")

        assert (policy.idle_timeout_minutes, policy.max_lifetime_hours) == (120, 48)
        assert len(db.calls) == calls

    @pytest.mark.parametrize(
        "kind", ["admin", "", "Member", "SUPER_ADMIN", "org_admin", "system", None, 1]
    )
    async def test_scoped_settings_policy_for_unknown_kind_raises_without_a_query(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch, kind: Any
    ) -> None:
        monkeypatch.setattr(svc, "_platform_cache", None)
        _platform(db)

        with pytest.raises(ValueError):
            await svc.session_policy_for(db.pool, kind)

        assert db.calls == []


# ---------------------------------------------------------------------------
# 6g. Only the Super Admin changes a platform default (GH-160)
# ---------------------------------------------------------------------------


class TestUpdatePlatformSectionsAuthorization:
    """platform.defaults.manage for every section: a member of any role is refused before
    any statement; nothing is written and the cache is kept."""

    @pytest.mark.parametrize("section", list(_ONE_CHANGE))
    @pytest.mark.parametrize("role", ["org_admin", "editor", "viewer"])
    async def test_scoped_settings_member_cant_update_a_platform_section(
        self,
        svc: ModuleType,
        db: FakeDb,
        monkeypatch: pytest.MonkeyPatch,
        role: str,
        section: str,
    ) -> None:
        cached = _stored(svc)
        monkeypatch.setattr(svc, "_platform_cache", cached)
        _platform(db)
        actor = _actor(db, role)
        _super_admin_sessions(db, _actor(db, "super_admin"))
        before = _state(db)
        sessions_before = copy.deepcopy(db.sessions)

        with pytest.raises(PermissionError):
            await svc.update_platform_settings(
                db.pool,
                actor=actor,
                patch=_settings_patch(**{section: _ONE_CHANGE[section]}),
                ip=_IP,
            )

        assert db.calls == []
        assert _state(db) == before
        assert db.sessions == sessions_before
        assert svc._platform_cache is cached

    @pytest.mark.parametrize("section", list(_ONE_CHANGE))
    async def test_scoped_settings_platform_section_capability_refused_by_can(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch, section: str
    ) -> None:
        """Even the Super Admin is refused before any statement when can() refuses
        platform.defaults.manage."""
        _platform(db)
        admin = _actor(db, "super_admin")
        _CanSpy(monkeypatch, svc, deny=frozenset({Capability.PLATFORM_DEFAULTS_MANAGE}))

        with pytest.raises(PermissionError):
            await svc.update_platform_settings(
                db.pool,
                actor=admin,
                patch=_settings_patch(**{section: _ONE_CHANGE[section]}),
                ip=_IP,
            )

        assert db.calls == []


# ---------------------------------------------------------------------------
# 7. The acceptance criterion: each scope is seeded with defaults after the migration
# ---------------------------------------------------------------------------


class TestEachScopeSeededWithDefaults:
    """Migration 0013's own INSERT statements run against the fake, then the startup seed:
    every org, every user (members of any status and Super Admins) and the platform start
    from their defaults, and nothing is carried over."""

    async def _migrate_and_seed(self, svc: ModuleType, db: FakeDb, config: AppConfig) -> None:
        for statement in _migration_inserts():
            await db.pool.execute(statement)
        await svc.seed_platform_settings(db.pool, config)

    @pytest.fixture()
    def people(self, db: FakeDb) -> list[uuid.UUID]:
        return [
            db.add_account(role="org_admin", org_id=ORG_ID),
            db.add_account(role="viewer", org_id=OTHER_ORG_ID, status="invited", name=None),
            db.add_account(kind="super_admin", role=None),
        ]

    def test_scoped_settings_migration_seeds_orgs_and_users(self) -> None:
        """The migration seeds both tables from their parents (and nothing else)."""
        inserts = [re.sub(r"\s+", " ", statement).lower() for statement in _migration_inserts()]

        assert len(inserts) == 2
        assert any(re.match(r"insert into org_settings\b", s) for s in inserts)
        assert any(re.match(r"insert into user_settings\b", s) for s in inserts)

    async def test_scoped_settings_every_org_has_the_default_row(
        self, svc: ModuleType, db: FakeDb, people: list[uuid.UUID]
    ) -> None:
        third = db.add_org()

        await self._migrate_and_seed(svc, db, _config())

        assert set(db.org_settings) == {ORG_ID, OTHER_ORG_ID, third}
        for org_id in db.org_settings:
            assert db.org_tools(org_id) == _ALL_ON

    async def test_scoped_settings_every_user_has_the_default_row(
        self, svc: ModuleType, db: FakeDb, people: list[uuid.UUID]
    ) -> None:
        await self._migrate_and_seed(svc, db, _config())

        assert set(db.user_settings) == set(people)
        for row in db.user_settings.values():
            assert (row["theme"], row["notifications_enabled"]) == ("light", True)

    async def test_scoped_settings_platform_row_is_seeded_from_the_config(
        self, svc: ModuleType, db: FakeDb, people: list[uuid.UUID]
    ) -> None:
        config = _config()

        await self._migrate_and_seed(svc, db, config)
        stored = await svc.load_platform_settings(db.pool)

        assert stored.llm.provider == config.llm.provider
        assert stored.llm.anthropic_model == config.llm.anthropic_model
        assert stored.limits.model_dump() == config.limits.model_dump()
        # GH-160: the files, retention and security columns take migration 0014's defaults.
        assert {name: _section(stored, name) for name in _DEFAULT_SECTIONS} == _SECTION_DEFAULTS

    async def test_scoped_settings_seeded_scopes_read_as_the_defaults(
        self, svc: ModuleType, db: FakeDb, people: list[uuid.UUID]
    ) -> None:
        await self._migrate_and_seed(svc, db, _config())
        admin, _viewer, super_admin = (_principal(db, user_id) for user_id in people)

        org = await svc.get_org_settings(db.pool, actor=admin)
        mine = await svc.get_user_settings(db.pool, actor=admin)
        platform_admin = await svc.get_user_settings(db.pool, actor=super_admin)
        gate = await svc.all_orgs_tools_gate(db.pool)

        assert _tools(org) == _ALL_ON
        assert mine.model_dump() == _USER_DEFAULTS
        assert platform_admin.model_dump() == _USER_DEFAULTS
        assert dict(gate) == _ALL_ON


# ---------------------------------------------------------------------------
# 8. The org purge removes the org's settings (ON DELETE CASCADE)
# ---------------------------------------------------------------------------


class TestPurgeRemovesSettings:
    """An org's org_settings row and its users' user_settings rows go with the org."""

    async def test_scoped_settings_org_purge_removes_the_org_and_user_rows(
        self, svc: ModuleType, db: FakeDb, tmp_path: Path
    ) -> None:
        from admino import organizations

        admin = _actor(db, "org_admin", OTHER_ORG_ID)
        editor = _actor(db, "editor", ORG_ID)
        await svc.update_org_settings(db.pool, actor=admin, patch=_org_patch(gmail=False), ip=_IP)
        await svc.update_user_settings(
            db.pool, actor=admin, patch=_user_patch({"appearance": {"theme": "dark"}})
        )
        await svc.update_user_settings(
            db.pool, actor=editor, patch=_user_patch({"appearance": {"theme": "system"}})
        )
        db.add_org(
            OTHER_ORG_ID,
            status="pending_deletion",
            purge_after=datetime.now(UTC) - timedelta(minutes=1),
        )
        root = tmp_path / "attachments"
        root.mkdir()

        purged = await organizations.purge_due_orgs(db.pool, attachments_root=root)

        assert purged == 1
        assert OTHER_ORG_ID not in db.org_settings
        assert set(db.user_settings) == {editor.user_id}


# ---------------------------------------------------------------------------
# 9. No content in logs
# ---------------------------------------------------------------------------


class TestNoContentInLogs:
    """No email, name or model name reaches a log record, on success or failure."""

    async def test_scoped_settings_flow_logs_no_content(
        self, svc: ModuleType, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        _platform(db)
        admin = _actor(db, "org_admin", email=_EMAIL_MARKER, name=_NAME_MARKER)
        platform_admin = _actor(db, "super_admin", email="zephyr.marker.sa@example.ch")

        await svc.update_user_settings(
            db.pool, actor=admin, patch=_user_patch({"appearance": {"theme": "dark"}})
        )
        await svc.update_org_settings(db.pool, actor=admin, patch=_org_patch(gmail=False), ip=_IP)
        await svc.update_platform_settings(
            db.pool,
            actor=platform_admin,
            patch=_llm_patch(infomaniak_model=_MODEL_MARKER),
            ip=_IP,
        )
        db.open_session(platform_admin.user_id)
        await svc.update_platform_settings(
            db.pool,
            actor=platform_admin,
            patch=_settings_patch(files={"render_dpi": 300}, security=_SESSION_POLICY_CHANGE),
            ip=_IP,
        )
        await svc.session_policy_for(db.pool, "super_admin")
        with pytest.raises(svc.InvalidPlatformSettingsError):
            await svc.update_platform_settings(
                db.pool,
                actor=platform_admin,
                patch=_settings_patch(
                    llm={"vllm_model": "Zephyrmarker-vllm-3"},
                    retention={"trash_min_days": 80, "trash_max_days": 5},
                ),
                ip=_IP,
            )
        db.fail_audit = True
        with pytest.raises(AuditRecordError):
            await svc.update_platform_settings(
                db.pool,
                actor=platform_admin,
                patch=_llm_patch(openai_model="Zephyrmarker-openai-9"),
                ip=_IP,
            )
        with pytest.raises(PermissionError):
            await svc.update_platform_settings(
                db.pool, actor=admin, patch=_llm_patch(anthropic_model="Zephyrmarker-x"), ip=_IP
            )

        assert "zephyrmarker" not in _log_text(caplog).lower()

    async def test_scoped_settings_task_done_and_reset_log_no_content(
        self,
        svc: ModuleType,
        db: FakeDb,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """GH-35: switching task_done, a reset (with a row and without one) and a refused
        reset log no email or name."""
        caplog.set_level(logging.DEBUG)
        actor = _actor(db, "viewer", email=_EMAIL_MARKER, name=_NAME_MARKER)

        await svc.update_user_settings(
            db.pool, actor=actor, patch=_user_patch({"notifications": {"task_done": True}})
        )
        await svc.reset_user_settings(db.pool, actor=actor)
        await svc.reset_user_settings(db.pool, actor=actor)
        _CanSpy(monkeypatch, svc, deny=frozenset({Capability.ACCOUNT_MANAGE}))
        with pytest.raises(PermissionError):
            await svc.reset_user_settings(db.pool, actor=actor)

        assert "zephyrmarker" not in _log_text(caplog).lower()
