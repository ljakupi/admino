"""Tests for admino.scoped_settings — the platform, org and user settings scopes (GH-159).

The old key/value ``settings`` table is dropped (migration 0013). Each value
now has an owner: ``user_settings`` (each user: theme and notifications),
``org_settings`` (each org: the enabled tool services) and one
``platform_settings`` row (the Super Admin: the LLM provider and models, and
the limits). ``admino.scoped_settings`` is the service behind the three
routes and the startup.

What these tests pin down (the GH-159 implementation contract):
- Surface: ``get_user_settings`` / ``update_user_settings`` /
  ``get_org_settings`` / ``update_org_settings`` / ``all_orgs_tools_gate`` /
  ``seed_platform_settings`` / ``load_platform_settings`` /
  ``update_platform_llm`` are coroutines, ``apply_platform_settings`` is
  pure; ``actor``, ``patch`` and ``ip`` are keyword-only;
  ``StoredPlatformSettings`` (``llm`` + ``limits``) is importable from the
  module; the module imports only access, tenancy, audit_events, models and
  config from admino.
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
- ``update_platform_llm``: the same for ``platform.settings_change`` (actor
  super_admin, no org, no target, metadata ``{<changed field>: True}`` with
  field names only, never a provider or model value).
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

All database calls go to tests/db_fakes.FakeDb (which models migration
0013's columns, defaults, CHECKs, keys and cascades). ``admino.scoped_settings``
is imported per test through the ``svc`` fixture, so each test fails on its
own until the module exists.

Security notes:
- Least privilege: an Editor can't change org settings, an Org Admin can't
  change the platform LLM, and the Super Admin reaches no org's settings.
- Fail closed: every org or platform change shares one transaction with its
  audit event.
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
_USER_DEFAULTS = {"appearance": {"theme": "light"}, "notifications": {"enabled": True}}
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
_ORG_FUNCTIONS = ["get_org_settings", "update_org_settings"]
_USER_FUNCTIONS = ["get_user_settings", "update_user_settings"]
_CAPABILITIES: dict[str, Capability] = {
    "get_user_settings": Capability.ACCOUNT_MANAGE,
    "update_user_settings": Capability.ACCOUNT_MANAGE,
    "get_org_settings": Capability.ORG_SETTINGS_MANAGE,
    "update_org_settings": Capability.ORG_SETTINGS_MANAGE,
    "update_platform_llm": Capability.PLATFORM_DEFAULTS_MANAGE,
}
# (function, role) pairs that must be refused before any statement.
_REFUSED = [
    *(
        pytest.param(name, role, id=f"{name}-{role}")
        for name in _ORG_FUNCTIONS
        for role in ("editor", "viewer", "super_admin")
    ),
    *(
        pytest.param("update_platform_llm", role, id=f"update_platform_llm-{role}")
        for role in ("org_admin", "editor", "viewer")
    ),
]
_ALLOWED = [
    *(pytest.param(name, role, id=f"{name}-{role}") for name in _USER_FUNCTIONS for role in _ROLES),
    *(pytest.param(name, "org_admin", id=f"{name}-org_admin") for name in _ORG_FUNCTIONS),
    pytest.param("update_platform_llm", "super_admin", id="update_platform_llm-super_admin"),
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


def _llm_patch(**fields: str) -> Any:
    from admino.models import SettingsPatchLLM

    return SettingsPatchLLM.model_validate(fields)


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
    assert not overrides
    return svc.StoredPlatformSettings.model_validate({"llm": llm, "limits": limits})


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
    if name == "get_org_settings":
        return await svc.get_org_settings(pool, actor=actor)
    if name == "update_org_settings":
        return await svc.update_org_settings(
            pool, actor=actor, patch=_org_patch(gmail=False), ip=_IP
        )
    assert name == "update_platform_llm"
    return await svc.update_platform_llm(
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
            "update_platform_llm",
        ],
    )
    def test_scoped_settings_function_is_a_coroutine(self, svc: ModuleType, name: str) -> None:
        assert inspect.iscoroutinefunction(getattr(svc, name))

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
            ("get_org_settings", {"actor"}),
            ("update_org_settings", {"actor", "patch", "ip"}),
            ("update_platform_llm", {"actor", "patch", "ip"}),
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
        """access, tenancy, audit_events, models, config: never the server, agent, LLM,
        tools, OAuth, database or permission engine modules."""
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

        assert imported <= {"access", "tenancy", "audit_events", "models", "config"}, imported

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
            await svc.update_platform_llm(
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
        role = "super_admin" if name == "update_platform_llm" else "org_admin"
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
        role = "super_admin" if name == "update_platform_llm" else "org_admin"
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
    """The Super Admin changes the platform LLM; each change is audited by field name."""

    async def test_scoped_settings_update_llm_changes_only_the_given_fields(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        before = copy.deepcopy(_platform(db))
        admin = _actor(db, "super_admin")

        result = await svc.update_platform_llm(
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

        await svc.update_platform_llm(
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

        await svc.update_platform_llm(
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

        await svc.update_platform_llm(
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

        await svc.update_platform_llm(
            db.pool,
            actor=admin,
            patch=_llm_patch(provider="anthropic", anthropic_model="claude-sonnet-4-6"),
            ip=_IP,
        )

        assert db.audit == []
        current = db.platform_row()
        assert current is not None
        assert _platform_llm(current) == _platform_llm(row)

    async def test_scoped_settings_update_llm_audit_failure_rolls_the_change_back(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _platform(db)
        admin = _actor(db, "super_admin")
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await svc.update_platform_llm(
                db.pool, actor=admin, patch=_llm_patch(provider="openai"), ip=_IP
            )

        assert _state(db) == before

    async def test_scoped_settings_update_llm_audit_row_holds_no_provider_or_model(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _platform(db)
        admin = _actor(db, "super_admin")

        await svc.update_platform_llm(
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
        await svc.update_platform_llm(
            db.pool,
            actor=platform_admin,
            patch=_llm_patch(infomaniak_model=_MODEL_MARKER),
            ip=_IP,
        )
        db.fail_audit = True
        with pytest.raises(AuditRecordError):
            await svc.update_platform_llm(
                db.pool,
                actor=platform_admin,
                patch=_llm_patch(openai_model="Zephyrmarker-openai-9"),
                ip=_IP,
            )
        with pytest.raises(PermissionError):
            await svc.update_platform_llm(
                db.pool, actor=admin, patch=_llm_patch(anthropic_model="Zephyrmarker-x"), ip=_IP
            )

        assert "zephyrmarker" not in _log_text(caplog).lower()
