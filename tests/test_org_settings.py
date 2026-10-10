"""Tests for GH-169's org settings service in admino.scoped_settings (contract section 4).

``get_org_settings`` / ``update_org_settings`` grow from the tool switches
(GH-159/162) to the whole Organization -> Settings page, and
``session_policy_for`` gives a member's new session their org's stored policy
instead of the retired code default (``sessions.DEFAULT_ORG_SESSION_POLICY``).

What these tests pin down:
- ``get_org_settings(pool, *, actor)``: ``org.settings.manage`` before any
  query (Editor and Super Admin get ``PermissionError`` and nothing is
  read). The org is the actor's own (a bind parameter). The response holds the
  profile (``organizations.name`` / ``default_response_language``), the
  instructions, the session policy and the trash retention (``org_settings``;
  a missing row reads as the column defaults and nothing is written), the tool
  switches, the read-only ``data_residency`` and plan (``seats``,
  ``storage_quota`` = ``storage_quota_bytes``), and the platform trash bounds,
  with the effective retention = the stored value clamped into them. A missing
  organizations row is a ``LookupError``. Another org's values never show.
- ``update_org_settings(pool, *, actor, patch, ip)``: the capability first; one
  transaction on one connection that locks the org_settings row and the
  organizations row (``FOR UPDATE``). A field counts as changed only when it
  differs from the STORED value (the display name after the model's strip, the
  instructions verbatim); only changed values are written; nothing changed ->
  nothing written or recorded. A CHANGED trash retention outside the platform
  bounds is ``InvalidOrgSettingsError`` (a ValueError, a message without the
  values) before any write; an unchanged out-of-bounds stored value is no
  error. A changed session field re-times every live session of the org's
  users in the same transaction with the merged policy (idle timeout and
  ``expires_at = created_at + lifetime``); another org's and the Super Admin's
  sessions are untouched. One ``org.settings_change`` event per changed
  section, in the order profile, instructions, security, retention, tools, with
  content-free metadata (field names -> True for profile and instructions,
  ``<field>_old`` / ``<field>_new`` ints plus ``sessions_updated`` for
  security, the stored old/new days for retention, bool pairs for tools) and
  the actor, org, target and IP columns. An audit failure rolls back the
  settings, the organizations row and the sessions. The response equals a
  fresh GET.
- Both service functions require ``org.settings.manage`` AND
  ``org.instructions.manage`` (every response carries the instructions): an
  Org Admin refused either one (the check patched to refuse only it) gets
  ``PermissionError`` before any query, even for a tools-only patch; holding
  both, the service asks for both and proceeds.
- ``session_policy_for(executor, kind, org_id=None)``: "member" reads the
  org's stored policy with the contract's one SELECT (a missing row ->
  ``SessionPolicy()``, 60 min / 12 h); "member" without an org id and any
  unknown kind are ``ValueError`` without a query; "super_admin" is unchanged
  (the platform policy; the org id is ignored).

All database calls go to tests/db_fakes.FakeDb (migration 0023's org_settings
columns, defaults and CHECKs included). ``admino.scoped_settings`` is imported
per test through the ``svc`` fixture. The platform trash bounds come from the
platform settings cache, primed per test by tests/conftest.py; a test that
needs other bounds replaces the cached value.

Security notes:
- Least privilege: only the Org Admin reads or changes the org settings, and
  only their own org's (cross-org values never read, never bound).
- Fail closed: a refused or invalid patch and a failed audit write leave every
  table (sessions included) as it was.
- No content in audit rows, SQL text or logs: never the instructions text (nor
  its length), the org name or the language value.
"""

from __future__ import annotations

import copy
import inspect
import json
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from admino.access import Capability, Principal
from admino.audit_events import AuditRecordError
from tests.conftest import default_test_platform_settings
from tests.db_fakes import ORG_ID, ORG_NAME, OTHER_ORG_ID, TOOL_NAMES, FakeDb, norm, plain

if TYPE_CHECKING:
    from types import ModuleType

    from tests.db_fakes import Call

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP = "198.51.100.42"
_GIB = 1024**3
_ALL_ON: dict[str, bool] = dict.fromkeys(TOOL_NAMES, True)
# Content markers: none may reach an audit row, a SQL text or a log line.
_TEXT_MARKER = "Quokkatext169"
_NAME_MARKER = "Quokkaname169"
_STORED_INSTRUCTIONS = "Bestehende Hinweise der Kanzlei.\nBitte förmlich antworten."
_NEW_NAME = f"Kanzlei {_NAME_MARKER} AG"
_NEW_INSTRUCTIONS = f"{_TEXT_MARKER}: Antworte immer auf Deutsch.\n\tMit Tabulator."
_OTHER_NAME = "Fremdorg Beispiel GmbH"
# The member policy read of contract section 4 (FakeDb runs it on its SQL reader).
_POLICY_SQL = (
    "SELECT session_idle_timeout_minutes, session_max_lifetime_hours "
    "FROM org_settings WHERE org_id = $1"
)
_REFUSED_ROLES = ["editor", "super_admin"]

# Org A as _seed_a stores it, read with the platform's default trash bounds (0..90).
_A_RESPONSE: dict[str, Any] = {
    "profile": {"display_name": ORG_NAME, "default_response_language": "de"},
    "instructions": _STORED_INSTRUCTIONS,
    "security": {"session_idle_timeout_minutes": 60, "session_max_lifetime_hours": 12},
    "retention": {"trash_retention_days": 30, "trash_min_days": 0, "trash_max_days": 90},
    "tools": _ALL_ON,
    "data_residency": False,
    "plan": {"seats": 25, "storage_quota": 10 * _GIB},
}
# Org B as _seed_b stores it (every value differs from org A's).
_B_RESPONSE: dict[str, Any] = {
    "profile": {"display_name": _OTHER_NAME, "default_response_language": "it"},
    "instructions": "Fremdorg: nur Italienisch.",
    "security": {"session_idle_timeout_minutes": 20, "session_max_lifetime_hours": 2},
    "retention": {"trash_retention_days": 3, "trash_min_days": 0, "trash_max_days": 90},
    "tools": {**_ALL_ON, "gmail": False, "memory": False},
    "data_residency": True,
    "plan": {"seats": 3, "storage_quota": 777},
}
# A change in every section (against _seed_a).
_FULL_PATCH: dict[str, Any] = {
    "profile": {"display_name": _NEW_NAME, "default_response_language": "fr"},
    "instructions": _NEW_INSTRUCTIONS,
    "security": {"session_idle_timeout_minutes": 30, "session_max_lifetime_hours": 8},
    "retention": {"trash_retention_days": 14},
    "tools": {"gmail": False},
}
# The response sections _FULL_PATCH changes.
_FULL_CHANGE: dict[str, Any] = {
    "profile": {"display_name": _NEW_NAME, "default_response_language": "fr"},
    "instructions": _NEW_INSTRUCTIONS,
    "security": {"session_idle_timeout_minutes": 30, "session_max_lifetime_hours": 8},
    "retention": {"trash_retention_days": 14},
    "tools": {"gmail": False},
}


def _full_events(sessions_updated: int) -> list[dict[str, Any]]:
    """The metadata of _FULL_PATCH's five events, in the contract's order."""
    return [
        {"display_name": True, "default_response_language": True},
        {"instructions": True},
        {
            "session_idle_timeout_minutes_old": 60,
            "session_idle_timeout_minutes_new": 30,
            "session_max_lifetime_hours_old": 12,
            "session_max_lifetime_hours_new": 8,
            "sessions_updated": sessions_updated,
        },
        {"trash_retention_days_old": 30, "trash_retention_days_new": 14},
        {"gmail_old": True, "gmail_new": False},
    ]


# (patch, the response sections it changes, the one event's metadata) against _seed_a,
# without any open session. Each patch changes exactly one section.
_SECTION_ALONE = [
    pytest.param(
        {"profile": {"display_name": _NEW_NAME}},
        {"profile": {"display_name": _NEW_NAME}},
        {"display_name": True},
        id="profile-display-name",
    ),
    pytest.param(
        {"profile": {"default_response_language": "fr"}},
        {"profile": {"default_response_language": "fr"}},
        {"default_response_language": True},
        id="profile-language",
    ),
    pytest.param(
        {"profile": {"display_name": _NEW_NAME, "default_response_language": "it"}},
        {"profile": {"display_name": _NEW_NAME, "default_response_language": "it"}},
        {"display_name": True, "default_response_language": True},
        id="profile-both",
    ),
    pytest.param(
        {"instructions": _NEW_INSTRUCTIONS},
        {"instructions": _NEW_INSTRUCTIONS},
        {"instructions": True},
        id="instructions",
    ),
    pytest.param(
        {"instructions": ""},
        {"instructions": ""},
        {"instructions": True},
        id="instructions-cleared",
    ),
    pytest.param(
        {"security": {"session_idle_timeout_minutes": 30}},
        {"security": {"session_idle_timeout_minutes": 30}},
        {
            "session_idle_timeout_minutes_old": 60,
            "session_idle_timeout_minutes_new": 30,
            "sessions_updated": 0,
        },
        id="security-idle",
    ),
    pytest.param(
        {"security": {"session_max_lifetime_hours": 4}},
        {"security": {"session_max_lifetime_hours": 4}},
        {
            "session_max_lifetime_hours_old": 12,
            "session_max_lifetime_hours_new": 4,
            "sessions_updated": 0,
        },
        id="security-lifetime",
    ),
    pytest.param(
        {"retention": {"trash_retention_days": 14}},
        {"retention": {"trash_retention_days": 14}},
        {"trash_retention_days_old": 30, "trash_retention_days_new": 14},
        id="retention",
    ),
    # A null section and an empty one next to the tools are not given (no event).
    pytest.param(
        {"tools": {"gmail": False, "memory": True}, "profile": None, "security": {}},
        {"tools": {"gmail": False}},
        {"gmail_old": True, "gmail_new": False},
        id="tools-next-to-null-and-empty-sections",
    ),
]


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def svc() -> ModuleType:
    """admino.scoped_settings, imported per test."""
    from admino import scoped_settings

    return scoped_settings


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database with two active orgs (no org_settings rows)."""
    fake = FakeDb()
    fake.add_org(ORG_ID)
    fake.add_org(OTHER_ORG_ID)
    return fake


def _actor(db: FakeDb, role: str, org_id: uuid.UUID = ORG_ID) -> Principal:
    """A stored account with this role (or a Super Admin) and the Principal of its session."""
    if role == "super_admin":
        return Principal(user_id=db.add_account(kind="super_admin", role=None), kind="super_admin")
    user_id = db.add_account(role=role, org_id=org_id)
    return Principal(user_id=user_id, kind="member", org_id=org_id, role=role)


def _patch(body: dict[str, Any]) -> Any:
    """The validated OrgSettingsPatch of this body."""
    from admino.models import OrgSettingsPatch

    return OrgSettingsPatch.model_validate(body)


async def _update(svc: ModuleType, db: FakeDb, actor: Principal, body: dict[str, Any]) -> Any:
    return await svc.update_org_settings(db.pool, actor=actor, patch=_patch(body), ip=_IP)


def _seed_a(db: FakeDb, **settings: Any) -> None:
    """Org A: German, residency off, 25 seats, 10 GiB; an org_settings row with the stored
    instructions and (unless given) the column defaults."""
    db.add_org(
        ORG_ID,
        seats=25,
        data_residency=False,
        storage_quota_bytes=10 * _GIB,
        default_response_language="de",
    )
    settings.setdefault("instructions", _STORED_INSTRUCTIONS)
    db.add_org_settings(ORG_ID, **settings)


def _seed_b(db: FakeDb) -> None:
    """Org B: every value different from org A's (see _B_RESPONSE)."""
    db.add_org(
        OTHER_ORG_ID,
        name=_OTHER_NAME,
        seats=3,
        data_residency=True,
        storage_quota_bytes=777,
        default_response_language="it",
    )
    db.add_org_settings(
        OTHER_ORG_ID,
        instructions="Fremdorg: nur Italienisch.",
        session_idle_timeout_minutes=20,
        session_max_lifetime_hours=2,
        trash_retention_days=3,
        gmail=False,
        memory=False,
    )


def _set_trash_bounds(
    monkeypatch: pytest.MonkeyPatch, svc: ModuleType, low: int, high: int
) -> None:
    """Make the cached platform settings carry these trash bounds (nothing else changes)."""
    data = default_test_platform_settings().model_dump()
    data["retention"] = {**data["retention"], "trash_min_days": low, "trash_max_days": high}
    monkeypatch.setattr(svc, "_platform_cache", svc.StoredPlatformSettings.model_validate(data))


def _set_super_admin_policy(
    monkeypatch: pytest.MonkeyPatch, svc: ModuleType, idle: int, hours: int
) -> None:
    """Make the cached platform settings carry this Super Admin session policy."""
    data = default_test_platform_settings().model_dump()
    data["security"] = {
        **data["security"],
        "session_idle_timeout_minutes": idle,
        "session_max_lifetime_hours": hours,
    }
    monkeypatch.setattr(svc, "_platform_cache", svc.StoredPlatformSettings.model_validate(data))


def _merged(base: dict[str, Any], change: dict[str, Any]) -> dict[str, Any]:
    """``base`` with each section of ``change`` merged in (a dict section key by key)."""
    result = copy.deepcopy(base)
    for key, value in change.items():
        result[key] = {**result[key], **value} if isinstance(value, dict) else value
    return result


def _editable(response: dict[str, Any]) -> dict[str, Any]:
    """The stored (editable) part of a response dump, in _stored_view's shape."""
    return {
        "profile": response["profile"],
        "instructions": response["instructions"],
        "security": response["security"],
        "trash_retention_days": response["retention"]["trash_retention_days"],
        "tools": response["tools"],
    }


def _stored_view(db: FakeDb, org_id: uuid.UUID) -> dict[str, Any]:
    """The org's stored settings (organizations + org_settings rows) in _editable's shape."""
    org = db.orgs[org_id]
    row = db.org_settings_row(org_id)
    assert row is not None, "no org_settings row"
    return {
        "profile": {
            "display_name": org["name"],
            "default_response_language": org["default_response_language"],
        },
        "instructions": row["instructions"],
        "security": {
            "session_idle_timeout_minutes": row["session_idle_timeout_minutes"],
            "session_max_lifetime_hours": row["session_max_lifetime_hours"],
        },
        "trash_retention_days": row["trash_retention_days"],
        "tools": {tool: row[f"{tool}_enabled"] for tool in TOOL_NAMES},
    }


def _one(items: list[Any]) -> Any:
    assert len(items) == 1, items
    return items[0]


def _uuid(value: Any) -> uuid.UUID | None:
    return None if value is None else plain(value)


def _bound(db: FakeDb, value: uuid.UUID) -> bool:
    """True when any recorded statement bound this id (as a UUID or its string)."""
    for call in db.calls:
        for arg in call.args:
            if isinstance(arg, uuid.UUID) and plain(arg) == value:
                return True
            if isinstance(arg, str) and arg == str(value):
                return True
    return False


def _updates(db: FakeDb, table: str) -> list[Call]:
    return db.matching(rf"^update {table}\b")


def _writes(db: FakeDb) -> list[Call]:
    """Every UPDATE or DELETE statement, and every INSERT but the org_settings ensure."""
    return [
        call
        for call in db.matching(r"^(?:insert into|update|delete from)\b")
        if not call.normalized.startswith("insert into org_settings")
    ]


def _changed_values(call: Call) -> list[str]:
    """The non-null values a write binds besides org A's id, as sorted reprs."""
    return sorted(
        repr(arg)
        for arg in call.args
        if arg is not None and not (isinstance(arg, uuid.UUID) and plain(arg) == ORG_ID)
    )


def _strings(value: Any) -> list[str]:
    """Every string (keys included) inside a JSON-like value."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for key, item in value.items() for s in [str(key), *_strings(item)]]
    if isinstance(value, list | tuple):
        return [s for item in value for s in _strings(item)]
    return []


def _log_text(caplog: pytest.LogCaptureFixture) -> str:
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(formatter.format(record) for record in caplog.records)


def _open_org_sessions(db: FakeDb, admin: Principal) -> tuple[list[str], list[str]]:
    """Open live sessions: three of org A (the Org Admin's, an Editor's and another
    Editor's, created two hours ago) and two others (an org B admin's and a Super
    Admin's).

    Returns (org A tokens, other tokens).
    """
    editor = db.add_account(role="editor", org_id=ORG_ID)
    colleague = db.add_account(role="editor", org_id=ORG_ID)
    other = db.add_account(role="org_admin", org_id=OTHER_ORG_ID)
    super_admin = db.add_account(kind="super_admin", role=None)
    mine = [
        db.open_session(admin.user_id),
        db.open_session(editor),
        db.open_session(colleague, created_ago=timedelta(hours=2), expires_in=timedelta(hours=10)),
    ]
    others = [db.open_session(other), db.open_session(super_admin)]
    return mine, others


# ---------------------------------------------------------------------------
# 1. The module surface
# ---------------------------------------------------------------------------


class TestSurface:
    """The new error class and session_policy_for's extended signature."""

    def test_org_settings_invalid_org_settings_error_is_a_value_error(
        self, svc: ModuleType
    ) -> None:
        assert issubclass(svc.InvalidOrgSettingsError, ValueError)

    def test_org_settings_session_policy_for_takes_an_optional_org_id(
        self, svc: ModuleType
    ) -> None:
        """``session_policy_for(executor, kind, org_id=None)``: a positional third parameter."""
        parameters = inspect.signature(svc.session_policy_for).parameters

        assert list(parameters) == ["executor", "kind", "org_id"]
        assert parameters["org_id"].default is None
        assert parameters["org_id"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD


# ---------------------------------------------------------------------------
# 2. get_org_settings
# ---------------------------------------------------------------------------


class TestGetOrgSettings:
    """The Org Admin reads their own org's full settings; nothing is written."""

    @pytest.mark.parametrize("role", _REFUSED_ROLES)
    async def test_org_settings_get_refused_role_raises_before_any_query(
        self, svc: ModuleType, db: FakeDb, role: str
    ) -> None:
        _seed_a(db)
        actor = _actor(db, role)

        with pytest.raises(PermissionError):
            await svc.get_org_settings(db.pool, actor=actor)

        assert db.calls == []

    async def test_org_settings_get_fresh_org_returns_the_full_default_response(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """No org_settings row: the contract's JSON (the column defaults, every tool on),
        and nothing is written."""
        from admino.models import OrgSettingsResponse

        db.add_org(ORG_ID, seats=40, data_residency=False, storage_quota_bytes=5 * _GIB)
        admin = _actor(db, "org_admin")
        before = db.snapshot()

        result = await svc.get_org_settings(db.pool, actor=admin)

        assert isinstance(result, OrgSettingsResponse)
        assert result.model_dump() == {
            "profile": {"display_name": "Treuhand Muster AG", "default_response_language": "en"},
            "instructions": "",
            "security": {"session_idle_timeout_minutes": 60, "session_max_lifetime_hours": 12},
            "retention": {"trash_retention_days": 30, "trash_min_days": 0, "trash_max_days": 90},
            "tools": _ALL_ON,
            "data_residency": False,
            "plan": {"seats": 40, "storage_quota": 5 * _GIB},
        }
        assert db.snapshot() == before
        assert db.org_settings == {}

    async def test_org_settings_get_returns_the_stored_values(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _seed_a(
            db,
            session_idle_timeout_minutes=45,
            session_max_lifetime_hours=24,
            trash_retention_days=14,
            onedrive=False,
        )
        admin = _actor(db, "org_admin")

        result = await svc.get_org_settings(db.pool, actor=admin)

        assert result.model_dump() == _merged(
            _A_RESPONSE,
            {
                "security": {"session_idle_timeout_minutes": 45, "session_max_lifetime_hours": 24},
                "retention": {"trash_retention_days": 14},
                "tools": {"onedrive": False},
            },
        )

    @pytest.mark.parametrize("language", ["de", "fr", "it", "en"])
    async def test_org_settings_get_profile_comes_from_the_organizations_row(
        self, svc: ModuleType, db: FakeDb, language: str
    ) -> None:
        _seed_a(db)
        db.add_org(ORG_ID, name="Kanzlei Profil AG", default_response_language=language)
        admin = _actor(db, "org_admin")

        result = await svc.get_org_settings(db.pool, actor=admin)

        assert result.profile.model_dump() == {
            "display_name": "Kanzlei Profil AG",
            "default_response_language": language,
        }

    @pytest.mark.parametrize("residency", [True, False])
    async def test_org_settings_get_carries_the_read_only_residency_and_plan(
        self, svc: ModuleType, db: FakeDb, residency: bool
    ) -> None:
        """The plan is seats and the storage quota in bytes (no budget: V2)."""
        _seed_a(db)
        db.add_org(ORG_ID, seats=7, storage_quota_bytes=123_456_789, data_residency=residency)
        admin = _actor(db, "org_admin")

        result = await svc.get_org_settings(db.pool, actor=admin)

        dumped = result.model_dump()
        assert (dumped["data_residency"], dumped["plan"]) == (
            residency,
            {"seats": 7, "storage_quota": 123_456_789},
        )

    @pytest.mark.parametrize(
        ("stored", "low", "high", "effective"),
        [
            pytest.param(30, 0, 20, 20, id="above-max-clamped-down"),
            pytest.param(5, 7, 60, 7, id="below-min-clamped-up"),
            pytest.param(14, 7, 60, 14, id="inside"),
            pytest.param(0, 0, 90, 0, id="at-min"),
            pytest.param(90, 0, 90, 90, id="at-max"),
            pytest.param(30, 45, 45, 45, id="single-value-bounds"),
        ],
    )
    async def test_org_settings_get_retention_is_the_stored_value_clamped_into_the_bounds(
        self,
        svc: ModuleType,
        db: FakeDb,
        monkeypatch: pytest.MonkeyPatch,
        stored: int,
        low: int,
        high: int,
        effective: int,
    ) -> None:
        """The platform bounds come along read-only; the stored value is not rewritten."""
        _seed_a(db, trash_retention_days=stored)
        _set_trash_bounds(monkeypatch, svc, low, high)
        admin = _actor(db, "org_admin")

        result = await svc.get_org_settings(db.pool, actor=admin)

        assert result.retention.model_dump() == {
            "trash_retention_days": effective,
            "trash_min_days": low,
            "trash_max_days": high,
        }
        assert db.org_settings_row(ORG_ID)["trash_retention_days"] == stored

    async def test_org_settings_get_without_a_row_clamps_the_default_retention(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The column default (30) is clamped like a stored value: bounds 0..20 show 20."""
        _set_trash_bounds(monkeypatch, svc, 0, 20)
        admin = _actor(db, "org_admin")

        result = await svc.get_org_settings(db.pool, actor=admin)

        assert result.retention.model_dump() == {
            "trash_retention_days": 20,
            "trash_min_days": 0,
            "trash_max_days": 20,
        }
        assert db.org_settings == {}

    async def test_org_settings_get_reads_only_the_actors_org(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Org B holds a different value everywhere; none of them shows, B's id is never
        bound, and the org id is never inlined into the SQL."""
        _seed_a(db)
        _seed_b(db)
        admin = _actor(db, "org_admin", ORG_ID)

        result = await svc.get_org_settings(db.pool, actor=admin)

        assert result.model_dump() == _A_RESPONSE
        assert not _bound(db, OTHER_ORG_ID)
        assert all(str(ORG_ID) not in call.sql for call in db.calls)

    async def test_org_settings_get_each_org_admin_sees_their_own_org(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _seed_a(db)
        _seed_b(db)
        admin_a = _actor(db, "org_admin", ORG_ID)
        admin_b = _actor(db, "org_admin", OTHER_ORG_ID)

        result_a = await svc.get_org_settings(db.pool, actor=admin_a)
        db.calls.clear()
        result_b = await svc.get_org_settings(db.pool, actor=admin_b)

        assert (result_a.model_dump(), result_b.model_dump()) == (_A_RESPONSE, _B_RESPONSE)
        assert not _bound(db, ORG_ID)

    async def test_org_settings_get_without_an_organizations_row_is_a_lookup_error(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """An org id with no organizations row: a generic LookupError (no id in the
        message), and nothing is written."""
        ghost = uuid.uuid4()
        admin = Principal(user_id=uuid.uuid4(), kind="member", org_id=ghost, role="org_admin")
        before = db.snapshot()

        with pytest.raises(LookupError) as caught:
            await svc.get_org_settings(db.pool, actor=admin)

        assert str(ghost) not in str(caught.value)
        assert db.snapshot() == before


# ---------------------------------------------------------------------------
# 3. update_org_settings: what is stored, returned and recorded
# ---------------------------------------------------------------------------


class TestUpdateOrgSettings:
    """Each section alone and all together: stored, returned, one event per section."""

    @pytest.mark.parametrize(("body", "change", "metadata"), _SECTION_ALONE)
    async def test_org_settings_update_one_section_returns_the_change(
        self,
        svc: ModuleType,
        db: FakeDb,
        body: dict[str, Any],
        change: dict[str, Any],
        metadata: dict[str, Any],
    ) -> None:
        _seed_a(db)
        admin = _actor(db, "org_admin")

        result = await _update(svc, db, admin, body)

        assert result.model_dump() == _merged(_A_RESPONSE, change)

    @pytest.mark.parametrize(("body", "change", "metadata"), _SECTION_ALONE)
    async def test_org_settings_update_one_section_stores_only_that_section(
        self,
        svc: ModuleType,
        db: FakeDb,
        body: dict[str, Any],
        change: dict[str, Any],
        metadata: dict[str, Any],
    ) -> None:
        """The organizations and org_settings rows hold the change and nothing else
        changed (residency, seats and quota included)."""
        _seed_a(db)
        admin = _actor(db, "org_admin")
        org_before = copy.deepcopy(db.orgs[ORG_ID])

        await _update(svc, db, admin, body)

        assert _stored_view(db, ORG_ID) == _editable(_merged(_A_RESPONSE, change))
        read_only = ("data_residency", "seats", "storage_quota_bytes", "status")
        assert {k: db.orgs[ORG_ID][k] for k in read_only} == {k: org_before[k] for k in read_only}

    @pytest.mark.parametrize(("body", "change", "metadata"), _SECTION_ALONE)
    async def test_org_settings_update_one_section_records_one_event(
        self,
        svc: ModuleType,
        db: FakeDb,
        body: dict[str, Any],
        change: dict[str, Any],
        metadata: dict[str, Any],
    ) -> None:
        _seed_a(db)
        admin = _actor(db, "org_admin")

        await _update(svc, db, admin, body)

        row = _one(db.audit)
        assert (row["action"], row["metadata"]) == ("org.settings_change", metadata)

    async def test_org_settings_update_all_sections_stores_and_returns_every_change(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _seed_a(db)
        admin = _actor(db, "org_admin")
        expected = _merged(_A_RESPONSE, _FULL_CHANGE)

        result = await _update(svc, db, admin, _FULL_PATCH)

        assert result.model_dump() == expected
        assert _stored_view(db, ORG_ID) == _editable(expected)

    async def test_org_settings_update_all_sections_records_five_events_in_order(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """profile, instructions, security, retention, tools; the security event counts
        the org's re-timed live sessions."""
        _seed_a(db)
        admin = _actor(db, "org_admin")
        _open_org_sessions(db, admin)

        await _update(svc, db, admin, _FULL_PATCH)

        assert [row["action"] for row in db.audit] == ["org.settings_change"] * 5
        assert [row["metadata"] for row in db.audit] == _full_events(sessions_updated=3)

    async def test_org_settings_update_every_event_has_the_actor_org_target_and_ip(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _seed_a(db)
        admin = _actor(db, "org_admin")

        await _update(svc, db, admin, _FULL_PATCH)

        columns = {
            (
                row["actor_kind"],
                _uuid(row["actor_user_id"]),
                _uuid(row["org_id"]),
                row["target_type"],
                tuple(row["target_ids"]),
                row["ip"],
            )
            for row in db.audit
        }
        assert len(db.audit) == 5
        assert columns == {("member", admin.user_id, ORG_ID, "organization", (str(ORG_ID),), _IP)}

    async def test_org_settings_update_without_ip_records_no_ip(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _seed_a(db)
        admin = _actor(db, "org_admin")

        await svc.update_org_settings(
            db.pool, actor=admin, patch=_patch({"instructions": _NEW_INSTRUCTIONS}), ip=None
        )

        assert _one(db.audit)["ip"] is None

    async def test_org_settings_update_metadata_values_are_true_ints_and_bools_only(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """profile and instructions: exactly True per field name; security and retention:
        ints (not bools); tools: bools."""
        _seed_a(db)
        admin = _actor(db, "org_admin")

        await _update(svc, db, admin, _FULL_PATCH)

        profile, instructions, security, retention, tools = (row["metadata"] for row in db.audit)
        assert all(value is True for value in (*profile.values(), *instructions.values()))
        assert all(type(value) is int for value in (*security.values(), *retention.values()))
        assert all(type(value) is bool for value in tools.values())

    async def test_org_settings_update_audit_rows_hold_no_content(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Never the instructions text, the org name or the language value in any audit
        row (metadata, target, anything), and never the instructions' length."""
        _seed_a(db)
        admin = _actor(db, "org_admin")

        await _update(svc, db, admin, _FULL_PATCH)

        text = json.dumps(db.audit, default=str).lower()
        assert _TEXT_MARKER.lower() not in text
        assert _NAME_MARKER.lower() not in text
        assert ORG_NAME.lower() not in text
        values = [s for row in db.audit for s in _strings(row["metadata"])]
        assert "fr" not in values
        assert "de" not in values
        lengths = {len(_NEW_INSTRUCTIONS), len(_STORED_INSTRUCTIONS)}
        assert not lengths & {v for row in db.audit for v in row["metadata"].values()}

    async def test_org_settings_update_display_name_is_stored_stripped(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _seed_a(db)
        admin = _actor(db, "org_admin")

        result = await _update(
            svc, db, admin, {"profile": {"display_name": "   Neue Kanzlei AG   "}}
        )

        assert (db.orgs[ORG_ID]["name"], result.profile.display_name) == (
            "Neue Kanzlei AG",
            "Neue Kanzlei AG",
        )

    async def test_org_settings_update_instructions_are_stored_verbatim(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Not stripped: the stored text plus a trailing newline is a change."""
        _seed_a(db, instructions="Hinweis")
        admin = _actor(db, "org_admin")

        result = await _update(svc, db, admin, {"instructions": "  Hinweis\n"})

        assert (db.org_settings_row(ORG_ID)["instructions"], result.instructions) == (
            "  Hinweis\n",
            "  Hinweis\n",
        )
        assert _one(db.audit)["metadata"] == {"instructions": True}

    async def test_org_settings_update_creates_a_missing_row_from_the_defaults(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """No org_settings row yet: created with the column defaults, then changed."""
        admin = _actor(db, "org_admin")

        await _update(svc, db, admin, {"retention": {"trash_retention_days": 7}})

        row = db.org_settings_row(ORG_ID)
        assert row is not None
        assert {k: row[k] for k in ("instructions", "session_idle_timeout_minutes")} == {
            "instructions": "",
            "session_idle_timeout_minutes": 60,
        }
        assert (row["session_max_lifetime_hours"], row["trash_retention_days"]) == (12, 7)
        assert _one(db.audit)["metadata"] == {
            "trash_retention_days_old": 30,
            "trash_retention_days_new": 7,
        }

    async def test_org_settings_update_response_equals_a_fresh_get(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _seed_a(db)
        admin = _actor(db, "org_admin")

        result = await _update(svc, db, admin, _FULL_PATCH)
        fresh = await svc.get_org_settings(db.pool, actor=admin)

        assert result.model_dump() == fresh.model_dump() == _merged(_A_RESPONSE, _FULL_CHANGE)


# ---------------------------------------------------------------------------
# 4. update_org_settings: only changes count
# ---------------------------------------------------------------------------


class TestUpdateOnlyChanges:
    """A field counts as changed only when it differs from the stored value."""

    async def test_org_settings_update_noop_writes_and_records_nothing(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Every given value equals the stored one (the display name after the strip):
        no UPDATE, no event, every table as it was; the current response comes back."""
        _seed_a(db)
        admin = _actor(db, "org_admin")
        _open_org_sessions(db, admin)
        before = db.snapshot()

        result = await _update(
            svc,
            db,
            admin,
            {
                "profile": {"display_name": f"  {ORG_NAME}  ", "default_response_language": "de"},
                "instructions": _STORED_INSTRUCTIONS,
                "security": {"session_idle_timeout_minutes": 60, "session_max_lifetime_hours": 12},
                "retention": {"trash_retention_days": 30},
                "tools": {"gmail": True, "memory": True},
            },
        )

        assert result.model_dump() == _A_RESPONSE
        assert db.audit == []
        assert _writes(db) == []
        assert db.snapshot() == before

    async def test_org_settings_update_unchanged_fields_get_no_metadata(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Given but unchanged fields and sections record nothing; only the changed ones
        do (the instructions and retention sections here: no event at all)."""
        _seed_a(db)
        admin = _actor(db, "org_admin")

        await _update(
            svc,
            db,
            admin,
            {
                "profile": {"display_name": ORG_NAME, "default_response_language": "fr"},
                "instructions": _STORED_INSTRUCTIONS,
                "security": {"session_idle_timeout_minutes": 30, "session_max_lifetime_hours": 12},
                "retention": {"trash_retention_days": 30},
                "tools": {"gmail": True, "memory": False},
            },
        )

        assert [row["metadata"] for row in db.audit] == [
            {"default_response_language": True},
            {
                "session_idle_timeout_minutes_old": 60,
                "session_idle_timeout_minutes_new": 30,
                "sessions_updated": 0,
            },
            {"memory_old": True, "memory_new": False},
        ]

    async def test_org_settings_update_binds_only_the_changed_values(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """One UPDATE per table; besides the org id, each binds only the changed values
        (the unchanged ones are NULL, which keeps the stored value)."""
        _seed_a(db)
        admin = _actor(db, "org_admin")

        await _update(
            svc,
            db,
            admin,
            {
                "profile": {"display_name": ORG_NAME, "default_response_language": "fr"},
                "instructions": _STORED_INSTRUCTIONS,
                "security": {"session_idle_timeout_minutes": 30, "session_max_lifetime_hours": 12},
                "retention": {"trash_retention_days": 30},
                "tools": {"gmail": True, "memory": False},
            },
        )

        assert _changed_values(_one(_updates(db, "org_settings"))) == sorted(["30", "False"])
        assert _changed_values(_one(_updates(db, "organizations"))) == ["'fr'"]

    async def test_org_settings_update_without_a_profile_change_leaves_the_org_row_alone(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """No UPDATE organizations unless the profile changed."""
        _seed_a(db)
        admin = _actor(db, "org_admin")
        org_before = copy.deepcopy(db.orgs[ORG_ID])

        await _update(
            svc,
            db,
            admin,
            {
                "profile": {"display_name": ORG_NAME},
                "instructions": _NEW_INSTRUCTIONS,
                "security": {"session_max_lifetime_hours": 6},
            },
        )

        assert _updates(db, "organizations") == []
        assert db.orgs[ORG_ID] == org_before

    async def test_org_settings_update_profile_only_leaves_the_settings_row_alone(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """A profile change writes the organizations row only: the org_settings values
        stay (and no session is re-timed)."""
        _seed_a(db)
        admin = _actor(db, "org_admin")
        _open_org_sessions(db, admin)
        settings_before = db.org_settings_row(ORG_ID)
        sessions_before = copy.deepcopy(db.sessions)

        await _update(svc, db, admin, {"profile": {"default_response_language": "en"}})

        after = db.org_settings_row(ORG_ID)
        assert after is not None and settings_before is not None
        assert {k: v for k, v in after.items() if k != "updated_at"} == {
            k: v for k, v in settings_before.items() if k != "updated_at"
        }
        assert db.sessions == sessions_before


# ---------------------------------------------------------------------------
# 5. The trash retention within the platform bounds
# ---------------------------------------------------------------------------


_OUT_OF_BOUNDS = [
    pytest.param(7, 60, 6, id="below-min"),
    pytest.param(7, 60, 61, id="above-max"),
    pytest.param(0, 20, 21, id="above-max-default-min"),
    pytest.param(10, 10, 9, id="single-value-below"),
    pytest.param(10, 10, 11, id="single-value-above"),
]


class TestTrashRetentionBounds:
    """A changed retention outside the Super Admin's bounds is refused before any write."""

    @pytest.mark.parametrize(("low", "high", "value"), _OUT_OF_BOUNDS)
    async def test_org_settings_update_retention_outside_the_bounds_is_refused(
        self,
        svc: ModuleType,
        db: FakeDb,
        monkeypatch: pytest.MonkeyPatch,
        low: int,
        high: int,
        value: int,
    ) -> None:
        _seed_a(db)
        _set_trash_bounds(monkeypatch, svc, low, high)
        admin = _actor(db, "org_admin")
        before = db.snapshot()

        with pytest.raises(svc.InvalidOrgSettingsError) as caught:
            await _update(svc, db, admin, {"retention": {"trash_retention_days": value}})

        assert isinstance(caught.value, ValueError)
        assert db.snapshot() == before
        assert _writes(db) == []

    async def test_org_settings_update_refused_retention_message_has_no_values(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_a(db)
        _set_trash_bounds(monkeypatch, svc, 17, 43)
        admin = _actor(db, "org_admin")

        with pytest.raises(svc.InvalidOrgSettingsError) as caught:
            await _update(svc, db, admin, {"retention": {"trash_retention_days": 61}})

        message = str(caught.value)
        assert message
        assert re.search(r"\b(?:61|17|43|30)\b", message) is None

    async def test_org_settings_update_refused_retention_writes_no_other_section(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Refused before any write: the valid profile, instructions, security and tools
        changes of the same patch are not stored, no session is re-timed, no event."""
        _seed_a(db)
        _set_trash_bounds(monkeypatch, svc, 7, 60)
        admin = _actor(db, "org_admin")
        _open_org_sessions(db, admin)
        before = db.snapshot()
        body = {**_FULL_PATCH, "retention": {"trash_retention_days": 90}}

        with pytest.raises(svc.InvalidOrgSettingsError):
            await _update(svc, db, admin, body)

        assert db.audit == []
        assert _writes(db) == []
        assert db.snapshot() == before

    @pytest.mark.parametrize(
        ("low", "high", "value"),
        [
            pytest.param(7, 60, 7, id="at-min"),
            pytest.param(7, 60, 60, id="at-max"),
            pytest.param(10, 10, 10, id="single-value"),
        ],
    )
    async def test_org_settings_update_retention_at_the_bounds_is_stored(
        self,
        svc: ModuleType,
        db: FakeDb,
        monkeypatch: pytest.MonkeyPatch,
        low: int,
        high: int,
        value: int,
    ) -> None:
        _seed_a(db)
        _set_trash_bounds(monkeypatch, svc, low, high)
        admin = _actor(db, "org_admin")

        result = await _update(svc, db, admin, {"retention": {"trash_retention_days": value}})

        assert db.org_settings_row(ORG_ID)["trash_retention_days"] == value
        assert result.retention.model_dump() == {
            "trash_retention_days": value,
            "trash_min_days": low,
            "trash_max_days": high,
        }

    async def test_org_settings_update_unchanged_out_of_bounds_retention_is_no_error(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Stored 30 under bounds 0..20, given again unchanged next to an instructions
        change: no error, the instructions are stored, the retention stays 30 and reads 20."""
        _seed_a(db, trash_retention_days=30)
        _set_trash_bounds(monkeypatch, svc, 0, 20)
        admin = _actor(db, "org_admin")

        result = await _update(
            svc,
            db,
            admin,
            {"retention": {"trash_retention_days": 30}, "instructions": _NEW_INSTRUCTIONS},
        )

        row = db.org_settings_row(ORG_ID)
        assert (row["instructions"], row["trash_retention_days"]) == (_NEW_INSTRUCTIONS, 30)
        assert result.retention.trash_retention_days == 20
        assert [r["metadata"] for r in db.audit] == [{"instructions": True}]

    async def test_org_settings_update_retention_event_carries_the_stored_old_value(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Old = the stored 30 (not the effective 20 under bounds 0..20)."""
        _seed_a(db, trash_retention_days=30)
        _set_trash_bounds(monkeypatch, svc, 0, 20)
        admin = _actor(db, "org_admin")

        await _update(svc, db, admin, {"retention": {"trash_retention_days": 15}})

        assert _one(db.audit)["metadata"] == {
            "trash_retention_days_old": 30,
            "trash_retention_days_new": 15,
        }


# ---------------------------------------------------------------------------
# 6. The org's open sessions follow a session policy change
# ---------------------------------------------------------------------------


class TestOrgSessionsFollowThePolicy:
    """A changed idle timeout or lifetime reaches every live session of the org's users in
    the same transaction; another org's and the Super Admin's sessions keep theirs."""

    async def test_org_settings_policy_change_retimes_every_session_of_the_org(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _seed_a(db)
        admin = _actor(db, "org_admin")
        mine, others = _open_org_sessions(db, admin)
        others_before = [copy.deepcopy(db.session(token)) for token in others]

        await _update(
            svc,
            db,
            admin,
            {"security": {"session_idle_timeout_minutes": 30, "session_max_lifetime_hours": 8}},
        )

        for token in mine:
            row = db.session(token)
            assert row["idle_timeout_minutes"] == 30
            assert row["expires_at"] == row["created_at"] + timedelta(hours=8)
        assert [db.session(token) for token in others] == others_before

    async def test_org_settings_policy_change_counts_the_retimed_sessions(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _seed_a(db)
        admin = _actor(db, "org_admin")
        _open_org_sessions(db, admin)

        await _update(
            svc,
            db,
            admin,
            {"security": {"session_idle_timeout_minutes": 30, "session_max_lifetime_hours": 8}},
        )

        assert _one(db.audit)["metadata"] == {
            "session_idle_timeout_minutes_old": 60,
            "session_idle_timeout_minutes_new": 30,
            "session_max_lifetime_hours_old": 12,
            "session_max_lifetime_hours_new": 8,
            "sessions_updated": 3,
        }

    @pytest.mark.parametrize(
        ("change", "policy", "metadata"),
        [
            pytest.param(
                {"session_idle_timeout_minutes": 90},
                (90, 24),
                {"session_idle_timeout_minutes_old": 45, "session_idle_timeout_minutes_new": 90},
                id="idle-only-keeps-the-stored-lifetime",
            ),
            pytest.param(
                {"session_max_lifetime_hours": 6},
                (45, 6),
                {"session_max_lifetime_hours_old": 24, "session_max_lifetime_hours_new": 6},
                id="lifetime-only-keeps-the-stored-idle",
            ),
        ],
    )
    async def test_org_settings_one_session_field_applies_the_merged_policy(
        self,
        svc: ModuleType,
        db: FakeDb,
        change: dict[str, int],
        policy: tuple[int, int],
        metadata: dict[str, int],
    ) -> None:
        """Stored 45 min / 24 h: the sessions take the changed value and the OTHER stored
        one (never the 60 / 12 code defaults)."""
        _seed_a(db, session_idle_timeout_minutes=45, session_max_lifetime_hours=24)
        admin = _actor(db, "org_admin")
        token = db.open_session(admin.user_id)
        idle, hours = policy

        await _update(svc, db, admin, {"security": change})

        row = db.session(token)
        assert row["idle_timeout_minutes"] == idle
        assert row["expires_at"] == row["created_at"] + timedelta(hours=hours)
        assert _one(db.audit)["metadata"] == {**metadata, "sessions_updated": 1}

    async def test_org_settings_member_session_older_than_the_new_lifetime_ends(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Created 5 hours ago: live under 12 hours, gone under 4; org B's session of the
        same age keeps resolving."""
        from admino import sessions

        _seed_a(db)
        _seed_b(db)
        admin = _actor(db, "org_admin")
        editor = db.add_account(role="editor", org_id=ORG_ID)
        other = db.add_account(role="editor", org_id=OTHER_ORG_ID)
        age = {"created_ago": timedelta(hours=5), "expires_in": timedelta(hours=7)}
        token = db.open_session(editor, **age)
        other_token = db.open_session(other, idle_timeout_minutes=20, **age)
        assert await sessions.resolve_session(db.pool, token) is not None

        await _update(svc, db, admin, {"security": {"session_max_lifetime_hours": 4}})

        assert db.session(token)["expires_at"] <= datetime.now(UTC)
        assert await sessions.resolve_session(db.pool, token) is None
        assert await sessions.resolve_session(db.pool, other_token) is not None

    async def test_org_settings_member_session_idle_past_the_new_timeout_ends(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Seen 40 minutes ago: live under 60 minutes, gone under 30; a Super Admin seen as
        long ago keeps their session."""
        from admino import sessions

        _seed_a(db)
        admin = _actor(db, "org_admin")
        editor = db.add_account(role="editor", org_id=ORG_ID)
        super_admin = db.add_account(kind="super_admin", role=None)
        token = db.open_session(editor, last_seen_ago=timedelta(minutes=40))
        sa_token = db.open_session(super_admin, last_seen_ago=timedelta(minutes=40))

        await _update(svc, db, admin, {"security": {"session_idle_timeout_minutes": 30}})

        assert db.session(token)["idle_timeout_minutes"] == 30
        assert await sessions.resolve_session(db.pool, token) is None
        assert await sessions.resolve_session(db.pool, sa_token) is not None

    async def test_org_settings_ended_member_session_is_not_revived_or_counted(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """An expired session and one idle past its old timeout (both not purged yet) stay
        ended under a longer policy; ``sessions_updated`` counts only the live one."""
        _seed_a(db)
        admin = _actor(db, "org_admin")
        editor = db.add_account(role="editor", org_id=ORG_ID)
        colleague = db.add_account(role="editor", org_id=ORG_ID)
        db.open_session(admin.user_id)
        ended = [
            db.open_session(
                editor, created_ago=timedelta(hours=13), expires_in=timedelta(hours=-1)
            ),
            db.open_session(colleague, last_seen_ago=timedelta(minutes=90)),
        ]
        ended_before = [copy.deepcopy(db.session(token)) for token in ended]

        await _update(
            svc,
            db,
            admin,
            {"security": {"session_idle_timeout_minutes": 240, "session_max_lifetime_hours": 24}},
        )

        assert [db.session(token) for token in ended] == ended_before
        assert _one(db.audit)["metadata"]["sessions_updated"] == 1

    async def test_org_settings_session_statement_shares_the_update_transaction(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _seed_a(db)
        admin = _actor(db, "org_admin")
        _open_org_sessions(db, admin)

        await _update(svc, db, admin, {"security": {"session_idle_timeout_minutes": 30}})

        statement = _one(_updates(db, "sessions"))
        update = _one(_updates(db, "org_settings"))
        audit = _one(db.matching(r"^insert into audit_events\b"))
        assert statement.tx is not None
        assert (statement.via, statement.tx) == (update.via, update.tx) == (audit.via, audit.tx)
        assert (statement.tx, "commit") in db.transactions

    async def test_org_settings_unchanged_session_policy_leaves_the_sessions_alone(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """The security values given equal the stored ones (next to a real change): no
        sessions statement, no security event."""
        _seed_a(db)
        admin = _actor(db, "org_admin")
        _open_org_sessions(db, admin)
        sessions_before = copy.deepcopy(db.sessions)

        await _update(
            svc,
            db,
            admin,
            {
                "security": {"session_idle_timeout_minutes": 60, "session_max_lifetime_hours": 12},
                "instructions": _NEW_INSTRUCTIONS,
            },
        )

        assert _updates(db, "sessions") == []
        assert db.sessions == sessions_before
        assert [row["metadata"] for row in db.audit] == [{"instructions": True}]

    async def test_org_settings_new_member_session_takes_the_changed_policy(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """After the change the next login of a member gets the stored values."""
        _seed_a(db)
        admin = _actor(db, "org_admin")

        await _update(
            svc,
            db,
            admin,
            {"security": {"session_idle_timeout_minutes": 120, "session_max_lifetime_hours": 48}},
        )
        policy = await svc.session_policy_for(db.pool, "member", ORG_ID)

        assert (policy.idle_timeout_minutes, policy.max_lifetime_hours) == (120, 48)


# ---------------------------------------------------------------------------
# 7. update_org_settings: authorization, isolation, one transaction, rollback
# ---------------------------------------------------------------------------


class TestUpdateGuarantees:
    """Capability first, the actor's org only, one transaction, all or nothing."""

    @pytest.mark.parametrize("role", _REFUSED_ROLES)
    async def test_org_settings_update_refused_role_raises_before_any_query(
        self, svc: ModuleType, db: FakeDb, role: str
    ) -> None:
        _seed_a(db)
        actor = _actor(db, role)
        patch = _patch(_FULL_PATCH)
        before = db.snapshot()

        with pytest.raises(PermissionError):
            await svc.update_org_settings(db.pool, actor=actor, patch=patch, ip=_IP)

        assert db.calls == []
        assert db.snapshot() == before

    async def test_org_settings_update_runs_in_one_transaction_on_one_connection(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Every statement (reads, locks, writes, sessions, audit) on one connection inside
        one committed transaction; nothing on the pool."""
        _seed_a(db)
        admin = _actor(db, "org_admin")
        _open_org_sessions(db, admin)

        await _update(svc, db, admin, _FULL_PATCH)

        assert db.calls
        assert len({call.via for call in db.calls}) == 1
        assert db.calls[0].via != "pool"
        transactions = {call.tx for call in db.calls}
        assert len(transactions) == 1 and None not in transactions
        (tx,) = transactions
        assert db.transactions == [(tx, "commit")]

    async def test_org_settings_update_locks_both_rows_before_any_write(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """org_settings and organizations are read FOR UPDATE before the first UPDATE and
        the first audit insert."""
        _seed_a(db)
        admin = _actor(db, "org_admin")

        await _update(svc, db, admin, _FULL_PATCH)

        normalized = [call.normalized for call in db.calls]
        first_write = min(
            i
            for i, sql in enumerate(normalized)
            if sql.startswith("update") or sql.startswith("insert into audit_events")
        )

        def locked(table: str) -> list[int]:
            return [
                i
                for i, sql in enumerate(normalized)
                if sql.startswith("select")
                and re.search(rf"\bfrom {table}\b", sql)
                and "for update" in sql
            ]

        assert locked("org_settings") and min(locked("org_settings")) < first_write
        assert locked("organizations") and min(locked("organizations")) < first_write

    async def test_org_settings_update_never_touches_another_org(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Org B's organizations row, settings row and sessions stay; its id is never bound;
        every event is org A's."""
        _seed_a(db)
        _seed_b(db)
        admin = _actor(db, "org_admin", ORG_ID)
        _open_org_sessions(db, admin)
        other_org = copy.deepcopy(db.orgs[OTHER_ORG_ID])
        other_settings = db.org_settings_row(OTHER_ORG_ID)
        other_sessions = {
            key: copy.deepcopy(row)
            for key, row in db.sessions.items()
            if db.users[row["user_id"]]["org_id"] == OTHER_ORG_ID
        }

        await _update(svc, db, admin, _FULL_PATCH)

        assert db.orgs[OTHER_ORG_ID] == other_org
        assert db.org_settings_row(OTHER_ORG_ID) == other_settings
        assert {key: db.sessions[key] for key in other_sessions} == other_sessions
        assert not _bound(db, OTHER_ORG_ID)
        assert {_uuid(row["org_id"]) for row in db.audit} == {ORG_ID}

    async def test_org_settings_update_sql_carries_no_value(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """The name, the instructions and the org id are bind parameters, never SQL text."""
        _seed_a(db)
        admin = _actor(db, "org_admin")

        await _update(svc, db, admin, _FULL_PATCH)

        sql = "\n".join(call.sql for call in db.calls)
        assert _NAME_MARKER not in sql
        assert _TEXT_MARKER not in sql
        assert str(ORG_ID) not in sql
        bound = [arg for call in db.calls for arg in call.args if isinstance(arg, str)]
        assert _NEW_NAME in bound and _NEW_INSTRUCTIONS in bound

    async def test_org_settings_update_audit_failure_rolls_everything_back(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """The first event fails: the settings row, the organizations row and the sessions
        are as they were."""
        _seed_a(db)
        admin = _actor(db, "org_admin")
        _open_org_sessions(db, admin)
        before = db.snapshot()
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _update(svc, db, admin, _FULL_PATCH)

        assert db.snapshot() == before
        assert any(outcome.startswith("rollback") for _, outcome in db.transactions)

    async def test_org_settings_update_last_event_failure_rolls_everything_back(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Only the tools event (the last one) fails: the four events before it, the
        writes and the re-timed sessions are rolled back too."""
        _seed_a(db)
        admin = _actor(db, "org_admin")
        _open_org_sessions(db, admin)
        before = db.snapshot()
        db.fail_audit_when = lambda row: "gmail_old" in row["metadata"]

        with pytest.raises(AuditRecordError):
            await _update(svc, db, admin, _FULL_PATCH)

        assert len(db.matching(r"^insert into audit_events\b")) == 5
        assert db.snapshot() == before


# ---------------------------------------------------------------------------
# 8. session_policy_for: a member's org policy
# ---------------------------------------------------------------------------


class TestSessionPolicyForMembers:
    """A member's new session takes their org's stored policy, read when called."""

    async def test_org_settings_policy_for_member_reads_the_orgs_stored_policy(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        from admino import sessions

        _seed_a(db, session_idle_timeout_minutes=45, session_max_lifetime_hours=6)

        policy = await svc.session_policy_for(db.pool, "member", ORG_ID)

        assert type(policy) is sessions.SessionPolicy
        assert (policy.idle_timeout_minutes, policy.max_lifetime_hours) == (45, 6)

    async def test_org_settings_policy_for_member_is_one_query_of_the_contract(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One SELECT on org_settings bound to the org id; the platform row is never read
        (an empty cache and no platform row change nothing)."""
        monkeypatch.setattr(svc, "_platform_cache", None)
        _seed_a(db, session_idle_timeout_minutes=45, session_max_lifetime_hours=6)

        await svc.session_policy_for(db.pool, "member", ORG_ID)

        call = _one(db.calls)
        assert call.normalized == norm(_POLICY_SQL)
        assert len(call.args) == 1
        assert plain(call.args[0]) == ORG_ID

    async def test_org_settings_policy_for_member_without_a_row_is_the_column_default(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """No org_settings row: SessionPolicy() (60 min / 12 h), and nothing is written."""
        from admino import sessions

        policy = await svc.session_policy_for(db.pool, "member", ORG_ID)

        assert policy == sessions.SessionPolicy()
        assert (policy.idle_timeout_minutes, policy.max_lifetime_hours) == (60, 12)
        assert db.org_settings == {}

    @pytest.mark.parametrize("given", ["omitted", "none"])
    async def test_org_settings_policy_for_member_without_an_org_id_raises_without_a_query(
        self, svc: ModuleType, db: FakeDb, given: str
    ) -> None:
        _seed_a(db)

        with pytest.raises(ValueError):
            if given == "omitted":
                await svc.session_policy_for(db.pool, "member")
            else:
                await svc.session_policy_for(db.pool, "member", None)

        assert db.calls == []

    async def test_org_settings_policy_for_member_never_uses_another_orgs_policy(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Org B stores 20 min / 2 h; org A has no row: A's member gets 60 / 12, and B's id
        is never bound."""
        _seed_b(db)

        policy = await svc.session_policy_for(db.pool, "member", ORG_ID)

        assert (policy.idle_timeout_minutes, policy.max_lifetime_hours) == (60, 12)
        assert not _bound(db, OTHER_ORG_ID)

    async def test_org_settings_policy_for_member_follows_the_given_org(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _seed_a(db, session_idle_timeout_minutes=45, session_max_lifetime_hours=6)
        _seed_b(db)

        policy_a = await svc.session_policy_for(db.pool, "member", ORG_ID)
        policy_b = await svc.session_policy_for(db.pool, "member", OTHER_ORG_ID)

        assert (policy_a.idle_timeout_minutes, policy_a.max_lifetime_hours) == (45, 6)
        assert (policy_b.idle_timeout_minutes, policy_b.max_lifetime_hours) == (20, 2)

    async def test_org_settings_policy_for_member_runs_on_a_connection(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        _seed_a(db, session_idle_timeout_minutes=45, session_max_lifetime_hours=6)

        async with db.pool.acquire() as conn:
            policy = await svc.session_policy_for(conn, "member", ORG_ID)

        assert (policy.idle_timeout_minutes, policy.max_lifetime_hours) == (45, 6)
        assert db.calls
        assert all(call.via != "pool" for call in db.calls)

    async def test_org_settings_policy_for_super_admin_ignores_the_org_id(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The stored platform policy (cached, no query), whatever org id comes along."""
        _seed_a(db, session_idle_timeout_minutes=20, session_max_lifetime_hours=2)
        _set_super_admin_policy(monkeypatch, svc, 45, 8)

        policy = await svc.session_policy_for(db.pool, "super_admin", ORG_ID)

        assert (policy.idle_timeout_minutes, policy.max_lifetime_hours) == (45, 8)
        assert db.calls == []

    @pytest.mark.parametrize("kind", ["admin", "", "Member", "org_admin", "system", None, 1])
    async def test_org_settings_policy_for_unknown_kind_with_an_org_id_raises_without_a_query(
        self, svc: ModuleType, db: FakeDb, kind: Any
    ) -> None:
        _seed_a(db)

        with pytest.raises(ValueError):
            await svc.session_policy_for(db.pool, kind, ORG_ID)

        assert db.calls == []


# ---------------------------------------------------------------------------
# 9. No content in logs
# ---------------------------------------------------------------------------


class TestNoContentInLogs:
    """No instructions text or org name in any log record, on success or failure."""

    async def test_org_settings_flow_logs_no_content(
        self,
        svc: ModuleType,
        db: FakeDb,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        _seed_a(db, instructions=f"{_TEXT_MARKER} gespeichert")
        db.add_org(ORG_ID, name=f"{_NAME_MARKER} Alt AG")
        admin = _actor(db, "org_admin")
        _open_org_sessions(db, admin)

        await svc.get_org_settings(db.pool, actor=admin)
        await _update(svc, db, admin, _FULL_PATCH)
        await _update(svc, db, admin, {"instructions": _NEW_INSTRUCTIONS})
        await svc.session_policy_for(db.pool, "member", ORG_ID)
        _set_trash_bounds(monkeypatch, svc, 7, 60)
        with pytest.raises(svc.InvalidOrgSettingsError):
            await _update(
                svc,
                db,
                admin,
                {"retention": {"trash_retention_days": 90}, "instructions": f"{_TEXT_MARKER} x"},
            )
        db.fail_audit = True
        with pytest.raises(AuditRecordError):
            await _update(svc, db, admin, {"profile": {"display_name": f"{_NAME_MARKER} Neu AG"}})

        text = _log_text(caplog).lower()
        assert _TEXT_MARKER.lower() not in text
        assert _NAME_MARKER.lower() not in text


# ---------------------------------------------------------------------------
# 10. Both capabilities: org.settings.manage AND org.instructions.manage
# ---------------------------------------------------------------------------

# Contract section 4: every response carries the instructions, so both service
# functions require both capabilities; either one missing -> PermissionError, no query.
_EACH_CAPABILITY = [
    pytest.param(Capability.ORG_INSTRUCTIONS_MANAGE, id="instructions-refused"),
    pytest.param(Capability.ORG_SETTINGS_MANAGE, id="settings-refused"),
]
# A tools-only patch carries no instructions, yet its response does: both are needed.
_CAPABILITY_BODIES = [
    pytest.param({"tools": {"gmail": False}}, id="tools-only"),
    pytest.param({"instructions": _NEW_INSTRUCTIONS}, id="instructions"),
]
_BOTH = {Capability.ORG_SETTINGS_MANAGE, Capability.ORG_INSTRUCTIONS_MANAGE}


def _refuse_only(
    monkeypatch: pytest.MonkeyPatch, svc: ModuleType, refused: Capability | None
) -> list[Capability]:
    """Make the capability check refuse ``refused`` only (None: nothing) and record every
    capability asked.

    Patched where scoped_settings looks ``can`` up and in access.py itself; every
    other capability keeps the real role matrix (an Org Admin holds both).
    """
    from admino import access

    real_can = access.can
    asked: list[Capability] = []

    def spy(principal: Principal, capability: Capability) -> bool:
        asked.append(capability)
        return capability != refused and real_can(principal, capability)

    monkeypatch.setattr(svc, "can", spy, raising=False)
    monkeypatch.setattr(access, "can", spy)
    return asked


class TestBothCapabilities:
    """An Org Admin missing either capability is refused before any query."""

    @pytest.mark.parametrize("refused", _EACH_CAPABILITY)
    async def test_org_settings_get_without_one_capability_raises_before_any_query(
        self,
        svc: ModuleType,
        db: FakeDb,
        monkeypatch: pytest.MonkeyPatch,
        refused: Capability,
    ) -> None:
        _seed_a(db)
        admin = _actor(db, "org_admin")
        _refuse_only(monkeypatch, svc, refused)

        with pytest.raises(PermissionError):
            await svc.get_org_settings(db.pool, actor=admin)

        assert db.calls == []

    @pytest.mark.parametrize("body", _CAPABILITY_BODIES)
    @pytest.mark.parametrize("refused", _EACH_CAPABILITY)
    async def test_org_settings_update_without_one_capability_raises_before_any_query(
        self,
        svc: ModuleType,
        db: FakeDb,
        monkeypatch: pytest.MonkeyPatch,
        refused: Capability,
        body: dict[str, Any],
    ) -> None:
        """Nothing is read, written or recorded, whichever section the patch changes."""
        _seed_a(db)
        admin = _actor(db, "org_admin")
        patch = _patch(body)
        before = db.snapshot()
        _refuse_only(monkeypatch, svc, refused)

        with pytest.raises(PermissionError):
            await svc.update_org_settings(db.pool, actor=admin, patch=patch, ip=_IP)

        assert db.calls == []
        assert db.snapshot() == before

    async def test_org_settings_get_with_both_capabilities_asks_both_and_reads(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Control: holding both, the Org Admin reads the stored settings."""
        _seed_a(db)
        admin = _actor(db, "org_admin")
        asked = _refuse_only(monkeypatch, svc, None)

        result = await svc.get_org_settings(db.pool, actor=admin)

        assert set(asked) >= _BOTH
        assert result.model_dump() == _A_RESPONSE

    @pytest.mark.parametrize("body", _CAPABILITY_BODIES)
    async def test_org_settings_update_with_both_capabilities_asks_both_and_writes(
        self,
        svc: ModuleType,
        db: FakeDb,
        monkeypatch: pytest.MonkeyPatch,
        body: dict[str, Any],
    ) -> None:
        """Control: holding both, the Org Admin's change is stored and returned."""
        _seed_a(db)
        admin = _actor(db, "org_admin")
        asked = _refuse_only(monkeypatch, svc, None)

        result = await _update(svc, db, admin, body)

        assert set(asked) >= _BOTH
        assert result.model_dump() == _merged(_A_RESPONSE, body)
        assert _stored_view(db, ORG_ID) == _editable(_merged(_A_RESPONSE, body))
