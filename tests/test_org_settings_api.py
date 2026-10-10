"""HTTP spec for the organization's profile, policies and instructions (GH-169).

``GET`` / ``PATCH /api/org/settings`` grow from the tool switches (GH-159/162) to
the whole organization settings page of contract sections 2, 4 and 6. The
FastAPI app from ``create_app()`` runs against the in-memory database of
tests/db_fakes.py (what ``admino.database.get_pool`` returns) with a real
``AppConfig``; the real ``require_session``, ``admino.scoped_settings``,
``admino.sessions`` and ``admino.audit_events`` code runs. No network: the two
provider probes of the platform settings GET are mocks.

What these tests pin down:
- The response (GET and PATCH): ``profile`` (``display_name`` = the
  organizations row's name, ``default_response_language``), ``instructions``,
  ``security`` (session idle timeout and maximum lifetime), ``retention`` (the
  EFFECTIVE ``trash_retention_days``, i.e. the stored value clamped into the
  platform's ``trash_min_days`` .. ``trash_max_days``, plus both bounds),
  ``tools``, ``data_residency`` and ``plan`` (``seats``, ``storage_quota`` in
  bytes; no budget). A fresh org without an org_settings row reads the column
  defaults (60 minutes, 12 hours, 30 days, no instructions) and nothing is
  written.
- PATCH: any of profile, instructions, security, retention and tools; the
  response is the full settings after the change and the values are stored
  (the display name stripped, the instructions verbatim, ``""`` clears them).
  A null counts as not given. A CHANGED trash retention outside the platform
  bounds is a 400 ``{"detail": "The trash retention must be within the
  platform's bounds.", "reason": "trash_retention_bounds"}`` with nothing
  written and no audit row; an unchanged stored value outside the bounds never
  blocks another change.
- 422 without echo (and nothing written) for out-of-range or wrongly typed
  values, forbidden characters (instructions: Cc but tab/LF/CR, Cf but
  ZWNJ/ZWJ, Zl, Zp; display name: Cc, Cf, Zl, Zp), an unknown language, the
  read-only keys (``data_residency``, ``plan``, ``org_id``, the trash bounds,
  ``profile.name``), any unknown key and an empty patch. Each error points at
  the offending field (``loc``), so a model that refuses the whole section
  doesn't pass.
- 401 without a session; 403 ``{"detail": "Forbidden"}`` for the Editor and
  the Super Admin on both verbs, before any settings read or write;
  a cross-site PATCH is refused by the CSRF middleware before the database;
  per-user rate limits (one Org Admin's patch bucket never throttles another
  org's admin).
- Audit: one ``org.settings_change`` event per CHANGED section, in the order
  profile, instructions, security, retention, tools, with the actor, the org,
  the org as target and the client IP. Profile and instructions events carry
  field names only (``True``), never the name, the language or the text; the
  security event carries ``<field>_old`` / ``<field>_new`` ints and
  ``sessions_updated``; the retention event old/new ints; the tools event
  old/new bools. A no-op PATCH writes and records nothing. An audit failure is
  a 500 with nothing written (settings, organizations row, sessions).
- Sessions (the issue's cleanup criterion): a session-policy change re-times
  every LIVE session of the org's users in the same transaction (idle timeout,
  ``expires_at = created_at + lifetime``, the merged stored+patched values);
  one older than the new lifetime or idle past the new timeout stops
  resolving; an ended session is never revived; other orgs' and Super Admins'
  sessions are untouched; a new login of an org member takes the org's policy.
- Operator blindness: no platform route returns the instructions. No log
  record and no audit row carries the instructions or the org name.

All database calls are faked. No network, no real PostgreSQL, no LLM.

Security notes: every email, password and token is a fixed fake value or
generated per test; the markers are fake content.
"""

from __future__ import annotations

import copy
import json
import logging
import re
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from admino import scoped_settings, server
from admino.config import AppConfig
from admino.server import create_app
from tests.db_fakes import ORG_ID, ORG_NAME, OTHER_ORG_ID, PUBLIC_URL, TOOL_NAMES, FakeDb, plain
from tests.db_fakes import fake_hash as _fake_hash
from tests.log_capture import configured_logging
from tests.tenancy_world import use_fast_passwords, use_roomy_rate_limits

if TYPE_CHECKING:
    import uuid
    from datetime import datetime

    import httpx
    from fastapi import FastAPI

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE: Final = "admino_session"
_IP: Final = "203.0.113.169"
_PATH: Final = "/api/org/settings"
_PATCH_KEY: Final = "/api/org/settings/patch"
_PASSWORD: Final = "org-Settings-169-larch"
_FORBIDDEN: Final = {"detail": "Forbidden"}
_UNAUTHORIZED: Final = {"detail": "Unauthorized"}
_CSRF_REFUSED: Final = {"detail": "Cross-origin request refused"}
_RATE_LIMITED: Final = {"detail": "Rate limit exceeded"}
_TRASH_BOUNDS: Final = {
    "detail": "The trash retention must be within the platform's bounds.",
    "reason": "trash_retention_bounds",
}
_ALL_ON: Final = dict.fromkeys(TOOL_NAMES, True)
# The db fixture's org A plan limits.
_SEATS: Final = 25
_QUOTA: Final = 5 * 1024**3
_MARKER: Final = "ECHOMARK42"
# Content that must never reach a log record, an audit row or a platform route.
_SECRET_NAME: Final = "Zephyrmarker Holding AG"
_SECRET_INSTRUCTIONS: Final = "Zephyrmarker vertraulich: nenne nie die Mandantennamen."
_SECRET_FRAGMENTS: Final = ("zephyrmarker", "mandantennamen", "holding ag")
_EVERYTHING_ELSE_RE: Final = r"\borg_settings\b|\bplatform_settings\b|\bfrom organizations\b"
_CROSS_ORIGIN: Final = [
    pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
    pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
]


def _expected(
    *,
    display_name: str = ORG_NAME,
    language: str = "en",
    instructions: str = "",
    idle: int = 60,
    lifetime: int = 12,
    trash: int = 30,
    trash_min: int = 0,
    trash_max: int = 90,
    tools: dict[str, bool] | None = None,
    residency: bool = False,
    seats: int = _SEATS,
    quota: int = _QUOTA,
) -> dict[str, Any]:
    """The full settings response of org A (the db fixture's defaults unless given)."""
    return {
        "profile": {"display_name": display_name, "default_response_language": language},
        "instructions": instructions,
        "security": {
            "session_idle_timeout_minutes": idle,
            "session_max_lifetime_hours": lifetime,
        },
        "retention": {
            "trash_retention_days": trash,
            "trash_min_days": trash_min,
            "trash_max_days": trash_max,
        },
        "tools": {**_ALL_ON, **(tools or {})},
        "data_residency": residency,
        "plan": {"seats": seats, "storage_quota": quota},
    }


# One change in every section, against the db fixture's fresh org A.
_EVERY_SECTION: Final[dict[str, Any]] = {
    "profile": {"display_name": "Muster Revision AG", "default_response_language": "de"},
    "instructions": "Antworte stets formell.\nKeine Emojis.",
    "security": {"session_idle_timeout_minutes": 30, "session_max_lifetime_hours": 8},
    "retention": {"trash_retention_days": 14},
    "tools": {"gmail": False},
}
_EVERY_SECTION_RESPONSE: Final = _expected(
    display_name="Muster Revision AG",
    language="de",
    instructions="Antworte stets formell.\nKeine Emojis.",
    idle=30,
    lifetime=8,
    trash=14,
    tools={"gmail": False},
)
# The events of _EVERY_SECTION, in order (one live session: the caller's own).
_EVERY_SECTION_EVENTS: Final = [
    {"display_name": True, "default_response_language": True},
    {"instructions": True},
    {
        "session_idle_timeout_minutes_old": 60,
        "session_idle_timeout_minutes_new": 30,
        "session_max_lifetime_hours_old": 12,
        "session_max_lifetime_hours_new": 8,
        "sessions_updated": 1,
    },
    {"trash_retention_days_old": 30, "trash_retention_days_new": 14},
    {"gmail_old": True, "gmail_new": False},
]

_LONG_INSTRUCTIONS: Final = _MARKER + "a" * (8001 - len(_MARKER))
_INSTRUCTIONS_LOC: Final = ("body", "instructions")
_NAME_LOC: Final = ("body", "profile", "display_name")
_LANGUAGE_LOC: Final = ("body", "profile", "default_response_language")
_IDLE_LOC: Final = ("body", "security", "session_idle_timeout_minutes")
_LIFETIME_LOC: Final = ("body", "security", "session_max_lifetime_hours")
_TRASH_LOC: Final = ("body", "retention", "trash_retention_days")
_PATCH_LOC: Final = ("body",)

# (body, the one loc every 422 error must have)
_BAD_BODIES: Final = [
    # instructions: <= 8000 code points, no Cc but tab/LF/CR, no Cf but ZWNJ/ZWJ, no Zl/Zp
    pytest.param({"instructions": _LONG_INSTRUCTIONS}, _INSTRUCTIONS_LOC, id="instructions-8001"),
    pytest.param(
        {"instructions": _MARKER + chr(0) + " Text"}, _INSTRUCTIONS_LOC, id="instructions-nul"
    ),
    pytest.param(
        {"instructions": _MARKER + chr(7) + " Text"}, _INSTRUCTIONS_LOC, id="instructions-bell"
    ),
    pytest.param(
        {"instructions": _MARKER + chr(0x202E) + " Text"},
        _INSTRUCTIONS_LOC,
        id="instructions-bidi-override",
    ),
    pytest.param(
        {"instructions": _MARKER + chr(0x200B) + " Text"},
        _INSTRUCTIONS_LOC,
        id="instructions-zero-width-space",
    ),
    pytest.param(
        {"instructions": _MARKER + chr(0x2028) + " Text"},
        _INSTRUCTIONS_LOC,
        id="instructions-line-separator",
    ),
    pytest.param(
        {"instructions": _MARKER + chr(0x2029) + " Text"},
        _INSTRUCTIONS_LOC,
        id="instructions-paragraph-separator",
    ),
    pytest.param({"instructions": 42}, _INSTRUCTIONS_LOC, id="instructions-int"),
    pytest.param({"instructions": ["Text"]}, _INSTRUCTIONS_LOC, id="instructions-list"),
    # display name: stripped, 1..120, no Cc / Cf / Zl / Zp
    pytest.param({"profile": {"display_name": "   "}}, _NAME_LOC, id="name-blank"),
    pytest.param({"profile": {"display_name": ""}}, _NAME_LOC, id="name-empty"),
    pytest.param(
        {"profile": {"display_name": _MARKER + "b" * 111}}, _NAME_LOC, id="name-121-chars"
    ),
    pytest.param(
        {"profile": {"display_name": _MARKER + chr(7) + " AG"}}, _NAME_LOC, id="name-bell"
    ),
    pytest.param({"profile": {"display_name": _MARKER + chr(0) + " AG"}}, _NAME_LOC, id="name-nul"),
    pytest.param({"profile": {"display_name": _MARKER + "\t AG"}}, _NAME_LOC, id="name-tab"),
    pytest.param({"profile": {"display_name": _MARKER + "\n AG"}}, _NAME_LOC, id="name-line-feed"),
    pytest.param(
        {"profile": {"display_name": _MARKER + chr(0x202E) + " AG"}}, _NAME_LOC, id="name-bidi"
    ),
    pytest.param(
        {"profile": {"display_name": _MARKER + chr(0x200B) + " AG"}},
        _NAME_LOC,
        id="name-zero-width-space",
    ),
    pytest.param(
        {"profile": {"display_name": _MARKER + chr(0x2028) + " AG"}},
        _NAME_LOC,
        id="name-line-separator",
    ),
    pytest.param(
        {"profile": {"display_name": _MARKER + chr(0x2029) + " AG"}},
        _NAME_LOC,
        id="name-paragraph-separator",
    ),
    pytest.param({"profile": {"display_name": 42}}, _NAME_LOC, id="name-int"),
    # default response language: de / fr / it / en only
    pytest.param({"profile": {"default_response_language": "es"}}, _LANGUAGE_LOC, id="lang-es"),
    pytest.param({"profile": {"default_response_language": "DE"}}, _LANGUAGE_LOC, id="lang-caps"),
    pytest.param(
        {"profile": {"default_response_language": _MARKER}}, _LANGUAGE_LOC, id="lang-marker"
    ),
    pytest.param({"profile": {"default_response_language": ""}}, _LANGUAGE_LOC, id="lang-empty"),
    # security: strict ints, idle 15..480, lifetime 1..72
    pytest.param({"security": {"session_idle_timeout_minutes": 14}}, _IDLE_LOC, id="idle-14"),
    pytest.param({"security": {"session_idle_timeout_minutes": 481}}, _IDLE_LOC, id="idle-481"),
    pytest.param(
        {"security": {"session_idle_timeout_minutes": "60"}}, _IDLE_LOC, id="idle-numeric-string"
    ),
    pytest.param({"security": {"session_idle_timeout_minutes": True}}, _IDLE_LOC, id="idle-true"),
    pytest.param({"security": {"session_idle_timeout_minutes": 30.0}}, _IDLE_LOC, id="idle-float"),
    pytest.param(
        {"security": {"session_idle_timeout_minutes": _MARKER}}, _IDLE_LOC, id="idle-marker"
    ),
    pytest.param({"security": {"session_max_lifetime_hours": 0}}, _LIFETIME_LOC, id="lifetime-0"),
    pytest.param({"security": {"session_max_lifetime_hours": 73}}, _LIFETIME_LOC, id="lifetime-73"),
    pytest.param(
        {"security": {"session_max_lifetime_hours": "12"}}, _LIFETIME_LOC, id="lifetime-string"
    ),
    pytest.param(
        {"security": {"session_max_lifetime_hours": False}}, _LIFETIME_LOC, id="lifetime-false"
    ),
    # retention: strict int 0..90 (the platform bounds are the service's 400)
    pytest.param({"retention": {"trash_retention_days": -1}}, _TRASH_LOC, id="retention-minus-1"),
    pytest.param({"retention": {"trash_retention_days": 91}}, _TRASH_LOC, id="retention-91"),
    pytest.param({"retention": {"trash_retention_days": "30"}}, _TRASH_LOC, id="retention-string"),
    pytest.param({"retention": {"trash_retention_days": True}}, _TRASH_LOC, id="retention-true"),
    pytest.param({"retention": {"trash_retention_days": 14.0}}, _TRASH_LOC, id="retention-float"),
    # read-only keys
    pytest.param({"data_residency": False}, ("body", "data_residency"), id="data-residency"),
    pytest.param(
        {"instructions": "Neu", "data_residency": False},
        ("body", "data_residency"),
        id="data-residency-beside-a-change",
    ),
    pytest.param(
        {"instructions": "Neu", "tools": {"gmail": False, "data_residency": False}},
        ("body", "tools", "data_residency"),
        id="data-residency-under-tools",
    ),
    pytest.param({"plan": {"seats": 999}}, ("body", "plan"), id="plan"),
    pytest.param(
        {"instructions": "Neu", "plan": {"storage_quota": 1}},
        ("body", "plan"),
        id="plan-beside-a-change",
    ),
    pytest.param(
        {"instructions": "Neu", "org_id": str(OTHER_ORG_ID)}, ("body", "org_id"), id="org-id"
    ),
    pytest.param(
        {"retention": {"trash_retention_days": 14, "trash_min_days": 0}},
        ("body", "retention", "trash_min_days"),
        id="retention-trash-min-days",
    ),
    pytest.param(
        {"retention": {"trash_max_days": 90}},
        ("body", "retention", "trash_max_days"),
        id="retention-trash-max-days",
    ),
    pytest.param({"trash_min_days": 0}, ("body", "trash_min_days"), id="top-trash-min-days"),
    pytest.param({"trash_max_days": 90}, ("body", "trash_max_days"), id="top-trash-max-days"),
    pytest.param(
        {"profile": {"name": _MARKER + " AG"}}, ("body", "profile", "name"), id="profile-name"
    ),
    # unknown keys at any level
    pytest.param({"instructions": "Neu", "theme": _MARKER}, ("body", "theme"), id="unknown-top"),
    pytest.param(
        {"profile": {"display_name": "Neu AG", "logo": _MARKER}},
        ("body", "profile", "logo"),
        id="unknown-under-profile",
    ),
    pytest.param(
        {"security": {"session_idle_timeout_minutes": 30, "mfa_required": True}},
        ("body", "security", "mfa_required"),
        id="unknown-under-security",
    ),
    pytest.param(
        {"security": {"session_idle_timeout_minutes": 30, "lockout_minutes": 5}},
        ("body", "security", "lockout_minutes"),
        id="platform-field-under-security",
    ),
    pytest.param(
        {"retention": {"trash_retention_days": 14, "audit_months": 24}},
        ("body", "retention", "audit_months"),
        id="platform-field-under-retention",
    ),
    pytest.param({"profile": "Neu AG"}, ("body", "profile"), id="profile-string"),
    pytest.param({"security": [30]}, ("body", "security"), id="security-list"),
    # nothing given (empty sections and nulls don't count)
    pytest.param({}, _PATCH_LOC, id="empty-object"),
    pytest.param({"profile": {}}, _PATCH_LOC, id="empty-profile"),
    pytest.param(
        {"profile": {"display_name": None, "default_response_language": None}},
        _PATCH_LOC,
        id="null-profile-fields",
    ),
    pytest.param({"instructions": None}, _PATCH_LOC, id="null-instructions"),
    pytest.param({"security": {}, "retention": {}}, _PATCH_LOC, id="empty-security-retention"),
    pytest.param(
        {"security": {"session_idle_timeout_minutes": None, "session_max_lifetime_hours": None}},
        _PATCH_LOC,
        id="null-security-fields",
    ),
    pytest.param({"retention": {"trash_retention_days": None}}, _PATCH_LOC, id="null-retention"),
    pytest.param({"tools": {}, "retention": {}}, _PATCH_LOC, id="empty-tools-retention"),
    pytest.param(
        {"profile": None, "instructions": None, "security": None, "retention": None, "tools": None},
        _PATCH_LOC,
        id="every-section-null",
    ),
]

# A patch per section that is a no-op against _STORED (the no-op tests' seeded values).
_STORED: Final[dict[str, Any]] = {
    "instructions": "Bestehende Anweisungen.\n",
    "session_idle_timeout_minutes": 120,
    "session_max_lifetime_hours": 24,
    "trash_retention_days": 14,
}
_NOOP_BODIES: Final = [
    pytest.param({"profile": {"display_name": "  " + ORG_NAME + " "}}, id="same-name-with-spaces"),
    pytest.param({"profile": {"default_response_language": "en"}}, id="same-language"),
    pytest.param({"instructions": "Bestehende Anweisungen.\n"}, id="same-instructions"),
    pytest.param(
        {"security": {"session_idle_timeout_minutes": 120, "session_max_lifetime_hours": 24}},
        id="same-security",
    ),
    pytest.param({"retention": {"trash_retention_days": 14}}, id="same-retention"),
    pytest.param({"tools": {"gmail": False}}, id="same-tool"),
    pytest.param(
        {
            "profile": {"display_name": ORG_NAME, "default_response_language": "en"},
            "instructions": "Bestehende Anweisungen.\n",
            "security": {"session_idle_timeout_minutes": 120, "session_max_lifetime_hours": 24},
            "retention": {"trash_retention_days": 14},
            "tools": {"gmail": False, "outlook": True},
        },
        id="every-section-unchanged",
    ),
]
# Changes that touch no session field.
_NON_SESSION_BODIES: Final = [
    pytest.param({"profile": {"display_name": "Muster Revision AG"}}, id="profile"),
    pytest.param({"instructions": "Neu."}, id="instructions"),
    pytest.param({"retention": {"trash_retention_days": 7}}, id="retention"),
    pytest.param({"tools": {"memory": False}}, id="tools"),
]

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch) -> FakeDb:
    """The fake database the server's get_pool() returns: org A (25 seats, a 5 GiB
    storage quota) and org B, both without data residency, and the default platform
    row (trash bounds 0..90, the primed cache's values too)."""
    fake = FakeDb()
    fake.add_org(ORG_ID, data_residency=False, seats=_SEATS, storage_quota_bytes=_QUOTA)
    fake.add_org(OTHER_ORG_ID, data_residency=False)
    fake.add_platform_settings()
    monkeypatch.setattr("admino.database.get_pool", lambda: fake.pool)
    return fake


@pytest.fixture(autouse=True)
def _fast_and_roomy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Argon2 replaced by a fast fake; every rate-limit bucket roomy (the rate-limit
    test sets its own)."""
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)


@pytest.fixture()
def app() -> FastAPI:
    """create_app with a stub agent and a real config (no lifespan under TestClient)."""
    agent = MagicMock(name="agent")
    agent._llm = MagicMock(name="llm-client")
    agent._llm.close = AsyncMock()
    config = AppConfig.model_validate(
        {
            "server": {"host": "127.0.0.1", "port": 8000, "public_url": PUBLIC_URL},
            "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
        }
    )
    return create_app(agent=agent, config=config)


def _client(app: FastAPI, **kwargs: Any) -> TestClient:
    return TestClient(app, client=(_IP, 50000), follow_redirects=False, **kwargs)


def _login(
    db: FakeDb, role: str, org_id: uuid.UUID = ORG_ID, **fields: Any
) -> tuple[uuid.UUID, str]:
    """An account with this role (or a Super Admin) and a live session: (id, token)."""
    if role == "super_admin":
        user_id = db.add_account(kind="super_admin", role=None, **fields)
    else:
        user_id = db.add_account(role=role, org_id=org_id, **fields)
    return user_id, db.open_session(user_id)


def _headers(token: str | None, **extra: str) -> dict[str, str]:
    cookie = {} if token is None else {"Cookie": f"{_COOKIE}={token}"}
    return {**cookie, **extra}


def _get(client: TestClient, token: str | None, **headers: str) -> httpx.Response:
    return client.get(_PATH, headers=_headers(token, **headers))


def _patch(client: TestClient, token: str | None, body: Any, **headers: str) -> httpx.Response:
    return client.patch(_PATH, json=body, headers=_headers(token, **headers))


def _me(client: TestClient, token: str) -> int:
    """The status of GET /api/auth/me with this session (200 live, 401 ended)."""
    return client.get("/api/auth/me", headers=_headers(token)).status_code


def _bounds(db: FakeDb, low: int, high: int) -> None:
    """Set the platform trash bounds in the row and empty the cache (read from the row)."""
    row = db.platform_row()
    assert row is not None
    row.update(trash_min_days=low, trash_max_days=high)
    scoped_settings._platform_cache = None


def _policies(db: FakeDb) -> dict[bytes, tuple[int, datetime, datetime]]:
    """Each session's (idle timeout, created_at, expires_at), by token hash."""
    return {
        token_hash: (row["idle_timeout_minutes"], row["created_at"], row["expires_at"])
        for token_hash, row in db.sessions.items()
    }


def _state(db: FakeDb) -> dict[str, Any]:
    """Every table; sessions reduced to what a settings change may touch (any request
    refreshes the caller's last_seen_at)."""
    tables = db.snapshot()
    tables["sessions"] = _policies(db)
    return tables


def _settings_reads(db: FakeDb, since: int) -> list[str]:
    """The statements since ``since`` that read or write settings or an org row (the
    session lookup joins organizations; it never selects FROM it)."""
    return [
        call.normalized
        for call in db.calls[since:]
        if re.search(_EVERYTHING_ELSE_RE, call.normalized)
    ]


def _events(db: FakeDb) -> list[dict[str, Any]]:
    """The org.settings_change audit rows, in order."""
    return db.audit_rows("org.settings_change")


def _changes(db: FakeDb) -> list[dict[str, Any]]:
    """The metadata of every org.settings_change audit row, in order."""
    return [row["metadata"] for row in _events(db)]


def _stored(db: FakeDb, org_id: uuid.UUID = ORG_ID) -> dict[str, Any]:
    """The stored org_settings values of an org (no updated_at, no org_id)."""
    row = db.org_settings_row(org_id)
    assert row is not None, "no org_settings row"
    return {key: value for key, value in row.items() if key not in {"org_id", "updated_at"}}


def _uuid(value: Any) -> uuid.UUID | None:
    return None if value is None else plain(value)


def _one(items: list[Any]) -> Any:
    assert len(items) == 1, items
    return items[0]


def _lifetime(row: dict[str, Any]) -> timedelta:
    return row["expires_at"] - row["created_at"]


def _log_in(client: TestClient, email: str) -> tuple[str, dict[str, str | None]]:
    """POST /api/auth/login; return (token, cookie attributes) of the one session cookie."""
    response = client.post("/api/auth/login", json={"email": email, "password": _PASSWORD})
    assert response.status_code == 204, response.text
    client.cookies.clear()
    headers = [
        header
        for header in response.headers.get_list("set-cookie")
        if header.lower().startswith(f"{_COOKIE}=")
    ]
    assert len(headers) == 1, response.headers.get_list("set-cookie")
    parts = [part.strip() for part in headers[0].split(";")]
    attributes: dict[str, str | None] = {}
    for part in parts[1:]:
        key, sep, value = part.partition("=")
        attributes[key.strip().lower()] = value.strip() if sep else None
    return parts[0].split("=", 1)[1], attributes


def _assert_leak_free(text: str) -> None:
    lowered = text.lower()
    leaked = [fragment for fragment in _SECRET_FRAGMENTS if fragment in lowered]
    assert leaked == [], leaked


# ---------------------------------------------------------------------------
# 1. GET: every section, the column defaults without a row, the clamped retention
# ---------------------------------------------------------------------------


class TestOrgSettingsGet:
    """The Org Admin reads the whole settings page of their own org."""

    def test_org_settings_api_get_fresh_org_returns_every_section_with_the_defaults(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """No org_settings row: the column defaults, the org row's profile and plan, and
        nothing written."""
        _, token = _login(db, "org_admin")

        response = _get(_client(app), token)

        assert response.status_code == 200, response.text
        assert response.json() == _expected()
        assert (db.org_settings, db.audit) == ({}, [])

    def test_org_settings_api_get_returns_the_stored_values(self, db: FakeDb, app: FastAPI) -> None:
        """Stored name, language, residency, plan, instructions, policies and switches."""
        db.add_org(
            ORG_ID,
            name="Muster Revision AG",
            seats=40,
            storage_quota_bytes=1024**3,
            data_residency=True,
            default_response_language="fr",
        )
        instructions = "Bitte stets formell.\n\tKeine Emojis." + chr(0x200C)
        db.add_org_settings(
            ORG_ID,
            instructions=instructions,
            session_idle_timeout_minutes=120,
            session_max_lifetime_hours=24,
            trash_retention_days=14,
            gmail=False,
            onedrive=False,
        )
        _, token = _login(db, "org_admin")

        response = _get(_client(app), token)

        assert response.status_code == 200, response.text
        assert response.json() == _expected(
            display_name="Muster Revision AG",
            language="fr",
            instructions=instructions,
            idle=120,
            lifetime=24,
            trash=14,
            tools={"gmail": False, "onedrive": False},
            residency=True,
            seats=40,
            quota=1024**3,
        )

    @pytest.mark.parametrize(
        ("stored", "low", "high", "effective"),
        [
            pytest.param(30, 7, 14, 14, id="above-the-maximum"),
            pytest.param(3, 7, 60, 7, id="below-the-minimum"),
            pytest.param(45, 0, 90, 45, id="within"),
            pytest.param(0, 0, 5, 0, id="at-the-minimum"),
            pytest.param(90, 0, 90, 90, id="at-the-maximum"),
        ],
    )
    def test_org_settings_api_get_clamps_the_trash_retention_into_the_platform_bounds(
        self, db: FakeDb, app: FastAPI, stored: int, low: int, high: int, effective: int
    ) -> None:
        """The response shows the effective value and both bounds; the stored value stays."""
        _bounds(db, low, high)
        db.add_org_settings(ORG_ID, trash_retention_days=stored)
        _, token = _login(db, "org_admin")

        response = _get(_client(app), token)

        assert response.status_code == 200, response.text
        assert response.json().get("retention") == {
            "trash_retention_days": effective,
            "trash_min_days": low,
            "trash_max_days": high,
        }
        assert _stored(db)["trash_retention_days"] == stored


# ---------------------------------------------------------------------------
# 2. PATCH: each section and all of them, stored and returned in full
# ---------------------------------------------------------------------------


class TestOrgSettingsPatch:
    """Every section is editable; the response is the full settings after the change."""

    def test_org_settings_api_patch_display_name_is_stripped_stored_and_returned(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "org_admin")

        response = _patch(_client(app), token, {"profile": {"display_name": "  Neue Treuhand AG "}})

        assert response.status_code == 200, response.text
        assert response.json() == _expected(display_name="Neue Treuhand AG")
        assert (db.orgs[ORG_ID]["name"], db.orgs[ORG_ID]["default_response_language"]) == (
            "Neue Treuhand AG",
            "en",
        )

    def test_org_settings_api_patch_display_name_of_120_chars_is_accepted(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "org_admin")
        name = "Ä" + "b" * 118 + "G"

        response = _patch(_client(app), token, {"profile": {"display_name": name}})

        assert response.status_code == 200, response.text
        assert db.orgs[ORG_ID]["name"] == name

    @pytest.mark.parametrize("language", ["de", "fr", "it"])
    def test_org_settings_api_patch_response_language_is_stored_and_returned(
        self, db: FakeDb, app: FastAPI, language: str
    ) -> None:
        _, token = _login(db, "org_admin")

        response = _patch(_client(app), token, {"profile": {"default_response_language": language}})

        assert response.status_code == 200, response.text
        assert response.json() == _expected(language=language)
        assert (db.orgs[ORG_ID]["name"], db.orgs[ORG_ID]["default_response_language"]) == (
            ORG_NAME,
            language,
        )

    def test_org_settings_api_patch_instructions_are_stored_verbatim(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """Not stripped; tab, line breaks, ZWNJ and ZWJ are allowed."""
        _, token = _login(db, "org_admin")
        text = (
            "  Antworte stets formell.\n\tKeine Emojis.\r\nGruss"
            + chr(0x200C)
            + "x"
            + chr(0x200D)
            + "y  \n"
        )

        response = _patch(_client(app), token, {"instructions": text})

        assert response.status_code == 200, response.text
        assert response.json() == _expected(instructions=text)
        assert _stored(db)["instructions"] == text

    def test_org_settings_api_patch_instructions_of_8000_code_points_are_accepted(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """8000 code points (one outside the BMP) is the limit, not 8000 UTF-16 units."""
        _, token = _login(db, "org_admin")
        text = "x" * 7999 + chr(0x1F600)

        response = _patch(_client(app), token, {"instructions": text})

        assert response.status_code == 200, response.text
        assert _stored(db)["instructions"] == text

    def test_org_settings_api_patch_empty_instructions_clear_them(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        db.add_org_settings(ORG_ID, instructions="Alte Anweisungen.")
        _, token = _login(db, "org_admin")

        response = _patch(_client(app), token, {"instructions": ""})

        assert response.status_code == 200, response.text
        assert response.json()["instructions"] == ""
        assert _stored(db)["instructions"] == ""
        assert _changes(db) == [{"instructions": True}]

    def test_org_settings_api_patch_security_is_stored_and_returned(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "org_admin")

        response = _patch(
            _client(app),
            token,
            {"security": {"session_idle_timeout_minutes": 30, "session_max_lifetime_hours": 8}},
        )

        assert response.status_code == 200, response.text
        assert response.json() == _expected(idle=30, lifetime=8)
        stored = _stored(db)
        assert (stored["session_idle_timeout_minutes"], stored["session_max_lifetime_hours"]) == (
            30,
            8,
        )

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            pytest.param("session_idle_timeout_minutes", 15, id="idle-15"),
            pytest.param("session_idle_timeout_minutes", 480, id="idle-480"),
            pytest.param("session_max_lifetime_hours", 1, id="lifetime-1"),
            pytest.param("session_max_lifetime_hours", 72, id="lifetime-72"),
        ],
    )
    def test_org_settings_api_patch_security_boundary_value_is_accepted(
        self, db: FakeDb, app: FastAPI, field: str, value: int
    ) -> None:
        _, token = _login(db, "org_admin")

        response = _patch(_client(app), token, {"security": {field: value}})

        assert response.status_code == 200, response.text
        assert response.json()["security"][field] == value
        assert _stored(db)[field] == value

    def test_org_settings_api_patch_retention_is_stored_and_returned(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "org_admin")

        response = _patch(_client(app), token, {"retention": {"trash_retention_days": 14}})

        assert response.status_code == 200, response.text
        assert response.json() == _expected(trash=14)
        assert _stored(db)["trash_retention_days"] == 14

    @pytest.mark.parametrize(
        ("low", "high", "value"),
        [
            pytest.param(7, 60, 7, id="at-the-platform-minimum"),
            pytest.param(7, 60, 60, id="at-the-platform-maximum"),
            pytest.param(0, 90, 0, id="zero-days"),
            pytest.param(0, 90, 90, id="ninety-days"),
        ],
    )
    def test_org_settings_api_patch_retention_within_the_platform_bounds_is_accepted(
        self, db: FakeDb, app: FastAPI, low: int, high: int, value: int
    ) -> None:
        _bounds(db, low, high)
        _, token = _login(db, "org_admin")

        response = _patch(_client(app), token, {"retention": {"trash_retention_days": value}})

        assert response.status_code == 200, response.text
        assert response.json()["retention"] == {
            "trash_retention_days": value,
            "trash_min_days": low,
            "trash_max_days": high,
        }
        assert _stored(db)["trash_retention_days"] == value

    def test_org_settings_api_patch_tools_only_returns_the_full_response(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """The GH-159 switch patch keeps working; its response is the whole page now."""
        _, token = _login(db, "org_admin")

        response = _patch(_client(app), token, {"tools": {"gmail": False}})

        assert response.status_code == 200, response.text
        assert response.json() == _expected(tools={"gmail": False})

    def test_org_settings_api_patch_every_section_at_once_is_stored_and_returned(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "org_admin")
        client = _client(app)

        response = _patch(client, token, _EVERY_SECTION)
        read = _get(client, token)

        assert response.status_code == 200, response.text
        assert response.json() == _EVERY_SECTION_RESPONSE
        assert read.json() == _EVERY_SECTION_RESPONSE
        assert (db.orgs[ORG_ID]["name"], db.orgs[ORG_ID]["default_response_language"]) == (
            "Muster Revision AG",
            "de",
        )
        assert _stored(db) == {
            **{f"{tool}_enabled": tool != "gmail" for tool in TOOL_NAMES},
            "instructions": "Antworte stets formell.\nKeine Emojis.",
            "session_idle_timeout_minutes": 30,
            "session_max_lifetime_hours": 8,
            "trash_retention_days": 14,
        }

    def test_org_settings_api_patch_without_a_row_stores_the_defaults_and_the_change(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "org_admin")

        response = _patch(_client(app), token, {"instructions": "Neu."})

        assert response.status_code == 200, response.text
        assert _stored(db) == {
            **{f"{tool}_enabled": True for tool in TOOL_NAMES},
            "instructions": "Neu.",
            "session_idle_timeout_minutes": 60,
            "session_max_lifetime_hours": 12,
            "trash_retention_days": 30,
        }

    def test_org_settings_api_patch_keeps_every_field_not_given(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """Nulls and missing fields keep their stored values."""
        db.add_org(ORG_ID, default_response_language="fr")
        db.add_org_settings(ORG_ID, gmail=False, **_STORED)
        _, token = _login(db, "org_admin")

        response = _patch(
            _client(app),
            token,
            {
                "profile": {"display_name": None, "default_response_language": "it"},
                "instructions": None,
                "security": {
                    "session_idle_timeout_minutes": None,
                    "session_max_lifetime_hours": 48,
                },
                "retention": None,
                "tools": {"outlook": False, "gmail": None},
            },
        )

        assert response.status_code == 200, response.text
        assert response.json() == _expected(
            language="it",
            instructions="Bestehende Anweisungen.\n",
            idle=120,
            lifetime=48,
            trash=14,
            tools={"gmail": False, "outlook": False},
        )
        assert db.orgs[ORG_ID]["name"] == ORG_NAME

    def test_org_settings_api_patch_response_shows_the_clamped_retention(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """Stored 30 days, platform bounds 7..14: an instructions change answers 14 and
        leaves the stored 30."""
        _bounds(db, 7, 14)
        db.add_org_settings(ORG_ID)
        _, token = _login(db, "org_admin")

        response = _patch(_client(app), token, {"instructions": "Neu."})

        assert response.status_code == 200, response.text
        assert response.json() == _expected(
            instructions="Neu.", trash=14, trash_min=7, trash_max=14
        )
        assert _stored(db)["trash_retention_days"] == 30


# ---------------------------------------------------------------------------
# 3. The platform's trash bounds: 400, nothing written
# ---------------------------------------------------------------------------


class TestOrgSettingsTrashBounds:
    """A changed retention outside the platform bounds is a 400 with nothing written."""

    @pytest.mark.parametrize("value", [0, 6, 61, 90], ids=["zero", "below", "above", "ninety"])
    def test_org_settings_api_patch_retention_outside_the_bounds_is_400_and_writes_nothing(
        self, db: FakeDb, app: FastAPI, value: int
    ) -> None:
        _bounds(db, 7, 60)
        _, token = _login(db, "org_admin")
        before = _state(db)

        response = _patch(_client(app), token, {"retention": {"trash_retention_days": value}})

        assert (response.status_code, response.json()) == (400, _TRASH_BOUNDS)
        assert _state(db) == before

    def test_org_settings_api_patch_retention_refusal_drops_the_whole_patch(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """Every other section of the refused patch is dropped too: no name, instructions,
        policy, switch or session change, no audit row."""
        _bounds(db, 7, 60)
        db.add_org_settings(ORG_ID)
        _, token = _login(db, "org_admin")
        editor, _ = _login(db, "editor")
        before = _state(db)

        response = _patch(
            _client(app),
            token,
            {**_EVERY_SECTION, "retention": {"trash_retention_days": 3}},
        )

        assert (response.status_code, response.json()) == (400, _TRASH_BOUNDS)
        assert _state(db) == before
        assert db.audit == []
        assert _one(db.sessions_of(editor))["idle_timeout_minutes"] == 60

    def test_org_settings_api_patch_unchanged_retention_outside_the_bounds_is_not_refused(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """Stored 30 days, bounds 7..14: giving the same 30 is no change, so the
        instructions change goes through (and only it is audited)."""
        _bounds(db, 7, 14)
        db.add_org_settings(ORG_ID)
        _, token = _login(db, "org_admin")

        response = _patch(
            _client(app),
            token,
            {"instructions": "Neu.", "retention": {"trash_retention_days": 30}},
        )

        assert response.status_code == 200, response.text
        assert (_stored(db)["instructions"], _stored(db)["trash_retention_days"]) == ("Neu.", 30)
        assert response.json()["retention"]["trash_retention_days"] == 14
        assert _changes(db) == [{"instructions": True}]


# ---------------------------------------------------------------------------
# 4. Validation: 422 at the field, without echo, nothing written
# ---------------------------------------------------------------------------


class TestOrgSettingsValidation:
    """Bad values, read-only and unknown keys and empty patches are 422s at the field."""

    @pytest.mark.parametrize(("body", "loc"), _BAD_BODIES)
    def test_org_settings_api_patch_bad_body_is_422_at_the_field_without_echo(
        self, db: FakeDb, app: FastAPI, body: Any, loc: tuple[str, ...]
    ) -> None:
        db.add_org_settings(ORG_ID, instructions="Alt.")
        _, token = _login(db, "org_admin")
        before = _state(db)

        response = _patch(_client(app), token, body)

        assert response.status_code == 422, response.text
        errors = response.json()["detail"]
        assert {tuple(error["loc"]) for error in errors} == {loc}, errors
        assert all("input" not in error for error in errors)
        assert _MARKER not in response.text
        assert _LONG_INSTRUCTIONS[:40] not in response.text
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 5. Access: session, role, CSRF, per-user rate limit
# ---------------------------------------------------------------------------


class TestOrgSettingsAccess:
    """401 without a session; only the Org Admin; same-origin writes; per-user buckets."""

    @pytest.mark.parametrize("method", ["GET", "PATCH"])
    def test_org_settings_api_without_a_session_is_401_before_the_database(
        self, db: FakeDb, app: FastAPI, method: str
    ) -> None:
        kwargs: dict[str, Any] = {"json": _EVERY_SECTION} if method == "PATCH" else {}

        response = _client(app).request(method, _PATH, **kwargs)

        assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)
        assert db.calls == []

    @pytest.mark.parametrize("role", ["editor", "super_admin"])
    def test_org_settings_api_other_roles_are_403_on_both_verbs_and_touch_nothing(
        self, db: FakeDb, app: FastAPI, role: str
    ) -> None:
        """A valid full patch and a read: 403 Forbidden, no settings or org row read, nothing
        written, no audit row."""
        db.add_org_settings(ORG_ID, instructions=_SECRET_INSTRUCTIONS)
        _, token = _login(db, role)
        client = _client(app)
        before = _state(db)
        since = len(db.calls)

        read = _get(client, token)
        write = _patch(client, token, _EVERY_SECTION)

        assert (read.status_code, read.json()) == (403, _FORBIDDEN)
        assert (write.status_code, write.json()) == (403, _FORBIDDEN)
        assert _settings_reads(db, since) == []
        assert _state(db) == before

    @pytest.mark.parametrize("headers", _CROSS_ORIGIN)
    def test_org_settings_api_cross_site_patch_is_refused_and_same_origin_is_accepted(
        self, db: FakeDb, app: FastAPI, headers: dict[str, str]
    ) -> None:
        """The cross-site PATCH is refused before the database; the same patch from the
        same origin is stored."""
        _, token = _login(db, "org_admin")
        client = _client(app)
        before = _state(db)

        refused = _patch(client, token, _EVERY_SECTION, **headers)
        refused_calls = list(db.calls)
        state_after_refusal = _state(db)
        accepted = _patch(client, token, _EVERY_SECTION, **{"Sec-Fetch-Site": "same-origin"})

        assert (refused.status_code, refused.json()) == (403, _CSRF_REFUSED)
        assert refused_calls == []
        assert state_after_refusal == before
        assert accepted.status_code == 200, accepted.text
        assert accepted.json() == _EVERY_SECTION_RESPONSE

    def test_org_settings_api_patch_rate_limit_is_per_user(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Burst 1: org A's admin's second patch is 429 (nothing stored); org B's admin is
        not throttled; the bucket is (key, "user:<id>")."""
        monkeypatch.setitem(server._RATE_LIMITS, _PATCH_KEY, (0.001, 1))
        admin_a, token_a = _login(db, "org_admin")
        _, token_b = _login(db, "org_admin", OTHER_ORG_ID)
        client = _client(app)

        first = _patch(client, token_a, {"instructions": "Erste."})
        limited = _patch(client, token_a, {"instructions": "Zweite."})
        other = _patch(client, token_b, {"instructions": "Org B."})

        assert first.status_code == 200, first.text
        assert (limited.status_code, limited.json()) == (429, _RATE_LIMITED)
        assert other.status_code == 200, other.text
        assert (_stored(db)["instructions"], _stored(db, OTHER_ORG_ID)["instructions"]) == (
            "Erste.",
            "Org B.",
        )
        assert (_PATCH_KEY, f"user:{admin_a}") in server._rate_buckets


# ---------------------------------------------------------------------------
# 6. Audit: one content-free event per changed section
# ---------------------------------------------------------------------------


class TestOrgSettingsAudit:
    """org.settings_change per changed section, in order, field names only for content."""

    def test_org_settings_api_patch_every_section_records_one_event_per_section_in_order(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        admin_id, token = _login(db, "org_admin")

        response = _patch(_client(app), token, _EVERY_SECTION)

        assert response.status_code == 200, response.text
        assert _changes(db) == _EVERY_SECTION_EVENTS
        for event in _events(db):
            assert (event["actor_kind"], _uuid(event["actor_user_id"])) == ("member", admin_id)
            assert _uuid(event["org_id"]) == ORG_ID
            assert (event["target_type"], event["target_ids"]) == ("organization", [str(ORG_ID)])
            assert event["ip"] == _IP

    @pytest.mark.parametrize(
        ("profile", "metadata"),
        [
            pytest.param({"display_name": _SECRET_NAME}, {"display_name": True}, id="display-name"),
            pytest.param(
                {"default_response_language": "it"},
                {"default_response_language": True},
                id="language",
            ),
            pytest.param(
                {"display_name": _SECRET_NAME, "default_response_language": "fr"},
                {"display_name": True, "default_response_language": True},
                id="both",
            ),
            pytest.param(
                {"display_name": _SECRET_NAME, "default_response_language": "en"},
                {"display_name": True},
                id="name-changed-language-same",
            ),
        ],
    )
    def test_org_settings_api_profile_event_names_the_changed_fields_only(
        self, db: FakeDb, app: FastAPI, profile: dict[str, str], metadata: dict[str, bool]
    ) -> None:
        _, token = _login(db, "org_admin")

        response = _patch(_client(app), token, {"profile": profile})

        assert response.status_code == 200, response.text
        changes = _changes(db)
        assert changes == [metadata]
        assert all(value is True for value in changes[0].values())

    def test_org_settings_api_security_event_has_the_changed_field_and_the_session_count(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """Only the lifetime changes (the idle timeout is given unchanged): its old/new
        ints and the number of re-timed sessions (the caller's and an editor's)."""
        db.add_org_settings(ORG_ID, session_idle_timeout_minutes=90)
        _, token = _login(db, "org_admin")
        _login(db, "editor")

        response = _patch(
            _client(app),
            token,
            {"security": {"session_idle_timeout_minutes": 90, "session_max_lifetime_hours": 6}},
        )

        assert response.status_code == 200, response.text
        assert _changes(db) == [
            {
                "session_max_lifetime_hours_old": 12,
                "session_max_lifetime_hours_new": 6,
                "sessions_updated": 2,
            }
        ]
        assert all(type(value) is int for value in _changes(db)[0].values())

    def test_org_settings_api_unchanged_sections_record_no_event(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """Security and retention given with their stored values: only the instructions
        event, and no session is re-timed."""
        db.add_org_settings(ORG_ID, **_STORED)
        _, token = _login(db, "org_admin")
        policies = _policies(db)

        response = _patch(
            _client(app),
            token,
            {
                "instructions": "Neue Anweisungen.",
                "security": {"session_idle_timeout_minutes": 120, "session_max_lifetime_hours": 24},
                "retention": {"trash_retention_days": 14},
            },
        )

        assert response.status_code == 200, response.text
        assert _changes(db) == [{"instructions": True}]
        assert _policies(db) == policies

    def test_org_settings_api_audit_rows_hold_no_instructions_name_or_language_value(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "org_admin")

        response = _patch(
            _client(app),
            token,
            {
                "profile": {"display_name": _SECRET_NAME, "default_response_language": "it"},
                "instructions": _SECRET_INSTRUCTIONS,
            },
        )

        assert response.status_code == 200, response.text
        assert _changes(db) == [
            {"display_name": True, "default_response_language": True},
            {"instructions": True},
        ]
        for event in _events(db):
            assert all(value is True for value in event["metadata"].values()), event
        _assert_leak_free(json.dumps(db.audit, default=str))


# ---------------------------------------------------------------------------
# 7. Sessions follow the org's policy (the cleanup criterion)
# ---------------------------------------------------------------------------


class TestOrgSessionPolicy:
    """A policy change re-times the org's live sessions; new logins take it."""

    _POLICY: Final = {"session_idle_timeout_minutes": 30, "session_max_lifetime_hours": 4}

    def test_org_settings_api_session_policy_patch_retimes_the_orgs_live_sessions(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """The caller's and two editors' live sessions take 30 minutes and
        created_at + 4 hours; an ended session of the org, org B's and a Super Admin's
        sessions are untouched; the event counts the three."""
        admin, token = _login(db, "org_admin")
        editor = db.add_account(role="editor")
        db.open_session(editor, created_ago=timedelta(hours=2), expires_in=timedelta(hours=10))
        colleague = db.add_account(role="editor")
        db.open_session(
            colleague,
            idle_timeout_minutes=45,
            last_seen_ago=timedelta(minutes=10),
            created_ago=timedelta(minutes=30),
            expires_in=timedelta(hours=11),
        )
        ended = db.add_account(role="editor")
        db.open_session(
            ended, created_ago=timedelta(hours=12, minutes=1), expires_in=timedelta(minutes=-1)
        )
        other = db.add_account(role="editor", org_id=OTHER_ORG_ID)
        db.open_session(other, created_ago=timedelta(hours=1), expires_in=timedelta(hours=11))
        root = db.add_account(kind="super_admin", role=None)
        db.open_session(root)
        untouched = copy.deepcopy([db.sessions_of(user) for user in (ended, other, root)])

        response = _patch(_client(app), token, {"security": self._POLICY})

        assert response.status_code == 200, response.text
        for user in (admin, editor, colleague):
            row = _one(db.sessions_of(user))
            assert (row["idle_timeout_minutes"], _lifetime(row)) == (30, timedelta(hours=4))
        assert [db.sessions_of(user) for user in (ended, other, root)] == untouched
        assert _changes(db) == [
            {
                "session_idle_timeout_minutes_old": 60,
                "session_idle_timeout_minutes_new": 30,
                "session_max_lifetime_hours_old": 12,
                "session_max_lifetime_hours_new": 4,
                "sessions_updated": 3,
            }
        ]

    def test_org_settings_api_idle_only_change_keeps_the_stored_lifetime(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """Stored 24 hours: an idle-only change re-times the sessions with 24 hours."""
        db.add_org_settings(ORG_ID, session_max_lifetime_hours=24)
        _, token = _login(db, "org_admin")
        editor = db.add_account(role="editor")
        db.open_session(editor, created_ago=timedelta(hours=3), expires_in=timedelta(hours=9))

        response = _patch(_client(app), token, {"security": {"session_idle_timeout_minutes": 240}})

        assert response.status_code == 200, response.text
        row = _one(db.sessions_of(editor))
        assert (row["idle_timeout_minutes"], _lifetime(row)) == (240, timedelta(hours=24))

    def test_org_settings_api_shorter_lifetime_ends_an_older_members_session(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """A session created 5 hours ago is past a new 4-hour lifetime: 401 on its next
        request; a session created just now goes on."""
        _, token = _login(db, "org_admin")
        old_user = db.add_account(role="editor")
        old = db.open_session(
            old_user, created_ago=timedelta(hours=5), expires_in=timedelta(hours=7)
        )
        _, fresh = _login(db, "editor")
        client = _client(app)

        response = _patch(client, token, {"security": {"session_max_lifetime_hours": 4}})

        assert response.status_code == 200, response.text
        assert (_me(client, old), _me(client, fresh)) == (401, 200)

    def test_org_settings_api_shorter_idle_timeout_ends_an_idle_members_session(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """Seen 40 minutes ago with 60 minutes allowed: past a new 30-minute timeout."""
        _, token = _login(db, "org_admin")
        idle_user = db.add_account(role="editor")
        idle = db.open_session(idle_user, last_seen_ago=timedelta(minutes=40))
        client = _client(app)

        response = _patch(client, token, {"security": {"session_idle_timeout_minutes": 30}})

        assert response.status_code == 200, response.text
        assert _me(client, idle) == 401

    @pytest.mark.parametrize(
        ("session", "body"),
        [
            pytest.param(
                {
                    "created_ago": timedelta(hours=12, minutes=1),
                    "expires_in": timedelta(minutes=-1),
                },
                {"session_max_lifetime_hours": 24},
                id="expired-then-longer-lifetime",
            ),
            pytest.param(
                {"last_seen_ago": timedelta(minutes=70)},
                {"session_idle_timeout_minutes": 120},
                id="idle-then-longer-timeout",
            ),
        ],
    )
    def test_org_settings_api_longer_policy_never_revives_an_ended_session(
        self, db: FakeDb, app: FastAPI, session: dict[str, timedelta], body: dict[str, int]
    ) -> None:
        _, token = _login(db, "org_admin")
        user = db.add_account(role="editor")
        ended = db.open_session(user, **session)
        row = copy.deepcopy(db.session(ended))
        client = _client(app)

        response = _patch(client, token, {"security": body})

        assert response.status_code == 200, response.text
        assert db.session(ended) == row
        assert _me(client, ended) == 401

    @pytest.mark.parametrize("body", _NON_SESSION_BODIES)
    def test_org_settings_api_non_session_change_leaves_the_sessions_alone(
        self, db: FakeDb, app: FastAPI, body: dict[str, Any]
    ) -> None:
        """Sessions that differ from the stored policy keep their own values."""
        db.add_org_settings(ORG_ID)
        _, token = _login(db, "org_admin")
        editor = db.add_account(role="editor")
        db.open_session(
            editor,
            idle_timeout_minutes=45,
            created_ago=timedelta(hours=1),
            expires_in=timedelta(hours=3),
        )
        policies = _policies(db)

        response = _patch(_client(app), token, body)

        assert response.status_code == 200, response.text
        assert response.json().get("security") == {
            "session_idle_timeout_minutes": 60,
            "session_max_lifetime_hours": 12,
        }
        assert _policies(db) == policies

    def test_org_settings_api_new_login_after_a_policy_change_takes_the_orgs_policy(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """Org A's editor logs in with 30 minutes / 8 hours (cookie Max-Age 8 hours); org
        B's editor keeps the column defaults (60 minutes / 12 hours)."""
        _, token = _login(db, "org_admin")
        db.add_account(
            role="editor", email="editor.a@example.ch", password_hash=_fake_hash(_PASSWORD)
        )
        db.add_account(
            role="editor",
            org_id=OTHER_ORG_ID,
            email="editor.b@example.ch",
            password_hash=_fake_hash(_PASSWORD),
        )
        client = _client(app)

        patched = _patch(
            client,
            token,
            {"security": {"session_idle_timeout_minutes": 30, "session_max_lifetime_hours": 8}},
        )
        a_token, a_cookie = _log_in(client, "editor.a@example.ch")
        b_token, b_cookie = _log_in(client, "editor.b@example.ch")

        assert patched.status_code == 200, patched.text
        a_row = db.session(a_token)
        assert (a_row["idle_timeout_minutes"], _lifetime(a_row)) == (30, timedelta(hours=8))
        assert a_cookie.get("max-age") == str(8 * 3600)
        b_row = db.session(b_token)
        assert (b_row["idle_timeout_minutes"], _lifetime(b_row)) == (60, timedelta(hours=12))
        assert b_cookie.get("max-age") == str(12 * 3600)


# ---------------------------------------------------------------------------
# 8. No-op and failure: nothing written
# ---------------------------------------------------------------------------


class TestOrgSettingsNothingWritten:
    """A no-op writes and records nothing; an audit failure rolls everything back."""

    @pytest.mark.parametrize("body", _NOOP_BODIES)
    def test_org_settings_api_noop_patch_writes_and_records_nothing(
        self, db: FakeDb, app: FastAPI, body: dict[str, Any]
    ) -> None:
        """The stored values given again (the name compared after the strip): 200 with
        the current settings, no row or session changed, no audit row."""
        db.add_org_settings(ORG_ID, gmail=False, **_STORED)
        _, token = _login(db, "org_admin")
        before = _state(db)

        response = _patch(_client(app), token, body)

        assert response.status_code == 200, response.text
        assert response.json() == _expected(
            instructions="Bestehende Anweisungen.\n",
            idle=120,
            lifetime=24,
            trash=14,
            tools={"gmail": False},
        )
        assert _state(db) == before

    def test_org_settings_api_audit_failure_is_500_and_writes_nothing(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "org_admin")
        _login(db, "editor")
        before = _state(db)
        db.fail_audit = True

        response = _patch(_client(app, raise_server_exceptions=False), token, _EVERY_SECTION)

        assert response.status_code == 500
        assert _state(db) == before

    def test_org_settings_api_late_audit_failure_rolls_back_the_earlier_sections(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """The retention event fails after the profile, instructions and security events
        were written: the org row, the settings, the sessions and the audit log are back
        as they were."""
        _, token = _login(db, "org_admin")
        _login(db, "editor")
        before = _state(db)
        db.fail_audit_when = lambda row: "trash_retention_days_new" in row["metadata"]

        response = _patch(_client(app, raise_server_exceptions=False), token, _EVERY_SECTION)

        assert response.status_code == 500
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 9. Operator blindness and logs
# ---------------------------------------------------------------------------

_PLATFORM_READS: Final = [
    pytest.param("/api/platform/orgs", id="orgs"),
    pytest.param(f"/api/platform/orgs/{ORG_ID}/metadata", id="org-metadata"),
    pytest.param(f"/api/platform/orgs/{ORG_ID}/users", id="org-users"),
    pytest.param("/api/platform/settings", id="platform-settings"),
]


class TestOrgSettingsContentFree:
    """The instructions reach no platform route, log record or audit row."""

    @pytest.mark.parametrize("path", _PLATFORM_READS)
    def test_org_settings_api_platform_route_never_returns_the_instructions(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch, path: str
    ) -> None:
        """The Org Admin stores and reads the instructions; the Super Admin's platform
        route answers 200 without them."""
        monkeypatch.setattr(server, "_get_vllm_available_models", AsyncMock(return_value=[]))
        monkeypatch.setattr(server, "_get_infomaniak_available_models", AsyncMock(return_value=[]))
        _, admin = _login(db, "org_admin")
        _, root = _login(db, "super_admin")
        client = _client(app)

        stored = _patch(client, admin, {"instructions": _SECRET_INSTRUCTIONS})
        shown = _get(client, admin)
        platform = client.get(path, headers=_headers(root))

        assert stored.status_code == 200, stored.text
        assert shown.json().get("instructions") == _SECRET_INSTRUCTIONS
        assert platform.status_code == 200, platform.text
        assert "zephyrmarker" not in platform.text.lower()
        assert "mandantennamen" not in platform.text.lower()

    def test_org_settings_api_flow_logs_no_instructions_or_org_name(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """A change, a read, a 422, a 400 and an audit failure, logged at DEBUG: no
        record carries the instructions or the org name."""
        _bounds(db, 7, 60)
        _, token = _login(db, "org_admin")
        client = _client(app, raise_server_exceptions=False)
        formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")

        with configured_logging("DEBUG", "text") as logs:
            changed = _patch(
                client,
                token,
                {
                    "profile": {"display_name": _SECRET_NAME, "default_response_language": "it"},
                    "instructions": _SECRET_INSTRUCTIONS,
                },
            )
            read = _get(client, token)
            invalid = _patch(client, token, {"instructions": _SECRET_INSTRUCTIONS + chr(0)})
            refused = _patch(
                client,
                token,
                {
                    "instructions": _SECRET_INSTRUCTIONS + " Zwei.",
                    "retention": {"trash_retention_days": 3},
                },
            )
            db.fail_audit = True
            failed = _patch(
                client,
                token,
                {
                    "profile": {"display_name": _SECRET_NAME + " Neu"},
                    "instructions": _SECRET_INSTRUCTIONS + " Drei.",
                },
            )
            logging.getLogger("admino.scoped_settings").debug("org settings probe line")
            text = logs.text + "\n".join(formatter.format(record) for record in logs.records)

        assert [
            changed.status_code,
            read.status_code,
            invalid.status_code,
            refused.status_code,
            failed.status_code,
        ] == [200, 200, 422, 400, 500]
        assert read.json()["profile"]["display_name"] == _SECRET_NAME
        assert "org settings probe line" in text
        _assert_leak_free(text)
