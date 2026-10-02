"""HTTP spec for the settings scopes: /api/me, /api/org and /api/platform settings (GH-159).

Replaces the tests of the removed ``GET`` / ``PATCH /api/settings``. The FastAPI
app from ``create_app()`` runs against the in-memory database of
tests/db_fakes.py (what ``admino.database.get_pool`` returns) with a real
``AppConfig`` (Anthropic, every provider's model set). The real
``require_session``, ``admino.scoped_settings`` and ``admino.audit_events``
code runs; the LLM client factory and the two provider probes
(``server._get_vllm_available_models`` / ``server._get_infomaniak_available_models``)
are mocks, so no network call is ever made.

What these tests pin down (the GH-159 implementation contract):
- Six routes, each behind a session (401 ``{"detail": "Unauthorized"}``), a
  per-user rate limit (429 ``{"detail": "Rate limit exceeded"}``, keys
  ``/api/{me,org,platform}/settings/{get,patch}`` with (1.0, 10) / (0.5, 5) /
  (1.0, 10) / (0.5, 5) / (1.0, 10) / (0.2, 5)), then ``access.can``
  (403 ``{"detail": "Forbidden"}``, nothing read or written, no provider
  probe): ``account.manage`` for /api/me/settings (every role, the Super
  Admin included), ``org.settings.manage`` for /api/org/settings (Org Admin
  only), ``platform.defaults.manage`` for /api/platform/settings (Super Admin
  only). The issue's two AC tests are explicit: an Editor can't patch org
  settings; an Org Admin can't patch platform settings.
- ``GET`` / ``PATCH /api/settings`` and their rate-limit keys are gone.
- Bodies: 422 without echoing the input for extra keys at any level (``llm``
  / ``tools`` / ``limits`` on /api/me/settings, ``tools`` on
  /api/platform/settings, the removed ``files`` tool), non-JSON-bool values,
  empty patches, a bad theme and a model name with a trailing newline, shell
  characters, 201 characters or a non-string value.
- /api/me/settings: each user's own row (two users keep different themes).
- /api/org/settings: the principal's own org only (two orgs' admins never see
  each other's row); each change is an ``org.settings_change`` audit row with
  the client IP; a no-op writes none. GH-161 retired #159's interim AND gate
  (``scoped_settings.all_orgs_tools_gate``): a PATCH sets no attribute on the
  running agent, and each chat run takes its own org's enabled services
  (``tool_policy.enabled_tools`` of ``_agent.run``), so one org's switch
  never reaches another org's runs. An audit failure is a 500 with nothing
  written.
- /api/platform/settings: GET returns ``llm`` (the stored provider and models,
  ``""`` for NULL; the available models from the two probe helpers, filtered
  by ``SettingsLLM``; key flags that are booleans of env presence, never
  values) and ``limits`` (the stored five). PATCH of ``llm`` (#159; GH-160
  adds the other sections, below): a provider change, or a model change of the
  active vllm/infomaniak provider, builds a new client with
  ``create_llm_client`` BEFORE writing (from the merged ``LLMConfig``, the
  config's other llm fields kept), swaps ``_agent._llm`` and closes the old
  client best-effort. A no-op never re-inits. A client that can't be built is
  a 400 ``{"detail": "Failed to create LLM client for the selected
  provider"}`` with nothing written and no audit row; an audit failure is a
  500, the new client is closed and the old one kept. Each change is a
  ``platform.settings_change`` audit row naming the changed fields only.
- Cross-origin PATCH → 403 before any database call.
- The server lifespan computes no tools gate and reloads no promoted
  permissions (GH-161): it reads no org_settings row and sets nothing on the
  agent; ``scoped_settings.all_orgs_tools_gate`` is gone.
- No email, name or model name in any log record; no provider or model value
  in any audit row.

GH-160 (platform defaults) adds, over the same routes:
- ``GET /api/platform/settings`` returns five sections, ``llm``, ``limits``,
  ``files``, ``retention`` and ``security``, from the stored row (read with
  ``scoped_settings.load_platform_settings``, which also replaces
  ``scoped_settings._platform_cache``).
- ``PATCH /api/platform/settings`` takes any of the five sections (``limits``
  is no longer refused). Each field is a strict int within the issue's bounds:
  a bool, float, numeric string, out-of-bounds value, unknown field or empty
  patch (only empty or null sections) is a 422 whose error points at the
  field, without echoing the input. Every changed section is one
  ``platform.settings_change`` audit row with ``<field>_old`` /
  ``<field>_new`` ints and the client IP (``llm`` stays names only); an
  unchanged section writes none, a no-op writes nothing at all. A mixed patch
  (``llm`` + others) is one request with the #159 LLM path unchanged. Merged
  retention with ``trash_min_days`` above ``trash_max_days`` is a 400 ``{"detail":
  "The trash retention minimum can't exceed the maximum."}`` with nothing
  written, no audit row and any newly built LLM client closed. An audit
  failure is a 500 with nothing written and the cache unchanged. The
  response has all five sections after the change and the cache equals it.
- Without a restart: after a ``limits`` change, ``POST /api/message`` refuses
  a message over the new ``max_message_length`` (422 "Message exceeds maximum
  length of N characters") and both ``POST /api/message`` and ``POST
  /api/confirm`` pass ``agent_config`` (max_tool_calls, max_context_messages,
  confirmation_timeout_s from the stored limits) to ``_agent.run``. After a
  ``security`` session change a new Super Admin login stores the new idle
  timeout and lifetime, every open Super Admin session follows (idle timeout
  updated, ``expires_at = created_at + lifetime``; one older than the new
  lifetime is 401 on its next request), members' sessions are untouched and
  the audit row carries ``sessions_updated``. After a ``retention`` change the
  next org deletion uses the new grace period.
- A member role's PATCH of any section is 403 with nothing read or written.

GH-35 (settings page controls) adds, on the user scope:
- ``notifications.task_done`` (the task-done pings toggle, default off,
  independent of ``notifications.enabled``) on ``GET`` / ``PATCH
  /api/me/settings``, stored in ``user_settings.notifications_task_done``. A
  field not given keeps its stored value; a non-JSON-bool ``task_done`` is a 422
  at that field, a ``task_done``-only null patch the "nothing given" 422, both
  without echo.
- ``POST /api/me/settings/reset``: behind a session (401), a per-user rate
  limit (key ``/api/me/settings/reset``, (0.2, 3), 429 before any database
  work), then ``account.manage`` (every role; 403 when ``can`` refuses, nothing
  written). It reverts the caller's own ``user_settings`` row (absent or the
  column defaults afterwards) and answers 200 with the defaults. Other users'
  rows (same org or another), ``org_settings``, ``platform_settings`` and the
  caller's ``users`` row (languages, name) are untouched; no audit row; no
  email or name in a log record; cross-origin is a 403 before the database.

Contract notes for the implementation: ``admino.llm.create_llm_client`` is
looked up at call time (as today); the lifespan and the handlers reach
``admino.scoped_settings`` functions at call time (module attribute or a
lazy import). The conftest primes ``scoped_settings._platform_cache`` with the
default row; tests whose consumers must see this file's FakeDb row set it to
None (or load it through a GET or PATCH first).

GH-162 (data residency) adds, on the org scope:
- ``GET`` / ``PATCH /api/org/settings`` answer ``{"tools": ..., "data_residency":
  <bool>}``: the actor's own org's residency policy (``SELECT data_residency
  FROM organizations WHERE id = $1`` with the actor's org), read on every
  request, read-only here. The fixture orgs have no residency, so the GH-159
  bodies gain ``"data_residency": false``.
- A Google/Microsoft switch can still be changed while residency is on: it is
  stored and audited as before (the gating is separate), and the response
  says ``data_residency: true``.
- The PATCH body can't set residency: a ``data_residency`` key, at the top or
  under ``tools``, is a 422 like any unknown key (no echo, nothing written,
  the org keeps its policy).

All database calls are faked. No network, no real PostgreSQL, no LLM.

Security notes:
- Least privilege and tenant isolation: the org is always the principal's
  own; the Super Admin reaches no org's settings; member roles never reach the
  platform settings.
- Operator blindness: the platform routes return no content and no secret
  (key presence flags only).
- Fail closed: an audit failure is a 500 and nothing is written.
"""

from __future__ import annotations

import contextlib
import copy
import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from admino import scoped_settings, server
from admino.access import Capability
from admino.config import AppConfig
from admino.models import AgentConfig, AgentResult, LLMMessage, PendingConfirmation, ToolCall
from admino.server import create_app
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, PUBLIC_URL, TOOL_NAMES, FakeDb, fake_hash, plain
from tests.lifespan_stubs import patch_login_throttle_purge_job, patch_org_purge_job

if TYPE_CHECKING:
    import uuid
    from collections.abc import Callable

    import httpx
    from fastapi import FastAPI
    from fastapi.dependencies.models import Dependant

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE = "admino_session"
_IP_A = "203.0.113.5"
_ME = "/api/me/settings"
_ORG = "/api/org/settings"
_PLATFORM = "/api/platform/settings"
_RESET = "/api/me/settings/reset"
_RESET_KEY = "/api/me/settings/reset"
# GH-35: the user scope's defaults (task-done pings start off).
_ME_DEFAULTS: dict[str, Any] = {
    "appearance": {"theme": "light"},
    "notifications": {"enabled": True, "task_done": False},
}
_UNAUTHORIZED = {"detail": "Unauthorized"}
_FORBIDDEN = {"detail": "Forbidden"}
_CSRF_REFUSED = {"detail": "Cross-origin request refused"}
_RATE_LIMITED = {"detail": "Rate limit exceeded"}
_CLIENT_FAILED = {"detail": "Failed to create LLM client for the selected provider"}
_ALL_ON: dict[str, bool] = dict.fromkeys(TOOL_NAMES, True)
_ROLES = ["super_admin", "org_admin", "editor", "viewer"]
_MODEL_MARKER = "Zephyrmarker/Model-77"
_KEY_MARKER = "sk-ant-zephyrmarker-key-0000000000000000"
_TOKEN_MARKER = "ik-zephyrmarker-token-1111111111"
_UNSET: Final = object()

# action -> (method, path)
_ROUTES: dict[str, tuple[str, str]] = {
    "me_get": ("GET", _ME),
    "me_patch": ("PATCH", _ME),
    "org_get": ("GET", _ORG),
    "org_patch": ("PATCH", _ORG),
    "platform_get": ("GET", _PLATFORM),
    "platform_patch": ("PATCH", _PLATFORM),
}
_ACTIONS = list(_ROUTES)
_PATCH_ACTIONS = ["me_patch", "org_patch", "platform_patch"]
_SCOPE = {action: action.split("_")[0] for action in _ACTIONS}
_ROUTE_KEYS: dict[str, str] = {
    action: f"/api/{_SCOPE[action]}/settings/{action.split('_')[1]}" for action in _ACTIONS
}
_EXPECTED_LIMITS: dict[str, tuple[float, int]] = {
    "/api/me/settings/get": (1.0, 10),
    "/api/me/settings/patch": (0.5, 5),
    "/api/org/settings/get": (1.0, 10),
    "/api/org/settings/patch": (0.5, 5),
    "/api/platform/settings/get": (1.0, 10),
    "/api/platform/settings/patch": (0.2, 5),
    # GH-35: reset my settings, per user.
    _RESET_KEY: (0.2, 3),
}
# Read at import, before any fixture patches the limits.
_CONFIGURED_LIMITS = {key: server._RATE_LIMITS.get(key) for key in _EXPECTED_LIMITS}
_OLD_RATE_KEYS = ["/api/settings/get", "/api/settings/patch"]
_CAPABILITIES: dict[str, Capability] = {
    "me": Capability.ACCOUNT_MANAGE,
    "org": Capability.ORG_SETTINGS_MANAGE,
    "platform": Capability.PLATFORM_DEFAULTS_MANAGE,
}
_ALLOWED_ROLES: dict[str, frozenset[str]] = {
    "me": frozenset(_ROLES),
    "org": frozenset({"org_admin"}),
    "platform": frozenset({"super_admin"}),
}
_SCOPE_TABLES = {"me": "user_settings", "org": "org_settings", "platform": "platform_settings"}
_DEFAULT_BODIES: dict[str, dict[str, Any]] = {
    "me_patch": {"appearance": {"theme": "dark"}},
    "org_patch": {"tools": {"gmail": False}},
    "platform_patch": {"llm": {"provider": "openai"}},
}
_MATRIX = [
    pytest.param(action, role, id=f"{action}-{role}") for action in _ACTIONS for role in _ROLES
]
_CROSS_ORIGIN = [
    pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
    pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
]
_STORED_LIMITS = {
    "max_tool_calls_per_message": 7,
    "max_pending_confirmations": 4,
    "confirmation_timeout_s": 120,
    "max_message_length": 5000,
    "max_context_messages": 30,
}
_LLM_RESPONSE_KEYS = frozenset(
    {
        "provider",
        "anthropic_model",
        "openai_model",
        "infomaniak_model",
        "infomaniak_available_models",
        "vllm_model",
        "vllm_available_models",
        "anthropic_key_configured",
        "openai_key_configured",
        "infomaniak_token_configured",
    }
)

# GH-35: values a strict-bool ``task_done`` refuses (id, value).
_BAD_TASK_DONE_VALUES: list[tuple[str, Any]] = [
    ("task-done-marker", "ECHOMARK42"),
    ("task-done-yes", "yes"),
    ("task-done-1", 1),
    ("task-done-0", 0),
    ("task-done-string-true", "true"),
    ("task-done-list", [1]),
    ("task-done-object", {}),
]
# GH-35: patches whose only task_done is null give nothing to change.
_NULL_TASK_DONE_BODIES = [
    pytest.param({"notifications": {"task_done": None}}, id="null-task-done"),
    pytest.param(
        {"notifications": {"enabled": None, "task_done": None}}, id="null-enabled-and-task-done"
    ),
    pytest.param(
        {"appearance": None, "notifications": {"task_done": None}},
        id="null-appearance-and-task-done",
    ),
]
_BAD_ME_BODIES = [
    pytest.param({"llm": {"provider": "ECHOMARK42"}}, id="extra-llm"),
    pytest.param({"tools": {"gmail": False}}, id="extra-tools"),
    pytest.param({"limits": {"max_message_length": 4000}}, id="extra-limits"),
    pytest.param({"appearance": {"theme": "dark"}, "ui_language": "fr"}, id="extra-ui-language"),
    pytest.param(
        {"appearance": {"theme": "dark"}, "server": {"host": "ECHOMARK42"}}, id="extra-server"
    ),
    pytest.param({"appearance": {"theme": "dark", "font": "ECHOMARK42"}}, id="extra-nested"),
    pytest.param(
        {"notifications": {"enabled": True, "email": "ECHOMARK42@example.ch"}},
        id="extra-nested-notifications",
    ),
    pytest.param({"notifications": {"enabled": "yes"}}, id="enabled-yes"),
    pytest.param({"notifications": {"enabled": 1}}, id="enabled-1"),
    pytest.param({"notifications": {"enabled": 0}}, id="enabled-0"),
    pytest.param({"notifications": {"enabled": "true"}}, id="enabled-string-true"),
    pytest.param({"notifications": {"enabled": [1, 2]}}, id="enabled-list"),
    pytest.param({"appearance": {"theme": "ECHOMARK42-blue"}}, id="theme-unknown"),
    pytest.param({"appearance": {"theme": "DARK"}}, id="theme-capitals"),
    pytest.param({"appearance": {"theme": ""}}, id="theme-empty"),
    pytest.param({"appearance": {"theme": 42}}, id="theme-int"),
    pytest.param({}, id="empty-object"),
    pytest.param({"appearance": {}}, id="empty-appearance"),
    pytest.param({"appearance": None}, id="null-appearance"),
    pytest.param({"notifications": {"enabled": None}}, id="null-enabled"),
    pytest.param({"appearance": {}, "notifications": {}}, id="both-empty"),
    pytest.param([], id="list"),
    pytest.param("ECHOMARK42", id="string"),
    *(
        pytest.param({"notifications": {"task_done": value}}, id=name)
        for name, value in _BAD_TASK_DONE_VALUES
    ),
    pytest.param(
        {"appearance": {"theme": "dark"}, "notifications": {"task_done": "ECHOMARK42"}},
        id="valid-theme-bad-task-done",
    ),
    *_NULL_TASK_DONE_BODIES,
]
_BAD_ORG_BODIES = [
    pytest.param({"tools": {"files": False}}, id="removed-files-tool"),
    pytest.param({"tools": {"gmail": False, "slack": True}}, id="unknown-tool"),
    pytest.param({"tools": {"gmail": "yes"}}, id="bool-yes"),
    pytest.param({"tools": {"gmail": 1}}, id="bool-1"),
    pytest.param({"tools": {"gmail": "false"}}, id="bool-string"),
    pytest.param({"tools": {}}, id="no-tool"),
    pytest.param({"tools": {"gmail": None}}, id="only-null"),
    pytest.param({}, id="empty-object"),
    pytest.param({"tools": None}, id="null-tools"),
    pytest.param({"gmail": False}, id="tool-at-top-level"),
    pytest.param({"tools": {"gmail": False}, "llm": {"provider": "vllm"}}, id="extra-llm"),
    pytest.param({"tools": {"gmail": False}, "org_id": str(OTHER_ORG_ID)}, id="extra-org-id"),
    pytest.param({"tools": ["gmail"]}, id="tools-list"),
    pytest.param("ECHOMARK42", id="string"),
]
# GH-160: a ``limits`` section is accepted now (see _BAD_SECTION_BODIES for its bad values).
_BAD_PLATFORM_BODIES = [
    pytest.param({"llm": {"provider": "openai"}, "tools": {"gmail": False}}, id="extra-tools"),
    pytest.param({"llm": {}}, id="empty-llm"),
    pytest.param({"llm": {"provider": None}}, id="only-null"),
    pytest.param({}, id="empty-object"),
    pytest.param({"llm": None}, id="null-llm"),
    pytest.param({"llm": {"provider": "ECHOMARK42"}}, id="provider-unknown"),
    pytest.param({"llm": {"provider": 123}}, id="provider-int"),
    pytest.param({"llm": {"anthropic_model": "ECHOMARK42-model\n"}}, id="model-trailing-newline"),
    pytest.param({"llm": {"anthropic_model": "ECHOMARK42; rm -rf /"}}, id="model-semicolon"),
    pytest.param({"llm": {"openai_model": "ECHOMARK42$(id)"}}, id="model-subshell"),
    pytest.param({"llm": {"infomaniak_model": "ECHOMARK42`id`"}}, id="model-backtick"),
    pytest.param({"llm": {"vllm_model": "ECHOMARK42|cat"}}, id="model-pipe"),
    pytest.param({"llm": {"vllm_model": "ECHOMARK42" + "a" * 191}}, id="model-201-chars"),
    pytest.param(
        {"llm": {"anthropic_model": "'; DROP TABLE platform_settings; --ECHOMARK42"}},
        id="model-sql",
    ),
    pytest.param({"llm": {"anthropic_model": 1234567}}, id="model-int"),
    pytest.param({"llm": {"openai_model": ""}}, id="model-empty"),
    pytest.param({"llm": {"api_key": "sk-ECHOMARK42-secret"}}, id="extra-api-key"),
    pytest.param("ECHOMARK42", id="string"),
]

# GH-160: the editable sections, section -> field -> (default, low, high) (the issue's
# Decisions; the limits' defaults are LimitsConfig's).
_SECTION_FIELDS: dict[str, dict[str, tuple[int, int, int]]] = {
    "limits": {
        "max_tool_calls_per_message": (10, 1, 100),
        "max_pending_confirmations": (3, 1, 50),
        "confirmation_timeout_s": (300, 10, 3600),
        "max_message_length": (4000, 1, 100000),
        "max_context_messages": (20, 1, 200),
    },
    "files": {
        "max_file_size_mb": (50, 1, 500),
        "max_files_per_message": (10, 1, 50),
        "max_pages_per_file": (100, 1, 1000),
        "render_dpi": (150, 72, 300),
    },
    "retention": {
        "trash_min_days": (0, 0, 90),
        "trash_max_days": (90, 0, 90),
        "audit_months": (12, 6, 84),
        "org_deletion_grace_days": (30, 7, 90),
    },
    "security": {
        "rate_limit_per_minute": (20, 1, 600),
        "lockout_after_failures": (10, 3, 100),
        "lockout_window_minutes": (15, 1, 1440),
        "lockout_minutes": (15, 1, 1440),
        "session_idle_timeout_minutes": (60, 15, 480),
        "session_max_lifetime_hours": (12, 1, 72),
    },
}
_EDITABLE = tuple(_SECTION_FIELDS)
_SECTIONS = frozenset({"llm", *_EDITABLE})
# What the db fixture's row holds: its limits and the defaults of every new section.
_STORED_SECTIONS: dict[str, dict[str, int]] = {
    "limits": dict(_STORED_LIMITS),
    **{
        section: {field: default for field, (default, _, _) in fields.items()}
        for section, fields in _SECTION_FIELDS.items()
        if section != "limits"
    },
}
_TRASH_REFUSED = {"detail": "The trash retention minimum can't exceed the maximum."}
_FIELDS = [
    (section, field, low, high)
    for section, fields in _SECTION_FIELDS.items()
    for field, (_, low, high) in fields.items()
]
_BOUNDARY_VALUES = [
    pytest.param(section, field, value, id=f"{field}-{name}")
    for section, field, low, high in _FIELDS
    for name, value in (("low", low), ("high", high))
]
# (body, the loc an error must start with)
_BAD_SECTION_BODIES = [
    *(
        pytest.param({section: {field: value}}, ["body", section, field], id=f"{field}-{name}")
        for section, field, low, high in _FIELDS
        for name, value in (("below", low - 1), ("above", high + 1))
    ),
    *(
        pytest.param({section: {field: value}}, ["body", section, field], id=f"{section}-{name}")
        for section, field in (
            ("limits", "max_message_length"),
            ("files", "render_dpi"),
            ("retention", "audit_months"),
            ("security", "lockout_minutes"),
        )
        for name, value in (
            ("true", True),
            ("false", False),
            ("float", 100.0),
            ("fraction", 100.5),
            ("numeric-string", "100"),
            ("string", "ECHOMARK42"),
            ("list", [100]),
            ("object", {"value": 100}),
            ("huge", 9876543210),
            ("negative-huge", -9876543210),
        )
    ),
    pytest.param(
        {"files": {"render_dpi": 200, "virus_scan": "ECHOMARK42"}},
        ["body", "files", "virus_scan"],
        id="files-unknown-field",
    ),
    pytest.param(
        {"limits": {"max_message_length": 10, "max_file_size_mb": 5}},
        ["body", "limits", "max_file_size_mb"],
        id="limits-field-of-another-section",
    ),
    pytest.param(
        {"retention": {"trash_days": 5}},
        ["body", "retention", "trash_days"],
        id="retention-unknown",
    ),
    pytest.param(
        {"security": {"session_idle_timeout_minutes": 30, "delay_after_failures": 5}},
        ["body", "security", "delay_after_failures"],
        id="security-delay-is-a-constant",
    ),
    pytest.param(
        {"security": {"lockout_minutes": 30}, "storage": {"quota_gb": 5}},
        ["body", "storage"],
        id="unknown-section-beside-a-valid-one",
    ),
    pytest.param(
        {"llm": {"provider": "openai"}, "files": {"render_dpi": 301}},
        ["body", "files", "render_dpi"],
        id="valid-llm-bad-files",
    ),
    pytest.param(
        {"llm": {"provider": "ECHOMARK42"}, "limits": {"max_message_length": 10}},
        ["body", "llm", "provider"],
        id="bad-llm-valid-limits",
    ),
    pytest.param({"files": 5}, ["body", "files"], id="files-int"),
    pytest.param({"security": ["lockout_minutes"]}, ["body", "security"], id="security-list"),
    pytest.param({"retention": "ECHOMARK42"}, ["body", "retention"], id="retention-string"),
    pytest.param({"files": {}}, ["body"], id="empty-files"),
    pytest.param({"limits": {}}, ["body"], id="empty-limits"),
    pytest.param({"files": {"render_dpi": None}}, ["body"], id="only-null-field"),
    pytest.param({"files": None, "retention": None}, ["body"], id="null-sections"),
    pytest.param({"llm": {}, "security": {}}, ["body"], id="empty-llm-and-security"),
    pytest.param(
        {"llm": {}, "limits": {}, "files": {}, "retention": {}, "security": {}},
        ["body"],
        id="every-section-empty",
    ),
]
# One valid change per section: (section, fields), against the db fixture's row.
_SECTION_PATCHES = [
    pytest.param(
        "limits",
        {"max_message_length": 10, "max_tool_calls_per_message": 60, "confirmation_timeout_s": 900},
        id="limits",
    ),
    pytest.param(
        "files",
        {"max_file_size_mb": 200, "max_files_per_message": 20, "max_pages_per_file": 500},
        id="files",
    ),
    pytest.param(
        "retention",
        {"trash_min_days": 7, "trash_max_days": 60, "audit_months": 24},
        id="retention",
    ),
    pytest.param(
        "security",
        {"rate_limit_per_minute": 30, "lockout_after_failures": 5, "lockout_window_minutes": 30},
        id="security",
    ),
]
_MEMBER_SECTION_BODIES = [
    pytest.param({"limits": {"max_message_length": 10}}, id="limits"),
    pytest.param({"files": {"render_dpi": 300}}, id="files"),
    pytest.param({"retention": {"org_deletion_grace_days": 7}}, id="retention"),
    pytest.param({"security": {"session_max_lifetime_hours": 1}}, id="security"),
]
_PASSWORD = "correct horse battery staple"
_METADATA_KEY = re.compile(r"[a-z][a-z_]*_(?:old|new)|sessions_updated")


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@dataclass
class _Probes:
    """The mocked provider probes and LLM client factory."""

    vllm: AsyncMock
    infomaniak: AsyncMock
    create: MagicMock
    new_client: MagicMock


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch) -> FakeDb:
    """The fake database the server's get_pool() returns: two active orgs without data
    residency (GH-162) and the platform row (Anthropic active, every model set, limits
    7/4/120/5000/30)."""
    fake = FakeDb()
    fake.add_org(ORG_ID, data_residency=False)
    fake.add_org(OTHER_ORG_ID, data_residency=False)
    fake.add_platform_settings(
        llm_provider="anthropic",
        anthropic_model="claude-sonnet-4-6",
        openai_model="gpt-4o",
        infomaniak_model="Qwen/Qwen3.5-397B-A17B-FP8",
        vllm_model="Qwen/Qwen3-4B-Instruct-2507",
        **_STORED_LIMITS,
    )
    monkeypatch.setattr("admino.database.get_pool", lambda: fake.pool)
    return fake


@pytest.fixture(autouse=True)
def _fast_passwords(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace Argon2 with a fast fake (the real hashing is covered by test_passwords)."""
    monkeypatch.setattr(
        "admino.passwords.verify_password", lambda password, encoded: encoded == fake_hash(password)
    )
    monkeypatch.setattr("admino.passwords.needs_rehash", lambda _encoded: False)
    monkeypatch.setattr("admino.passwords.hash_password", fake_hash)


@pytest.fixture(autouse=True)
def configured_keys(monkeypatch: pytest.MonkeyPatch) -> frozenset[str]:
    """Functional tests aren't about rate limits: every key gets a large bucket (the
    rate-limit tests set their own). Returns the keys the server configured itself."""
    present = frozenset(key for key in _EXPECTED_LIMITS if key in server._RATE_LIMITS)
    for key in _EXPECTED_LIMITS:
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))
    return present


@pytest.fixture(autouse=True)
def probes(monkeypatch: pytest.MonkeyPatch) -> _Probes:
    """No network: both provider probes and the LLM client factory are mocks."""
    vllm = AsyncMock(return_value=[])
    infomaniak = AsyncMock(return_value=[])
    monkeypatch.setattr(server, "_get_vllm_available_models", vllm)
    monkeypatch.setattr(server, "_get_infomaniak_available_models", infomaniak)
    new_client = MagicMock(name="new-llm-client")
    new_client.close = AsyncMock()
    create = MagicMock(return_value=new_client)
    monkeypatch.setattr("admino.llm.create_llm_client", create)
    monkeypatch.setattr(server, "create_llm_client", create, raising=False)
    return _Probes(vllm=vllm, infomaniak=infomaniak, create=create, new_client=new_client)


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provider credentials: an Anthropic key only (a marker value)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", _KEY_MARKER)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("INFOMANIAK_API_TOKEN", raising=False)


@pytest.fixture()
def agent() -> MagicMock:
    """A stub agent with its live LLM client (closable). GH-161: the server never sets
    ``_tools_enabled`` (or ``_permissions`` / ``_promoted``) on it, which
    ``_assert_no_agent_gate`` checks through ``vars()``."""
    stub = MagicMock(name="agent")
    old_client = MagicMock(name="old-llm-client")
    old_client.close = AsyncMock()
    stub._llm = old_client
    return stub


_AGENT_POLICY_ATTRS: Final = ("_tools_enabled", "_permissions", "_promoted")


def _assert_no_agent_gate(agent: MagicMock) -> None:
    """Nothing assigned the retired gate or policy attributes on the agent (GH-161)."""
    assigned = [name for name in _AGENT_POLICY_ATTRS if name in vars(agent)]
    assert assigned == [], f"the server set {assigned} on the shared agent"


def _config() -> AppConfig:
    """A real config: Anthropic, every model set, and llm fields the platform row lacks."""
    return AppConfig.model_validate(
        {
            "server": {"host": "127.0.0.1", "port": 8000, "public_url": PUBLIC_URL},
            "llm": {
                "provider": "anthropic",
                "anthropic_model": "claude-sonnet-4-6",
                "openai_model": "gpt-4o",
                "infomaniak_model": "Qwen/Qwen3.5-397B-A17B-FP8",
                "vllm_model": "Qwen/Qwen3-4B-Instruct-2507",
                "timeout_s": 77,
                "vllm_base_url": "http://vllm-test:8000/v1",
                "max_response_tokens": 1234,
            },
        }
    )


@pytest.fixture()
def app(agent: MagicMock) -> FastAPI:
    """create_app with the stub agent and the real config (no lifespan under TestClient)."""
    return create_app(agent=agent, config=_config())  # type: ignore[arg-type]


def _client(app: FastAPI, ip: str = _IP_A, **kwargs: Any) -> TestClient:
    return TestClient(app, client=(ip, 50000), follow_redirects=False, **kwargs)


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


def _call(
    client: TestClient, action: str, token: str | None, *, body: Any = _UNSET, **headers: str
) -> httpx.Response:
    """Call one of the six routes (a PATCH with its default body unless one is given)."""
    method, path = _ROUTES[action]
    if body is _UNSET:
        body = _DEFAULT_BODIES.get(action)
    kwargs: dict[str, Any] = {} if body is None else {"json": body}
    return client.request(method, path, headers=_headers(token, **headers), **kwargs)


def _depends_on(dependant: Dependant, target: Callable[..., Any]) -> bool:
    return any(dep.call is target or _depends_on(dep, target) for dep in dependant.dependencies)


def _route(app: FastAPI, method: str, path: str) -> APIRoute:
    matches = [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and route.path == path and method in route.methods
    ]
    assert len(matches) == 1, f"{method} {path} is not registered"
    return matches[0]


def _route_of(app: FastAPI, action: str) -> APIRoute:
    return _route(app, *_ROUTES[action])


def _state(db: FakeDb) -> dict[str, Any]:
    """A deep copy of every table a settings route may write (sessions excluded: any
    request may refresh last_seen_at)."""
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


def _uuid(value: Any) -> uuid.UUID | None:
    return None if value is None else plain(value)


def _row(db: FakeDb) -> dict[str, Any]:
    row = db.platform_row()
    assert row is not None
    return row


def _limited(monkeypatch: pytest.MonkeyPatch, key: str) -> None:
    """One request per key, then nothing for a long time."""
    monkeypatch.setitem(server._RATE_LIMITS, key, (0.001, 1))


def _echo_markers(value: Any) -> list[str]:
    """What a 422 body must never contain: the ECHOMARK42 marker and every long string or
    large number the request carried (at any depth)."""
    markers = ["ECHOMARK42"]
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str) and len(item.strip()) >= 10:
            markers.append(item.strip())
        elif isinstance(item, int) and not isinstance(item, bool) and abs(item) >= 100000:
            markers.append(str(item))
    return markers


def _log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured app record (not the test client's own httpx request lines)."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(
        formatter.format(record)
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore"))
    )


class _CanSpy:
    """Wraps admino.access.can wherever it is looked up; records every capability asked
    for and can refuse chosen capabilities."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, deny: frozenset[Capability] = frozenset()
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
        monkeypatch.setattr(server, "can", spy, raising=False)
        with contextlib.suppress(ImportError):
            from admino import scoped_settings

            if hasattr(scoped_settings, "can"):
                monkeypatch.setattr(scoped_settings, "can", spy)


def _editable(body: dict[str, Any]) -> dict[str, Any]:
    """The four editable sections of a platform settings response (GH-160)."""
    return {section: body.get(section) for section in _EDITABLE}


def _after(changes: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    """The db fixture's sections with the given changes applied."""
    sections = copy.deepcopy(_STORED_SECTIONS)
    for section, fields in changes.items():
        sections[section].update(fields)
    return sections


def _cached_sections() -> dict[str, Any]:
    """The editable sections of scoped_settings._platform_cache, as plain dicts."""
    cache = scoped_settings._platform_cache
    assert cache is not None
    return {section: getattr(cache, section).model_dump() for section in _EDITABLE}


def _cache_the_row(app: FastAPI, token: str) -> None:
    """GET /api/platform/settings: the cache holds the stored row (GH-160). A failed
    PATCH may re-read the row into the cache, but never its own uncommitted values."""
    response = _call(_client(app), "platform_get", token)
    assert response.status_code == 200, response.text


def _row_without_updated_at(db: FakeDb) -> dict[str, Any]:
    return {key: value for key, value in _row(db).items() if key != "updated_at"}


def _settings_changes(db: FakeDb) -> list[dict[str, Any]]:
    """The metadata of every platform.settings_change audit row, in order."""
    return [row["metadata"] for row in db.audit if row["action"] == "platform.settings_change"]


def _old_new(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    """The ``<field>_old`` / ``<field>_new`` metadata of the fields that changed."""
    metadata: dict[str, int] = {}
    for field, new in after.items():
        if before[field] != new:
            metadata[f"{field}_old"] = before[field]
            metadata[f"{field}_new"] = new
    return metadata


def _agent_result(pending: PendingConfirmation | None = None) -> AgentResult:
    return AgentResult(
        status="final" if pending is None else "awaiting_confirmation",
        response="Done.",
        history=[
            LLMMessage(role="user", content="hi"),
            LLMMessage(role="assistant", content="Done."),
        ],
        tool_calls=[],
        pending_confirmation=pending,
    )


def _pending(session_id: str) -> PendingConfirmation:
    now = datetime.now(UTC)
    return PendingConfirmation(
        confirmation_id="confirm-160",
        session_id=session_id,
        tool_call=ToolCall(tool="calendar", action="create", args={}),
        created_at=now,
        expires_at=now + timedelta(seconds=300),
    )


def _post_message(
    client: TestClient, token: str, message: str, session_id: str = "chat-160"
) -> httpx.Response:
    return client.post(
        "/api/message",
        headers=_headers(token),
        json={"message": message, "session_id": session_id},
    )


def _agent_config_of(agent: MagicMock, index: int = -1) -> tuple[int, int, float]:
    """(max_tool_calls, max_context_messages, confirmation_timeout_s) of one agent run."""
    config = agent.run.await_args_list[index].kwargs["agent_config"]
    assert isinstance(config, AgentConfig), config
    return (config.max_tool_calls, config.max_context_messages, config.confirmation_timeout_s)


def _with_password(db: FakeDb, email: str, *, kind: str = "member") -> uuid.UUID:
    """An account that can log in with _PASSWORD (a Super Admin, or an Editor of ORG_ID)."""
    if kind == "super_admin":
        return db.add_account(
            kind="super_admin", role=None, email=email, password_hash=fake_hash(_PASSWORD)
        )
    return db.add_account(role="editor", email=email, password_hash=fake_hash(_PASSWORD))


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


def _lifetime(row: dict[str, Any]) -> timedelta:
    return row["expires_at"] - row["created_at"]


# ---------------------------------------------------------------------------
# 1. The routes
# ---------------------------------------------------------------------------


class TestRoutes:
    """Six session routes with their own per-user rate-limit keys; /api/settings is gone."""

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_settings_api_route_is_registered(self, app: FastAPI, action: str) -> None:
        _route_of(app, action)

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_settings_api_route_depends_on_require_session(self, app: FastAPI, action: str) -> None:
        assert _depends_on(_route_of(app, action).dependant, server.require_session)

    def test_settings_api_rate_limit_keys_are_configured(
        self, configured_keys: frozenset[str]
    ) -> None:
        assert configured_keys == frozenset(_EXPECTED_LIMITS)

    @pytest.mark.parametrize("key", list(_EXPECTED_LIMITS))
    def test_settings_api_rate_limit_values(self, key: str) -> None:
        assert _CONFIGURED_LIMITS[key] == pytest.approx(_EXPECTED_LIMITS[key])

    @pytest.mark.parametrize("key", _OLD_RATE_KEYS)
    def test_settings_api_old_rate_limit_keys_are_removed(self, key: str) -> None:
        assert key not in server._RATE_LIMITS

    def test_settings_api_old_route_is_not_registered(self, app: FastAPI) -> None:
        """No APIRoute answers /api/settings any more, for any method."""
        assert [
            route
            for route in app.routes
            if isinstance(route, APIRoute) and route.path == "/api/settings"
        ] == []

    def test_settings_api_old_get_is_404_and_reads_nothing(self, db: FakeDb, app: FastAPI) -> None:
        _, token = _login(db, "org_admin")

        response = _client(app).get("/api/settings", headers=_headers(token))

        assert response.status_code == 404
        assert db.matching(r"\b(?:platform|org|user)_settings\b") == []

    def test_settings_api_old_patch_is_refused_and_writes_nothing(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """404 (or the static files' 405 when the PWA is mounted at "/"), nothing written."""
        _, token = _login(db, "org_admin")
        before = _state(db)

        response = _client(app).patch(
            "/api/settings",
            headers=_headers(token),
            json={"appearance": {"theme": "dark"}, "tools": {"gmail": False}},
        )

        assert response.status_code in {404, 405}
        assert _state(db) == before

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_settings_api_route_without_a_session_is_401(
        self, db: FakeDb, app: FastAPI, action: str
    ) -> None:
        """No cookie → 401 and no database call."""
        _route_of(app, action)

        response = _call(_client(app), action, None)

        assert response.status_code == 401
        assert response.json() == _UNAUTHORIZED
        assert db.calls == []

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_settings_api_route_with_an_unknown_cookie_is_401(
        self, db: FakeDb, app: FastAPI, action: str
    ) -> None:
        _route_of(app, action)
        before = _state(db)

        response = _call(_client(app), action, "not-a-session-token")

        assert response.status_code == 401
        assert response.json() == _UNAUTHORIZED
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 2. Authorization: the role matrix through access.can
# ---------------------------------------------------------------------------


class TestAuthorization:
    """/api/me/settings: every role; /api/org/settings: the Org Admin; /api/platform/settings:
    the Super Admin. A refusal reads and writes nothing and probes no provider."""

    @pytest.mark.parametrize(("action", "role"), _MATRIX)
    def test_settings_api_role_matrix(
        self, db: FakeDb, app: FastAPI, probes: _Probes, action: str, role: str
    ) -> None:
        _route_of(app, action)
        _, token = _login(db, role)
        scope = _SCOPE[action]
        before = _state(db)

        response = _call(_client(app), action, token)

        if role in _ALLOWED_ROLES[scope]:
            assert response.status_code == 200, response.text
            return
        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _state(db) == before
        assert db.audit == []
        assert db.matching(rf"\b{_SCOPE_TABLES[scope]}\b") == []
        probes.vllm.assert_not_awaited()
        probes.infomaniak.assert_not_awaited()
        probes.create.assert_not_called()

    def test_settings_api_editor_cannot_patch_org_settings(
        self, db: FakeDb, app: FastAPI, agent: MagicMock
    ) -> None:
        """The issue's AC: an Editor can't patch org settings: 403, no org_settings row, no
        audit row, nothing set on the running agent."""
        _route_of(app, "org_patch")
        _, token = _login(db, "editor")

        response = _call(_client(app), "org_patch", token, body={"tools": {"gmail": False}})

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert db.org_settings == {}
        assert db.audit == []
        _assert_no_agent_gate(agent)

    def test_settings_api_org_admin_cannot_patch_platform_settings(
        self, db: FakeDb, app: FastAPI, agent: MagicMock, probes: _Probes
    ) -> None:
        """The issue's AC: an Org Admin can't patch platform settings: 403, the platform row
        unchanged, no audit row, no new LLM client."""
        _route_of(app, "platform_patch")
        _, token = _login(db, "org_admin")
        row = copy.deepcopy(_row(db))
        old_client = agent._llm

        response = _call(_client(app), "platform_patch", token, body={"llm": {"provider": "vllm"}})

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _row(db) == row
        assert db.audit == []
        probes.create.assert_not_called()
        assert agent._llm is old_client

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_settings_api_route_asks_can_for_its_capability(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        scope = _SCOPE[action]
        _, token = _login(db, "super_admin" if scope == "platform" else "org_admin")
        spy = _CanSpy(monkeypatch)

        response = _call(_client(app), action, token)

        assert response.status_code == 200, response.text
        assert _CAPABILITIES[scope] in spy.capabilities

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_settings_api_capability_refused_by_can_is_403(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        _route_of(app, action)
        scope = _SCOPE[action]
        _, token = _login(db, "super_admin" if scope == "platform" else "org_admin")
        _CanSpy(monkeypatch, deny=frozenset({_CAPABILITIES[scope]}))
        before = _state(db)

        response = _call(_client(app), action, token)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _state(db) == before

    def test_settings_api_rate_limit_runs_before_the_capability_check(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An Editor's refused calls spend its own bucket: 403, then 429."""
        _route_of(app, "org_get")
        _limited(monkeypatch, _ROUTE_KEYS["org_get"])
        _, token = _login(db, "editor")
        client = _client(app)

        first = _call(client, "org_get", token)
        second = _call(client, "org_get", token)

        assert first.status_code == 403
        assert (second.status_code, second.json()) == (429, _RATE_LIMITED)


# ---------------------------------------------------------------------------
# 3. Validation: 422 without echo, nothing written
# ---------------------------------------------------------------------------


class TestValidation:
    """Pydantic-validated bodies: extra keys, non-bools, empty patches and bad model names
    are 422; the body never repeats the input; nothing is written; no client is built."""

    def _assert_refused(
        self,
        db: FakeDb,
        app: FastAPI,
        probes: _Probes,
        action: str,
        role: str,
        body: Any,
    ) -> None:
        _route_of(app, action)
        _, token = _login(db, role)
        before = _state(db)

        response = _call(_client(app), action, token, body=body)

        assert response.status_code == 422, response.text
        for marker in _echo_markers(body):
            assert marker not in response.text, marker
        errors = response.json()["detail"]
        assert all(isinstance(error, dict) and "input" not in error for error in errors)
        assert _state(db) == before
        probes.create.assert_not_called()

    @pytest.mark.parametrize("body", _BAD_ME_BODIES)
    def test_settings_api_me_patch_bad_body_is_422_without_echo(
        self, db: FakeDb, app: FastAPI, probes: _Probes, body: Any
    ) -> None:
        self._assert_refused(db, app, probes, "me_patch", "editor", body)

    @pytest.mark.parametrize("body", _BAD_ORG_BODIES)
    def test_settings_api_org_patch_bad_body_is_422_without_echo(
        self, db: FakeDb, app: FastAPI, probes: _Probes, body: Any
    ) -> None:
        self._assert_refused(db, app, probes, "org_patch", "org_admin", body)

    @pytest.mark.parametrize("body", _BAD_PLATFORM_BODIES)
    def test_settings_api_platform_patch_bad_body_is_422_without_echo(
        self, db: FakeDb, app: FastAPI, probes: _Probes, body: Any
    ) -> None:
        self._assert_refused(db, app, probes, "platform_patch", "super_admin", body)


# ---------------------------------------------------------------------------
# 4. /api/me/settings
# ---------------------------------------------------------------------------


class TestMySettings:
    """Each user reads and changes their own theme and notifications."""

    def test_settings_api_me_get_defaults_without_a_row(self, db: FakeDb, app: FastAPI) -> None:
        _, token = _login(db, "viewer")

        response = _call(_client(app), "me_get", token)

        assert response.status_code == 200, response.text
        assert response.json() == _ME_DEFAULTS

    def test_settings_api_me_patch_theme_is_stored_and_returned(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        user_id, token = _login(db, "editor")
        client = _client(app)

        patched = _call(client, "me_patch", token, body={"appearance": {"theme": "dark"}})
        read = _call(client, "me_get", token)

        assert patched.status_code == 200, patched.text
        assert patched.json() == {
            "appearance": {"theme": "dark"},
            "notifications": {"enabled": True, "task_done": False},
        }
        assert read.json() == patched.json()
        row = db.user_settings[user_id]
        assert (row["theme"], row["notifications_enabled"]) == ("dark", True)

    def test_settings_api_me_patch_notifications_keeps_the_theme(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        user_id, token = _login(db, "viewer")
        db.add_user_settings(user_id, theme="system")

        response = _call(
            _client(app), "me_patch", token, body={"notifications": {"enabled": False}}
        )

        assert response.status_code == 200, response.text
        assert response.json() == {
            "appearance": {"theme": "system"},
            "notifications": {"enabled": False, "task_done": False},
        }

    def test_settings_api_two_users_keep_different_themes(self, db: FakeDb, app: FastAPI) -> None:
        user_a, token_a = _login(db, "editor")
        user_b, token_b = _login(db, "editor")
        client = _client(app)

        assert _call(client, "me_patch", token_a, body={"appearance": {"theme": "dark"}}).is_success
        assert _call(
            client, "me_patch", token_b, body={"appearance": {"theme": "system"}}
        ).is_success

        assert _call(client, "me_get", token_a).json()["appearance"]["theme"] == "dark"
        assert _call(client, "me_get", token_b).json()["appearance"]["theme"] == "system"
        assert (db.user_settings[user_a]["theme"], db.user_settings[user_b]["theme"]) == (
            "dark",
            "system",
        )

    def test_settings_api_super_admin_has_own_settings(self, db: FakeDb, app: FastAPI) -> None:
        user_id, token = _login(db, "super_admin")

        response = _call(_client(app), "me_patch", token, body={"appearance": {"theme": "dark"}})

        assert response.status_code == 200, response.text
        assert set(db.user_settings) == {user_id}

    def test_settings_api_me_patch_writes_no_audit_row(self, db: FakeDb, app: FastAPI) -> None:
        _, token = _login(db, "org_admin")

        response = _call(_client(app), "me_patch", token)

        assert response.status_code == 200, response.text
        assert db.audit == []


# ---------------------------------------------------------------------------
# 5. /api/org/settings
# ---------------------------------------------------------------------------


def _enabled_tools_of_runs(agent: MagicMock) -> list[dict[str, bool]]:
    """The enabled services each agent run received (``tool_policy.enabled_tools``)."""
    enabled: list[dict[str, bool]] = []
    for call in agent.run.await_args_list:
        assert "tool_policy" in call.kwargs, f"the run got no tool_policy: {sorted(call.kwargs)}"
        enabled.append(dict(call.kwargs["tool_policy"].enabled_tools))
    return enabled


class TestOrgSettings:
    """The Org Admin's own org: its tool services, audited; only that org's runs follow."""

    def test_settings_api_org_get_defaults_without_a_row(self, db: FakeDb, app: FastAPI) -> None:
        _, token = _login(db, "org_admin")

        response = _call(_client(app), "org_get", token)

        assert response.status_code == 200, response.text
        assert response.json() == {"tools": _ALL_ON, "data_residency": False}

    def test_settings_api_org_patch_is_stored_returned_and_audited(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        admin_id, token = _login(db, "org_admin")
        db.add_org_settings(ORG_ID, outlook=False)

        response = _call(_client(app), "org_patch", token, body={"tools": {"gmail": False}})

        expected = {**_ALL_ON, "gmail": False, "outlook": False}
        assert response.status_code == 200, response.text
        assert response.json() == {"tools": expected, "data_residency": False}
        assert db.org_tools(ORG_ID) == expected
        event = _one(db.audit)
        assert event["action"] == "org.settings_change"
        assert (event["actor_kind"], _uuid(event["actor_user_id"])) == ("member", admin_id)
        assert _uuid(event["org_id"]) == ORG_ID
        assert (event["target_type"], event["target_ids"]) == ("organization", [str(ORG_ID)])
        assert event["ip"] == _IP_A
        assert event["metadata"] == {"gmail_old": True, "gmail_new": False}

    def test_settings_api_org_patch_noop_writes_no_audit_row(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "org_admin")
        db.add_org_settings(ORG_ID, gmail=False)

        response = _call(_client(app), "org_patch", token, body={"tools": {"gmail": False}})

        assert response.status_code == 200, response.text
        assert db.audit == []

    def test_settings_api_two_orgs_admins_are_isolated(self, db: FakeDb, app: FastAPI) -> None:
        """Org A's change never shows in org B, and B's admin reads B's own row."""
        _, token_a = _login(db, "org_admin", ORG_ID)
        _, token_b = _login(db, "org_admin", OTHER_ORG_ID)
        client = _client(app)

        patched = _call(client, "org_patch", token_a, body={"tools": {"gmail": False}})
        read_b = _call(client, "org_get", token_b)
        read_a = _call(client, "org_get", token_a)

        assert patched.status_code == 200, patched.text
        assert read_b.json() == {"tools": _ALL_ON, "data_residency": False}
        assert read_a.json() == {"tools": {**_ALL_ON, "gmail": False}, "data_residency": False}
        assert OTHER_ORG_ID not in db.org_settings
        assert _uuid(_one(db.audit)["org_id"]) == ORG_ID

    def test_settings_api_org_patch_sets_nothing_on_the_agent(
        self, db: FakeDb, app: FastAPI, agent: MagicMock
    ) -> None:
        """GH-161: the PATCH no longer recomputes a gate on the running agent."""
        db.add_org_settings(OTHER_ORG_ID, memory=False)
        _, token = _login(db, "org_admin", ORG_ID)

        response = _call(_client(app), "org_patch", token, body={"tools": {"gmail": False}})

        assert response.status_code == 200, response.text
        _assert_no_agent_gate(agent)

    def test_settings_api_org_patch_reaches_only_its_own_orgs_runs(
        self, db: FakeDb, app: FastAPI, chat_agent: MagicMock
    ) -> None:
        """Another org already turned memory off: after org A turns gmail off, org A's next
        run has gmail off (memory on), org B's has memory off (gmail on)."""
        db.add_org_settings(OTHER_ORG_ID, memory=False)
        _, admin_a = _login(db, "org_admin", ORG_ID)
        _, editor_a = _login(db, "editor", ORG_ID)
        _, editor_b = _login(db, "editor", OTHER_ORG_ID)
        client = _client(app)

        response = _call(client, "org_patch", admin_a, body={"tools": {"gmail": False}})
        _post_message(client, editor_a, "hello")
        _post_message(client, editor_b, "hello")

        assert response.status_code == 200, response.text
        assert _enabled_tools_of_runs(chat_agent) == [
            {**_ALL_ON, "gmail": False},
            {**_ALL_ON, "memory": False},
        ]

    def test_settings_api_org_patch_reenabling_reopens_it_for_that_org_only(
        self, db: FakeDb, app: FastAPI, chat_agent: MagicMock
    ) -> None:
        """Both orgs had gmail off: org A turning it back on reopens it for org A's runs
        only; org B's stays off."""
        db.add_org_settings(ORG_ID, gmail=False)
        db.add_org_settings(OTHER_ORG_ID, gmail=False)
        _, admin_a = _login(db, "org_admin", ORG_ID)
        _, editor_a = _login(db, "editor", ORG_ID)
        _, editor_b = _login(db, "editor", OTHER_ORG_ID)
        client = _client(app)

        response = _call(client, "org_patch", admin_a, body={"tools": {"gmail": True}})
        _post_message(client, editor_a, "hello")
        _post_message(client, editor_b, "hello")

        assert response.status_code == 200, response.text
        assert _enabled_tools_of_runs(chat_agent) == [_ALL_ON, {**_ALL_ON, "gmail": False}]

    def test_settings_api_org_patch_audit_failure_is_500_and_writes_nothing(
        self, db: FakeDb, app: FastAPI, agent: MagicMock
    ) -> None:
        _route_of(app, "org_patch")
        _, token = _login(db, "org_admin")
        before = _state(db)
        db.fail_audit = True

        response = _call(
            _client(app, raise_server_exceptions=False),
            "org_patch",
            token,
            body={"tools": {"gmail": False}},
        )

        assert response.status_code == 500
        assert _state(db) == before
        _assert_no_agent_gate(agent)


# ---------------------------------------------------------------------------
# 5b. GH-162: the org's data residency policy on /api/org/settings
# ---------------------------------------------------------------------------

# GH-162: the tools an org's data residency switches off (RESIDENCY_BLOCKED_TOOLS).
_RESIDENCY_TOOLS: Final = (
    "gmail",
    "google_calendar",
    "google_drive",
    "outlook",
    "outlook_calendar",
    "onedrive",
)
_RESIDENCY_KEY_BODIES = [
    pytest.param({"tools": {"gmail": False}, "data_residency": False}, id="beside-tools"),
    pytest.param({"data_residency": False}, id="alone"),
    pytest.param({"tools": {"gmail": False, "data_residency": False}}, id="under-tools"),
    pytest.param({"tools": {"gmail": False}, "data_residency": "ECHOMARK42"}, id="marker-value"),
]


def _residency_reads(db: FakeDb, since: int) -> list[Any]:
    """The statements since ``since`` that read data_residency from organizations."""
    return [
        call
        for call in db.calls[since:]
        if re.search(r"\bdata_residency\b.*\bfrom organizations\b", call.normalized)
    ]


class TestOrgSettingsDataResidency:
    """The org settings answer the actor's own org's residency policy, which the PATCH
    body can't change; switches stay editable under residency (GH-162)."""

    @pytest.mark.parametrize("residency", [True, False], ids=["residency", "no-residency"])
    def test_settings_api_org_get_reports_the_orgs_data_residency(
        self, db: FakeDb, app: FastAPI, residency: bool
    ) -> None:
        db.add_org(ORG_ID, data_residency=residency)
        _, token = _login(db, "org_admin")

        response = _call(_client(app), "org_get", token)

        assert response.status_code == 200, response.text
        assert response.json() == {"tools": _ALL_ON, "data_residency": residency}

    def test_settings_api_org_settings_report_each_admins_own_orgs_residency(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """Org A has residency, org B hasn't: each admin reads their own org's policy, and
        the residency read binds the admin's org only."""
        db.add_org(ORG_ID, data_residency=True)
        _, token_a = _login(db, "org_admin", ORG_ID)
        _, token_b = _login(db, "org_admin", OTHER_ORG_ID)
        client = _client(app)

        since = len(db.calls)
        read_b = _call(client, "org_get", token_b)
        reads_b = _residency_reads(db, since)
        read_a = _call(client, "org_get", token_a)

        assert (read_a.status_code, read_b.status_code) == (200, 200), read_a.text
        assert read_a.json()["data_residency"] is True
        assert read_b.json()["data_residency"] is False
        assert reads_b, "GET /api/org/settings read no data_residency"
        assert all(str(OTHER_ORG_ID) in map(str, call.args) for call in reads_b)
        assert not any(str(ORG_ID) in map(str, call.args) for call in reads_b)

    def test_settings_api_org_get_follows_a_residency_change(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """The policy is read on every request (no cached value)."""
        _, token = _login(db, "org_admin")
        client = _client(app)

        before = _call(client, "org_get", token)
        db.add_org(ORG_ID, data_residency=True)
        after = _call(client, "org_get", token)

        assert before.json()["data_residency"] is False
        assert after.json()["data_residency"] is True

    @pytest.mark.parametrize("tool", _RESIDENCY_TOOLS)
    def test_settings_api_org_patch_of_a_connector_switch_under_residency_is_stored(
        self, db: FakeDb, app: FastAPI, tool: str
    ) -> None:
        """Residency gating is separate: the switch is stored, returned and audited as
        before, and the response says residency is on."""
        db.add_org(ORG_ID, data_residency=True)
        admin_id, token = _login(db, "org_admin")

        response = _call(_client(app), "org_patch", token, body={"tools": {tool: False}})

        expected = {**_ALL_ON, tool: False}
        assert response.status_code == 200, response.text
        assert response.json() == {"tools": expected, "data_residency": True}
        assert db.org_tools(ORG_ID) == expected
        event = _one(db.audit)
        assert event["action"] == "org.settings_change"
        assert (event["actor_kind"], _uuid(event["actor_user_id"])) == ("member", admin_id)
        assert _uuid(event["org_id"]) == ORG_ID
        assert event["ip"] == _IP_A
        assert event["metadata"] == {f"{tool}_old": True, f"{tool}_new": False}
        assert db.orgs[ORG_ID]["data_residency"] is True

    def test_settings_api_org_patch_noop_under_residency_reports_it(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        db.add_org(ORG_ID, data_residency=True)
        db.add_org_settings(ORG_ID, outlook=False)
        _, token = _login(db, "org_admin")

        response = _call(_client(app), "org_patch", token, body={"tools": {"outlook": False}})

        assert response.status_code == 200, response.text
        assert response.json() == {
            "tools": {**_ALL_ON, "outlook": False},
            "data_residency": True,
        }
        assert db.audit == []

    @pytest.mark.parametrize("body", _RESIDENCY_KEY_BODIES)
    def test_settings_api_org_patch_cannot_set_data_residency(
        self, db: FakeDb, app: FastAPI, probes: _Probes, body: Any
    ) -> None:
        """A data_residency key is refused like any unknown key (422, no echo, nothing
        written); the org keeps residency on, as the next GET reports."""
        db.add_org(ORG_ID, data_residency=True)
        _, token = _login(db, "org_admin")
        client = _client(app)
        before = _state(db)

        response = _call(client, "org_patch", token, body=body)
        read = _call(client, "org_get", token)

        assert response.status_code == 422, response.text
        assert "ECHOMARK42" not in response.text
        assert all("input" not in error for error in response.json()["detail"])
        assert _state(db) == before
        assert db.orgs[ORG_ID]["data_residency"] is True
        assert read.status_code == 200, read.text
        assert read.json() == {"tools": _ALL_ON, "data_residency": True}


# ---------------------------------------------------------------------------
# 6. GET /api/platform/settings
# ---------------------------------------------------------------------------


class TestPlatformGet:
    """The stored LLM and limits, the probed model lists and key presence flags only."""

    def test_settings_api_platform_get_returns_the_stored_row(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "super_admin")

        response = _call(_client(app), "platform_get", token)

        assert response.status_code == 200, response.text
        body = response.json()
        # GH-160: five sections (was llm and limits only in #159).
        assert set(body) == _SECTIONS
        assert set(body["llm"]) == _LLM_RESPONSE_KEYS
        assert body["limits"] == _STORED_LIMITS
        assert {section: body[section] for section in _EDITABLE} == _STORED_SECTIONS
        assert {key: body["llm"][key] for key in _LLM_RESPONSE_KEYS} == {
            "provider": "anthropic",
            "anthropic_model": "claude-sonnet-4-6",
            "openai_model": "gpt-4o",
            "infomaniak_model": "Qwen/Qwen3.5-397B-A17B-FP8",
            "infomaniak_available_models": [],
            "vllm_model": "Qwen/Qwen3-4B-Instruct-2507",
            "vllm_available_models": [],
            "anthropic_key_configured": True,
            "openai_key_configured": False,
            "infomaniak_token_configured": False,
        }

    def test_settings_api_platform_get_shows_the_stored_provider_not_the_config(
        self, db: FakeDb, app: FastAPI, probes: _Probes
    ) -> None:
        """The row says infomaniak (the config anthropic); a NULL model reads as ""; the
        Infomaniak probe is asked with the stored provider."""
        _row(db).update(llm_provider="infomaniak", openai_model=None, anthropic_model=None)
        _, token = _login(db, "super_admin")

        response = _call(_client(app), "platform_get", token)

        llm = response.json()["llm"]
        assert (llm["provider"], llm["openai_model"], llm["anthropic_model"]) == (
            "infomaniak",
            "",
            "",
        )
        call = _one(probes.infomaniak.await_args_list)
        assert (call.args[0] if call.args else call.kwargs["provider"]) == "infomaniak"

    def test_settings_api_platform_get_available_models_come_from_the_probes_filtered(
        self, db: FakeDb, app: FastAPI, probes: _Probes
    ) -> None:
        rlo = chr(0x202E)
        probes.infomaniak.return_value = ["mistralai/Small-3.2", "bad id; rm -rf /", "x" * 201]
        probes.vllm.return_value = ["org/served-model", f"evil{rlo}model", "org/other"]
        _, token = _login(db, "super_admin")

        response = _call(_client(app), "platform_get", token)

        llm = response.json()["llm"]
        assert llm["infomaniak_available_models"] == ["mistralai/Small-3.2"]
        assert llm["vllm_available_models"] == ["org/served-model", "org/other"]
        probes.vllm.assert_awaited()

    def test_settings_api_platform_get_key_flags_are_booleans_without_values(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("INFOMANIAK_API_TOKEN", _TOKEN_MARKER)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-zephyrmarker-2222222222222222")
        _, token = _login(db, "super_admin")

        response = _call(_client(app), "platform_get", token)

        llm = response.json()["llm"]
        flags = [
            llm["anthropic_key_configured"],
            llm["openai_key_configured"],
            llm["infomaniak_token_configured"],
        ]
        assert flags == [True, True, True]
        assert all(type(flag) is bool for flag in flags)
        assert "zephyrmarker" not in response.text.lower()

    def test_settings_api_platform_get_flags_false_without_env(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        _, token = _login(db, "super_admin")

        llm = _call(_client(app), "platform_get", token).json()["llm"]

        assert (
            llm["anthropic_key_configured"],
            llm["openai_key_configured"],
            llm["infomaniak_token_configured"],
        ) == (False, False, False)


# ---------------------------------------------------------------------------
# 7. PATCH /api/platform/settings: the LLM switch
# ---------------------------------------------------------------------------


class TestPlatformPatch:
    """A provider change (or a model change of the active vllm/infomaniak provider) builds a
    new client before anything is written, swaps it in and closes the old one."""

    def test_settings_api_provider_switch_rebuilds_the_client_and_is_audited(
        self, db: FakeDb, app: FastAPI, agent: MagicMock, probes: _Probes
    ) -> None:
        admin_id, token = _login(db, "super_admin")
        old_client = agent._llm

        response = _call(
            _client(app), "platform_patch", token, body={"llm": {"provider": "openai"}}
        )

        assert response.status_code == 200, response.text
        assert response.json()["llm"]["provider"] == "openai"
        assert response.json()["limits"] == _STORED_LIMITS
        probes.create.assert_called_once()
        assert agent._llm is probes.new_client
        old_client.close.assert_awaited_once()
        assert _row(db)["llm_provider"] == "openai"
        event = _one(db.audit)
        assert event["action"] == "platform.settings_change"
        assert (event["actor_kind"], _uuid(event["actor_user_id"])) == ("super_admin", admin_id)
        assert event["org_id"] is None
        assert (event["target_type"], event["target_ids"]) == (None, [])
        assert event["ip"] == _IP_A
        assert event["metadata"] == {"provider": True}

    def test_settings_api_new_client_gets_the_merged_llm_config(
        self, db: FakeDb, app: FastAPI, probes: _Probes
    ) -> None:
        """The stored models over the config's llm section; the fields the row doesn't hold
        (timeout, vLLM URL, response tokens) come from the config."""
        from admino.config import LLMConfig

        _, token = _login(db, "super_admin")

        response = _call(
            _client(app),
            "platform_patch",
            token,
            body={"llm": {"provider": "infomaniak", "infomaniak_model": "mistralai/Small-3.2"}},
        )

        assert response.status_code == 200, response.text
        built = _one(probes.create.call_args_list).args[0]
        assert isinstance(built, LLMConfig)
        assert (built.provider, built.infomaniak_model) == ("infomaniak", "mistralai/Small-3.2")
        assert (built.anthropic_model, built.openai_model) == ("claude-sonnet-4-6", "gpt-4o")
        assert (built.timeout_s, built.vllm_base_url, built.max_response_tokens) == (
            77,
            "http://vllm-test:8000/v1",
            1234,
        )
        assert _one(db.audit)["metadata"] == {"provider": True, "infomaniak_model": True}

    @pytest.mark.parametrize(
        ("provider", "field", "model"),
        [
            pytest.param("vllm", "vllm_model", "org/new-served-model", id="vllm"),
            pytest.param("infomaniak", "infomaniak_model", "mistralai/Small-3.2", id="infomaniak"),
        ],
    )
    def test_settings_api_active_local_or_infomaniak_model_change_rebuilds_the_client(
        self,
        db: FakeDb,
        app: FastAPI,
        agent: MagicMock,
        probes: _Probes,
        provider: str,
        field: str,
        model: str,
    ) -> None:
        _row(db)["llm_provider"] = provider
        _, token = _login(db, "super_admin")

        response = _call(_client(app), "platform_patch", token, body={"llm": {field: model}})

        assert response.status_code == 200, response.text
        built = _one(probes.create.call_args_list).args[0]
        assert (built.provider, getattr(built, field)) == (provider, model)
        assert agent._llm is probes.new_client
        assert _row(db)[field] == model

    @pytest.mark.parametrize(
        ("field", "model"),
        [
            pytest.param("infomaniak_model", "mistralai/Small-3.2", id="inactive-infomaniak"),
            pytest.param("vllm_model", "org/new-served-model", id="inactive-vllm"),
            pytest.param("anthropic_model", "claude-opus-4-1", id="active-anthropic"),
        ],
    )
    def test_settings_api_other_model_change_is_stored_without_rebuilding(
        self,
        db: FakeDb,
        app: FastAPI,
        agent: MagicMock,
        probes: _Probes,
        field: str,
        model: str,
    ) -> None:
        """Anthropic is active: a model change re-inits only for vllm/infomaniak when that
        provider is the active one."""
        _, token = _login(db, "super_admin")
        old_client = agent._llm

        response = _call(_client(app), "platform_patch", token, body={"llm": {field: model}})

        assert response.status_code == 200, response.text
        probes.create.assert_not_called()
        assert agent._llm is old_client
        assert _row(db)[field] == model
        assert _one(db.audit)["metadata"] == {field: True}

    def test_settings_api_same_value_patch_is_a_noop(
        self, db: FakeDb, app: FastAPI, agent: MagicMock, probes: _Probes
    ) -> None:
        _, token = _login(db, "super_admin")
        old_client = agent._llm
        row = copy.deepcopy(_row(db))

        response = _call(
            _client(app),
            "platform_patch",
            token,
            body={"llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"}},
        )

        assert response.status_code == 200, response.text
        probes.create.assert_not_called()
        assert agent._llm is old_client
        assert db.audit == []
        assert {k: v for k, v in _row(db).items() if k != "updated_at"} == {
            k: v for k, v in row.items() if k != "updated_at"
        }

    @pytest.mark.parametrize("error", [ValueError, ImportError])
    def test_settings_api_client_build_failure_is_400_and_writes_nothing(
        self,
        db: FakeDb,
        app: FastAPI,
        agent: MagicMock,
        probes: _Probes,
        error: type[Exception],
    ) -> None:
        _, token = _login(db, "super_admin")
        old_client = agent._llm
        probes.create.side_effect = error("provider sdk missing zephyrmarker")
        before = _state(db)

        response = _call(
            _client(app), "platform_patch", token, body={"llm": {"provider": "openai"}}
        )

        assert (response.status_code, response.json()) == (400, _CLIENT_FAILED)
        assert _state(db) == before
        assert db.audit == []
        assert agent._llm is old_client
        old_client.close.assert_not_awaited()

    def test_settings_api_audit_failure_is_500_closes_the_new_client_and_keeps_the_old(
        self, db: FakeDb, app: FastAPI, agent: MagicMock, probes: _Probes
    ) -> None:
        _, token = _login(db, "super_admin")
        old_client = agent._llm
        before = _state(db)
        db.fail_audit = True

        response = _call(
            _client(app, raise_server_exceptions=False),
            "platform_patch",
            token,
            body={"llm": {"provider": "openai"}},
        )

        assert response.status_code == 500
        assert _state(db) == before
        assert agent._llm is old_client
        old_client.close.assert_not_awaited()
        probes.new_client.close.assert_awaited_once()

    def test_settings_api_old_client_close_failure_never_fails_the_switch(
        self,
        db: FakeDb,
        app: FastAPI,
        agent: MagicMock,
        probes: _Probes,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        _, token = _login(db, "super_admin")
        agent._llm.close.side_effect = RuntimeError("teardown zephyrmarker detail")

        response = _call(
            _client(app), "platform_patch", token, body={"llm": {"provider": "openai"}}
        )

        assert response.status_code == 200, response.text
        assert agent._llm is probes.new_client
        assert _row(db)["llm_provider"] == "openai"
        assert "zephyrmarker" not in _log_text(caplog).lower()

    def test_settings_api_platform_patch_never_returns_key_values(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("INFOMANIAK_API_TOKEN", _TOKEN_MARKER)
        _, token = _login(db, "super_admin")

        response = _call(
            _client(app), "platform_patch", token, body={"llm": {"provider": "infomaniak"}}
        )

        assert response.status_code == 200, response.text
        assert response.json()["llm"]["infomaniak_token_configured"] is True
        assert "zephyrmarker" not in response.text.lower()


class TestLiveConfigFollowsTheSwitch:
    """Security audit (Medium): after a live switch, the server's own config follows the
    stored platform LLM, so diagnostics and the provider-gated probes (vLLM model list,
    reachability) report the provider that actually processes messages, not the one the
    process started with. A failed switch leaves it unchanged."""

    def test_settings_api_live_config_follows_a_provider_switch(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "super_admin")

        response = _call(
            _client(app),
            "platform_patch",
            token,
            body={"llm": {"provider": "vllm", "vllm_model": "org/new-served-model"}},
        )

        assert response.status_code == 200, response.text
        assert server._config is not None
        live = server._config.llm
        assert (live.provider, live.vllm_model) == ("vllm", "org/new-served-model")
        assert live.active_model_name == "org/new-served-model"
        # The fields the platform row doesn't hold stay from the config.
        assert (live.timeout_s, live.vllm_base_url, live.max_response_tokens) == (
            77,
            "http://vllm-test:8000/v1",
            1234,
        )

    def test_settings_api_diagnostics_report_the_switched_provider(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("admino.database.check_health", AsyncMock(return_value=True))
        monkeypatch.setattr(server, "_check_llm_reachable", AsyncMock(return_value=True))
        _, token = _login(db, "super_admin")
        client = _client(app)

        switched = _call(client, "platform_patch", token, body={"llm": {"provider": "openai"}})
        diagnostics = client.get("/api/platform/diagnostics", headers=_headers(token))

        assert switched.status_code == 200, switched.text
        assert diagnostics.status_code == 200, diagnostics.text
        assert (diagnostics.json()["provider"], diagnostics.json()["model"]) == (
            "openai",
            "gpt-4o",
        )

    def test_settings_api_failed_client_build_leaves_the_live_config(
        self, db: FakeDb, app: FastAPI, probes: _Probes
    ) -> None:
        _, token = _login(db, "super_admin")
        probes.create.side_effect = ValueError("no client")

        response = _call(
            _client(app), "platform_patch", token, body={"llm": {"provider": "openai"}}
        )

        assert response.status_code == 400
        assert server._config is not None
        assert server._config.llm.provider == "anthropic"

    def test_settings_api_failed_audit_leaves_the_live_config(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "super_admin")
        db.fail_audit = True

        response = _call(
            _client(app, raise_server_exceptions=False),
            "platform_patch",
            token,
            body={"llm": {"provider": "openai"}},
        )

        assert response.status_code == 500
        assert server._config is not None
        assert server._config.llm.provider == "anthropic"


# ---------------------------------------------------------------------------
# 8. Rate limits and CSRF
# ---------------------------------------------------------------------------


class TestRateLimitsAndCsrf:
    """Per-user buckets (one user never throttles another); cross-origin writes refused."""

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_settings_api_rate_limit_is_per_user(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        """With a burst of 1: the second call is 429; another user's call still runs; the
        bucket is (key, "user:<id>")."""
        _route_of(app, action)
        _limited(monkeypatch, _ROUTE_KEYS[action])
        role = {"me": "editor", "org": "org_admin", "platform": "super_admin"}[_SCOPE[action]]
        user_a, token_a = _login(db, role)
        _, token_b = _login(db, role, OTHER_ORG_ID)
        client = _client(app)

        first = _call(client, action, token_a)
        limited = _call(client, action, token_a)
        other = _call(client, action, token_b)

        assert first.status_code == 200, first.text
        assert (limited.status_code, limited.json()) == (429, _RATE_LIMITED)
        assert other.status_code == 200, other.text
        assert (_ROUTE_KEYS[action], f"user:{user_a}") in server._rate_buckets

    @pytest.mark.parametrize("headers", _CROSS_ORIGIN)
    @pytest.mark.parametrize("action", _PATCH_ACTIONS)
    def test_settings_api_cross_origin_patch_is_refused_before_the_database(
        self, db: FakeDb, app: FastAPI, action: str, headers: dict[str, str]
    ) -> None:
        _route_of(app, action)
        _, token = _login(db, "super_admin" if action == "platform_patch" else "org_admin")
        before = _state(db)

        response = _call(_client(app), action, token, **headers)

        assert (response.status_code, response.json()) == (403, _CSRF_REFUSED)
        assert db.calls == []
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 9. The lifespan computes no gate (GH-161)
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _lifespan_patches(db: FakeDb, monkeypatch: pytest.MonkeyPatch) -> Any:
    """The lifespan runs on the fake pool; every background job is a no-op."""
    monkeypatch.setattr("admino.database.init_pool", AsyncMock(return_value=db.pool))
    monkeypatch.setattr("admino.database.close_pool", AsyncMock())
    monkeypatch.setattr("admino.audit_events.run_retention_job", AsyncMock())
    monkeypatch.setattr("admino.sessions.run_session_purge_job", AsyncMock())
    monkeypatch.setattr("admino.mailer.load_smtp_config", MagicMock(return_value=None))
    with patch_org_purge_job(AsyncMock()), patch_login_throttle_purge_job(AsyncMock()):
        yield


class TestLifespanComputesNoGate:
    """GH-161 retires #159's interim gate: startup reads no org_settings row and sets no
    gate, promoted set or matrix on the agent (each run loads its own org's policy)."""

    async def test_settings_api_lifespan_sets_no_gate_on_the_agent(
        self, db: FakeDb, app: FastAPI, agent: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db.add_org_settings(ORG_ID, gmail=False)
        db.add_org_settings(OTHER_ORG_ID, outlook=False)

        with _lifespan_patches(db, monkeypatch):
            async with server._lifespan(app):
                _assert_no_agent_gate(agent)

        assert db.matching(r"\borg_settings\b") == []

    async def test_settings_api_lifespan_reloads_no_promoted_permissions(
        self, db: FakeDb, app: FastAPI, agent: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An org's stored promotion stays in its own rows: nothing reaches the agent."""
        db.add_permissions(ORG_ID, {"gmail": {"send": "confirm"}})
        db.add_permissions(OTHER_ORG_ID)

        with _lifespan_patches(db, monkeypatch):
            async with server._lifespan(app):
                _assert_no_agent_gate(agent)

    def test_settings_api_all_orgs_tools_gate_is_removed(self) -> None:
        assert not hasattr(scoped_settings, "all_orgs_tools_gate")


# ---------------------------------------------------------------------------
# 10. No content in logs or audit rows
# ---------------------------------------------------------------------------


class TestNoContentInLogs:
    """No email, name or model name in a log record; no provider or model value in an
    audit row."""

    def _flow(self, db: FakeDb, app: FastAPI, probes: _Probes) -> None:
        _, member = _login(
            db, "org_admin", email="zephyrmarker.admin@example.ch", name="Zephyrmarker Admin"
        )
        _, platform = _login(db, "super_admin", email="zephyrmarker.root@example.ch")
        client = _client(app, raise_server_exceptions=False)
        assert _call(client, "me_patch", member).status_code == 200
        assert _call(client, "org_patch", member).status_code == 200
        assert _call(client, "org_get", member).status_code == 200
        assert _call(client, "platform_get", platform).status_code == 200
        switched = _call(
            client,
            "platform_patch",
            platform,
            body={"llm": {"provider": "infomaniak", "infomaniak_model": _MODEL_MARKER}},
        )
        assert switched.status_code == 200, switched.text
        stored = _call(
            client, "platform_patch", platform, body={"llm": {"anthropic_model": "Zephyrmarker-a1"}}
        )
        assert stored.status_code == 200, stored.text
        probes.create.side_effect = ValueError("zephyrmarker build failure")
        failed = _call(
            client,
            "platform_patch",
            platform,
            body={"llm": {"provider": "openai", "openai_model": "Zephyrmarker-o1"}},
        )
        assert failed.status_code == 400
        refused = _call(
            client, "platform_patch", member, body={"llm": {"openai_model": "Zephyrmarker-o2"}}
        )
        assert refused.status_code == 403
        bad = _call(
            client, "platform_patch", platform, body={"llm": {"openai_model": "Zephyrmarker\n"}}
        )
        assert bad.status_code == 422

    def test_settings_api_flow_logs_no_content(
        self, db: FakeDb, app: FastAPI, probes: _Probes, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)

        self._flow(db, app, probes)

        assert "zephyrmarker" not in _log_text(caplog).lower()

    def test_settings_api_audit_rows_carry_no_provider_model_or_person(
        self, db: FakeDb, app: FastAPI, probes: _Probes
    ) -> None:
        self._flow(db, app, probes)

        assert {row["action"] for row in db.audit} == {
            "org.settings_change",
            "platform.settings_change",
        }
        stored = json.dumps(db.audit, default=str).lower()
        assert "zephyrmarker" not in stored
        for row in db.audit:
            assert all(type(value) is bool for value in row["metadata"].values()), row


# ---------------------------------------------------------------------------
# 11. GH-160: the platform defaults, validation
# ---------------------------------------------------------------------------


class TestPlatformDefaultsValidation:
    """Every field of limits, files, retention and security is a strict int within the
    issue's bounds. A bad value, an unknown field or section, or a patch of only empty or
    null sections is a 422 whose error points at the field (the sections themselves are
    known keys), never echoing the input; nothing is written, the cache is unchanged and
    no LLM client is built."""

    @pytest.mark.parametrize(("body", "loc"), _BAD_SECTION_BODIES)
    def test_settings_api_platform_patch_bad_section_is_422_at_the_field_without_echo(
        self, db: FakeDb, app: FastAPI, probes: _Probes, body: dict[str, Any], loc: list[str]
    ) -> None:
        _route_of(app, "platform_patch")
        _, token = _login(db, "super_admin")
        before = _state(db)
        cache = scoped_settings._platform_cache

        response = _call(_client(app), "platform_patch", token, body=body)

        assert response.status_code == 422, response.text
        for marker in _echo_markers(body):
            assert marker not in response.text, marker
        errors = response.json()["detail"]
        assert all(isinstance(error, dict) and "input" not in error for error in errors)
        known = [["body", section] for section in body if section in _EDITABLE]
        refused_sections = [
            error
            for error in errors
            if error["type"] == "extra_forbidden" and error["loc"] in known
        ]
        assert refused_sections == [], errors
        assert any(error["loc"][: len(loc)] == loc for error in errors), errors
        assert _state(db) == before
        assert scoped_settings._platform_cache is cache
        probes.create.assert_not_called()

    @pytest.mark.parametrize(("section", "field", "value"), _BOUNDARY_VALUES)
    def test_settings_api_platform_patch_boundary_value_is_accepted(
        self, db: FakeDb, app: FastAPI, section: str, field: str, value: int
    ) -> None:
        _, token = _login(db, "super_admin")

        response = _call(_client(app), "platform_patch", token, body={section: {field: value}})

        assert response.status_code == 200, response.text
        assert response.json()[section][field] == value
        assert _row(db)[field] == value


# ---------------------------------------------------------------------------
# 12. GH-160: GET /api/platform/settings, five sections
# ---------------------------------------------------------------------------

_CUSTOM_SECTIONS: dict[str, dict[str, int]] = {
    "files": {
        "max_file_size_mb": 10,
        "max_files_per_message": 3,
        "max_pages_per_file": 40,
        "render_dpi": 200,
    },
    "retention": {
        "trash_min_days": 5,
        "trash_max_days": 45,
        "audit_months": 36,
        "org_deletion_grace_days": 60,
    },
    "security": {
        "rate_limit_per_minute": 100,
        "lockout_after_failures": 4,
        "lockout_window_minutes": 90,
        "lockout_minutes": 120,
        "session_idle_timeout_minutes": 240,
        "session_max_lifetime_hours": 24,
    },
}


class TestPlatformDefaultsGet:
    """GET reads the whole row: the five sections, and the cache is replaced with it."""

    def test_settings_api_platform_get_returns_every_section_from_the_row(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        for fields in _CUSTOM_SECTIONS.values():
            _row(db).update(fields)
        _, token = _login(db, "super_admin")

        response = _call(_client(app), "platform_get", token)

        assert response.status_code == 200, response.text
        assert set(response.json()) == _SECTIONS
        assert _editable(response.json()) == _after(_CUSTOM_SECTIONS)

    @pytest.mark.parametrize("primed", [True, False], ids=["primed-cache", "empty-cache"])
    def test_settings_api_platform_get_replaces_the_cache_with_the_row(
        self, db: FakeDb, app: FastAPI, primed: bool
    ) -> None:
        """Primed with the conftest's default row or empty: after a GET the cache is this
        row (the Anthropic provider, the stored limits and the custom sections)."""
        for fields in _CUSTOM_SECTIONS.values():
            _row(db).update(fields)
        if not primed:
            scoped_settings._platform_cache = None
        _, token = _login(db, "super_admin")

        response = _call(_client(app), "platform_get", token)

        assert response.status_code == 200, response.text
        assert _cached_sections() == _after(_CUSTOM_SECTIONS)
        assert scoped_settings._platform_cache is not None
        assert scoped_settings._platform_cache.llm.provider == "anthropic"


# ---------------------------------------------------------------------------
# 13. GH-160: PATCH /api/platform/settings, the new sections
# ---------------------------------------------------------------------------


class TestPlatformDefaultsPatch:
    """A section change is stored, returned with all five sections, cached and audited as
    one platform.settings_change row per changed section (``<field>_old`` /
    ``<field>_new`` ints and the client IP); unchanged sections and no-ops record
    nothing. A mixed patch runs the #159 LLM path in the same request."""

    @pytest.mark.parametrize(("section", "fields"), _SECTION_PATCHES)
    def test_settings_api_platform_patch_section_is_stored_and_returned(
        self,
        db: FakeDb,
        app: FastAPI,
        agent: MagicMock,
        probes: _Probes,
        section: str,
        fields: dict[str, int],
    ) -> None:
        _, token = _login(db, "super_admin")
        old_client = agent._llm
        before = _row_without_updated_at(db)

        response = _call(_client(app), "platform_patch", token, body={section: fields})

        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == _SECTIONS
        assert _editable(body) == _after({section: fields})
        assert body["llm"]["provider"] == "anthropic"
        assert _row_without_updated_at(db) == {**before, **fields}
        probes.create.assert_not_called()
        assert agent._llm is old_client

    @pytest.mark.parametrize(("section", "fields"), _SECTION_PATCHES)
    def test_settings_api_platform_patch_section_change_is_audited_with_old_and_new(
        self, db: FakeDb, app: FastAPI, section: str, fields: dict[str, int]
    ) -> None:
        admin_id, token = _login(db, "super_admin")

        response = _call(_client(app), "platform_patch", token, body={section: fields})

        assert response.status_code == 200, response.text
        event = _one(db.audit)
        assert event["action"] == "platform.settings_change"
        assert (event["actor_kind"], _uuid(event["actor_user_id"])) == ("super_admin", admin_id)
        assert event["org_id"] is None
        assert (event["target_type"], event["target_ids"]) == (None, [])
        assert event["ip"] == _IP_A
        assert event["metadata"] == _old_new(_STORED_SECTIONS[section], fields)
        assert all(type(value) is int for value in event["metadata"].values())

    @pytest.mark.parametrize(("section", "fields"), _SECTION_PATCHES)
    def test_settings_api_platform_patch_section_change_updates_the_cache(
        self, db: FakeDb, app: FastAPI, section: str, fields: dict[str, int]
    ) -> None:
        _, token = _login(db, "super_admin")

        response = _call(_client(app), "platform_patch", token, body={section: fields})

        assert response.status_code == 200, response.text
        assert _cached_sections() == _after({section: fields})
        assert _cached_sections() == _editable(response.json())

    def test_settings_api_platform_patch_audits_only_the_changed_fields(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """max_file_size_mb is given with its stored value: only render_dpi is recorded."""
        _, token = _login(db, "super_admin")

        response = _call(
            _client(app),
            "platform_patch",
            token,
            body={"files": {"max_file_size_mb": 50, "render_dpi": 300}},
        )

        assert response.status_code == 200, response.text
        assert _settings_changes(db) == [{"render_dpi_old": 150, "render_dpi_new": 300}]

    def test_settings_api_platform_patch_one_row_per_changed_section_in_order(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """files and security change (given in another order), retention is given with its
        stored value: two rows, files then security."""
        _, token = _login(db, "super_admin")

        response = _call(
            _client(app),
            "platform_patch",
            token,
            body={
                "security": {"lockout_minutes": 30},
                "retention": {"audit_months": 12},
                "files": {"render_dpi": 300},
            },
        )

        assert response.status_code == 200, response.text
        assert _settings_changes(db) == [
            {"render_dpi_old": 150, "render_dpi_new": 300},
            {"lockout_minutes_old": 15, "lockout_minutes_new": 30},
        ]

    def test_settings_api_platform_patch_mixed_with_llm_is_one_request(
        self, db: FakeDb, app: FastAPI, agent: MagicMock, probes: _Probes
    ) -> None:
        """llm + limits + security (+ an unchanged files value): the client is rebuilt and
        swapped as in #159, every section is stored, and the audit rows are llm (names
        only), limits and security, in that order."""
        _, token = _login(db, "super_admin")
        old_client = agent._llm

        response = _call(
            _client(app),
            "platform_patch",
            token,
            body={
                "llm": {"provider": "openai"},
                "limits": {"max_message_length": 10},
                "security": {"lockout_minutes": 30},
                "files": {"render_dpi": 150},
            },
        )

        assert response.status_code == 200, response.text
        changes = {"limits": {"max_message_length": 10}, "security": {"lockout_minutes": 30}}
        assert response.json()["llm"]["provider"] == "openai"
        assert _editable(response.json()) == _after(changes)
        probes.create.assert_called_once()
        assert agent._llm is probes.new_client
        old_client.close.assert_awaited_once()
        assert server._config is not None
        assert server._config.llm.provider == "openai"
        row = _row(db)
        assert (row["llm_provider"], row["max_message_length"], row["lockout_minutes"]) == (
            "openai",
            10,
            30,
        )
        assert _settings_changes(db) == [
            {"provider": True},
            {"max_message_length_old": 5000, "max_message_length_new": 10},
            {"lockout_minutes_old": 15, "lockout_minutes_new": 30},
        ]

    def test_settings_api_platform_patch_mixed_client_failure_writes_nothing(
        self, db: FakeDb, app: FastAPI, agent: MagicMock, probes: _Probes
    ) -> None:
        _, token = _login(db, "super_admin")
        old_client = agent._llm
        probes.create.side_effect = ValueError("no client")
        _cache_the_row(app, token)
        before = _state(db)

        response = _call(
            _client(app),
            "platform_patch",
            token,
            body={"llm": {"provider": "openai"}, "limits": {"max_message_length": 10}},
        )

        assert (response.status_code, response.json()) == (400, _CLIENT_FAILED)
        assert _state(db) == before
        assert _cached_sections() == _STORED_SECTIONS
        assert agent._llm is old_client

    def test_settings_api_platform_patch_noop_writes_and_records_nothing(
        self, db: FakeDb, app: FastAPI, agent: MagicMock, probes: _Probes
    ) -> None:
        """Every given value equals the stored one: 200 with the stored sections, no UPDATE,
        no audit row, no session policy change, no client."""
        _, token = _login(db, "super_admin")
        other_admin, _ = _login(db, "super_admin")
        db.open_session(other_admin, expires_in=timedelta(hours=5))
        sessions = copy.deepcopy(db.sessions_of(other_admin))
        row = copy.deepcopy(_row(db))

        response = _call(
            _client(app),
            "platform_patch",
            token,
            body={
                "limits": dict(_STORED_LIMITS),
                "files": {"render_dpi": 150},
                "retention": {"trash_max_days": 90},
                "security": {"session_idle_timeout_minutes": 60, "session_max_lifetime_hours": 12},
            },
        )

        assert response.status_code == 200, response.text
        assert _editable(response.json()) == _STORED_SECTIONS
        assert _row(db) == row
        assert db.audit == []
        assert db.matching(r"\bupdate platform_settings\b") == []
        assert db.sessions_of(other_admin) == sessions
        probes.create.assert_not_called()

    @pytest.mark.parametrize(
        ("stored", "retention"),
        [
            pytest.param({}, {"trash_min_days": 60, "trash_max_days": 30}, id="both-given"),
            pytest.param({"trash_max_days": 30}, {"trash_min_days": 45}, id="min-over-stored-max"),
            pytest.param({"trash_min_days": 20}, {"trash_max_days": 10}, id="max-under-stored-min"),
            pytest.param({"trash_max_days": 30}, {"trash_min_days": 31}, id="one-over"),
        ],
    )
    def test_settings_api_platform_patch_trash_min_over_max_is_400_and_writes_nothing(
        self,
        db: FakeDb,
        app: FastAPI,
        stored: dict[str, int],
        retention: dict[str, int],
    ) -> None:
        _row(db).update(stored)
        _, token = _login(db, "super_admin")
        _cache_the_row(app, token)
        before = _state(db)

        response = _call(_client(app), "platform_patch", token, body={"retention": retention})

        assert (response.status_code, response.json()) == (400, _TRASH_REFUSED)
        assert _state(db) == before
        assert db.audit == []
        assert db.matching(r"\bupdate platform_settings\b") == []
        assert _cached_sections() == _after({"retention": stored})

    def test_settings_api_platform_patch_trash_refusal_drops_the_whole_patch(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """A valid security change in the same patch is not written either."""
        _, token = _login(db, "super_admin")
        before = _state(db)

        response = _call(
            _client(app),
            "platform_patch",
            token,
            body={
                "retention": {"trash_min_days": 60, "trash_max_days": 30},
                "security": {"lockout_minutes": 30},
            },
        )

        assert (response.status_code, response.json()) == (400, _TRASH_REFUSED)
        assert _state(db) == before
        assert _row(db)["lockout_minutes"] == 15

    def test_settings_api_platform_patch_trash_refusal_with_llm_closes_the_new_client(
        self, db: FakeDb, app: FastAPI, agent: MagicMock, probes: _Probes
    ) -> None:
        """With a provider switch in the same patch: 400, the running client kept (never
        closed), any client built for the switch closed, the live config unchanged."""
        _, token = _login(db, "super_admin")
        old_client = agent._llm
        before = _state(db)

        response = _call(
            _client(app),
            "platform_patch",
            token,
            body={
                "llm": {"provider": "openai"},
                "retention": {"trash_min_days": 60, "trash_max_days": 30},
            },
        )

        assert (response.status_code, response.json()) == (400, _TRASH_REFUSED)
        assert _state(db) == before
        assert agent._llm is old_client
        old_client.close.assert_not_awaited()
        assert probes.new_client.close.await_count == probes.create.call_count
        assert server._config is not None
        assert server._config.llm.provider == "anthropic"

    @pytest.mark.parametrize(
        ("stored", "retention"),
        [
            pytest.param({}, {"trash_min_days": 30, "trash_max_days": 30}, id="both-given"),
            pytest.param({"trash_max_days": 30}, {"trash_min_days": 30}, id="min-to-stored-max"),
        ],
    )
    def test_settings_api_platform_patch_trash_min_equal_to_max_is_accepted(
        self,
        db: FakeDb,
        app: FastAPI,
        stored: dict[str, int],
        retention: dict[str, int],
    ) -> None:
        _row(db).update(stored)
        _, token = _login(db, "super_admin")

        response = _call(_client(app), "platform_patch", token, body={"retention": retention})

        assert response.status_code == 200, response.text
        assert (_row(db)["trash_min_days"], _row(db)["trash_max_days"]) == (30, 30)

    def test_settings_api_platform_patch_audit_failure_is_500_and_changes_nothing(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """limits + a session policy change with a failing audit write: 500, the row, the
        other Super Admin's session and the cache are all unchanged."""
        _, token = _login(db, "super_admin")
        other_admin, _ = _login(db, "super_admin")
        sessions = copy.deepcopy(db.sessions_of(other_admin))
        _cache_the_row(app, token)
        before = _state(db)
        db.fail_audit = True

        response = _call(
            _client(app, raise_server_exceptions=False),
            "platform_patch",
            token,
            body={
                "limits": {"max_message_length": 10},
                "security": {"session_idle_timeout_minutes": 30},
            },
        )

        assert response.status_code == 500
        assert _state(db) == before
        assert db.sessions_of(other_admin) == sessions
        assert _cached_sections() == _STORED_SECTIONS


# ---------------------------------------------------------------------------
# 14. GH-160: a limits change applies without a restart
# ---------------------------------------------------------------------------


@pytest.fixture()
def chat_agent(agent: MagicMock) -> MagicMock:
    """The stub agent answers every run with a final result."""
    agent.run = AsyncMock(return_value=_agent_result())
    return agent


class TestLimitsApplyWithoutRestart:
    """POST /api/message and POST /api/confirm read the stored limits on every request:
    the message length check and the agent_config passed to the agent run."""

    def test_settings_api_message_length_change_applies_to_the_next_message(
        self, db: FakeDb, app: FastAPI, chat_agent: MagicMock
    ) -> None:
        _, admin = _login(db, "super_admin")
        _, editor = _login(db, "editor")
        client = _client(app)

        patched = _call(
            client, "platform_patch", admin, body={"limits": {"max_message_length": 10}}
        )
        too_long = _post_message(client, editor, "x" * 11)
        fits = _post_message(client, editor, "y" * 10)

        assert patched.status_code == 200, patched.text
        assert (too_long.status_code, too_long.json()) == (
            422,
            {"detail": "Message exceeds maximum length of 10 characters"},
        )
        assert fits.status_code == 200, fits.text
        call = _one(chat_agent.run.await_args_list)
        assert call.kwargs["user_message"] == "y" * 10

    def test_settings_api_message_length_is_read_from_the_row_when_not_cached(
        self, db: FakeDb, app: FastAPI, chat_agent: MagicMock
    ) -> None:
        """The cache is empty: the route loads the row (max_message_length 12) and caches it."""
        _row(db)["max_message_length"] = 12
        scoped_settings._platform_cache = None
        _, editor = _login(db, "editor")

        response = _post_message(_client(app), editor, "z" * 13)

        assert (response.status_code, response.json()) == (
            422,
            {"detail": "Message exceeds maximum length of 12 characters"},
        )
        chat_agent.run.assert_not_awaited()
        assert scoped_settings._platform_cache is not None
        assert scoped_settings._platform_cache.limits.max_message_length == 12

    def test_settings_api_message_run_gets_the_cached_limits(
        self, db: FakeDb, app: FastAPI, chat_agent: MagicMock
    ) -> None:
        """Without a change: the conftest's default row (10 tool calls, 20 context
        messages, 300 s)."""
        _, editor = _login(db, "editor")

        response = _post_message(_client(app), editor, "hello")

        assert response.status_code == 200, response.text
        assert _agent_config_of(chat_agent) == (10, 20, 300.0)

    def test_settings_api_limits_change_applies_to_the_next_agent_run(
        self, db: FakeDb, app: FastAPI, chat_agent: MagicMock
    ) -> None:
        """Values past #159's AgentConfig bounds (60 tool calls, 900 s) reach the run."""
        _, admin = _login(db, "super_admin")
        _, editor = _login(db, "editor")
        client = _client(app)

        patched = _call(
            client,
            "platform_patch",
            admin,
            body={
                "limits": {
                    "max_tool_calls_per_message": 60,
                    "max_context_messages": 150,
                    "confirmation_timeout_s": 900,
                }
            },
        )
        response = _post_message(client, editor, "hello")

        assert patched.status_code == 200, patched.text
        assert response.status_code == 200, response.text
        assert _agent_config_of(chat_agent) == (60, 150, 900.0)

    def test_settings_api_limits_change_applies_to_a_confirmed_run(
        self, db: FakeDb, app: FastAPI, chat_agent: MagicMock
    ) -> None:
        """The message awaits a confirmation; a limits change lands in between; the
        resumed run gets the new limits."""
        session_id = "chat-160"
        pending = _pending(session_id)
        chat_agent.run = AsyncMock(side_effect=[_agent_result(pending), _agent_result()])
        _, admin = _login(db, "super_admin")
        _, editor = _login(db, "editor")
        client = _client(app)

        asked = _post_message(client, editor, "book it", session_id)
        patched = _call(
            client,
            "platform_patch",
            admin,
            body={"limits": {"max_tool_calls_per_message": 5, "confirmation_timeout_s": 60}},
        )
        confirmed = client.post(
            f"/api/confirm/{pending.confirmation_id}",
            headers=_headers(editor),
            json={
                "session_id": session_id,
                "confirmation_id": pending.confirmation_id,
                "approved": True,
            },
        )

        assert asked.status_code == 200, asked.text
        assert patched.status_code == 200, patched.text
        assert confirmed.status_code == 200, confirmed.text
        assert chat_agent.run.await_count == 2
        assert chat_agent.run.await_args_list[1].kwargs["pending_confirmation"] is not None
        assert _agent_config_of(chat_agent, 1) == (5, 30, 60.0)


# ---------------------------------------------------------------------------
# 15. GH-160: the Super Admin session policy
# ---------------------------------------------------------------------------


class TestSuperAdminSessionPolicy:
    """security.session_idle_timeout_minutes / session_max_lifetime_hours: new Super Admin
    logins take them, every open Super Admin session follows at once (expires_at =
    created_at + lifetime), members keep theirs, and the audit row counts the sessions."""

    _POLICY: Final = {"session_idle_timeout_minutes": 30, "session_max_lifetime_hours": 8}

    def test_settings_api_session_policy_applies_to_a_new_super_admin_login(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "super_admin")
        _with_password(db, "root.two@example.ch", kind="super_admin")
        _with_password(db, "editor.one@example.ch")
        client = _client(app)

        patched = _call(client, "platform_patch", token, body={"security": self._POLICY})
        admin_token, admin_cookie = _log_in(client, "root.two@example.ch")
        member_token, member_cookie = _log_in(client, "editor.one@example.ch")

        assert patched.status_code == 200, patched.text
        admin_row = db.session(admin_token)
        assert admin_row["idle_timeout_minutes"] == 30
        assert _lifetime(admin_row) == timedelta(hours=8)
        assert admin_cookie.get("max-age") == "28800"
        member_row = db.session(member_token)
        assert (member_row["idle_timeout_minutes"], _lifetime(member_row)) == (
            60,
            timedelta(hours=12),
        )
        assert member_cookie.get("max-age") == "43200"

    def test_settings_api_session_policy_login_reads_the_row_when_not_cached(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """No PATCH: the row holds 45 minutes / 6 hours and the cache is empty."""
        _row(db).update(session_idle_timeout_minutes=45, session_max_lifetime_hours=6)
        scoped_settings._platform_cache = None
        _with_password(db, "root.two@example.ch", kind="super_admin")

        token, cookie = _log_in(_client(app), "root.two@example.ch")

        row = db.session(token)
        assert (row["idle_timeout_minutes"], _lifetime(row)) == (45, timedelta(hours=6))
        assert cookie.get("max-age") == str(6 * 3600)

    def test_settings_api_session_policy_applies_to_open_super_admin_sessions(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """The acting Super Admin's own session and another Super Admin's follow; a
        member's session is untouched; the audit row counts the two sessions."""
        actor, token = _login(db, "super_admin")
        other_admin, _ = _login(db, "super_admin")
        member, _ = _login(db, "editor")
        db.open_session(member, idle_timeout_minutes=45, expires_in=timedelta(hours=5))
        member_sessions = copy.deepcopy(db.sessions_of(member))

        response = _call(_client(app), "platform_patch", token, body={"security": self._POLICY})

        assert response.status_code == 200, response.text
        for admin in (actor, other_admin):
            row = _one(db.sessions_of(admin))
            assert (row["idle_timeout_minutes"], _lifetime(row)) == (30, timedelta(hours=8))
        assert db.sessions_of(member) == member_sessions
        assert _settings_changes(db) == [
            {
                "session_idle_timeout_minutes_old": 60,
                "session_idle_timeout_minutes_new": 30,
                "session_max_lifetime_hours_old": 12,
                "session_max_lifetime_hours_new": 8,
                "sessions_updated": 2,
            }
        ]

    def test_settings_api_idle_only_change_keeps_the_stored_lifetime(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """Only the idle timeout changes: every Super Admin session takes it and
        created_at + the stored 12 hours as its expiry."""
        _, token = _login(db, "super_admin")
        other_admin, _ = _login(db, "super_admin")
        db.open_session(other_admin, expires_in=timedelta(hours=5))

        response = _call(
            _client(app),
            "platform_patch",
            token,
            body={"security": {"session_idle_timeout_minutes": 20}},
        )

        assert response.status_code == 200, response.text
        rows = db.sessions_of(other_admin)
        assert len(rows) == 2
        assert all(
            (row["idle_timeout_minutes"], _lifetime(row)) == (20, timedelta(hours=12))
            for row in rows
        ), rows
        assert _settings_changes(db) == [
            {
                "session_idle_timeout_minutes_old": 60,
                "session_idle_timeout_minutes_new": 20,
                "sessions_updated": 3,
            }
        ]

    def test_settings_api_shorter_lifetime_ends_an_older_super_admin_session(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """Another Super Admin's session is 3 hours old (seen just now): with a 2-hour
        lifetime its next request is 401; the acting session (just opened) goes on."""
        _, token = _login(db, "super_admin")
        other_admin, other_token = _login(db, "super_admin")
        db.session(other_token)["created_at"] = datetime.now(UTC) - timedelta(hours=3)
        client = _client(app)

        patched = _call(
            client, "platform_patch", token, body={"security": {"session_max_lifetime_hours": 2}}
        )
        other = _call(client, "me_get", other_token)
        own = _call(client, "me_get", token)

        assert patched.status_code == 200, patched.text
        assert (other.status_code, other.json()) == (401, _UNAUTHORIZED)
        assert own.status_code == 200, own.text
        assert db.sessions_of(other_admin) == [] or all(
            row["expires_at"] <= datetime.now(UTC) for row in db.sessions_of(other_admin)
        )

    def test_settings_api_other_security_change_leaves_sessions_alone(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """A lockout change applies no session policy: no sessions_updated, no row
        changed."""
        _, token = _login(db, "super_admin")
        other_admin, _ = _login(db, "super_admin")
        db.open_session(other_admin, expires_in=timedelta(hours=5))
        sessions = copy.deepcopy(db.sessions_of(other_admin))

        response = _call(
            _client(app), "platform_patch", token, body={"security": {"lockout_minutes": 30}}
        )

        assert response.status_code == 200, response.text
        assert db.sessions_of(other_admin) == sessions
        assert _settings_changes(db) == [{"lockout_minutes_old": 15, "lockout_minutes_new": 30}]


# ---------------------------------------------------------------------------
# 16. GH-160: the org deletion grace period
# ---------------------------------------------------------------------------


class TestGracePeriodFollowsTheSetting:
    """The next scheduled org deletion uses the changed grace period."""

    def test_settings_api_grace_period_change_applies_to_the_next_deletion(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "super_admin")
        client = _client(app)

        patched = _call(
            client, "platform_patch", token, body={"retention": {"org_deletion_grace_days": 45}}
        )
        scheduled = client.post(
            f"/api/platform/orgs/{OTHER_ORG_ID}/deletion", headers=_headers(token)
        )

        assert patched.status_code == 200, patched.text
        assert scheduled.status_code == 200, scheduled.text
        org = db.orgs[OTHER_ORG_ID]
        assert org["purge_after"] - org["deletion_requested_at"] == timedelta(days=45)
        assert _one(db.audit_rows("org.deletion_schedule"))["metadata"]["grace_days"] == 45


# ---------------------------------------------------------------------------
# 17. GH-160: access, rate limit and content-free records
# ---------------------------------------------------------------------------


class TestPlatformDefaultsAccess:
    """Member roles never read or change a platform default; the section patches spend the
    one PATCH bucket."""

    @pytest.mark.parametrize("body", _MEMBER_SECTION_BODIES)
    @pytest.mark.parametrize("role", ["org_admin", "editor", "viewer"])
    def test_settings_api_member_patch_of_a_section_is_403_and_touches_nothing(
        self, db: FakeDb, app: FastAPI, role: str, body: dict[str, Any]
    ) -> None:
        _, token = _login(db, role)
        before = _state(db)
        cache = scoped_settings._platform_cache

        response = _call(_client(app), "platform_patch", token, body=body)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _state(db) == before
        assert db.matching(r"\bplatform_settings\b") == []
        assert scoped_settings._platform_cache is cache

    def test_settings_api_section_patches_share_the_patch_bucket(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _limited(monkeypatch, _ROUTE_KEYS["platform_patch"])
        user_id, token = _login(db, "super_admin")
        client = _client(app)

        first = _call(client, "platform_patch", token, body={"files": {"render_dpi": 300}})
        second = _call(client, "platform_patch", token, body={"security": {"lockout_minutes": 30}})

        assert first.status_code == 200, first.text
        assert (second.status_code, second.json()) == (429, _RATE_LIMITED)
        assert (_row(db)["render_dpi"], _row(db)["lockout_minutes"]) == (300, 15)
        assert (_ROUTE_KEYS["platform_patch"], f"user:{user_id}") in server._rate_buckets


class TestPlatformDefaultsContentFree:
    """No email, name or model name in a log record; the section rows hold field names and
    ints only, never a provider or model value."""

    def _flow(self, db: FakeDb, app: FastAPI) -> None:
        _, root = _login(
            db, "super_admin", email="zephyrmarker.root@example.ch", name="Zephyrmarker Root"
        )
        _with_password(db, "zephyrmarker.two@example.ch", kind="super_admin")
        client = _client(app, raise_server_exceptions=False)
        mixed = _call(
            client,
            "platform_patch",
            root,
            body={
                "llm": {"provider": "infomaniak", "infomaniak_model": _MODEL_MARKER},
                "limits": {"max_message_length": 10},
                "files": {"render_dpi": 300},
            },
        )
        assert mixed.status_code == 200, mixed.text
        retention = _call(
            client, "platform_patch", root, body={"retention": {"org_deletion_grace_days": 45}}
        )
        assert retention.status_code == 200, retention.text
        security = _call(
            client,
            "platform_patch",
            root,
            body={"security": {"session_idle_timeout_minutes": 30, "lockout_minutes": 30}},
        )
        assert security.status_code == 200, security.text
        refused = _call(
            client,
            "platform_patch",
            root,
            body={
                "llm": {"anthropic_model": "Zephyrmarker-a2"},
                "retention": {"trash_min_days": 60, "trash_max_days": 30},
            },
        )
        assert refused.status_code == 400, refused.text
        bad = _call(
            client, "platform_patch", root, body={"files": {"render_dpi": "Zephyrmarker-dpi"}}
        )
        assert bad.status_code == 422, bad.text
        _log_in(client, "zephyrmarker.two@example.ch")
        assert _call(client, "platform_get", root).status_code == 200

    def test_settings_api_section_flow_logs_no_content(
        self, db: FakeDb, app: FastAPI, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)

        self._flow(db, app)

        assert "zephyrmarker" not in _log_text(caplog).lower()

    def test_settings_api_section_audit_rows_hold_field_names_and_ints_only(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        self._flow(db, app)

        changes = _settings_changes(db)
        assert changes[0] == {"provider": True, "infomaniak_model": True}
        assert len(changes) == 5
        for metadata in changes[1:]:
            assert all(_METADATA_KEY.fullmatch(key) for key in metadata), metadata
            assert all(type(value) is int for value in metadata.values()), metadata
        assert "zephyrmarker" not in json.dumps(db.audit, default=str).lower()


# ---------------------------------------------------------------------------
# 18. GH-35: task-done pings on /api/me/settings
# ---------------------------------------------------------------------------


def _me(theme: str = "light", *, enabled: bool = True, task_done: bool = False) -> dict[str, Any]:
    """A /api/me/settings response body."""
    return {
        "appearance": {"theme": theme},
        "notifications": {"enabled": enabled, "task_done": task_done},
    }


def _stored(db: FakeDb, user_id: uuid.UUID) -> tuple[str, bool, bool]:
    """(theme, notifications_enabled, notifications_task_done) of a user's stored row."""
    row = db.user_settings[user_id]
    return (row["theme"], row["notifications_enabled"], row["notifications_task_done"])


class TestTaskDonePings:
    """GH-35: ``notifications.task_done`` (default off) is read, patched on its own and kept
    by every other patch; it is independent of ``notifications.enabled``."""

    def test_settings_api_me_get_returns_the_stored_task_done(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        user_id, token = _login(db, "viewer")
        db.add_user_settings(user_id, theme="dark", notifications_task_done=True)

        response = _call(_client(app), "me_get", token)

        assert response.status_code == 200, response.text
        assert response.json() == _me("dark", task_done=True)

    @pytest.mark.parametrize("role", _ROLES)
    def test_settings_api_me_patch_task_done_on_is_stored_and_returned(
        self, db: FakeDb, app: FastAPI, role: str
    ) -> None:
        """Without a row: task_done on, theme and tool-approval pings keep their defaults."""
        user_id, token = _login(db, role)

        response = _call(
            _client(app), "me_patch", token, body={"notifications": {"task_done": True}}
        )

        assert response.status_code == 200, response.text
        assert response.json() == _me(task_done=True)
        assert _stored(db, user_id) == ("light", True, True)

    def test_settings_api_me_patch_task_done_keeps_theme_and_enabled(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        user_id, token = _login(db, "editor")
        db.add_user_settings(user_id, theme="dark", notifications_enabled=False)

        response = _call(
            _client(app), "me_patch", token, body={"notifications": {"task_done": True}}
        )

        assert response.status_code == 200, response.text
        assert response.json() == _me("dark", enabled=False, task_done=True)
        assert _stored(db, user_id) == ("dark", False, True)

    def test_settings_api_me_patch_task_done_off_is_stored(self, db: FakeDb, app: FastAPI) -> None:
        user_id, token = _login(db, "editor")
        db.add_user_settings(user_id, theme="system", notifications_task_done=True)

        response = _call(
            _client(app), "me_patch", token, body={"notifications": {"task_done": False}}
        )

        assert response.status_code == 200, response.text
        assert response.json() == _me("system", task_done=False)
        assert _stored(db, user_id) == ("system", True, False)

    def test_settings_api_me_task_done_persists_across_a_reload(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """A later GET from a fresh client (a page reload) still reads task_done on."""
        _, token = _login(db, "editor")
        patched = _call(
            _client(app), "me_patch", token, body={"notifications": {"task_done": True}}
        )
        assert patched.status_code == 200, patched.text

        reloaded = _call(_client(app), "me_get", token)

        assert reloaded.status_code == 200, reloaded.text
        assert reloaded.json() == _me(task_done=True)

    def test_settings_api_me_patch_theme_keeps_task_done(self, db: FakeDb, app: FastAPI) -> None:
        user_id, token = _login(db, "viewer")
        db.add_user_settings(user_id, notifications_task_done=True)

        response = _call(_client(app), "me_patch", token, body={"appearance": {"theme": "dark"}})

        assert response.status_code == 200, response.text
        assert response.json() == _me("dark", task_done=True)
        assert _stored(db, user_id) == ("dark", True, True)

    def test_settings_api_me_patch_enabled_keeps_task_done(self, db: FakeDb, app: FastAPI) -> None:
        """Tool-approval pings off is not a master switch: task-done pings stay on."""
        user_id, token = _login(db, "viewer")
        db.add_user_settings(user_id, notifications_task_done=True)

        response = _call(
            _client(app), "me_patch", token, body={"notifications": {"enabled": False}}
        )

        assert response.status_code == 200, response.text
        assert response.json() == _me(enabled=False, task_done=True)
        assert _stored(db, user_id) == ("light", False, True)

    def test_settings_api_me_patch_every_field_at_once(self, db: FakeDb, app: FastAPI) -> None:
        user_id, token = _login(db, "org_admin")

        response = _call(
            _client(app),
            "me_patch",
            token,
            body={
                "appearance": {"theme": "dark"},
                "notifications": {"enabled": False, "task_done": True},
            },
        )

        assert response.status_code == 200, response.text
        assert response.json() == _me("dark", enabled=False, task_done=True)
        assert _stored(db, user_id) == ("dark", False, True)

    def test_settings_api_me_patch_task_done_with_a_null_enabled_is_valid(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        user_id, token = _login(db, "editor")

        response = _call(
            _client(app),
            "me_patch",
            token,
            body={"notifications": {"enabled": None, "task_done": True}},
        )

        assert response.status_code == 200, response.text
        assert response.json() == _me(task_done=True)
        assert _stored(db, user_id) == ("light", True, True)

    def test_settings_api_me_task_done_is_per_user(self, db: FakeDb, app: FastAPI) -> None:
        """One user's task-done pings never switch another user's on."""
        user_a, token_a = _login(db, "editor")
        user_b, token_b = _login(db, "editor")
        client = _client(app)

        patched = _call(client, "me_patch", token_a, body={"notifications": {"task_done": True}})
        other = _call(client, "me_get", token_b)

        assert patched.status_code == 200, patched.text
        assert other.json() == _ME_DEFAULTS
        assert db.user_settings[user_a]["notifications_task_done"] is True
        assert user_b not in db.user_settings

    def test_settings_api_me_patch_task_done_writes_no_audit_row(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "org_admin")

        response = _call(
            _client(app), "me_patch", token, body={"notifications": {"task_done": True}}
        )

        assert response.status_code == 200, response.text
        assert db.audit == []

    @pytest.mark.parametrize(
        "value", [pytest.param(value, id=name) for name, value in _BAD_TASK_DONE_VALUES]
    )
    def test_settings_api_me_patch_bad_task_done_is_refused_at_the_field(
        self, db: FakeDb, app: FastAPI, value: Any
    ) -> None:
        """A known field with a non-JSON-bool value: the 422 points at task_done (not an
        unknown key), never echoes the input, and nothing is written."""
        _, token = _login(db, "editor")
        before = _state(db)

        response = _call(
            _client(app), "me_patch", token, body={"notifications": {"task_done": value}}
        )

        assert response.status_code == 422, response.text
        errors = response.json()["detail"]
        assert errors
        assert all(error["loc"] == ["body", "notifications", "task_done"] for error in errors)
        assert all(error["type"] != "extra_forbidden" for error in errors), errors
        assert all("input" not in error for error in errors)
        assert "ECHOMARK42" not in response.text
        assert _state(db) == before

    @pytest.mark.parametrize("body", _NULL_TASK_DONE_BODIES)
    def test_settings_api_me_patch_null_task_done_gives_nothing_to_change(
        self, db: FakeDb, app: FastAPI, body: dict[str, Any]
    ) -> None:
        """A patch whose only task_done is null is the "nothing given" 422 on the body."""
        _, token = _login(db, "editor")
        before = _state(db)

        response = _call(_client(app), "me_patch", token, body=body)

        assert response.status_code == 422, response.text
        errors = response.json()["detail"]
        assert all(error["type"] != "extra_forbidden" for error in errors), errors
        assert [error["loc"] for error in errors] == [["body"]]
        assert "Give at least one setting to change." in errors[0]["msg"]
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 19. GH-35: POST /api/me/settings/reset
# ---------------------------------------------------------------------------


def _reset(client: TestClient, token: str | None, **headers: str) -> httpx.Response:
    """POST /api/me/settings/reset (no body)."""
    return client.post(_RESET, headers=_headers(token, **headers))


def _customized(db: FakeDb, user_id: uuid.UUID) -> None:
    """A stored row that differs from the defaults in every column."""
    db.add_user_settings(
        user_id, theme="dark", notifications_enabled=False, notifications_task_done=True
    )


def _assert_reset_row(db: FakeDb, user_id: uuid.UUID) -> None:
    """The caller's row is gone, or holds exactly the column defaults."""
    row = db.user_settings.get(user_id)
    if row is not None:
        assert _stored(db, user_id) == ("light", True, False), row


def _user_settings_calls(db: FakeDb, since: int) -> list[str]:
    return [call.normalized for call in db.calls[since:] if "user_settings" in call.normalized]


class TestResetMySettings:
    """GH-35: the caller reverts their own user settings to the defaults; nothing else
    changes."""

    def test_settings_api_reset_route_is_registered(self, app: FastAPI) -> None:
        _route(app, "POST", _RESET)

    def test_settings_api_reset_route_depends_on_require_session(self, app: FastAPI) -> None:
        assert _depends_on(_route(app, "POST", _RESET).dependant, server.require_session)

    def test_settings_api_reset_without_a_session_is_401(self, db: FakeDb, app: FastAPI) -> None:
        """No cookie → 401 and no database call."""
        _route(app, "POST", _RESET)

        response = _reset(_client(app), None)

        assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)
        assert db.calls == []

    def test_settings_api_reset_with_an_unknown_cookie_is_401(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _route(app, "POST", _RESET)
        user_id, _ = _login(db, "editor")
        _customized(db, user_id)
        before = _state(db)

        response = _reset(_client(app), "not-a-session-token")

        assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)
        assert _state(db) == before

    @pytest.mark.parametrize("role", _ROLES)
    def test_settings_api_reset_returns_the_defaults_for_every_role(
        self, db: FakeDb, app: FastAPI, role: str
    ) -> None:
        user_id, token = _login(db, role)
        _customized(db, user_id)

        response = _reset(_client(app), token)

        assert response.status_code == 200, response.text
        assert response.json() == _ME_DEFAULTS
        _assert_reset_row(db, user_id)

    @pytest.mark.parametrize("role", _ROLES)
    def test_settings_api_reset_then_get_reads_the_defaults(
        self, db: FakeDb, app: FastAPI, role: str
    ) -> None:
        user_id, token = _login(db, role)
        _customized(db, user_id)
        assert _call(_client(app), "me_get", token).json() == _me(
            "dark", enabled=False, task_done=True
        )

        reset = _reset(_client(app), token)
        reloaded = _call(_client(app), "me_get", token)

        assert reset.status_code == 200, reset.text
        assert (reloaded.status_code, reloaded.json()) == (200, _ME_DEFAULTS)

    @pytest.mark.parametrize("role", _ROLES)
    def test_settings_api_reset_touches_nothing_but_the_callers_row(
        self, db: FakeDb, app: FastAPI, role: str
    ) -> None:
        """Other users' rows (same org, another org, a Super Admin), both orgs'
        org_settings, the platform row, the caller's users row (languages, name) and the
        audit log are exactly as before."""
        user_id, token = _login(db, role, ui_language="fr", name="Reset Caller")
        db.users[user_id]["response_language"] = "en"
        _customized(db, user_id)
        peer = db.add_account(role="editor")
        db.add_user_settings(peer, theme="system", notifications_task_done=True)
        stranger = db.add_account(role="org_admin", org_id=OTHER_ORG_ID)
        db.add_user_settings(stranger, theme="dark", notifications_enabled=False)
        root = db.add_account(kind="super_admin", role=None)
        db.add_user_settings(root, notifications_task_done=True)
        db.add_org_settings(ORG_ID, gmail=False)
        db.add_org_settings(OTHER_ORG_ID, outlook=False)
        expected = _state(db)
        del expected["user_settings"][user_id]

        response = _reset(_client(app), token)

        assert response.status_code == 200, response.text
        _assert_reset_row(db, user_id)
        after = _state(db)
        after["user_settings"].pop(user_id, None)
        assert after == expected

    def test_settings_api_reset_writes_no_other_table(self, db: FakeDb, app: FastAPI) -> None:
        """Every statement the reset adds that writes names user_settings (or the session's
        own refresh), and no user_settings statement interpolates an id."""
        user_id, token = _login(db, "editor")
        _customized(db, user_id)
        other = db.add_account(role="editor")
        db.add_user_settings(other, theme="dark")
        since = len(db.calls)

        response = _reset(_client(app), token)

        assert response.status_code == 200, response.text
        writes = [
            call.normalized
            for call in db.calls[since:]
            if re.match(r"\s*(?:with\b.*\b)?(?:insert|update|delete)\b", call.normalized)
        ]
        assert all(re.search(r"\b(?:user_settings|sessions)\b", sql) for sql in writes), writes
        assert not [
            sql
            for sql in writes
            if re.search(r"\b(?:users|org_settings|platform_settings|audit_events)\b", sql)
        ]
        statements = _user_settings_calls(db, since)
        assert statements, "the reset never reached user_settings"
        for sql in statements:
            assert str(user_id) not in sql
            assert str(other) not in sql

    def test_settings_api_reset_writes_no_audit_row(self, db: FakeDb, app: FastAPI) -> None:
        user_id, token = _login(db, "org_admin")
        _customized(db, user_id)

        response = _reset(_client(app), token)

        assert response.status_code == 200, response.text
        assert db.audit == []

    def test_settings_api_reset_without_a_row_is_idempotent(self, db: FakeDb, app: FastAPI) -> None:
        user_id, token = _login(db, "viewer")
        client = _client(app)

        first = _reset(client, token)
        second = _reset(client, token)

        assert (first.status_code, first.json()) == (200, _ME_DEFAULTS)
        assert (second.status_code, second.json()) == (200, _ME_DEFAULTS)
        _assert_reset_row(db, user_id)
        assert db.audit == []

    def test_settings_api_reset_asks_can_for_account_manage(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, token = _login(db, "editor")
        spy = _CanSpy(monkeypatch)

        response = _reset(_client(app), token)

        assert response.status_code == 200, response.text
        assert Capability.ACCOUNT_MANAGE in spy.capabilities

    def test_settings_api_reset_refused_by_can_is_403_and_writes_nothing(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _route(app, "POST", _RESET)
        user_id, token = _login(db, "editor")
        _customized(db, user_id)
        _CanSpy(monkeypatch, deny=frozenset({Capability.ACCOUNT_MANAGE}))
        before = _state(db)
        since = len(db.calls)

        response = _reset(_client(app), token)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _state(db) == before
        assert _user_settings_calls(db, since) == []

    @pytest.mark.parametrize("headers", _CROSS_ORIGIN)
    def test_settings_api_reset_cross_origin_is_refused_before_the_database(
        self, db: FakeDb, app: FastAPI, headers: dict[str, str]
    ) -> None:
        _route(app, "POST", _RESET)
        user_id, token = _login(db, "editor")
        _customized(db, user_id)
        before = _state(db)

        response = _reset(_client(app), token, **headers)

        assert (response.status_code, response.json()) == (403, _CSRF_REFUSED)
        assert db.calls == []
        assert _state(db) == before

    def test_settings_api_reset_rate_limit_is_per_user_after_the_burst(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The burst of 3 runs, the 4th call is 429 before any user_settings statement (the
        row stays), another user's reset still runs; the bucket is (key, "user:<id>")."""
        _route(app, "POST", _RESET)
        _, burst = _EXPECTED_LIMITS[_RESET_KEY]
        monkeypatch.setitem(server._RATE_LIMITS, _RESET_KEY, (0.001, burst))
        user_a, token_a = _login(db, "editor")
        user_b, token_b = _login(db, "editor", OTHER_ORG_ID)
        _customized(db, user_b)
        client = _client(app)

        allowed = [_reset(client, token_a).status_code for _ in range(burst)]
        _customized(db, user_a)
        since = len(db.calls)
        limited = _reset(client, token_a)
        statements = _user_settings_calls(db, since)
        other = _reset(client, token_b)

        assert allowed == [200] * burst
        assert (limited.status_code, limited.json()) == (429, _RATE_LIMITED)
        assert statements == []
        assert _stored(db, user_a) == ("dark", False, True)
        assert other.status_code == 200, other.text
        _assert_reset_row(db, user_b)
        assert (_RESET_KEY, f"user:{user_a}") in server._rate_buckets

    def test_settings_api_reset_rate_limit_runs_before_the_capability_check(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A refused caller's calls spend its own bucket: 403, then 429."""
        _route(app, "POST", _RESET)
        _limited(monkeypatch, _RESET_KEY)
        _, token = _login(db, "editor")
        _CanSpy(monkeypatch, deny=frozenset({Capability.ACCOUNT_MANAGE}))
        client = _client(app)

        first = _reset(client, token)
        second = _reset(client, token)

        assert (first.status_code, first.json()) == (403, _FORBIDDEN)
        assert (second.status_code, second.json()) == (429, _RATE_LIMITED)

    def test_settings_api_reset_logs_no_content(
        self, db: FakeDb, app: FastAPI, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No email or name of the caller in any app log record."""
        caplog.set_level(logging.DEBUG)
        user_id, token = _login(
            db, "editor", email="zephyrmarker.reset@example.ch", name="Zephyrmarker Reset"
        )
        _customized(db, user_id)
        client = _client(app, raise_server_exceptions=False)

        reset = _reset(client, token)
        again = _reset(client, token)

        assert reset.status_code == 200, reset.text
        assert again.status_code == 200, again.text
        assert "zephyrmarker" not in _log_text(caplog).lower()
