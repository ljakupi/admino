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
  / ``tools`` / ``limits`` on /api/me/settings, ``limits`` on
  /api/platform/settings, the removed ``files`` tool), non-JSON-bool values,
  empty patches, a bad theme and a model name with a trailing newline, shell
  characters, 201 characters or a non-string value.
- /api/me/settings: each user's own row (two users keep different themes).
- /api/org/settings: the principal's own org only (two orgs' admins never see
  each other's row); each change is an ``org.settings_change`` audit row with
  the client IP; a no-op writes none; after a successful PATCH the running
  agent's ``_tools_enabled`` is the AND gate over every org
  (``scoped_settings.all_orgs_tools_gate``). An audit failure is a 500 with
  nothing written and the gate unchanged.
- /api/platform/settings: GET returns ``llm`` (the stored provider and
  models, ``""`` for NULL; the available models from the two probe helpers,
  filtered by ``SettingsLLM``; key flags that are booleans of env presence,
  never values) and ``limits`` (the stored five). PATCH takes ``llm`` only;
  a provider change, or a model change of the active vllm/infomaniak
  provider, builds a new client with ``create_llm_client`` BEFORE writing
  (from the merged ``LLMConfig``, the config's other llm fields kept), swaps
  ``_agent._llm`` and closes the old client best-effort. A no-op never
  re-inits. A client that can't be built is a 400 ``{"detail": "Failed to
  create LLM client for the selected provider"}`` with nothing written and no
  audit row; an audit failure is a 500, the new client is closed and the old
  one kept. Each change is a ``platform.settings_change`` audit row naming
  the changed fields only.
- Cross-origin PATCH → 403 before any database call.
- The server lifespan recomputes the gate with ``all_orgs_tools_gate``; a
  failure keeps the construction-time gate (logged by class name).
- No email, name or model name in any log record; no provider or model value
  in any audit row.

Contract notes for the implementation: ``admino.llm.create_llm_client`` is
looked up at call time (as today); the lifespan and the handlers reach
``admino.scoped_settings`` functions at call time (module attribute or a
lazy import).

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
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from admino import server
from admino.access import Capability
from admino.config import AppConfig
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
_BAD_PLATFORM_BODIES = [
    pytest.param({"limits": {"max_message_length": 5}}, id="limits-only"),
    pytest.param(
        {"llm": {"provider": "openai"}, "limits": {"max_message_length": 5}}, id="llm-and-limits"
    ),
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
    """The fake database the server's get_pool() returns: two active orgs and the platform
    row (Anthropic active, every model set, limits 7/4/120/5000/30)."""
    fake = FakeDb()
    fake.add_org(ORG_ID)
    fake.add_org(OTHER_ORG_ID)
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
    """Functional tests aren't about rate limits: the six keys get a large bucket (the
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
    """A stub agent: its live LLM client (closable) and its construction-time gate."""
    stub = MagicMock(name="agent")
    old_client = MagicMock(name="old-llm-client")
    old_client.close = AsyncMock()
    stub._llm = old_client
    stub._tools_enabled = dict(_ALL_ON)
    return stub


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
        audit row, the running agent's gate unchanged."""
        _route_of(app, "org_patch")
        _, token = _login(db, "editor")

        response = _call(_client(app), "org_patch", token, body={"tools": {"gmail": False}})

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert db.org_settings == {}
        assert db.audit == []
        assert agent._tools_enabled == _ALL_ON

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
        assert response.json() == {
            "appearance": {"theme": "light"},
            "notifications": {"enabled": True},
        }

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
            "notifications": {"enabled": True},
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
            "notifications": {"enabled": False},
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


def _expected_gate(db: FakeDb) -> dict[str, bool]:
    """The AND over every stored org_settings row (all on without rows)."""
    gate = dict(_ALL_ON)
    for org_id in db.org_settings:
        tools = db.org_tools(org_id)
        assert tools is not None
        for tool, enabled in tools.items():
            gate[tool] = gate[tool] and enabled
    return gate


class TestOrgSettings:
    """The Org Admin's own org: its tool services, audited, and the agent's gate follows."""

    def test_settings_api_org_get_defaults_without_a_row(self, db: FakeDb, app: FastAPI) -> None:
        _, token = _login(db, "org_admin")

        response = _call(_client(app), "org_get", token)

        assert response.status_code == 200, response.text
        assert response.json() == {"tools": _ALL_ON}

    def test_settings_api_org_patch_is_stored_returned_and_audited(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        admin_id, token = _login(db, "org_admin")
        db.add_org_settings(ORG_ID, outlook=False)

        response = _call(_client(app), "org_patch", token, body={"tools": {"gmail": False}})

        expected = {**_ALL_ON, "gmail": False, "outlook": False}
        assert response.status_code == 200, response.text
        assert response.json() == {"tools": expected}
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
        assert read_b.json() == {"tools": _ALL_ON}
        assert read_a.json() == {"tools": {**_ALL_ON, "gmail": False}}
        assert OTHER_ORG_ID not in db.org_settings
        assert _uuid(_one(db.audit)["org_id"]) == ORG_ID

    def test_settings_api_org_patch_sets_the_agent_gate_to_the_and_over_orgs(
        self, db: FakeDb, app: FastAPI, agent: MagicMock
    ) -> None:
        """Another org already turned memory off: after org A turns gmail off, the running
        agent's gate has both off."""
        db.add_org_settings(OTHER_ORG_ID, memory=False)
        _, token = _login(db, "org_admin", ORG_ID)

        response = _call(_client(app), "org_patch", token, body={"tools": {"gmail": False}})

        assert response.status_code == 200, response.text
        assert dict(agent._tools_enabled) == {**_ALL_ON, "gmail": False, "memory": False}
        assert dict(agent._tools_enabled) == _expected_gate(db)

    def test_settings_api_org_patch_reenabling_reopens_the_gate(
        self, db: FakeDb, app: FastAPI, agent: MagicMock
    ) -> None:
        """Org A was the only org with gmail off: turning it back on reopens it for all."""
        db.add_org_settings(ORG_ID, gmail=False)
        db.add_org_settings(OTHER_ORG_ID)
        agent._tools_enabled = {**_ALL_ON, "gmail": False}
        _, token = _login(db, "org_admin", ORG_ID)

        response = _call(_client(app), "org_patch", token, body={"tools": {"gmail": True}})

        assert response.status_code == 200, response.text
        assert dict(agent._tools_enabled) == _ALL_ON

    def test_settings_api_org_patch_one_org_cant_reenable_what_another_disabled(
        self, db: FakeDb, app: FastAPI, agent: MagicMock
    ) -> None:
        db.add_org_settings(OTHER_ORG_ID, gmail=False)
        agent._tools_enabled = {**_ALL_ON, "gmail": False}
        _, token = _login(db, "org_admin", ORG_ID)

        response = _call(_client(app), "org_patch", token, body={"tools": {"gmail": True}})

        assert response.status_code == 200, response.text
        assert dict(agent._tools_enabled) == {**_ALL_ON, "gmail": False}

    def test_settings_api_org_patch_audit_failure_is_500_and_writes_nothing(
        self, db: FakeDb, app: FastAPI, agent: MagicMock
    ) -> None:
        _route_of(app, "org_patch")
        _, token = _login(db, "org_admin")
        before = _state(db)
        gate = dict(agent._tools_enabled)
        db.fail_audit = True

        response = _call(
            _client(app, raise_server_exceptions=False),
            "org_patch",
            token,
            body={"tools": {"gmail": False}},
        )

        assert response.status_code == 500
        assert _state(db) == before
        assert agent._tools_enabled == gate


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
        assert set(body) == {"llm", "limits"}
        assert set(body["llm"]) == _LLM_RESPONSE_KEYS
        assert body["limits"] == _STORED_LIMITS
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
# 9. The lifespan's gate reload
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _lifespan_patches(db: FakeDb, monkeypatch: pytest.MonkeyPatch) -> Any:
    """The lifespan runs on the fake pool; every background job is a no-op."""
    monkeypatch.setattr("admino.database.init_pool", AsyncMock(return_value=db.pool))
    monkeypatch.setattr("admino.database.close_pool", AsyncMock())
    monkeypatch.setattr("admino.database.load_permissions_from_db", AsyncMock(return_value={}))
    monkeypatch.setattr("admino.audit_events.run_retention_job", AsyncMock())
    monkeypatch.setattr("admino.sessions.run_session_purge_job", AsyncMock())
    monkeypatch.setattr("admino.mailer.load_smtp_config", MagicMock(return_value=None))
    with patch_org_purge_job(AsyncMock()), patch_login_throttle_purge_job(AsyncMock()):
        yield


class TestLifespanGate:
    """At startup the lifespan sets the agent's gate to the AND over every org."""

    async def test_settings_api_lifespan_sets_the_and_gate(
        self, db: FakeDb, app: FastAPI, agent: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db.add_org_settings(ORG_ID, gmail=False)
        db.add_org_settings(OTHER_ORG_ID, outlook=False)

        with _lifespan_patches(db, monkeypatch):
            async with server._lifespan(app):
                gate = dict(agent._tools_enabled)

        assert gate == {**_ALL_ON, "gmail": False, "outlook": False}

    async def test_settings_api_lifespan_failure_keeps_the_construction_gate(
        self,
        db: FakeDb,
        app: FastAPI,
        agent: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The org_settings read fails: the gate stays as constructed and the failure is
        logged by exception class name."""
        caplog.set_level(logging.WARNING)
        db.add_org_settings(ORG_ID, gmail=False)
        construction_gate = {**_ALL_ON, "memory": False}
        agent._tools_enabled = dict(construction_gate)
        db.fail_sql = r"\borg_settings\b"

        with _lifespan_patches(db, monkeypatch):
            async with server._lifespan(app):
                gate = dict(agent._tools_enabled)

        assert gate == construction_gate
        assert db.matching(r"\borg_settings\b"), "the gate was never read from org_settings"
        assert any(
            "DeadlockDetectedError" in record.getMessage()
            for record in caplog.records
            if record.levelno >= logging.WARNING
        )


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
