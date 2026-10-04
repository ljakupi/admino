"""HTTP spec for the V1 model policy (GH-242, contract section 5; no new routes).

The FastAPI app from ``create_app()`` runs a REAL ``Agent`` (with the real
tool-call recorder of ``main._build_tool_call_recorder()``) against the
in-memory database of tests/db_fakes.py (what ``admino.database.get_pool``
returns). The real ``require_session``, ``scoped_settings``,
``org_permissions.load_tool_policy`` (the org's residency included),
``audit_events`` and registry dispatch run. Only the LLM is a fake
(``_FakeLLM``: a ``provider`` class attribute like every client, a script of
replies or errors, a call counter), the registry holds one spied
``memory.store`` handler, and the LLM client factory and the two provider
model probes are mocks, so no network call is ever made. Users are FakeDb
accounts with real session cookies. The platform cache is emptied, so every
consumer reads this file's platform row.

What these tests pin down:
- ``GET`` / ``PATCH /api/platform/settings`` show ``llm.max_input_tokens``,
  ``llm.image_input``, ``llm.max_retries`` (the stored values) and
  ``llm.residency_orgs`` (the number of organizations whose data residency is
  on, every status counted).
- PATCH of those three fields: stored, returned, one ``platform.settings_change``
  event naming the changed fields mapped to True (never values), a no-op
  writes no event, and the LLM client is never rebuilt. Bounds and strict
  types are a 422 without echo and nothing written. A member gets 403 before
  any write.
- Residency confirmation (D1): a PATCH whose ``llm.provider`` is not Swiss
  (infomaniak, vllm) and differs from the stored provider needs
  ``confirm_residency_orgs`` equal to the current count; otherwise 409
  ``{"detail": str, "reason": "residency_confirmation", "residency_orgs": N}``
  with nothing written, no audit event and the running client kept. Checked
  after the rate limit and the capability (a member gets 403, not 409). The
  right count (0 included) switches as today. A Swiss target, or a patch that
  doesn't change the provider, needs no confirmation (a given count is
  ignored). A bad ``confirm_residency_orgs`` is a 422 without echo; given
  alone it is "nothing to change".
- Chat: ``POST /api/message`` and ``POST /api/confirm/{id}`` carry
  ``error_code`` (null on success and for uncoded failures, else the coded
  LLMError's code). A run's retry limit is the stored ``llm.max_retries``,
  read through the settings cache on every request.
- Residency end to end: a residency org's run with a non-Swiss (or
  provider-less) client ends with ``residency_blocked`` before any LLM call or
  tool dispatch, a resumed confirmation included; a non-residency org, or a
  Swiss client, is answered.
- No provider text: a provider error's message or cause never reaches a chat
  response or any log record.

``admino.llm_policy`` is imported inside the tests that patch its ``_sleep``
seam, so the rest of the file collects (and fails per test) before it exists.

All database calls are faked. No network, no real PostgreSQL, no real LLM.

Security notes:
- Data residency fails closed: a residency org never reaches a non-Swiss
  provider, a confirmation resumed after a provider switch included.
- Operator awareness: a non-Swiss switch can't happen without the Super Admin
  confirming the exact number of residency orgs it affects.
- No provider text: responses and logs carry codes only.
"""

from __future__ import annotations

import copy
import logging
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from admino import main as main_module
from admino import scoped_settings, server
from admino.agent import Agent
from admino.config import AppConfig
from admino.llm import LLMError, LLMResponse
from admino.models import AgentConfig, MemoryStoreArgs, ToolCall
from admino.server import create_app
from admino.tools import registry
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, PUBLIC_URL, FakeDb

if TYPE_CHECKING:
    import httpx
    from fastapi import FastAPI

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE: Final = "admino_session"
_IP: Final = "203.0.113.242"
_PLATFORM: Final = "/api/platform/settings"
_CHAT_ID: Final = "chat-242"
_FORBIDDEN: Final = {"detail": "Forbidden"}
_RATE_LIMITED: Final = {"detail": "Rate limit exceeded"}
_FINAL_REPLY: Final = "All done."
_CANARY: Final = "Zephyr-canary-242-provider-body"
_NOISE_STATUSES: Final = ("active", "deactivated", "pending_deletion")
_RETRYABLE: Final = ("provider_unavailable", "rate_limited", "timeout")
# code -> the HTTP status a provider would have answered (None: no response).
_STATUS_OF: Final[dict[str, int | None]] = {
    "not_configured": 401,
    "missing_model": 404,
    "provider_unavailable": 503,
    "rate_limited": 429,
    "timeout": None,
    "context_too_long": 400,
}
# field -> the platform_settings column it is stored in.
_COLUMNS: Final = {
    "max_input_tokens": "max_input_tokens",
    "image_input": "image_input",
    "max_retries": "llm_max_retries",
}
# field -> a valid value other than the column default.
_VALID: Final[dict[str, Any]] = {
    "max_input_tokens": 64000,
    "image_input": False,
    "max_retries": 4,
}
_RATE_KEYS: Final = (
    "/api/platform/settings/get",
    "/api/platform/settings/patch",
    "/api/message",
    "/api/confirm",
)

_BAD_CAPABILITY_VALUES = [
    pytest.param("max_input_tokens", 999, id="max-input-tokens-below"),
    pytest.param("max_input_tokens", 2_000_001, id="max-input-tokens-above"),
    pytest.param("max_input_tokens", 0, id="max-input-tokens-zero"),
    pytest.param("max_input_tokens", -64000, id="max-input-tokens-negative"),
    pytest.param("max_input_tokens", 9_876_543_210, id="max-input-tokens-huge"),
    pytest.param("max_input_tokens", True, id="max-input-tokens-true"),
    pytest.param("max_input_tokens", False, id="max-input-tokens-false"),
    pytest.param("max_input_tokens", 64000.0, id="max-input-tokens-float"),
    pytest.param("max_input_tokens", 64000.5, id="max-input-tokens-fraction"),
    pytest.param("max_input_tokens", "1234567", id="max-input-tokens-numeric-string"),
    pytest.param("max_input_tokens", "ECHOMARK42", id="max-input-tokens-string"),
    pytest.param("max_input_tokens", [64000], id="max-input-tokens-list"),
    pytest.param("image_input", 1, id="image-input-1"),
    pytest.param("image_input", 0, id="image-input-0"),
    pytest.param("image_input", "true", id="image-input-string-true"),
    pytest.param("image_input", "ECHOMARK42", id="image-input-string"),
    pytest.param("image_input", [True], id="image-input-list"),
    pytest.param("image_input", {}, id="image-input-object"),
    pytest.param("max_retries", -1, id="max-retries-below"),
    pytest.param("max_retries", 6, id="max-retries-above"),
    pytest.param("max_retries", 9_876_543_210, id="max-retries-huge"),
    pytest.param("max_retries", True, id="max-retries-true"),
    pytest.param("max_retries", 2.0, id="max-retries-float"),
    pytest.param("max_retries", "2", id="max-retries-numeric-string"),
    pytest.param("max_retries", "ECHOMARK42", id="max-retries-string"),
]
_CAPABILITY_BOUNDARIES = [
    pytest.param("max_input_tokens", 1000, id="max-input-tokens-low"),
    pytest.param("max_input_tokens", 2_000_000, id="max-input-tokens-high"),
    pytest.param("max_retries", 0, id="max-retries-low"),
    pytest.param("max_retries", 5, id="max-retries-high"),
    pytest.param("image_input", False, id="image-input-false"),
]
_BAD_CONFIRMATIONS = [
    pytest.param(True, id="true"),
    pytest.param(False, id="false"),
    pytest.param("3", id="numeric-string"),
    pytest.param(3.0, id="float"),
    pytest.param(-1, id="negative"),
    pytest.param(1_000_001, id="above-limit"),
    pytest.param(9_876_543_210, id="huge"),
    pytest.param("ECHOMARK42", id="string"),
    pytest.param([3], id="list"),
    pytest.param({"count": 3}, id="object"),
]
# (stored provider, target provider): a switch that needs the confirmation.
_UNCONFIRMED_SWITCHES = [
    pytest.param("infomaniak", "anthropic", id="infomaniak-to-anthropic"),
    pytest.param("infomaniak", "openai", id="infomaniak-to-openai"),
    pytest.param("vllm", "anthropic", id="vllm-to-anthropic"),
    pytest.param("anthropic", "openai", id="anthropic-to-openai"),
    pytest.param("openai", "anthropic", id="openai-to-anthropic"),
]


# ---------------------------------------------------------------------------
# Fakes: the LLM
# ---------------------------------------------------------------------------


class _FakeLLM:
    """A client of the given provider: plays its script (a reply, or an exception to
    raise) in order, then answers ``_FINAL_REPLY``; counts its calls and closes."""

    provider = "infomaniak"

    def __init__(self, provider: str | None = "infomaniak") -> None:
        self.provider = provider  # type: ignore[assignment]
        self.script: list[LLMResponse | BaseException] = []
        self.calls = 0
        self.closed = 0

    async def chat(
        self,
        messages: list[Any],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        self.calls += 1
        if self.script:
            step = self.script.pop(0)
            if isinstance(step, BaseException):
                raise step
            return step
        return LLMResponse(content=_FINAL_REPLY)

    async def close(self) -> None:
        self.closed += 1


def _coded(code: str, message: str | None = None) -> LLMError:
    """A coded (so user-facing) LLMError as a provider client raises it."""
    return LLMError(message or f"Fixed user-facing text for {code}.", _STATUS_OF[code], code=code)


def _store_call() -> LLMResponse:
    """The LLM asks for memory.store (confirm-gated in the confirmation tests)."""
    return LLMResponse(
        content="",
        tool_calls=[
            ToolCall(
                tool="memory",
                action="store",
                args={"key": "plan", "value": "the plan"},
                tool_call_id="call-242-store",
            )
        ],
    )


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
    """The fake database every get_pool() returns: two active orgs WITHOUT data residency
    (each with the default permission matrix), a deactivated org without residency (it
    must never be counted), and the platform row (Infomaniak, every model set, the
    column defaults). The settings cache is emptied, so every consumer reads this row."""
    fake = FakeDb()
    for org_id in (ORG_ID, OTHER_ORG_ID):
        fake.add_org(org_id, data_residency=False)
        fake.add_permissions(org_id)
    fake.add_org(uuid.uuid4(), status="deactivated", data_residency=False)
    fake.add_platform_settings(
        llm_provider="infomaniak",
        infomaniak_model="Qwen/Qwen3.5-397B-A17B-FP8",
        vllm_model="Qwen/Qwen3-4B-Instruct-2507",
        anthropic_model="claude-sonnet-4-6",
        openai_model="gpt-4o",
    )
    monkeypatch.setattr("admino.database.get_pool", lambda: fake.pool)
    scoped_settings._platform_cache = None
    return fake


@pytest.fixture(autouse=True)
def _roomy_rate_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Functional tests aren't about rate limits (the one that is sets its own)."""
    for key in _RATE_KEYS:
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))


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
def dispatched(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """An unfrozen registry holding one spied memory.store handler; returns the keys it
    stored, in order (the previous registry is restored after)."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)
    keys: list[str] = []

    async def store(args: MemoryStoreArgs, **_: object) -> str:
        keys.append(args.key)
        return f"Stored memory: {args.key}"

    registry.register_tool("memory", "store", "memory.store (GH-242 spec)", MemoryStoreArgs)(store)
    return keys


@pytest.fixture()
def llm() -> _FakeLLM:
    """The running client: an Infomaniak (Swiss) one unless a test says otherwise."""
    return _FakeLLM()


@pytest.fixture()
def agent(llm: _FakeLLM) -> Agent:
    """A real Agent around the fake LLM, with the real tool-call recorder."""
    return Agent(
        llm_client=llm,  # type: ignore[arg-type]
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
    )


def _config() -> AppConfig:
    return AppConfig.model_validate(
        {
            "server": {"host": "127.0.0.1", "port": 8000, "public_url": PUBLIC_URL},
            "llm": {
                "provider": "infomaniak",
                "infomaniak_model": "Qwen/Qwen3.5-397B-A17B-FP8",
                "vllm_model": "Qwen/Qwen3-4B-Instruct-2507",
                "anthropic_model": "claude-sonnet-4-6",
                "openai_model": "gpt-4o",
            },
        }
    )


@pytest.fixture()
def app(db: FakeDb, agent: Agent) -> FastAPI:
    """create_app with the real Agent and a real config (no lifespan runs)."""
    return create_app(agent=agent, config=_config())


def _client(app: FastAPI) -> TestClient:
    return TestClient(app, client=(_IP, 50000), follow_redirects=False)


def _headers(token: str) -> dict[str, str]:
    return {"Cookie": f"{_COOKIE}={token}"}


def _super_admin(db: FakeDb) -> tuple[uuid.UUID, str]:
    """A Super Admin with a live session: (id, token)."""
    user_id = db.add_account(kind="super_admin", role=None)
    return user_id, db.open_session(user_id)


def _member(db: FakeDb, role: str = "editor", org_id: uuid.UUID = ORG_ID) -> str:
    """A member of ``org_id`` with ``role`` and a live session: the session token."""
    user_id = db.add_account(role=role, org_id=org_id)
    return db.open_session(user_id)


def _get(client: TestClient, token: str) -> httpx.Response:
    return client.get(_PLATFORM, headers=_headers(token))


def _patch(client: TestClient, token: str, body: Any) -> httpx.Response:
    return client.patch(_PLATFORM, headers=_headers(token), json=body)


def _switch(provider: str, confirm: Any = None) -> dict[str, Any]:
    """A provider switch, with ``confirm_residency_orgs`` when one is given."""
    body: dict[str, Any] = {"llm": {"provider": provider}}
    if confirm is not None:
        body["confirm_residency_orgs"] = confirm
    return body


def _chat(
    client: TestClient, token: str, message: str = "hello", chat_id: str = _CHAT_ID
) -> httpx.Response:
    return client.post(
        "/api/message", headers=_headers(token), json={"message": message, "session_id": chat_id}
    )


def _confirm(
    client: TestClient, token: str, confirmation_id: str, chat_id: str = _CHAT_ID
) -> httpx.Response:
    return client.post(
        f"/api/confirm/{confirmation_id}",
        headers=_headers(token),
        json={"session_id": chat_id, "confirmation_id": confirmation_id, "approved": True},
    )


def _ask_confirmation(client: TestClient, token: str, llm: _FakeLLM) -> str:
    """POST a message whose LLM asks for memory.store; return the confirmation id."""
    llm.script.append(_store_call())
    asked = _chat(client, token, "store my plan")
    assert asked.status_code == 200, asked.text
    assert asked.json()["status"] == "awaiting_confirmation", asked.json()
    return str(asked.json()["pending_confirmation"]["confirmation_id"])


def _confirm_gated_store(db: FakeDb, org_id: uuid.UUID = ORG_ID) -> None:
    """The org's memory.store needs a confirmation."""
    db.add_permissions(org_id, {"memory": {"store": "confirm"}})


def _row(db: FakeDb) -> dict[str, Any]:
    row = db.platform_row()
    assert row is not None
    return row


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


def _add_residency_orgs(db: FakeDb, count: int) -> None:
    """``count`` orgs with data residency on, cycling through every org status."""
    for index in range(count):
        status = _NOISE_STATUSES[index % len(_NOISE_STATUSES)]
        db.add_org(uuid.uuid4(), status=status, data_residency=True)


def _settings_changes(db: FakeDb) -> list[dict[str, Any]]:
    """The metadata of every platform.settings_change audit row, in order."""
    return [row["metadata"] for row in db.audit if row["action"] == "platform.settings_change"]


def _error_code(body: dict[str, Any]) -> Any:
    """The chat response's error_code, which every response carries (null included)."""
    assert "error_code" in body, f"the chat response has no error_code: {sorted(body)}"
    return body["error_code"]


def _assert_confirmation_needed(response: httpx.Response, count: int) -> None:
    """The residency confirmation 409 with the current count."""
    assert response.status_code == 409, response.text
    body = response.json()
    assert set(body) == {"detail", "reason", "residency_orgs"}, body
    assert isinstance(body["detail"], str), body
    assert body["detail"].strip(), body
    assert (body["reason"], body["residency_orgs"]) == ("residency_confirmation", count)
    assert type(body["residency_orgs"]) is int


def _assert_client_kept(agent: Agent, llm: _FakeLLM, probes: _Probes) -> None:
    """No client was built, the running one is still in place and was never closed."""
    probes.create.assert_not_called()
    assert agent._llm is llm
    assert llm.closed == 0


def _assert_no_echo(response: httpx.Response, value: Any) -> None:
    """A 422 never repeats a marker string or a large number the request carried."""
    text = response.text
    assert "ECHOMARK42" not in text, text
    if isinstance(value, str) and len(value) >= 6:
        assert value not in text, text
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) >= 100000:
        assert str(value) not in text, text


def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Replace llm_policy's backoff sleep with a recorder; return the delays asked for."""
    import admino.llm_policy as llm_policy

    delays: list[float] = []

    async def record(delay: float, *_args: object, **_kwargs: object) -> None:
        delays.append(float(delay))

    monkeypatch.setattr(llm_policy, "_sleep", record)
    return delays


def _log_dump(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured record: formatted (exception traceback included) and raw."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(f"{formatter.format(record)}\n{vars(record)!r}" for record in caplog.records)


# ---------------------------------------------------------------------------
# 1. GET /api/platform/settings
# ---------------------------------------------------------------------------


class TestPlatformGet:
    """The stored capabilities and retry limit, and the live residency-org count."""

    def test_model_policy_api_get_shows_the_stored_capabilities_and_retry_limit(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _row(db).update(max_input_tokens=64000, image_input=False, llm_max_retries=4)
        _, token = _super_admin(db)

        response = _get(_client(app), token)

        assert response.status_code == 200, response.text
        llm = response.json()["llm"]
        assert (llm["max_input_tokens"], llm["image_input"], llm["max_retries"]) == (
            64000,
            False,
            4,
        )
        assert (type(llm["max_input_tokens"]), type(llm["image_input"])) == (int, bool)

    def test_model_policy_api_get_shows_the_column_defaults(self, db: FakeDb, app: FastAPI) -> None:
        _, token = _super_admin(db)

        llm = _get(_client(app), token).json()["llm"]

        assert (llm["max_input_tokens"], llm["image_input"], llm["max_retries"]) == (
            200000,
            True,
            2,
        )

    @pytest.mark.parametrize("count", [0, 1, 3, 5])
    def test_model_policy_api_get_counts_residency_orgs_of_every_status(
        self, db: FakeDb, app: FastAPI, count: int
    ) -> None:
        """Active, deactivated and pending-deletion residency orgs all count; the three
        orgs without residency don't."""
        _add_residency_orgs(db, count)
        _, token = _super_admin(db)

        llm = _get(_client(app), token).json()["llm"]

        assert llm["residency_orgs"] == count
        assert type(llm["residency_orgs"]) is int

    def test_model_policy_api_get_count_follows_a_residency_change(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """The count is read on every request, never cached."""
        _, token = _super_admin(db)
        client = _client(app)

        before = _get(client, token).json()["llm"]["residency_orgs"]
        db.add_org(ORG_ID, data_residency=True)
        after = _get(client, token).json()["llm"]["residency_orgs"]

        assert (before, after) == (0, 1)


# ---------------------------------------------------------------------------
# 2. PATCH /api/platform/settings: the capabilities and the retry limit
# ---------------------------------------------------------------------------


class TestCapabilityPatch:
    """max_input_tokens, image_input and max_retries: stored, returned, audited by name,
    and never a client rebuild."""

    @pytest.mark.parametrize("field", list(_VALID))
    def test_model_policy_api_patch_capability_is_stored_returned_and_audited(
        self, db: FakeDb, app: FastAPI, field: str
    ) -> None:
        admin_id, token = _super_admin(db)

        response = _patch(_client(app), token, {"llm": {field: _VALID[field]}})

        assert response.status_code == 200, response.text
        assert response.json()["llm"][field] == _VALID[field]
        assert _row(db)[_COLUMNS[field]] == _VALID[field]
        event = db.audit[-1]
        assert len(db.audit) == 1, db.audit
        assert (event["action"], event["actor_kind"]) == ("platform.settings_change", "super_admin")
        assert str(event["actor_user_id"]) == str(admin_id)
        assert event["metadata"] == {field: True}

    def test_model_policy_api_patch_all_three_is_one_event_naming_each_field(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _super_admin(db)

        response = _patch(_client(app), token, {"llm": dict(_VALID)})

        assert response.status_code == 200, response.text
        llm = response.json()["llm"]
        assert {field: llm[field] for field in _VALID} == _VALID
        assert {field: _row(db)[column] for field, column in _COLUMNS.items()} == _VALID
        assert _settings_changes(db) == [dict.fromkeys(_VALID, True)]

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param({"llm": {"max_input_tokens": 64000}}, id="max-input-tokens"),
            pytest.param({"llm": {"image_input": False}}, id="image-input"),
            pytest.param({"llm": {"max_retries": 0}}, id="max-retries"),
            pytest.param({"llm": dict(_VALID)}, id="all-three"),
        ],
    )
    def test_model_policy_api_patch_capability_never_rebuilds_the_client(
        self,
        db: FakeDb,
        app: FastAPI,
        agent: Agent,
        llm: _FakeLLM,
        probes: _Probes,
        body: dict[str, Any],
    ) -> None:
        _, token = _super_admin(db)

        response = _patch(_client(app), token, body)

        assert response.status_code == 200, response.text
        _assert_client_kept(agent, llm, probes)
        assert response.json()["llm"]["provider"] == "infomaniak"

    def test_model_policy_api_patch_same_capability_values_writes_no_event(
        self, db: FakeDb, app: FastAPI, agent: Agent, llm: _FakeLLM, probes: _Probes
    ) -> None:
        _, token = _super_admin(db)

        response = _patch(
            _client(app),
            token,
            {"llm": {"max_input_tokens": 200000, "image_input": True, "max_retries": 2}},
        )

        assert response.status_code == 200, response.text
        assert db.audit == []
        _assert_client_kept(agent, llm, probes)

    @pytest.mark.parametrize(("field", "value"), _CAPABILITY_BOUNDARIES)
    def test_model_policy_api_patch_capability_boundary_is_accepted(
        self, db: FakeDb, app: FastAPI, field: str, value: Any
    ) -> None:
        _, token = _super_admin(db)

        response = _patch(_client(app), token, {"llm": {field: value}})

        assert response.status_code == 200, response.text
        assert _row(db)[_COLUMNS[field]] == value
        assert response.json()["llm"][field] == value

    @pytest.mark.parametrize(("field", "value"), _BAD_CAPABILITY_VALUES)
    def test_model_policy_api_patch_bad_capability_is_422_without_echo_and_writes_nothing(
        self, db: FakeDb, app: FastAPI, field: str, value: Any
    ) -> None:
        """The bad value is refused at its field; the same field then takes a valid
        value (it is a known setting, not an unknown key)."""
        _, token = _super_admin(db)
        client = _client(app)
        before = _state(db)

        refused = _patch(client, token, {"llm": {field: value}})
        after_refusal = _state(db)
        accepted = _patch(client, token, {"llm": {field: _VALID[field]}})

        assert refused.status_code == 422, refused.text
        _assert_no_echo(refused, value)
        locs = [list(error["loc"]) for error in refused.json()["detail"]]
        assert any(loc[:3] == ["body", "llm", field] for loc in locs), locs
        assert after_refusal == before
        assert accepted.status_code == 200, accepted.text
        assert _row(db)[_COLUMNS[field]] == _VALID[field]

    @pytest.mark.parametrize("role", ["org_admin", "editor", "viewer"])
    @pytest.mark.parametrize("field", list(_VALID))
    def test_model_policy_api_member_capability_patch_is_403_before_any_write(
        self, db: FakeDb, app: FastAPI, role: str, field: str
    ) -> None:
        token = _member(db, role)
        before = _state(db)

        response = _patch(_client(app), token, {"llm": {field: _VALID[field]}})

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 3. PATCH /api/platform/settings: the residency confirmation (D1)
# ---------------------------------------------------------------------------


class TestResidencyConfirmation:
    """A switch to a non-Swiss provider needs ``confirm_residency_orgs`` equal to the
    current count of residency orgs; else 409 and nothing changes."""

    @pytest.mark.parametrize("count", [0, 3])
    @pytest.mark.parametrize(("stored", "target"), _UNCONFIRMED_SWITCHES)
    def test_model_policy_api_unconfirmed_non_swiss_switch_is_409_and_changes_nothing(
        self,
        db: FakeDb,
        app: FastAPI,
        agent: Agent,
        llm: _FakeLLM,
        probes: _Probes,
        stored: str,
        target: str,
        count: int,
    ) -> None:
        _row(db)["llm_provider"] = stored
        _add_residency_orgs(db, count)
        _, token = _super_admin(db)
        before = _state(db)
        assert server._config is not None
        live_before = server._config.llm.model_dump()

        response = _patch(_client(app), token, _switch(target))

        _assert_confirmation_needed(response, count)
        assert _state(db) == before
        _assert_client_kept(agent, llm, probes)
        assert server._config.llm.model_dump() == live_before

    def test_model_policy_api_unconfirmed_switch_in_a_mixed_patch_writes_no_section(
        self, db: FakeDb, app: FastAPI, agent: Agent, llm: _FakeLLM, probes: _Probes
    ) -> None:
        """The capability, limits and model changes beside the switch are not written
        either, and the cache never holds them."""
        _add_residency_orgs(db, 2)
        _, token = _super_admin(db)
        before = _state(db)

        response = _patch(
            _client(app),
            token,
            {
                "llm": {
                    "provider": "anthropic",
                    "anthropic_model": "claude-opus-4-1",
                    "max_retries": 4,
                    "image_input": False,
                },
                "limits": {"max_message_length": 10},
            },
        )

        _assert_confirmation_needed(response, 2)
        assert _state(db) == before
        _assert_client_kept(agent, llm, probes)
        cache = scoped_settings._platform_cache
        if cache is not None:
            assert cache.llm.provider == "infomaniak"
            assert cache.limits.max_message_length != 10

    @pytest.mark.parametrize(
        ("count", "given"),
        [
            pytest.param(3, 2, id="three-given-two"),
            pytest.param(3, 4, id="three-given-four"),
            pytest.param(3, 0, id="three-given-zero"),
            pytest.param(3, 1_000_000, id="three-given-limit"),
            pytest.param(0, 1, id="zero-given-one"),
            pytest.param(1, None, id="one-given-null"),
        ],
    )
    def test_model_policy_api_wrong_confirmation_is_409_with_the_current_count(
        self,
        db: FakeDb,
        app: FastAPI,
        agent: Agent,
        llm: _FakeLLM,
        probes: _Probes,
        count: int,
        given: int | None,
    ) -> None:
        _add_residency_orgs(db, count)
        _, token = _super_admin(db)
        before = _state(db)
        body: dict[str, Any] = {"llm": {"provider": "anthropic"}, "confirm_residency_orgs": given}

        response = _patch(_client(app), token, body)

        _assert_confirmation_needed(response, count)
        assert _state(db) == before
        _assert_client_kept(agent, llm, probes)

    @pytest.mark.parametrize("target", ["anthropic", "openai"])
    @pytest.mark.parametrize("count", [0, 3])
    def test_model_policy_api_right_confirmation_switches_the_provider(
        self,
        db: FakeDb,
        app: FastAPI,
        agent: Agent,
        llm: _FakeLLM,
        probes: _Probes,
        count: int,
        target: str,
    ) -> None:
        """The switch happens as today: a client built for the target, swapped in, the
        old one closed, one event naming the provider (the confirmation is no setting)."""
        _add_residency_orgs(db, count)
        _, token = _super_admin(db)

        response = _patch(_client(app), token, _switch(target, count))

        assert response.status_code == 200, response.text
        assert response.json()["llm"]["provider"] == target
        assert response.json()["llm"]["residency_orgs"] == count
        assert _row(db)["llm_provider"] == target
        probes.create.assert_called_once()
        assert probes.create.call_args.args[0].provider == target
        assert agent._llm is probes.new_client
        assert llm.closed == 1
        assert _settings_changes(db) == [{"provider": True}]

    @pytest.mark.parametrize(
        ("stored", "target", "given"),
        [
            pytest.param("infomaniak", "vllm", None, id="infomaniak-to-vllm"),
            pytest.param("infomaniak", "vllm", 7, id="infomaniak-to-vllm-wrong-count-ignored"),
            pytest.param("anthropic", "infomaniak", None, id="anthropic-to-infomaniak"),
            pytest.param("openai", "vllm", 0, id="openai-to-vllm-wrong-count-ignored"),
        ],
    )
    def test_model_policy_api_switch_to_a_swiss_provider_needs_no_confirmation(
        self,
        db: FakeDb,
        app: FastAPI,
        agent: Agent,
        probes: _Probes,
        stored: str,
        target: str,
        given: int | None,
    ) -> None:
        _row(db)["llm_provider"] = stored
        _add_residency_orgs(db, 3)
        _, token = _super_admin(db)

        response = _patch(_client(app), token, _switch(target, given))

        assert response.status_code == 200, response.text
        assert response.json()["llm"]["provider"] == target
        assert response.json()["llm"]["residency_orgs"] == 3
        assert _row(db)["llm_provider"] == target
        assert agent._llm is probes.new_client

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param(
                {"llm": {"provider": "anthropic", "anthropic_model": "claude-opus-4-1"}},
                id="same-provider-new-model",
            ),
            pytest.param(
                {
                    "llm": {"provider": "anthropic", "anthropic_model": "claude-opus-4-1"},
                    "confirm_residency_orgs": 99,
                },
                id="same-provider-wrong-count-ignored",
            ),
            pytest.param(
                {"llm": {"max_retries": 3}, "confirm_residency_orgs": 99},
                id="capability-only-wrong-count-ignored",
            ),
            pytest.param(
                {"limits": {"max_message_length": 5000}, "confirm_residency_orgs": 0},
                id="limits-only-wrong-count-ignored",
            ),
        ],
    )
    def test_model_policy_api_patch_not_changing_the_provider_needs_no_confirmation(
        self, db: FakeDb, app: FastAPI, probes: _Probes, body: dict[str, Any]
    ) -> None:
        """Anthropic is stored and stays: nothing to confirm, a given count is ignored."""
        _row(db)["llm_provider"] = "anthropic"
        _add_residency_orgs(db, 3)
        _, token = _super_admin(db)

        response = _patch(_client(app), token, body)

        assert response.status_code == 200, response.text
        assert response.json()["llm"]["provider"] == "anthropic"
        assert response.json()["llm"]["residency_orgs"] == 3
        assert _row(db)["llm_provider"] == "anthropic"
        probes.create.assert_not_called()

    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    def test_model_policy_api_member_switch_is_403_not_409(
        self, db: FakeDb, app: FastAPI, agent: Agent, llm: _FakeLLM, probes: _Probes, role: str
    ) -> None:
        """Unconfirmed or wrongly confirmed: the capability check comes first."""
        _add_residency_orgs(db, 3)
        token = _member(db, role)
        client = _client(app)
        before = _state(db)

        unconfirmed = _patch(client, token, _switch("anthropic"))
        wrong = _patch(client, token, _switch("anthropic", 2))

        assert (unconfirmed.status_code, unconfirmed.json()) == (403, _FORBIDDEN)
        assert (wrong.status_code, wrong.json()) == (403, _FORBIDDEN)
        assert _state(db) == before
        _assert_client_kept(agent, llm, probes)

    def test_model_policy_api_rate_limit_comes_before_the_residency_check(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A burst of 1: the first unconfirmed switch is the 409, the second the 429."""
        monkeypatch.setitem(server._RATE_LIMITS, "/api/platform/settings/patch", (0.001, 1))
        _add_residency_orgs(db, 3)
        _, token = _super_admin(db)
        client = _client(app)

        first = _patch(client, token, _switch("anthropic"))
        second = _patch(client, token, _switch("anthropic"))

        _assert_confirmation_needed(first, 3)
        assert (second.status_code, second.json()) == (429, _RATE_LIMITED)

    @pytest.mark.parametrize("value", _BAD_CONFIRMATIONS)
    def test_model_policy_api_bad_confirmation_is_422_without_echo_and_writes_nothing(
        self, db: FakeDb, app: FastAPI, value: Any
    ) -> None:
        """A strict int 0..1_000_000 only; the right count then switches."""
        _add_residency_orgs(db, 3)
        _, token = _super_admin(db)
        client = _client(app)
        before = _state(db)

        refused = _patch(client, token, _switch("anthropic", value))
        after_refusal = _state(db)
        confirmed = _patch(client, token, _switch("anthropic", 3))

        assert refused.status_code == 422, refused.text
        _assert_no_echo(refused, value)
        locs = [list(error["loc"]) for error in refused.json()["detail"]]
        assert any(loc[:2] == ["body", "confirm_residency_orgs"] for loc in locs), locs
        assert after_refusal == before
        assert confirmed.status_code == 200, confirmed.text
        assert _row(db)["llm_provider"] == "anthropic"

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param({"confirm_residency_orgs": 3}, id="confirmation-only"),
            pytest.param({"llm": {}, "confirm_residency_orgs": 3}, id="empty-llm"),
            pytest.param({"llm": {"provider": None}, "confirm_residency_orgs": 0}, id="null"),
        ],
    )
    def test_model_policy_api_confirmation_alone_is_nothing_to_change(
        self, db: FakeDb, app: FastAPI, body: dict[str, Any]
    ) -> None:
        """The confirmation is no setting: the patch-level "nothing given" 422."""
        _add_residency_orgs(db, 3)
        _, token = _super_admin(db)
        before = _state(db)

        response = _patch(_client(app), token, body)

        assert response.status_code == 422, response.text
        locs = [list(error["loc"]) for error in response.json()["detail"]]
        assert locs == [["body"]], locs
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 4. Chat: error_code and the stored retry limit
# ---------------------------------------------------------------------------


class TestChatErrorCode:
    """POST /api/message and POST /api/confirm carry the run's error_code."""

    def test_model_policy_api_message_success_has_a_null_error_code(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM
    ) -> None:
        response = _chat(_client(app), _member(db))

        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["status"], body["response"]) == ("final", _FINAL_REPLY)
        assert _error_code(body) is None
        assert llm.calls == 1

    @pytest.mark.parametrize("code", ["not_configured", "missing_model", "context_too_long"])
    def test_model_policy_api_message_carries_a_non_retryable_code(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, code: str
    ) -> None:
        """No retry; the coded error's fixed message is the response."""
        error = _coded(code)
        llm.script.extend([error, LLMResponse(content="never reached")])

        response = _chat(_client(app), _member(db))

        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["status"], _error_code(body)) == ("error", code)
        assert body["response"] == error.message
        assert llm.calls == 1

    def test_model_policy_api_message_is_rate_limited_after_retries_are_exhausted(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The stored default of 2 retries: three calls, two backoff sleeps."""
        delays = _no_sleep(monkeypatch)
        llm.script.extend(_coded("rate_limited") for _ in range(4))

        response = _chat(_client(app), _member(db))

        body = response.json()
        assert (body["status"], _error_code(body)) == ("error", "rate_limited")
        assert llm.calls == 3
        assert len(delays) == 2

    @pytest.mark.parametrize("code", _RETRYABLE)
    def test_model_policy_api_stored_retry_limit_one_fails_after_two_calls(
        self,
        db: FakeDb,
        app: FastAPI,
        llm: _FakeLLM,
        monkeypatch: pytest.MonkeyPatch,
        code: str,
    ) -> None:
        delays = _no_sleep(monkeypatch)
        _row(db)["llm_max_retries"] = 1
        llm.script.extend([_coded(code), _coded(code), LLMResponse(content="too late")])

        response = _chat(_client(app), _member(db))

        body = response.json()
        assert (body["status"], _error_code(body)) == ("error", code)
        assert llm.calls == 2
        assert len(delays) == 1

    def test_model_policy_api_stored_retry_limit_two_answers_on_the_third_call(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        delays = _no_sleep(monkeypatch)
        _row(db)["llm_max_retries"] = 2
        llm.script.extend([_coded("provider_unavailable"), _coded("provider_unavailable")])

        response = _chat(_client(app), _member(db))

        body = response.json()
        assert (body["status"], body["response"]) == ("final", _FINAL_REPLY)
        assert _error_code(body) is None
        assert llm.calls == 3
        assert len(delays) == 2

    def test_model_policy_api_patched_retry_limit_applies_to_the_next_message(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No restart: after max_retries 0 the next run fails at the first transient
        error, without a sleep."""
        delays = _no_sleep(monkeypatch)
        _, admin = _super_admin(db)
        client = _client(app)

        patched = _patch(client, admin, {"llm": {"max_retries": 0}})
        llm.script.extend([_coded("timeout"), LLMResponse(content="too late")])
        response = _chat(client, _member(db))

        assert patched.status_code == 200, patched.text
        body = response.json()
        assert (body["status"], _error_code(body)) == ("error", "timeout")
        assert llm.calls == 1
        assert delays == []

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(LLMError("Infomaniak API returned HTTP 400", 400), id="internal-llm"),
            pytest.param(RuntimeError("unexpected"), id="other-exception"),
        ],
    )
    def test_model_policy_api_uncoded_failure_has_a_null_error_code(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, error: Exception
    ) -> None:
        llm.script.append(error)

        response = _chat(_client(app), _member(db))

        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["status"], _error_code(body)) == ("error", None)
        assert body["response"] != str(error)
        assert llm.calls == 1

    def test_model_policy_api_confirm_success_has_a_null_error_code(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, dispatched: list[str]
    ) -> None:
        _confirm_gated_store(db)
        token = _member(db)
        client = _client(app)
        confirmation_id = _ask_confirmation(client, token, llm)

        response = _confirm(client, token, confirmation_id)

        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["status"], body["response"]) == ("final", _FINAL_REPLY)
        assert _error_code(body) is None
        assert dispatched == ["plan"]

    def test_model_policy_api_confirm_carries_the_code_of_the_follow_up_error(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, dispatched: list[str]
    ) -> None:
        _confirm_gated_store(db)
        token = _member(db)
        client = _client(app)
        confirmation_id = _ask_confirmation(client, token, llm)
        llm.script.append(_coded("not_configured"))

        response = _confirm(client, token, confirmation_id)

        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["status"], _error_code(body)) == ("error", "not_configured")
        assert dispatched == ["plan"]


# ---------------------------------------------------------------------------
# 5. Residency end to end
# ---------------------------------------------------------------------------


class TestResidencyEndToEnd:
    """A residency org never reaches a non-Swiss provider: no LLM call, no dispatch."""

    @pytest.mark.parametrize(
        "provider",
        [
            pytest.param("anthropic", id="anthropic"),
            pytest.param("openai", id="openai"),
            pytest.param(None, id="no-provider"),
        ],
    )
    def test_model_policy_api_residency_org_with_a_non_swiss_client_is_blocked(
        self,
        db: FakeDb,
        app: FastAPI,
        llm: _FakeLLM,
        dispatched: list[str],
        provider: str | None,
    ) -> None:
        from admino.llm_policy import residency_blocked_error

        db.add_org(ORG_ID, data_residency=True)
        llm.provider = provider  # type: ignore[assignment]
        llm.script.append(_store_call())
        audit_before = len(db.audit_rows("tool.call"))

        response = _chat(_client(app), _member(db, org_id=ORG_ID))

        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["status"], _error_code(body)) == ("error", "residency_blocked")
        assert body["response"] == residency_blocked_error().message
        assert llm.calls == 0
        assert dispatched == []
        assert len(db.audit_rows("tool.call")) == audit_before

    @pytest.mark.parametrize("provider", ["anthropic", "openai"])
    def test_model_policy_api_non_residency_org_with_a_non_swiss_client_is_answered(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, provider: str
    ) -> None:
        db.add_org(OTHER_ORG_ID, data_residency=False)
        llm.provider = provider

        response = _chat(_client(app), _member(db, org_id=OTHER_ORG_ID))

        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["status"], body["response"]) == ("final", _FINAL_REPLY)
        assert _error_code(body) is None
        assert llm.calls == 1

    @pytest.mark.parametrize("provider", ["infomaniak", "vllm"])
    def test_model_policy_api_residency_org_with_a_swiss_client_is_answered(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, provider: str
    ) -> None:
        db.add_org(ORG_ID, data_residency=True)
        llm.provider = provider

        response = _chat(_client(app), _member(db, org_id=ORG_ID))

        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["status"], body["response"]) == ("final", _FINAL_REPLY)
        assert _error_code(body) is None
        assert llm.calls == 1

    def test_model_policy_api_confirm_after_a_non_swiss_switch_is_blocked_without_dispatch(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, dispatched: list[str]
    ) -> None:
        """The confirmation was asked under a Swiss client; the provider then became
        non-Swiss: the approved tool is not dispatched, nothing is recorded, the LLM is
        not called again."""
        db.add_org(ORG_ID, data_residency=True)
        _confirm_gated_store(db)
        token = _member(db, org_id=ORG_ID)
        client = _client(app)
        confirmation_id = _ask_confirmation(client, token, llm)
        calls_before = llm.calls
        audit_before = len(db.audit_rows("tool.call"))
        llm.provider = "anthropic"

        response = _confirm(client, token, confirmation_id)

        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["status"], _error_code(body)) == ("error", "residency_blocked")
        assert dispatched == []
        assert llm.calls == calls_before
        assert len(db.audit_rows("tool.call")) == audit_before

    def test_model_policy_api_confirmed_switch_blocks_residency_orgs_only(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, probes: _Probes
    ) -> None:
        """Through the real switch: the Super Admin confirms the one residency org and
        switches to Anthropic; that org's member is blocked, the other org's member is
        answered by the new client."""
        db.add_org(ORG_ID, data_residency=True)
        anthropic = _FakeLLM(provider="anthropic")
        probes.create.return_value = anthropic
        _, admin = _super_admin(db)
        resident = _member(db, org_id=ORG_ID)
        other = _member(db, org_id=OTHER_ORG_ID)
        client = _client(app)

        switched = _patch(client, admin, _switch("anthropic", 1))
        blocked = _chat(client, resident, chat_id="chat-242-resident")
        answered = _chat(client, other, chat_id="chat-242-other")

        assert switched.status_code == 200, switched.text
        assert (blocked.json()["status"], _error_code(blocked.json())) == (
            "error",
            "residency_blocked",
        )
        assert (answered.json()["status"], _error_code(answered.json())) == ("final", None)
        assert (anthropic.calls, llm.calls) == (1, 0)


# ---------------------------------------------------------------------------
# 6. No provider text in responses or logs
# ---------------------------------------------------------------------------


class TestNoProviderText:
    """A provider error's text (message, body, cause) never reaches a chat response or
    any log record."""

    def test_model_policy_api_internal_provider_error_text_reaches_no_response_or_log(
        self, db: FakeDb, app: FastAPI, llm: _FakeLLM, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        error = LLMError(f"provider body: {_CANARY}", 400)
        error.__cause__ = RuntimeError(f"sdk said {_CANARY}")
        llm.script.append(error)

        response = _chat(_client(app), _member(db))

        assert response.status_code == 200, response.text
        assert (response.json()["status"], _error_code(response.json())) == ("error", None)
        assert _CANARY not in response.text
        assert _CANARY not in _log_dump(caplog)

    def test_model_policy_api_retried_provider_error_cause_reaches_no_response_or_log(
        self,
        db: FakeDb,
        app: FastAPI,
        llm: _FakeLLM,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A transient error retried twice (one WARNING per retry), its cause holding the
        provider's text."""
        _no_sleep(monkeypatch)
        caplog.set_level(logging.DEBUG)
        for _ in range(3):
            error = _coded("provider_unavailable")
            error.__cause__ = RuntimeError(f"upstream body: {_CANARY}")
            llm.script.append(error)

        response = _chat(_client(app), _member(db))

        assert (response.json()["status"], _error_code(response.json())) == (
            "error",
            "provider_unavailable",
        )
        assert llm.calls == 3
        assert _CANARY not in response.text
        assert _CANARY not in _log_dump(caplog)


# ---------------------------------------------------------------------------
# GH-242 security fix: a residency change racing the switch
# ---------------------------------------------------------------------------


class TestResidencyConfirmationRace:
    """The route's count is checked again inside the write transaction."""

    def test_model_policy_api_residency_change_during_the_switch_is_409_and_changes_nothing(
        self, db: FakeDb, app: FastAPI, agent: Agent, llm: _FakeLLM, probes: _Probes
    ) -> None:
        """An org turns residency on after the route counted 0 (here: while the new
        client is built). The write counts again and refuses with the new count: nothing
        is written or audited, the new client is closed and the running one kept."""
        _, token = _super_admin(db)

        def _build_while_an_org_turns_residency_on(config: Any) -> MagicMock:
            db.add_org(uuid.uuid4(), data_residency=True)
            return probes.new_client

        probes.create.side_effect = _build_while_an_org_turns_residency_on
        before = copy.deepcopy(_row(db))

        response = _patch(_client(app), token, _switch("anthropic", 0))

        _assert_confirmation_needed(response, 1)
        assert _row(db) == before
        assert _settings_changes(db) == []
        probes.new_client.close.assert_awaited_once()
        assert agent._llm is llm
        assert llm.closed == 0
