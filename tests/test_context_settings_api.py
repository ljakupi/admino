"""``max_context_messages`` 0 (no cap) end to end, and the startup wiring of the context
budget (GH-190, issue Decisions 1, 7 and 8; contract C3, C7 and C11).

The FastAPI app from ``create_app()`` runs against the in-memory database of
tests/db_fakes.py (what ``admino.database.get_pool`` returns) with a real
``AppConfig``. The real ``require_session``, ``admino.scoped_settings`` and
``admino.audit_events`` code runs; the LLM client factory and the two provider probes
are mocks, so no network call is ever made. The fake models the schema the shipped
migrations leave in place: until migration 0030 ships, a stored 0 is refused like
0013's CHECK refuses it.

What these tests pin down:
- ``GET /api/platform/settings`` shows ``limits.max_context_messages`` 0 when the row
  holds 0.
- ``PATCH /api/platform/settings`` takes 0 to 200 for ``limits.max_context_messages``
  (0 and 200 stored and returned); -1, 201, a bool and a numeric string are a 422 with
  nothing written. A change to 0 is one ``platform.settings_change`` event whose
  metadata is ``{"max_context_messages_old": <int>, "max_context_messages_new": 0}``.
- The startup seed (``scoped_settings.seed_platform_settings``) stores config.yaml's 0
  on a first boot and keeps a stored value on a later boot (an install keeps the 20 it
  has).
- ``server._run_config(platform)``: the run's AgentConfig gets the stored 0 (no cap),
  the platform's ``llm.max_input_tokens``, and from the config ``llm.max_response_tokens``
  (reserved output), ``context.safety_margin_percent`` and
  ``context.max_tool_result_tokens``.
- ``create_app`` builds its processing pool with ``BudgetSettings.from_config(config)``:
  every job the pool runs gets that ``budget``.

(main.py's construction-time AgentConfig is pinned in tests/test_main.py.)

All database calls are faked. No network, no real PostgreSQL, no LLM.

Security notes:
- The budget values come from config.yaml and the stored platform row, never from a
  request.
- Audit metadata stays ints only (old and new values), no content.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from admino import attachment_processing, scoped_settings, server
from admino.config import AppConfig
from admino.server import create_app
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, PUBLIC_URL, FakeDb

if TYPE_CHECKING:
    from pathlib import Path

    import httpx
    from fastapi import FastAPI

_COOKIE: Final = "admino_session"
_IP: Final = "203.0.113.90"
_PLATFORM: Final = "/api/platform/settings"
_RATE_KEYS: Final = ("/api/platform/settings/get", "/api/platform/settings/patch")
_FIELD: Final = "max_context_messages"
_STORED_LIMITS: Final[dict[str, int]] = {
    "max_tool_calls_per_message": 7,
    "max_pending_confirmations": 4,
    "confirmation_timeout_s": 120,
    "max_message_length": 5000,
    "max_context_messages": 30,
}
_MIB: Final = 1_048_576
# The config's budget values: none of them a default, so a pool or run built from the
# defaults is told apart.
_RESPONSE_TOKENS: Final = 1234
_MARGIN_PERCENT: Final = 15
_TURN_MB: Final = 8
_TOOL_RESULT_TOKENS: Final = 5000
_PLATFORM_INPUT_TOKENS: Final = 64000


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _config(*, limits: dict[str, int] | None = None) -> AppConfig:
    """A real config: Anthropic, every model set, the budget values above."""
    return AppConfig.model_validate(
        {
            "server": {"host": "127.0.0.1", "port": 8000, "public_url": PUBLIC_URL},
            "llm": {
                "provider": "anthropic",
                "anthropic_model": "claude-sonnet-4-6",
                "openai_model": "gpt-4o",
                "infomaniak_model": "Qwen/Qwen3.5-397B-A17B-FP8",
                "vllm_model": "Qwen/Qwen3-4B-Instruct-2507",
                "max_response_tokens": _RESPONSE_TOKENS,
            },
            "limits": limits or {},
            "context": {
                "safety_margin_percent": _MARGIN_PERCENT,
                "max_attachment_mb_per_turn": _TURN_MB,
                "max_tool_result_tokens": _TOOL_RESULT_TOKENS,
            },
        }
    )


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both provider probes and the LLM client factory are mocks; the platform routes get
    large rate-limit buckets (this file isn't about rate limits)."""
    monkeypatch.setattr(server, "_get_vllm_available_models", AsyncMock(return_value=[]))
    monkeypatch.setattr(server, "_get_infomaniak_available_models", AsyncMock(return_value=[]))
    monkeypatch.setattr("admino.llm.create_llm_client", MagicMock(name="create_llm_client"))
    for key in _RATE_KEYS:
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))


def _world(monkeypatch: pytest.MonkeyPatch, **limits: int) -> FakeDb:
    """Two orgs and the platform row (the stored limits, overridden by ``limits``), the
    database the server's get_pool() returns, and an empty settings cache (the routes
    read this row)."""
    db = FakeDb()
    db.add_org(ORG_ID, data_residency=False)
    db.add_org(OTHER_ORG_ID, data_residency=False)
    db.add_platform_settings(
        llm_provider="anthropic",
        anthropic_model="claude-sonnet-4-6",
        openai_model="gpt-4o",
        **{**_STORED_LIMITS, **limits},
    )
    monkeypatch.setattr("admino.database.get_pool", lambda: db.pool)
    monkeypatch.setattr(scoped_settings, "_platform_cache", None)
    return db


def _app() -> FastAPI:
    agent = MagicMock(name="agent")
    agent._llm = MagicMock(name="llm-client")
    agent._llm.close = AsyncMock()
    return create_app(agent=agent, config=_config())


def _super_admin(db: FakeDb) -> str:
    """A Super Admin with a live session: the session token."""
    return db.open_session(db.add_account(kind="super_admin", role=None))


def _request(app: FastAPI, method: str, token: str, body: Any = None) -> httpx.Response:
    client = TestClient(app, client=(_IP, 50000), follow_redirects=False)
    kwargs: dict[str, Any] = {} if body is None else {"json": body}
    return client.request(method, _PLATFORM, headers={"Cookie": f"{_COOKIE}={token}"}, **kwargs)


def _stored_value(db: FakeDb) -> Any:
    row = db.platform_row()
    assert row is not None
    return row[_FIELD]


def _settings_changes(db: FakeDb) -> list[dict[str, Any]]:
    """The metadata of every platform.settings_change audit row, in order."""
    return [row["metadata"] for row in db.audit if row["action"] == "platform.settings_change"]


def _stored_platform(*, max_context_messages: int) -> Any:
    """A StoredPlatformSettings: Anthropic, max_input_tokens 64000, the stored limits with
    this max_context_messages."""
    return scoped_settings.StoredPlatformSettings.model_validate(
        {
            "llm": {
                "provider": "anthropic",
                "infomaniak_model": None,
                "vllm_model": None,
                "anthropic_model": "claude-sonnet-4-6",
                "openai_model": None,
                "max_input_tokens": _PLATFORM_INPUT_TOKENS,
            },
            "limits": {**_STORED_LIMITS, _FIELD: max_context_messages},
        }
    )


# ---------------------------------------------------------------------------
# 1. GET / PATCH /api/platform/settings (Decision 8)
# ---------------------------------------------------------------------------


def test_context_settings_api_get_shows_a_stored_0(monkeypatch: pytest.MonkeyPatch) -> None:
    """A row holding 0 (no cap) is shown as 0, an int."""
    db = _world(monkeypatch, max_context_messages=0)
    app = _app()

    response = _request(app, "GET", _super_admin(db))

    assert response.status_code == 200, response.text
    value = response.json()["limits"][_FIELD]
    assert (value, type(value)) == (0, int)


def test_context_settings_api_patch_takes_0_to_200_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """-1, 201, a bool and a numeric string are a 422 with nothing written; 0 and 200 are
    stored and returned. (status, the value returned, the value stored) per patch, in
    this order on one row."""
    db = _world(monkeypatch)
    app = _app()
    token = _super_admin(db)
    outcomes: dict[str, tuple[int, Any, Any]] = {}

    for name, value in (("-1", -1), ("201", 201), ("true", True), ("'0'", "0"), ("0", 0)):
        response = _request(app, "PATCH", token, {"limits": {_FIELD: value}})
        returned = response.json()["limits"][_FIELD] if response.status_code == 200 else None
        outcomes[name] = (response.status_code, returned, _stored_value(db))
    response = _request(app, "PATCH", token, {"limits": {_FIELD: 200}})
    returned = response.json()["limits"][_FIELD] if response.status_code == 200 else None
    outcomes["200"] = (response.status_code, returned, _stored_value(db))

    assert outcomes == {
        "-1": (422, None, 30),
        "201": (422, None, 30),
        "true": (422, None, 30),
        "'0'": (422, None, 30),
        "0": (200, 0, 0),
        "200": (200, 200, 200),
    }


def test_context_settings_api_patch_to_0_records_the_old_and_new_ints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One platform.settings_change event: max_context_messages_old 30, _new 0, ints."""
    db = _world(monkeypatch)
    app = _app()

    response = _request(app, "PATCH", _super_admin(db), {"limits": {_FIELD: 0}})

    assert response.status_code == 200, response.text
    changes = _settings_changes(db)
    assert changes == [{f"{_FIELD}_old": 30, f"{_FIELD}_new": 0}]
    assert [type(value) for value in changes[0].values()] == [int, int]


# ---------------------------------------------------------------------------
# 2. The startup seed (Decision 8: the config default is 0, a stored value stays)
# ---------------------------------------------------------------------------


async def test_context_settings_api_seed_first_boot_stores_the_config_0() -> None:
    """An empty platform_settings table gets config.yaml's 0."""
    db = FakeDb()
    config = _config(limits={_FIELD: 0})

    await scoped_settings.seed_platform_settings(db.pool, config)

    assert _stored_value(db) == 0


async def test_context_settings_api_seed_later_boot_keeps_the_stored_value() -> None:
    """An install that stored 20 keeps it when config.yaml now says 0."""
    db = FakeDb()
    db.add_platform_settings(**{**_STORED_LIMITS, _FIELD: 20})
    config = _config(limits={_FIELD: 0})

    await scoped_settings.seed_platform_settings(db.pool, config)

    assert _stored_value(db) == 20


# ---------------------------------------------------------------------------
# 3. The run's AgentConfig (contract C11 "Run config")
# ---------------------------------------------------------------------------


def test_context_settings_api_run_config_passes_a_stored_0_as_no_cap() -> None:
    """The stored 0 reaches the run as max_context_messages 0 (the budget alone decides)."""
    _app()

    run_config = server._run_config(_stored_platform(max_context_messages=0))

    assert run_config.max_context_messages == 0


def test_context_settings_api_run_config_takes_the_budget_settings() -> None:
    """max_input_tokens from the stored platform llm; the reserved output, the margin and
    the tool-result cap from the config."""
    _app()

    run_config = server._run_config(_stored_platform(max_context_messages=30))

    assert {
        name: getattr(run_config, name, None)
        for name in (
            "max_context_messages",
            "max_input_tokens",
            "reserved_output_tokens",
            "context_margin_percent",
            "max_tool_result_tokens",
        )
    } == {
        "max_context_messages": 30,
        "max_input_tokens": _PLATFORM_INPUT_TOKENS,
        "reserved_output_tokens": _RESPONSE_TOKENS,
        "context_margin_percent": _MARGIN_PERCENT,
        "max_tool_result_tokens": _TOOL_RESULT_TOKENS,
    }


# ---------------------------------------------------------------------------
# 4. The processing pool's budget (contract C7)
# ---------------------------------------------------------------------------


async def test_context_settings_api_processing_jobs_get_the_config_budget(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """create_app's pool passes BudgetSettings.from_config(config) to every job: the
    reserved output, margin, byte cap (MiB) and tool-result cap of the config."""
    from admino.context_budget import BudgetSettings

    jobs: list[dict[str, Any]] = []

    async def record(
        pool: Any, root: Any, attachment_id: uuid.UUID, org_id: uuid.UUID, **kwargs: Any
    ) -> None:
        jobs.append({"attachment_id": attachment_id, **kwargs})

    monkeypatch.setattr(attachment_processing, "process_attachment", record)
    _app()
    attachment_id = uuid.uuid4()

    server._processing.submit(MagicMock(name="pool"), tmp_path, attachment_id, ORG_ID)
    await server._processing.join()

    assert [(job["attachment_id"], job.get("budget")) for job in jobs] == [
        (
            attachment_id,
            BudgetSettings(
                reserved_output_tokens=_RESPONSE_TOKENS,
                safety_margin_percent=_MARGIN_PERCENT,
                max_turn_bytes=_TURN_MB * _MIB,
                max_tool_result_tokens=_TOOL_RESULT_TOKENS,
            ),
        )
    ]
