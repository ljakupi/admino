"""The platform LLM ``PATCH`` refuses a merged ``LLMConfig`` without echoing input (GH-304).

Issue #304, criterion 4 (Decision 4, contract C5; #302 security audit I-1): when the
Super Admin's ``PATCH /api/platform/settings`` merges the ``llm`` patch over the stored
LLM and the config's other llm fields and ``LLMConfig`` refuses the result, the answer
stays ``400 {"detail": [{"loc", "msg", "type"}, ...]}``, but each entry is built by the
same per-error mapping as the two 422 handlers (contract C2) instead of passing
pydantic's ``msg`` through.

What is pinned, as a Super Admin with ``{"llm": {"image_input": false}}`` (the
provider unchanged and Swiss, so no residency confirmation and no client to build),
for each kind of error:
- the real ``LLMConfig.validate_model_name`` over a stored model name it refuses
  (its plain ``ValueError`` stays a ``ValueError``, Decision 2): ``"Invalid value"``;
- a plain ``ValueError`` whose pydantic ``msg`` quotes the input: ``"Invalid value"``;
- a library's ``PydanticCustomError`` of type ``value_error`` quoting the input (an
  email validator's kind): ``"Invalid value"``;
- a built-in type (``uuid_parsing``, whose pydantic ``msg`` quotes the offending
  character): its GH-302 table text, ``"Input should be a valid UUID"``;
- a custom type outside the table: the fallback ``"Invalid input"``;
- a ``FixedMessageError`` (``admino.models``, GH-304) raised by a validator: its own
  text; an empty one: ``"Invalid value"``;
- several errors at once: pydantic's order, each entry mapped on its own.
In every case the body is ``{"detail": [...]}`` with the keys ``loc``, ``msg`` and
``type`` in that order, no character of the input in the body or in an app log record,
nothing written (tables and audit log), no LLM client built, the running client kept
(not closed) and the live config unchanged.

How the refusal is reached: ``SettingsPatchLLM`` already refuses every bad value of the
patch, and the database CHECKs of migration 0013 (which the fake applies when the row is
seeded) refuse every bad stored model name, so the merged config fails only on a
corrupt stored row or a stricter ``LLMConfig``. The tests seed a valid row and then
corrupt its ``openai_model`` in place (a value the CHECK would refuse, holding the
canary) and, except for the real-validator cases, replace ``LLMConfig`` with a subclass
whose extra validator or field type produces the error. The handler looks the class up
at call time, so the subclass is set on ``admino.config`` and on ``admino.server``.

The new name (``admino.models.FixedMessageError``) is imported inside the tests, so the
file collects before GH-304 is implemented. The canary is three Greek capital letters
(built with ``chr``): none of them occurs in a table text, a ``loc`` or a ``type``.

All database calls are faked; the LLM client factory and the provider probes are mocks.
No network, no real PostgreSQL, no LLM.

Security notes: the refusal names fields and fixed texts only, never a stored or patched
value (operator blindness: a Super Admin route returns no content).
"""

from __future__ import annotations

import copy
import json
import uuid
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel, create_model, field_validator
from pydantic_core import PydanticCustomError

import admino.config
from admino import scoped_settings, server
from admino.config import AppConfig, LLMConfig
from admino.server import create_app
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, PUBLIC_URL, FakeDb

if TYPE_CHECKING:
    from collections.abc import Callable

    import httpx
    from fastapi import FastAPI

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE: Final = "admino_session"
_IP: Final = "203.0.113.104"
_PLATFORM: Final = "/api/platform/settings"
_RATE_KEYS: Final = ("/api/platform/settings/get", "/api/platform/settings/patch")
# Keeps the stored (Swiss) provider: no residency confirmation, no client to build.
_PATCH: Final = {"llm": {"image_input": False}}

# Greek capital Omega, Psi and Phi: in no table text, loc or type.
_CANARY: Final = chr(0x3A9) + chr(0x3A8) + chr(0x3A6)
_CANARY_CHARS: Final = frozenset(_CANARY)
# A stored model name the database CHECK and LLMConfig's validator refuse.
_CORRUPT_NAME: Final = f"{_CANARY}-model"

# Contract C2's texts (GH-302's table and fallback), spelled out here.
_INVALID_VALUE: Final = "Invalid value"
_INVALID_UUID: Final = "Input should be a valid UUID"
_FALLBACK: Final = "Invalid input"
# A fixed message a FixedMessageError probe raises (no character of the input).
_FIXED_TEXT: Final = "The model is retired."
_UNKNOWN_TYPE: Final = "admino_probe_unknown"


# ---------------------------------------------------------------------------
# LLMConfig stand-ins (built inside the tests, after collection)
# ---------------------------------------------------------------------------


def _plain_value_error() -> type[BaseModel]:
    """A validator raising a plain ValueError that quotes its input."""

    class _Probe(LLMConfig):
        @field_validator("openai_model", mode="before")
        @classmethod
        def _refuse(cls, value: Any) -> Any:
            msg = f"Unknown model {value!r}"
            raise ValueError(msg)

    return _Probe


def _library_value_error() -> type[BaseModel]:
    """A library validator's ``value_error`` (a PydanticCustomError) quoting its input."""

    class _Probe(LLMConfig):
        @field_validator("openai_model", mode="before")
        @classmethod
        def _refuse(cls, value: Any) -> Any:
            raise PydanticCustomError(
                "value_error",
                "value is not a valid model name: {reason}",
                {"reason": f"{value} is unknown"},
            )

    return _Probe


def _uuid_typed(field: str) -> type[BaseModel]:
    """LLMConfig with ``field`` typed as an optional UUID (built at runtime)."""
    probe: type[BaseModel] = create_model(
        "_UuidProbe", __base__=LLMConfig, **{field: (uuid.UUID | None, None)}
    )
    return probe


def _builtin_uuid() -> type[BaseModel]:
    """``openai_model`` typed as a UUID: the corrupt name is a ``uuid_parsing`` error."""
    return _uuid_typed("openai_model")


def _unknown_type() -> type[BaseModel]:
    """A custom error type outside the table, whose message is the input."""

    class _Probe(LLMConfig):
        @field_validator("openai_model", mode="before")
        @classmethod
        def _refuse(cls, value: Any) -> Any:
            raise PydanticCustomError(_UNKNOWN_TYPE, "{x}", {"x": value})

    return _Probe


def _fixed_message(text: str) -> Callable[[], type[BaseModel]]:
    """A validator raising ``admino.models.FixedMessageError(text)``."""

    def build() -> type[BaseModel]:
        from admino.models import FixedMessageError

        class _Probe(LLMConfig):
            @field_validator("openai_model", mode="before")
            @classmethod
            def _refuse(cls, value: Any) -> Any:
                raise FixedMessageError(text)

        return _Probe

    return build


def _mixed() -> type[BaseModel]:
    """Three errors in field order: ``vllm_model`` typed as a UUID (``uuid_parsing``),
    the real validator over ``anthropic_model`` (``value_error``) and a
    FixedMessageError on ``openai_model``."""
    from admino.models import FixedMessageError

    class _Probe(_uuid_typed("vllm_model")):  # type: ignore[misc]
        @field_validator("openai_model", mode="before")
        @classmethod
        def _refuse(cls, value: Any) -> Any:
            raise FixedMessageError(_FIXED_TEXT)

    return _Probe


def _entry(loc: list[str], msg: str, error_type: str) -> list[tuple[str, Any]]:
    """One expected detail entry as its (key, value) pairs, in order."""
    return [("loc", loc), ("msg", msg), ("type", error_type)]


# (LLMConfig stand-in or None for the real class, the expected detail list)
_CASES: Final[dict[str, tuple[Callable[[], type[BaseModel]] | None, list[Any]]]] = {
    "real-validator-corrupt-stored-name": (
        None,
        [_entry(["openai_model"], _INVALID_VALUE, "value_error")],
    ),
    "plain-value-error-quoting-input": (
        _plain_value_error,
        [_entry(["openai_model"], _INVALID_VALUE, "value_error")],
    ),
    "library-value-error-quoting-input": (
        _library_value_error,
        [_entry(["openai_model"], _INVALID_VALUE, "value_error")],
    ),
    "builtin-uuid-parsing": (
        _builtin_uuid,
        [_entry(["openai_model"], _INVALID_UUID, "uuid_parsing")],
    ),
    "unknown-custom-type": (
        _unknown_type,
        [_entry(["openai_model"], _FALLBACK, _UNKNOWN_TYPE)],
    ),
    "fixed-message-error": (
        _fixed_message(_FIXED_TEXT),
        [_entry(["openai_model"], _FIXED_TEXT, "value_error")],
    ),
    "empty-fixed-message-error": (
        _fixed_message(""),
        [_entry(["openai_model"], _INVALID_VALUE, "value_error")],
    ),
}

# What every refusal leaves behind: nothing but the 400 itself.
_UNTOUCHED: Final[dict[str, Any]] = {
    "status": 400,
    "body_keys": ["detail"],
    "canary_in_body": [],
    "canary_in_logs": [],
    "written": False,
    "clients_built": 0,
    "live_client_swapped": False,
    "live_client_closes": 0,
    "live_config_changed": False,
}


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _config() -> AppConfig:
    """A real config: Infomaniak (Swiss), every model set."""
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
def create_client(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """No network: both provider probes and the LLM client factory are mocks (the factory
    is returned); the platform routes get large rate-limit buckets."""
    monkeypatch.setattr(server, "_get_vllm_available_models", AsyncMock(return_value=[]))
    monkeypatch.setattr(server, "_get_infomaniak_available_models", AsyncMock(return_value=[]))
    new_client = MagicMock(name="new-llm-client")
    new_client.close = AsyncMock()
    factory = MagicMock(name="create_llm_client", return_value=new_client)
    monkeypatch.setattr("admino.llm.create_llm_client", factory)
    monkeypatch.setattr(server, "create_llm_client", factory, raising=False)
    for key in _RATE_KEYS:
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))
    return factory


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch, create_client: MagicMock) -> FakeDb:
    """Two orgs without data residency and a valid platform row (Infomaniak, every model
    set) whose ``openai_model`` is then corrupted to ``_CORRUPT_NAME`` in place (past the
    CHECK the fake applies on seeding); get_pool() returns this database and the
    settings cache is empty."""
    fake = FakeDb()
    fake.add_org(ORG_ID, data_residency=False)
    fake.add_org(OTHER_ORG_ID, data_residency=False)
    fake.add_platform_settings(
        llm_provider="infomaniak",
        infomaniak_model="Qwen/Qwen3.5-397B-A17B-FP8",
        vllm_model="Qwen/Qwen3-4B-Instruct-2507",
        anthropic_model="claude-sonnet-4-6",
        openai_model="gpt-4o",
    )
    row = fake.platform_row()
    assert row is not None
    row["openai_model"] = _CORRUPT_NAME
    monkeypatch.setattr("admino.database.get_pool", lambda: fake.pool)
    monkeypatch.setattr(scoped_settings, "_platform_cache", None)
    return fake


@pytest.fixture()
def agent() -> MagicMock:
    """A stub agent with its running (closable) LLM client."""
    stub = MagicMock(name="agent")
    stub._llm = MagicMock(name="running-llm-client")
    stub._llm.close = AsyncMock()
    return stub


@pytest.fixture()
def app(agent: MagicMock) -> FastAPI:
    """create_app with the stub agent and the real config (no lifespan under TestClient)."""
    return create_app(agent=agent, config=_config())  # type: ignore[arg-type]


def _use_llm_config(monkeypatch: pytest.MonkeyPatch, build: Callable[[], type[BaseModel]]) -> None:
    """Replace LLMConfig where the handler may look it up at call time."""
    probe = build()
    monkeypatch.setattr(admino.config, "LLMConfig", probe)
    monkeypatch.setattr(server, "LLMConfig", probe, raising=False)


def _super_admin(db: FakeDb) -> str:
    """A Super Admin with a live session: the session token."""
    return db.open_session(db.add_account(kind="super_admin", role=None))


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


def _app_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured app record in full (message, args and extras), without the test
    client's own httpx request lines."""
    return "\n".join(
        f"{record.getMessage()} {vars(record)!r}"
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore"))
    )


def _refuse(
    app: FastAPI,
    db: FakeDb,
    agent: MagicMock,
    create_client: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> dict[str, Any]:
    """PATCH ``_PATCH`` as a Super Admin; return what the request answered and left."""
    token = _super_admin(db)
    running = agent._llm
    assert server._config is not None
    config_before = server._config.model_dump()
    state_before = _state(db)
    caplog.set_level("DEBUG")

    response: httpx.Response = TestClient(app, client=(_IP, 50000), follow_redirects=False).patch(
        _PLATFORM, headers={"Cookie": f"{_COOKIE}={token}"}, json=_PATCH
    )

    body = response.json()
    detail = body.get("detail") if isinstance(body, dict) else None
    return {
        "status": response.status_code,
        "body_keys": list(body) if isinstance(body, dict) else body,
        "detail": (
            [list(entry.items()) if isinstance(entry, dict) else entry for entry in detail]
            if isinstance(detail, list)
            else detail
        ),
        "canary_in_body": sorted(set(json.dumps(body, ensure_ascii=False)) & _CANARY_CHARS),
        "canary_in_logs": sorted(set(_app_log_text(caplog)) & _CANARY_CHARS),
        "written": _state(db) != state_before,
        "clients_built": create_client.call_count,
        "live_client_swapped": agent._llm is not running,
        "live_client_closes": running.close.await_count,
        "live_config_changed": server._config.model_dump() != config_before,
    }


# ---------------------------------------------------------------------------
# Criterion 4: the 400's list comes from the shared mapping (Decision 4, C5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", list(_CASES))
def test_platform_llm_patch_errors_merged_config_refusal_maps_each_error_without_input(
    case: str,
    app: FastAPI,
    db: FakeDb,
    agent: MagicMock,
    create_client: MagicMock,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 400 of a merged config ``LLMConfig`` refuses: each entry's ``msg`` is the
    mapping's text for the error (never pydantic's), keys ``loc``, ``msg``, ``type`` in
    order, no canary character in the body or a log record, and nothing written, built,
    swapped or changed."""
    build, expected = _CASES[case]
    if build is not None:
        _use_llm_config(monkeypatch, build)

    outcome = _refuse(app, db, agent, create_client, caplog)

    assert outcome == {**_UNTOUCHED, "detail": expected}


def test_platform_llm_patch_errors_several_errors_keep_their_order_each_mapped(
    app: FastAPI,
    db: FakeDb,
    agent: MagicMock,
    create_client: MagicMock,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Three stored model names refused at once (``vllm_model`` as a UUID, the real
    validator over ``anthropic_model``, a FixedMessageError on ``openai_model``): one
    entry each, in pydantic's (field) order, each mapped on its own: the table text, the
    "Invalid value" of a plain ValueError and the fixed message."""
    row = db.platform_row()
    assert row is not None
    row["vllm_model"] = _CORRUPT_NAME
    row["anthropic_model"] = _CORRUPT_NAME
    _use_llm_config(monkeypatch, _mixed)

    outcome = _refuse(app, db, agent, create_client, caplog)

    assert outcome == {
        **_UNTOUCHED,
        "detail": [
            _entry(["vllm_model"], _INVALID_UUID, "uuid_parsing"),
            _entry(["anthropic_model"], _INVALID_VALUE, "value_error"),
            _entry(["openai_model"], _FIXED_TEXT, "value_error"),
        ],
    }
