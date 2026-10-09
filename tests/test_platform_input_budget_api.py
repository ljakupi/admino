"""``PATCH /api/platform/settings`` refuses a ``llm.max_input_tokens`` the reserved output
and the safety margin don't fit (GH-294, issue Decisions 1, 3 and 11).

The FastAPI app from ``create_app()`` runs against the in-memory database of
tests/db_fakes.py (what ``admino.database.get_pool`` returns) with a real
``AppConfig``. The real ``require_session``, ``admino.scoped_settings`` and
``admino.audit_events`` code runs; the LLM client factory and the two provider probes
are mocks, so no network call is ever made.

What these tests pin down:
- Decision 1: a model fits when the reserved output (``llm.max_response_tokens``) is
  below ``budget_limit(max_input_tokens, context.safety_margin_percent)``, that is
  ``max_input_tokens - ceil(max_input_tokens * margin / 100)``: at least one input
  token is left. With the defaults (4096 reserved, 10 % margin) 4553 fits, 4552 (a
  budget equal to the reserve) and 4551 don't. With 1000 reserved and a 20 % margin
  1252 fits and 1251 doesn't (where a rounded-down margin would still fit).
- Decision 3: such a patch is ``422 {"detail": "The model's max input tokens leave no
  room for the reserved output and the safety margin", "reason":
  "max_input_tokens_too_small"}``, checked after the rate limit and the capability
  check and before any database statement: nothing written or audited, no LLM client
  built, the residency confirmation not consulted (a non-Swiss switch in the same
  patch is the 422, not the 409), the settings cache untouched. A member gets 403 and
  a caller over the rate limit 429 first. A patch without ``llm.max_input_tokens``
  (``null`` included) isn't checked, even while the stored value wouldn't fit; one
  that gives it is checked even when it equals the stored value.
- The route's OpenAPI 422 names the usual validation list and the code, with the body
  as an ``examples`` entry.
- Decision 11: ``docs/configuration.md`` names the code in its platform defaults or
  context budget section.

All database calls are faked. No network, no real PostgreSQL, no LLM.

Security notes:
- The refusal body is fixed text and a code: never a value of the request or the
  config.
- The check reads the running config only, so a refused patch can't reach the
  database, the audit log or a provider.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from admino import organizations, scoped_settings, server
from admino.config import AppConfig
from admino.server import create_app
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, PUBLIC_URL, FakeDb

if TYPE_CHECKING:
    import httpx
    from fastapi import FastAPI

_COOKIE: Final = "admino_session"
_IP: Final = "203.0.113.94"
_PLATFORM: Final = "/api/platform/settings"
_PATCH_RATE_KEY: Final = "/api/platform/settings/patch"
_RATE_KEYS: Final = ("/api/platform/settings/get", _PATCH_RATE_KEY)
_TOO_SMALL: Final = {
    "detail": (
        "The model's max input tokens leave no room for the reserved output and the safety margin"
    ),
    "reason": "max_input_tokens_too_small",
}
_FORBIDDEN: Final = {"detail": "Forbidden"}
_RATE_LIMITED: Final = {"detail": "Rate limit exceeded"}
# The stored row's max_input_tokens: none of the values patched below.
_STORED_INPUT: Final = 64000
# (max_response_tokens, safety_margin_percent) -> the values patched, refused ones first,
# and the smallest that fits (patched last, so the refusals all meet the stored row).
_PAIRS: Final[dict[str, tuple[int | None, int | None, tuple[int, ...], int]]] = {
    # The defaults: budget(4553) = 4553 - 456 = 4097 > 4096; budget(4552) = 4096.
    "default-4096-10": (None, None, (4552, 4551), 4553),
    # budget(1252) = 1252 - 251 = 1001 > 1000; budget(1251) = 1251 - 251 = 1000 (a
    # rounded-down margin, 250, would leave 1001 and wrongly fit).
    "reserve-1000-margin-20": (1000, 20, (1251, 1250), 1252),
}
_TABLE_RE: Final = re.compile(r"\b(?:from|join|into|update)\s+([a-z_]+)")


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _config(*, response_tokens: int | None = None, margin: int | None = None) -> AppConfig:
    """A real config: Infomaniak (Swiss), every model set; the reserved output and the
    margin given (the defaults otherwise)."""
    llm: dict[str, Any] = {
        "provider": "infomaniak",
        "infomaniak_model": "Qwen/Qwen3.5-397B-A17B-FP8",
        "vllm_model": "Qwen/Qwen3-4B-Instruct-2507",
        "anthropic_model": "claude-sonnet-4-6",
        "openai_model": "gpt-4o",
    }
    if response_tokens is not None:
        llm["max_response_tokens"] = response_tokens
    data: dict[str, Any] = {
        "server": {"host": "127.0.0.1", "port": 8000, "public_url": PUBLIC_URL},
        "llm": llm,
    }
    if margin is not None:
        data["context"] = {"safety_margin_percent": margin}
    return AppConfig.model_validate(data)


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
    for key in _RATE_KEYS:
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))
    return factory


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch, create_client: MagicMock) -> FakeDb:
    """Two orgs without data residency, the platform row (Infomaniak, every model set,
    ``max_input_tokens`` ``_STORED_INPUT``), the database get_pool() returns; the
    settings cache holds that row."""
    fake = FakeDb()
    fake.add_org(ORG_ID, data_residency=False)
    fake.add_org(OTHER_ORG_ID, data_residency=False)
    fake.add_platform_settings(
        llm_provider="infomaniak",
        infomaniak_model="Qwen/Qwen3.5-397B-A17B-FP8",
        vllm_model="Qwen/Qwen3-4B-Instruct-2507",
        anthropic_model="claude-sonnet-4-6",
        openai_model="gpt-4o",
        max_input_tokens=_STORED_INPUT,
    )
    monkeypatch.setattr("admino.database.get_pool", lambda: fake.pool)
    monkeypatch.setattr(scoped_settings, "_platform_cache", None)
    return fake


def _app(config: AppConfig | None = None) -> FastAPI:
    agent = MagicMock(name="agent")
    agent._llm = MagicMock(name="llm-client")
    agent._llm.provider = "infomaniak"
    agent._llm.close = AsyncMock()
    return create_app(agent=agent, config=config or _config())


def _client(app: FastAPI) -> TestClient:
    return TestClient(app, client=(_IP, 50000), follow_redirects=False)


def _super_admin(db: FakeDb) -> str:
    """A Super Admin with a live session: the session token."""
    return db.open_session(db.add_account(kind="super_admin", role=None))


def _member(db: FakeDb, role: str) -> str:
    """A member of ORG_ID with ``role`` and a live session: the session token."""
    return db.open_session(db.add_account(role=role, org_id=ORG_ID))


def _patch(client: TestClient, token: str, body: Any) -> httpx.Response:
    response: httpx.Response = client.patch(
        _PLATFORM, headers={"Cookie": f"{_COOKIE}={token}"}, json=body
    )
    return response


def _get(client: TestClient, token: str) -> httpx.Response:
    response: httpx.Response = client.get(_PLATFORM, headers={"Cookie": f"{_COOKIE}={token}"})
    return response


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


def _tables(sql: str) -> set[str]:
    """The tables a normalized statement names after FROM, JOIN, INTO or UPDATE."""
    return set(_TABLE_RE.findall(sql))


def _outcome(response: httpx.Response) -> tuple[int, Any]:
    """(status, the refusal body, or the returned llm.max_input_tokens on a 200)."""
    if response.status_code == 200:
        return 200, response.json()["llm"]["max_input_tokens"]
    return response.status_code, response.json()


# ---------------------------------------------------------------------------
# 1. The fit rule at its boundary (Decisions 1 and 3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pair", list(_PAIRS))
def test_platform_input_budget_patch_refuses_a_budget_at_or_below_the_reserve(
    db: FakeDb, pair: str
) -> None:
    """Each value whose budget equals the reserve or lies below it is the 422 with the
    exact body and the platform row and audit log unchanged; the smallest value with a
    budget above the reserve is stored and returned. (status, body or value, the
    stored max_input_tokens, the audit rows added) per patch, in order on one row."""
    response_tokens, margin, refused, fits = _PAIRS[pair]
    client = _client(_app(_config(response_tokens=response_tokens, margin=margin)))
    token = _super_admin(db)
    outcomes: dict[int, tuple[Any, ...]] = {}

    for value in (*refused, fits):
        audit_before = len(db.audit)
        response = _patch(client, token, {"llm": {"max_input_tokens": value}})
        outcomes[value] = (
            *_outcome(response),
            _row(db)["max_input_tokens"],
            len(db.audit) - audit_before,
        )

    assert outcomes == {
        **dict.fromkeys(refused, (422, _TOO_SMALL, _STORED_INPUT, 0)),
        fits: (200, fits, fits, 1),
    }


# ---------------------------------------------------------------------------
# 2. Before anything else (Decision 3)
# ---------------------------------------------------------------------------


def test_platform_input_budget_refusal_runs_no_statement_builds_no_client_and_skips_residency(
    db: FakeDb, create_client: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A patch that also switches to a non-Swiss provider without the residency
    confirmation (alone it is the 409) and changes the model: the 422, with no statement
    but the session lookup (every one names ``sessions``), the residency count never
    taken, no client built, the tables and the settings cache (the same object)
    unchanged."""
    app = _app()
    client = _client(app)
    token = _super_admin(db)
    primed = _get(client, token)
    assert primed.status_code == 200, primed.text
    cache = scoped_settings._platform_cache
    counted = AsyncMock(name="count_residency_orgs", return_value=0)
    monkeypatch.setattr(organizations, "count_residency_orgs", counted)
    before = _state(db)
    since = len(db.calls)

    response = _patch(
        client,
        token,
        {"llm": {"provider": "openai", "openai_model": "gpt-4.1", "max_input_tokens": 4552}},
    )

    statements = [call.normalized for call in db.calls[since:]]
    assert (response.status_code, response.json()) == (422, _TOO_SMALL)
    assert [sql for sql in statements if "sessions" not in _tables(sql)] == []
    assert (counted.await_count, create_client.call_count) == (0, 0)
    assert _state(db) == before
    assert scoped_settings._platform_cache is cache


@pytest.mark.parametrize("role", ["org_admin", "editor", "viewer"])
def test_platform_input_budget_member_gets_403_where_the_super_admin_gets_422(
    db: FakeDb, role: str
) -> None:
    """The capability check comes first: a member's too-small patch is the 403 with
    nothing written, the Super Admin's same patch the 422."""
    client = _client(_app())
    body = {"llm": {"max_input_tokens": 4552}}
    member_token, admin_token = _member(db, role), _super_admin(db)
    before = _state(db)

    member = _patch(client, member_token, body)
    after_member = _state(db)
    admin = _patch(client, admin_token, body)

    assert (member.status_code, member.json(), after_member == before) == (
        403,
        _FORBIDDEN,
        True,
    )
    assert (admin.status_code, admin.json()) == (422, _TOO_SMALL)


def test_platform_input_budget_rate_limit_counts_refused_patches_first(
    db: FakeDb, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rate limit comes first: with a burst of 2, two too-small patches are each the
    422 (and spend the bucket), the third is the 429."""
    monkeypatch.setitem(server._RATE_LIMITS, _PATCH_RATE_KEY, (0.001, 2))
    client = _client(_app())
    token = _super_admin(db)

    responses = [_patch(client, token, {"llm": {"max_input_tokens": 4552}}) for _ in range(3)]

    assert [(r.status_code, r.json()) for r in responses] == [
        (422, _TOO_SMALL),
        (422, _TOO_SMALL),
        (429, _RATE_LIMITED),
    ]


# ---------------------------------------------------------------------------
# 3. Only a given llm.max_input_tokens is checked (Decision 3)
# ---------------------------------------------------------------------------


def test_platform_input_budget_patch_without_the_value_is_not_checked(db: FakeDb) -> None:
    """The stored value (4552) wouldn't fit the running config. Patches that don't give
    ``llm.max_input_tokens`` (``null`` is "not given") are answered as before: an
    ``image_input`` change, a limits change, a Swiss provider switch. A patch that
    gives the stored value itself is still the 422."""
    _row(db)["max_input_tokens"] = 4552
    client = _client(_app())
    token = _super_admin(db)
    bodies: dict[str, dict[str, Any]] = {
        "image-input": {"llm": {"image_input": False}},
        "null-value": {"llm": {"max_input_tokens": None, "max_retries": 4}},
        "limits": {"limits": {"max_tool_calls_per_message": 7}},
        "swiss-switch": {"llm": {"provider": "vllm"}},
        "stored-value": {"llm": {"max_input_tokens": 4552}},
    }

    outcomes = {name: _outcome(_patch(client, token, body)) for name, body in bodies.items()}

    assert outcomes == {
        "image-input": (200, 4552),
        "null-value": (200, 4552),
        "limits": (200, 4552),
        "swiss-switch": (200, 4552),
        "stored-value": (422, _TOO_SMALL),
    }


# ---------------------------------------------------------------------------
# 4. The contract: OpenAPI (Decision 3) and the docs (Decision 11)
# ---------------------------------------------------------------------------


def test_platform_input_budget_openapi_documents_the_422(db: FakeDb) -> None:
    """The PATCH route's 422 names the validation list and ``max_input_tokens_too_small``
    in its description, and shows the body as an ``examples`` entry (no ``example``
    beside it)."""
    responses = _app().openapi()["paths"][_PLATFORM]["patch"]["responses"]
    documented = responses.get("422", {})
    description = documented.get("description", "")
    content = documented.get("content", {}).get("application/json", {})
    examples = [entry.get("value") for entry in content.get("examples", {}).values()]

    assert (
        "validation" in description.lower(),
        "max_input_tokens_too_small" in description,
        _TOO_SMALL in examples,
        "example" in content,
    ) == (True, True, True, False)


def test_platform_input_budget_docs_name_the_code() -> None:
    """``docs/configuration.md``'s "Platform defaults" section (up to the next heading)
    or its "Context budget" section (up to the next ``## ``) names
    ``max_input_tokens_too_small``."""
    text = (Path(__file__).resolve().parents[1] / "docs" / "configuration.md").read_text(
        encoding="utf-8"
    )
    platform_start = text.index("\n### Platform defaults\n")
    platform_end = text.find("\n#", platform_start + 1)
    budget_start = text.index("\n### Context budget\n")
    budget_end = text.find("\n## ", budget_start + 1)
    sections = (text[platform_start:platform_end], text[budget_start:budget_end])

    assert [s for s in sections if "max_input_tokens_too_small" in s] != []
