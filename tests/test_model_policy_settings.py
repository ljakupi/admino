"""Tests for the V1 model policy settings, config and models (GH-242).

GH-242 gives the platform model two capabilities (its input window and whether
it takes images) and a retry limit, makes data residency part of a run's tool
policy, and gives every failed chat reply a stable error code. This module pins
the settings, config and model side of that contract (the migration lives in
tests/test_migration_0022.py, the LLM error catalogue, the policy module, the
agent and the routes in their own modules).

What these tests pin down:
- ``config.LLMConfig``: ``max_input_tokens`` (default 200000, 1000 to 2000000)
  and ``image_input`` (default True). The shipped config/config.yaml sets
  ``max_input_tokens: 200000`` and ``image_input: true`` in its llm section,
  with a comment.
- ``models.SettingsLLM`` (what GET/PATCH /api/platform/settings shows) gains
  ``max_input_tokens`` (200000, 1000 to 2000000), ``image_input`` (True),
  ``max_retries`` (2, 0 to 5) and ``residency_orgs`` (0, never negative: the
  number of organizations whose data residency is on).
- ``models.SettingsPatchLLM`` gains optional, strict ``max_input_tokens``
  (int 1000 to 2000000; a bool, float, numeric string or Decimal refused),
  ``image_input`` (strict bool: 1, 0, "true" refused) and ``max_retries`` (int
  0 to 5, strict like the other patch ints). Errors never repeat the input.
- ``models.PlatformSettingsPatch`` gains the top-level
  ``confirm_residency_orgs`` (strict int 0 to 1000000, default None). It is not
  a setting: a patch that gives only it is still "nothing to change".
- ``scoped_settings.StoredPlatformLLM`` gains ``max_input_tokens`` (200000,
  1000 to 2000000), ``image_input`` (True) and ``max_retries`` (2, 0 to 5;
  the column ``llm_max_retries``).
- ``models.AgentConfig.llm_max_retries`` (default 0, 0 to 5),
  ``models.ToolPolicy.data_residency`` (default False),
  ``models.AgentResult.error_code`` and ``models.ChatResponse.error_code``
  (default None, one of the seven codes, anything else refused);
  ``models.LLM_ERROR_CODES`` and ``models.LLMErrorCode`` are exactly the
  seven codes.
- ``scoped_settings`` against the FakeDb (which knows migration 0022's
  columns): ``seed_platform_settings`` stores config.yaml's
  ``max_input_tokens`` / ``image_input`` on the first boot and re-applies them
  on every later boot, never writing ``llm_max_retries`` (column default 2, a
  stored value kept); ``load_platform_settings`` and
  ``current_platform_settings`` return the three; ``apply_platform_settings``
  overlays ``max_input_tokens`` and ``image_input`` onto ``config.llm`` and
  is not broken by ``max_retries`` (no LLMConfig field);
  ``update_platform_settings`` changes each of the three, records one llm
  ``platform.settings_change`` event naming the changed fields (mapped to
  True, never a value), writes nothing for a no-op and refuses a
  non-Super-Admin before any statement.
- ``organizations.count_residency_orgs(executor)``: the number of
  organizations with ``data_residency`` on, of every status (active,
  deactivated, pending_deletion); one read, no capability check.
- ``org_permissions.load_tool_policy`` sets ``ToolPolicy.data_residency`` from
  the fail-closed ``scoped_settings.org_residency``: True for a residency org
  and for a missing org row, False for a non-residency org.

New symbols are looked up per test (module attributes, imports inside the
tests), so each test fails on its own until its part exists.

Security notes:
- Strict ints and bools: ``true``, ``"5"`` or ``1.0`` can never become a retry
  limit, an input window or a residency confirmation by coercion.
- hide_input_in_errors: a 422 never echoes the body.
- The llm audit event names the changed fields only, never a value.
- Fail closed: an org without an organizations row runs as a residency org.
"""

from __future__ import annotations

import copy
import inspect
import json
import re
import typing
import uuid
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest
import yaml
from pydantic import ValidationError

import admino.models as models_module
from admino.access import Principal
from admino.config import AppConfig, LLMConfig, load_app_config
from admino.models import (
    AgentConfig,
    AgentResult,
    ChatResponse,
    PlatformSettingsPatch,
    SettingsLLM,
    SettingsPatchLLM,
    ToolPolicy,
)
from admino.permissions import build_default_permissions_config
from admino.tenancy import TenantContext
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, plain

if TYPE_CHECKING:
    from types import ModuleType

    from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP = "203.0.113.7"
_SENTINEL = "ZZ-SENTINEL-242"
_HUGE = 987_654_321
_NOTHING_GIVEN = "Give at least one setting to change."
_ERROR_CODES = frozenset(
    {
        "not_configured",
        "missing_model",
        "provider_unavailable",
        "rate_limited",
        "timeout",
        "residency_blocked",
        "context_too_long",
    }
)
_UNKNOWN_CODES = ["unknown", "RATE_LIMITED", "rate-limited", "", "error", _SENTINEL]
# field -> (default, low, high)
_INT_FIELDS: dict[str, tuple[int, int, int]] = {
    "max_input_tokens": (200_000, 1000, 2_000_000),
    "max_retries": (2, 0, 5),
}
_INT_IDS = list(_INT_FIELDS)
_BOUND_ERRORS = frozenset({"greater_than_equal", "less_than_equal"})
_RESIDENCY_CONFIRM_MAX = 1_000_000
# GH-176: a ChatResponse names its persisted chat (a required chat_id).
_CHAT_ID = uuid.UUID("5b2e9d14-7a3c-4f68-b1e0-2c9d8f7a6e51")

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SHIPPED_CONFIG_PATH = _REPO_ROOT / "config" / "config.yaml"
# Env vars that load_app_config / LLMConfig validators read (the test_shipped_defaults list).
_ENV_VARS_TO_CLEAR = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "INFOMANIAK_API_TOKEN",
    "INFOMANIAK_PRODUCT_ID",
    "LLM_PROVIDER",
    "VLLM_MODEL",
    "VLLM_BASE_URL",
    "VLLM_MAX_MODEL_LEN",
    "COOKIE_SECURE",
    "ADMINO_PUBLIC_URL",
    "ADMINO_TRUSTED_PROXIES",
    "LOG_LEVEL",
    "AUDIT_LOG_PATH",
)

# What StoredPlatformLLM / SettingsLLM need besides the fields under test.
_STORED_LLM_BASE: dict[str, Any] = {
    "provider": "infomaniak",
    "infomaniak_model": "Qwen/Qwen3.5-397B-A17B-FP8",
    "vllm_model": "Qwen/Qwen3-4B-Instruct-2507",
    "anthropic_model": None,
    "openai_model": None,
}
_SETTINGS_LLM_BASE: dict[str, Any] = {
    "provider": "infomaniak",
    "anthropic_model": "",
    "openai_model": "",
}
_STORED_LIMITS: dict[str, int] = {
    "max_tool_calls_per_message": 7,
    "max_pending_confirmations": 4,
    "confirmation_timeout_s": 120,
    "max_message_length": 5000,
    "max_context_messages": 30,
}
# (patch field, platform_settings column, stored value, new value)
_UPDATES = [
    pytest.param("max_input_tokens", "max_input_tokens", 200_000, 100_000, id="max_input_tokens"),
    pytest.param("max_input_tokens", "max_input_tokens", 50_000, 2_000_000, id="max_input_high"),
    pytest.param("image_input", "image_input", True, False, id="image_input-off"),
    pytest.param("image_input", "image_input", False, True, id="image_input-on"),
    pytest.param("max_retries", "llm_max_retries", 2, 0, id="max_retries-0"),
    pytest.param("max_retries", "llm_max_retries", 2, 5, id="max_retries-5"),
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
    """A fresh in-memory database with two active orgs (residency on, the FakeDb default)."""
    fake = FakeDb()
    fake.add_org(ORG_ID)
    fake.add_org(OTHER_ORG_ID)
    return fake


@pytest.fixture()
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every env var that could override the shipped config values."""
    for name in _ENV_VARS_TO_CLEAR:
        monkeypatch.delenv(name, raising=False)


def _errors(exc: ValidationError) -> list[tuple[tuple[int | str, ...], str]]:
    """(loc, type) of every error, without the input."""
    return [
        (tuple(error["loc"]), error["type"])
        for error in exc.errors(include_url=False, include_input=False)
    ]


def _rejects(model: type[BaseModel], payload: dict[str, Any]) -> ValidationError:
    with pytest.raises(ValidationError) as exc_info:
        model.model_validate(payload)
    return exc_info.value


def _rejects_json(model: type[BaseModel], body: str) -> ValidationError:
    with pytest.raises(ValidationError) as exc_info:
        model.model_validate_json(body)
    return exc_info.value


def _not_strict_ints(value: int) -> list[object]:
    """Values a lax int would coerce to ``value`` (or a bool would pass as an int)."""
    return [True, False, float(value), str(value), Decimal(value)]


def _config(**llm: Any) -> AppConfig:
    """A real AppConfig: Anthropic with every provider's model set, plus these llm fields."""
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
        **llm,
    }
    return AppConfig.model_validate(
        {
            "server": {
                "host": "127.0.0.1",
                "port": 8123,
                "public_url": "https://admino.example.ch",
            },
            "llm": llm_section,
            "limits": {},
            "log_level": "WARNING",
        }
    )


def _stored(svc: ModuleType, **llm: Any) -> Any:
    """A StoredPlatformSettings: OpenAI with its model, these llm fields, limits 7/4/120/5000/30."""
    return svc.StoredPlatformSettings.model_validate(
        {
            "llm": {
                "provider": "openai",
                "infomaniak_model": None,
                "vllm_model": "org/served-model",
                "anthropic_model": None,
                "openai_model": "gpt-4.1",
                **llm,
            },
            "limits": _STORED_LIMITS,
        }
    )


def _platform_patch(payload: dict[str, Any]) -> Any:
    return PlatformSettingsPatch.model_validate(payload)


def _super_admin(db: FakeDb) -> Principal:
    user_id = db.add_account(kind="super_admin", role=None)
    return Principal(user_id=user_id, kind="super_admin")


def _member(db: FakeDb, role: str, org_id: uuid.UUID = ORG_ID) -> Principal:
    user_id = db.add_account(role=role, org_id=org_id)
    return Principal(user_id=user_id, kind="member", org_id=org_id, role=role)


def _tenant(org_id: uuid.UUID) -> TenantContext:
    principal = Principal(user_id=uuid.uuid4(), kind="member", org_id=org_id, role="editor")
    return TenantContext.from_principal(principal)


def _model_policy(stored_llm: Any) -> tuple[Any, Any, Any]:
    """(max_input_tokens, image_input, max_retries) of a StoredPlatformLLM."""
    return stored_llm.max_input_tokens, stored_llm.image_input, stored_llm.max_retries


def _row_policy(row: dict[str, Any] | None) -> tuple[Any, Any, Any]:
    """(max_input_tokens, image_input, llm_max_retries) of the platform row."""
    assert row is not None
    return row["max_input_tokens"], row["image_input"], row["llm_max_retries"]


def _without(row: dict[str, Any] | None, *columns: str) -> dict[str, Any]:
    """A platform row without these columns and its updated_at."""
    assert row is not None
    return {key: value for key, value in row.items() if key not in {*columns, "updated_at"}}


def _one(items: list[Any]) -> Any:
    assert len(items) == 1, items
    return items[0]


# ---------------------------------------------------------------------------
# 1. LLMConfig and the shipped config.yaml
# ---------------------------------------------------------------------------


class TestLLMConfigModelPolicy:
    """LLMConfig.max_input_tokens (200000, 1000..2000000) and image_input (True)."""

    def test_config_llm_max_input_tokens_defaults_to_200000(self) -> None:
        assert LLMConfig().max_input_tokens == 200_000

    def test_config_llm_image_input_defaults_to_true(self) -> None:
        assert LLMConfig().image_input is True

    @pytest.mark.parametrize("value", [1000, 64_000, 200_000, 2_000_000])
    def test_config_llm_max_input_tokens_within_bounds_is_accepted(self, value: int) -> None:
        assert LLMConfig(max_input_tokens=value).max_input_tokens == value

    @pytest.mark.parametrize("value", [999, 2_000_001, 0, -1])
    def test_config_llm_max_input_tokens_out_of_bounds_is_refused(self, value: int) -> None:
        exc = _rejects(LLMConfig, {"max_input_tokens": value})

        assert [loc for loc, _ in _errors(exc)] == [("max_input_tokens",)]

    def test_config_llm_image_input_can_be_switched_off(self) -> None:
        assert LLMConfig(image_input=False).image_input is False

    def test_config_llm_has_no_retry_field(self) -> None:
        """max_retries is a platform setting only (the run's AgentConfig carries it)."""
        assert "max_input_tokens" in LLMConfig.model_fields
        assert "max_retries" not in LLMConfig.model_fields
        assert "llm_max_retries" not in LLMConfig.model_fields


class TestShippedConfigModelPolicy:
    """config/config.yaml ships max_input_tokens 200000 and image_input true, commented."""

    def test_shipped_config_llm_sets_max_input_tokens_and_image_input(self) -> None:
        raw = yaml.safe_load(_SHIPPED_CONFIG_PATH.read_text(encoding="utf-8"))

        assert raw["llm"]["max_input_tokens"] == 200000
        assert raw["llm"]["image_input"] is True

    def test_shipped_config_loads_the_model_policy(self, clean_env: None) -> None:
        config = load_app_config(_SHIPPED_CONFIG_PATH)

        assert config.llm.max_input_tokens == 200_000
        assert config.llm.image_input is True

    def test_shipped_config_model_policy_keys_carry_a_comment(self) -> None:
        """A comment line sits right above the first of the two keys (or on one of them)."""
        lines = _SHIPPED_CONFIG_PATH.read_text(encoding="utf-8").splitlines()
        keys = [
            index
            for index, line in enumerate(lines)
            if re.match(r"^\s+(?:max_input_tokens|image_input)\s*:", line)
        ]

        assert len(keys) == 2, keys
        above = next(
            (lines[i].strip() for i in range(min(keys) - 1, -1, -1) if lines[i].strip()), ""
        )
        inline = any("#" in lines[index].split(":", 1)[1] for index in keys)
        assert above.startswith("#") or inline, above


# ---------------------------------------------------------------------------
# 2. SettingsLLM (the GET/PATCH /api/platform/settings llm section)
# ---------------------------------------------------------------------------


class TestSettingsLLMModelPolicy:
    """SettingsLLM shows max_input_tokens, image_input, max_retries and residency_orgs."""

    def test_settings_llm_model_policy_defaults(self) -> None:
        shown = SettingsLLM.model_validate(_SETTINGS_LLM_BASE)

        assert (
            shown.max_input_tokens,
            shown.image_input,
            shown.max_retries,
            shown.residency_orgs,
        ) == (200_000, True, 2, 0)

    @pytest.mark.parametrize("field", _INT_IDS)
    def test_settings_llm_int_bounds_are_accepted(self, field: str) -> None:
        _, low, high = _INT_FIELDS[field]

        for value in (low, high):
            shown = SettingsLLM.model_validate({**_SETTINGS_LLM_BASE, field: value})
            assert getattr(shown, field) == value

    @pytest.mark.parametrize("field", _INT_IDS)
    def test_settings_llm_int_out_of_bounds_is_refused(self, field: str) -> None:
        _, low, high = _INT_FIELDS[field]

        for value in (low - 1, high + 1):
            exc = _rejects(SettingsLLM, {**_SETTINGS_LLM_BASE, field: value})
            assert [loc for loc, _ in _errors(exc)] == [(field,)], value

    @pytest.mark.parametrize("value", [0, 1, 7, 50_000])
    def test_settings_llm_residency_orgs_accepts_a_count(self, value: int) -> None:
        shown = SettingsLLM.model_validate({**_SETTINGS_LLM_BASE, "residency_orgs": value})

        assert shown.residency_orgs == value

    def test_settings_llm_residency_orgs_is_never_negative(self) -> None:
        exc = _rejects(SettingsLLM, {**_SETTINGS_LLM_BASE, "residency_orgs": -1})

        assert [loc for loc, _ in _errors(exc)] == [("residency_orgs",)]

    def test_settings_llm_image_input_can_be_false(self) -> None:
        shown = SettingsLLM.model_validate({**_SETTINGS_LLM_BASE, "image_input": False})

        assert shown.image_input is False

    def test_settings_llm_json_carries_the_model_policy(self) -> None:
        shown = SettingsLLM.model_validate(
            {
                **_SETTINGS_LLM_BASE,
                "max_input_tokens": 64_000,
                "image_input": False,
                "max_retries": 4,
                "residency_orgs": 3,
            }
        )

        dumped = json.loads(shown.model_dump_json())

        assert {
            key: dumped[key]
            for key in ("max_input_tokens", "image_input", "max_retries", "residency_orgs")
        } == {
            "max_input_tokens": 64_000,
            "image_input": False,
            "max_retries": 4,
            "residency_orgs": 3,
        }


# ---------------------------------------------------------------------------
# 3. SettingsPatchLLM (strict new fields)
# ---------------------------------------------------------------------------


class TestSettingsPatchLLMModelPolicy:
    """Optional strict max_input_tokens, image_input and max_retries; errors never echo."""

    @pytest.mark.parametrize("field", ["max_input_tokens", "image_input", "max_retries"])
    def test_settings_patch_llm_new_field_is_optional_with_default_none(self, field: str) -> None:
        info = SettingsPatchLLM.model_fields[field]

        assert not info.is_required()
        assert info.default is None
        assert getattr(SettingsPatchLLM(), field) is None

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("max_input_tokens", 1000),
            ("max_input_tokens", 200_000),
            ("max_input_tokens", 2_000_000),
            ("max_retries", 0),
            ("max_retries", 2),
            ("max_retries", 5),
            ("image_input", True),
            ("image_input", False),
        ],
    )
    def test_settings_patch_llm_valid_value_is_accepted(self, field: str, value: object) -> None:
        patch = SettingsPatchLLM.model_validate({field: value})

        assert getattr(patch, field) == value
        assert type(getattr(patch, field)) is type(value)

    @pytest.mark.parametrize("field", _INT_IDS)
    def test_settings_patch_llm_int_out_of_bounds_is_refused_at_its_field(self, field: str) -> None:
        _, low, high = _INT_FIELDS[field]

        for value in (low - 1, high + 1):
            exc = _rejects(SettingsPatchLLM, {field: value})
            errors = _errors(exc)
            assert [loc for loc, _ in errors] == [(field,)], value
            assert {kind for _, kind in errors} <= _BOUND_ERRORS, errors

    @pytest.mark.parametrize("field", _INT_IDS)
    def test_settings_patch_llm_int_is_strict(self, field: str) -> None:
        """A bool, float, numeric string or Decimal is refused as int_type."""
        default = _INT_FIELDS[field][0]

        for value in _not_strict_ints(default):
            exc = _rejects(SettingsPatchLLM, {field: value})
            assert _errors(exc) == [((field,), "int_type")], repr(value)

    @pytest.mark.parametrize("field", _INT_IDS)
    def test_settings_patch_llm_json_int_is_strict(self, field: str) -> None:
        default = _INT_FIELDS[field][0]

        patch = SettingsPatchLLM.model_validate_json(json.dumps({field: default}))
        assert getattr(patch, field) == default
        for body in (
            f'{{"{field}": {default}.0}}',
            f'{{"{field}": "{default}"}}',
            f'{{"{field}": true}}',
        ):
            exc = _rejects_json(SettingsPatchLLM, body)
            assert [loc for loc, _ in _errors(exc)] == [(field,)], body

    @pytest.mark.parametrize("value", [1, 0, "true", "false", "yes", 1.0, "1"])
    def test_settings_patch_llm_image_input_is_a_strict_bool(self, value: object) -> None:
        exc = _rejects(SettingsPatchLLM, {"image_input": value})

        assert _errors(exc) == [(("image_input",), "bool_type")], repr(value)

    @pytest.mark.parametrize("body", ['{"image_input": 1}', '{"image_input": "true"}'])
    def test_settings_patch_llm_json_image_input_is_a_strict_bool(self, body: str) -> None:
        assert SettingsPatchLLM.model_validate_json('{"image_input": false}').image_input is False
        exc = _rejects_json(SettingsPatchLLM, body)

        assert _errors(exc) == [(("image_input",), "bool_type")]

    @pytest.mark.parametrize(
        ("payload", "field", "echo"),
        [
            ({"max_input_tokens": _HUGE}, "max_input_tokens", str(_HUGE)),
            ({"max_retries": _HUGE}, "max_retries", str(_HUGE)),
            ({"max_input_tokens": _SENTINEL}, "max_input_tokens", _SENTINEL),
            ({"max_retries": _SENTINEL}, "max_retries", _SENTINEL),
            ({"image_input": _SENTINEL}, "image_input", _SENTINEL),
        ],
    )
    def test_settings_patch_llm_errors_never_repeat_the_input(
        self, payload: dict[str, Any], field: str, echo: str
    ) -> None:
        exc = _rejects(SettingsPatchLLM, payload)

        assert [loc for loc, _ in _errors(exc)] == [(field,)]
        assert "extra_forbidden" not in {kind for _, kind in _errors(exc)}
        assert echo not in str(exc)
        assert echo not in repr(exc.errors(include_url=False, include_input=False))

    def test_settings_patch_llm_still_forbids_extra_and_hides_input(self) -> None:
        assert SettingsPatchLLM.model_config.get("extra") == "forbid"
        assert SettingsPatchLLM.model_config.get("hide_input_in_errors") is True
        exc = _rejects(SettingsPatchLLM, {"max_retries": 3, "residency_orgs": 2})
        assert _errors(exc) == [(("residency_orgs",), "extra_forbidden")]


# ---------------------------------------------------------------------------
# 4. PlatformSettingsPatch: the new llm fields and confirm_residency_orgs
# ---------------------------------------------------------------------------


class TestPlatformSettingsPatchModelPolicy:
    """A new llm field alone is a change; confirm_residency_orgs alone is not."""

    @pytest.mark.parametrize(
        "payload",
        [
            {"llm": {"max_input_tokens": 1000}},
            {"llm": {"image_input": False}},
            {"llm": {"image_input": True}},
            {"llm": {"max_retries": 0}},
            {"llm": {"max_retries": 5, "max_input_tokens": 2_000_000}},
        ],
    )
    def test_platform_settings_patch_model_policy_field_alone_is_enough(
        self, payload: dict[str, Any]
    ) -> None:
        """0 and False are values, not "not given"."""
        patch = _platform_patch(payload)

        assert patch.model_dump(exclude_none=True) == payload

    def test_platform_settings_patch_confirm_residency_orgs_defaults_to_none(self) -> None:
        info = PlatformSettingsPatch.model_fields["confirm_residency_orgs"]

        assert not info.is_required()
        assert info.default is None
        assert _platform_patch({"llm": {"provider": "openai"}}).confirm_residency_orgs is None

    @pytest.mark.parametrize("value", [0, 1, 3, _RESIDENCY_CONFIRM_MAX])
    def test_platform_settings_patch_confirm_residency_orgs_beside_a_provider_is_accepted(
        self, value: int
    ) -> None:
        patch = _platform_patch({"llm": {"provider": "openai"}, "confirm_residency_orgs": value})

        assert patch.confirm_residency_orgs == value
        assert type(patch.confirm_residency_orgs) is int
        assert patch.llm is not None
        assert patch.llm.provider == "openai"

    def test_platform_settings_patch_confirm_residency_orgs_beside_another_section_is_accepted(
        self,
    ) -> None:
        patch = _platform_patch({"security": {"lockout_minutes": 30}, "confirm_residency_orgs": 2})

        assert patch.confirm_residency_orgs == 2

    @pytest.mark.parametrize("value", [-1, _RESIDENCY_CONFIRM_MAX + 1, _HUGE])
    def test_platform_settings_patch_confirm_residency_orgs_out_of_range_is_refused(
        self, value: int
    ) -> None:
        exc = _rejects(
            PlatformSettingsPatch, {"llm": {"provider": "openai"}, "confirm_residency_orgs": value}
        )
        errors = _errors(exc)

        assert [loc for loc, _ in errors] == [("confirm_residency_orgs",)]
        assert {kind for _, kind in errors} <= _BOUND_ERRORS, errors
        assert str(value) not in str(exc)

    @pytest.mark.parametrize("value", [True, False, 3.0, "3", Decimal(3)])
    def test_platform_settings_patch_confirm_residency_orgs_is_a_strict_int(
        self, value: object
    ) -> None:
        exc = _rejects(
            PlatformSettingsPatch, {"llm": {"provider": "openai"}, "confirm_residency_orgs": value}
        )

        assert _errors(exc) == [(("confirm_residency_orgs",), "int_type")], repr(value)

    @pytest.mark.parametrize("bad", ["3.0", '"3"', "true"])
    def test_platform_settings_patch_json_confirm_residency_orgs_is_a_strict_int(
        self, bad: str
    ) -> None:
        good = '{"llm": {"provider": "openai"}, "confirm_residency_orgs": 3}'
        assert PlatformSettingsPatch.model_validate_json(good).confirm_residency_orgs == 3

        exc = _rejects_json(
            PlatformSettingsPatch,
            f'{{"llm": {{"provider": "openai"}}, "confirm_residency_orgs": {bad}}}',
        )

        assert [loc for loc, _ in _errors(exc)] == [("confirm_residency_orgs",)]

    @pytest.mark.parametrize(
        "payload",
        [
            {"confirm_residency_orgs": 3},
            {"confirm_residency_orgs": 0},
            {"llm": {}, "confirm_residency_orgs": 3},
            {"llm": {"provider": None}, "confirm_residency_orgs": 2},
            {"files": {}, "security": None, "confirm_residency_orgs": 1},
        ],
    )
    def test_platform_settings_patch_confirm_residency_orgs_alone_is_nothing_to_change(
        self, payload: dict[str, Any]
    ) -> None:
        """It is not a setting: the "give at least one setting" rule still refuses."""
        exc = _rejects(PlatformSettingsPatch, payload)

        assert _errors(exc) == [((), "value_error")]
        assert _NOTHING_GIVEN in str(exc)

    def test_platform_settings_patch_confirm_residency_orgs_sentinel_is_not_echoed(self) -> None:
        exc = _rejects(
            PlatformSettingsPatch,
            {"llm": {"provider": "openai"}, "confirm_residency_orgs": _SENTINEL},
        )

        assert _errors(exc) == [(("confirm_residency_orgs",), "int_type")]
        assert _SENTINEL not in str(exc)


# ---------------------------------------------------------------------------
# 5. StoredPlatformLLM
# ---------------------------------------------------------------------------


class TestStoredPlatformLLMModelPolicy:
    """The stored llm row carries max_input_tokens, image_input and max_retries."""

    def test_stored_platform_llm_model_policy_defaults(self, svc: ModuleType) -> None:
        stored = svc.StoredPlatformLLM.model_validate(_STORED_LLM_BASE)

        assert _model_policy(stored) == (200_000, True, 2)

    @pytest.mark.parametrize("field", _INT_IDS)
    def test_stored_platform_llm_int_bounds_are_accepted(self, svc: ModuleType, field: str) -> None:
        _, low, high = _INT_FIELDS[field]

        for value in (low, high):
            stored = svc.StoredPlatformLLM.model_validate({**_STORED_LLM_BASE, field: value})
            assert getattr(stored, field) == value

    @pytest.mark.parametrize("field", _INT_IDS)
    def test_stored_platform_llm_int_out_of_bounds_is_refused(
        self, svc: ModuleType, field: str
    ) -> None:
        _, low, high = _INT_FIELDS[field]

        for value in (low - 1, high + 1):
            exc = _rejects(svc.StoredPlatformLLM, {**_STORED_LLM_BASE, field: value})
            assert [loc for loc, _ in _errors(exc)] == [(field,)], value

    def test_stored_platform_llm_image_input_can_be_false(self, svc: ModuleType) -> None:
        stored = svc.StoredPlatformLLM.model_validate({**_STORED_LLM_BASE, "image_input": False})

        assert stored.image_input is False

    def test_stored_platform_settings_default_llm_has_the_column_defaults(
        self, svc: ModuleType
    ) -> None:
        """A stored llm built without the new keys reads the migration's column defaults."""
        stored = _stored(svc)

        assert _model_policy(stored.llm) == (200_000, True, 2)


# ---------------------------------------------------------------------------
# 6. AgentConfig, ToolPolicy and the error codes
# ---------------------------------------------------------------------------


class TestAgentConfigRetries:
    """AgentConfig.llm_max_retries: default 0, 0..5."""

    def test_agent_config_llm_max_retries_defaults_to_zero(self) -> None:
        assert AgentConfig().llm_max_retries == 0

    @pytest.mark.parametrize("value", [0, 1, 2, 5])
    def test_agent_config_llm_max_retries_within_bounds_is_accepted(self, value: int) -> None:
        assert AgentConfig(llm_max_retries=value).llm_max_retries == value

    @pytest.mark.parametrize("value", [-1, 6, 50])
    def test_agent_config_llm_max_retries_out_of_bounds_is_refused(self, value: int) -> None:
        exc = _rejects(AgentConfig, {"llm_max_retries": value})

        assert [loc for loc, _ in _errors(exc)] == [("llm_max_retries",)]


class TestToolPolicyDataResidency:
    """ToolPolicy.data_residency: default False, frozen."""

    def test_tool_policy_data_residency_defaults_to_false(self) -> None:
        policy = ToolPolicy(permissions=build_default_permissions_config())

        assert policy.data_residency is False

    def test_tool_policy_data_residency_can_be_true(self) -> None:
        policy = ToolPolicy.model_validate(
            {"permissions": build_default_permissions_config(), "data_residency": True}
        )

        assert policy.data_residency is True

    def test_tool_policy_data_residency_is_frozen(self) -> None:
        policy = ToolPolicy.model_validate(
            {"permissions": build_default_permissions_config(), "data_residency": True}
        )

        with pytest.raises(ValidationError):
            policy.data_residency = False
        assert policy.data_residency is True


class TestErrorCodes:
    """The seven LLM error codes and the error_code of a run and a chat response."""

    def test_models_llm_error_codes_are_exactly_the_seven(self) -> None:
        codes = models_module.LLM_ERROR_CODES

        assert isinstance(codes, frozenset)
        assert codes == _ERROR_CODES

    def test_models_llm_error_code_literal_is_exactly_the_seven(self) -> None:
        assert set(typing.get_args(models_module.LLMErrorCode)) == _ERROR_CODES

    def test_agent_result_error_code_defaults_to_none(self) -> None:
        result = AgentResult(status="error", response="Something went wrong.")

        assert result.error_code is None

    @pytest.mark.parametrize("code", sorted(_ERROR_CODES))
    def test_agent_result_error_code_accepts_each_code(self, code: str) -> None:
        result = AgentResult.model_validate(
            {"status": "error", "response": "Something went wrong.", "error_code": code}
        )

        assert result.error_code == code

    @pytest.mark.parametrize("code", _UNKNOWN_CODES)
    def test_agent_result_error_code_refuses_an_unknown_code(self, code: str) -> None:
        exc = _rejects(AgentResult, {"status": "error", "response": "x", "error_code": code})

        assert [loc[:1] for loc, _ in _errors(exc)] == [("error_code",)]

    def test_chat_response_error_code_defaults_to_none_and_is_serialized(self) -> None:
        response = ChatResponse(chat_id=_CHAT_ID, session_id="sess-1", response="Hello.")

        assert response.error_code is None
        assert json.loads(response.model_dump_json())["error_code"] is None

    @pytest.mark.parametrize("code", sorted(_ERROR_CODES))
    def test_chat_response_error_code_accepts_each_code(self, code: str) -> None:
        response = ChatResponse.model_validate(
            {
                "chat_id": str(_CHAT_ID),
                "session_id": "sess-1",
                "response": "x",
                "status": "error",
                "error_code": code,
            }
        )

        assert response.error_code == code
        assert json.loads(response.model_dump_json())["error_code"] == code

    @pytest.mark.parametrize("code", _UNKNOWN_CODES)
    def test_chat_response_error_code_refuses_an_unknown_code(self, code: str) -> None:
        exc = _rejects(
            ChatResponse,
            {
                "chat_id": str(_CHAT_ID),
                "session_id": "sess-1",
                "response": "x",
                "status": "error",
                "error_code": code,
            },
        )

        assert [loc[:1] for loc, _ in _errors(exc)] == [("error_code",)]


# ---------------------------------------------------------------------------
# 7. scoped_settings: seed, load, apply
# ---------------------------------------------------------------------------


class TestSeedModelPolicy:
    """config.yaml's max_input_tokens / image_input are stored on every boot; the retries never."""

    async def test_scoped_settings_seed_first_boot_stores_the_config_model_capabilities(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        config = _config(max_input_tokens=150_000, image_input=False)

        await svc.seed_platform_settings(db.pool, config)

        assert _row_policy(db.platform_row()) == (150_000, False, 2)

    async def test_scoped_settings_seed_never_writes_the_retry_limit(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        config = _config(max_input_tokens=150_000, image_input=False)

        await svc.seed_platform_settings(db.pool, config)

        row = db.platform_row()
        assert row is not None
        assert row["max_input_tokens"] == 150_000
        call = _one(db.calls)
        assert "llm_max_retries" not in call.normalized

    @pytest.mark.parametrize(
        ("stored_image", "config_image"),
        [pytest.param(True, False, id="image-off"), pytest.param(False, True, id="image-on")],
    )
    async def test_scoped_settings_seed_later_boot_reapplies_them_and_keeps_the_retries(
        self, svc: ModuleType, db: FakeDb, stored_image: bool, config_image: bool
    ) -> None:
        db.add_platform_settings(
            max_input_tokens=50_000, image_input=stored_image, llm_max_retries=4
        )
        config = _config(max_input_tokens=300_000, image_input=config_image)

        await svc.seed_platform_settings(db.pool, config)

        assert len(db.platform_settings) == 1
        assert _row_policy(db.platform_row()) == (300_000, config_image, 4)

    async def test_scoped_settings_seed_default_config_stores_the_defaults(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """A later boot with config.yaml's defaults resets a stored window to 200000."""
        db.add_platform_settings(max_input_tokens=50_000, image_input=False, llm_max_retries=0)

        await svc.seed_platform_settings(db.pool, _config())

        assert _row_policy(db.platform_row()) == (200_000, True, 0)


class TestLoadModelPolicy:
    """load_platform_settings / current_platform_settings return the three values."""

    async def test_scoped_settings_load_returns_the_stored_model_policy(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_platform_settings(max_input_tokens=64_000, image_input=False, llm_max_retries=5)

        stored = await svc.load_platform_settings(db.pool)

        assert _model_policy(stored.llm) == (64_000, False, 5)

    async def test_scoped_settings_load_default_row_reads_the_column_defaults(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_platform_settings()

        stored = await svc.load_platform_settings(db.pool)

        assert _model_policy(stored.llm) == (200_000, True, 2)

    async def test_scoped_settings_current_miss_returns_the_stored_model_policy(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(svc, "_platform_cache", None)
        db.add_platform_settings(max_input_tokens=1000, image_input=False, llm_max_retries=0)

        current = await svc.current_platform_settings(db.pool)

        assert _model_policy(current.llm) == (1000, False, 0)
        assert svc._platform_cache == current

    async def test_scoped_settings_load_reads_the_retries_from_llm_max_retries(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """The column is llm_max_retries; the field is max_retries."""
        db.add_platform_settings(llm_max_retries=3)

        stored = await svc.load_platform_settings(db.pool)

        assert stored.llm.max_retries == 3
        assert re.search(r"\bllm_max_retries\b", _one(db.calls).normalized)


class TestApplyModelPolicy:
    """apply_platform_settings overlays max_input_tokens and image_input onto config.llm."""

    def test_scoped_settings_apply_overlays_the_model_capabilities(self, svc: ModuleType) -> None:
        config = _config(max_input_tokens=300_000, image_input=True)
        stored = _stored(svc, max_input_tokens=50_000, image_input=False, max_retries=4)

        result = svc.apply_platform_settings(config, stored)

        assert type(result) is AppConfig
        assert (result.llm.max_input_tokens, result.llm.image_input) == (50_000, False)

    def test_scoped_settings_apply_is_not_broken_by_the_retries(self, svc: ModuleType) -> None:
        """max_retries is no LLMConfig field: the overlay keeps every other llm field."""
        config = _config()
        stored = _stored(svc, max_retries=5)

        result = svc.apply_platform_settings(config, stored)

        assert stored.llm.max_retries == 5
        assert (
            result.llm.timeout_s,
            result.llm.vllm_base_url,
            result.llm.vllm_max_model_len,
            result.llm.max_response_tokens,
        ) == (77, "http://vllm-test:8000/v1", 4096, 1234)
        assert "max_retries" not in result.llm.model_dump()

    def test_scoped_settings_apply_leaves_the_input_config_unchanged(self, svc: ModuleType) -> None:
        config = _config(max_input_tokens=300_000, image_input=True)
        before = config.model_dump()

        svc.apply_platform_settings(
            config, _stored(svc, max_input_tokens=50_000, image_input=False)
        )

        assert config.model_dump() == before
        assert config.llm.max_input_tokens == 300_000


# ---------------------------------------------------------------------------
# 8. scoped_settings: update_platform_settings
# ---------------------------------------------------------------------------


class TestUpdateModelPolicy:
    """The Super Admin changes max_input_tokens, image_input and max_retries."""

    @pytest.mark.parametrize(("field", "column", "old", "new"), _UPDATES)
    async def test_scoped_settings_update_changes_the_model_policy_field(
        self, svc: ModuleType, db: FakeDb, field: str, column: str, old: object, new: object
    ) -> None:
        before = copy.deepcopy(db.add_platform_settings(**{column: old}))
        admin = _super_admin(db)

        result = await svc.update_platform_settings(
            db.pool, actor=admin, patch=_platform_patch({"llm": {field: new}}), ip=_IP
        )

        row = db.platform_row()
        assert row is not None
        assert row[column] == new
        assert _without(row, column) == _without(before, column)
        assert getattr(result.llm, field) == new
        assert svc._platform_cache == result

    @pytest.mark.parametrize(("field", "column", "old", "new"), _UPDATES)
    async def test_scoped_settings_update_model_policy_records_one_llm_event_by_name(
        self, svc: ModuleType, db: FakeDb, field: str, column: str, old: object, new: object
    ) -> None:
        db.add_platform_settings(**{column: old})
        admin = _super_admin(db)

        await svc.update_platform_settings(
            db.pool, actor=admin, patch=_platform_patch({"llm": {field: new}}), ip=_IP
        )

        event = _one(db.audit)
        assert event["action"] == "platform.settings_change"
        assert event["actor_kind"] == "super_admin"
        assert plain(event["actor_user_id"]) == admin.user_id
        assert event["org_id"] is None
        assert event["metadata"] == {field: True}

    async def test_scoped_settings_update_all_llm_fields_is_one_event_naming_each(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_platform_settings()
        admin = _super_admin(db)
        patch = _platform_patch(
            {
                "llm": {
                    "provider": "vllm",
                    "max_input_tokens": 123_456,
                    "image_input": False,
                    "max_retries": 4,
                }
            }
        )

        result = await svc.update_platform_settings(db.pool, actor=admin, patch=patch, ip=_IP)

        row = db.platform_row()
        assert row is not None
        assert row["llm_provider"] == "vllm"
        assert _row_policy(row) == (123_456, False, 4)
        assert _model_policy(result.llm) == (123_456, False, 4)
        event = _one(db.audit)
        assert event["metadata"] == {
            "provider": True,
            "max_input_tokens": True,
            "image_input": True,
            "max_retries": True,
        }
        assert "123456" not in json.dumps(event, default=str)

    async def test_scoped_settings_update_model_policy_names_only_the_changed_fields(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_platform_settings(max_input_tokens=200_000, image_input=True, llm_max_retries=2)
        admin = _super_admin(db)
        patch = _platform_patch(
            {"llm": {"max_input_tokens": 200_000, "image_input": True, "max_retries": 3}}
        )

        await svc.update_platform_settings(db.pool, actor=admin, patch=patch, ip=_IP)

        assert _row_policy(db.platform_row()) == (200_000, True, 3)
        assert _one(db.audit)["metadata"] == {"max_retries": True}

    async def test_scoped_settings_update_model_policy_noop_writes_nothing(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        before = copy.deepcopy(
            db.add_platform_settings(max_input_tokens=64_000, image_input=False, llm_max_retries=1)
        )
        admin = _super_admin(db)
        patch = _platform_patch(
            {"llm": {"max_input_tokens": 64_000, "image_input": False, "max_retries": 1}}
        )

        result = await svc.update_platform_settings(db.pool, actor=admin, patch=patch, ip=_IP)

        assert db.audit == []
        assert db.platform_row() == before
        assert db.matching(r"^update platform_settings\b") == []
        assert _model_policy(result.llm) == (64_000, False, 1)

    @pytest.mark.parametrize("role", ["org_admin", "editor", "viewer"])
    async def test_scoped_settings_update_model_policy_member_is_refused_before_any_query(
        self, svc: ModuleType, db: FakeDb, role: str
    ) -> None:
        before = copy.deepcopy(db.add_platform_settings())
        member = _member(db, role)
        patch = _platform_patch({"llm": {"max_retries": 5, "max_input_tokens": 1000}})

        with pytest.raises(PermissionError):
            await svc.update_platform_settings(db.pool, actor=member, patch=patch, ip=_IP)

        assert db.calls == []
        assert db.platform_row() == before
        assert db.audit == []


# ---------------------------------------------------------------------------
# 9. organizations.count_residency_orgs
# ---------------------------------------------------------------------------


class TestCountResidencyOrgs:
    """The number of organizations with data residency on, of every status."""

    def test_organizations_count_residency_orgs_is_a_coroutine_of_one_executor(self) -> None:
        """No actor: the route checks the capability."""
        from admino import organizations

        function = organizations.count_residency_orgs
        parameters = list(inspect.signature(function).parameters.values())

        assert inspect.iscoroutinefunction(function)
        assert len(parameters) == 1
        assert parameters[0].kind in {
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        }

    async def test_organizations_count_residency_orgs_counts_every_status(self, db: FakeDb) -> None:
        from admino import organizations

        db.add_org(OTHER_ORG_ID, data_residency=False)
        db.add_org(status="deactivated")
        db.add_org(status="pending_deletion")
        db.add_org(status="deactivated", data_residency=False)
        db.add_org(status="pending_deletion", data_residency=False)
        db.add_org(data_residency=False)

        count = await organizations.count_residency_orgs(db.pool)

        # ORG_ID (active), the deactivated one and the pending_deletion one.
        assert count == 3
        assert type(count) is int

    @pytest.mark.parametrize("status", ["active", "deactivated", "pending_deletion"])
    @pytest.mark.parametrize("residency", [True, False])
    async def test_organizations_count_residency_orgs_one_org_of_each_status(
        self, status: str, residency: bool
    ) -> None:
        from admino import organizations

        fake = FakeDb()
        fake.add_org(ORG_ID, status=status, data_residency=residency)

        assert await organizations.count_residency_orgs(fake.pool) == (1 if residency else 0)

    async def test_organizations_count_residency_orgs_without_orgs_is_zero(self) -> None:
        from admino import organizations

        count = await organizations.count_residency_orgs(FakeDb().pool)

        assert count == 0
        assert type(count) is int

    async def test_organizations_count_residency_orgs_is_one_read_of_organizations(
        self, db: FakeDb
    ) -> None:
        from admino import organizations

        orgs = copy.deepcopy(db.orgs)

        await organizations.count_residency_orgs(db.pool)

        call = _one(db.calls)
        assert call.method in {"fetchval", "fetchrow", "fetch"}
        assert re.search(r"\bfrom organizations\b", call.normalized)
        assert re.search(r"\bdata_residency\b", call.normalized)
        assert db.orgs == orgs
        assert db.audit == []

    async def test_organizations_count_residency_orgs_reads_through_a_connection(
        self, db: FakeDb
    ) -> None:
        from admino import organizations

        async with db.pool.acquire() as conn:
            count = await organizations.count_residency_orgs(conn)

        assert count == 2
        assert _one(db.calls).via == conn.name


# ---------------------------------------------------------------------------
# 10. org_permissions.load_tool_policy: ToolPolicy.data_residency
# ---------------------------------------------------------------------------


class TestLoadToolPolicyDataResidency:
    """The run's policy carries the org's fail-closed residency flag."""

    @pytest.mark.parametrize("residency", [True, False])
    async def test_org_permissions_policy_data_residency_follows_the_org(
        self, db: FakeDb, residency: bool
    ) -> None:
        from admino import org_permissions

        db.add_org(ORG_ID, data_residency=residency)
        db.add_org(OTHER_ORG_ID, data_residency=not residency)

        policy = await org_permissions.load_tool_policy(db.pool, _tenant(ORG_ID))

        assert policy.data_residency is residency

    async def test_org_permissions_policy_missing_org_row_is_a_residency_org(
        self, db: FakeDb
    ) -> None:
        """No organizations row: fail closed (residency on)."""
        from admino import org_permissions

        db.add_org(ORG_ID, data_residency=False)
        db.add_org(OTHER_ORG_ID, data_residency=False)

        policy = await org_permissions.load_tool_policy(db.pool, _tenant(uuid.uuid4()))

        assert policy.data_residency is True

    @pytest.mark.parametrize("residency", [True, False])
    async def test_org_permissions_policy_data_residency_is_the_one_org_residency_read(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, residency: bool
    ) -> None:
        """The flag comes from scoped_settings.org_residency (asked once), not a read of its
        own: the stored flag is set the other way."""
        from admino import org_permissions, scoped_settings

        db.add_org(ORG_ID, data_residency=not residency)
        spy = AsyncMock(return_value=residency)
        monkeypatch.setattr(scoped_settings, "org_residency", spy)
        if hasattr(org_permissions, "org_residency"):
            monkeypatch.setattr(org_permissions, "org_residency", spy)

        policy = await org_permissions.load_tool_policy(db.pool, _tenant(ORG_ID))

        assert policy.data_residency is residency
        spy.assert_awaited_once()

    async def test_org_permissions_policy_data_residency_matches_the_tool_switches(
        self, db: FakeDb
    ) -> None:
        """A residency org's policy has the flag and the connector tools off together."""
        from admino import org_permissions

        db.add_org(ORG_ID, data_residency=True)

        policy = await org_permissions.load_tool_policy(db.pool, _tenant(ORG_ID))

        assert policy.data_residency is True
        assert policy.enabled_tools["gmail"] is False
        assert policy.enabled_tools["memory"] is True


# ---------------------------------------------------------------------------
# GH-242 security fix: the residency count is checked again in the write
# ---------------------------------------------------------------------------


class TestResidencyConfirmationInTransaction:
    """The route passes the residency count it confirmed; the write transaction counts
    again under the platform row lock, so an org whose residency changed between the
    route's check and the write can't pass a stale count (the fixture has 2)."""

    async def test_scoped_settings_stale_expected_count_is_refused_and_writes_nothing(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        before = copy.deepcopy(db.add_platform_settings(llm_provider="infomaniak"))
        admin = _super_admin(db)
        audit_before = copy.deepcopy(db.audit)
        cache_before = svc._platform_cache

        with pytest.raises(svc.ResidencyConfirmationError) as exc_info:
            await svc.update_platform_settings(
                db.pool,
                actor=admin,
                patch=_platform_patch(
                    {"llm": {"provider": "anthropic"}, "confirm_residency_orgs": 1}
                ),
                ip=_IP,
                expected_residency_orgs=1,
            )

        assert exc_info.value.residency_orgs == 2
        assert db.platform_row() == before
        assert db.audit == audit_before
        assert svc._platform_cache is cache_before
        assert db.transactions[-1][1].startswith("rollback")

    async def test_scoped_settings_matching_expected_count_switches_the_provider(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_platform_settings(llm_provider="infomaniak")
        admin = _super_admin(db)

        result = await svc.update_platform_settings(
            db.pool,
            actor=admin,
            patch=_platform_patch({"llm": {"provider": "anthropic"}, "confirm_residency_orgs": 2}),
            ip=_IP,
            expected_residency_orgs=2,
        )

        row = db.platform_row()
        assert row is not None
        assert row["llm_provider"] == "anthropic"
        assert result.llm.provider == "anthropic"

    async def test_scoped_settings_expected_count_is_read_under_the_lock_in_the_write(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_platform_settings(llm_provider="infomaniak")
        admin = _super_admin(db)
        db.calls.clear()

        await svc.update_platform_settings(
            db.pool,
            actor=admin,
            patch=_platform_patch({"llm": {"provider": "openai"}, "confirm_residency_orgs": 2}),
            ip=_IP,
            expected_residency_orgs=2,
        )

        sqls = [" ".join(call.sql.lower().split()) for call in db.calls]
        lock = next(
            i
            for i, sql in enumerate(sqls)
            if "from platform_settings" in sql and "for update" in sql
        )
        count = next(
            i for i, sql in enumerate(sqls) if "count(" in sql and "from organizations" in sql
        )
        update = next(i for i, sql in enumerate(sqls) if sql.startswith("update platform_settings"))
        assert lock < count < update
        assert db.calls[count].tx is not None
        assert db.calls[count].tx == db.calls[lock].tx == db.calls[update].tx
        assert db.calls[count].via == db.calls[lock].via

    async def test_scoped_settings_without_expected_count_reads_no_count(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """The route decides when a confirmation is needed: without one, nothing is counted."""
        db.add_platform_settings(llm_provider="infomaniak")
        admin = _super_admin(db)
        db.calls.clear()

        await svc.update_platform_settings(
            db.pool, actor=admin, patch=_platform_patch({"llm": {"provider": "anthropic"}}), ip=_IP
        )

        row = db.platform_row()
        assert row is not None
        assert row["llm_provider"] == "anthropic"
        assert not any("from organizations" in call.sql.lower() for call in db.calls)
