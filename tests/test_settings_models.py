"""Tests for the scoped settings API models in admino.models (GH-159).

The single ``/api/settings`` body is split into three scopes, each with its own
request and response models: user (``/api/me/settings``: theme and
notifications), org (``/api/org/settings``: the enabled tool services) and
platform (``/api/platform/settings``: the LLM provider and models, plus the
limits, which stay read-only until #160).

What these tests pin down:
- The old combined models are gone: ``SettingsResponse``, ``SettingsPatch``,
  ``SettingsImmutable``, ``SettingsConnectedAccounts``, ``SettingsPatchTools``,
  ``SettingsLimits``.
- ``UserSettingsPatch``: ``appearance`` / ``notifications`` only; unknown keys
  refused at every level (``llm``, ``tools``, ``limits``, ``ui_language`` ...);
  strict bools; the theme is one of light, dark, system; at least one leaf
  value must be given (a null counts as not given).
- ``OrgSettingsPatch`` / ``OrgToolsPatch``: ``tools`` is required; the seven
  tool names of ``ToolsSettings`` only (an unknown tool such as ``files`` and
  an ``org_id`` in the body are refused, never ignored); strict bools; at least
  one tool given.
- ``PlatformSettingsPatch``: ``llm`` is required; a ``limits`` key is refused
  until #160; at least one llm field given. ``SettingsPatchLLM`` refuses
  unknown fields (so ``vllm_base_url``, ``timeout_s`` or a key can never be
  patched) and model names must fully match ``[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,199}``
  (a trailing newline is refused: the database CHECK would reject it with a 500).
- ``PlatformLimits`` has exactly the ``LimitsConfig`` fields and bounds.
- ``UserSettingsResponse``, ``OrgSettingsResponse`` and
  ``PlatformSettingsResponse`` carry exactly their scope's sections.
- Validation errors of the request models never repeat the rejected input.

New symbols are looked up per test, so a missing model fails its own tests and
not the whole module.

Security notes:
- extra="forbid" everywhere: a client can't smuggle another scope's key, an
  org id or an LLM endpoint into a patch and have it silently dropped or used.
- Strict bools: "false" or 0 can never re-enable or disable a service by
  coercion.
- The model-name rule matches the database CHECK exactly.
"""

from __future__ import annotations

import json
import typing
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

import admino.models as models_module
from admino.config import LimitsConfig
from admino.models import (
    SettingsAppearance,
    SettingsLLM,
    SettingsNotifications,
    SettingsPatchAppearance,
    SettingsPatchLLM,
    SettingsPatchNotifications,
    ToolsSettings,
)

_SENTINEL = "ZZ-SENTINEL-42"
_TOOLS = (
    "gmail",
    "google_calendar",
    "google_drive",
    "outlook",
    "outlook_calendar",
    "onedrive",
    "memory",
)
_PROVIDERS = ("infomaniak", "vllm", "anthropic", "openai")
_MODEL_FIELDS = ("infomaniak_model", "vllm_model", "anthropic_model", "openai_model")
_LIMIT_BOUNDS: dict[str, tuple[int, int]] = {
    "max_tool_calls_per_message": (1, 100),
    "max_pending_confirmations": (1, 50),
    "confirmation_timeout_s": (10, 3600),
    "max_message_length": (1, 100_000),
    "max_context_messages": (1, 200),
}
_NOT_STRICT_BOOLS: tuple[object, ...] = ("yes", "true", "false", "1", "on", 1, 0, 1.0)
_GOOD_MODEL_NAMES = (
    "Qwen/Qwen3.5-397B-A17B-FP8",
    "gpt-4o",
    "claude-sonnet-4-6",
    "a",
    "mistralai/Mistral-Small-3.2",
    "llama3.1:8b",
    "org_name/model_v2",
    "a" * 200,
)
_BAD_MODEL_NAMES = (
    "",
    "-x",
    "_x",
    ".hidden",
    "/abs",
    "../x",
    "a b",
    "a;rm",
    "a|b",
    "model$(id)",
    "evil; rm -rf /",
    "a\n",
    "gpt-4o\n",
    "a\tb",
    "a" + chr(0) + "b",
    "mod" + chr(0xE9) + "le",
    "x" * 201,
)


def _model(name: str) -> type[BaseModel]:
    """A GH-159 model from admino.models; fails the calling test when missing."""
    model = getattr(models_module, name, None)
    if model is None:
        pytest.fail(f"admino.models.{name} does not exist (GH-159)")
    assert isinstance(model, type)
    assert issubclass(model, BaseModel)
    return model


def _rejects(model: type[BaseModel], payload: object) -> ValidationError:
    with pytest.raises(ValidationError) as exc_info:
        model.model_validate(payload)
    return exc_info.value


def _field_bounds(name: str) -> tuple[int, int]:
    metadata = LimitsConfig.model_fields[name].metadata
    low = next(item.ge for item in metadata if hasattr(item, "ge"))
    high = next(item.le for item in metadata if hasattr(item, "le"))
    return int(low), int(high)


def _limits(**overrides: int) -> dict[str, int]:
    values = {name: low for name, (low, _) in _LIMIT_BOUNDS.items()}
    values.update(overrides)
    return values


# ---------------------------------------------------------------------------
# 1. The old combined models are removed
# ---------------------------------------------------------------------------


class TestSettingsModelsRemoved:
    """The single /api/settings body and its parts are gone."""

    @pytest.mark.parametrize(
        "name",
        [
            "SettingsResponse",
            "SettingsPatch",
            "SettingsImmutable",
            "SettingsConnectedAccounts",
            "SettingsPatchTools",
            "SettingsLimits",
        ],
    )
    def test_settings_models_old_combined_model_is_removed(self, name: str) -> None:
        assert not hasattr(models_module, name)


# ---------------------------------------------------------------------------
# 2. UserSettingsPatch (PATCH /api/me/settings)
# ---------------------------------------------------------------------------


class TestUserSettingsPatch:
    """The user's own theme and notifications; nothing else."""

    def test_user_settings_patch_fields_are_appearance_and_notifications(self) -> None:
        fields = _model("UserSettingsPatch").model_fields

        assert set(fields) == {"appearance", "notifications"}
        assert SettingsPatchAppearance in typing.get_args(fields["appearance"].annotation)
        assert SettingsPatchNotifications in typing.get_args(fields["notifications"].annotation)

    @pytest.mark.parametrize(
        "payload",
        [
            {"appearance": {"theme": "light"}},
            {"appearance": {"theme": "dark"}},
            {"appearance": {"theme": "system"}},
            {"notifications": {"enabled": True}},
            {"notifications": {"enabled": False}},
            {"appearance": {"theme": "dark"}, "notifications": {"enabled": False}},
        ],
    )
    def test_user_settings_patch_valid_payload_is_accepted(self, payload: dict[str, Any]) -> None:
        patch = _model("UserSettingsPatch").model_validate(payload)

        assert patch.model_dump(exclude_none=True) == payload

    def test_user_settings_patch_accepts_a_json_body(self) -> None:
        patch = _model("UserSettingsPatch").model_validate_json(
            '{"notifications": {"enabled": false}}'
        )

        assert patch.model_dump(exclude_none=True) == {"notifications": {"enabled": False}}

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("llm", {"provider": "openai"}),
            ("tools", {"gmail": False}),
            ("limits", {"max_message_length": 10}),
            ("ui_language", "de"),
            ("response_language", "fr"),
            ("server", {"port": 1}),
            ("connected_accounts", {}),
            ("user_id", "00000000-0000-4000-8000-000000000001"),
        ],
    )
    def test_user_settings_patch_unknown_top_level_key_is_rejected(
        self, key: str, value: object
    ) -> None:
        """Another scope's key (or a user id) is refused, not silently dropped."""
        _rejects(_model("UserSettingsPatch"), {"appearance": {"theme": "dark"}, key: value})

    @pytest.mark.parametrize(
        "payload",
        [
            {"appearance": {"theme": "dark", "font": "mono"}},
            {"notifications": {"enabled": True, "sound": True}},
        ],
    )
    def test_user_settings_patch_unknown_nested_key_is_rejected(
        self, payload: dict[str, Any]
    ) -> None:
        _rejects(_model("UserSettingsPatch"), payload)

    @pytest.mark.parametrize("value", _NOT_STRICT_BOOLS)
    def test_user_settings_patch_notifications_enabled_is_a_strict_bool(
        self, value: object
    ) -> None:
        _rejects(_model("UserSettingsPatch"), {"notifications": {"enabled": value}})

    @pytest.mark.parametrize(
        "body", ['{"notifications": {"enabled": 1}}', '{"notifications": {"enabled": "true"}}']
    )
    def test_user_settings_patch_json_bool_is_strict(self, body: str) -> None:
        with pytest.raises(ValidationError):
            _model("UserSettingsPatch").model_validate_json(body)

    @pytest.mark.parametrize("theme", ["blue", "LIGHT", "Dark", "", "light ", 1, True])
    def test_user_settings_patch_unknown_theme_is_rejected(self, theme: object) -> None:
        _rejects(_model("UserSettingsPatch"), {"appearance": {"theme": theme}})

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"appearance": {}},
            {"appearance": None},
            {"notifications": {}},
            {"notifications": None},
            {"appearance": {"theme": None}},
            {"notifications": {"enabled": None}},
            {"appearance": {}, "notifications": {}},
            {"appearance": None, "notifications": None},
        ],
    )
    def test_user_settings_patch_without_any_value_is_rejected(
        self, payload: dict[str, Any]
    ) -> None:
        """A patch must change something; a null counts as not given."""
        _rejects(_model("UserSettingsPatch"), payload)

    @pytest.mark.parametrize(
        "payload",
        [
            {"appearance": {"theme": _SENTINEL}},
            {"notifications": {"enabled": _SENTINEL}},
            {"appearance": {"theme": "dark"}, "llm": _SENTINEL},
            {"appearance": {"theme": "dark", "font": _SENTINEL}},
        ],
    )
    def test_user_settings_patch_errors_never_repeat_the_input(
        self, payload: dict[str, Any]
    ) -> None:
        exc = _rejects(_model("UserSettingsPatch"), payload)

        assert _SENTINEL not in str(exc)


# ---------------------------------------------------------------------------
# 3. OrgSettingsPatch / OrgToolsPatch (PATCH /api/org/settings)
# ---------------------------------------------------------------------------


class TestOrgSettingsPatch:
    """The org's enabled tool services; nothing else."""

    def test_org_tools_patch_fields_are_the_tools_settings_fields(self) -> None:
        fields = _model("OrgToolsPatch").model_fields

        assert set(ToolsSettings.model_fields) == set(_TOOLS)
        assert set(fields) == set(ToolsSettings.model_fields)

    def test_org_settings_patch_has_only_a_required_tools_field(self) -> None:
        fields = _model("OrgSettingsPatch").model_fields

        assert set(fields) == {"tools"}
        assert fields["tools"].annotation is _model("OrgToolsPatch")
        assert fields["tools"].is_required()

    @pytest.mark.parametrize("tool", _TOOLS)
    @pytest.mark.parametrize("enabled", [True, False])
    def test_org_settings_patch_single_tool_is_accepted(self, tool: str, enabled: bool) -> None:
        patch = _model("OrgSettingsPatch").model_validate({"tools": {tool: enabled}})

        assert patch.model_dump(exclude_none=True) == {"tools": {tool: enabled}}

    def test_org_settings_patch_all_tools_at_once_are_accepted(self) -> None:
        payload = {"tools": {tool: index % 2 == 0 for index, tool in enumerate(_TOOLS)}}

        patch = _model("OrgSettingsPatch").model_validate(payload)

        assert patch.model_dump(exclude_none=True) == payload

    def test_org_settings_patch_accepts_a_json_body(self) -> None:
        patch = _model("OrgSettingsPatch").model_validate_json('{"tools": {"memory": false}}')

        assert patch.model_dump(exclude_none=True) == {"tools": {"memory": False}}

    @pytest.mark.parametrize("payload", [{}, {"tools": None}])
    def test_org_settings_patch_tools_is_required(self, payload: dict[str, Any]) -> None:
        _rejects(_model("OrgSettingsPatch"), payload)

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("org_id", "00000000-0000-4000-8000-000000000001"),
            ("appearance", {"theme": "dark"}),
            ("notifications", {"enabled": False}),
            ("llm", {"provider": "openai"}),
            ("limits", {"max_message_length": 10}),
            ("name", "Acme"),
        ],
    )
    def test_org_settings_patch_unknown_top_level_key_is_rejected(
        self, key: str, value: object
    ) -> None:
        """An org id in the body is refused: the org is always the caller's own."""
        _rejects(_model("OrgSettingsPatch"), {"tools": {"gmail": False}, key: value})

    @pytest.mark.parametrize("tool", ["files", "drive", "Gmail", "web_search", "documents"])
    def test_org_settings_patch_unknown_tool_is_rejected(self, tool: str) -> None:
        """The removed files toggle (GH-143) and any unknown tool are refused, not ignored."""
        _rejects(_model("OrgSettingsPatch"), {"tools": {tool: False}})
        _rejects(_model("OrgSettingsPatch"), {"tools": {"gmail": False, tool: False}})

    def test_org_tools_patch_rejects_the_files_toggle(self) -> None:
        _rejects(_model("OrgToolsPatch"), {"files": False})

    @pytest.mark.parametrize("value", _NOT_STRICT_BOOLS)
    @pytest.mark.parametrize("tool", ["gmail", "memory"])
    def test_org_settings_patch_tool_value_is_a_strict_bool(self, tool: str, value: object) -> None:
        _rejects(_model("OrgSettingsPatch"), {"tools": {tool: value}})

    @pytest.mark.parametrize("body", ['{"tools": {"gmail": 0}}', '{"tools": {"gmail": "false"}}'])
    def test_org_settings_patch_json_bool_is_strict(self, body: str) -> None:
        with pytest.raises(ValidationError):
            _model("OrgSettingsPatch").model_validate_json(body)

    @pytest.mark.parametrize(
        "payload",
        [
            {"tools": {}},
            {"tools": {"gmail": None}},
            {"tools": dict.fromkeys(_TOOLS)},
        ],
    )
    def test_org_settings_patch_without_any_tool_is_rejected(self, payload: dict[str, Any]) -> None:
        _rejects(_model("OrgSettingsPatch"), payload)

    @pytest.mark.parametrize(
        "payload",
        [
            {"tools": {"gmail": _SENTINEL}},
            {"tools": {"files": _SENTINEL}},
            {"tools": {"gmail": True}, "org_id": _SENTINEL},
        ],
    )
    def test_org_settings_patch_errors_never_repeat_the_input(
        self, payload: dict[str, Any]
    ) -> None:
        exc = _rejects(_model("OrgSettingsPatch"), payload)

        assert _SENTINEL not in str(exc)


# ---------------------------------------------------------------------------
# 4. PlatformSettingsPatch / SettingsPatchLLM (PATCH /api/platform/settings)
# ---------------------------------------------------------------------------


class TestPlatformSettingsPatch:
    """The platform LLM (provider and models); limits are read-only until #160."""

    def test_platform_settings_patch_has_only_a_required_llm_field(self) -> None:
        fields = _model("PlatformSettingsPatch").model_fields

        assert set(fields) == {"llm"}
        assert fields["llm"].annotation is SettingsPatchLLM
        assert fields["llm"].is_required()
        assert set(SettingsPatchLLM.model_fields) == {"provider", *_MODEL_FIELDS}

    @pytest.mark.parametrize("provider", _PROVIDERS)
    def test_platform_settings_patch_provider_is_accepted(self, provider: str) -> None:
        patch = _model("PlatformSettingsPatch").model_validate({"llm": {"provider": provider}})

        assert patch.model_dump(exclude_none=True) == {"llm": {"provider": provider}}

    @pytest.mark.parametrize("field", _MODEL_FIELDS)
    @pytest.mark.parametrize("name", _GOOD_MODEL_NAMES)
    def test_platform_settings_patch_well_formed_model_name_is_accepted(
        self, field: str, name: str
    ) -> None:
        patch = _model("PlatformSettingsPatch").model_validate({"llm": {field: name}})

        assert patch.model_dump(exclude_none=True) == {"llm": {field: name}}

    @pytest.mark.parametrize("field", _MODEL_FIELDS)
    @pytest.mark.parametrize("name", _BAD_MODEL_NAMES, ids=[repr(n)[:30] for n in _BAD_MODEL_NAMES])
    def test_platform_settings_patch_malformed_model_name_is_rejected(
        self, field: str, name: str
    ) -> None:
        """Shell metacharacters, a leading '-', a trailing newline or >200 chars."""
        _rejects(_model("PlatformSettingsPatch"), {"llm": {field: name}})

    @pytest.mark.parametrize("value", [5, True, ["gpt-4o"], {"name": "gpt-4o"}])
    def test_platform_settings_patch_non_string_model_name_is_a_validation_error(
        self, value: object
    ) -> None:
        """Not a TypeError from the validator (which would be a 500)."""
        _rejects(_model("PlatformSettingsPatch"), {"llm": {"openai_model": value}})

    @pytest.mark.parametrize("provider", ["ollama", "OpenAI", "", "infomaniak ", 1])
    def test_platform_settings_patch_unknown_provider_is_rejected(self, provider: object) -> None:
        _rejects(_model("PlatformSettingsPatch"), {"llm": {"provider": provider}})

    @pytest.mark.parametrize("payload", [{}, {"llm": None}])
    def test_platform_settings_patch_llm_is_required(self, payload: dict[str, Any]) -> None:
        _rejects(_model("PlatformSettingsPatch"), payload)

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("limits", {"max_message_length": 100}),
            ("tools", {"gmail": False}),
            ("appearance", {"theme": "dark"}),
            ("notifications", {"enabled": False}),
            ("server", {"port": 1}),
        ],
    )
    def test_platform_settings_patch_unknown_top_level_key_is_rejected(
        self, key: str, value: object
    ) -> None:
        """A limits key is refused until #160 makes limits editable."""
        _rejects(_model("PlatformSettingsPatch"), {"llm": {"provider": "openai"}, key: value})

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("vllm_base_url", "http://evil.example:8000/v1"),
            ("timeout_s", 10),
            ("vllm_max_model_len", 1024),
            ("max_response_tokens", 10),
            ("api_key", "sk-x"),
            ("anthropic_key_configured", True),
        ],
    )
    def test_platform_settings_patch_unknown_llm_field_is_rejected(
        self, key: str, value: object
    ) -> None:
        """Only the provider and the four model names can be patched."""
        _rejects(_model("PlatformSettingsPatch"), {"llm": {"provider": "openai", key: value}})

    @pytest.mark.parametrize(
        "payload",
        [
            {"llm": {}},
            {"llm": {"provider": None}},
            {"llm": {"provider": None, **dict.fromkeys(_MODEL_FIELDS)}},
        ],
    )
    def test_platform_settings_patch_without_any_llm_field_is_rejected(
        self, payload: dict[str, Any]
    ) -> None:
        _rejects(_model("PlatformSettingsPatch"), payload)

    @pytest.mark.parametrize(
        "payload",
        [
            {"llm": {"provider": _SENTINEL}},
            {"llm": {"infomaniak_model": f"{_SENTINEL};"}},
            {"llm": {"provider": "openai"}, "limits": _SENTINEL},
            {"llm": {"provider": "openai", "vllm_base_url": _SENTINEL}},
        ],
    )
    def test_platform_settings_patch_errors_never_repeat_the_input(
        self, payload: dict[str, Any]
    ) -> None:
        exc = _rejects(_model("PlatformSettingsPatch"), payload)

        assert _SENTINEL not in str(exc)


class TestSettingsPatchLLMTightened:
    """SettingsPatchLLM itself refuses unknown fields and a trailing newline."""

    @pytest.mark.parametrize("key", ["vllm_base_url", "timeout_s", "api_key"])
    def test_settings_patch_llm_unknown_field_is_rejected(self, key: str) -> None:
        _rejects(SettingsPatchLLM, {"provider": "openai", key: "x"})

    @pytest.mark.parametrize("field", _MODEL_FIELDS)
    def test_settings_patch_llm_model_name_with_trailing_newline_is_rejected(
        self, field: str
    ) -> None:
        """Python's '$' matches before a final newline; the rule is a full match."""
        _rejects(SettingsPatchLLM, {field: "gpt-4o\n"})


# ---------------------------------------------------------------------------
# 5. PlatformLimits
# ---------------------------------------------------------------------------


class TestPlatformLimits:
    """The five LimitsConfig limits, with the same bounds."""

    def test_platform_limits_fields_equal_limits_config(self) -> None:
        assert set(LimitsConfig.model_fields) == set(_LIMIT_BOUNDS)
        assert set(_model("PlatformLimits").model_fields) == set(LimitsConfig.model_fields)

    @pytest.mark.parametrize("name", sorted(_LIMIT_BOUNDS))
    def test_platform_limits_bounds_are_accepted(self, name: str) -> None:
        low, high = _LIMIT_BOUNDS[name]
        model = _model("PlatformLimits")

        assert _field_bounds(name) == (low, high)
        assert getattr(model.model_validate(_limits(**{name: low})), name) == low
        assert getattr(model.model_validate(_limits(**{name: high})), name) == high

    @pytest.mark.parametrize("name", sorted(_LIMIT_BOUNDS))
    def test_platform_limits_out_of_bounds_are_rejected(self, name: str) -> None:
        low, high = _LIMIT_BOUNDS[name]

        _rejects(_model("PlatformLimits"), _limits(**{name: low - 1}))
        _rejects(_model("PlatformLimits"), _limits(**{name: high + 1}))

    def test_platform_limits_round_trips_the_config_defaults(self) -> None:
        defaults = LimitsConfig().model_dump()

        assert _model("PlatformLimits").model_validate(defaults).model_dump() == defaults


# ---------------------------------------------------------------------------
# 6. The three response bodies
# ---------------------------------------------------------------------------


class TestScopedSettingsResponses:
    """Each response carries exactly its scope's sections."""

    def test_user_settings_response_shape(self) -> None:
        model = _model("UserSettingsResponse")
        fields = model.model_fields

        assert set(fields) == {"appearance", "notifications"}
        assert fields["appearance"].annotation is SettingsAppearance
        assert fields["notifications"].annotation is SettingsNotifications

    def test_user_settings_response_defaults_dump(self) -> None:
        body = _model("UserSettingsResponse")(
            appearance=SettingsAppearance(), notifications=SettingsNotifications()
        )

        assert body.model_dump() == {
            "appearance": {"theme": "light"},
            "notifications": {"enabled": True},
        }

    def test_org_settings_response_shape(self) -> None:
        fields = _model("OrgSettingsResponse").model_fields

        assert set(fields) == {"tools"}
        assert fields["tools"].annotation is ToolsSettings

    def test_org_settings_response_defaults_dump(self) -> None:
        body = _model("OrgSettingsResponse")(tools=ToolsSettings())

        assert body.model_dump() == {"tools": dict.fromkeys(_TOOLS, True)}

    def test_platform_settings_response_shape(self) -> None:
        fields = _model("PlatformSettingsResponse").model_fields

        assert set(fields) == {"llm", "limits"}
        assert fields["llm"].annotation is SettingsLLM
        assert fields["limits"].annotation is _model("PlatformLimits")

    def test_platform_settings_response_dump(self) -> None:
        limits = _model("PlatformLimits").model_validate(LimitsConfig().model_dump())
        llm = SettingsLLM(provider="infomaniak", anthropic_model="", openai_model="")

        body = _model("PlatformSettingsResponse")(llm=llm, limits=limits)
        dumped = json.loads(body.model_dump_json())

        assert set(dumped) == {"llm", "limits"}
        assert dumped["limits"] == LimitsConfig().model_dump()
        assert dumped["llm"]["provider"] == "infomaniak"
