"""Tests for the scoped settings API models in admino.models (GH-159).

The single ``/api/settings`` body is split into three scopes, each with its own
request and response models: user (``/api/me/settings``: theme and
notifications), org (``/api/org/settings``: the enabled tool services) and
platform (``/api/platform/settings``: the LLM provider and models, plus the
limits, which GH-160 makes editable next to the files, retention and security
defaults; those sections are pinned in tests/test_platform_settings_models.py).

What these tests pin down:
- The old combined models are gone: ``SettingsResponse``, ``SettingsPatch``,
  ``SettingsImmutable``, ``SettingsConnectedAccounts``, ``SettingsPatchTools``,
  ``SettingsLimits``.
- ``UserSettingsPatch``: ``appearance`` / ``notifications`` only; unknown keys
  refused at every level (``llm``, ``tools``, ``limits``, ``ui_language`` ...);
  strict bools; the theme is one of light, dark, system; at least one leaf
  value must be given (a null counts as not given).
- ``OrgSettingsPatch`` / ``OrgToolsPatch``: ``tools`` is an optional section
  since GH-169 (next to profile, instructions, security and retention, pinned in
  tests/test_org_settings_models.py); the seven tool names of ``ToolsSettings``
  only (an unknown tool such as ``files`` and an ``org_id`` in the body are
  refused, never ignored); strict bools; a tools-only patch needs at least one
  tool given.
- ``PlatformSettingsPatch``: ``llm`` is optional (GH-160 adds the ``limits``,
  ``files``, ``retention`` and ``security`` sections, so a ``limits`` key is now
  accepted); any other key is refused; an llm-only patch needs at least one llm
  field. ``SettingsPatchLLM`` refuses
  unknown fields (so ``vllm_base_url``, ``timeout_s`` or a key can never be
  patched) and model names must fully match ``[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,199}``
  (a trailing newline is refused: the database CHECK would reject it with a 500).
- ``PlatformLimits`` has exactly the ``LimitsConfig`` fields and bounds
  (GH-190: ``max_context_messages`` is 0 to 200, where 0 means no cap).
- ``UserSettingsResponse``, ``OrgSettingsResponse`` and
  ``PlatformSettingsResponse`` carry exactly their scope's sections (the
  platform one: llm, limits, files, retention, security since GH-160; the org
  one: tools plus the required, read-only ``data_residency`` bool since GH-162,
  and profile, instructions, security, retention and plan since GH-169).
- Validation errors of the request models never repeat the rejected input.
- GH-35 (task-done pings), retargeted by GH-307: ``notifications.completed``
  replaces ``task_done`` and ``notifications.approvals`` replaces ``enabled``.
  ``SettingsNotifications`` is ``{approvals: True, completed: True}`` by
  default (neither is a master switch for the other);
  ``SettingsPatchNotifications.approvals`` / ``.completed`` are strict bools or
  null, refused at their own loc with ``bool_type`` (not as an unknown key);
  a completed-only patch is valid, an all-null one is refused by the "at least
  one value" rule.
- GH-307 (account preferences): ``SettingsAppearance`` is ``{theme: "light",
  density: "comfortable"}`` by default and the density is exactly
  ``comfortable`` or ``compact`` (refused at its own loc with
  ``literal_error``); ``UserSettingsResponse`` dumps ``{appearance: {theme,
  density}, notifications: {approvals, completed}}``. The old keys
  ``notifications.enabled`` / ``notifications.task_done`` are unknown fields
  (``extra_forbidden``), like any other unknown key at any level. A density-,
  approvals- or completed-only patch is "something given"; an all-null patch is
  refused with the fixed message "Give at least one setting to change."
  (a ``FixedMessageError``); no error repeats the input.

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
    "max_context_messages": (0, 200),
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


# GH-169: the org settings response's other sections (a fresh org's values).
_ORG_SETTINGS_SECTIONS: dict[str, Any] = {
    "profile": {"display_name": "Treuhand Muster AG", "default_response_language": "en"},
    "instructions": "",
    "security": {"session_idle_timeout_minutes": 60, "session_max_lifetime_hours": 12},
    "retention": {"trash_retention_days": 30, "trash_min_days": 0, "trash_max_days": 90},
    "plan": {"seats": 10, "storage_quota": 1024},
}


def _org_settings_sections() -> dict[str, Any]:
    """Every OrgSettingsResponse field but tools and data_residency (GH-169), as JSON values
    plus the GH-162 tools."""
    return {**json.loads(json.dumps(_ORG_SETTINGS_SECTIONS)), "tools": ToolsSettings()}


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
            {"notifications": {"approvals": True}},
            {"notifications": {"approvals": False}},
            {"appearance": {"theme": "dark"}, "notifications": {"approvals": False}},
        ],
    )
    def test_user_settings_patch_valid_payload_is_accepted(self, payload: dict[str, Any]) -> None:
        patch = _model("UserSettingsPatch").model_validate(payload)

        assert patch.model_dump(exclude_none=True) == payload

    def test_user_settings_patch_accepts_a_json_body(self) -> None:
        patch = _model("UserSettingsPatch").model_validate_json(
            '{"notifications": {"approvals": false}}'
        )

        assert patch.model_dump(exclude_none=True) == {"notifications": {"approvals": False}}

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
        ("payload", "loc"),
        [
            ({"appearance": {"theme": "dark", "font": "mono"}}, ("appearance", "font")),
            ({"notifications": {"approvals": True, "sound": True}}, ("notifications", "sound")),
        ],
    )
    def test_user_settings_patch_unknown_nested_key_is_rejected(
        self, payload: dict[str, Any], loc: tuple[str, ...]
    ) -> None:
        """Only the unknown key is refused, not the valid one next to it."""
        exc = _rejects(_model("UserSettingsPatch"), payload)

        assert _locs_and_types(exc) == [(loc, "extra_forbidden")]

    @pytest.mark.parametrize("value", _NOT_STRICT_BOOLS)
    def test_user_settings_patch_notifications_approvals_is_a_strict_bool(
        self, value: object
    ) -> None:
        """Refused as a non-bool at approvals itself, not as an unknown key."""
        exc = _rejects(_model("UserSettingsPatch"), {"notifications": {"approvals": value}})

        assert _locs_and_types(exc) == [(("notifications", "approvals"), "bool_type")]

    @pytest.mark.parametrize(
        "body", ['{"notifications": {"approvals": 1}}', '{"notifications": {"approvals": "true"}}']
    )
    def test_user_settings_patch_json_bool_is_strict(self, body: str) -> None:
        with pytest.raises(ValidationError) as exc_info:
            _model("UserSettingsPatch").model_validate_json(body)

        assert _locs_and_types(exc_info.value) == [(("notifications", "approvals"), "bool_type")]

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
            {"notifications": {"approvals": None}},
            {"appearance": {}, "notifications": {}},
            {"appearance": None, "notifications": None},
        ],
    )
    def test_user_settings_patch_without_any_value_is_rejected(
        self, payload: dict[str, Any]
    ) -> None:
        """A patch must change something; a null counts as not given (refused by the
        "at least one value" rule, not as an unknown key)."""
        exc = _rejects(_model("UserSettingsPatch"), payload)

        assert _locs_and_types(exc) == [((), "value_error")]

    @pytest.mark.parametrize(
        ("payload", "expected"),
        [
            ({"appearance": {"theme": _SENTINEL}}, [(("appearance", "theme"), "literal_error")]),
            (
                {"notifications": {"approvals": _SENTINEL}},
                [(("notifications", "approvals"), "bool_type")],
            ),
            ({"appearance": {"theme": "dark"}, "llm": _SENTINEL}, [(("llm",), "extra_forbidden")]),
            (
                {"appearance": {"theme": "dark", "font": _SENTINEL}},
                [(("appearance", "font"), "extra_forbidden")],
            ),
        ],
    )
    def test_user_settings_patch_errors_never_repeat_the_input(
        self, payload: dict[str, Any], expected: list[tuple[tuple[str, ...], str]]
    ) -> None:
        exc = _rejects(_model("UserSettingsPatch"), payload)

        assert _locs_and_types(exc) == expected
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

    def test_org_settings_patch_tools_is_an_optional_section(self) -> None:
        """GH-169: tools is one of five optional sections (OrgToolsPatch | None)."""
        fields = _model("OrgSettingsPatch").model_fields

        assert set(fields) == {"profile", "instructions", "security", "retention", "tools"}
        assert set(typing.get_args(fields["tools"].annotation)) == {
            _model("OrgToolsPatch"),
            type(None),
        }
        assert not fields["tools"].is_required()

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
    def test_org_settings_patch_without_tools_or_another_section_is_rejected(
        self, payload: dict[str, Any]
    ) -> None:
        """GH-169: tools is optional, but a body giving nothing at all is still refused."""
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
    """The platform LLM (provider and models); since GH-160 also the other sections."""

    def test_platform_settings_patch_llm_is_an_optional_section(self) -> None:
        """GH-160: llm is one of five optional sections (it was the only, required one)."""
        fields = _model("PlatformSettingsPatch").model_fields

        # GH-242: the request-level residency confirmation, and the active
        # model's capabilities and retry limit in the llm section.
        assert set(fields) == {
            "llm",
            "limits",
            "files",
            "retention",
            "security",
            "confirm_residency_orgs",
        }
        assert SettingsPatchLLM in typing.get_args(fields["llm"].annotation)
        assert not fields["llm"].is_required()
        assert set(SettingsPatchLLM.model_fields) == {
            "provider",
            *_MODEL_FIELDS,
            "max_input_tokens",
            "image_input",
            "max_retries",
        }

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
    def test_platform_settings_patch_without_any_section_is_rejected(
        self, payload: dict[str, Any]
    ) -> None:
        _rejects(_model("PlatformSettingsPatch"), payload)

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("tools", {"gmail": False}),
            ("appearance", {"theme": "dark"}),
            ("notifications", {"enabled": False}),
            ("server", {"port": 1}),
            ("org_id", "00000000-0000-4000-8000-000000000001"),
        ],
    )
    def test_platform_settings_patch_unknown_top_level_key_is_rejected(
        self, key: str, value: object
    ) -> None:
        """Another scope's key is refused, never silently dropped."""
        _rejects(_model("PlatformSettingsPatch"), {"llm": {"provider": "openai"}, key: value})

    @pytest.mark.parametrize(
        "payload",
        [
            {"llm": {"provider": "openai"}, "limits": {"max_message_length": 100}},
            {"limits": {"max_message_length": 100}},
        ],
    )
    def test_platform_settings_patch_limits_key_is_accepted(self, payload: dict[str, Any]) -> None:
        """GH-160 makes the limits editable: the key #159 refused is now accepted."""
        patch = _model("PlatformSettingsPatch").model_validate(payload)

        assert patch.model_dump(exclude_none=True) == payload

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
            "appearance": {"theme": "light", "density": "comfortable"},
            "notifications": {"approvals": True, "completed": True},
        }

    def test_org_settings_response_shape(self) -> None:
        """GH-162 adds the org's data residency policy (required, read-only here); GH-169
        adds profile, instructions, security, retention and plan."""
        fields = _model("OrgSettingsResponse").model_fields

        assert set(fields) == {
            "profile",
            "instructions",
            "security",
            "retention",
            "tools",
            "data_residency",
            "plan",
        }
        assert fields["tools"].annotation is ToolsSettings
        assert fields["data_residency"].annotation is bool
        assert fields["data_residency"].is_required()

    def test_org_settings_response_defaults_dump(self) -> None:
        body = _model("OrgSettingsResponse")(**_org_settings_sections(), data_residency=False)

        assert body.model_dump() == {
            **_ORG_SETTINGS_SECTIONS,
            "tools": dict.fromkeys(_TOOLS, True),
            "data_residency": False,
        }

    def test_org_settings_response_without_data_residency_is_refused(self) -> None:
        """GH-162: a response can't silently omit the residency policy."""
        with pytest.raises(ValidationError) as error:
            _model("OrgSettingsResponse")(**_org_settings_sections())

        assert [tuple(item["loc"]) for item in error.value.errors()] == [("data_residency",)]

    def test_platform_settings_response_shape(self) -> None:
        """GH-160 adds files, retention and security next to llm and limits."""
        fields = _model("PlatformSettingsResponse").model_fields

        assert set(fields) == {"llm", "limits", "files", "retention", "security"}
        assert fields["llm"].annotation is SettingsLLM
        assert fields["limits"].annotation is _model("PlatformLimits")
        assert fields["files"].annotation is _model("PlatformFiles")
        assert fields["retention"].annotation is _model("PlatformRetention")
        assert fields["security"].annotation is _model("PlatformSecurity")

    def test_platform_settings_response_dump(self) -> None:
        limits = _model("PlatformLimits").model_validate(LimitsConfig().model_dump())
        llm = SettingsLLM(provider="infomaniak", anthropic_model="", openai_model="")

        body = _model("PlatformSettingsResponse")(
            llm=llm,
            limits=limits,
            files=_model("PlatformFiles")(),
            retention=_model("PlatformRetention")(),
            security=_model("PlatformSecurity")(),
        )
        dumped = json.loads(body.model_dump_json())

        assert set(dumped) == {"llm", "limits", "files", "retention", "security"}
        assert dumped["limits"] == LimitsConfig().model_dump()
        assert dumped["llm"]["provider"] == "infomaniak"


# ---------------------------------------------------------------------------
# 7. GH-35's notification preferences, retargeted by GH-307: notifications.completed
#    replaces task_done, notifications.approvals replaces enabled
# ---------------------------------------------------------------------------

_ECHOMARK = "ECHOMARK-307-notify"
# GH-35's list ("yes", 1, 0, "true", [1], {}) plus the other lax-bool lookalikes.
_NOT_PATCH_BOOLS: tuple[object, ...] = (
    "yes",
    1,
    0,
    "true",
    [1],
    {},
    "false",
    "1",
    "on",
    1.0,
)


def _locs_and_types(exc: ValidationError) -> list[tuple[tuple[int | str, ...], str]]:
    return [
        (tuple(error["loc"]), error["type"])
        for error in exc.errors(include_input=False, include_url=False)
    ]


class TestSettingsNotificationsCompleted:
    """The response part: approvals (actions waiting for a decision) and completed
    (finished tasks and routine runs), both on by default (GH-307)."""

    def test_settings_notifications_fields_are_approvals_and_completed(self) -> None:
        fields = models_module.SettingsNotifications.model_fields

        assert set(fields) == {"approvals", "completed"}
        assert fields["approvals"].annotation is bool
        assert fields["completed"].annotation is bool

    def test_settings_notifications_defaults_approvals_and_completed_on(self) -> None:
        """Both start on (GH-307's defaults; GH-35's task_done started off)."""
        notifications = models_module.SettingsNotifications()

        assert notifications.model_dump() == {"approvals": True, "completed": True}

    @pytest.mark.parametrize(
        ("approvals", "completed"), [(True, True), (True, False), (False, True), (False, False)]
    )
    def test_settings_notifications_completed_is_independent_of_approvals(
        self, approvals: bool, completed: bool
    ) -> None:
        """Neither value is a master switch for the other."""
        notifications = models_module.SettingsNotifications(
            approvals=approvals, completed=completed
        )

        assert notifications.model_dump() == {"approvals": approvals, "completed": completed}


class TestSettingsPatchNotificationsCompleted:
    """approvals and completed: strict bools or null; unknown keys still refused."""

    def test_settings_patch_notifications_fields_are_approvals_and_completed(self) -> None:
        fields = SettingsPatchNotifications.model_fields

        assert set(fields) == {"approvals", "completed"}
        assert fields["completed"].annotation == fields["approvals"].annotation
        assert [fields[name].default for name in ("approvals", "completed")] == [None, None]
        assert not fields["approvals"].is_required()
        assert not fields["completed"].is_required()

    @pytest.mark.parametrize("value", [True, False, None])
    def test_settings_patch_notifications_completed_value_is_accepted(
        self, value: bool | None
    ) -> None:
        patch = SettingsPatchNotifications.model_validate({"completed": value})

        assert patch.model_dump() == {"approvals": None, "completed": value}

    def test_settings_patch_notifications_completed_defaults_to_not_given(self) -> None:
        patch = SettingsPatchNotifications.model_validate({"approvals": False})

        assert patch.model_dump() == {"approvals": False, "completed": None}

    @pytest.mark.parametrize("value", _NOT_PATCH_BOOLS, ids=repr)
    def test_settings_patch_notifications_completed_is_a_strict_bool(self, value: object) -> None:
        """Refused as a non-bool at completed itself, not as an unknown key."""
        exc = _rejects(SettingsPatchNotifications, {"completed": value})

        assert _locs_and_types(exc) == [(("completed",), "bool_type")]

    def test_settings_patch_notifications_completed_error_never_echoes_the_input(self) -> None:
        exc = _rejects(SettingsPatchNotifications, {"completed": _ECHOMARK})

        assert _locs_and_types(exc) == [(("completed",), "bool_type")]
        assert _ECHOMARK not in str(exc)

    @pytest.mark.parametrize("key", ["sound", "Completed", "completedAt", "completed_at", "all"])
    def test_settings_patch_notifications_unknown_key_is_still_rejected(self, key: str) -> None:
        """With a valid completed next to it, only the unknown key is refused."""
        exc = _rejects(SettingsPatchNotifications, {"completed": True, key: _ECHOMARK})

        assert _locs_and_types(exc) == [((key,), "extra_forbidden")]
        assert _ECHOMARK not in str(exc)


class TestUserSettingsPatchCompleted:
    """A completed-only patch is valid; an all-null one is refused."""

    @pytest.mark.parametrize("value", [True, False])
    def test_user_settings_patch_completed_only_is_accepted(self, value: bool) -> None:
        payload = {"notifications": {"completed": value}}

        patch = _model("UserSettingsPatch").model_validate(payload)

        assert patch.model_dump(exclude_none=True) == payload

    @pytest.mark.parametrize(
        ("payload", "expected"),
        [
            (
                {"notifications": {"approvals": True, "completed": False}},
                (None, None, True, False),
            ),
            (
                {"notifications": {"approvals": None, "completed": True}},
                (None, None, None, True),
            ),
            (
                {"notifications": {"approvals": False, "completed": None}},
                (None, None, False, None),
            ),
            (
                {"appearance": {"theme": "dark"}, "notifications": {"completed": True}},
                ("dark", None, None, True),
            ),
            (
                {"appearance": {"theme": None}, "notifications": {"completed": False}},
                (None, None, None, False),
            ),
            (
                {"appearance": None, "notifications": {"completed": True}},
                (None, None, None, True),
            ),
            (
                {"appearance": {"theme": "light"}, "notifications": {"completed": None}},
                ("light", None, None, None),
            ),
            (
                {"appearance": {"density": "compact"}, "notifications": {"approvals": None}},
                (None, "compact", None, None),
            ),
            (
                {"appearance": {"theme": None, "density": "comfortable"}},
                (None, "comfortable", None, None),
            ),
            (
                {
                    "appearance": {"theme": "system", "density": "compact"},
                    "notifications": {"approvals": False, "completed": True},
                },
                ("system", "compact", False, True),
            ),
        ],
    )
    def test_user_settings_patch_any_mix_with_a_value_is_accepted(
        self,
        payload: dict[str, Any],
        expected: tuple[str | None, str | None, bool | None, bool | None],
    ) -> None:
        """(theme, density, approvals, completed) as given; a null or missing value stays
        None."""
        patch = models_module.UserSettingsPatch.model_validate(payload)
        appearance = patch.appearance
        notifications = patch.notifications

        assert (
            None if appearance is None else appearance.theme,
            None if appearance is None else getattr(appearance, "density", "missing"),
            None if notifications is None else getattr(notifications, "approvals", "missing"),
            None if notifications is None else getattr(notifications, "completed", "missing"),
        ) == expected

    def test_user_settings_patch_completed_json_body_is_accepted(self) -> None:
        patch = _model("UserSettingsPatch").model_validate_json(
            '{"notifications": {"completed": true}}'
        )

        assert patch.model_dump(exclude_none=True) == {"notifications": {"completed": True}}

    @pytest.mark.parametrize(
        "payload",
        [
            {"notifications": {"completed": None}},
            {"notifications": {"approvals": None, "completed": None}},
            {"appearance": {"theme": None}, "notifications": {"completed": None}},
            {"appearance": None, "notifications": {"approvals": None, "completed": None}},
            {"appearance": {}, "notifications": {"completed": None}},
        ],
    )
    def test_user_settings_patch_null_completed_alone_is_refused_as_empty(
        self, payload: dict[str, Any]
    ) -> None:
        """Refused by the 'at least one value' rule, not as an unknown key."""
        exc = _rejects(_model("UserSettingsPatch"), payload)

        errors = exc.errors(include_input=False, include_url=False)
        assert _locs_and_types(exc) == [((), "value_error")]
        assert "Give at least one setting to change." in errors[0]["msg"]

    @pytest.mark.parametrize("value", _NOT_PATCH_BOOLS, ids=repr)
    def test_user_settings_patch_completed_is_a_strict_bool(self, value: object) -> None:
        exc = _rejects(_model("UserSettingsPatch"), {"notifications": {"completed": value}})

        assert _locs_and_types(exc) == [(("notifications", "completed"), "bool_type")]

    @pytest.mark.parametrize(
        "body",
        [
            '{"notifications": {"completed": 1}}',
            '{"notifications": {"completed": 0}}',
            '{"notifications": {"completed": "true"}}',
            '{"notifications": {"completed": "yes"}}',
        ],
    )
    def test_user_settings_patch_completed_json_bool_is_strict(self, body: str) -> None:
        with pytest.raises(ValidationError) as exc_info:
            _model("UserSettingsPatch").model_validate_json(body)

        assert _locs_and_types(exc_info.value) == [(("notifications", "completed"), "bool_type")]

    @pytest.mark.parametrize(
        ("payload", "expected"),
        [
            (
                {"notifications": {"completed": _ECHOMARK}},
                [(("notifications", "completed"), "bool_type")],
            ),
            (
                {"notifications": {"completed": [_ECHOMARK]}},
                [(("notifications", "completed"), "bool_type")],
            ),
            (
                {"notifications": {"completed": True, "sound": _ECHOMARK}},
                [(("notifications", "sound"), "extra_forbidden")],
            ),
        ],
    )
    def test_user_settings_patch_completed_errors_never_echo_the_input(
        self, payload: dict[str, Any], expected: list[tuple[tuple[str, ...], str]]
    ) -> None:
        exc = _rejects(_model("UserSettingsPatch"), payload)

        assert _locs_and_types(exc) == expected
        assert _ECHOMARK not in str(exc)


class TestUserSettingsResponseCompleted:
    """GET/PATCH /api/me/settings carry appearance {theme, density} and notifications
    {approvals, completed}."""

    @pytest.mark.parametrize(
        ("theme", "density", "approvals", "completed"),
        [
            ("dark", "compact", False, True),
            ("system", "comfortable", True, True),
            ("light", "compact", True, False),
        ],
    )
    def test_user_settings_response_dumps_the_four_settings(
        self, theme: str, density: str, approvals: bool, completed: bool
    ) -> None:
        payload = {
            "appearance": {"theme": theme, "density": density},
            "notifications": {"approvals": approvals, "completed": completed},
        }

        body = _model("UserSettingsResponse").model_validate(payload)

        assert body.model_dump() == payload

    def test_user_settings_response_json_has_exactly_the_four_settings(self) -> None:
        body = _model("UserSettingsResponse")(
            appearance=SettingsAppearance.model_validate({"theme": "dark", "density": "compact"}),
            notifications=models_module.SettingsNotifications.model_validate(
                {"approvals": False, "completed": False}
            ),
        )

        assert json.loads(body.model_dump_json()) == {
            "appearance": {"theme": "dark", "density": "compact"},
            "notifications": {"approvals": False, "completed": False},
        }

    def test_user_settings_response_without_completed_reads_as_on(self) -> None:
        """A notifications part without completed takes the default (on), like a missing
        row."""
        body = _model("UserSettingsResponse").model_validate(
            {"appearance": {"theme": "light"}, "notifications": {"approvals": False}}
        )

        assert body.model_dump() == {
            "appearance": {"theme": "light", "density": "comfortable"},
            "notifications": {"approvals": False, "completed": True},
        }


# ---------------------------------------------------------------------------
# 8. GH-307: density, approvals and completed replace enabled and task_done
# ---------------------------------------------------------------------------

_MARK307 = "ECHOMARK-307-pref"
_DENSITIES = ("comfortable", "compact")
_FIXED_EMPTY_MESSAGE = "Give at least one setting to change."
# The three new leaves of a patch, each with a value that is not its default.
_NEW_LEAVES = [
    pytest.param("appearance", "density", "compact", id="density"),
    pytest.param("notifications", "approvals", False, id="approvals"),
    pytest.param("notifications", "completed", False, id="completed"),
]


class TestDefaultsGH307:
    """A user without a row reads light, comfortable, approvals on, completed on."""

    def test_settings_appearance_defaults_are_light_and_comfortable(self) -> None:
        assert SettingsAppearance().model_dump() == {"theme": "light", "density": "comfortable"}

    def test_user_settings_response_of_the_default_parts_is_the_four_defaults(self) -> None:
        body = _model("UserSettingsResponse")(
            appearance=SettingsAppearance(), notifications=SettingsNotifications()
        )

        assert json.loads(body.model_dump_json()) == {
            "appearance": {"theme": "light", "density": "comfortable"},
            "notifications": {"approvals": True, "completed": True},
        }


class TestDensityGH307:
    """appearance.density: exactly comfortable or compact; a null is not given."""

    def test_settings_appearance_density_is_comfortable_or_compact(self) -> None:
        field = SettingsAppearance.model_fields.get("density")

        assert field is not None
        assert set(typing.get_args(field.annotation)) == set(_DENSITIES)
        assert field.default == "comfortable"

    def test_settings_patch_appearance_fields_are_theme_and_density(self) -> None:
        fields = SettingsPatchAppearance.model_fields

        assert set(fields) == {"theme", "density"}
        assert fields["density"].default is None
        assert not fields["density"].is_required()

    @pytest.mark.parametrize("density", _DENSITIES)
    def test_settings_appearance_density_value_is_kept(self, density: str) -> None:
        appearance = SettingsAppearance.model_validate({"theme": "dark", "density": density})

        assert appearance.model_dump() == {"theme": "dark", "density": density}

    @pytest.mark.parametrize("density", _DENSITIES)
    def test_user_settings_patch_density_only_is_accepted(self, density: str) -> None:
        payload = {"appearance": {"density": density}}

        patch = _model("UserSettingsPatch").model_validate(payload)

        assert patch.model_dump(exclude_none=True) == payload

    def test_user_settings_patch_density_json_body_is_accepted(self) -> None:
        patch = _model("UserSettingsPatch").model_validate_json(
            '{"appearance": {"density": "compact"}}'
        )

        assert patch.model_dump(exclude_none=True) == {"appearance": {"density": "compact"}}

    @pytest.mark.parametrize("density", ["tiny", "Compact", 1], ids=repr)
    def test_user_settings_patch_unknown_density_is_refused_at_its_loc(
        self, density: object
    ) -> None:
        """Not a member (or not a string): a literal_error at density, not an unknown key."""
        exc = _rejects(_model("UserSettingsPatch"), {"appearance": {"density": density}})

        assert _locs_and_types(exc) == [(("appearance", "density"), "literal_error")]

    def test_user_settings_patch_null_density_is_not_given(self) -> None:
        """A null density next to a theme is accepted and stays not given."""
        patch = _model("UserSettingsPatch").model_validate(
            {"appearance": {"theme": "dark", "density": None}}
        )

        assert patch.model_dump() == {
            "appearance": {"theme": "dark", "density": None},
            "notifications": None,
        }


class TestUserSettingsPatchGH307:
    """The new leaves count as given; the old keys and any unknown key are refused."""

    @pytest.mark.parametrize(("section", "field", "value"), _NEW_LEAVES)
    def test_user_settings_patch_one_new_setting_alone_counts_as_given(
        self, section: str, field: str, value: object
    ) -> None:
        payload = {section: {field: value}}

        patch = _model("UserSettingsPatch").model_validate(payload)

        assert patch.model_dump(exclude_none=True) == payload

    @pytest.mark.parametrize("key", ["enabled", "task_done"])
    @pytest.mark.parametrize(
        "neighbour",
        [{}, {"approvals": True}, {"completed": False}],
        ids=["alone", "next-to-approvals", "next-to-completed"],
    )
    def test_user_settings_patch_old_notification_key_is_refused_as_unknown(
        self, key: str, neighbour: dict[str, bool]
    ) -> None:
        """GH-307 replaces enabled and task_done: each is an unknown field now."""
        exc = _rejects(_model("UserSettingsPatch"), {"notifications": {**neighbour, key: False}})

        assert _locs_and_types(exc) == [(("notifications", key), "extra_forbidden")]

    @pytest.mark.parametrize(
        ("payload", "loc"),
        [
            (
                {"appearance": {"density": "compact", "font": "mono"}},
                ("appearance", "font"),
            ),
            (
                {"notifications": {"completed": True, "sound": True}},
                ("notifications", "sound"),
            ),
            ({"appearance": {"density": "compact"}, "density": "compact"}, ("density",)),
            ({"notifications": {"approvals": True}, "approvals": True}, ("approvals",)),
        ],
        ids=["appearance", "notifications", "top-level-density", "top-level-approvals"],
    )
    def test_user_settings_patch_unknown_key_next_to_a_new_setting_is_refused(
        self, payload: dict[str, Any], loc: tuple[str, ...]
    ) -> None:
        """Only the unknown key is refused; the valid new setting next to it is not."""
        exc = _rejects(_model("UserSettingsPatch"), payload)

        assert _locs_and_types(exc) == [(loc, "extra_forbidden")]

    @pytest.mark.parametrize(
        "payload",
        [
            {"appearance": {"density": None}},
            {"notifications": {"approvals": None}},
            {"appearance": {"density": None}, "notifications": {"completed": None}},
            {
                "appearance": {"theme": None, "density": None},
                "notifications": {"approvals": None, "completed": None},
            },
        ],
        ids=["density", "approvals", "density-completed", "all-four"],
    )
    def test_user_settings_patch_all_null_is_refused_with_the_fixed_message(
        self, payload: dict[str, Any]
    ) -> None:
        """A null counts as not given: the model-level FixedMessageError, nothing else."""
        exc = _rejects(_model("UserSettingsPatch"), payload)

        errors = exc.errors(include_input=False, include_url=False)
        assert _locs_and_types(exc) == [((), "value_error")]
        error = errors[0]["ctx"]["error"]
        assert isinstance(error, models_module.FixedMessageError)
        assert str(error) == _FIXED_EMPTY_MESSAGE

    @pytest.mark.parametrize(
        ("payload", "expected"),
        [
            (
                {"appearance": {"density": _MARK307}},
                [(("appearance", "density"), "literal_error")],
            ),
            (
                {"notifications": {"approvals": _MARK307}},
                [(("notifications", "approvals"), "bool_type")],
            ),
            (
                {"notifications": {"completed": _MARK307}},
                [(("notifications", "completed"), "bool_type")],
            ),
            (
                {"notifications": {"enabled": _MARK307}},
                [(("notifications", "enabled"), "extra_forbidden")],
            ),
            (
                {"notifications": {"task_done": _MARK307}},
                [(("notifications", "task_done"), "extra_forbidden")],
            ),
        ],
        ids=["density", "approvals", "completed", "enabled", "task_done"],
    )
    def test_user_settings_patch_gh307_errors_never_echo_the_input(
        self, payload: dict[str, Any], expected: list[tuple[tuple[str, ...], str]]
    ) -> None:
        exc = _rejects(_model("UserSettingsPatch"), payload)

        assert _locs_and_types(exc) == expected
        assert _MARK307 not in str(exc)

    def test_settings_patch_appearance_density_error_never_echoes_the_input(self) -> None:
        """The part model hides the input too (hide_input_in_errors)."""
        exc = _rejects(SettingsPatchAppearance, {"density": _MARK307})

        assert _locs_and_types(exc) == [(("density",), "literal_error")]
        assert _MARK307 not in str(exc)
