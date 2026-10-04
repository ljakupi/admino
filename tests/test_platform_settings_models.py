"""Tests for the platform defaults models in admino.models (GH-160).

The Super Admin's platform settings grow from the LLM and the (read-only)
limits of #159 to five editable sections: ``llm``, ``limits``, ``files``,
``retention`` and ``security``. Each section has a response model (the stored
values) and a patch model (the values to change).

What these tests pin down:
- ``PlatformFiles``, ``PlatformRetention``, ``PlatformSecurity``: exactly the
  issue's fields, the issue's defaults (``PlatformFiles()`` etc. give them) and
  the issue's inclusive bounds (low and high accepted, low - 1 and high + 1
  refused). ``PlatformRetention`` refuses ``trash_min_days > trash_max_days``
  and its message never repeats the values.
- The session and audit bounds stay single-sourced: ``PlatformSecurity``'s
  session fields use ``admino.sessions``' MIN/MAX/DEFAULT constants and
  ``PlatformRetention.audit_months`` uses ``admino.audit_events``' retention
  constants.
- ``PlatformSettingsResponse`` carries the five sections.
- ``PlatformLimitsPatch``, ``PlatformFilesPatch``, ``PlatformRetentionPatch``,
  ``PlatformSecurityPatch``: the section's fields only, every one optional
  (default None), strict ints (a bool, a float, a numeric string or a Decimal
  is refused, in Python and in JSON), the same bounds, unknown keys refused.
  The retention patch does not compare min and max itself (the service checks
  the merged values).
- ``PlatformSettingsPatch``: the five sections, each optional; ``limits`` is
  now accepted (#159 refused it); any other top-level key is refused; at
  least one non-null field across all sections ("Give at least one setting to
  change."), where an empty section or a null counts as not given; an llm-only
  patch still works as in #159.
- Validation errors of every patch model never repeat the rejected input.

New symbols are looked up per test, so a missing model fails its own tests and
not the whole module.

Security notes:
- extra="forbid" everywhere: a client can't smuggle an unknown setting (for
  example the constant login delay, ``delay_after_failures``) or an org id
  into a patch and have it silently dropped or used.
- Strict ints: ``true``, ``"10"`` or ``10.5`` can never become a limit by
  coercion.
- The bounds mirror the database CHECKs of migration 0014
  (tests/test_migration_0014.py), so the API refuses what the database would.
- hide_input_in_errors: a 422 never echoes the body.
"""

from __future__ import annotations

import json
import typing
from decimal import Decimal
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

import admino.models as models_module
from admino import audit_events, sessions
from admino.config import LimitsConfig
from admino.models import SettingsLLM, SettingsPatchLLM

_SENTINEL = "ZZ-SENTINEL-42"
_HUGE = 987_654_321
_NOTHING_GIVEN = "Give at least one setting to change."

# field -> (default, low, high): the issue's Decisions table.
_FILES: dict[str, tuple[int, int, int]] = {
    "max_file_size_mb": (50, 1, 500),
    "max_files_per_message": (10, 1, 50),
    "max_pages_per_file": (100, 1, 1000),
    "render_dpi": (150, 72, 300),
}
_RETENTION: dict[str, tuple[int, int, int]] = {
    "trash_min_days": (0, 0, 90),
    "trash_max_days": (90, 0, 90),
    "audit_months": (12, 6, 84),
    "org_deletion_grace_days": (30, 7, 90),
}
_SECURITY: dict[str, tuple[int, int, int]] = {
    "rate_limit_per_minute": (20, 1, 600),
    "lockout_after_failures": (10, 3, 100),
    "lockout_window_minutes": (15, 1, 1440),
    "lockout_minutes": (15, 1, 1440),
    "session_idle_timeout_minutes": (60, 15, 480),
    "session_max_lifetime_hours": (12, 1, 72),
}
# The #159 limits (no model default: the config.yaml defaults are LimitsConfig's).
_LIMITS: dict[str, tuple[int, int, int]] = {
    "max_tool_calls_per_message": (10, 1, 100),
    "max_pending_confirmations": (3, 1, 50),
    "confirmation_timeout_s": (300, 10, 3600),
    "max_message_length": (4000, 1, 100_000),
    "max_context_messages": (20, 1, 200),
}
# section -> (response model, patch model, field table)
_SECTIONS: dict[str, tuple[str, str, dict[str, tuple[int, int, int]]]] = {
    "limits": ("PlatformLimits", "PlatformLimitsPatch", _LIMITS),
    "files": ("PlatformFiles", "PlatformFilesPatch", _FILES),
    "retention": ("PlatformRetention", "PlatformRetentionPatch", _RETENTION),
    "security": ("PlatformSecurity", "PlatformSecurityPatch", _SECURITY),
}
_NEW_SECTIONS = ("files", "retention", "security")
_PATCH_SECTIONS = ("llm", "limits", "files", "retention", "security")

# (section, field) for every editable integer setting.
_SECTION_FIELDS: tuple[tuple[str, str], ...] = tuple(
    (section, field) for section, (_, _, table) in _SECTIONS.items() for field in table
)
_NEW_SECTION_FIELDS: tuple[tuple[str, str], ...] = tuple(
    (section, field) for section, field in _SECTION_FIELDS if section in _NEW_SECTIONS
)


def _ids(pairs: tuple[tuple[str, str], ...]) -> list[str]:
    return [f"{section}.{field}" for section, field in pairs]


def _model(name: str) -> type[BaseModel]:
    """A GH-160 model from admino.models; fails the calling test when missing."""
    model = getattr(models_module, name, None)
    if model is None:
        pytest.fail(f"admino.models.{name} does not exist (GH-160)")
    assert isinstance(model, type)
    assert issubclass(model, BaseModel)
    return model


def _rejects(model: type[BaseModel], payload: object) -> ValidationError:
    with pytest.raises(ValidationError) as exc_info:
        model.model_validate(payload)
    return exc_info.value


def _table(section: str) -> dict[str, tuple[int, int, int]]:
    return _SECTIONS[section][2]


def _response(section: str) -> type[BaseModel]:
    return _model(_SECTIONS[section][0])


def _patch(section: str) -> type[BaseModel]:
    return _model(_SECTIONS[section][1])


def _defaults(section: str, **overrides: int) -> dict[str, int]:
    values = {field: default for field, (default, _, _) in _table(section).items()}
    values.update(overrides)
    return values


def _not_strict_ints(value: int) -> tuple[object, ...]:
    """Values a lax int field would coerce to ``value`` (or to 0/1)."""
    return (True, False, float(value), str(value), Decimal(value))


# ---------------------------------------------------------------------------
# 1. The response sections: fields, defaults, bounds
# ---------------------------------------------------------------------------


class TestPlatformSectionModels:
    """PlatformFiles, PlatformRetention and PlatformSecurity carry the issue's table."""

    @pytest.mark.parametrize("section", _NEW_SECTIONS)
    def test_platform_section_fields_are_the_issue_table(self, section: str) -> None:
        assert set(_response(section).model_fields) == set(_table(section))

    @pytest.mark.parametrize("section", _NEW_SECTIONS)
    def test_platform_section_defaults_are_the_issue_table(self, section: str) -> None:
        """PlatformFiles() (etc.) gives the defaults: an existing row takes them too."""
        assert _response(section)().model_dump() == _defaults(section)

    @pytest.mark.parametrize(
        ("section", "field"), _NEW_SECTION_FIELDS, ids=_ids(_NEW_SECTION_FIELDS)
    )
    def test_platform_section_field_default_is_declared_on_the_field(
        self, section: str, field: str
    ) -> None:
        info = _response(section).model_fields[field]

        assert not info.is_required()
        assert info.default == _table(section)[field][0]

    @pytest.mark.parametrize(
        ("section", "field"), _NEW_SECTION_FIELDS, ids=_ids(_NEW_SECTION_FIELDS)
    )
    def test_platform_section_inclusive_bounds_are_accepted(self, section: str, field: str) -> None:
        _, low, high = _table(section)[field]
        model = _response(section)

        assert getattr(model.model_validate(_defaults(section, **{field: low})), field) == low
        assert getattr(model.model_validate(_defaults(section, **{field: high})), field) == high

    @pytest.mark.parametrize(
        ("section", "field"), _NEW_SECTION_FIELDS, ids=_ids(_NEW_SECTION_FIELDS)
    )
    @pytest.mark.parametrize("side", ["below", "above"])
    def test_platform_section_out_of_bounds_is_rejected(
        self, section: str, field: str, side: str
    ) -> None:
        _, low, high = _table(section)[field]
        value = low - 1 if side == "below" else high + 1

        exc = _rejects(_response(section), _defaults(section, **{field: value}))

        assert [error["loc"] for error in exc.errors()] == [(field,)]

    def test_platform_security_session_fields_use_the_sessions_constants(self) -> None:
        """One source of truth for the Super Admin session policy bounds."""
        assert _SECURITY["session_idle_timeout_minutes"] == (
            sessions.DEFAULT_IDLE_TIMEOUT_MINUTES,
            sessions.MIN_IDLE_TIMEOUT_MINUTES,
            sessions.MAX_IDLE_TIMEOUT_MINUTES,
        )
        assert _SECURITY["session_max_lifetime_hours"] == (
            sessions.DEFAULT_LIFETIME_HOURS,
            sessions.MIN_LIFETIME_HOURS,
            sessions.MAX_LIFETIME_HOURS,
        )
        security = _model("PlatformSecurity")()
        assert security.session_idle_timeout_minutes == sessions.DEFAULT_IDLE_TIMEOUT_MINUTES
        assert security.session_max_lifetime_hours == sessions.DEFAULT_LIFETIME_HOURS

    def test_platform_retention_audit_months_uses_the_audit_events_constants(self) -> None:
        assert _RETENTION["audit_months"] == (
            audit_events.DEFAULT_RETENTION_MONTHS,
            audit_events.MIN_RETENTION_MONTHS,
            audit_events.MAX_RETENTION_MONTHS,
        )
        assert _model("PlatformRetention")().audit_months == audit_events.DEFAULT_RETENTION_MONTHS


class TestPlatformRetentionOrder:
    """The trash minimum can't exceed the trash maximum."""

    @pytest.mark.parametrize(("trash_min", "trash_max"), [(1, 0), (90, 89), (50, 10), (90, 0)])
    def test_platform_retention_min_above_max_is_rejected(
        self, trash_min: int, trash_max: int
    ) -> None:
        _rejects(
            _model("PlatformRetention"),
            _defaults("retention", trash_min_days=trash_min, trash_max_days=trash_max),
        )

    @pytest.mark.parametrize(("trash_min", "trash_max"), [(0, 0), (45, 45), (90, 90), (7, 30)])
    def test_platform_retention_min_up_to_max_is_accepted(
        self, trash_min: int, trash_max: int
    ) -> None:
        retention = _model("PlatformRetention").model_validate(
            _defaults("retention", trash_min_days=trash_min, trash_max_days=trash_max)
        )

        assert (retention.trash_min_days, retention.trash_max_days) == (trash_min, trash_max)

    def test_platform_retention_order_error_message_never_repeats_the_values(self) -> None:
        exc = _rejects(
            _model("PlatformRetention"),
            _defaults("retention", trash_min_days=73, trash_max_days=41),
        )

        for error in exc.errors():
            assert "73" not in error["msg"]
            assert "41" not in error["msg"]


# ---------------------------------------------------------------------------
# 2. PlatformSettingsResponse
# ---------------------------------------------------------------------------


class TestPlatformSettingsResponse:
    """GET/PATCH /api/platform/settings answer with all five sections."""

    def test_platform_settings_response_has_the_five_sections(self) -> None:
        fields = _model("PlatformSettingsResponse").model_fields

        assert set(fields) == set(_PATCH_SECTIONS)
        assert fields["llm"].annotation is SettingsLLM
        for section in ("limits", *_NEW_SECTIONS):
            assert fields[section].annotation is _response(section), section

    def test_platform_settings_response_dumps_every_section(self) -> None:
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

        assert set(dumped) == set(_PATCH_SECTIONS)
        assert dumped["limits"] == LimitsConfig().model_dump()
        for section in _NEW_SECTIONS:
            assert dumped[section] == _defaults(section), section


# ---------------------------------------------------------------------------
# 3. The section patch models
# ---------------------------------------------------------------------------


class TestPlatformSectionPatchModels:
    """PlatformLimitsPatch, PlatformFilesPatch, PlatformRetentionPatch, PlatformSecurityPatch."""

    @pytest.mark.parametrize("section", sorted(_SECTIONS))
    def test_platform_section_patch_fields_are_the_section_fields(self, section: str) -> None:
        assert set(_patch(section).model_fields) == set(_table(section))

    def test_platform_limits_patch_fields_equal_the_limits_section(self) -> None:
        assert set(_patch("limits").model_fields) == set(_model("PlatformLimits").model_fields)
        assert set(_patch("limits").model_fields) == set(LimitsConfig.model_fields)

    @pytest.mark.parametrize("section", sorted(_SECTIONS))
    def test_platform_section_patch_forbids_extra_and_hides_input(self, section: str) -> None:
        config = _patch(section).model_config

        assert config.get("extra") == "forbid"
        assert config.get("hide_input_in_errors") is True

    @pytest.mark.parametrize(("section", "field"), _SECTION_FIELDS, ids=_ids(_SECTION_FIELDS))
    def test_platform_section_patch_field_is_optional_with_default_none(
        self, section: str, field: str
    ) -> None:
        info = _patch(section).model_fields[field]

        assert not info.is_required()
        assert info.default is None

    @pytest.mark.parametrize("section", sorted(_SECTIONS))
    def test_platform_section_patch_empty_body_gives_all_none(self, section: str) -> None:
        """Nothing given in the section is valid here; PlatformSettingsPatch checks the total."""
        patch = _patch(section).model_validate({})

        assert patch.model_dump() == dict.fromkeys(_table(section))

    @pytest.mark.parametrize(("section", "field"), _SECTION_FIELDS, ids=_ids(_SECTION_FIELDS))
    def test_platform_section_patch_inclusive_bounds_are_accepted(
        self, section: str, field: str
    ) -> None:
        _, low, high = _table(section)[field]
        model = _patch(section)

        assert model.model_validate({field: low}).model_dump(exclude_none=True) == {field: low}
        assert model.model_validate({field: high}).model_dump(exclude_none=True) == {field: high}

    @pytest.mark.parametrize(("section", "field"), _SECTION_FIELDS, ids=_ids(_SECTION_FIELDS))
    @pytest.mark.parametrize("side", ["below", "above", "far_below", "far_above"])
    def test_platform_section_patch_out_of_bounds_is_rejected(
        self, section: str, field: str, side: str
    ) -> None:
        _, low, high = _table(section)[field]
        value = {"below": low - 1, "above": high + 1, "far_below": -_HUGE, "far_above": _HUGE}[side]

        exc = _rejects(_patch(section), {field: value})

        assert [error["loc"] for error in exc.errors()] == [(field,)]

    @pytest.mark.parametrize(("section", "field"), _SECTION_FIELDS, ids=_ids(_SECTION_FIELDS))
    def test_platform_section_patch_value_is_a_strict_int(self, section: str, field: str) -> None:
        """A bool, float, numeric string or Decimal is refused as a type error."""
        default = _table(section)[field][0]
        model = _patch(section)

        for value in _not_strict_ints(default):
            exc = _rejects(model, {field: value})
            assert {error["type"] for error in exc.errors()} == {"int_type"}, repr(value)

    @pytest.mark.parametrize(("section", "field"), _SECTION_FIELDS, ids=_ids(_SECTION_FIELDS))
    def test_platform_section_patch_json_value_is_a_strict_int(
        self, section: str, field: str
    ) -> None:
        default = _table(section)[field][0]
        model = _patch(section)

        assert model.model_validate_json(json.dumps({field: default})).model_dump(
            exclude_none=True
        ) == {field: default}
        for body in (
            json.dumps({field: float(default)}),
            json.dumps({field: str(default)}),
            json.dumps({field: True}),
            json.dumps({field: default + 0.5}),
        ):
            with pytest.raises(ValidationError):
                model.model_validate_json(body)

    @pytest.mark.parametrize("section", sorted(_SECTIONS))
    @pytest.mark.parametrize(
        "key",
        ["org_id", "enabled", "delay_after_failures", "max_tool_calls", "retention_days", "dpi"],
    )
    def test_platform_section_patch_unknown_key_is_rejected(self, section: str, key: str) -> None:
        field = next(iter(_table(section)))

        _rejects(_patch(section), {field: _table(section)[field][0], key: 5})
        _rejects(_patch(section), {key: 5})

    @pytest.mark.parametrize("section", sorted(_SECTIONS))
    def test_platform_section_patch_other_section_field_is_rejected(self, section: str) -> None:
        """A field is only accepted in its own section."""
        for other, (_, _, table) in _SECTIONS.items():
            if other == section:
                continue
            for field, (default, _, _) in table.items():
                _rejects(_patch(section), {field: default})

    @pytest.mark.parametrize(("section", "field"), _SECTION_FIELDS, ids=_ids(_SECTION_FIELDS))
    def test_platform_section_patch_errors_never_repeat_the_input(
        self, section: str, field: str
    ) -> None:
        model = _patch(section)

        for payload in (
            {field: _SENTINEL},
            {field: f"{_table(section)[field][0]}{_SENTINEL}"},
            {field: [_SENTINEL]},
            {field: _table(section)[field][0], "extra": _SENTINEL},
        ):
            exc = _rejects(model, payload)
            assert _SENTINEL not in str(exc)
            assert _SENTINEL not in repr(exc.errors(include_url=False, include_input=False))

    @pytest.mark.parametrize(
        ("trash_min", "trash_max"), [(90, 0), (1, 0), (50, 10)], ids=["90>0", "1>0", "50>10"]
    )
    def test_platform_retention_patch_does_not_compare_min_and_max(
        self, trash_min: int, trash_max: int
    ) -> None:
        """The service validates the merged stored + patched values, not the patch."""
        patch = _patch("retention").model_validate(
            {"trash_min_days": trash_min, "trash_max_days": trash_max}
        )

        assert patch.model_dump(exclude_none=True) == {
            "trash_min_days": trash_min,
            "trash_max_days": trash_max,
        }


# ---------------------------------------------------------------------------
# 4. PlatformSettingsPatch (PATCH /api/platform/settings)
# ---------------------------------------------------------------------------


class TestPlatformSettingsPatchSections:
    """The five sections, each optional; at least one value across them."""

    def test_platform_settings_patch_fields_are_the_five_sections(self) -> None:
        model = _model("PlatformSettingsPatch")

        # GH-242: plus the request-level residency confirmation (not a section).
        assert set(model.model_fields) == {*_PATCH_SECTIONS, "confirm_residency_orgs"}
        assert model.model_config.get("extra") == "forbid"
        assert model.model_config.get("hide_input_in_errors") is True

    @pytest.mark.parametrize("section", _PATCH_SECTIONS)
    def test_platform_settings_patch_section_is_optional_with_default_none(
        self, section: str
    ) -> None:
        info = _model("PlatformSettingsPatch").model_fields[section]
        expected = SettingsPatchLLM if section == "llm" else _patch(section)

        assert not info.is_required()
        assert info.default is None
        assert expected in typing.get_args(info.annotation)
        assert type(None) in typing.get_args(info.annotation)

    @pytest.mark.parametrize("payload", [{"limits": {"max_message_length": 100}}])
    def test_platform_settings_patch_limits_is_accepted(self, payload: dict[str, Any]) -> None:
        """#159 refused a limits key; GH-160 makes the limits editable."""
        patch = _model("PlatformSettingsPatch").model_validate(payload)

        assert patch.model_dump(exclude_none=True) == payload

    @pytest.mark.parametrize(("section", "field"), _SECTION_FIELDS, ids=_ids(_SECTION_FIELDS))
    @pytest.mark.parametrize("which", ["low", "default", "high"])
    def test_platform_settings_patch_single_field_is_enough(
        self, section: str, field: str, which: str
    ) -> None:
        default, low, high = _table(section)[field]
        value = {"low": low, "default": default, "high": high}[which]
        payload = {section: {field: value}}

        patch = _model("PlatformSettingsPatch").model_validate(payload)

        assert patch.model_dump(exclude_none=True) == payload

    @pytest.mark.parametrize(("section", "field"), _SECTION_FIELDS, ids=_ids(_SECTION_FIELDS))
    def test_platform_settings_patch_out_of_bounds_field_is_rejected(
        self, section: str, field: str
    ) -> None:
        _, low, high = _table(section)[field]

        for value in (low - 1, high + 1):
            exc = _rejects(_model("PlatformSettingsPatch"), {section: {field: value}})
            assert [error["loc"][:2] for error in exc.errors()] == [(section, field)]

    @pytest.mark.parametrize(("section", "field"), _SECTION_FIELDS, ids=_ids(_SECTION_FIELDS))
    def test_platform_settings_patch_field_is_a_strict_int(self, section: str, field: str) -> None:
        """The int is accepted; a bool, float, numeric string or Decimal for it is not."""
        default = _table(section)[field][0]
        model = _model("PlatformSettingsPatch")

        assert model.model_validate({section: {field: default}}).model_dump(exclude_none=True) == {
            section: {field: default}
        }
        for value in _not_strict_ints(default):
            exc = _rejects(model, {section: {field: value}})
            assert [error["loc"][:2] for error in exc.errors()] == [(section, field)], repr(value)

    def test_platform_settings_patch_every_section_at_once_is_accepted(self) -> None:
        payload: dict[str, Any] = {"llm": {"provider": "openai"}}
        for section in ("limits", *_NEW_SECTIONS):
            payload[section] = _defaults(section)

        patch = _model("PlatformSettingsPatch").model_validate(payload)

        assert patch.model_dump(exclude_none=True) == payload

    @pytest.mark.parametrize(
        "payload",
        [
            {"llm": {"provider": "openai"}},
            {"llm": {"infomaniak_model": "Qwen/Qwen3.5-397B-A17B-FP8"}},
            {"llm": {"provider": "vllm", "vllm_model": "Qwen/Qwen3-4B-Instruct-2507"}},
        ],
    )
    def test_platform_settings_patch_llm_only_still_works(self, payload: dict[str, Any]) -> None:
        """The #159 LLM patch is unchanged; the other sections stay not given."""
        patch = _model("PlatformSettingsPatch").model_validate(payload)

        assert patch.model_dump(exclude_none=True) == payload
        for section in ("limits", *_NEW_SECTIONS):
            assert getattr(patch, section) is None, section

    @pytest.mark.parametrize(
        "payload",
        [
            {"llm": {"provider": "openai"}, "files": {}},
            {"llm": {"provider": "openai"}, "files": None, "security": {}},
            {"limits": {"max_context_messages": 50}, "retention": {"audit_months": None}},
            {"security": {"lockout_minutes": 30}, "llm": {}},
        ],
    )
    def test_platform_settings_patch_empty_sections_beside_a_value_are_accepted(
        self, payload: dict[str, Any]
    ) -> None:
        """An empty or null section counts as not given; one value elsewhere is enough."""
        _model("PlatformSettingsPatch").model_validate(payload)

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"llm": None},
            {"llm": {}},
            {"llm": {"provider": None}},
            {"limits": None},
            {"limits": {}},
            {"files": {}},
            {"retention": {}},
            {"security": {}},
            {"files": None, "retention": None, "security": None},
            dict.fromkeys(_PATCH_SECTIONS),
            {section: {} for section in _PATCH_SECTIONS},
            {"security": {"rate_limit_per_minute": None}},
            {"retention": {"trash_min_days": None, "trash_max_days": None}},
            {section: dict.fromkeys(table) for section, (_, _, table) in _SECTIONS.items()},
            {"llm": {"provider": None}, "limits": dict.fromkeys(_LIMITS), "files": {}},
        ],
    )
    def test_platform_settings_patch_without_any_value_is_rejected(
        self, payload: dict[str, Any]
    ) -> None:
        """A patch must change something; an empty section or a null is not given."""
        exc = _rejects(_model("PlatformSettingsPatch"), payload)

        assert [error["msg"] for error in exc.errors() if _NOTHING_GIVEN in error["msg"]], [
            error["msg"] for error in exc.errors()
        ]

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("tools", {"gmail": False}),
            ("appearance", {"theme": "dark"}),
            ("notifications", {"enabled": False}),
            ("server", {"port": 1}),
            ("org_id", "00000000-0000-4000-8000-000000000001"),
            ("sessions", {"idle_timeout_minutes": 30}),
            ("login", {"delay_after_failures": 0}),
            ("agent", {"max_tool_calls": 100}),
            ("audit", {"retention_months": 6}),
        ],
    )
    def test_platform_settings_patch_unknown_top_level_key_is_rejected(
        self, key: str, value: object
    ) -> None:
        """Only the unknown key is refused (the security section beside it is valid)."""
        exc = _rejects(
            _model("PlatformSettingsPatch"),
            {"security": {"lockout_minutes": 30}, key: value},
        )

        assert [(error["loc"], error["type"]) for error in exc.errors()] == [
            ((key,), "extra_forbidden")
        ]

    @pytest.mark.parametrize(
        ("section", "key"),
        [
            ("files", "dpi"),
            ("limits", "max_tool_calls"),
            ("security", "delay_after_failures"),
            ("security", "idle_timeout_minutes"),
            ("retention", "retention_months"),
            ("files", "rate_limit_per_minute"),
            ("security", "render_dpi"),
            ("retention", "max_message_length"),
        ],
    )
    def test_platform_settings_patch_unknown_nested_key_is_rejected(
        self, section: str, key: str
    ) -> None:
        """Unknown or other-section fields are refused inside their section, never dropped."""
        exc = _rejects(_model("PlatformSettingsPatch"), {section: {key: 5}})

        assert [(error["loc"], error["type"]) for error in exc.errors()] == [
            ((section, key), "extra_forbidden")
        ]

    @pytest.mark.parametrize("section", ("limits", *_NEW_SECTIONS))
    @pytest.mark.parametrize("value", [5, "files", [1], True])
    def test_platform_settings_patch_section_must_be_an_object(
        self, section: str, value: object
    ) -> None:
        exc = _rejects(_model("PlatformSettingsPatch"), {section: value})

        assert [error["loc"][:1] for error in exc.errors()] == [(section,)]

    def test_platform_settings_patch_retention_min_above_max_is_left_to_the_service(
        self,
    ) -> None:
        payload = {"retention": {"trash_min_days": 60, "trash_max_days": 30}}

        patch = _model("PlatformSettingsPatch").model_validate(payload)

        assert patch.model_dump(exclude_none=True) == payload

    @pytest.mark.parametrize(
        "body",
        [
            '{"security": {"session_idle_timeout_minutes": 30}}',
            '{"limits": {"max_tool_calls_per_message": 100}}',
            '{"files": {"render_dpi": 300}, "retention": {"audit_months": 84}}',
        ],
    )
    def test_platform_settings_patch_accepts_a_json_body(self, body: str) -> None:
        patch = _model("PlatformSettingsPatch").model_validate_json(body)

        assert patch.model_dump(exclude_none=True) == json.loads(body)

    @pytest.mark.parametrize(
        ("good", "bad"),
        [
            ('{"files": {"render_dpi": 150}}', '{"files": {"render_dpi": 150.5}}'),
            ('{"files": {"render_dpi": 150}}', '{"files": {"render_dpi": 150.0}}'),
            ('{"security": {"lockout_minutes": 15}}', '{"security": {"lockout_minutes": "15"}}'),
            (
                '{"limits": {"max_context_messages": 1}}',
                '{"limits": {"max_context_messages": true}}',
            ),
        ],
    )
    def test_platform_settings_patch_json_ints_are_strict(self, good: str, bad: str) -> None:
        model = _model("PlatformSettingsPatch")

        assert model.model_validate_json(good).model_dump(exclude_none=True) == json.loads(good)
        with pytest.raises(ValidationError):
            model.model_validate_json(bad)

    @pytest.mark.parametrize(
        ("payload", "loc"),
        [
            ({"files": {"render_dpi": _SENTINEL}}, ("files", "render_dpi")),
            ({"limits": {"max_message_length": _SENTINEL}}, ("limits", "max_message_length")),
            ({"retention": {"audit_months": 12, "purge": _SENTINEL}}, ("retention", "purge")),
            ({"security": {"rate_limit_per_minute": 20}, "org_id": _SENTINEL}, ("org_id",)),
            ({"files": _SENTINEL}, ("files",)),
            (
                {"llm": {"provider": _SENTINEL}, "files": {"render_dpi": 150}},
                ("llm", "provider"),
            ),
            (
                {"llm": {"openai_model": f"{_SENTINEL};"}, "security": {"lockout_minutes": 15}},
                ("llm", "openai_model"),
            ),
            ({"security": {"lockout_minutes": [_SENTINEL]}}, ("security", "lockout_minutes")),
        ],
    )
    def test_platform_settings_patch_errors_never_repeat_the_input(
        self, payload: dict[str, Any], loc: tuple[str, ...]
    ) -> None:
        exc = _rejects(_model("PlatformSettingsPatch"), payload)

        assert {error["loc"][: len(loc)] for error in exc.errors()} == {loc}
        assert _SENTINEL not in str(exc)
        assert _SENTINEL not in repr(exc.errors(include_url=False, include_input=False))

    @pytest.mark.parametrize(("section", "field"), _SECTION_FIELDS, ids=_ids(_SECTION_FIELDS))
    def test_platform_settings_patch_out_of_range_value_is_not_echoed(
        self, section: str, field: str
    ) -> None:
        exc = _rejects(_model("PlatformSettingsPatch"), {section: {field: _HUGE}})

        assert [error["loc"][:2] for error in exc.errors()] == [(section, field)]
        assert str(_HUGE) not in str(exc)
