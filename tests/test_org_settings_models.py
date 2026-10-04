"""Tests for GH-169's org settings models in admino.models (contract section 2).

``GET`` / ``PATCH /api/org/settings`` grow from the tool switches (GH-159/162) to
the whole Organization -> Settings page: profile (display name and default
response language), the organization instructions, the session policy, the
trash retention, the tool services, and the read-only data residency and plan.

What these tests pin down:
- Response models, every field required (no defaults):
  ``OrgProfile`` {display_name (at most 120), default_response_language (de, fr,
  it, en)}, ``OrgSecurity`` {session_idle_timeout_minutes,
  session_max_lifetime_hours}, ``OrgRetention`` {trash_retention_days,
  trash_min_days, trash_max_days}, ``OrgPlan`` {seats, storage_quota} (no
  budget: V2) and ``OrgSettingsResponse`` {profile, instructions (at most
  8000), security, retention, tools (``ToolsSettings``), data_residency, plan}.
  A fresh org's response dumps to exactly the contract's JSON.
- Patch models, every field optional (None = not given), ``extra="forbid"`` and
  ``hide_input_in_errors=True`` on each:
  - ``OrgProfilePatch``: ``display_name`` stripped, then 1 to 120 code points,
    no Cc/Cf/Cs/Zl/Zp character (exactly ``OrgCreateRequest.name``'s rule);
    ``default_response_language`` de/fr/it/en only.
  - ``OrgSecurityPatch`` (strict ints: bool, float, str, Decimal refused):
    idle timeout 15..480, lifetime 1..72 (the ``admino.sessions`` bounds).
  - ``OrgRetentionPatch`` (strict ints): ``trash_retention_days`` 0..90.
  - ``OrgSettingsPatch``: profile, instructions, security, retention, tools
    (``OrgToolsPatch``, now optional). The instructions are kept verbatim (not
    stripped), at most 8000 code points, no Cc but tab/newline/carriage return,
    no Cf but U+200C/U+200D, no Cs/Zl/Zp (the personal-instructions rule of
    ``MyAccountPatch``); ``""`` is a value (it clears them).
  - At least one value must be given across all sections: an empty body, all
    nulls and empty sections are refused at the model level (``loc == ()``),
    while an empty section next to a real value is fine. A tools-only patch is
    still valid (back-compat with the GH-162 tool switches).
  - Read-only and unknown keys are refused at every level: ``data_residency``,
    ``plan``, ``org_id``, ``trash_min_days`` / ``trash_max_days`` (top level and
    in ``retention``), ``profile.name`` ...
- Validation errors never contain the input: neither ``str(exc)`` / ``repr(exc)``
  nor ``exc.errors(include_input=False)`` (what the 422 body is built from)
  carries the marker. Each refusal is also anchored on its exact error location,
  so the old tools-only model (which refuses every new key as unknown) can't
  pass these tests by accident.

New symbols are looked up per test, so a missing model fails its own tests and
not the whole module.

Security notes:
- extra="forbid" everywhere: an Org Admin can't switch residency off, raise the
  plan limits, widen the Super Admin's trash bounds or target another org by
  adding a key that would otherwise be silently dropped.
- Strict ints: ``true`` or ``"480"`` never becomes a session policy by coercion.
- The character rules keep bidi overrides, zero-width spaces and line
  separators out of the org name (an email Subject header) and out of the
  instructions (fed to the LLM by #170).
"""

from __future__ import annotations

import copy
import functools
import json
import sys
import types
import typing
import unicodedata
from decimal import Decimal
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

import admino.models as models_module
from admino import sessions
from admino.models import MyAccountPatch, OrgCreateRequest, ToolsSettings

_MARKER = "ECHOMARK169"
_TOOLS = (
    "gmail",
    "google_calendar",
    "google_drive",
    "outlook",
    "outlook_calendar",
    "onedrive",
    "memory",
)
_LANGUAGES = ("de", "fr", "it", "en")
_SECTIONS = ("profile", "instructions", "security", "retention", "tools")
_RESPONSE_FIELDS = (
    "profile",
    "instructions",
    "security",
    "retention",
    "tools",
    "data_residency",
    "plan",
)
_PATCH_MODELS = ("OrgProfilePatch", "OrgSecurityPatch", "OrgRetentionPatch", "OrgSettingsPatch")

_IDLE = "session_idle_timeout_minutes"
_LIFETIME = "session_max_lifetime_hours"
_TRASH = "trash_retention_days"
_NAME = "display_name"
_LANGUAGE = "default_response_language"

_NUL = chr(0x00)
_BEL = chr(0x07)
_TAB = chr(0x09)
_NEWLINE = chr(0x0A)
_VERTICAL_TAB = chr(0x0B)
_FORM_FEED = chr(0x0C)
_CARRIAGE_RETURN = chr(0x0D)
_ESCAPE = chr(0x1B)
_DELETE = chr(0x7F)
_NEXT_LINE = chr(0x85)
_SOFT_HYPHEN = chr(0xAD)
_ZERO_WIDTH_SPACE = chr(0x200B)
_ZERO_WIDTH_NON_JOINER = chr(0x200C)
_ZERO_WIDTH_JOINER = chr(0x200D)
_LTR_MARK = chr(0x200E)
_LINE_SEPARATOR = chr(0x2028)
_PARAGRAPH_SEPARATOR = chr(0x2029)
_RTL_OVERRIDE = chr(0x202E)
_LTR_ISOLATE = chr(0x2066)
_BYTE_ORDER_MARK = chr(0xFEFF)
_ANNOTATION_ANCHOR = chr(0xFFF9)
_LANGUAGE_TAG = chr(0xE0001)
_LONE_SURROGATE = chr(0xD800)
_GRINNING_FACE = chr(0x1F600)
_TECHNOLOGIST = chr(0x1F469) + _ZERO_WIDTH_JOINER + chr(0x1F4BB)
_U_UMLAUT = chr(0xFC)
_E_DIAERESIS = chr(0xEB)

# The only control / format characters the instructions keep.
_INSTRUCTIONS_ALLOWED = frozenset(
    {_TAB, _NEWLINE, _CARRIAGE_RETURN, _ZERO_WIDTH_NON_JOINER, _ZERO_WIDTH_JOINER}
)

# The contract's GET JSON for a fresh org (no org_settings row), residency off,
# platform retention 0..90; seats and quota are the org's.
_FRESH_ORG_JSON: dict[str, Any] = {
    "profile": {"display_name": "Treuhand Muster AG", "default_response_language": "en"},
    "instructions": "",
    "security": {_IDLE: 60, _LIFETIME: 12},
    "retention": {_TRASH: 30, "trash_min_days": 0, "trash_max_days": 90},
    "tools": dict.fromkeys(_TOOLS, True),
    "data_residency": False,
    "plan": {"seats": 25, "storage_quota": 10 * 1024**3},
}

# A valid value for one leaf of every patch section.
_VALID_LEAF: dict[str, tuple[tuple[str, ...], object]] = {
    "profile": (("profile", _NAME), "Treuhand Muster AG"),
    "instructions": (("instructions",), "Antworte bitte knapp."),
    "security": (("security", _IDLE), 30),
    "retention": (("retention", _TRASH), 7),
    "tools": (("tools", "gmail"), False),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _model(name: str) -> type[BaseModel]:
    """A GH-169 model from admino.models; fails the calling test when missing."""
    model = getattr(models_module, name, None)
    if model is None:
        pytest.fail(f"admino.models.{name} does not exist (GH-169)")
    assert isinstance(model, type)
    assert issubclass(model, BaseModel)
    return model


def _patch(payload: object) -> Any:
    return _model("OrgSettingsPatch").model_validate(payload)


def _rejects(model: type[BaseModel], payload: object) -> ValidationError:
    with pytest.raises(ValidationError) as exc_info:
        model.model_validate(payload)
    return exc_info.value


def _errors(model: type[BaseModel], payload: object) -> list[tuple[tuple[int | str, ...], str]]:
    """(loc, type) of every error of a refused payload, without the input."""
    exc = _rejects(model, payload)
    return [
        (tuple(item["loc"]), item["type"])
        for item in exc.errors(include_input=False, include_url=False)
    ]


def _error_locs(model: type[BaseModel], payload: object) -> set[tuple[int | str, ...]]:
    return {loc for loc, _ in _errors(model, payload)}


def _accepts(model: type[BaseModel], payload: object) -> bool:
    try:
        model.model_validate(payload)
    except ValidationError:
        return False
    return True


def _with(payload: dict[str, Any], path: tuple[str, ...], value: object) -> dict[str, Any]:
    """A deep copy of payload with value set at path (a null or missing section becomes {})."""
    result = copy.deepcopy(payload)
    node = result
    for key in path[:-1]:
        if not isinstance(node.get(key), dict):
            node[key] = {}
        node = node[key]
    node[path[-1]] = value
    return result


def _response(**overrides: object) -> dict[str, Any]:
    return {**copy.deepcopy(_FRESH_ORG_JSON), **overrides}


def _optional_args(annotation: object) -> set[object]:
    """The members of an ``X | None`` annotation (empty when it isn't a union);
    an ``Annotated[T, ...]`` member counts as T."""
    if typing.get_origin(annotation) not in (typing.Union, types.UnionType):
        return set()
    return {
        typing.get_args(member)[0] if typing.get_origin(member) is typing.Annotated else member
        for member in typing.get_args(annotation)
    }


def _org_create_name(name: object) -> tuple[bool, object]:
    """(accepted, stored name) of OrgCreateRequest.name for this input."""
    try:
        request = OrgCreateRequest.model_validate(
            {
                "name": name,
                "primary_admin_email": "ada@example.ch",
                "seats": 5,
                "monthly_budget_chf": "10.00",
                "storage_quota": 1024,
            }
        )
    except ValidationError:
        return False, None
    return True, request.name


def _profile_name(name: object) -> tuple[bool, object]:
    """(accepted, stored name) of OrgProfilePatch.display_name for this input."""
    try:
        patch = _model("OrgProfilePatch").model_validate({_NAME: name})
    except ValidationError:
        return False, None
    return True, patch.display_name  # type: ignore[attr-defined]


@functools.cache
def _banned_sweep(categories: frozenset[str]) -> tuple[str, ...]:
    """Every code point of the given general categories (the whole Unicode range)."""
    return tuple(
        chr(code)
        for code in range(sys.maxunicode + 1)
        if unicodedata.category(chr(code)) in categories
    )


# ---------------------------------------------------------------------------
# 1. Response models
# ---------------------------------------------------------------------------


class TestOrgSettingsResponseModels:
    """The GET/PATCH response: every section, every field required."""

    @pytest.mark.parametrize(
        ("name", "fields"),
        [
            ("OrgProfile", {_NAME, _LANGUAGE}),
            ("OrgSecurity", {_IDLE, _LIFETIME}),
            ("OrgRetention", {_TRASH, "trash_min_days", "trash_max_days"}),
            ("OrgPlan", {"seats", "storage_quota"}),
            ("OrgSettingsResponse", set(_RESPONSE_FIELDS)),
        ],
    )
    def test_org_settings_models_response_model_has_exactly_its_fields(
        self, name: str, fields: set[str]
    ) -> None:
        """OrgPlan carries seats and storage only: the budget is V2."""
        assert set(_model(name).model_fields) == fields

    @pytest.mark.parametrize("name", ["OrgProfile", "OrgSecurity", "OrgRetention", "OrgPlan"])
    def test_org_settings_models_response_section_fields_are_all_required(self, name: str) -> None:
        fields = _model(name).model_fields

        assert fields
        assert all(info.is_required() for info in fields.values())

    def test_org_settings_models_response_sections_are_the_section_models(self) -> None:
        fields = _model("OrgSettingsResponse").model_fields

        assert fields["profile"].annotation is _model("OrgProfile")
        assert fields["security"].annotation is _model("OrgSecurity")
        assert fields["retention"].annotation is _model("OrgRetention")
        assert fields["plan"].annotation is _model("OrgPlan")
        assert fields["tools"].annotation is ToolsSettings
        assert fields["instructions"].annotation is str
        assert fields["data_residency"].annotation is bool

    def test_org_settings_models_fresh_org_response_dumps_the_contract_json(self) -> None:
        body = _model("OrgSettingsResponse").model_validate(_FRESH_ORG_JSON)

        assert json.loads(body.model_dump_json()) == _FRESH_ORG_JSON
        assert body.model_dump() == _FRESH_ORG_JSON

    def test_org_settings_models_response_without_any_one_section_is_refused(self) -> None:
        """No section has a default: a response can't silently omit residency or the plan.
        Each of the seven sections, left out alone, is the one missing field."""
        model = _model("OrgSettingsResponse")
        found: dict[str, object] = {}
        for missing in _RESPONSE_FIELDS:
            payload = _response()
            del payload[missing]
            try:
                model.model_validate(payload)
            except ValidationError as exc:
                found[missing] = [
                    (tuple(item["loc"]), item["type"]) for item in exc.errors(include_input=False)
                ]
            else:
                found[missing] = "accepted"

        assert found == {missing: [((missing,), "missing")] for missing in _RESPONSE_FIELDS}

    @pytest.mark.parametrize(
        ("section", "missing"),
        [
            ("profile", _NAME),
            ("profile", _LANGUAGE),
            ("security", _IDLE),
            ("security", _LIFETIME),
            ("retention", _TRASH),
            ("retention", "trash_min_days"),
            ("retention", "trash_max_days"),
            ("plan", "seats"),
            ("plan", "storage_quota"),
        ],
    )
    def test_org_settings_models_response_without_a_nested_field_is_refused(
        self, section: str, missing: str
    ) -> None:
        payload = _response()
        del payload[section][missing]

        assert _errors(_model("OrgSettingsResponse"), payload) == [((section, missing), "missing")]

    def test_org_settings_models_response_instructions_hold_8000_code_points(self) -> None:
        """8000 emoji are 8000 characters (16000 UTF-16 units, 32000 bytes)."""
        text = _GRINNING_FACE * 8000

        body = _model("OrgSettingsResponse").model_validate(_response(instructions=text))

        assert body.instructions == text  # type: ignore[attr-defined]

    def test_org_settings_models_response_instructions_over_8000_are_refused(self) -> None:
        payload = _response(instructions="a" * 8001)

        assert _error_locs(_model("OrgSettingsResponse"), payload) == {("instructions",)}

    def test_org_settings_models_response_display_name_over_120_is_refused(self) -> None:
        payload = _response()
        assert _accepts(
            _model("OrgSettingsResponse"), _with(payload, ("profile", _NAME), "a" * 120)
        )

        payload["profile"][_NAME] = "a" * 121

        assert _error_locs(_model("OrgSettingsResponse"), payload) == {("profile", _NAME)}

    @pytest.mark.parametrize("language", _LANGUAGES)
    def test_org_settings_models_response_language_is_accepted(self, language: str) -> None:
        payload = _with(_response(), ("profile", _LANGUAGE), language)

        body = _model("OrgSettingsResponse").model_validate(payload)

        assert body.profile.default_response_language == language  # type: ignore[attr-defined]

    @pytest.mark.parametrize("language", ["DE", "es", "", "de-CH", "english", None])
    def test_org_settings_models_response_unknown_language_is_refused(
        self, language: object
    ) -> None:
        payload = _with(_response(), ("profile", _LANGUAGE), language)

        assert _error_locs(_model("OrgSettingsResponse"), payload) == {("profile", _LANGUAGE)}


# ---------------------------------------------------------------------------
# 2. Patch models: shape
# ---------------------------------------------------------------------------


class TestOrgSettingsPatchShape:
    """Every patch field is optional; every patch model forbids extras and hides input."""

    @pytest.mark.parametrize(
        ("name", "fields"),
        [
            ("OrgProfilePatch", {_NAME, _LANGUAGE}),
            ("OrgSecurityPatch", {_IDLE, _LIFETIME}),
            ("OrgRetentionPatch", {_TRASH}),
            ("OrgSettingsPatch", set(_SECTIONS)),
        ],
    )
    def test_org_settings_models_patch_model_has_exactly_its_fields(
        self, name: str, fields: set[str]
    ) -> None:
        """No read-only field (residency, plan, the platform trash bounds) is patchable."""
        assert set(_model(name).model_fields) == fields

    @pytest.mark.parametrize("name", _PATCH_MODELS)
    def test_org_settings_models_patch_fields_default_to_not_given(self, name: str) -> None:
        fields = _model(name).model_fields

        assert fields
        for field_name, info in fields.items():
            assert not info.is_required(), field_name
            assert info.default is None, field_name

    @pytest.mark.parametrize("name", ["OrgProfilePatch", "OrgSecurityPatch", "OrgRetentionPatch"])
    def test_org_settings_models_section_patch_forbids_extras_and_hides_input(
        self, name: str
    ) -> None:
        config = _model(name).model_config

        assert config.get("extra") == "forbid"
        assert config.get("hide_input_in_errors") is True

    @pytest.mark.parametrize(
        ("section", "section_model"),
        [
            ("profile", "OrgProfilePatch"),
            ("security", "OrgSecurityPatch"),
            ("retention", "OrgRetentionPatch"),
            ("tools", "OrgToolsPatch"),
        ],
    )
    def test_org_settings_models_patch_sections_are_optional_section_models(
        self, section: str, section_model: str
    ) -> None:
        """``tools`` keeps the GH-162 OrgToolsPatch but is no longer required."""
        annotation = _model("OrgSettingsPatch").model_fields[section].annotation

        assert _optional_args(annotation) == {_model(section_model), type(None)}

    def test_org_settings_models_patch_instructions_is_an_optional_string(self) -> None:
        annotation = _model("OrgSettingsPatch").model_fields["instructions"].annotation

        assert _optional_args(annotation) == {str, type(None)}


# ---------------------------------------------------------------------------
# 3. Patch models: valid bodies
# ---------------------------------------------------------------------------


class TestOrgSettingsPatchAccepted:
    """A value in any one section is a valid patch; nulls are not given."""

    def test_org_settings_models_patch_every_section_at_once_is_accepted(self) -> None:
        payload = {
            "profile": {_NAME: "Treuhand Muster AG", _LANGUAGE: "de"},
            "instructions": "Antworte auf Deutsch.\nSei knapp.",
            "security": {_IDLE: 30, _LIFETIME: 8},
            "retention": {_TRASH: 14},
            "tools": {"gmail": False, "memory": True},
        }

        patch = _patch(payload)

        assert patch.model_dump(exclude_none=True) == payload

    def test_org_settings_models_patch_accepts_a_json_body(self) -> None:
        body = (
            '{"profile": {"default_response_language": "it"}, "instructions": "",'
            ' "security": {"session_max_lifetime_hours": 24},'
            ' "retention": {"trash_retention_days": 0}}'
        )

        patch = _model("OrgSettingsPatch").model_validate_json(body)

        assert patch.profile.default_response_language == "it"
        assert patch.instructions == ""
        assert patch.security.session_max_lifetime_hours == 24
        assert patch.retention.trash_retention_days == 0
        assert patch.tools is None

    @pytest.mark.parametrize(
        ("path", "value"),
        [
            pytest.param(("profile", _NAME), "Acme AG", id="display-name"),
            pytest.param(("profile", _LANGUAGE), "fr", id="language"),
            pytest.param(("instructions",), "Be brief.", id="instructions"),
            pytest.param(("security", _IDLE), 120, id="idle-timeout"),
            pytest.param(("security", _LIFETIME), 48, id="lifetime"),
            pytest.param(("retention", _TRASH), 60, id="trash-retention"),
        ],
    )
    def test_org_settings_models_patch_single_value_is_accepted(
        self, path: tuple[str, ...], value: object
    ) -> None:
        """A value in any one new section is enough (tools alone: the back-compat test)."""
        patch = _patch(_with({}, path, value))

        leaf: Any = patch
        for key in path:
            leaf = getattr(leaf, key)
        assert leaf == value
        assert type(leaf) is type(value)

    def test_org_settings_models_patch_tools_only_is_still_valid(self) -> None:
        """Back-compat: the GH-162 tool switches send ``{"tools": {...}}`` alone."""
        patch = _patch({"tools": {"gmail": False}})

        assert (patch.profile, patch.instructions, patch.security, patch.retention) == (
            None,
            None,
            None,
            None,
        )
        assert patch.tools.gmail is False

    def test_org_settings_models_patch_empty_instructions_are_a_value(self) -> None:
        """``""`` clears the instructions: it is given, not "nothing to change"."""
        patch = _patch({"instructions": ""})

        assert patch.instructions == ""
        assert "instructions" in patch.model_dump(exclude_none=True)

    def test_org_settings_models_patch_nulls_are_not_given(self) -> None:
        patch = _patch(
            {
                "profile": {_NAME: None, _LANGUAGE: "en"},
                "instructions": None,
                "security": {_IDLE: None, _LIFETIME: 6},
                "retention": None,
                "tools": None,
            }
        )

        assert patch.profile.display_name is None
        assert patch.profile.default_response_language == "en"
        assert patch.instructions is None
        assert patch.security.session_idle_timeout_minutes is None
        assert patch.security.session_max_lifetime_hours == 6
        assert patch.retention is None
        assert patch.tools is None

    def test_org_settings_models_patch_empty_sections_next_to_a_value_are_accepted(self) -> None:
        patch = _patch(
            {"profile": {}, "security": {}, "retention": {}, "tools": {}, "instructions": "x"}
        )

        assert patch.instructions == "x"


# ---------------------------------------------------------------------------
# 4. Session policy and trash retention: bounds and strict ints
# ---------------------------------------------------------------------------

_INT_LEAVES = (("security", _IDLE), ("security", _LIFETIME), ("retention", _TRASH))


class TestOrgSettingsPatchPolicyBounds:
    """Idle 15..480, lifetime 1..72, trash 0..90; strict ints only."""

    @pytest.mark.parametrize(
        ("section", "field_name", "value"),
        [
            ("security", _IDLE, 15),
            ("security", _IDLE, 60),
            ("security", _IDLE, 480),
            ("security", _LIFETIME, 1),
            ("security", _LIFETIME, 12),
            ("security", _LIFETIME, 72),
            ("retention", _TRASH, 0),
            ("retention", _TRASH, 30),
            ("retention", _TRASH, 90),
        ],
    )
    def test_org_settings_models_patch_bound_value_is_accepted(
        self, section: str, field_name: str, value: int
    ) -> None:
        patch = _patch({section: {field_name: value}})

        assert getattr(getattr(patch, section), field_name) == value

    @pytest.mark.parametrize(
        ("section", "field_name", "value", "error"),
        [
            ("security", _IDLE, 14, "greater_than_equal"),
            ("security", _IDLE, 0, "greater_than_equal"),
            ("security", _IDLE, -1, "greater_than_equal"),
            ("security", _IDLE, 481, "less_than_equal"),
            ("security", _LIFETIME, 0, "greater_than_equal"),
            ("security", _LIFETIME, 73, "less_than_equal"),
            ("security", _LIFETIME, 8760, "less_than_equal"),
            ("retention", _TRASH, -1, "greater_than_equal"),
            ("retention", _TRASH, 91, "less_than_equal"),
            ("retention", _TRASH, 3650, "less_than_equal"),
        ],
    )
    def test_org_settings_models_patch_out_of_bounds_value_is_refused(
        self, section: str, field_name: str, value: int, error: str
    ) -> None:
        errors = _errors(_model("OrgSettingsPatch"), {section: {field_name: value}})

        assert errors == [((section, field_name), error)]

    @pytest.mark.parametrize(
        ("model", "field_name", "low", "high"),
        [
            ("OrgSecurityPatch", _IDLE, 15, 480),
            ("OrgSecurityPatch", _LIFETIME, 1, 72),
            ("OrgRetentionPatch", _TRASH, 0, 90),
        ],
    )
    def test_org_settings_models_section_model_enforces_its_bounds(
        self, model: str, field_name: str, low: int, high: int
    ) -> None:
        section = _model(model)

        assert _accepts(section, {field_name: low})
        assert _accepts(section, {field_name: high})
        assert not _accepts(section, {field_name: low - 1})
        assert not _accepts(section, {field_name: high + 1})

    def test_org_settings_models_security_bounds_are_the_session_constants(self) -> None:
        security = _model("OrgSecurityPatch")

        assert _accepts(security, {_IDLE: sessions.MIN_IDLE_TIMEOUT_MINUTES})
        assert _accepts(security, {_IDLE: sessions.MAX_IDLE_TIMEOUT_MINUTES})
        assert not _accepts(security, {_IDLE: sessions.MIN_IDLE_TIMEOUT_MINUTES - 1})
        assert not _accepts(security, {_IDLE: sessions.MAX_IDLE_TIMEOUT_MINUTES + 1})
        assert _accepts(security, {_LIFETIME: sessions.MIN_LIFETIME_HOURS})
        assert _accepts(security, {_LIFETIME: sessions.MAX_LIFETIME_HOURS})
        assert not _accepts(security, {_LIFETIME: sessions.MIN_LIFETIME_HOURS - 1})
        assert not _accepts(security, {_LIFETIME: sessions.MAX_LIFETIME_HOURS + 1})

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(True, id="true"),
            pytest.param(False, id="false"),
            pytest.param(30.0, id="float"),
            pytest.param("30", id="numeric-string"),
            pytest.param(Decimal(30), id="decimal"),
            pytest.param([30], id="list"),
        ],
    )
    @pytest.mark.parametrize(("section", "field_name"), _INT_LEAVES)
    def test_org_settings_models_patch_policy_value_is_a_strict_int(
        self, section: str, field_name: str, value: object
    ) -> None:
        """30 is inside every range, so only strictness refuses these (True is 1 and
        False is 0, inside the lifetime and retention ranges when coerced)."""
        errors = _errors(_model("OrgSettingsPatch"), {section: {field_name: value}})

        assert errors == [((section, field_name), "int_type")]

    @pytest.mark.parametrize("raw", ["30.0", '"30"', "true"])
    @pytest.mark.parametrize(("section", "field_name"), _INT_LEAVES)
    def test_org_settings_models_patch_json_policy_value_is_a_strict_int(
        self, section: str, field_name: str, raw: str
    ) -> None:
        body = f'{{"{section}": {{"{field_name}": {raw}}}}}'

        with pytest.raises(ValidationError) as caught:
            _model("OrgSettingsPatch").model_validate_json(body)

        locs = {tuple(item["loc"]) for item in caught.value.errors(include_input=False)}
        assert locs == {(section, field_name)}


# ---------------------------------------------------------------------------
# 5. Profile: display name and default response language
# ---------------------------------------------------------------------------

_NAMES_ACCEPTED: list[Any] = [
    pytest.param("Acme AG", "Acme AG", id="plain"),
    pytest.param("  Acme AG \t", "Acme AG", id="stripped"),
    pytest.param(
        "Zo" + _E_DIAERESIS + " M" + _U_UMLAUT + "ller & Partner GmbH",
        "Zo" + _E_DIAERESIS + " M" + _U_UMLAUT + "ller & Partner GmbH",
        id="unicode",
    ),
    pytest.param("X", "X", id="one-char"),
    pytest.param("a" * 120, "a" * 120, id="120-chars"),
    pytest.param("  " + "a" * 120 + _NEWLINE, "a" * 120, id="120-after-strip"),
    pytest.param(_GRINNING_FACE * 120, _GRINNING_FACE * 120, id="120-code-points"),
    pytest.param(_LINE_SEPARATOR + "Acme", "Acme", id="leading-line-separator-stripped"),
]

_NAMES_REFUSED: list[Any] = [
    pytest.param("", id="empty"),
    pytest.param("   " + _TAB + " ", id="whitespace-only"),
    pytest.param("a" * 121, id="121-chars"),
    pytest.param(" " + "a" * 121 + " ", id="121-after-strip"),
    pytest.param(_GRINNING_FACE * 121, id="121-code-points"),
    pytest.param("Ac" + _NUL + "me", id="nul"),
    pytest.param("Ac" + _ESCAPE + "me", id="escape"),
    pytest.param("Ac" + _NEWLINE + "me", id="newline"),
    pytest.param("Acme" + _CARRIAGE_RETURN + _NEWLINE + "Bcc: x@example.ch", id="header-inject"),
    pytest.param("Ac" + _TAB + "me", id="tab"),
    pytest.param("Ac" + _DELETE + "me", id="del"),
    pytest.param("Ac" + _NEXT_LINE + "me", id="c1-next-line"),
    pytest.param("Ac" + _SOFT_HYPHEN + "me", id="soft-hyphen"),
    pytest.param("Ac" + _ZERO_WIDTH_SPACE + "me", id="zero-width-space"),
    pytest.param("Ac" + _ZERO_WIDTH_NON_JOINER + "me", id="zero-width-non-joiner"),
    pytest.param("Ac" + _ZERO_WIDTH_JOINER + "me", id="zero-width-joiner"),
    pytest.param("Ac" + _RTL_OVERRIDE + "me", id="rtl-override"),
    pytest.param("Ac" + _LTR_ISOLATE + "me", id="ltr-isolate"),
    pytest.param("Ac" + _BYTE_ORDER_MARK + "me", id="bom"),
    pytest.param("Ac" + _LONE_SURROGATE + "me", id="lone-surrogate"),
    pytest.param("Ac" + _LINE_SEPARATOR + "me", id="line-separator"),
    pytest.param("Ac" + _PARAGRAPH_SEPARATOR + "me", id="paragraph-separator"),
    pytest.param(123, id="int"),
    pytest.param(True, id="bool"),
    pytest.param(["Acme"], id="list"),
    pytest.param({"name": "Acme"}, id="dict"),
]


class TestOrgProfilePatch:
    """Display name: OrgCreateRequest.name's rule; language: de/fr/it/en."""

    @pytest.mark.parametrize(("name", "expected"), _NAMES_ACCEPTED)
    def test_org_settings_models_display_name_is_accepted_stripped(
        self, name: str, expected: str
    ) -> None:
        patch = _patch({"profile": {_NAME: name}})

        assert patch.profile.display_name == expected

    @pytest.mark.parametrize("name", _NAMES_REFUSED)
    def test_org_settings_models_display_name_is_refused(self, name: object) -> None:
        assert _error_locs(_model("OrgSettingsPatch"), {"profile": {_NAME: name}}) == {
            ("profile", _NAME)
        }

    def test_org_settings_models_display_name_refuses_every_banned_character(self) -> None:
        """Every Cc, Cf, Zl and Zp code point (and a surrogate sample) in the middle of a
        name is refused; at the start or end a whitespace one would just be stripped."""
        banned = [*_banned_sweep(frozenset({"Cc", "Cf", "Zl", "Zp"})), _LONE_SURROGATE, chr(0xDFFF)]
        profile = _model("OrgProfilePatch")

        accepted = [hex(ord(char)) for char in banned if _accepts(profile, {_NAME: f"A{char}B"})]

        assert banned
        assert accepted == []

    @pytest.mark.parametrize(
        "name",
        [
            *(pytest.param(param.values[0], id=param.id) for param in _NAMES_ACCEPTED),
            *(pytest.param(param.values[0], id=param.id) for param in _NAMES_REFUSED),
            pytest.param(_NEXT_LINE + "Acme" + _PARAGRAPH_SEPARATOR, id="c1-and-zp-ends"),
            pytest.param("Acme" + chr(0x1F) + " ", id="unit-separator-end"),
            pytest.param(chr(0xA0) + "Acme" + chr(0x3000), id="nbsp-ideographic-space-ends"),
            pytest.param("A" + chr(0xA0) + "B", id="inner-nbsp"),
            pytest.param("A" + chr(0x2003) + "B", id="inner-em-space"),
        ],
    )
    def test_org_settings_models_display_name_rule_is_the_org_create_rule(
        self, name: object
    ) -> None:
        """Exactly OrgCreateRequest.name's rule: same accept/refuse, same stripped value."""
        assert _profile_name(name) == _org_create_name(name)

    @pytest.mark.parametrize("language", _LANGUAGES)
    def test_org_settings_models_default_response_language_is_accepted(self, language: str) -> None:
        patch = _patch({"profile": {_LANGUAGE: language}})

        assert patch.profile.default_response_language == language

    @pytest.mark.parametrize(
        "language", ["DE", "Fr", "es", "rm", "", "de-CH", "english", " de", 1, True, ["de"]]
    )
    def test_org_settings_models_unknown_default_response_language_is_refused(
        self, language: object
    ) -> None:
        assert _error_locs(_model("OrgSettingsPatch"), {"profile": {_LANGUAGE: language}}) == {
            ("profile", _LANGUAGE)
        }


# ---------------------------------------------------------------------------
# 6. Organization instructions
# ---------------------------------------------------------------------------

_INSTRUCTIONS_ACCEPTED: list[Any] = [
    pytest.param("", id="empty-clears"),
    pytest.param("  Antworte auf Deutsch.  " + _NEWLINE + _NEWLINE, id="kept-unstripped"),
    pytest.param(_TAB + "Indented" + _CARRIAGE_RETURN + _NEWLINE + "line", id="tab-crlf"),
    pytest.param(_NEWLINE * 3, id="only-newlines"),
    pytest.param("R" + _E_DIAERESIS + "ponse en fran" + chr(0xE7) + "ais", id="accented"),
    pytest.param("Use emoji " + _GRINNING_FACE + " sparingly", id="emoji"),
    pytest.param("Team " + _TECHNOLOGIST, id="zwj-sequence"),
    pytest.param("mi" + _ZERO_WIDTH_NON_JOINER + "x", id="zero-width-non-joiner"),
    pytest.param(chr(0x4F60) + chr(0x597D), id="cjk"),
    pytest.param("a" * 8000, id="8000-chars"),
    pytest.param(_GRINNING_FACE * 8000, id="8000-code-points"),
    pytest.param(_NEWLINE * 8000, id="8000-newlines"),
]


class TestOrgSettingsPatchInstructions:
    """Kept verbatim; at most 8000 code points; the personal-instructions character rule."""

    @pytest.mark.parametrize("text", _INSTRUCTIONS_ACCEPTED)
    def test_org_settings_models_instructions_are_accepted_verbatim(self, text: str) -> None:
        patch = _patch({"instructions": text})

        assert patch.instructions == text

    @pytest.mark.parametrize(
        "text",
        [
            pytest.param("a" * 8001, id="8001-chars"),
            pytest.param(_GRINNING_FACE * 8001, id="8001-code-points"),
            pytest.param(" " * 8001, id="8001-spaces"),
        ],
    )
    def test_org_settings_models_instructions_over_8000_are_refused(self, text: str) -> None:
        """Counted in code points before anything else: spaces are not stripped away."""
        assert _error_locs(_model("OrgSettingsPatch"), {"instructions": text}) == {
            ("instructions",)
        }

    @pytest.mark.parametrize("position", ["start", "middle", "end"])
    @pytest.mark.parametrize(
        "char",
        [
            pytest.param(_NUL, id="nul"),
            pytest.param(_BEL, id="bel"),
            pytest.param(_VERTICAL_TAB, id="vertical-tab"),
            pytest.param(_FORM_FEED, id="form-feed"),
            pytest.param(_ESCAPE, id="escape"),
            pytest.param(_DELETE, id="del"),
            pytest.param(_NEXT_LINE, id="c1-next-line"),
            pytest.param(_SOFT_HYPHEN, id="soft-hyphen"),
            pytest.param(_ZERO_WIDTH_SPACE, id="zero-width-space"),
            pytest.param(_LTR_MARK, id="ltr-mark"),
            pytest.param(_RTL_OVERRIDE, id="rtl-override"),
            pytest.param(_LTR_ISOLATE, id="ltr-isolate"),
            pytest.param(_BYTE_ORDER_MARK, id="bom"),
            pytest.param(_ANNOTATION_ANCHOR, id="annotation-anchor"),
            pytest.param(_LANGUAGE_TAG, id="language-tag"),
            pytest.param(_LINE_SEPARATOR, id="line-separator"),
            pytest.param(_PARAGRAPH_SEPARATOR, id="paragraph-separator"),
            pytest.param(_LONE_SURROGATE, id="lone-surrogate"),
        ],
    )
    def test_org_settings_models_instructions_with_a_banned_character_are_refused(
        self, char: str, position: str
    ) -> None:
        """Not stripped, so a banned character is refused wherever it is."""
        text = {"start": char + "Be brief.", "middle": "Be" + char + " brief.", "end": "Be." + char}

        assert _error_locs(_model("OrgSettingsPatch"), {"instructions": text[position]}) == {
            ("instructions",)
        }

    def test_org_settings_models_instructions_character_sweep(self) -> None:
        """Every Cc, Cf, Zl and Zp code point is refused except tab, newline, carriage
        return, U+200C and U+200D, which are kept."""
        candidates = _banned_sweep(frozenset({"Cc", "Cf", "Zl", "Zp"}))
        patch = _model("OrgSettingsPatch")

        verdicts = {char: _accepts(patch, {"instructions": f"A{char}B"}) for char in candidates}

        wrongly_accepted = [
            hex(ord(c)) for c, ok in verdicts.items() if ok and c not in _INSTRUCTIONS_ALLOWED
        ]
        wrongly_refused = [
            hex(ord(c)) for c, ok in verdicts.items() if not ok and c in _INSTRUCTIONS_ALLOWED
        ]
        assert wrongly_accepted == []
        assert wrongly_refused == []
        assert set(candidates) >= _INSTRUCTIONS_ALLOWED

    def test_org_settings_models_instructions_rule_is_the_personal_instructions_rule(
        self,
    ) -> None:
        """The same verdict and the same stored text as MyAccountPatch.personal_instructions
        for every sample within its 1500 limit (accepted and refused alike)."""
        samples = [
            *(param.values[0] for param in _INSTRUCTIONS_ACCEPTED if len(param.values[0]) < 1500),
            "Be" + _NUL + " brief.",
            "Be" + _RTL_OVERRIDE + " brief.",
            "Be" + _LINE_SEPARATOR + " brief.",
            "Be" + _BYTE_ORDER_MARK + " brief.",
            "Be" + _ZERO_WIDTH_SPACE + " brief.",
            "Be" + _LONE_SURROGATE + " brief.",
            _VERTICAL_TAB + "x" + _FORM_FEED,
        ]

        def verdict(model: type[BaseModel], key: str, text: str) -> tuple[bool, object]:
            try:
                return True, getattr(model.model_validate({key: text}), key)
            except ValidationError:
                return False, None

        mismatches = [
            ascii(text)
            for text in samples
            if verdict(_model("OrgSettingsPatch"), "instructions", text)
            != verdict(MyAccountPatch, "personal_instructions", text)
        ]

        assert mismatches == []

    @pytest.mark.parametrize("value", [123, True, ["Be brief."], {"text": "Be brief."}, 1.5])
    def test_org_settings_models_non_string_instructions_are_refused(self, value: object) -> None:
        assert _error_locs(_model("OrgSettingsPatch"), {"instructions": value}) == {
            ("instructions",)
        }


# ---------------------------------------------------------------------------
# 7. Read-only and unknown keys
# ---------------------------------------------------------------------------


class TestOrgSettingsPatchUnknownKeys:
    """Refused (422), never ignored, at every level."""

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("data_residency", False),
            ("plan", {"seats": 500}),
            ("org_id", "00000000-0000-4000-8000-000000000001"),
            ("trash_min_days", 0),
            ("trash_max_days", 90),
            ("display_name", "Acme AG"),
            ("name", "Acme AG"),
            ("default_response_language", "de"),
            (_IDLE, 30),
            (_TRASH, 7),
            ("seats", 500),
            ("storage_quota", 1),
            ("monthly_budget_chf", "1000.00"),
            ("budget", 1000),
            ("appearance", {"theme": "dark"}),
            ("llm", {"provider": "openai"}),
            ("limits", {"max_message_length": 10}),
        ],
    )
    def test_org_settings_models_patch_unknown_top_level_key_is_refused(
        self, key: str, value: object
    ) -> None:
        """Residency and the plan are the Super Admin's; the org is always the caller's."""
        payload = {"instructions": "Be brief.", key: value}

        assert _errors(_model("OrgSettingsPatch"), payload) == [((key,), "extra_forbidden")]

    @pytest.mark.parametrize(
        ("section", "key", "value"),
        [
            ("profile", "name", "Acme AG"),
            ("profile", "instructions", "x"),
            ("profile", "data_residency", False),
            ("profile", "org_id", "00000000-0000-4000-8000-000000000001"),
            ("profile", "ui_language", "de"),
            ("security", "idle_timeout_minutes", 30),
            ("security", "max_lifetime_hours", 8),
            ("security", _TRASH, 7),
            ("retention", "trash_min_days", 0),
            ("retention", "trash_max_days", 90),
            ("retention", "retention_days", 7),
            ("retention", _IDLE, 30),
            ("tools", "files", False),
            ("tools", "web_search", True),
            ("tools", "custom_mailboxes", True),
        ],
    )
    def test_org_settings_models_patch_unknown_nested_key_is_refused(
        self, section: str, key: str, value: object
    ) -> None:
        """Next to valid values (the section's own and the instructions), only the unknown
        key is reported."""
        path, valid = _VALID_LEAF[section]
        payload = _with(_with({"instructions": "Be brief."}, path, valid), (section, key), value)

        assert _errors(_model("OrgSettingsPatch"), payload) == [((section, key), "extra_forbidden")]


# ---------------------------------------------------------------------------
# 8. At least one value
# ---------------------------------------------------------------------------

_ALL_NULL = dict.fromkeys(_SECTIONS)
_ALL_EMPTY: dict[str, dict[str, Any]] = {
    "profile": {},
    "security": {},
    "retention": {},
    "tools": {},
}
_ALL_NULL_LEAVES = {
    "profile": {_NAME: None, _LANGUAGE: None},
    "instructions": None,
    "security": {_IDLE: None, _LIFETIME: None},
    "retention": {_TRASH: None},
    "tools": dict.fromkeys(_TOOLS),
}


class TestOrgSettingsPatchSomethingGiven:
    """An empty body, nulls and empty sections give nothing: refused at the model level."""

    @pytest.mark.parametrize(
        ("payload", "path", "value"),
        [
            pytest.param({}, ("instructions",), "", id="empty-body"),
            pytest.param(_ALL_NULL, ("instructions",), "", id="all-sections-null"),
            pytest.param(_ALL_EMPTY, ("security", _LIFETIME), 1, id="all-sections-empty"),
            pytest.param(_ALL_NULL_LEAVES, ("retention", _TRASH), 0, id="all-leaves-null"),
            pytest.param({"profile": None}, ("instructions",), "", id="profile-null"),
            pytest.param({"profile": {}}, ("profile", _LANGUAGE), "de", id="profile-empty"),
            pytest.param(
                {"profile": {_NAME: None, _LANGUAGE: None}},
                ("profile", _NAME),
                "Acme AG",
                id="profile-leaves-null",
            ),
            pytest.param({"instructions": None}, ("security", _IDLE), 15, id="instructions-null"),
            pytest.param({"security": {}}, ("security", _IDLE), 480, id="security-empty"),
            pytest.param(
                {"security": {_IDLE: None, _LIFETIME: None}},
                ("security", _LIFETIME),
                72,
                id="security-leaves-null",
            ),
            pytest.param({"retention": {}}, ("retention", _TRASH), 90, id="retention-empty"),
            pytest.param(
                {"retention": {_TRASH: None}}, ("instructions",), "", id="retention-leaf-null"
            ),
            pytest.param({"tools": {}}, ("instructions",), "", id="tools-empty"),
            pytest.param(
                {"tools": dict.fromkeys(_TOOLS)}, ("profile", _LANGUAGE), "it", id="tools-null"
            ),
        ],
    )
    def test_org_settings_models_patch_without_any_value_is_refused(
        self, payload: dict[str, Any], path: tuple[str, ...], value: object
    ) -> None:
        """Refused as a whole (loc ``()``), and one value anywhere makes the same body valid."""
        assert _errors(_model("OrgSettingsPatch"), payload) == [((), "value_error")]
        assert _accepts(_model("OrgSettingsPatch"), _with(payload, path, value))

    def test_org_settings_models_patch_empty_error_never_names_a_value(self) -> None:
        exc = _rejects(_model("OrgSettingsPatch"), _ALL_NULL_LEAVES)

        assert [item["loc"] for item in exc.errors(include_input=False)] == [()]
        assert "None" not in str(exc.errors(include_input=False)[0]["msg"])


# ---------------------------------------------------------------------------
# 9. Validation errors never echo the input
# ---------------------------------------------------------------------------


class TestOrgSettingsPatchNoEcho:
    """Neither the exception text nor the error list carries the refused value."""

    @pytest.mark.parametrize(
        ("payload", "loc"),
        [
            pytest.param(
                {"profile": {_NAME: _MARKER + "a" * 120}}, ("profile", _NAME), id="name-too-long"
            ),
            pytest.param(
                {"profile": {_NAME: _MARKER + _RTL_OVERRIDE + "x"}},
                ("profile", _NAME),
                id="name-bidi",
            ),
            pytest.param(
                {"profile": {_NAME: "Acme", _LANGUAGE: _MARKER}},
                ("profile", _LANGUAGE),
                id="language",
            ),
            pytest.param(
                {"instructions": _MARKER * 800}, ("instructions",), id="instructions-long"
            ),
            pytest.param(
                {"instructions": _MARKER + _NUL + _MARKER}, ("instructions",), id="instructions-nul"
            ),
            pytest.param(
                {"instructions": _MARKER + _LINE_SEPARATOR},
                ("instructions",),
                id="instructions-line-separator",
            ),
            pytest.param({"security": {_IDLE: _MARKER}}, ("security", _IDLE), id="idle-string"),
            pytest.param(
                {"security": {_LIFETIME: _MARKER}}, ("security", _LIFETIME), id="lifetime-string"
            ),
            pytest.param({"retention": {_TRASH: _MARKER}}, ("retention", _TRASH), id="trash"),
            pytest.param(
                {"instructions": "ok", "tools": {"gmail": _MARKER}}, ("tools", "gmail"), id="tool"
            ),
            pytest.param(
                {"instructions": "ok", "data_residency": _MARKER},
                ("data_residency",),
                id="residency",
            ),
            pytest.param({"instructions": "ok", "plan": {"seats": _MARKER}}, ("plan",), id="plan"),
            pytest.param(
                {"retention": {_TRASH: 7, "trash_min_days": _MARKER}},
                ("retention", "trash_min_days"),
                id="trash-bound",
            ),
            pytest.param(
                {"profile": {_NAME: "Acme", "name": _MARKER}}, ("profile", "name"), id="old-name"
            ),
        ],
    )
    def test_org_settings_models_patch_error_never_echoes_the_input(
        self, payload: dict[str, Any], loc: tuple[str, ...]
    ) -> None:
        exc = _rejects(_model("OrgSettingsPatch"), payload)
        errors = exc.errors(include_input=False, include_url=False)

        assert {tuple(item["loc"]) for item in errors} == {loc}
        assert _MARKER not in str(exc)
        assert _MARKER not in repr(exc)
        assert _MARKER not in json.dumps(errors, default=str)

    def test_org_settings_models_patch_json_error_never_echoes_the_input(self) -> None:
        body = json.dumps({"instructions": _MARKER + _RTL_OVERRIDE, "profile": {_NAME: _MARKER}})

        with pytest.raises(ValidationError) as caught:
            _model("OrgSettingsPatch").model_validate_json(body)

        errors = caught.value.errors(include_input=False, include_url=False)
        assert {tuple(item["loc"]) for item in errors} == {("instructions",)}
        assert _MARKER not in str(caught.value)
        assert _MARKER not in json.dumps(errors, default=str)
