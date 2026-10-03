"""Tests for the account self-service API models in admino.models (GH-166).

``GET /api/me`` and ``PATCH /api/me`` answer ``MyAccountResponse``;
``PATCH /api/me`` takes a ``MyAccountPatch``; ``POST /api/me/password`` takes a
``PasswordChangeRequest``. Each test looks the models up on ``admino.models``
at call time, so a missing model fails only its own tests.

What these tests pin down:
- ``MyAccountResponse`` has exactly ``email``, ``name``, ``ui_language``,
  ``response_language``, ``timezone`` and ``personal_instructions``: no
  password, hash, token, id, org id, role or account kind. ``name`` may be
  null (a Super Admin created without one), ``response_language`` null means
  "the org default", ``timezone`` null means "not preset yet" (consumers use
  Europe/Zurich), ``personal_instructions`` ``""`` means none. ``ui_language``
  is de/fr/en; ``response_language`` is de/fr/it/en.
- ``MyAccountPatch`` (unknown fields refused: ``email``, ``password``,
  ``role``, ``kind``, ``org_id``, ``user_id``, ``theme`` ...) takes any of
  ``name``, ``ui_language``, ``response_language``, ``timezone`` and
  ``personal_instructions``; at least one must be given (``{}`` is refused).
  Field presence is ``model_fields_set``: ``response_language: null`` is a
  given field ("use the org default"), an absent one is not; a null
  ``name``, ``ui_language``, ``timezone`` or ``personal_instructions`` is
  refused (they can't be cleared; ``""`` clears the instructions).
  - ``name``: stripped, then 1 to 120 characters, refusing control (Cc),
    format (Cf, e.g. zero-width and direction overrides), surrogate (Cs) and
    line/paragraph separator (Zl, Zp) characters.
  - ``timezone``: 1 to 64 characters and a name of
    ``zoneinfo.available_timezones()``, case-sensitive and not stripped.
  - ``personal_instructions``: at most 1500 code points (not bytes, not UTF-16
    units), NOT stripped (kept verbatim, leading and trailing whitespace
    included), tab / newline / carriage return allowed, every other control
    character (Cc) and lone surrogates (Cs) refused; emoji ZWJ sequences are
    fine. Security audit (GH-166, M1): format characters (Cf: bidi overrides
    and isolates, direction marks, zero-width space, BOM, soft hyphen) and
    line/paragraph separators (Zl, Zp) are refused too, except the zero-width
    joiner and non-joiner (U+200D, U+200C) that emoji sequences and some
    scripts need: the instructions reach the system prompt (#170).
- ``PasswordChangeRequest`` is exactly ``current_password`` and
  ``new_password``, both ``SecretStr`` of 1 to 1024 characters, required,
  kept as typed; unknown fields are refused.

Security notes:
- Validation errors of ``MyAccountPatch`` never contain the submitted name,
  timezone or instructions (nor any other rejected value): the model sets
  ``hide_input_in_errors`` and its own messages never repeat the value, so a
  422 body or a log line built from them repeats nothing.
- The body can't choose the account, its email, its role, its org or its
  kind: those come from the session and from Org Admin routes only.
- The passwords never show in a repr, a str or a JSON dump (``SecretStr``).
"""

from __future__ import annotations

import json
import zoneinfo
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

_RESPONSE_FIELDS = frozenset(
    {"email", "name", "ui_language", "response_language", "timezone", "personal_instructions"}
)
_PATCH_FIELDS = frozenset(
    {"name", "ui_language", "response_language", "timezone", "personal_instructions"}
)
_PASSWORD_FIELDS = frozenset({"current_password", "new_password"})

# Field names that would carry a credential, a scope, a role or the account kind.
_NEVER_FIELDS = frozenset(
    {
        "id",
        "user_id",
        "org_id",
        "password",
        "password_hash",
        "hash",
        "token",
        "role",
        "kind",
        "status",
        "is_super_admin",
        "deleted_at",
    }
)

_NAME_MAX = 120
_TIMEZONE_MAX = 64
_INSTRUCTIONS_MAX = 1500
_PASSWORD_MAX = 1024

# Characters built with chr() so they survive editing tools verbatim.
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
_U_UMLAUT = chr(0xFC)
_ZERO_WIDTH_SPACE = chr(0x200B)
_ZERO_WIDTH_JOINER = chr(0x200D)
_LINE_SEPARATOR = chr(0x2028)
_PARAGRAPH_SEPARATOR = chr(0x2029)
_RTL_OVERRIDE = chr(0x202E)
_LTR_ISOLATE = chr(0x2066)
_BYTE_ORDER_MARK = chr(0xFEFF)
_LONE_SURROGATE = chr(0xD800)
# One code point, four UTF-8 bytes, two UTF-16 units.
_GRINNING_FACE = chr(0x1F600)
# A ZWJ emoji sequence: woman + ZWJ + laptop, three code points, one glyph.
_TECHNOLOGIST = chr(0x1F469) + _ZERO_WIDTH_JOINER + chr(0x1F4BB)

# The contract's timezone samples.
_ACCEPTED_TIMEZONES = ("Europe/Zurich", "America/Argentina/Buenos_Aires", "Etc/GMT+5", "UTC")


def _model(name: str) -> Any:
    """Look a model up on admino.models at call time (it is new in GH-166)."""
    from admino import models

    model = getattr(models, name, None)
    assert model is not None, f"admino.models must define {name}"
    return model


def _response_data(**overrides: Any) -> dict[str, Any]:
    return {
        "email": "Ada.Lovelace@Example.CH",
        "name": "Ada Lovelace",
        "ui_language": "de",
        "response_language": "it",
        "timezone": "Europe/Zurich",
        "personal_instructions": "I lead the finance team.\nSign off with 'Best, Ada'.",
        **overrides,
    }


def _response(**overrides: Any) -> Any:
    return _model("MyAccountResponse").model_validate(_response_data(**overrides))


def _patch(values: dict[str, Any]) -> Any:
    return _model("MyAccountPatch").model_validate(values)


def _password_request(values: dict[str, Any]) -> Any:
    return _model("PasswordChangeRequest").model_validate(values)


def _accepted(build: Any) -> bool:
    try:
        build()
    except ValidationError:
        return False
    return True


def _patch_errors(values: dict[str, Any]) -> list[Any]:
    """The error list of a refused patch, without the input."""
    with pytest.raises(ValidationError) as caught:
        _patch(values)
    return caught.value.errors(include_input=False, include_url=False)


# ---------------------------------------------------------------------------
# 1. MyAccountResponse
# ---------------------------------------------------------------------------


class TestMyAccountResponse:
    """The caller's own account: the GET and PATCH /api/me response."""

    def test_account_models_response_has_exactly_the_contract_fields(self) -> None:
        assert set(_model("MyAccountResponse").model_fields) == _RESPONSE_FIELDS

    def test_account_models_response_has_no_credential_scope_or_kind_field(self) -> None:
        assert set(_model("MyAccountResponse").model_fields).isdisjoint(_NEVER_FIELDS)

    def test_account_models_response_keeps_the_values(self) -> None:
        response = _response()

        assert response.email == "Ada.Lovelace@Example.CH"
        assert response.name == "Ada Lovelace"
        assert response.ui_language == "de"
        assert response.response_language == "it"
        assert response.timezone == "Europe/Zurich"
        assert response.personal_instructions == (
            "I lead the finance team.\nSign off with 'Best, Ada'."
        )

    def test_account_models_response_json_has_exactly_the_contract_keys(self) -> None:
        dumped = json.loads(_response().model_dump_json())

        assert set(dumped) == _RESPONSE_FIELDS

    def test_account_models_response_language_may_be_null(self) -> None:
        """None = the org's default response language."""
        response = _response(response_language=None)

        assert response.response_language is None
        assert json.loads(response.model_dump_json())["response_language"] is None

    def test_account_models_response_timezone_may_be_null(self) -> None:
        """None = not preset yet (consumers use Europe/Zurich)."""
        response = _response(timezone=None)

        assert response.timezone is None
        assert json.loads(response.model_dump_json())["timezone"] is None

    def test_account_models_response_name_may_be_null(self) -> None:
        """A Super Admin created without a name."""
        response = _response(name=None)

        assert response.name is None
        assert json.loads(response.model_dump_json())["name"] is None

    def test_account_models_response_instructions_may_be_empty(self) -> None:
        assert _response(personal_instructions="").personal_instructions == ""

    @pytest.mark.parametrize("language", ["de", "fr", "it", "en"])
    def test_account_models_response_accepts_response_language(self, language: str) -> None:
        assert _response(response_language=language).response_language == language

    @pytest.mark.parametrize("language", ["de", "fr", "en"])
    def test_account_models_response_accepts_ui_language(self, language: str) -> None:
        assert _response(ui_language=language).ui_language == language

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            pytest.param("ui_language", "it", id="ui-italian"),
            pytest.param("ui_language", "es", id="ui-spanish"),
            pytest.param("response_language", "es", id="response-spanish"),
        ],
    )
    def test_account_models_response_rejects_language(self, field: str, value: str) -> None:
        """The UI has no Italian; neither list has Spanish."""
        assert not _accepted(lambda: _response(**{field: value}))


# ---------------------------------------------------------------------------
# 2. MyAccountPatch: shape, presence and unknown fields
# ---------------------------------------------------------------------------

_ONE_FIELD_PATCHES: list[Any] = [
    pytest.param({"name": "Grace Hopper"}, id="name"),
    pytest.param({"ui_language": "fr"}, id="ui-language"),
    pytest.param({"response_language": "it"}, id="response-language"),
    pytest.param({"response_language": None}, id="response-language-null"),
    pytest.param({"timezone": "Europe/Zurich"}, id="timezone"),
    pytest.param({"personal_instructions": "Be brief."}, id="instructions"),
    pytest.param({"personal_instructions": ""}, id="instructions-cleared"),
]

_CLEARABLE_ONLY_BY_VALUE = ("name", "ui_language", "timezone", "personal_instructions")

_FORBIDDEN_KEYS = (
    "email",
    "password",
    "current_password",
    "new_password",
    "password_hash",
    "role",
    "kind",
    "org_id",
    "user_id",
    "id",
    "status",
    "is_super_admin",
    "theme",
    "deleted_at",
)


class TestMyAccountPatchShape:
    """Any of the five fields, at least one given; nothing else."""

    def test_account_models_patch_has_exactly_the_contract_fields(self) -> None:
        assert set(_model("MyAccountPatch").model_fields) == _PATCH_FIELDS

    @pytest.mark.parametrize("values", _ONE_FIELD_PATCHES)
    def test_account_models_patch_accepts_one_field(self, values: dict[str, Any]) -> None:
        patch = _patch(values)

        assert patch.model_fields_set == set(values)
        for key, value in values.items():
            assert getattr(patch, key) == value

    def test_account_models_patch_accepts_every_field_at_once(self) -> None:
        values = {
            "name": "Grace Hopper",
            "ui_language": "en",
            "response_language": "fr",
            "timezone": "America/Argentina/Buenos_Aires",
            "personal_instructions": "Answer in short paragraphs.",
        }

        patch = _patch(values)

        assert patch.model_fields_set == _PATCH_FIELDS
        assert {key: getattr(patch, key) for key in _PATCH_FIELDS} == values

    def test_account_models_patch_rejects_an_empty_body(self) -> None:
        """{} changes nothing: refused."""
        assert not _accepted(lambda: _patch({}))

    def test_account_models_patch_response_language_null_is_a_given_field(self) -> None:
        """An explicit null means "use the org default": given, stored as NULL."""
        patch = _patch({"response_language": None})

        assert patch.response_language is None
        assert "response_language" in patch.model_fields_set

    def test_account_models_patch_absent_response_language_is_not_given(self) -> None:
        """An absent response_language leaves the stored one unchanged."""
        patch = _patch({"name": "Grace Hopper"})

        assert "response_language" not in patch.model_fields_set
        assert patch.response_language is None

    def test_account_models_patch_response_language_value_is_a_given_field(self) -> None:
        patch = _patch({"response_language": "de"})

        assert patch.response_language == "de"
        assert "response_language" in patch.model_fields_set

    def test_account_models_patch_response_language_null_with_another_field(self) -> None:
        patch = _patch({"timezone": "UTC", "response_language": None})

        assert patch.model_fields_set == {"timezone", "response_language"}
        assert patch.response_language is None

    @pytest.mark.parametrize("field", _CLEARABLE_ONLY_BY_VALUE)
    def test_account_models_patch_rejects_null_alone(self, field: str) -> None:
        """A null name, UI language, timezone or instructions can't be stored."""
        assert not _accepted(lambda: _patch({field: None}))

    @pytest.mark.parametrize("field", _CLEARABLE_ONLY_BY_VALUE)
    def test_account_models_patch_rejects_null_next_to_a_valid_field(self, field: str) -> None:
        """The null is refused even when another field makes the patch non-empty."""
        sibling = {"response_language": "en"}

        assert _accepted(lambda: _patch(sibling))
        assert not _accepted(lambda: _patch({**sibling, field: None}))

    @pytest.mark.parametrize("key", _FORBIDDEN_KEYS)
    def test_account_models_patch_rejects_unknown_field(self, key: str) -> None:
        """The account, email, password, role, org and kind are never chosen here."""
        errors = _patch_errors({"ui_language": "de", key: "x"})

        assert [(e["loc"], e["type"]) for e in errors] == [((key,), "extra_forbidden")]

    @pytest.mark.parametrize("value", ["", "Grace", 1, None, True])
    def test_account_models_patch_rejects_email_whatever_the_value(self, value: Any) -> None:
        assert not _accepted(lambda: _patch({"name": "Grace Hopper", "email": value}))


# ---------------------------------------------------------------------------
# 3. MyAccountPatch.name
# ---------------------------------------------------------------------------


class TestMyAccountPatchName:
    """Stripped, 1 to 120 characters, no Cc/Cf/Cs/Zl/Zp characters."""

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            pytest.param("Grace Hopper", "Grace Hopper", id="plain"),
            pytest.param("  Grace Hopper " + _TAB, "Grace Hopper", id="stripped"),
            pytest.param(_NEWLINE + "Grace" + _NEWLINE, "Grace", id="stripped-newlines"),
            pytest.param("Zo" + chr(0xEB) + " M" + _U_UMLAUT + "ller", None, id="unicode"),
            pytest.param("O'Brien-Smith", None, id="apostrophe-hyphen"),
            pytest.param("X", None, id="one-char"),
            pytest.param("a" * _NAME_MAX, None, id="120-chars"),
            pytest.param("  " + "a" * _NAME_MAX + " ", "a" * _NAME_MAX, id="120-after-strip"),
        ],
    )
    def test_account_models_patch_accepts_name(self, name: str, expected: str | None) -> None:
        assert _patch({"name": name}).name == (expected or name)

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("", id="empty"),
            pytest.param("   " + _TAB + " ", id="whitespace-only"),
            pytest.param("a" * (_NAME_MAX + 1), id="121-chars"),
            pytest.param(" " + "a" * (_NAME_MAX + 1) + " ", id="121-after-strip"),
            pytest.param("Gr" + _NUL + "ace", id="nul"),
            pytest.param("Gr" + _ESCAPE + "ace", id="escape"),
            pytest.param("Gr" + _NEWLINE + "ace", id="newline"),
            pytest.param("Grace" + _CARRIAGE_RETURN + _NEWLINE + "Hopper", id="crlf"),
            pytest.param("Gr" + _TAB + "ace", id="tab"),
            pytest.param("Gr" + _DELETE + "ace", id="del"),
            pytest.param("Gr" + _NEXT_LINE + "ace", id="c1-next-line"),
            pytest.param("Gr" + _ZERO_WIDTH_SPACE + "ace", id="zero-width-space"),
            pytest.param("Gr" + _ZERO_WIDTH_JOINER + "ace", id="zero-width-joiner"),
            pytest.param("Gr" + _RTL_OVERRIDE + "ace", id="rtl-override"),
            pytest.param("Gr" + _LTR_ISOLATE + "ace", id="ltr-isolate"),
            pytest.param("Gr" + _BYTE_ORDER_MARK + "ace", id="bom"),
            pytest.param("Gr" + _SOFT_HYPHEN + "ace", id="soft-hyphen"),
            pytest.param("Gr" + _LONE_SURROGATE + "ace", id="lone-surrogate"),
            pytest.param("Gr" + _LINE_SEPARATOR + "ace", id="line-separator"),
            pytest.param("Gr" + _PARAGRAPH_SEPARATOR + "ace", id="paragraph-separator"),
            pytest.param(123, id="int"),
            pytest.param(["Grace"], id="list"),
        ],
    )
    def test_account_models_patch_rejects_name(self, name: Any) -> None:
        assert not _accepted(lambda: _patch({"name": name}))


# ---------------------------------------------------------------------------
# 4. MyAccountPatch.ui_language and response_language
# ---------------------------------------------------------------------------


class TestMyAccountPatchLanguages:
    """ui_language: de/fr/en; response_language: de/fr/it/en (or null); exact case."""

    @pytest.mark.parametrize("language", ["de", "fr", "en"])
    def test_account_models_patch_accepts_ui_language(self, language: str) -> None:
        assert _patch({"ui_language": language}).ui_language == language

    @pytest.mark.parametrize(
        "language",
        [
            pytest.param("it", id="italian-has-no-ui"),
            pytest.param("es", id="spanish"),
            pytest.param("DE", id="upper-case"),
            pytest.param("En", id="mixed-case"),
            pytest.param("de-CH", id="region"),
            pytest.param("", id="empty"),
            pytest.param(" de", id="leading-space"),
            pytest.param(1, id="int"),
        ],
    )
    def test_account_models_patch_rejects_ui_language(self, language: Any) -> None:
        assert not _accepted(lambda: _patch({"ui_language": language}))

    @pytest.mark.parametrize("language", ["de", "fr", "it", "en"])
    def test_account_models_patch_accepts_response_language(self, language: str) -> None:
        assert _patch({"response_language": language}).response_language == language

    @pytest.mark.parametrize(
        "language",
        [
            pytest.param("es", id="spanish"),
            pytest.param("IT", id="upper-case"),
            pytest.param("it-CH", id="region"),
            pytest.param("org_default", id="ui-choice-token"),
            pytest.param("", id="empty"),
            pytest.param(1, id="int"),
        ],
    )
    def test_account_models_patch_rejects_response_language(self, language: Any) -> None:
        assert not _accepted(lambda: _patch({"response_language": language}))


# ---------------------------------------------------------------------------
# 5. MyAccountPatch.timezone
# ---------------------------------------------------------------------------


class TestMyAccountPatchTimezone:
    """1 to 64 characters and a zoneinfo name, exactly as written."""

    @pytest.mark.parametrize("timezone", _ACCEPTED_TIMEZONES)
    def test_account_models_patch_accepts_timezone(self, timezone: str) -> None:
        assert _patch({"timezone": timezone}).timezone == timezone

    @pytest.mark.parametrize(
        "timezone",
        [
            pytest.param("Mars/Olympus", id="unknown-zone"),
            pytest.param("europe/zurich", id="lower-case"),
            pytest.param("EUROPE/ZURICH", id="upper-case"),
            pytest.param("Europe/Zurich ", id="trailing-space"),
            pytest.param(" Europe/Zurich", id="leading-space"),
            pytest.param("Europe/Zurich" + _NEWLINE, id="trailing-newline"),
            pytest.param("../etc/passwd", id="path-traversal"),
            pytest.param("/usr/share/zoneinfo/UTC", id="absolute-path"),
            pytest.param("Europe//Zurich", id="empty-segment"),
            pytest.param("Europe/Z" + _U_UMLAUT + "rich", id="non-ascii"),
            pytest.param("", id="empty"),
            pytest.param("Europe/" + "A" * (_TIMEZONE_MAX + 1 - len("Europe/")), id="65-chars"),
            pytest.param("A" * 1000, id="1000-chars"),
            pytest.param("+02:00", id="offset"),
            pytest.param(5, id="int"),
            pytest.param(["Europe/Zurich"], id="list"),
        ],
    )
    def test_account_models_patch_rejects_timezone(self, timezone: Any) -> None:
        assert not _accepted(lambda: _patch({"timezone": timezone}))

    def test_account_models_patch_rejects_timezone_one_over_the_limit(self) -> None:
        """A 65-character value is refused (the sample is checked to be 65 long)."""
        sample = "Europe/" + "A" * (_TIMEZONE_MAX + 1 - len("Europe/"))

        assert len(sample) == _TIMEZONE_MAX + 1
        assert not _accepted(lambda: _patch({"timezone": sample}))

    def test_account_models_patch_accepts_every_available_zone(self) -> None:
        """Every zoneinfo name is accepted (all of them are at most 64 characters)."""
        zones = sorted(zoneinfo.available_timezones())
        refused = [zone for zone in zones if not _accepted(lambda z=zone: _patch({"timezone": z}))]

        assert zones
        assert refused == []

    def test_account_models_patch_timezone_error_does_not_name_the_zone(self) -> None:
        """The refusal of an unknown zone doesn't repeat it (message or context)."""
        errors = _patch_errors({"timezone": "Quokka/Marmalade"})

        assert errors
        assert "Quokka" not in json.dumps(errors, default=str)


# ---------------------------------------------------------------------------
# 6. MyAccountPatch.personal_instructions
# ---------------------------------------------------------------------------

_ACCEPTED_INSTRUCTIONS: list[Any] = [
    pytest.param("", id="empty-clears"),
    pytest.param("Sign off with 'Best, Ada'.", id="plain"),
    pytest.param("  Be brief.  ", id="leading-and-trailing-spaces-kept"),
    pytest.param(
        "I lead finance at Example AG."
        + _CARRIAGE_RETURN
        + _NEWLINE
        + _TAB
        + "- Be brief."
        + _NEWLINE
        + _NEWLINE,
        id="newlines-tabs-carriage-returns-kept",
    ),
    pytest.param(_NEWLINE + _NEWLINE + "Hello" + _NEWLINE + _NEWLINE, id="outer-newlines-kept"),
    pytest.param("a" * _INSTRUCTIONS_MAX, id="1500-ascii"),
    pytest.param(_U_UMLAUT * _INSTRUCTIONS_MAX, id="1500-two-byte-chars"),
    pytest.param(_GRINNING_FACE * _INSTRUCTIONS_MAX, id="1500-emoji-code-points"),
    pytest.param(_TECHNOLOGIST * (_INSTRUCTIONS_MAX // 3), id="1500-code-points-of-zwj-emoji"),
    pytest.param("Team " + _TECHNOLOGIST + " notes", id="zwj-emoji-sequence"),
    pytest.param(" " * _INSTRUCTIONS_MAX, id="1500-spaces"),
    # Security audit M1: the zero-width non-joiner stays allowed (Persian, Indic scripts).
    pytest.param("\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645", id="zwnj-in-persian"),
]

# Security audit M1 (GH-166): format (Cf) and line/paragraph separator (Zl, Zp)
# characters, other than the zero-width joiner and non-joiner, are refused.
_REFUSED_FORMAT_CHARACTERS: list[Any] = [
    pytest.param("\u202e", id="right-to-left-override"),
    pytest.param("\u202d", id="left-to-right-override"),
    pytest.param("\u202a", id="left-to-right-embedding"),
    pytest.param("\u2066", id="left-to-right-isolate"),
    pytest.param("\u2069", id="pop-directional-isolate"),
    pytest.param("\u200e", id="left-to-right-mark"),
    pytest.param("\u200f", id="right-to-left-mark"),
    pytest.param("\u061c", id="arabic-letter-mark"),
    pytest.param("\u200b", id="zero-width-space"),
    pytest.param("\ufeff", id="byte-order-mark"),
    pytest.param("\u00ad", id="soft-hyphen"),
    pytest.param("\u2028", id="line-separator"),
    pytest.param("\u2029", id="paragraph-separator"),
]

_REFUSED_INSTRUCTIONS: list[Any] = [
    pytest.param("a" * (_INSTRUCTIONS_MAX + 1), id="1501-ascii"),
    pytest.param(_GRINNING_FACE * (_INSTRUCTIONS_MAX + 1), id="1501-emoji"),
    pytest.param("a" * _INSTRUCTIONS_MAX + _NEWLINE, id="1501-with-trailing-newline"),
    pytest.param(" " + "a" * (_INSTRUCTIONS_MAX - 1) + " ", id="1501-with-outer-spaces"),
    pytest.param("Be" + _NUL + "brief", id="nul"),
    pytest.param("Be" + _BEL + "brief", id="bel"),
    pytest.param("Be" + _ESCAPE + "[31mbrief", id="escape"),
    pytest.param("Be" + _DELETE + "brief", id="del"),
    pytest.param("Be" + _VERTICAL_TAB + "brief", id="vertical-tab"),
    pytest.param("Be" + _FORM_FEED + "brief", id="form-feed"),
    pytest.param("Be" + _NEXT_LINE + "brief", id="c1-next-line"),
    pytest.param("Be brief" + _NUL, id="trailing-nul"),
    pytest.param("Be" + _LONE_SURROGATE + "brief", id="lone-surrogate"),
    pytest.param(1500, id="int"),
    pytest.param(["Be brief."], id="list"),
]


class TestMyAccountPatchPersonalInstructions:
    """At most 1500 code points, kept verbatim, no control characters but tab/LF/CR."""

    @pytest.mark.parametrize("text", _ACCEPTED_INSTRUCTIONS)
    def test_account_models_patch_accepts_instructions_verbatim(self, text: str) -> None:
        """Accepted and kept exactly as typed: nothing is stripped or normalized."""
        assert _patch({"personal_instructions": text}).personal_instructions == text

    @pytest.mark.parametrize("text", _REFUSED_INSTRUCTIONS)
    def test_account_models_patch_rejects_instructions(self, text: Any) -> None:
        assert not _accepted(lambda: _patch({"personal_instructions": text}))

    @pytest.mark.parametrize("char", _REFUSED_FORMAT_CHARACTERS)
    def test_account_models_patch_rejects_instructions_with_format_characters(
        self, char: str
    ) -> None:
        """A format or separator character anywhere in the text is refused (audit M1)."""
        assert not _accepted(lambda: _patch({"personal_instructions": "Be " + char + "brief"}))

    def test_account_models_patch_instructions_format_error_hides_the_text(self) -> None:
        """The refusal's message never repeats the submitted instructions."""
        text = "Zanzibar launch codes \u202e"
        with pytest.raises(ValidationError) as caught:
            _patch({"personal_instructions": text})

        assert "Zanzibar" not in str(caught.value)

    def test_account_models_patch_instructions_count_code_points_not_bytes(self) -> None:
        """1500 emoji are 1500 code points but 6000 UTF-8 bytes and 3000 UTF-16 units:
        only a code-point count accepts them (the samples are checked first)."""
        text = _GRINNING_FACE * _INSTRUCTIONS_MAX
        zwj_text = _TECHNOLOGIST * (_INSTRUCTIONS_MAX // 3)

        assert len(text) == _INSTRUCTIONS_MAX
        assert len(text.encode("utf-8")) == 4 * _INSTRUCTIONS_MAX
        assert len(text.encode("utf-16-le")) // 2 == 2 * _INSTRUCTIONS_MAX
        assert len(zwj_text) == _INSTRUCTIONS_MAX
        assert _patch({"personal_instructions": text}).personal_instructions == text
        assert _patch({"personal_instructions": zwj_text}).personal_instructions == zwj_text


# ---------------------------------------------------------------------------
# 7. MyAccountPatch: validation errors never repeat the input
# ---------------------------------------------------------------------------


class TestMyAccountPatchErrorsHideInput:
    """Neither str(ValidationError) nor its error list (without input) repeats a value."""

    @pytest.mark.parametrize(
        ("values", "markers"),
        [
            pytest.param(
                {"timezone": "Quokka/Marmalade"}, ["Quokka", "Marmalade"], id="timezone-unknown"
            ),
            pytest.param({"timezone": "europe/zurich"}, ["europe/zurich"], id="timezone-case"),
            pytest.param({"timezone": "Wombat/" + "W" * 60}, ["Wombat"], id="timezone-too-long"),
            pytest.param(
                {"timezone": "../Capybara/passwd"}, ["Capybara"], id="timezone-path-traversal"
            ),
            pytest.param(
                {"personal_instructions": "Zanzibar" + _NUL + "launch codes"},
                ["Zanzibar", "launch codes"],
                id="instructions-control-char",
            ),
            pytest.param(
                {"personal_instructions": "Pangolin " * 200},
                ["Pangolin"],
                id="instructions-too-long",
            ),
            pytest.param(
                {"name": "Quetzalcoatl" + _RTL_OVERRIDE + "Hopper"},
                ["Quetzalcoatl", "Hopper"],
                id="name-invisible-char",
            ),
            pytest.param(
                {"name": "Xylophonist" + _NEWLINE + "Bcc: eve@evil.example"},
                ["Xylophonist", "eve@evil"],
                id="name-newline",
            ),
            pytest.param({"name": "Marmalade" * 14}, ["Marmalade"], id="name-too-long"),
            pytest.param({"ui_language": "klingon-marker"}, ["klingon-marker"], id="ui-language"),
            pytest.param(
                {"response_language": "esperanto-marker"},
                ["esperanto-marker"],
                id="response-language",
            ),
            pytest.param(
                {"ui_language": "de", "password": "hunter2-marker"},
                ["hunter2-marker"],
                id="extra-password",
            ),
            pytest.param(
                {"ui_language": "de", "email": "eve-marker@evil.example"},
                ["eve-marker"],
                id="extra-email",
            ),
        ],
    )
    def test_account_models_patch_error_hides_input(
        self, values: dict[str, Any], markers: list[str]
    ) -> None:
        with pytest.raises(ValidationError) as caught:
            _patch(values)

        text = str(caught.value)
        details = json.dumps(
            caught.value.errors(include_input=False, include_url=False), default=str
        )
        for marker in markers:
            assert marker not in text, text
            assert marker not in details, details


# ---------------------------------------------------------------------------
# 8. PasswordChangeRequest
# ---------------------------------------------------------------------------

_CURRENT = "Old Password 2025!"
_NEW = "Correct Horse Battery Staple"


class TestPasswordChangeRequest:
    """Two SecretStr fields of 1 to 1024 characters; nothing else."""

    def test_account_models_password_request_has_exactly_the_contract_fields(self) -> None:
        assert set(_model("PasswordChangeRequest").model_fields) == _PASSWORD_FIELDS

    def test_account_models_password_request_fields_are_secret(self) -> None:
        request = _password_request({"current_password": _CURRENT, "new_password": _NEW})

        assert isinstance(request.current_password, SecretStr)
        assert isinstance(request.new_password, SecretStr)
        assert request.current_password.get_secret_value() == _CURRENT
        assert request.new_password.get_secret_value() == _NEW

    def test_account_models_password_request_repr_hides_the_passwords(self) -> None:
        request = _password_request({"current_password": _CURRENT, "new_password": _NEW})

        for text in (repr(request), str(request), request.model_dump_json()):
            assert _CURRENT not in text
            assert _NEW not in text
            assert "Horse" not in text

    def test_account_models_password_request_keeps_the_passwords_as_typed(self) -> None:
        """Surrounding spaces are part of a password: nothing is stripped."""
        request = _password_request(
            {"current_password": "  spaced out  ", "new_password": " " + _NEW + " "}
        )

        assert request.current_password.get_secret_value() == "  spaced out  "
        assert request.new_password.get_secret_value() == " " + _NEW + " "

    @pytest.mark.parametrize("field", sorted(_PASSWORD_FIELDS))
    @pytest.mark.parametrize("length", [1, _PASSWORD_MAX])
    def test_account_models_password_request_accepts_bound_length(
        self, field: str, length: int
    ) -> None:
        values = {"current_password": _CURRENT, "new_password": _NEW, field: "p" * length}

        request = _password_request(values)

        assert getattr(request, field).get_secret_value() == "p" * length

    @pytest.mark.parametrize("field", sorted(_PASSWORD_FIELDS))
    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("", id="empty"),
            pytest.param("p" * (_PASSWORD_MAX + 1), id="1025-chars"),
            pytest.param(None, id="null"),
            pytest.param(12345678, id="int"),
            pytest.param(["secret"], id="list"),
        ],
    )
    def test_account_models_password_request_rejects_value(self, field: str, value: Any) -> None:
        values = {"current_password": _CURRENT, "new_password": _NEW, field: value}

        assert not _accepted(lambda: _password_request(values))

    @pytest.mark.parametrize("missing", sorted(_PASSWORD_FIELDS))
    def test_account_models_password_request_rejects_missing_field(self, missing: str) -> None:
        values = {"current_password": _CURRENT, "new_password": _NEW}
        del values[missing]

        assert not _accepted(lambda: _password_request(values))

    @pytest.mark.parametrize(
        "key", ["email", "user_id", "org_id", "confirm_password", "new_password_confirm", "role"]
    )
    def test_account_models_password_request_rejects_unknown_field(self, key: str) -> None:
        values = {"current_password": _CURRENT, "new_password": _NEW, key: "x"}

        with pytest.raises(ValidationError) as caught:
            _password_request(values)

        errors = caught.value.errors(include_input=False, include_url=False)
        assert [(e["loc"], e["type"]) for e in errors] == [((key,), "extra_forbidden")]
