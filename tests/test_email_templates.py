"""Tests for admino.email_templates — the transactional email templates (GH-148, GH-164).

admino sends eight kinds of transactional email: invitation, password reset,
account activated, account deactivated, budget alert (the 80% warning), model
deprecation, scheduled org deletion and (GH-164) email changed. Each one is a
params model plus a DE, FR and EN rendering in plain text and minimal HTML,
picked by the recipient's ``ui_language``.

What these tests pin down:
- EmailTemplate is the closed catalog of the 8 template keys, EmailLanguage is
  exactly de/fr/en, and TEMPLATE_PARAMS maps every key to its params model.
- The params models are SealedModels (frozen, extra="forbid"), and their
  fields follow the field-kind rule: the only str fields are ``org_name`` and
  ``*_link``, and everything else is a timezone-aware datetime or a date. So a
  template can't be given a content field (project, chat or file names,
  message text, user names, addresses): an extra key is a ValidationError.
- ``org_name`` is 1 to 120 characters, not blank, and refuses control, format
  and line/paragraph separator characters (it reaches the Subject header).
  Links are absolute https URLs (http only for localhost), with a host, no
  userinfo, and no whitespace, control characters, ``<``, ``>`` or ``"``.
- params_for() validates stored JSON back into the right model (round trip).
- render() produces a RenderedEmail per language. The raw org name, the links
  and the per-language dates (UTC, month names) appear in the text. The three
  languages differ, no placeholder is left behind, the subject is one line,
  and the HTML is minimal (doctype, lang attribute, <a href> links, every
  value HTML-escaped, no scripts or remote resources).
- GH-164: ``EmailTemplate.EMAIL_CHANGED`` ("email_changed") with
  ``EmailChangedParams`` (only ``org_name``): the notice an Org Admin's email
  change sends to the user's old address. Its DE/FR/EN copy names the org,
  says an administrator changed the sign-in address and to contact the org's
  administrator if unexpected, and never carries an address ('@'), a name or
  a link. The GH-164 names are looked up at call time (``_cls``, string keys
  for "email_changed"), so the rest of the file keeps collecting before they
  exist.

The module is pure: no I/O and no logging. Nothing is mocked because nothing
external is touched.

Security notes:
- No org content in email (tracker #139 §5): only the org display name, links
  and dates. The ModelDeprecation email doesn't even name the model.
- Header injection: nothing that reaches the subject can carry CR, LF or other
  control/separator characters.
- HTML injection: every param value is escaped in the HTML part; links can't
  be javascript:, data: or mailto: URLs, and can't break out of an attribute.
"""

from __future__ import annotations

import ast
import html as html_lib
import json
import logging
import re
import sys
from datetime import UTC, date, datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, get_args

import pytest
from pydantic import ValidationError

import admino.email_templates as templates_mod
from admino.access import SealedModel
from admino.email_templates import (
    TEMPLATE_PARAMS,
    AccountActivatedParams,
    AccountDeactivatedParams,
    BudgetAlertParams,
    EmailLanguage,
    EmailTemplate,
    InvitationParams,
    ModelDeprecationParams,
    OrgDeletionScheduledParams,
    PasswordResetParams,
    RenderedEmail,
    TemplateParams,
    params_for,
    render,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LANGUAGES: tuple[str, ...] = ("de", "fr", "en")

_ORG_NAME = "Müller & Partner AG"
_ACCEPT_LINK = "https://admino.example.ch/invite/inv-tok-4f9a2c"
_RESET_LINK = "https://admino.example.ch/reset/rst-tok-8c2e71"
_LOGIN_LINK = "https://admino.example.ch/login"
_USAGE_LINK = "https://admino.example.ch/admin/usage"
_MODELS_LINK = "https://admino.example.ch/admin/models"
_EXPIRES_AT = datetime(2026, 9, 1, 14, 30, tzinfo=UTC)
_PURGE_AFTER = datetime(2026, 10, 15, 23, 45, tzinfo=UTC)
_BUDGET_MONTH = date(2026, 9, 1)
_RETIRES_ON = date(2026, 12, 31)

# Characters built with chr() so they survive editing tools verbatim.
_NUL = chr(0x00)
_TAB = chr(0x09)
_NEWLINE = chr(0x0A)
_CARRIAGE_RETURN = chr(0x0D)
_DELETE = chr(0x7F)
_NEXT_LINE = chr(0x85)  # NEL, category Cc
_NO_BREAK_SPACE = chr(0xA0)
_SOFT_HYPHEN = chr(0xAD)  # category Cf
_ZERO_WIDTH_SPACE = chr(0x200B)  # category Cf
_ZERO_WIDTH_JOINER = chr(0x200D)  # category Cf
_LINE_SEPARATOR = chr(0x2028)  # category Zl
_PARAGRAPH_SEPARATOR = chr(0x2029)  # category Zp
_RTL_OVERRIDE = chr(0x202E)  # category Cf
_IDEOGRAPHIC_SPACE = chr(0x3000)
_BYTE_ORDER_MARK = chr(0xFEFF)  # category Cf

_SPEC_TEMPLATE_KEYS: frozenset[str] = frozenset(
    {
        "invitation",
        "password_reset",
        "account_activated",
        "account_deactivated",
        "budget_alert",
        "model_deprecation",
        "org_deletion_scheduled",
        # GH-164: the notice to the old address after an Org Admin changed a user's email.
        "email_changed",
    }
)

_EMAIL_CHANGED = "email_changed"

_CLASSES: dict[EmailTemplate, type[TemplateParams]] = {
    EmailTemplate.INVITATION: InvitationParams,
    EmailTemplate.PASSWORD_RESET: PasswordResetParams,
    EmailTemplate.ACCOUNT_ACTIVATED: AccountActivatedParams,
    EmailTemplate.ACCOUNT_DEACTIVATED: AccountDeactivatedParams,
    EmailTemplate.BUDGET_ALERT: BudgetAlertParams,
    EmailTemplate.MODEL_DEPRECATION: ModelDeprecationParams,
    EmailTemplate.ORG_DELETION_SCHEDULED: OrgDeletionScheduledParams,
}

# Keyed by the template value (EmailTemplate is a StrEnum, so a member finds its entry):
# the GH-164 key exists here before the member does.
_VALID_KWARGS: dict[str, dict[str, Any]] = {
    EmailTemplate.INVITATION: {
        "org_name": _ORG_NAME,
        "accept_link": _ACCEPT_LINK,
        "expires_at": _EXPIRES_AT,
    },
    EmailTemplate.PASSWORD_RESET: {"reset_link": _RESET_LINK, "expires_at": _EXPIRES_AT},
    EmailTemplate.ACCOUNT_ACTIVATED: {"org_name": _ORG_NAME, "login_link": _LOGIN_LINK},
    EmailTemplate.ACCOUNT_DEACTIVATED: {"org_name": _ORG_NAME},
    EmailTemplate.BUDGET_ALERT: {
        "org_name": _ORG_NAME,
        "month": _BUDGET_MONTH,
        "usage_link": _USAGE_LINK,
    },
    EmailTemplate.MODEL_DEPRECATION: {
        "org_name": _ORG_NAME,
        "retires_on": _RETIRES_ON,
        "models_link": _MODELS_LINK,
    },
    EmailTemplate.ORG_DELETION_SCHEDULED: {"org_name": _ORG_NAME, "purge_after": _PURGE_AFTER},
    _EMAIL_CHANGED: {"org_name": _ORG_NAME},
}

# The exact fields of every params model: nothing that could carry org content.
_SPEC_FIELDS: dict[str, frozenset[str]] = {
    EmailTemplate.INVITATION: frozenset({"org_name", "accept_link", "expires_at"}),
    EmailTemplate.PASSWORD_RESET: frozenset({"reset_link", "expires_at"}),
    EmailTemplate.ACCOUNT_ACTIVATED: frozenset({"org_name", "login_link"}),
    EmailTemplate.ACCOUNT_DEACTIVATED: frozenset({"org_name"}),
    EmailTemplate.BUDGET_ALERT: frozenset({"org_name", "month", "usage_link"}),
    EmailTemplate.MODEL_DEPRECATION: frozenset({"org_name", "retires_on", "models_link"}),
    EmailTemplate.ORG_DELETION_SCHEDULED: frozenset({"org_name", "purge_after"}),
    _EMAIL_CHANGED: frozenset({"org_name"}),
}

# JSON schema format of every non-str field: "date-time" for datetimes, "date" for dates.
_TEMPORAL_FORMATS: dict[tuple[EmailTemplate, str], str] = {
    (EmailTemplate.INVITATION, "expires_at"): "date-time",
    (EmailTemplate.PASSWORD_RESET, "expires_at"): "date-time",
    (EmailTemplate.BUDGET_ALERT, "month"): "date",
    (EmailTemplate.MODEL_DEPRECATION, "retires_on"): "date",
    (EmailTemplate.ORG_DELETION_SCHEDULED, "purge_after"): "date-time",
}

# The date fragments each template's text must show for the sample params.
_EXPECTED_DATES: dict[EmailTemplate, dict[str, tuple[str, ...]]] = {
    EmailTemplate.INVITATION: {
        "de": ("1. September 2026", "14:30 UTC"),
        "fr": ("1 septembre 2026", "14:30 UTC"),
        "en": ("1 September 2026", "14:30 UTC"),
    },
    EmailTemplate.PASSWORD_RESET: {
        "de": ("1. September 2026", "14:30 UTC"),
        "fr": ("1 septembre 2026", "14:30 UTC"),
        "en": ("1 September 2026", "14:30 UTC"),
    },
    EmailTemplate.BUDGET_ALERT: {
        "de": ("September 2026",),
        "fr": ("septembre 2026",),
        "en": ("September 2026",),
    },
    EmailTemplate.MODEL_DEPRECATION: {
        "de": ("31. Dezember 2026",),
        "fr": ("31 décembre 2026",),
        "en": ("31 December 2026",),
    },
    EmailTemplate.ORG_DELETION_SCHEDULED: {
        "de": ("15. Oktober 2026", "23:45 UTC"),
        "fr": ("15 octobre 2026", "23:45 UTC"),
        "en": ("15 October 2026", "23:45 UTC"),
    },
}

_MONTH_NAMES: dict[str, tuple[str, ...]] = {
    "de": (
        "Januar",
        "Februar",
        "März",
        "April",
        "Mai",
        "Juni",
        "Juli",
        "August",
        "September",
        "Oktober",
        "November",
        "Dezember",
    ),
    "fr": (
        "janvier",
        "février",
        "mars",
        "avril",
        "mai",
        "juin",
        "juillet",
        "août",
        "septembre",
        "octobre",
        "novembre",
        "décembre",
    ),
    "en": (
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ),
}

# A loose language marker per language: a word the text of every template uses.
_LANGUAGE_MARKERS: dict[str, re.Pattern[str]] = {
    "de": re.compile(r"organisation|konto", re.IGNORECASE),
    "fr": re.compile(r"organisation|compte", re.IGNORECASE),
    "en": re.compile(r"organization|account", re.IGNORECASE),
}

# Leftover template syntax: {field}, {{ field }}, ${field}, $field, %(field)s.
_PLACEHOLDER_RE = re.compile(r"\{\{?\s*[A-Za-z_]\w*\s*\}\}?|\$\{?[A-Za-z_]\w*|%\(\w+\)[sd]")

# Keys that would carry org content or personal data: never a template field.
_CONTENT_KEYS: tuple[str, ...] = (
    "project_name",
    "project_title",
    "chat_title",
    "chat_name",
    "file_name",
    "message",
    "message_text",
    "content",
    "body",
    "subject",
    "user_name",
    "email",
    "note",
    "model_name",
)

_SRC_DIR = Path(templates_mod.__file__).resolve().parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _email_changed_params() -> type[TemplateParams]:
    """GH-164's EmailChangedParams, looked up at call time (AttributeError until it exists)."""
    cls: type[TemplateParams] = templates_mod.EmailChangedParams
    return cls


def _email_changed_template() -> EmailTemplate:
    """GH-164's EmailTemplate.EMAIL_CHANGED (ValueError until it exists)."""
    return EmailTemplate(_EMAIL_CHANGED)


def _cls(template: str) -> type[TemplateParams]:
    """The params class of a template (GH-164's looked up at call time)."""
    if template == _EMAIL_CHANGED:
        return _email_changed_params()
    return _CLASSES[EmailTemplate(template)]


def _params(template: str, **overrides: Any) -> TemplateParams:
    """Build the sample params of a template, with some fields overridden."""
    kwargs = {**_VALID_KWARGS[template], **overrides}
    return _cls(template)(**kwargs)


def _links(params: TemplateParams) -> list[str]:
    """Return every link value of a params instance."""
    return [getattr(params, name) for name in type(params).model_fields if name.endswith("_link")]


def _day_form(language: str, day: int, month: int, year: int) -> str:
    """Format a date the way the spec wants it per language."""
    name = _MONTH_NAMES[language][month - 1]
    if language == "de":
        return f"{day}. {name} {year}"
    return f"{day} {name} {year}"


def _all_cases() -> list[Any]:
    """Every (template, language) pair."""
    return [
        pytest.param(template, language, id=f"{template.value}-{language}")
        for template in EmailTemplate
        for language in _LANGUAGES
    ]


def _org_cases() -> list[Any]:
    """Every (template, language) pair of the templates that carry an org name."""
    return [
        pytest.param(template, language, id=f"{template.value}-{language}")
        for template in EmailTemplate
        if "org_name" in _SPEC_FIELDS[template]
        for language in _LANGUAGES
    ]


def _org_templates() -> list[Any]:
    """Every template with an org_name field."""
    return [
        pytest.param(template, id=template.value)
        for template in EmailTemplate
        if "org_name" in _SPEC_FIELDS[template]
    ]


def _link_fields() -> list[Any]:
    """Every (template, link field) pair."""
    return [
        pytest.param(template, field, id=f"{template.value}-{field}")
        for template in EmailTemplate
        for field in sorted(_SPEC_FIELDS[template])
        if field.endswith("_link")
    ]


def _datetime_fields() -> list[Any]:
    """Every (template, datetime field) pair."""
    return [
        pytest.param(template, field, id=f"{template.value}-{field}")
        for (template, field), kind in _TEMPORAL_FORMATS.items()
        if kind == "date-time"
    ]


def _templates() -> list[Any]:
    """Every template, one param each."""
    return [pytest.param(template, id=template.value) for template in EmailTemplate]


# ---------------------------------------------------------------------------
# 1. The template catalog and the language set
# ---------------------------------------------------------------------------


class TestTemplateCatalog:
    """EmailTemplate is the closed catalog of the 8 email types; languages are de/fr/en."""

    def test_email_templates_template_is_a_str_enum(self) -> None:
        """EmailTemplate is a StrEnum, so its members bind as plain strings."""
        assert issubclass(EmailTemplate, StrEnum)

    def test_email_templates_catalog_has_exactly_the_eight_types(self) -> None:
        """invitation, password reset, account activated/deactivated, budget alert, model
        deprecation, scheduled org deletion and (GH-164) email changed: nothing else."""
        assert {template.value for template in EmailTemplate} == _SPEC_TEMPLATE_KEYS

    @pytest.mark.parametrize(
        ("member", "value"),
        [
            ("INVITATION", "invitation"),
            ("PASSWORD_RESET", "password_reset"),
            ("ACCOUNT_ACTIVATED", "account_activated"),
            ("ACCOUNT_DEACTIVATED", "account_deactivated"),
            ("BUDGET_ALERT", "budget_alert"),
            ("MODEL_DEPRECATION", "model_deprecation"),
            ("ORG_DELETION_SCHEDULED", "org_deletion_scheduled"),
            ("EMAIL_CHANGED", "email_changed"),
        ],
    )
    def test_email_templates_member_names_map_to_keys(self, member: str, value: str) -> None:
        """Each member has the spec's name and stored key."""
        assert EmailTemplate[member].value == value

    def test_email_templates_languages_are_de_fr_en(self) -> None:
        """EmailLanguage is exactly the three UI languages (users.ui_language)."""
        assert set(get_args(EmailLanguage)) == {"de", "fr", "en"}

    def test_email_templates_template_params_covers_every_key(self) -> None:
        """TEMPLATE_PARAMS has one entry per template key."""
        assert set(TEMPLATE_PARAMS) == set(EmailTemplate)

    @pytest.mark.parametrize("template", _templates())
    def test_email_templates_template_params_maps_to_the_right_class(
        self, template: EmailTemplate
    ) -> None:
        """Each key maps to its own params class, whose template ClassVar is that key."""
        cls = TEMPLATE_PARAMS[template]

        assert cls is _cls(template)
        assert cls.template is template

    @pytest.mark.parametrize("template", _templates())
    def test_email_templates_params_are_sealed_template_params(
        self, template: EmailTemplate
    ) -> None:
        """Every params model is a TemplateParams and a SealedModel (frozen, extra="forbid")."""
        cls = _cls(template)

        assert issubclass(cls, TemplateParams)
        assert issubclass(cls, SealedModel)
        assert cls.model_config.get("extra") == "forbid"
        assert cls.model_config.get("frozen") is True


# ---------------------------------------------------------------------------
# 2. Params models: the field-kind rule and "no content fields"
# ---------------------------------------------------------------------------


class TestParamsFields:
    """The params models hold only an org name, links and dates."""

    @pytest.mark.parametrize("template", _templates())
    def test_email_templates_params_have_exactly_the_spec_fields(
        self, template: EmailTemplate
    ) -> None:
        """No extra field (a project, chat or file name, message text, user name, address)."""
        assert set(_cls(template).model_fields) == _SPEC_FIELDS[template]

    @pytest.mark.parametrize("template", _templates())
    def test_email_templates_str_fields_are_only_org_name_and_links(
        self, template: EmailTemplate
    ) -> None:
        """The field-kind rule: a str field is org_name or ends in _link; every other field
        is a datetime or a date (JSON schema format date-time or date)."""
        cls = _cls(template)
        schema = cls.model_json_schema()["properties"]
        for name, field in cls.model_fields.items():
            if name == "org_name" or name.endswith("_link"):
                assert field.annotation is str, name
            else:
                assert schema[name].get("format") == _TEMPORAL_FORMATS[(template, name)], name

    @pytest.mark.parametrize("template", _templates())
    def test_email_templates_template_classvar_is_not_a_field(
        self, template: EmailTemplate
    ) -> None:
        """template is a ClassVar: not a field, and not in the dumped params."""
        params = _params(template)

        assert "template" not in _cls(template).model_fields
        assert "template" not in params.model_dump(mode="json")
        assert params.template is template

    @pytest.mark.parametrize(
        ("template", "key"),
        [
            pytest.param(template, key, id=f"{template.value}-{key}")
            for template in EmailTemplate
            for key in _CONTENT_KEYS
        ],
    )
    def test_email_templates_params_refuse_content_fields(
        self, template: EmailTemplate, key: str
    ) -> None:
        """A template can't be given a content field: the extra key is a ValidationError."""
        with pytest.raises(ValidationError):
            _params(template, **{key: "Project Alpha: Q3 board minutes.pdf"})

    @pytest.mark.parametrize("template", _templates())
    def test_email_templates_params_are_frozen(self, template: EmailTemplate) -> None:
        """A built params instance can't be changed."""
        params = _params(template)
        field = next(iter(_SPEC_FIELDS[template]))

        with pytest.raises(ValidationError):
            setattr(params, field, getattr(params, field))

    @pytest.mark.parametrize("template", _templates())
    def test_email_templates_params_refuse_unvalidated_construction(
        self, template: EmailTemplate
    ) -> None:
        """model_construct() (which skips validation) is refused, as for every SealedModel."""
        with pytest.raises(TypeError):
            _cls(template).model_construct(**_VALID_KWARGS[template])

    @pytest.mark.parametrize("template", _templates())
    def test_email_templates_params_refuse_copy_with_update(self, template: EmailTemplate) -> None:
        """model_copy(update=...) (which skips validation) is refused."""
        params = _params(template)

        with pytest.raises(TypeError):
            params.model_copy(update={"org_name": "Other"})

    @pytest.mark.parametrize("template", _templates())
    def test_email_templates_params_require_every_field(self, template: EmailTemplate) -> None:
        """Every field is required: a missing one is a ValidationError."""
        for field in _SPEC_FIELDS[template]:
            kwargs = dict(_VALID_KWARGS[template])
            del kwargs[field]
            with pytest.raises(ValidationError):
                _cls(template)(**kwargs)


# ---------------------------------------------------------------------------
# 3. org_name validation (it reaches the Subject header)
# ---------------------------------------------------------------------------

_ACCEPTED_ORG_NAMES: list[Any] = [
    pytest.param("Acme AG", id="plain"),
    pytest.param("A", id="one-char"),
    pytest.param("A" * 120, id="120-chars"),
    pytest.param("Müller & Söhne", id="umlauts-and-ampersand"),
    pytest.param("Société Générale SA", id="accents"),
    pytest.param("A&B <b>x</b>", id="markup-like"),
    pytest.param("株式会社アドミノ", id="cjk"),
    pytest.param("Café Zürich GmbH", id="mixed"),
]

_REFUSED_ORG_NAMES: list[Any] = [
    pytest.param("", id="empty"),
    pytest.param(" ", id="space-only"),
    pytest.param("   ", id="spaces-only"),
    pytest.param(_TAB, id="tab-only"),
    pytest.param(_NO_BREAK_SPACE, id="no-break-space-only"),
    pytest.param(_IDEOGRAPHIC_SPACE, id="ideographic-space-only"),
    pytest.param("A" * 121, id="121-chars"),
    pytest.param("Acme" + _CARRIAGE_RETURN + _NEWLINE + "Bcc: eve@evil.example", id="crlf-bcc"),
    pytest.param("Acme" + _NEWLINE + "AG", id="newline"),
    pytest.param("Acme" + _CARRIAGE_RETURN + "AG", id="carriage-return"),
    pytest.param("Acme" + _NUL + "AG", id="nul"),
    pytest.param("Acme" + _TAB + "AG", id="tab"),
    pytest.param("Acme" + _DELETE + "AG", id="delete"),
    pytest.param("Acme" + _NEXT_LINE + "AG", id="next-line"),
    pytest.param("Acme" + _ZERO_WIDTH_SPACE + "AG", id="zero-width-space"),
    pytest.param("Acme" + _ZERO_WIDTH_JOINER + "AG", id="zero-width-joiner"),
    pytest.param("Acme" + _SOFT_HYPHEN + "AG", id="soft-hyphen"),
    pytest.param(_RTL_OVERRIDE + "GA emcA", id="rtl-override"),
    pytest.param(_BYTE_ORDER_MARK + "Acme AG", id="byte-order-mark"),
    pytest.param("Acme" + _LINE_SEPARATOR + "AG", id="line-separator"),
    pytest.param("Acme" + _PARAGRAPH_SEPARATOR + "AG", id="paragraph-separator"),
    pytest.param(None, id="none"),
    pytest.param(42, id="int"),
]


class TestOrgName:
    """org_name: 1 to 120 chars, not blank, no Cc/Cf/Zl/Zp characters."""

    @pytest.mark.parametrize("template", _org_templates())
    @pytest.mark.parametrize("org_name", _ACCEPTED_ORG_NAMES)
    def test_email_templates_org_name_accepts_display_names(
        self, template: EmailTemplate, org_name: str
    ) -> None:
        """Ordinary organization display names are kept as given."""
        params = _params(template, org_name=org_name)

        assert params.org_name == org_name

    @pytest.mark.parametrize("template", _org_templates())
    @pytest.mark.parametrize("org_name", _REFUSED_ORG_NAMES)
    def test_email_templates_org_name_refuses_unsafe_values(
        self, template: EmailTemplate, org_name: object
    ) -> None:
        """Blank, too long, or carrying a control, format or line/paragraph separator
        character (header injection): a ValidationError."""
        with pytest.raises(ValidationError):
            _params(template, org_name=org_name)


# ---------------------------------------------------------------------------
# 4. Link validation
# ---------------------------------------------------------------------------

_LONGEST_LINK = "https://admino.example.ch/" + "a" * (2048 - len("https://admino.example.ch/"))

_ACCEPTED_LINKS: list[Any] = [
    pytest.param("https://admino.example.ch/invite/abc123", id="https"),
    pytest.param("https://admino.example.ch", id="https-no-path"),
    pytest.param("https://admino.example.ch:8443/x", id="https-port"),
    pytest.param("https://admino.example.ch/reset?token=abc&lang=de", id="https-query"),
    pytest.param("https://admino.example.ch/a#section", id="https-fragment"),
    pytest.param("http://localhost:8000/invite/abc", id="http-localhost"),
    pytest.param("http://localhost/invite/abc", id="http-localhost-no-port"),
    pytest.param("http://127.0.0.1:8000/reset/x", id="http-loopback-v4"),
    pytest.param("http://[::1]:8000/login", id="http-loopback-v6"),
    pytest.param(_LONGEST_LINK, id="2048-chars"),
]

_REFUSED_LINKS: list[Any] = [
    pytest.param("", id="empty"),
    pytest.param("Quarterly report", id="free-text"),
    pytest.param("report.pdf", id="file-name"),
    pytest.param("javascript:alert(1)", id="javascript"),
    pytest.param("JavaScript:alert(document.cookie)", id="javascript-mixed-case"),
    pytest.param("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", id="data"),
    pytest.param("mailto:alice@example.ch", id="mailto"),
    pytest.param("ftp://admino.example.ch/x", id="ftp"),
    pytest.param("file:///etc/passwd", id="file"),
    pytest.param("http://admino.example.ch/invite/abc", id="http-public-host"),
    pytest.param("http://localhost.evil.example/x", id="http-localhost-lookalike"),
    pytest.param("http://127.0.0.1.nip.io/x", id="http-loopback-lookalike"),
    pytest.param("http://127.0.0.2/x", id="http-other-loopback"),
    pytest.param("http://0.0.0.0/x", id="http-any-address"),
    pytest.param("http://localhost:8000@evil.example/x", id="http-localhost-as-userinfo"),
    pytest.param("https://user:pass@admino.example.ch/x", id="userinfo"),
    pytest.param("https://user@admino.example.ch/x", id="username-only"),
    pytest.param("https:///invite/abc", id="no-host"),
    pytest.param("//admino.example.ch/x", id="scheme-relative"),
    pytest.param("/invite/abc", id="relative-path"),
    pytest.param("https://admino.example.ch/a b", id="space"),
    pytest.param(" https://admino.example.ch/x", id="leading-space"),
    pytest.param("https://admino.example.ch/x ", id="trailing-space"),
    pytest.param("https://admino.example.ch/a" + _TAB + "b", id="tab"),
    pytest.param("https://admino.example.ch/a" + _NEWLINE + "b", id="newline"),
    pytest.param("https://admino.example.ch/a" + _CARRIAGE_RETURN + "b", id="carriage-return"),
    pytest.param("https://admino.example.ch/a" + _NUL + "b", id="nul"),
    pytest.param("https://admino.example.ch/a" + _DELETE + "b", id="delete"),
    pytest.param("https://admino.example.ch/a" + _NO_BREAK_SPACE + "b", id="no-break-space"),
    pytest.param("https://admino.example.ch/a" + _LINE_SEPARATOR + "b", id="line-separator"),
    pytest.param("https://admino.example.ch/<script>", id="less-than"),
    pytest.param("https://admino.example.ch/x>", id="greater-than"),
    pytest.param('https://admino.example.ch/x"onmouseover="alert(1)', id="double-quote"),
    pytest.param(_LONGEST_LINK + "a", id="2049-chars"),
    pytest.param(None, id="none"),
]


# A one-time token inside refused links; it must never reach an error's text.
_LINK_SECRET = "tok-7Qx9SECRETb2Lm"

_SECRET_REFUSED_LINKS: list[Any] = [
    pytest.param("https://admino.example.ch" + chr(0xFF03) + _LINK_SECRET, id="fullwidth-hash"),
    pytest.param("https://admino.example.ch" + chr(0xFF0F) + _LINK_SECRET, id="fullwidth-slash"),
    pytest.param(
        "https://admino.example.ch" + chr(0xFF1F) + "t=" + _LINK_SECRET, id="fullwidth-question"
    ),
    pytest.param("https://" + _LINK_SECRET + chr(0xFF20) + "admino.example.ch", id="fullwidth-at"),
    pytest.param("https://admino.example.ch" + chr(0xFF1A) + _LINK_SECRET, id="fullwidth-colon"),
    pytest.param("https://u:" + _LINK_SECRET + "@admino.example.ch/x", id="userinfo"),
    pytest.param("http://admino.example.ch/invite/" + _LINK_SECRET, id="http-public-host"),
    pytest.param("javascript:" + _LINK_SECRET, id="javascript"),
    pytest.param("https://admino.example.ch/<" + _LINK_SECRET, id="less-than"),
]


class TestLinks:
    """Every *_link is an absolute https URL (http for localhost only), safe in an href."""

    @pytest.mark.parametrize(("template", "field"), _link_fields())
    @pytest.mark.parametrize("link", _ACCEPTED_LINKS)
    def test_email_templates_link_accepts_https_and_local_http(
        self, template: EmailTemplate, field: str, link: str
    ) -> None:
        """https URLs with a host, and http for localhost / 127.0.0.1 / [::1], are kept
        verbatim (no normalization, so the link in the email is the one issued)."""
        params = _params(template, **{field: link})

        assert getattr(params, field) == link

    @pytest.mark.parametrize(("template", "field"), _link_fields())
    @pytest.mark.parametrize("link", _REFUSED_LINKS)
    def test_email_templates_link_refuses_unsafe_values(
        self, template: EmailTemplate, field: str, link: object
    ) -> None:
        """Free text, other schemes, public http, userinfo, missing host, whitespace, control
        characters, attribute-breaking characters and over-long links: a ValidationError."""
        with pytest.raises(ValidationError):
            _params(template, **{field: link})

    @pytest.mark.parametrize(("template", "field"), _link_fields())
    @pytest.mark.parametrize("link", _SECRET_REFUSED_LINKS)
    def test_email_templates_link_errors_never_repeat_the_link(
        self, template: EmailTemplate, field: str, link: str
    ) -> None:
        """A refused link can carry a one-time token, so the error's text, messages and
        context never repeat it, including the stdlib's own urlsplit() errors, which
        echo the netloc for NFKC confusables of "#", "/", "?", "@" and ":"."""
        with pytest.raises(ValidationError) as caught:
            _params(template, **{field: link})

        exc = caught.value
        assert _LINK_SECRET not in str(exc)
        for error in exc.errors():
            assert _LINK_SECRET not in error["msg"]
            assert _LINK_SECRET not in str(error.get("ctx", ""))


# ---------------------------------------------------------------------------
# 5. Datetime and date fields
# ---------------------------------------------------------------------------


class TestTemporalFields:
    """Datetimes must be timezone-aware; dates are plain dates."""

    @pytest.mark.parametrize(("template", "field"), _datetime_fields())
    def test_email_templates_naive_datetime_is_refused(
        self, template: EmailTemplate, field: str
    ) -> None:
        """A naive datetime is ambiguous (which zone?): a ValidationError."""
        with pytest.raises(ValidationError):
            _params(template, **{field: datetime(2026, 9, 1, 14, 30)})

    @pytest.mark.parametrize(("template", "field"), _datetime_fields())
    def test_email_templates_naive_iso_string_is_refused(
        self, template: EmailTemplate, field: str
    ) -> None:
        """A naive ISO string (e.g. from stored JSON) is refused as well."""
        with pytest.raises(ValidationError):
            _params(template, **{field: "2026-09-01T14:30:00"})

    @pytest.mark.parametrize(("template", "field"), _datetime_fields())
    def test_email_templates_aware_datetime_with_offset_is_accepted(
        self, template: EmailTemplate, field: str
    ) -> None:
        """Any timezone-aware datetime is accepted (it's converted to UTC for display)."""
        value = datetime(2026, 9, 1, 16, 30, tzinfo=timezone(timedelta(hours=2)))

        params = _params(template, **{field: value})

        assert getattr(params, field) == value

    @pytest.mark.parametrize(
        ("template", "field"),
        [
            pytest.param(EmailTemplate.BUDGET_ALERT, "month", id="budget-month"),
            pytest.param(EmailTemplate.MODEL_DEPRECATION, "retires_on", id="retires-on"),
        ],
    )
    def test_email_templates_date_field_accepts_a_date(
        self, template: EmailTemplate, field: str
    ) -> None:
        """month and retires_on are dates."""
        params = _params(template, **{field: date(2027, 2, 28)})

        assert getattr(params, field) == date(2027, 2, 28)

    @pytest.mark.parametrize(
        ("template", "field"),
        [
            pytest.param(EmailTemplate.BUDGET_ALERT, "month", id="budget-month"),
            pytest.param(EmailTemplate.MODEL_DEPRECATION, "retires_on", id="retires-on"),
        ],
    )
    def test_email_templates_date_field_refuses_text(
        self, template: EmailTemplate, field: str
    ) -> None:
        """Free text is not a date."""
        with pytest.raises(ValidationError):
            _params(template, **{field: "next month, after the board meeting"})


# ---------------------------------------------------------------------------
# 6. params_for(): stored JSON back into the model
# ---------------------------------------------------------------------------


class TestParamsFor:
    """params_for() validates stored JSON back into the right model."""

    @pytest.mark.parametrize("template", _templates())
    def test_email_templates_params_for_round_trips_with_the_enum(
        self, template: EmailTemplate
    ) -> None:
        """params_for(p.template, p.model_dump(mode="json")) == p."""
        params = _params(template)

        assert params_for(params.template, params.model_dump(mode="json")) == params

    @pytest.mark.parametrize("template", _templates())
    def test_email_templates_params_for_round_trips_with_the_stored_key(
        self, template: EmailTemplate
    ) -> None:
        """The stored template_key string and the JSON text (as the outbox keeps them)."""
        params = _params(template)
        stored = json.loads(json.dumps(params.model_dump(mode="json")))

        result = params_for(template.value, stored)

        assert result == params
        assert type(result) is _cls(template)

    @pytest.mark.parametrize(
        "template_key",
        [
            pytest.param("newsletter", id="unknown"),
            pytest.param("", id="empty"),
            pytest.param("INVITATION", id="upper-case"),
            pytest.param("invitation ", id="trailing-space"),
            pytest.param("Invitation", id="capitalized"),
        ],
    )
    def test_email_templates_params_for_refuses_unknown_template(self, template_key: str) -> None:
        """An unknown template key is a ValueError."""
        data = _params(EmailTemplate.INVITATION).model_dump(mode="json")

        with pytest.raises(ValueError, match=r".*"):
            params_for(template_key, data)

    @pytest.mark.parametrize(
        "data",
        [
            pytest.param({}, id="empty"),
            pytest.param({"org_name": _ORG_NAME}, id="missing-fields"),
            pytest.param(
                {
                    "org_name": _ORG_NAME,
                    "accept_link": _ACCEPT_LINK,
                    "expires_at": "2026-09-01T14:30:00Z",
                    "project_name": "Project Alpha",
                },
                id="extra-content-field",
            ),
            pytest.param(
                {
                    "org_name": _ORG_NAME,
                    "accept_link": "javascript:alert(1)",
                    "expires_at": "2026-09-01T14:30:00Z",
                },
                id="bad-link",
            ),
            pytest.param(
                {
                    "org_name": _ORG_NAME,
                    "accept_link": _ACCEPT_LINK,
                    "expires_at": "2026-09-01T14:30:00",
                },
                id="naive-datetime",
            ),
            pytest.param(
                {"org_name": 7, "accept_link": _ACCEPT_LINK, "expires_at": "2026-09-01T14:30:00Z"},
                id="wrong-type",
            ),
        ],
    )
    def test_email_templates_params_for_refuses_bad_data(self, data: dict[str, Any]) -> None:
        """Data that doesn't validate against the template's model is a ValueError (pydantic's
        ValidationError is one)."""
        with pytest.raises(ValueError, match=r".*"):
            params_for(EmailTemplate.INVITATION, data)

    def test_email_templates_params_for_picks_the_template_model(self) -> None:
        """The same data validates only against the model of the given template."""
        data = _params(EmailTemplate.ACCOUNT_DEACTIVATED).model_dump(mode="json")

        with pytest.raises(ValueError, match=r".*"):
            params_for(EmailTemplate.INVITATION, data)


# ---------------------------------------------------------------------------
# 7. render(): per-language text, subject and HTML
# ---------------------------------------------------------------------------


class TestRenderBasics:
    """render() returns a RenderedEmail for every template in every language."""

    @pytest.mark.parametrize(("template", "language"), _all_cases())
    def test_email_templates_render_returns_a_rendered_email(
        self, template: EmailTemplate, language: str
    ) -> None:
        """A RenderedEmail with a non-empty subject, text and HTML."""
        rendered = render(_params(template), language)

        assert isinstance(rendered, RenderedEmail)
        assert isinstance(rendered.subject, str)
        assert isinstance(rendered.text, str)
        assert isinstance(rendered.html, str)
        assert rendered.subject.strip()
        assert rendered.text.strip()
        assert rendered.html.strip()

    def test_email_templates_rendered_email_is_immutable(self) -> None:
        """RenderedEmail is frozen (a frozen dataclass or a NamedTuple)."""
        rendered = render(_params(EmailTemplate.INVITATION), "en")

        with pytest.raises(AttributeError):
            rendered.subject = "changed"

    @pytest.mark.parametrize(
        "language",
        [
            pytest.param("it", id="italian"),
            pytest.param("EN", id="upper-case"),
            pytest.param("", id="empty"),
            pytest.param("de-CH", id="region-tag"),
            pytest.param(" de", id="leading-space"),
            pytest.param("english", id="language-name"),
        ],
    )
    def test_email_templates_render_refuses_other_languages(self, language: str) -> None:
        """Only de, fr and en exist: anything else is a ValueError."""
        with pytest.raises(ValueError, match=r".*"):
            render(_params(EmailTemplate.INVITATION), language)

    @pytest.mark.parametrize("template", _templates())
    def test_email_templates_languages_differ(self, template: EmailTemplate) -> None:
        """DE, FR and EN produce three different subjects and three different texts."""
        rendered = [render(_params(template), lang) for lang in _LANGUAGES]

        assert len({r.subject for r in rendered}) == 3
        assert len({r.text for r in rendered}) == 3
        assert len({r.html for r in rendered}) == 3

    @pytest.mark.parametrize(("template", "language"), _all_cases())
    def test_email_templates_text_is_in_the_requested_language(
        self, template: EmailTemplate, language: str
    ) -> None:
        """A loose language marker: DE says Organisation/Konto, FR organisation/compte, EN
        organization/account."""
        rendered = render(_params(template), language)

        assert _LANGUAGE_MARKERS[language].search(rendered.text), rendered.text

    @pytest.mark.parametrize(("template", "language"), _all_cases())
    def test_email_templates_no_placeholder_is_left(
        self, template: EmailTemplate, language: str
    ) -> None:
        """No {field}, {{ field }}, ${field}, $field or %(field)s survives rendering."""
        rendered = render(_params(template), language)

        for part in (rendered.subject, rendered.text, rendered.html):
            assert _PLACEHOLDER_RE.search(part) is None, part

    @pytest.mark.parametrize(("template", "language"), _all_cases())
    def test_email_templates_subject_is_one_line(
        self, template: EmailTemplate, language: str
    ) -> None:
        """The subject has no CR, LF or other line break (it becomes a header)."""
        rendered = render(_params(template), language)

        assert rendered.subject == rendered.subject.strip()
        assert len(rendered.subject.splitlines()) == 1

    @pytest.mark.parametrize(("template", "language"), _all_cases())
    def test_email_templates_text_is_plain(self, template: EmailTemplate, language: str) -> None:
        """The text part carries no HTML markup."""
        rendered = render(_params(template), language)

        assert (
            re.search(r"<\s*/?\s*(?:a|p|br|html|body|div|span|b|strong)\b", rendered.text) is None
        )

    def test_email_templates_render_is_pure(self, caplog: pytest.LogCaptureFixture) -> None:
        """Rendering logs nothing (the module does no I/O and no logging)."""
        caplog.set_level(logging.DEBUG)

        for template in EmailTemplate:
            for language in _LANGUAGES:
                render(_params(template), language)

        assert caplog.records == []


class TestRenderValues:
    """The org name, the links and the formatted dates appear in the text."""

    @pytest.mark.parametrize(("template", "language"), _org_cases())
    def test_email_templates_text_contains_the_raw_org_name(
        self, template: EmailTemplate, language: str
    ) -> None:
        """The org display name appears as given (not escaped) in the plain text."""
        rendered = render(_params(template), language)

        assert _ORG_NAME in rendered.text

    @pytest.mark.parametrize(("template", "language"), _all_cases())
    def test_email_templates_text_contains_every_link_verbatim(
        self, template: EmailTemplate, language: str
    ) -> None:
        """Each link appears character for character in the plain text."""
        params = _params(template)
        rendered = render(params, language)

        for link in _links(params):
            assert link in rendered.text

    @pytest.mark.parametrize(
        ("template", "language"),
        [
            pytest.param(template, language, id=f"{template.value}-{language}")
            for template in _EXPECTED_DATES
            for language in _LANGUAGES
        ],
    )
    def test_email_templates_text_contains_formatted_dates(
        self, template: EmailTemplate, language: str
    ) -> None:
        """Dates use month names per language (de "1. September 2026", fr "1 septembre 2026",
        en "1 September 2026"); datetimes add "14:30 UTC"; the budget month is month + year."""
        rendered = render(_params(template), language)

        for fragment in _EXPECTED_DATES[template][language]:
            assert fragment in rendered.text, (fragment, rendered.text)

    @pytest.mark.parametrize("language", _LANGUAGES)
    def test_email_templates_datetimes_are_shown_in_utc(self, language: str) -> None:
        """01:30 on 2 September at UTC+2 is 23:30 UTC on 1 September."""
        expires_at = datetime(2026, 9, 2, 1, 30, tzinfo=timezone(timedelta(hours=2)))
        rendered = render(_params(EmailTemplate.INVITATION, expires_at=expires_at), language)

        assert _day_form(language, 1, 9, 2026) in rendered.text
        assert "23:30 UTC" in rendered.text
        assert _day_form(language, 2, 9, 2026) not in rendered.text
        assert "01:30" not in rendered.text

    @pytest.mark.parametrize(
        ("language", "month"),
        [
            pytest.param(language, month, id=f"{language}-{month:02d}")
            for language in _LANGUAGES
            for month in range(1, 13)
        ],
    )
    def test_email_templates_dates_use_the_language_month_names(
        self, language: str, month: int
    ) -> None:
        """Every month name per language, day without a leading zero: de "5. März 2026",
        fr "5 mars 2026", en "5 March 2026"."""
        params = _params(EmailTemplate.MODEL_DEPRECATION, retires_on=date(2026, month, 5))
        rendered = render(params, language)

        assert _day_form(language, 5, month, 2026) in rendered.text

    @pytest.mark.parametrize(
        ("language", "month"),
        [
            pytest.param(language, month, id=f"{language}-{month:02d}")
            for language in _LANGUAGES
            for month in range(1, 13)
        ],
    )
    def test_email_templates_budget_month_is_month_and_year(
        self, language: str, month: int
    ) -> None:
        """The budget alert names the month and year: de "März 2027", fr "mars 2027"."""
        params = _params(EmailTemplate.BUDGET_ALERT, month=date(2027, month, 1))
        rendered = render(params, language)

        assert f"{_MONTH_NAMES[language][month - 1]} 2027" in rendered.text

    @pytest.mark.parametrize("language", _LANGUAGES)
    def test_email_templates_budget_month_shows_no_day(self, language: str) -> None:
        """The budget alert is about a month: the day isn't rendered."""
        rendered = render(_params(EmailTemplate.BUDGET_ALERT), language)

        assert _day_form(language, 1, 9, 2026) not in rendered.text

    @pytest.mark.parametrize("language", _LANGUAGES)
    def test_email_templates_date_fields_show_no_time(self, language: str) -> None:
        """A date (retires_on) renders without a time of day."""
        rendered = render(_params(EmailTemplate.MODEL_DEPRECATION), language)

        assert "00:00" not in rendered.text


class TestRenderHtml:
    """The HTML part is minimal, and every value in it is escaped."""

    @pytest.mark.parametrize(("template", "language"), _all_cases())
    def test_email_templates_html_starts_with_doctype(
        self, template: EmailTemplate, language: str
    ) -> None:
        """<!DOCTYPE html> first."""
        rendered = render(_params(template), language)

        assert rendered.html.lstrip().lower().startswith("<!doctype html>")

    @pytest.mark.parametrize(("template", "language"), _all_cases())
    def test_email_templates_html_declares_the_language(
        self, template: EmailTemplate, language: str
    ) -> None:
        """<html lang="de|fr|en">."""
        rendered = render(_params(template), language)

        assert re.search(rf'<html\b[^>]*\blang="{language}"', rendered.html), rendered.html

    @pytest.mark.parametrize(("template", "language"), _all_cases())
    def test_email_templates_html_links_are_anchors(
        self, template: EmailTemplate, language: str
    ) -> None:
        """Each link appears as <a href="..."> with its value HTML-escaped."""
        params = _params(template)
        rendered = render(params, language)

        for link in _links(params):
            href = re.escape(html_lib.escape(link, quote=True))
            assert re.search(rf'<a\b[^>]*\bhref="{href}"', rendered.html), link

    @pytest.mark.parametrize(
        ("template", "field", "language"),
        [
            pytest.param(template, field, language, id=f"{template.value}-{field}-{language}")
            for template in EmailTemplate
            for field in sorted(_SPEC_FIELDS[template])
            if field.endswith("_link")
            for language in _LANGUAGES
        ],
    )
    def test_email_templates_html_escapes_ampersands_in_hrefs(
        self, template: EmailTemplate, field: str, language: str
    ) -> None:
        """A link with & in its query is &amp;-escaped in the href, raw in the text."""
        link = "https://admino.example.ch/reset?token=abc&lang=de"
        rendered = render(_params(template, **{field: link}), language)

        assert 'href="https://admino.example.ch/reset?token=abc&amp;lang=de"' in rendered.html
        assert "token=abc&lang=de" not in rendered.html
        assert link in rendered.text

    @pytest.mark.parametrize(("template", "language"), _org_cases())
    def test_email_templates_html_escapes_the_org_name(
        self, template: EmailTemplate, language: str
    ) -> None:
        """An org name "A&B <b>x</b>" is "A&amp;B &lt;b&gt;x&lt;/b&gt;" in the HTML and raw
        in the text."""
        org_name = "A&B <b>x</b>"
        rendered = render(_params(template, org_name=org_name), language)

        assert "A&amp;B &lt;b&gt;x&lt;/b&gt;" in rendered.html
        assert "<b>x</b>" not in rendered.html
        assert org_name in rendered.text

    @pytest.mark.parametrize(("template", "language"), _org_cases())
    def test_email_templates_html_neutralizes_script_in_org_name(
        self, template: EmailTemplate, language: str
    ) -> None:
        """A <script> in the org name never becomes a tag."""
        org_name = "<script>alert(1)</script>"
        rendered = render(_params(template, org_name=org_name), language)

        assert "<script" not in rendered.html.lower()
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered.html

    @pytest.mark.parametrize(("template", "language"), _all_cases())
    def test_email_templates_html_is_minimal(self, template: EmailTemplate, language: str) -> None:
        """No scripts, forms, iframes or remote resources (no src=, no tracking pixels)."""
        rendered = render(_params(template), language)
        lowered = rendered.html.lower()

        for forbidden in ("<script", "<form", "<iframe", "<img", "<link", " src=", "url("):
            assert forbidden not in lowered, forbidden


# ---------------------------------------------------------------------------
# 8. Module isolation and hygiene
# ---------------------------------------------------------------------------

_ALLOWED_ADMINO: frozenset[str] = frozenset({"admino.access"})
_ALLOWED_THIRD_PARTY: frozenset[str] = frozenset({"pydantic", "pydantic_core"})
# Pure module: no logging and no I/O-capable imports.
_IMPURE_ROOTS: frozenset[str] = frozenset(
    {"logging", "smtplib", "ssl", "socket", "asyncio", "subprocess", "os", "pathlib", "io"}
)


def _imported_modules(path: Path) -> list[str]:
    """Return every module a source file imports, with relative imports resolved under admino."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                base = f"admino.{base}" if base else "admino"
            if base == "admino":
                modules.extend(f"admino.{alias.name}" for alias in node.names)
            else:
                modules.append(base)
    return modules


class TestModuleIsolation:
    """email_templates.py is pure and imports only the stdlib, pydantic and admino.access."""

    def test_email_templates_imports_only_allowed_modules(self) -> None:
        """Only the standard library, pydantic and admino.access: no agent, server, llm*,
        tools, permissions, database or mailer import, and no new dependency."""
        modules = _imported_modules(_SRC_DIR / "email_templates.py")
        disallowed = [
            module
            for module in modules
            if not (
                module.split(".")[0] in sys.stdlib_module_names
                or module.split(".")[0] in _ALLOWED_THIRD_PARTY
                or module in _ALLOWED_ADMINO
            )
        ]

        assert disallowed == []

    def test_email_templates_imports_nothing_impure(self) -> None:
        """No logging, network, filesystem or process module: rendering is pure."""
        modules = _imported_modules(_SRC_DIR / "email_templates.py")
        impure = [
            m
            for m in modules
            if m.split(".")[0] in _IMPURE_ROOTS or m.startswith(("importlib", "urllib.request"))
        ]

        assert impure == []

    def test_email_templates_makes_no_dynamic_code_calls(self) -> None:
        """No eval, exec, compile or __import__."""
        tree = ast.parse((_SRC_DIR / "email_templates.py").read_text(encoding="utf-8"))
        calls = [
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"eval", "exec", "compile", "__import__"}
        ]

        assert calls == []

    def test_email_templates_permission_engine_does_not_import_it(self) -> None:
        """permissions.py gains no import of email_templates."""
        modules = _imported_modules(_SRC_DIR / "permissions.py")

        assert [m for m in modules if m.startswith("admino.email_templates")] == []

    def test_email_templates_docstring_states_the_content_rule(self) -> None:
        """The module docstring documents that templates carry no org content."""
        doc = (templates_mod.__doc__ or "").lower()

        assert "content" in doc


# ---------------------------------------------------------------------------
# 9. GH-164: the email_changed notice (to the old address, no address in it)
# ---------------------------------------------------------------------------

# Fields an email-change notice must never take: the old or new address, a name, a link.
_EMAIL_CHANGED_REFUSED_FIELDS: tuple[str, ...] = (
    "email",
    "new_email",
    "old_email",
    "address",
    "new_address",
    "name",
    "user_name",
    "new_name",
    "admin_name",
    "link",
    "login_link",
    "reset_link",
    "changed_at",
)

# A loose marker per language: the copy talks about the sign-in email address.
_ADDRESS_MARKERS: dict[str, re.Pattern[str]] = {
    "de": re.compile(r"E-Mail-Adresse|E-Mail Adresse|Adresse", re.IGNORECASE),
    "fr": re.compile(r"adresse", re.IGNORECASE),
    "en": re.compile(r"e-?mail address|address", re.IGNORECASE),
}

# A loose marker per language: the copy names the organization's administrator(s).
_ADMIN_MARKERS: dict[str, re.Pattern[str]] = {
    "de": re.compile(r"administr", re.IGNORECASE),
    "fr": re.compile(r"administr", re.IGNORECASE),
    "en": re.compile(r"administr", re.IGNORECASE),
}

# Anything link-like: a scheme, a www host or an anchor.
_LINK_RE = re.compile(r"https?:|://|www\.|href|<\s*a\b|mailto:", re.IGNORECASE)


def _email_changed(**overrides: Any) -> TemplateParams:
    """EmailChangedParams for the sample org name, with fields overridden."""
    return _email_changed_params()(**{"org_name": _ORG_NAME, **overrides})


class TestEmailChangedTemplate:
    """EmailTemplate.EMAIL_CHANGED and EmailChangedParams (org_name only)."""

    def test_email_templates_email_changed_member_is_the_stored_key(self) -> None:
        """EmailTemplate.EMAIL_CHANGED is "email_changed" (the outbox template_key)."""
        member = getattr(EmailTemplate, "EMAIL_CHANGED", None)

        assert member is not None, "EmailTemplate must define EMAIL_CHANGED"
        assert member.value == _EMAIL_CHANGED

    def test_email_templates_email_changed_params_is_in_template_params(self) -> None:
        """TEMPLATE_PARAMS maps the key to EmailChangedParams, whose template is the key."""
        template = _email_changed_template()
        cls = _email_changed_params()

        assert TEMPLATE_PARAMS[template] is cls
        assert cls.template is template

    def test_email_templates_email_changed_params_is_a_sealed_template_params(self) -> None:
        cls = _email_changed_params()

        assert issubclass(cls, TemplateParams)
        assert issubclass(cls, SealedModel)
        assert cls.model_config.get("extra") == "forbid"
        assert cls.model_config.get("frozen") is True

    def test_email_templates_email_changed_params_has_only_org_name(self) -> None:
        """No address, name, link or date: the org name is the whole params."""
        assert set(_email_changed_params().model_fields) == {"org_name"}

    def test_email_templates_email_changed_org_name_is_an_org_name(self) -> None:
        """org_name is a str with OrgName's bounds (same metadata as the other notices)."""
        field = _email_changed_params().model_fields["org_name"]
        reference = AccountDeactivatedParams.model_fields["org_name"]

        assert field.annotation is str
        assert field.metadata == reference.metadata

    def test_email_templates_email_changed_stored_params_are_the_org_name_only(self) -> None:
        """The outbox row's params JSON is {"org_name": ...}, nothing else."""
        assert _email_changed().model_dump(mode="json") == {"org_name": _ORG_NAME}

    @pytest.mark.parametrize("field", _EMAIL_CHANGED_REFUSED_FIELDS)
    def test_email_templates_email_changed_refuses_extra_fields(self, field: str) -> None:
        """An address, a name or a link can't be given: the extra key is a ValidationError."""
        cls = _email_changed_params()

        with pytest.raises(ValidationError):
            cls(org_name=_ORG_NAME, **{field: "new.address@example.ch"})

    @pytest.mark.parametrize(
        "org_name",
        [
            pytest.param("", id="empty"),
            pytest.param("   ", id="blank"),
            pytest.param("A" * 121, id="121-chars"),
            pytest.param("Acme" + _CARRIAGE_RETURN + _NEWLINE + "Bcc: eve@evil.example", id="crlf"),
            pytest.param("Acme" + _ZERO_WIDTH_SPACE + "AG", id="zero-width-space"),
            pytest.param(_RTL_OVERRIDE + "GA emcA", id="rtl-override"),
            pytest.param("Acme" + _LINE_SEPARATOR + "AG", id="line-separator"),
            pytest.param(None, id="none"),
        ],
    )
    def test_email_templates_email_changed_refuses_unsafe_org_names(self, org_name: Any) -> None:
        """The org name reaches the Subject header: OrgName's rules apply."""
        cls = _email_changed_params()

        with pytest.raises(ValidationError):
            cls(org_name=org_name)

    def test_email_templates_email_changed_requires_org_name(self) -> None:
        cls = _email_changed_params()

        with pytest.raises(ValidationError):
            cls()

    def test_email_templates_email_changed_params_for_round_trips(self) -> None:
        """The stored key and JSON params (as the outbox keeps them) give the model back."""
        params = _email_changed()
        stored = json.loads(json.dumps(params.model_dump(mode="json")))

        result = params_for(_EMAIL_CHANGED, stored)

        assert result == params
        assert type(result) is _email_changed_params()

    @pytest.mark.parametrize(
        "data",
        [
            pytest.param({}, id="empty"),
            pytest.param({"org_name": _ORG_NAME, "email": "a@example.ch"}, id="address"),
            pytest.param({"org_name": _ORG_NAME, "login_link": _LOGIN_LINK}, id="link"),
        ],
    )
    def test_email_templates_email_changed_params_for_refuses_bad_data(
        self, data: dict[str, Any]
    ) -> None:
        _email_changed_template()

        with pytest.raises(ValueError, match=r".*"):
            params_for(_EMAIL_CHANGED, data)

    @pytest.mark.parametrize("language", _LANGUAGES)
    def test_email_templates_email_changed_renders(self, language: str) -> None:
        """A RenderedEmail with a non-empty subject, text and HTML in each language."""
        rendered = render(_email_changed(), language)

        assert isinstance(rendered, RenderedEmail)
        assert rendered.subject.strip()
        assert rendered.text.strip()
        assert rendered.html.strip()

    @pytest.mark.parametrize("language", _LANGUAGES)
    def test_email_templates_email_changed_text_names_the_org(self, language: str) -> None:
        """The raw org name in the text, HTML-escaped in the HTML."""
        rendered = render(_email_changed(), language)

        assert _ORG_NAME in rendered.text
        assert html_lib.escape(_ORG_NAME, quote=False) in rendered.html

    @pytest.mark.parametrize("language", _LANGUAGES)
    def test_email_templates_email_changed_subject_is_one_line(self, language: str) -> None:
        rendered = render(_email_changed(), language)

        assert rendered.subject == rendered.subject.strip()
        assert len(rendered.subject.splitlines()) == 1
        assert _CARRIAGE_RETURN not in rendered.subject
        assert _NEWLINE not in rendered.subject

    @pytest.mark.parametrize("language", _LANGUAGES)
    def test_email_templates_email_changed_contains_no_address(self, language: str) -> None:
        """No '@' anywhere: neither the old nor the new address (nor any other)."""
        rendered = render(_email_changed(), language)

        for part in (rendered.subject, rendered.text, rendered.html):
            assert "@" not in part, part

    @pytest.mark.parametrize("language", _LANGUAGES)
    def test_email_templates_email_changed_contains_no_link(self, language: str) -> None:
        """No URL, www host, anchor or mailto: the notice links nowhere."""
        rendered = render(_email_changed(), language)

        for part in (rendered.subject, rendered.text, rendered.html):
            assert _LINK_RE.search(part) is None, part

    @pytest.mark.parametrize("language", _LANGUAGES)
    def test_email_templates_email_changed_no_placeholder_is_left(self, language: str) -> None:
        rendered = render(_email_changed(), language)

        for part in (rendered.subject, rendered.text, rendered.html):
            assert _PLACEHOLDER_RE.search(part) is None, part

    def test_email_templates_email_changed_languages_differ(self) -> None:
        rendered = [render(_email_changed(), language) for language in _LANGUAGES]

        assert len({r.subject for r in rendered}) == 3
        assert len({r.text for r in rendered}) == 3

    @pytest.mark.parametrize("language", _LANGUAGES)
    def test_email_templates_email_changed_says_what_happened(self, language: str) -> None:
        """Loose markers: the copy is about the (sign-in) email address, in the requested
        language, and points to the organization's administrator."""
        text = render(_email_changed(), language).text

        assert _LANGUAGE_MARKERS[language].search(text), text
        assert _ADDRESS_MARKERS[language].search(text), text
        assert _ADMIN_MARKERS[language].search(text), text

    @pytest.mark.parametrize("language", _LANGUAGES)
    def test_email_templates_email_changed_differs_from_the_deactivation_notice(
        self, language: str
    ) -> None:
        """Its own copy, not another template's text reused."""
        changed = render(_email_changed(), language)
        deactivated = render(AccountDeactivatedParams(org_name=_ORG_NAME), language)

        assert changed.subject != deactivated.subject
        assert changed.text != deactivated.text

    def test_email_templates_email_changed_render_logs_nothing(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        params = _email_changed()

        for language in _LANGUAGES:
            render(params, language)

        assert caplog.records == []
