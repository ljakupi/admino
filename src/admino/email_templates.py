"""Transactional email templates: params models and DE/FR/EN rendering (GH-148).

admino sends eight kinds of transactional email (``EmailTemplate``):
invitation, password reset, account activated, account deactivated, budget
alert (the 80% warning), model deprecation, scheduled org deletion and (GH-164)
email changed, the notice an Org Admin's change of a user's sign-in address
sends to the old address. Each has a params model and a German, French and
English copy, rendered as plain text plus a minimal HTML part in the
recipient's UI language.

Inputs: a ``TemplateParams`` instance (built by the caller, or restored from
the outbox with ``params_for()``) and a language (de, fr or en).
Outputs: ``render()`` returns a ``RenderedEmail`` (subject, text, html).

Security notes:
- No org content (tracker #139 §5): a params model holds only the org display
  name, links and dates. The only str fields are ``org_name`` and ``*_link``;
  everything else is a timezone-aware datetime or a date. Every params model is
  a ``SealedModel`` (frozen, extra="forbid"), so a project, chat or file name,
  message text, user name or address can't be passed in. The model deprecation
  email doesn't even name the model, and the email changed notice names neither
  the old nor the new address. The greeting is generic.
- Header injection: ``org_name`` (it reaches the Subject header) is 1 to 120
  characters, not blank, and refuses control (Cc), format (Cf), surrogate (Cs)
  and line/paragraph separator (Zl, Zp) characters.
- Links are absolute https URLs with a host (plain http only for localhost,
  127.0.0.1 and [::1]), without userinfo, whitespace, control or format
  characters, ``<``, ``>``, ``"`` or backslashes, at most 2048 characters. So a
  link can't be a javascript:, data: or mailto: URL or break out of an href.
- HTML injection: every value is HTML-escaped in the HTML part, which has no
  scripts, forms, images or other remote resources.
- Validation errors never repeat the rejected input: ``hide_input_in_errors``
  hides it from the error text, and the link check replaces urlsplit()'s own
  errors (which echo the netloc) with a generic message.
- Pure: no I/O and no logging. Imports only the standard library, pydantic and
  ``admino.access``.
"""

from __future__ import annotations

import html
import unicodedata
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, ClassVar, Final, Literal, TypeGuard, get_args
from urllib.parse import urlsplit

from pydantic import AfterValidator, AwareDatetime, ConfigDict, Field

from admino.access import SealedModel

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

EmailLanguage = Literal["de", "fr", "en"]


class EmailTemplate(StrEnum):
    """The closed catalog of transactional emails (stored as email_outbox.template_key)."""

    INVITATION = "invitation"
    PASSWORD_RESET = "password_reset"  # noqa: S105 - a template key, not a secret
    ACCOUNT_ACTIVATED = "account_activated"
    ACCOUNT_DEACTIVATED = "account_deactivated"
    BUDGET_ALERT = "budget_alert"
    MODEL_DEPRECATION = "model_deprecation"
    ORG_DELETION_SCHEDULED = "org_deletion_scheduled"
    EMAIL_CHANGED = "email_changed"


_LANGUAGES: Final[frozenset[str]] = frozenset(get_args(EmailLanguage))

# Control, format, surrogate and line/paragraph separator characters.
_UNSAFE_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_LINK_BANNED_CHARS: Final = frozenset('<>"\\')
_LOOPBACK_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1"})


def _has_unsafe_char(value: str) -> bool:
    """Return True if any character is a control, format, surrogate or separator character."""
    return any(unicodedata.category(char) in _UNSAFE_CATEGORIES for char in value)


def _check_org_name(value: str) -> str:
    """Accept an org display name that is not blank and fits on one header line."""
    if not value.strip():
        msg = "The organization name must not be blank."
        raise ValueError(msg)
    if _has_unsafe_char(value):
        msg = "The organization name must not contain control or separator characters."
        raise ValueError(msg)
    return value


def _check_link(value: str) -> str:
    """Accept an absolute https URL with a host (http for loopback only), safe in an href."""
    if _has_unsafe_char(value) or any(
        char.isspace() or char in _LINK_BANNED_CHARS for char in value
    ):
        msg = "A link must not contain whitespace, control characters, quotes or brackets."
        raise ValueError(msg)
    msg = "A link must be an absolute https URL with a host and no user info."
    try:
        parts = urlsplit(value)
    except ValueError:
        # urlsplit's own errors echo the netloc (e.g. for NFKC confusables of
        # "#" or "/"), and a link may carry a one-time token.
        raise ValueError(msg) from None
    if parts.scheme not in ("https", "http") or "@" in parts.netloc or not parts.hostname:
        raise ValueError(msg)
    if parts.scheme == "http" and parts.hostname not in _LOOPBACK_HOSTS:
        msg = "Plain http links are allowed for localhost only."
        raise ValueError(msg)
    return value


OrgName = Annotated[str, Field(min_length=1, max_length=120), AfterValidator(_check_org_name)]
Link = Annotated[str, Field(min_length=1, max_length=2048), AfterValidator(_check_link)]


class TemplateParams(SealedModel):
    """The params of one transactional email: an org name, links and dates, never content."""

    # Validation errors never repeat the rejected input (it may hold a one-time link).
    model_config = ConfigDict(hide_input_in_errors=True)

    template: ClassVar[EmailTemplate]


class InvitationParams(TemplateParams):
    """An invitation to join an org."""

    template: ClassVar[EmailTemplate] = EmailTemplate.INVITATION

    org_name: OrgName
    accept_link: Link
    expires_at: AwareDatetime


class PasswordResetParams(TemplateParams):
    """A password reset link."""

    template: ClassVar[EmailTemplate] = EmailTemplate.PASSWORD_RESET

    reset_link: Link
    expires_at: AwareDatetime


class AccountActivatedParams(TemplateParams):
    """The recipient's account was activated."""

    template: ClassVar[EmailTemplate] = EmailTemplate.ACCOUNT_ACTIVATED

    org_name: OrgName
    login_link: Link


class AccountDeactivatedParams(TemplateParams):
    """The recipient's account was deactivated."""

    template: ClassVar[EmailTemplate] = EmailTemplate.ACCOUNT_DEACTIVATED

    org_name: OrgName


class BudgetAlertParams(TemplateParams):
    """The org used 80% of its monthly budget; ``month`` is any day of that month."""

    template: ClassVar[EmailTemplate] = EmailTemplate.BUDGET_ALERT

    org_name: OrgName
    month: date
    usage_link: Link


class ModelDeprecationParams(TemplateParams):
    """A model the org allows will be retired (the model itself is not named)."""

    template: ClassVar[EmailTemplate] = EmailTemplate.MODEL_DEPRECATION

    org_name: OrgName
    retires_on: date
    models_link: Link


class OrgDeletionScheduledParams(TemplateParams):
    """The org is scheduled for deletion; its data is purged after ``purge_after``."""

    template: ClassVar[EmailTemplate] = EmailTemplate.ORG_DELETION_SCHEDULED

    org_name: OrgName
    purge_after: AwareDatetime


class EmailChangedParams(TemplateParams):
    """An administrator changed the recipient's sign-in address (sent to the old one)."""

    template: ClassVar[EmailTemplate] = EmailTemplate.EMAIL_CHANGED

    org_name: OrgName


TEMPLATE_PARAMS: Final[Mapping[EmailTemplate, type[TemplateParams]]] = MappingProxyType(
    {
        params.template: params
        for params in (
            InvitationParams,
            PasswordResetParams,
            AccountActivatedParams,
            AccountDeactivatedParams,
            BudgetAlertParams,
            ModelDeprecationParams,
            OrgDeletionScheduledParams,
            EmailChangedParams,
        )
    }
)


@dataclass(frozen=True, slots=True)
class RenderedEmail:
    """One email rendered in one language: a one-line subject, plain text and minimal HTML."""

    subject: str
    text: str
    html: str


@dataclass(frozen=True, slots=True)
class _Copy:
    """One template's wording in one language; ``{field}`` marks a params value."""

    subject: str
    paragraphs: tuple[str, ...]


_MONTHS: Final[Mapping[EmailLanguage, tuple[str, ...]]] = MappingProxyType(
    {
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
)

# Joins the date and the time of a datetime: "1. September 2026 um 14:30 UTC".
_TIME_JOINER: Final[Mapping[EmailLanguage, str]] = MappingProxyType(
    {"de": "um", "fr": "à", "en": "at"}
)

# The budget alert is about a calendar month: its date shows month and year only.
_MONTH_ONLY_FIELDS: Final = frozenset({"month"})

_GREETING: Final[Mapping[EmailLanguage, str]] = MappingProxyType(
    {"de": "Guten Tag,", "fr": "Bonjour,", "en": "Hello,"}
)

_FOOTER: Final[Mapping[EmailLanguage, str]] = MappingProxyType(
    {
        "de": "Diese E-Mail wurde automatisch von admino versendet. "
        "Bitte antworten Sie nicht darauf.",
        "fr": "Cet e-mail a été envoyé automatiquement par admino. Merci de ne pas y répondre.",
        "en": "This email was sent automatically by admino. Please do not reply to it.",
    }
)

_COPY: Final[Mapping[EmailTemplate, Mapping[EmailLanguage, _Copy]]] = MappingProxyType(
    {
        EmailTemplate.INVITATION: {
            "de": _Copy(
                "Einladung zur Organisation {org_name} auf admino",
                (
                    "Sie wurden eingeladen, der Organisation {org_name} auf admino beizutreten.",
                    "Um die Einladung anzunehmen und Ihr Konto einzurichten, "
                    "öffnen Sie diesen Link:\n{accept_link}",
                    "Der Link ist bis zum {expires_at} gültig.",
                    "Falls Sie diese Einladung nicht erwartet haben, "
                    "können Sie diese E-Mail ignorieren.",
                ),
            ),
            "fr": _Copy(
                "Invitation à rejoindre l'organisation {org_name} sur admino",
                (
                    "Vous avez reçu une invitation à rejoindre l'organisation {org_name} "
                    "sur admino.",
                    "Pour accepter l'invitation et configurer votre compte, "
                    "ouvrez ce lien :\n{accept_link}",
                    "Le lien est valable jusqu'au {expires_at}.",
                    "Si vous n'attendiez pas cette invitation, vous pouvez ignorer cet e-mail.",
                ),
            ),
            "en": _Copy(
                "Invitation to join {org_name} on admino",
                (
                    "You have been invited to join the organization {org_name} on admino.",
                    "To accept the invitation and set up your account, "
                    "open this link:\n{accept_link}",
                    "The link is valid until {expires_at}.",
                    "If you were not expecting this invitation, you can ignore this email.",
                ),
            ),
        },
        EmailTemplate.PASSWORD_RESET: {
            "de": _Copy(
                "Passwort für Ihr admino-Konto zurücksetzen",
                (
                    "Sie erhalten diese E-Mail, weil für Ihr admino-Konto "
                    "ein neues Passwort angefordert wurde.",
                    "Um ein neues Passwort festzulegen, öffnen Sie diesen Link:\n{reset_link}",
                    "Der Link ist bis zum {expires_at} gültig.",
                    "Falls Sie kein neues Passwort angefordert haben, können Sie diese E-Mail "
                    "ignorieren. Ihr Passwort bleibt unverändert.",
                ),
            ),
            "fr": _Copy(
                "Réinitialisation du mot de passe de votre compte admino",
                (
                    "Nous avons reçu une demande de réinitialisation du mot de passe "
                    "de votre compte admino.",
                    "Pour choisir un nouveau mot de passe, ouvrez ce lien :\n{reset_link}",
                    "Le lien est valable jusqu'au {expires_at}.",
                    "Si vous n'êtes pas à l'origine de cette demande, vous pouvez ignorer "
                    "cet e-mail. Votre mot de passe reste inchangé.",
                ),
            ),
            "en": _Copy(
                "Reset the password of your admino account",
                (
                    "We received a request to reset the password of your admino account.",
                    "To choose a new password, open this link:\n{reset_link}",
                    "The link is valid until {expires_at}.",
                    "If you did not request this, you can ignore this email. "
                    "Your password stays the same.",
                ),
            ),
        },
        EmailTemplate.ACCOUNT_ACTIVATED: {
            "de": _Copy(
                "Ihr Konto bei {org_name} ist aktiviert",
                (
                    "Ihr Konto in der Organisation {org_name} auf admino wurde aktiviert.",
                    "Hier können Sie sich anmelden:\n{login_link}",
                ),
            ),
            "fr": _Copy(
                "Votre compte chez {org_name} est activé",
                (
                    "Votre compte dans l'organisation {org_name} sur admino a été activé.",
                    "Vous pouvez vous connecter ici :\n{login_link}",
                ),
            ),
            "en": _Copy(
                "Your account at {org_name} is active",
                (
                    "Your account in the organization {org_name} on admino has been activated.",
                    "You can sign in here:\n{login_link}",
                ),
            ),
        },
        EmailTemplate.ACCOUNT_DEACTIVATED: {
            "de": _Copy(
                "Ihr Konto bei {org_name} wurde deaktiviert",
                (
                    "Ihr Konto in der Organisation {org_name} auf admino wurde deaktiviert. "
                    "Sie können sich nicht mehr anmelden.",
                    "Falls Sie dies für einen Fehler halten, wenden Sie sich bitte "
                    "an die Administration Ihrer Organisation.",
                ),
            ),
            "fr": _Copy(
                "Votre compte chez {org_name} a été désactivé",
                (
                    "Votre compte dans l'organisation {org_name} sur admino a été désactivé. "
                    "Vous ne pouvez plus vous connecter.",
                    "Si vous pensez qu'il s'agit d'une erreur, veuillez contacter "
                    "l'administration de votre organisation.",
                ),
            ),
            "en": _Copy(
                "Your account at {org_name} has been deactivated",
                (
                    "Your account in the organization {org_name} on admino has been "
                    "deactivated. You can no longer sign in.",
                    "If you think this is a mistake, please contact an administrator "
                    "of your organization.",
                ),
            ),
        },
        EmailTemplate.BUDGET_ALERT: {
            "de": _Copy(
                "Budgetwarnung: {org_name} hat 80 % des Monatsbudgets verbraucht",
                (
                    "Ihre Organisation {org_name} hat 80 % ihres admino-Budgets "
                    "für {month} verbraucht.",
                    "Die Nutzung können Sie hier einsehen:\n{usage_link}",
                ),
            ),
            "fr": _Copy(
                "Alerte budget : {org_name} a utilisé 80 % de son budget mensuel",
                (
                    "Votre organisation {org_name} a utilisé 80 % de son budget admino "
                    "pour {month}.",
                    "Vous pouvez consulter l'utilisation ici :\n{usage_link}",
                ),
            ),
            "en": _Copy(
                "Budget alert: {org_name} has used 80% of its monthly budget",
                (
                    "Your organization {org_name} has used 80% of its admino budget for {month}.",
                    "You can review the usage here:\n{usage_link}",
                ),
            ),
        },
        EmailTemplate.MODEL_DEPRECATION: {
            "de": _Copy(
                "Ein bei {org_name} zugelassenes Modell wird eingestellt",
                (
                    "Ihre Organisation {org_name} lässt auf admino ein Modell zu, "
                    "das am {retires_on} eingestellt wird.",
                    "Bitte prüfen Sie die zugelassenen Modelle und wählen Sie bei Bedarf "
                    "einen Ersatz:\n{models_link}",
                ),
            ),
            "fr": _Copy(
                "Un modèle autorisé chez {org_name} va être retiré",
                (
                    "Un modèle autorisé par votre organisation {org_name} sur admino "
                    "sera retiré le {retires_on}.",
                    "Veuillez vérifier les modèles autorisés et, si nécessaire, "
                    "choisir un remplacement :\n{models_link}",
                ),
            ),
            "en": _Copy(
                "A model allowed at {org_name} will be retired",
                (
                    "A model your organization {org_name} allows on admino will be retired "
                    "on {retires_on}.",
                    "Please review the allowed models and choose a replacement "
                    "if needed:\n{models_link}",
                ),
            ),
        },
        EmailTemplate.ORG_DELETION_SCHEDULED: {
            "de": _Copy(
                "Löschung der Organisation {org_name} geplant",
                (
                    "Ihre Organisation {org_name} auf admino ist zur Löschung vorgemerkt.",
                    "Alle Daten der Organisation werden nach dem {purge_after} endgültig gelöscht.",
                    "Falls dies nicht beabsichtigt ist, wenden Sie sich bitte vor diesem "
                    "Zeitpunkt an den admino-Support.",
                ),
            ),
            "fr": _Copy(
                "Suppression programmée de l'organisation {org_name}",
                (
                    "La suppression de votre organisation {org_name} sur admino a été programmée.",
                    "Toutes les données de l'organisation seront définitivement supprimées "
                    "après le {purge_after}.",
                    "S'il s'agit d'une erreur, veuillez contacter le support admino "
                    "avant cette date.",
                ),
            ),
            "en": _Copy(
                "The organization {org_name} is scheduled for deletion",
                (
                    "Your organization {org_name} on admino is scheduled for deletion.",
                    "All of the organization's data will be permanently deleted "
                    "after {purge_after}.",
                    "If this is not intended, please contact admino support before then.",
                ),
            ),
        },
        EmailTemplate.EMAIL_CHANGED: {
            "de": _Copy(
                "Die Anmeldeadresse Ihres Kontos bei {org_name} wurde geändert",
                (
                    "Die E-Mail-Adresse, mit der Sie sich bei Ihrem admino-Konto in der "
                    "Organisation {org_name} anmelden, wurde von der Administration Ihrer "
                    "Organisation geändert.",
                    "Ab sofort melden Sie sich mit der neuen Adresse an.",
                    "Falls Sie diese Änderung nicht erwartet haben, wenden Sie sich bitte "
                    "an die Administration Ihrer Organisation.",
                ),
            ),
            "fr": _Copy(
                "L'adresse de connexion de votre compte chez {org_name} a été modifiée",
                (
                    "L'adresse e-mail avec laquelle vous vous connectez à votre compte admino "
                    "dans l'organisation {org_name} a été modifiée par l'administration "
                    "de votre organisation.",
                    "Désormais, vous vous connectez avec la nouvelle adresse.",
                    "Si vous n'attendiez pas ce changement, veuillez contacter "
                    "l'administration de votre organisation.",
                ),
            ),
            "en": _Copy(
                "The sign-in address of your account at {org_name} has been changed",
                (
                    "The email address you use to sign in to your admino account in the "
                    "organization {org_name} has been changed by an administrator of your "
                    "organization.",
                    "From now on, you sign in with the new address.",
                    "If you were not expecting this change, please contact an administrator "
                    "of your organization.",
                ),
            ),
        },
    }
)


def params_for(template: EmailTemplate | str, data: Mapping[str, object]) -> TemplateParams:
    """Validate stored params data back into the model of its template.

    Args:
        template: The template, or its stored key (e.g. email_outbox.template_key).
        data: The params as JSON-decoded data (``model_dump(mode="json")``).

    Returns:
        The validated params instance of the template's model.

    Raises:
        ValueError: If the key is not a template, or the data doesn't validate
            against its model (pydantic's ValidationError is a ValueError).
    """
    return TEMPLATE_PARAMS[EmailTemplate(template)].model_validate(data)


def render(params: TemplateParams, language: str) -> RenderedEmail:
    """Render an email in one language as a subject, plain text and minimal HTML.

    Args:
        params: The validated params of the email.
        language: de, fr or en (the recipient's users.ui_language).

    Returns:
        The rendered email. The text holds the raw values; the HTML escapes them.

    Raises:
        ValueError: If the language is not de, fr or en.
    """
    if not _is_language(language):
        msg = "Emails are rendered in de, fr or en only."
        raise ValueError(msg)
    copy = _COPY[params.template][language]
    values = _display_values(params, language)
    paragraphs = (_GREETING[language], *copy.paragraphs, _FOOTER[language])
    subject = copy.subject.format_map(values)
    text = "\n\n".join(paragraph.format_map(values) for paragraph in paragraphs) + "\n"
    return RenderedEmail(
        subject=subject,
        text=text,
        html=_html(subject, paragraphs, values, language),
    )


def _is_language(value: str) -> TypeGuard[EmailLanguage]:
    """Return True if the value is one of the email languages."""
    return value in _LANGUAGES


def _display_values(params: TemplateParams, language: EmailLanguage) -> dict[str, str]:
    """Return every params value as display text: raw strings, localized dates in UTC."""
    values: dict[str, str] = {}
    for name, value in params:
        if isinstance(value, datetime):
            values[name] = _format_datetime(value, language)
        elif isinstance(value, date):
            values[name] = (
                _format_month(value, language)
                if name in _MONTH_ONLY_FIELDS
                else _format_date(value, language)
            )
        else:
            values[name] = value
    return values


def _format_date(value: date, language: EmailLanguage) -> str:
    """de "1. September 2026", fr "1 septembre 2026", en "1 September 2026"."""
    day = f"{value.day}." if language == "de" else str(value.day)
    return f"{day} {_format_month(value, language)}"


def _format_month(value: date, language: EmailLanguage) -> str:
    """de "September 2026", fr "septembre 2026", en "September 2026"."""
    return f"{_MONTHS[language][value.month - 1]} {value.year}"


def _format_datetime(value: datetime, language: EmailLanguage) -> str:
    """The date in UTC plus the time: en "1 September 2026 at 14:30 UTC"."""
    utc = value.astimezone(UTC)
    return f"{_format_date(utc.date(), language)} {_TIME_JOINER[language]} {utc:%H:%M} UTC"


def _html(
    subject: str,
    paragraphs: Sequence[str],
    values: Mapping[str, str],
    language: EmailLanguage,
) -> str:
    """Build the minimal HTML part: every value escaped, links as <a href> anchors."""
    escaped = {name: _html_value(name, value) for name, value in values.items()}
    body = "\n".join(
        "<p>" + html.escape(paragraph).replace("\n", "<br>\n").format_map(escaped) + "</p>"
        for paragraph in paragraphs
    )
    return (
        "<!DOCTYPE html>\n"
        f'<html lang="{language}">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        f"<title>{html.escape(subject)}</title>\n"
        "</head>\n"
        f"<body>\n{body}\n</body>\n"
        "</html>\n"
    )


def _html_value(name: str, value: str) -> str:
    """Escape a display value for HTML; a link becomes an anchor showing the URL."""
    escaped = html.escape(value)
    if name.endswith("_link"):
        return f'<a href="{escaped}">{escaped}</a>'
    return escaped
