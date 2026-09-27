"""Platform-wide SMTP transport for transactional email (GH-148).

admino sends every org's transactional email through one SMTP account,
configured by five environment variables (``SMTP_ENV_VARS``). The transport
is the standard library only: ``email.message.EmailMessage`` builds the
message and ``smtplib`` sends it over TLS, off the event loop.

Inputs: ``load_smtp_config()`` reads SMTP_HOST, SMTP_PORT (465 or 587),
SMTP_USERNAME, SMTP_PASSWORD and SMTP_FROM from the environment.
``build_message()`` takes the config, one recipient address and a
``RenderedEmail``; ``send_message()`` / ``deliver()`` take the config and
the built message.
Outputs: an ``SmtpConfig`` (or None), an ``EmailMessage``, and one sent
message per ``send_message()`` call. SMTP errors propagate to the caller (the
outbox decides on retries).

Security notes:
- TLS is required and verified: port 465 uses ``SMTP_SSL`` and port 587
  ``starttls()``, both with ``ssl.create_default_context()`` (certificate and
  hostname checks). A failed STARTTLS raises; there is no plaintext fallback,
  and plaintext ports (25, 2525) are refused by ``SmtpConfig``.
- The host must be a dotted DNS hostname, the same rule entrypoint.sh's
  apply_smtp_egress enforces before it opens exactly SMTP_HOST:SMTP_PORT.
- No secrets or addresses in logs (tracker #139 §5): the password is a
  ``SecretStr``, config warnings name variables only (never a value or
  pydantic's input echo), and smtplib's debug output (which prints
  addresses) is never switched on.
- Header injection: the from-address is one bare address, and
  ``build_message()`` refuses a recipient or subject that isn't exactly one
  line, and a recipient that isn't exactly one bare address.
- Every connection has a 30 second socket timeout and is closed by a context
  manager, on success and on error.
- Imports only the standard library, pydantic, ``admino.access`` and
  ``admino.email_templates``; the permission engine never imports this module.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import smtplib
import ssl
import unicodedata
from email.message import EmailMessage
from email.utils import formatdate, getaddresses, make_msgid
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Literal

from pydantic import ConfigDict, Field, SecretStr, ValidationError, field_validator

from admino.access import SealedModel

if TYPE_CHECKING:
    from collections.abc import Mapping

    from admino.email_templates import RenderedEmail

logger = logging.getLogger(__name__)

SMTP_ENV_VARS: Final[tuple[str, ...]] = (
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USERNAME",
    "SMTP_PASSWORD",
    "SMTP_FROM",
)
SMTP_TIMEOUT_SECONDS: Final = 30

# The SmtpConfig field each variable feeds, in SMTP_ENV_VARS order.
_FIELD_ENV_VARS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "host": "SMTP_HOST",
        "port": "SMTP_PORT",
        "username": "SMTP_USERNAME",
        "password": "SMTP_PASSWORD",
        "from_address": "SMTP_FROM",
    }
)
# Exact text only: entrypoint.sh refuses "587 " too.
_PORTS: Final[Mapping[str, int]] = MappingProxyType({"465": 465, "587": 587})
# entrypoint.sh's apply_smtp_egress rule; fullmatch, so a trailing newline fails.
_HOSTNAME_RE: Final = re.compile(r"[a-zA-Z0-9]([a-zA-Z0-9.\-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}")
# RFC 5322 dot-atom characters: no whitespace, control characters or specials.
_LOCAL_PART_RE: Final = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.\-]+")


class SmtpConfig(SealedModel):
    """The platform's SMTP account: a TLS host and port, credentials and a sender."""

    # Validation errors never repeat the rejected input.
    model_config = ConfigDict(hide_input_in_errors=True)

    host: str = Field(max_length=253)
    port: Literal[465, 587]
    username: str = Field(min_length=1, max_length=254)
    password: SecretStr = Field(min_length=1)
    from_address: str = Field(max_length=254)

    @field_validator("host")
    @classmethod
    def _check_host(cls, value: str) -> str:
        """Accept a dotted DNS hostname: no IP address, port, whitespace or lookalike."""
        if _HOSTNAME_RE.fullmatch(value) is None:
            msg = "The SMTP host must be a dotted DNS hostname."
            raise ValueError(msg)
        return value

    @field_validator("username")
    @classmethod
    def _check_username(cls, value: str) -> str:
        """Refuse control characters."""
        if any(unicodedata.category(char) == "Cc" for char in value):
            msg = "The SMTP username must not contain control characters."
            raise ValueError(msg)
        return value

    @field_validator("from_address")
    @classmethod
    def _check_from_address(cls, value: str) -> str:
        """Accept one bare address: a dot-atom local part, one "@" and a hostname."""
        local, at, domain = value.partition("@")
        if (
            not at
            or _LOCAL_PART_RE.fullmatch(local) is None
            or _HOSTNAME_RE.fullmatch(domain) is None
        ):
            msg = "The sender must be one bare email address."
            raise ValueError(msg)
        return value


def load_smtp_config(environ: Mapping[str, str] | None = None) -> SmtpConfig | None:
    """Build the SMTP config from the environment, or return None if it's incomplete.

    Never raises, so admino starts without SMTP: mail then stays queued. A
    missing, blank or invalid variable is logged as one WARNING that names the
    variables, never their values.

    Args:
        environ: The variables to read; os.environ by default.

    Returns:
        The validated config, or None when a variable is missing or invalid.
    """
    env = os.environ if environ is None else environ
    raw = {name: env.get(name, "") for name in SMTP_ENV_VARS}
    missing = [name for name, value in raw.items() if not value.strip()]
    if missing:
        logger.warning(
            "SMTP is not configured (missing: %s); transactional email stays queued.",
            ", ".join(missing),
        )
        return None
    port = raw["SMTP_PORT"]
    try:
        return SmtpConfig.model_validate(
            {
                "host": raw["SMTP_HOST"],
                # Anything but "465"/"587" stays text, which the Literal refuses.
                "port": _PORTS.get(port, port),
                "username": raw["SMTP_USERNAME"],
                "password": raw["SMTP_PASSWORD"],
                "from_address": raw["SMTP_FROM"],
            }
        )
    except ValidationError as exc:
        fields = {error["loc"][0] for error in exc.errors() if error["loc"]}
        invalid = [name for field, name in _FIELD_ENV_VARS.items() if field in fields]
        logger.warning(
            "SMTP is not configured (invalid: %s); transactional email stays queued.",
            ", ".join(invalid),
        )
        return None


def build_message(config: SmtpConfig, *, to: str, rendered: RenderedEmail) -> EmailMessage:
    """Build a multipart/alternative message (text/plain, then text/html) to one recipient.

    Args:
        config: The SMTP config (its from-address is the sender).
        to: The one recipient address.
        rendered: The rendered subject, text and HTML.

    Returns:
        The message, with From, To, Subject, Date, Message-ID and
        Auto-Submitted: auto-generated headers.

    Raises:
        ValueError: If the recipient or subject isn't exactly one line, or the
            recipient isn't exactly one bare address.
    """
    if to.splitlines() != [to] or rendered.subject.splitlines() != [rendered.subject]:
        msg = "Email headers must be exactly one line."
        raise ValueError(msg)
    # "a@x.ch,b@y.ch" would be two recipients, "Eve <a@x.ch>" a display name.
    if getaddresses([to]) != [("", to)]:
        msg = "The recipient must be exactly one bare address."
        raise ValueError(msg)
    message = EmailMessage()
    message["From"] = config.from_address
    message["To"] = to
    message["Subject"] = rendered.subject
    message["Date"] = formatdate(usegmt=True)
    # The sender's domain, not socket.getfqdn(): no DNS lookup, no host name leak.
    message["Message-ID"] = make_msgid(domain=config.from_address.partition("@")[2])
    # RFC 3834: autoresponders must not reply.
    message["Auto-Submitted"] = "auto-generated"
    message.set_content(rendered.text, subtype="plain", charset="utf-8")
    message.add_alternative(rendered.html, subtype="html", charset="utf-8")
    return message


def send_message(config: SmtpConfig, message: EmailMessage) -> None:
    """Send one message over verified TLS (blocking; see ``deliver()``).

    Port 465 connects with implicit TLS; port 587 upgrades with STARTTLS before
    logging in. The connection is closed on success and on error.

    Args:
        config: The SMTP account.
        message: The message from ``build_message()``.

    Raises:
        smtplib.SMTPException, ssl.SSLError, OSError: If connecting, the TLS
            handshake, the login or the send fails. Nothing is sent without TLS.
    """
    context = ssl.create_default_context()
    if config.port == 465:
        with smtplib.SMTP_SSL(
            config.host, config.port, timeout=SMTP_TIMEOUT_SECONDS, context=context
        ) as smtp:
            _login_and_send(smtp, config, message)
    else:
        with smtplib.SMTP(config.host, config.port, timeout=SMTP_TIMEOUT_SECONDS) as smtp:
            smtp.starttls(context=context)
            _login_and_send(smtp, config, message)


def _login_and_send(smtp: smtplib.SMTP, config: SmtpConfig, message: EmailMessage) -> None:
    """Log in and send on an encrypted connection."""
    smtp.login(config.username, config.password.get_secret_value())
    smtp.send_message(message)


async def deliver(config: SmtpConfig, message: EmailMessage) -> None:
    """Send one message in a worker thread, so the event loop never blocks on SMTP.

    Args:
        config: The SMTP account.
        message: The message from ``build_message()``.

    Raises:
        Whatever ``send_message()`` raises.
    """
    await asyncio.to_thread(send_message, config, message)
