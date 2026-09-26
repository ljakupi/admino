"""Tests for admino.mailer — the platform-wide SMTP transport (GH-148).

admino sends transactional email through one SMTP account for all orgs,
configured by SMTP_HOST, SMTP_PORT (465 implicit TLS or 587 STARTTLS),
SMTP_USERNAME, SMTP_PASSWORD and SMTP_FROM. The transport is stdlib only:
``email.message.EmailMessage`` builds the message and ``smtplib`` sends it,
run through ``asyncio.to_thread`` so it never blocks the event loop.

What these tests pin down:
- SmtpConfig (a SealedModel) validates the host (the entrypoint's hostname
  rule, no IPs, no ports), the port (465 or 587 only), the from-address (one
  bare address, no header injection), the username and a non-empty SecretStr
  password that never shows in repr() or str().
- load_smtp_config() returns a config when all five variables are set and
  valid. Otherwise it returns None and logs one WARNING naming the missing or
  offending variable names, never a value (so admino still starts and mail
  stays queued). It never raises.
- build_message() builds a multipart/alternative EmailMessage (text/plain then
  text/html, utf-8) with From, To, Subject, Date, Message-ID and
  Auto-Submitted: auto-generated; a CR/LF in To or Subject is a ValueError.
- send_message() uses SMTP_SSL on 465 and SMTP + starttls() on 587, always
  with a verified ssl.create_default_context(), logs in, sends, and closes the
  connection. A failed STARTTLS never falls back to plaintext.
- deliver() runs send_message() through asyncio.to_thread.

All smtplib classes are mocked. No real network or SMTP connections are made.

Security notes:
- TLS is required: a verified default context, no unverified context, no
  CERT_NONE, no check_hostname=False, and no plaintext fallback.
- No secrets or addresses in logs (tracker #139 §5): warnings name variables,
  never values or pydantic's input echo; smtplib debug output (which prints
  addresses) is never switched on.
- The transport imports only the stdlib, pydantic and admino's access and
  template modules; the permission engine gains no import.
"""

from __future__ import annotations

import ast
import asyncio
import email
import email.policy
import inspect
import logging
import smtplib
import ssl
import sys
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr, ValidationError

import admino.mailer as mailer_mod
from admino.access import SealedModel
from admino.email_templates import InvitationParams, RenderedEmail, render
from admino.mailer import (
    SMTP_ENV_VARS,
    SMTP_TIMEOUT_SECONDS,
    SmtpConfig,
    build_message,
    deliver,
    load_smtp_config,
    send_message,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_HOST = "smtp.admino.invalid"
_USERNAME = "smtp-user-7c41@admino.invalid"
_PASSWORD = "pw-S3cret-9d2f-marker"
_FROM = "noreply-4b8e@admino.invalid"
_TO = "alice-5e1a@example.invalid"

_ENV_NAMES: tuple[str, ...] = (
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USERNAME",
    "SMTP_PASSWORD",
    "SMTP_FROM",
)

# Characters built with chr() so they survive editing tools verbatim.
_NUL = chr(0x00)
_TAB = chr(0x09)
_NEWLINE = chr(0x0A)
_CARRIAGE_RETURN = chr(0x0D)
_CRLF = _CARRIAGE_RETURN + _NEWLINE
_DELETE = chr(0x7F)
_CYRILLIC_A = chr(0x0430)  # looks like a Latin "a"

_SRC_DIR = Path(mailer_mod.__file__).resolve().parent

# The real classes, kept before any test patches the smtplib attributes.
_REAL_SMTP = smtplib.SMTP
_REAL_SMTP_SSL = smtplib.SMTP_SSL


def _address_of_length(total: int) -> str:
    """Build a syntactically valid address of exactly `total` characters (<= 255):
    a 64-char local part and a domain of labels of at most 63 chars."""
    local = "n" * 64
    domain_len = total - len(local) - 1
    tail = ".ch"
    labels: list[str] = []
    remaining = domain_len - len(tail)
    letter = ord("a")
    while remaining > 0:
        size = min(63, remaining)
        if remaining - size == 1:  # never leave a single char for "." alone
            size -= 1
        labels.append(chr(letter) * size)
        letter += 1
        remaining -= size
        if remaining > 0:
            remaining -= 1  # the dot between labels
    address = f"{local}@{'.'.join(labels)}{tail}"
    assert len(address) == total, len(address)
    return address


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _config(**overrides: Any) -> SmtpConfig:
    """Build a valid SmtpConfig, with some fields overridden."""
    kwargs: dict[str, Any] = {
        "host": _HOST,
        "port": 587,
        "username": _USERNAME,
        "password": _PASSWORD,
        "from_address": _FROM,
    }
    kwargs.update(overrides)
    return SmtpConfig(**kwargs)


def _env(overrides: dict[str, str | None] | None = None) -> dict[str, str]:
    """A complete, valid SMTP environment; a None override removes the variable."""
    env = {
        "SMTP_HOST": _HOST,
        "SMTP_PORT": "587",
        "SMTP_USERNAME": _USERNAME,
        "SMTP_PASSWORD": _PASSWORD,
        "SMTP_FROM": _FROM,
    }
    for name, value in (overrides or {}).items():
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    return env


def _warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """The WARNING records admino's own loggers emitted."""
    return [
        record
        for record in caplog.records
        if record.name.startswith("admino") and record.levelno == logging.WARNING
    ]


def _assert_absent(caplog: pytest.LogCaptureFixture, *markers: str) -> None:
    """No marker appears in any record's message, args or the formatted log text."""
    for record in caplog.records:
        text = record.getMessage() + repr(record.args)
        for marker in markers:
            assert marker not in text, f"{marker!r} leaked into {text!r}"
    for marker in markers:
        assert marker not in caplog.text, f"{marker!r} leaked into the log output"


def _rendered(**overrides: str) -> RenderedEmail:
    """A small RenderedEmail with non-ASCII text."""
    values = {
        "subject": "Einladung: Müller & Partner AG",
        "text": "Grüezi\n\nBitte folgen Sie dem Link: https://admino.example.ch/invite/x\n",
        "html": (
            '<!DOCTYPE html>\n<html lang="de"><body><p>Grüezi</p>'
            '<p><a href="https://admino.example.ch/invite/x">Einladung</a></p></body></html>\n'
        ),
    }
    values.update(overrides)
    return RenderedEmail(**values)


def _normalized_body(text: str) -> str:
    """Line endings unified and the trailing newline set_content() adds removed."""
    return text.replace(_CRLF, _NEWLINE).rstrip(_NEWLINE)


def _bound(real: Any, call: Any) -> dict[str, Any]:
    """Bind a mock call's arguments to the real callable's signature (positional or keyword)."""
    return dict(inspect.signature(real).bind(*call.args, **call.kwargs).arguments)


@dataclass
class _SmtpMocks:
    """The patched smtplib classes, the shared connection mock and the TLS context."""

    smtp: MagicMock
    smtp_ssl: MagicMock
    conn: MagicMock
    create_context: MagicMock
    unverified: MagicMock
    context: ssl.SSLContext


@pytest.fixture()
def smtp_mocks() -> Iterator[_SmtpMocks]:
    """Patch smtplib.SMTP / SMTP_SSL and ssl.create_default_context as mailer looks them up.

    Both classes return the same connection mock, which works as a context manager
    (``__enter__`` returns itself; ``__exit__`` doesn't swallow errors). The context
    is a real verified SSLContext, so a test can see whether the code weakened it.
    """
    context = ssl.create_default_context()
    conn = MagicMock(name="smtp-connection")
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    smtp_cls = MagicMock(name="SMTP", return_value=conn)
    smtp_ssl_cls = MagicMock(name="SMTP_SSL", return_value=conn)
    create = MagicMock(name="create_default_context", return_value=context)
    unverified = MagicMock(
        name="_create_unverified_context", side_effect=AssertionError("unverified TLS context")
    )
    with (
        patch("admino.mailer.smtplib.SMTP", smtp_cls),
        patch("admino.mailer.smtplib.SMTP_SSL", smtp_ssl_cls),
        patch("admino.mailer.ssl.create_default_context", create),
        patch("admino.mailer.ssl._create_unverified_context", unverified),
    ):
        yield _SmtpMocks(smtp_cls, smtp_ssl_cls, conn, create, unverified, context)


def _login_args(conn: MagicMock) -> tuple[Any, Any]:
    """The (user, password) the single login() call received, positional or keyword."""
    conn.login.assert_called_once()
    call = conn.login.call_args
    bound = inspect.signature(_REAL_SMTP.login).bind(None, *call.args, **call.kwargs).arguments
    return bound["user"], bound["password"]


def _sent_message(conn: MagicMock) -> Any:
    """The message the single send_message() call received, positional or keyword."""
    conn.send_message.assert_called_once()
    call = conn.send_message.call_args
    bound = inspect.signature(_REAL_SMTP.send_message).bind(None, *call.args, **call.kwargs)
    return bound.arguments["msg"]


def _call_names(conn: MagicMock) -> list[str]:
    """The method names called on the connection mock, in order."""
    return [entry[0] for entry in conn.mock_calls]


def _closed(conn: MagicMock) -> bool:
    """True when the connection was closed: context manager exit, quit() or close()."""
    return bool(conn.__exit__.called or conn.quit.called or conn.close.called)


def _message() -> EmailMessage:
    """A built message for the send tests."""
    return build_message(_config(), to=_TO, rendered=_rendered())


# ---------------------------------------------------------------------------
# 1. Constants
# ---------------------------------------------------------------------------


class TestConstants:
    """The environment variable names and the socket timeout."""

    def test_mailer_env_var_names(self) -> None:
        """The five SMTP variables, in this order."""
        assert SMTP_ENV_VARS == _ENV_NAMES

    def test_mailer_timeout_is_thirty_seconds(self) -> None:
        """Every SMTP connection has a 30 second socket timeout."""
        assert SMTP_TIMEOUT_SECONDS == 30


# ---------------------------------------------------------------------------
# 2. SmtpConfig validation
# ---------------------------------------------------------------------------

_LONGEST_HOST = ("a" * 63 + ".") * 3 + "b" * 58 + ".ch"

_ACCEPTED_HOSTS: list[Any] = [
    pytest.param("mail.infomaniak.com", id="infomaniak"),
    pytest.param("smtp.admino.invalid", id="subdomain"),
    pytest.param("mail-1.example.co.uk", id="hyphen-and-multi-label"),
    pytest.param("example.ch", id="two-labels"),
    pytest.param(_LONGEST_HOST, id="253-chars"),
]

_REFUSED_HOSTS: list[Any] = [
    pytest.param("", id="empty"),
    pytest.param("localhost", id="localhost"),
    pytest.param("10.0.0.1", id="ipv4"),
    pytest.param("[::1]", id="ipv6"),
    pytest.param("mail.example.com:25", id="with-port"),
    pytest.param("a b.ch", id="space"),
    pytest.param("-mail.example.com", id="leading-hyphen"),
    pytest.param("mail.example.com.", id="trailing-dot"),
    pytest.param("mail.example.c", id="one-letter-tld"),
    pytest.param("mail_server.example.com", id="underscore"),
    pytest.param("http://mail.example.com", id="url"),
    pytest.param("mail.example.com" + _NEWLINE, id="trailing-newline"),
    pytest.param("m" + _CYRILLIC_A + "il.example.com", id="lookalike"),
    pytest.param(_LONGEST_HOST[:-3] + "c.ch", id="254-chars"),
]

_REFUSED_FROM: list[Any] = [
    pytest.param("", id="empty"),
    pytest.param("noreply", id="no-at"),
    pytest.param("@admino.ch", id="empty-local-part"),
    pytest.param("noreply@", id="empty-domain"),
    pytest.param("a@b@admino.ch", id="two-ats"),
    pytest.param("no reply@admino.ch", id="space"),
    pytest.param("admino <noreply@admino.ch>", id="display-name"),
    pytest.param("a" + _CRLF + "Bcc: x@y.ch", id="crlf-bcc"),
    pytest.param("noreply@admino.ch" + _NEWLINE, id="trailing-newline"),
    pytest.param("noreply@admino.ch" + _CARRIAGE_RETURN, id="trailing-carriage-return"),
    pytest.param("noreply@admino.ch" + _TAB, id="tab"),
    pytest.param("noreply" + _NUL + "@admino.ch", id="nul"),
    pytest.param("noreply" + _DELETE + "@admino.ch", id="delete"),
    pytest.param(_address_of_length(255), id="255-chars"),
]

_REFUSED_USERNAMES: list[Any] = [
    pytest.param("", id="empty"),
    pytest.param("u" * 255, id="255-chars"),
    pytest.param("user" + _CRLF, id="crlf"),
    pytest.param("user" + _NUL, id="nul"),
    pytest.param("us" + _TAB + "er", id="tab"),
    pytest.param("user" + _DELETE, id="delete"),
]


class TestSmtpConfig:
    """SmtpConfig: a validated, sealed, platform-wide SMTP account."""

    def test_mailer_config_is_a_sealed_model(self) -> None:
        """SmtpConfig is a SealedModel (frozen, extra="forbid")."""
        assert issubclass(SmtpConfig, SealedModel)

    def test_mailer_config_keeps_the_values(self) -> None:
        """A valid config keeps host, port, username, from-address and the password."""
        config = _config(port=465)

        assert config.host == _HOST
        assert config.port == 465
        assert config.username == _USERNAME
        assert config.from_address == _FROM
        assert isinstance(config.password, SecretStr)
        assert config.password.get_secret_value() == _PASSWORD

    def test_mailer_config_is_frozen(self) -> None:
        """A config can't be changed after it's built."""
        config = _config()

        with pytest.raises(ValidationError):
            config.host = "evil.example.com"

    def test_mailer_config_refuses_extra_fields(self) -> None:
        """An unknown field (e.g. a plaintext fallback switch) is refused."""
        with pytest.raises(ValidationError):
            _config(use_tls=False)

    @pytest.mark.parametrize("host", _ACCEPTED_HOSTS)
    def test_mailer_config_accepts_hostnames(self, host: str) -> None:
        """DNS hostnames up to 253 chars, per the entrypoint's hostname rule."""
        assert _config(host=host).host == host

    @pytest.mark.parametrize("host", _REFUSED_HOSTS)
    def test_mailer_config_refuses_bad_hosts(self, host: str) -> None:
        """IPs, localhost, host:port, whitespace, lookalikes and over-long names are refused."""
        with pytest.raises(ValidationError):
            _config(host=host)

    @pytest.mark.parametrize("port", [465, 587])
    def test_mailer_config_accepts_tls_ports(self, port: int) -> None:
        """465 (implicit TLS) and 587 (STARTTLS)."""
        assert _config(port=port).port == port

    @pytest.mark.parametrize("port", [25, 2525, 0, 443, 465 + 587, 65536, -587, None, True])
    def test_mailer_config_refuses_other_ports(self, port: object) -> None:
        """Port 25 or 2525 (plaintext relay ports) and anything else are refused."""
        with pytest.raises(ValidationError):
            _config(port=port)

    @pytest.mark.parametrize(
        "address",
        [
            pytest.param("noreply@admino.ch", id="plain"),
            pytest.param("no-reply+mail@mail.admino.ch", id="plus-and-subdomain"),
            pytest.param(_address_of_length(254), id="254-chars"),
        ],
    )
    def test_mailer_config_accepts_from_addresses(self, address: str) -> None:
        """A bare address with one "@", up to 254 chars."""
        assert _config(from_address=address).from_address == address

    @pytest.mark.parametrize("address", _REFUSED_FROM)
    def test_mailer_config_refuses_bad_from_addresses(self, address: str) -> None:
        """No "@", several, empty parts, whitespace, control characters (header injection)
        or more than 254 chars."""
        with pytest.raises(ValidationError):
            _config(from_address=address)

    @pytest.mark.parametrize(
        "username", [pytest.param("smtp-user", id="plain"), pytest.param(_USERNAME, id="address")]
    )
    def test_mailer_config_accepts_usernames(self, username: str) -> None:
        """A 1 to 254 char username without control characters."""
        assert _config(username=username).username == username

    @pytest.mark.parametrize("username", _REFUSED_USERNAMES)
    def test_mailer_config_refuses_bad_usernames(self, username: str) -> None:
        """Empty, over 254 chars, or with control characters."""
        with pytest.raises(ValidationError):
            _config(username=username)

    def test_mailer_config_refuses_empty_password(self) -> None:
        """The password must not be empty."""
        with pytest.raises(ValidationError):
            _config(password="")

    def test_mailer_config_repr_hides_the_password(self) -> None:
        """repr(), str(), model_dump() and model_dump_json() never show the password."""
        config = _config()

        assert _PASSWORD not in repr(config)
        assert _PASSWORD not in str(config)
        assert _PASSWORD not in str(config.model_dump())
        assert _PASSWORD not in config.model_dump_json()

    def test_mailer_config_validation_error_hides_the_password(self) -> None:
        """A config refused for another field doesn't echo the password."""
        with pytest.raises(ValidationError) as excinfo:
            _config(host="localhost")

        assert _PASSWORD not in str(excinfo.value)


# ---------------------------------------------------------------------------
# 3. load_smtp_config(): env to config, or None with a warning
# ---------------------------------------------------------------------------


class TestLoadSmtpConfig:
    """load_smtp_config() never blocks startup and never logs a value."""

    def test_mailer_load_returns_config_when_all_set(self) -> None:
        """All five set and valid: a config with the values (the port as an int)."""
        config = load_smtp_config(_env())

        assert isinstance(config, SmtpConfig)
        assert config.host == _HOST
        assert config.port == 587
        assert config.username == _USERNAME
        assert config.password.get_secret_value() == _PASSWORD
        assert config.from_address == _FROM

    def test_mailer_load_accepts_port_465(self) -> None:
        """SMTP_PORT=465 gives implicit TLS."""
        config = load_smtp_config(_env({"SMTP_PORT": "465"}))

        assert config is not None
        assert config.port == 465

    def test_mailer_load_logs_no_warning_when_configured(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A complete configuration logs no warning."""
        caplog.set_level(logging.DEBUG)

        load_smtp_config(_env())

        assert _warnings(caplog) == []

    def test_mailer_load_reads_os_environ_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without an argument it reads os.environ."""
        for name, value in _env().items():
            monkeypatch.setenv(name, value)

        config = load_smtp_config()

        assert config is not None
        assert config.host == _HOST

    def test_mailer_load_returns_none_without_os_environ_values(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With no SMTP variable in os.environ it returns None (admino still starts)."""
        for name in _ENV_NAMES:
            monkeypatch.delenv(name, raising=False)

        assert load_smtp_config() is None

    @pytest.mark.parametrize("missing", _ENV_NAMES)
    def test_mailer_load_returns_none_when_one_is_missing(self, missing: str) -> None:
        """Any variable missing: None."""
        assert load_smtp_config(_env({missing: None})) is None

    @pytest.mark.parametrize("missing", _ENV_NAMES)
    @pytest.mark.parametrize("blank", ["", "   "])
    def test_mailer_load_treats_blank_as_missing(self, missing: str, blank: str) -> None:
        """An empty or whitespace-only variable counts as missing."""
        assert load_smtp_config(_env({missing: blank})) is None

    @pytest.mark.parametrize("missing", _ENV_NAMES)
    def test_mailer_load_warns_once_naming_the_missing_variable(
        self, missing: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """One WARNING that names the missing variable."""
        caplog.set_level(logging.DEBUG)

        load_smtp_config(_env({missing: None}))

        warnings = _warnings(caplog)
        assert len(warnings) == 1
        assert missing in warnings[0].getMessage()

    def test_mailer_load_warning_names_every_missing_variable(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """With nothing set, the one warning names all five variables."""
        caplog.set_level(logging.DEBUG)

        assert load_smtp_config({}) is None

        warnings = _warnings(caplog)
        assert len(warnings) == 1
        for name in _ENV_NAMES:
            assert name in warnings[0].getMessage()

    def test_mailer_load_warning_names_only_the_missing_variables(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Variables that are set aren't reported as missing."""
        caplog.set_level(logging.DEBUG)

        load_smtp_config(_env({"SMTP_PASSWORD": None, "SMTP_FROM": ""}))

        message = _warnings(caplog)[0].getMessage()
        assert "SMTP_PASSWORD" in message
        assert "SMTP_FROM" in message
        assert "SMTP_HOST" not in message
        assert "SMTP_USERNAME" not in message

    @pytest.mark.parametrize("missing", _ENV_NAMES)
    def test_mailer_load_missing_warning_logs_no_values(
        self, missing: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The warning never carries the values of the variables that are set."""
        caplog.set_level(logging.DEBUG)

        load_smtp_config(_env({missing: None}))

        _assert_absent(caplog, _HOST, _USERNAME, _PASSWORD, _FROM)

    @pytest.mark.parametrize(
        ("name", "value", "markers"),
        [
            pytest.param("SMTP_PORT", "2525", ("2525",), id="port-2525"),
            pytest.param("SMTP_PORT", "25", (), id="port-25"),
            pytest.param("SMTP_PORT", "port-marker-x1", ("port-marker-x1",), id="port-text"),
            pytest.param("SMTP_PORT", "99999", ("99999",), id="port-out-of-range"),
            pytest.param("SMTP_HOST", "bad host-marker.example", ("host-marker",), id="host-space"),
            pytest.param("SMTP_HOST", "host-marker-nodot", ("host-marker",), id="host-no-tld"),
            pytest.param("SMTP_HOST", "10.20.30.40", ("10.20.30.40",), id="host-ip"),
            pytest.param("SMTP_FROM", "from-marker-no-at", ("from-marker",), id="from-no-at"),
            pytest.param(
                "SMTP_FROM",
                "from-marker@admino.invalid" + _CRLF + "Bcc: eve-marker@evil.invalid",
                ("from-marker", "eve-marker"),
                id="from-header-injection",
            ),
            pytest.param(
                "SMTP_USERNAME", "user-marker" + _NUL, ("user-marker",), id="username-nul"
            ),
        ],
    )
    def test_mailer_load_invalid_value_returns_none_and_names_the_variable(
        self,
        name: str,
        value: str,
        markers: tuple[str, ...],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """An invalid value: None, and a WARNING that names the variable, never its value,
        never pydantic's input echo, never the password."""
        caplog.set_level(logging.DEBUG)

        result = load_smtp_config(_env({name: value}))

        assert result is None
        warnings = _warnings(caplog)
        assert warnings
        assert any(name in record.getMessage() for record in warnings)
        _assert_absent(caplog, *markers, _PASSWORD, _USERNAME, "input_value")

    @pytest.mark.parametrize(
        "environ",
        [
            pytest.param(dict.fromkeys(_ENV_NAMES, _NUL), id="all-nul"),
            pytest.param(dict.fromkeys(_ENV_NAMES, "x" * 5000), id="all-huge"),
            pytest.param(_env({"SMTP_PORT": "587.0"}), id="port-float-text"),
            pytest.param(_env({"SMTP_PORT": "0x24b"}), id="port-hex"),
            pytest.param(_env({"SMTP_PORT": "-587"}), id="port-negative"),
            pytest.param(_env({"SMTP_PORT": "5" * 400}), id="port-huge-number"),
        ],
    )
    def test_mailer_load_never_raises(self, environ: dict[str, str]) -> None:
        """Garbage in any variable gives None, never an exception (startup must go on)."""
        assert load_smtp_config(environ) is None


# ---------------------------------------------------------------------------
# 4. build_message(): the EmailMessage
# ---------------------------------------------------------------------------


class TestBuildMessage:
    """build_message() builds one stdlib EmailMessage for one recipient."""

    def test_mailer_build_returns_email_message(self) -> None:
        """A stdlib email.message.EmailMessage."""
        assert isinstance(_message(), EmailMessage)

    def test_mailer_build_sets_from_to_subject(self) -> None:
        """From is the configured address (a display name is allowed), To the recipient,
        Subject the rendered subject."""
        rendered = _rendered()
        message = build_message(_config(), to=_TO, rendered=rendered)

        assert parseaddr(str(message["From"]))[1] == _FROM
        assert str(message["To"]) == _TO
        assert str(message["Subject"]) == rendered.subject

    def test_mailer_build_sets_date_and_message_id(self) -> None:
        """A parseable, timezone-aware Date and a <...@...> Message-ID."""
        message = _message()

        assert message["Date"] is not None
        sent = parsedate_to_datetime(str(message["Date"]))
        assert sent.tzinfo is not None
        assert abs((datetime.now(UTC) - sent).total_seconds()) < 3600
        message_id = str(message["Message-ID"])
        assert message_id.startswith("<")
        assert message_id.endswith(">")
        assert "@" in message_id

    def test_mailer_build_marks_the_message_auto_generated(self) -> None:
        """Auto-Submitted: auto-generated (RFC 3834), so autoresponders don't reply."""
        assert str(_message()["Auto-Submitted"]) == "auto-generated"

    def test_mailer_build_has_a_single_recipient(self) -> None:
        """No Cc, no Bcc: exactly the one recipient."""
        message = _message()

        assert message["Cc"] is None
        assert message["Bcc"] is None
        assert message.get_all("To") == [_TO]

    def test_mailer_build_is_multipart_alternative(self) -> None:
        """multipart/alternative with text/plain first and text/html second."""
        message = _message()

        assert message.get_content_type() == "multipart/alternative"
        assert [part.get_content_type() for part in message.iter_parts()] == [
            "text/plain",
            "text/html",
        ]

    def test_mailer_build_parts_carry_the_rendered_bodies(self) -> None:
        """The text part is rendered.text and the HTML part is rendered.html."""
        rendered = _rendered()
        message = build_message(_config(), to=_TO, rendered=rendered)
        text_part, html_part = list(message.iter_parts())

        assert _normalized_body(text_part.get_content()) == _normalized_body(rendered.text)
        assert _normalized_body(html_part.get_content()) == _normalized_body(rendered.html)

    def test_mailer_build_parts_are_utf8(self) -> None:
        """Both parts declare charset utf-8."""
        charsets = [part.get_content_charset() for part in _message().iter_parts()]

        assert charsets == ["utf-8", "utf-8"]

    def test_mailer_build_serializes_and_parses_back(self) -> None:
        """The message serializes to bytes and parses back with the same headers and text."""
        rendered = _rendered()
        message = build_message(_config(), to=_TO, rendered=rendered)

        parsed = email.message_from_bytes(message.as_bytes(), policy=email.policy.default)

        assert str(parsed["Subject"]) == rendered.subject
        assert str(parsed["To"]) == _TO
        body = parsed.get_body(preferencelist=("plain",))
        assert body is not None
        assert _normalized_body(body.get_content()) == _normalized_body(rendered.text)

    def test_mailer_build_works_with_rendered_templates(self) -> None:
        """A real render() output (French) goes through unchanged."""
        params = InvitationParams(
            org_name="Société Générale SA",
            accept_link="https://admino.example.ch/invite/tok",
            expires_at=datetime(2026, 9, 1, 14, 30, tzinfo=UTC),
        )
        rendered = render(params, "fr")

        message = build_message(_config(), to=_TO, rendered=rendered)

        assert str(message["Subject"]) == rendered.subject
        html_part = list(message.iter_parts())[1]
        assert _normalized_body(html_part.get_content()) == _normalized_body(rendered.html)

    @pytest.mark.parametrize(
        "to",
        [
            pytest.param(_TO + _CRLF + "Bcc: eve@evil.invalid", id="crlf-bcc"),
            pytest.param(_TO + _NEWLINE + "Bcc: eve@evil.invalid", id="lf-bcc"),
            pytest.param(_TO + _CARRIAGE_RETURN + "Bcc: eve@evil.invalid", id="cr-bcc"),
            pytest.param(_TO + _CRLF, id="trailing-crlf"),
        ],
    )
    def test_mailer_build_refuses_crlf_in_recipient(self, to: str) -> None:
        """A CR or LF in the recipient is a ValueError: never a header injection."""
        with pytest.raises(ValueError, match=r".*"):
            build_message(_config(), to=to, rendered=_rendered())

    @pytest.mark.parametrize(
        "to",
        [
            pytest.param(_TO + ",eve@evil.invalid", id="comma-list"),
            pytest.param(_TO + ", eve@evil.invalid", id="comma-space-list"),
            pytest.param("Eve <eve@evil.invalid>", id="display-name"),
            pytest.param("<" + _TO + ">", id="angle-brackets"),
            pytest.param("", id="empty"),
        ],
    )
    def test_mailer_build_refuses_anything_but_one_bare_recipient(self, to: str) -> None:
        """users_email_format_check lets "a@x.ch,b@y.ch" through, and smtplib would mail
        both: build_message() takes exactly one bare address, or raises ValueError."""
        with pytest.raises(ValueError, match=r".*"):
            build_message(_config(), to=to, rendered=_rendered())

    def test_mailer_build_refuses_crlf_in_subject(self) -> None:
        """A CR/LF in the subject is a ValueError, not an injected header."""
        rendered = _rendered(subject="Hello" + _CRLF + "Bcc: eve@evil.invalid")

        with pytest.raises(ValueError, match=r".*"):
            build_message(_config(), to=_TO, rendered=rendered)

    def test_mailer_build_is_keyword_only(self) -> None:
        """to and rendered are keyword-only, so they can't be swapped by position."""
        params = inspect.signature(build_message).parameters

        assert params["to"].kind is inspect.Parameter.KEYWORD_ONLY
        assert params["rendered"].kind is inspect.Parameter.KEYWORD_ONLY


# ---------------------------------------------------------------------------
# 5. send_message(): smtplib over TLS
# ---------------------------------------------------------------------------


class TestSendImplicitTls:
    """Port 465: SMTP_SSL with a verified context, then login and send."""

    def test_mailer_send_465_uses_smtp_ssl(self, smtp_mocks: _SmtpMocks) -> None:
        """SMTP_SSL(host, 465, timeout=30, context=<the default context>)."""
        send_message(_config(port=465), _message())

        smtp_mocks.smtp_ssl.assert_called_once()
        bound = _bound(_REAL_SMTP_SSL, smtp_mocks.smtp_ssl.call_args)
        assert bound["host"] == _HOST
        assert bound["port"] == 465
        assert bound["timeout"] == SMTP_TIMEOUT_SECONDS
        assert bound["context"] is smtp_mocks.context

    def test_mailer_send_465_never_constructs_plain_smtp(self, smtp_mocks: _SmtpMocks) -> None:
        """No plain SMTP connection on the implicit-TLS port."""
        send_message(_config(port=465), _message())

        smtp_mocks.smtp.assert_not_called()

    def test_mailer_send_465_logs_in_then_sends(self, smtp_mocks: _SmtpMocks) -> None:
        """login(username, password) then send_message(message), no STARTTLS."""
        message = _message()

        send_message(_config(port=465), message)

        names = _call_names(smtp_mocks.conn)
        assert names.index("login") < names.index("send_message")
        assert "starttls" not in names
        assert _login_args(smtp_mocks.conn) == (_USERNAME, _PASSWORD)
        assert _sent_message(smtp_mocks.conn) is message


class TestSendStartTls:
    """Port 587: SMTP, then STARTTLS with a verified context before anything else."""

    def test_mailer_send_587_uses_smtp(self, smtp_mocks: _SmtpMocks) -> None:
        """SMTP(host, 587, timeout=30)."""
        send_message(_config(port=587), _message())

        smtp_mocks.smtp.assert_called_once()
        bound = _bound(_REAL_SMTP, smtp_mocks.smtp.call_args)
        assert bound["host"] == _HOST
        assert bound["port"] == 587
        assert bound["timeout"] == SMTP_TIMEOUT_SECONDS

    def test_mailer_send_587_never_constructs_smtp_ssl(self, smtp_mocks: _SmtpMocks) -> None:
        """No SMTP_SSL on the STARTTLS port."""
        send_message(_config(port=587), _message())

        smtp_mocks.smtp_ssl.assert_not_called()

    def test_mailer_send_587_starttls_with_the_default_context(
        self, smtp_mocks: _SmtpMocks
    ) -> None:
        """starttls(context=<the default context>)."""
        send_message(_config(port=587), _message())

        smtp_mocks.conn.starttls.assert_called_once()
        assert smtp_mocks.conn.starttls.call_args.kwargs.get("context") is smtp_mocks.context

    def test_mailer_send_587_starttls_before_login_and_send(self, smtp_mocks: _SmtpMocks) -> None:
        """STARTTLS comes before login and before send_message: no credentials or mail in
        plaintext."""
        message = _message()

        send_message(_config(port=587), message)

        names = _call_names(smtp_mocks.conn)
        assert names.index("starttls") < names.index("login") < names.index("send_message")
        assert _login_args(smtp_mocks.conn) == (_USERNAME, _PASSWORD)
        assert _sent_message(smtp_mocks.conn) is message

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(
                smtplib.SMTPNotSupportedError("STARTTLS extension not supported by server."),
                id="not-supported",
            ),
            pytest.param(smtplib.SMTPResponseException(454, b"TLS not available"), id="454"),
            pytest.param(ssl.SSLCertVerificationError("certificate verify failed"), id="cert"),
            pytest.param(RuntimeError("No SSL support included in this Python"), id="no-ssl"),
        ],
    )
    def test_mailer_send_587_failed_starttls_never_falls_back(
        self, smtp_mocks: _SmtpMocks, error: Exception
    ) -> None:
        """If STARTTLS fails, the error propagates and nothing is sent in plaintext: no login,
        no send_message."""
        smtp_mocks.conn.starttls.side_effect = error

        with pytest.raises(type(error)):
            send_message(_config(port=587), _message())

        smtp_mocks.conn.login.assert_not_called()
        smtp_mocks.conn.send_message.assert_not_called()
        smtp_mocks.conn.sendmail.assert_not_called()

    def test_mailer_send_587_failed_starttls_closes_the_connection(
        self, smtp_mocks: _SmtpMocks
    ) -> None:
        """The connection is closed after a failed STARTTLS."""
        smtp_mocks.conn.starttls.side_effect = smtplib.SMTPNotSupportedError("no STARTTLS")

        with pytest.raises(smtplib.SMTPNotSupportedError):
            send_message(_config(port=587), _message())

        assert _closed(smtp_mocks.conn)


@pytest.mark.parametrize("port", [465, 587])
class TestSendCommon:
    """Rules both ports follow: verified TLS, no debug output, errors propagate, always closed."""

    def test_mailer_send_uses_a_verified_default_context(
        self, smtp_mocks: _SmtpMocks, port: int
    ) -> None:
        """ssl.create_default_context() for server auth, never an unverified context, and the
        context is left verifying (check_hostname on, CERT_REQUIRED)."""
        send_message(_config(port=port), _message())

        smtp_mocks.create_context.assert_called_once()
        bound = _bound(ssl.create_default_context, smtp_mocks.create_context.call_args)
        assert bound.get("purpose", ssl.Purpose.SERVER_AUTH) == ssl.Purpose.SERVER_AUTH
        smtp_mocks.unverified.assert_not_called()
        assert smtp_mocks.context.check_hostname is True
        assert smtp_mocks.context.verify_mode == ssl.CERT_REQUIRED

    def test_mailer_send_never_enables_debug_output(
        self, smtp_mocks: _SmtpMocks, port: int
    ) -> None:
        """set_debuglevel is never called with a non-zero level (it prints addresses)."""
        send_message(_config(port=port), _message())

        levels = [
            call.args[0] if call.args else call.kwargs.get("debuglevel")
            for call in smtp_mocks.conn.set_debuglevel.call_args_list
        ]
        assert all(level == 0 for level in levels)

    def test_mailer_send_closes_the_connection_on_success(
        self, smtp_mocks: _SmtpMocks, port: int
    ) -> None:
        """The connection is closed after a successful send."""
        send_message(_config(port=port), _message())

        assert _closed(smtp_mocks.conn)

    @pytest.mark.parametrize(
        ("method", "error"),
        [
            pytest.param(
                "login",
                smtplib.SMTPAuthenticationError(535, b"5.7.8 authentication failed"),
                id="login-refused",
            ),
            pytest.param(
                "send_message",
                smtplib.SMTPRecipientsRefused({_TO: (550, b"no such user")}),
                id="recipient-refused",
            ),
            pytest.param("send_message", smtplib.SMTPServerDisconnected("gone"), id="disconnected"),
            pytest.param("send_message", TimeoutError("timed out"), id="timeout"),
        ],
    )
    def test_mailer_send_errors_propagate_and_close(
        self, smtp_mocks: _SmtpMocks, port: int, method: str, error: Exception
    ) -> None:
        """An SMTP error propagates to the caller (the outbox decides on retries), and the
        connection is still closed."""
        getattr(smtp_mocks.conn, method).side_effect = error

        with pytest.raises(type(error)):
            send_message(_config(port=port), _message())

        assert _closed(smtp_mocks.conn)

    def test_mailer_send_failed_login_sends_nothing(
        self, smtp_mocks: _SmtpMocks, port: int
    ) -> None:
        """A refused login never reaches send_message."""
        smtp_mocks.conn.login.side_effect = smtplib.SMTPAuthenticationError(535, b"denied")

        with pytest.raises(smtplib.SMTPAuthenticationError):
            send_message(_config(port=port), _message())

        smtp_mocks.conn.send_message.assert_not_called()

    def test_mailer_send_connection_error_propagates(
        self, smtp_mocks: _SmtpMocks, port: int
    ) -> None:
        """A connection failure in the constructor propagates."""
        smtp_mocks.smtp.side_effect = ConnectionRefusedError("refused")
        smtp_mocks.smtp_ssl.side_effect = ConnectionRefusedError("refused")

        with pytest.raises(ConnectionRefusedError):
            send_message(_config(port=port), _message())

    def test_mailer_send_is_synchronous(self, smtp_mocks: _SmtpMocks, port: int) -> None:
        """send_message is a plain blocking function (deliver() moves it off the loop)."""
        assert not inspect.iscoroutinefunction(send_message)
        assert send_message(_config(port=port), _message()) is None


# ---------------------------------------------------------------------------
# 6. deliver(): off the event loop
# ---------------------------------------------------------------------------


class TestDeliver:
    """deliver() runs send_message in a worker thread through asyncio.to_thread."""

    def test_mailer_deliver_is_a_coroutine_function(self) -> None:
        """deliver is async."""
        assert inspect.iscoroutinefunction(deliver)

    async def test_mailer_deliver_runs_send_message_in_to_thread(self) -> None:
        """asyncio.to_thread(send_message, config, message) is awaited."""
        config = _config()
        message = _message()
        to_thread = AsyncMock(return_value=None)

        with patch("admino.mailer.asyncio.to_thread", to_thread):
            await deliver(config, message)

        to_thread.assert_awaited_once()
        args = to_thread.await_args.args if to_thread.await_args else ()
        assert args[0] is mailer_mod.send_message
        assert args[1:] == (config, message)

    async def test_mailer_deliver_propagates_errors(self) -> None:
        """A send error comes out of deliver() unchanged."""
        error = smtplib.SMTPServerDisconnected("Connection unexpectedly closed")

        with (
            patch("admino.mailer.asyncio.to_thread", AsyncMock(side_effect=error)),
            pytest.raises(smtplib.SMTPServerDisconnected),
        ):
            await deliver(_config(), _message())

    async def test_mailer_deliver_sends_from_a_worker_thread(self) -> None:
        """The blocking send runs on another thread than the event loop's."""
        loop_thread = threading.get_ident()
        seen: list[tuple[int, Any, Any]] = []

        def fake_send(config: SmtpConfig, message: EmailMessage) -> None:
            seen.append((threading.get_ident(), config, message))

        config = _config()
        message = _message()
        with patch("admino.mailer.send_message", fake_send):
            await asyncio.wait_for(deliver(config, message), timeout=5)

        assert len(seen) == 1
        assert seen[0][0] != loop_thread
        assert seen[0][1] is config
        assert seen[0][2] is message


# ---------------------------------------------------------------------------
# 7. Module isolation and hygiene
# ---------------------------------------------------------------------------

_ALLOWED_ADMINO: frozenset[str] = frozenset({"admino.access", "admino.email_templates"})
_ALLOWED_THIRD_PARTY: frozenset[str] = frozenset({"pydantic", "pydantic_core"})


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


def _tree() -> ast.Module:
    """The parsed mailer source."""
    return ast.parse((_SRC_DIR / "mailer.py").read_text(encoding="utf-8"))


class TestModuleIsolation:
    """mailer.py is stdlib-only transport code with no TLS downgrade anywhere."""

    def test_mailer_imports_only_allowed_modules(self) -> None:
        """Only the stdlib, pydantic, admino.access and admino.email_templates: no agent,
        server, llm*, tools, permissions or database import, and no new dependency."""
        disallowed = [
            module
            for module in _imported_modules(_SRC_DIR / "mailer.py")
            if not (
                module.split(".")[0] in sys.stdlib_module_names
                or module.split(".")[0] in _ALLOWED_THIRD_PARTY
                or module in _ALLOWED_ADMINO
            )
        ]

        assert disallowed == []

    def test_mailer_uses_stdlib_smtplib_and_email(self) -> None:
        """smtplib, ssl and email.message are the transport (no third-party mail library)."""
        roots = {module.split(".")[0] for module in _imported_modules(_SRC_DIR / "mailer.py")}

        assert {"smtplib", "ssl", "email", "asyncio"} <= roots

    def test_mailer_makes_no_dynamic_code_calls(self) -> None:
        """No eval, exec, compile, __import__ or importlib."""
        calls = [
            node.func.id
            for node in ast.walk(_tree())
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"eval", "exec", "compile", "__import__"}
        ]
        modules = _imported_modules(_SRC_DIR / "mailer.py")

        assert calls == []
        assert [m for m in modules if m.startswith("importlib")] == []

    def test_mailer_never_passes_shell_true(self) -> None:
        """No shell=True anywhere."""
        shells = [
            node
            for node in ast.walk(_tree())
            if isinstance(node, ast.keyword)
            and node.arg == "shell"
            and isinstance(node.value, ast.Constant)
            and node.value.value is True
        ]

        assert shells == []

    def test_mailer_never_weakens_tls(self) -> None:
        """No _create_unverified_context, CERT_NONE or CERT_OPTIONAL reference, and no
        assignment to check_hostname or verify_mode."""
        tree = _tree()
        weak_refs = [
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and node.attr in {"_create_unverified_context", "CERT_NONE", "CERT_OPTIONAL"}
        ]
        weak_assigns = [
            target.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign | ast.AugAssign | ast.AnnAssign)
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
            if isinstance(target, ast.Attribute)
            and target.attr in {"check_hostname", "verify_mode"}
        ]

        assert weak_refs == []
        assert weak_assigns == []

    def test_mailer_never_enables_smtp_debug_output(self) -> None:
        """No set_debuglevel call with anything but a literal 0."""
        calls = [
            node
            for node in ast.walk(_tree())
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "set_debuglevel"
            and not (
                len(node.args) == 1
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == 0
            )
        ]

        assert calls == []

    def test_mailer_permission_engine_does_not_import_it(self) -> None:
        """permissions.py gains no import of mailer."""
        modules = _imported_modules(_SRC_DIR / "permissions.py")

        assert [m for m in modules if m.startswith("admino.mailer")] == []
