"""Tests for admino.migrate — the one-shot migrate step and the runtime role's password (GH-220).

``python -m admino.migrate`` is the only code path that knows the owner credential
(PG_USER / PG_PASSWORD: the postgres image's superuser, which owns every table). It
applies the migrations as the owner (migration 0018 creates the least-privilege runtime
role ``admino_app``), then sets the runtime role's password from PG_APP_PASSWORD. The
app (server, startup, admin CLI) connects as ``admino_app`` only and never migrates.

What is pinned (contract section 2):
- ``owner_database_url_from_env()``: the owner DSN from PG_USER (default ``admino``),
  PG_PASSWORD (required; percent-encoded with ``quote(..., safe='')`` so asyncpg, which
  decodes it with ``unquote``, gets it back exactly: a space is %20, never '+'),
  PG_HOST/PG_PORT/PG_DATABASE; it never
  uses PG_APP_PASSWORD.
- ``scram_sha256_verifier()``: PostgreSQL's ``SCRAM-SHA-256$<i>:<salt>$<StoredKey>:<ServerKey>``
  verifier. Checked against an RFC 5802 computation written out step by step here
  (``Hi()`` as iterated HMAC, not pbkdf2), the RFC 7677 test vector (whose client proof
  and server signature the derived keys must reproduce), custom iterations, a fresh
  16-byte salt per call, and the plaintext never appearing in the output.
- ``check_runtime_password()``: missing, outside printable ASCII 0x20..0x7E, or equal to
  the owner password → ValueError with a fixed message that never contains the password.
- ``set_runtime_role_password()``: one ``fetchval`` of the exact server-side ``format()``
  statement (role name and verifier as ``$1::text``/``$2::text``), then ``execute`` of
  exactly what the server returned. The plaintext never reaches the connection.
- ``migrate()``: a one-connection owner pool, migrations BEFORE the password (0018
  creates the role), ``close_pool()`` on success and on every failure.
- ``main()``: exit 1 with nothing connected on a missing or unsafe configuration, exit 1
  on database/OS/timeout errors, exit 0 on success; output formatted by admino's
  formatters (text by default, JSON with LOG_FORMAT=json, LOG_LEVEL honoured).
- Source: the ``python -m`` entry point; no eval/exec/compile/importlib/subprocess/shell;
  no SQL built in Python (f-string, %-format, ``.format()``, concatenation).

All asyncpg access is mocked; no real PostgreSQL is needed. An autouse guard replaces
``asyncpg.create_pool`` and ``asyncpg.connect`` so an accidental real connection fails
the test instead of reaching the network.

Security notes:
- Every secret is a distinctive marker; the leak checks scan the raw value and its
  quote_plus form, plus "postgresql://" (a DSN), "SCRAM-SHA-256" (a verifier) and
  "Traceback". The migrate failures carry all of them in the exception message, so a
  ``str(exc)`` or traceback in a log line is caught.
- ``main()`` replaces the root logging handlers. Each main() test restores them inside
  the test body (``tests.log_capture.restored_logging``, never in a fixture teardown)
  and reads what the configured handler wrote to stderr/stdout through ``capsys``.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import inspect
import json
import re
import runpy
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import DEFAULT, AsyncMock, MagicMock, patch
from urllib.parse import quote, quote_plus, unquote, urlsplit

import asyncpg
import pytest

import admino.database as db_mod
import admino.migrate as migrate_mod
from tests.log_capture import restored_logging

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RUNTIME_ROLE: Final = "admino_app"

# Distinctive secrets. The owner password has "/" and "@" so the DSN encoding shows.
_OWNER_PASSWORD: Final = "0wner/Super@user-Pw-4417"
_APP_PASSWORD: Final = "App-Runtime-Pw-8823"

_ENV_VARS: Final[tuple[str, ...]] = (
    "PG_HOST",
    "PG_PORT",
    "PG_USER",
    "PG_DATABASE",
    "PG_PASSWORD",
    "PG_APP_PASSWORD",
    "LOG_LEVEL",
    "LOG_FORMAT",
)

# The exact statement the contract specifies: the SERVER quotes the identifier (%I)
# and the literal (%L); Python never interpolates anything into SQL.
_ALTER_ROLE_SQL: Final = (
    "SELECT format('ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
    "NOREPLICATION NOBYPASSRLS PASSWORD %L', $1::text, $2::text)"
)
_ROLE_ATTRIBUTES: Final[tuple[str, ...]] = (
    "LOGIN",
    "NOSUPERUSER",
    "NOCREATEDB",
    "NOCREATEROLE",
    "NOREPLICATION",
    "NOBYPASSRLS",
)

# What the mocked server returns for the format() query (it contains a verifier, so a
# log line that echoes the statement is caught by the "SCRAM-SHA-256" scan).
_FAKE_STATEMENT: Final = (
    "ALTER ROLE admino_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION "
    "NOBYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:ZmFrZS1zYWx0$ZmFrZQ==:ZmFrZQ=='"
)

# PostgreSQL's verifier: SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>,
# standard base64 with padding; StoredKey and ServerKey are 32-byte SHA-256 values.
_VERIFIER_RE: Final = re.compile(
    r"SCRAM-SHA-256\$(?P<iterations>[1-9][0-9]*):(?P<salt>[A-Za-z0-9+/]+={0,2})"
    r"\$(?P<stored_key>[A-Za-z0-9+/]{43}=):(?P<server_key>[A-Za-z0-9+/]{43}=)"
)

# RFC 7677 section 3 (SCRAM-SHA-256 example exchange): user "user", password "pencil".
_RFC7677_PASSWORD: Final = "pencil"
_RFC7677_SALT_B64: Final = "W22ZaJ0SNY7soEsUEjb6gQ=="
_RFC7677_CLIENT_FIRST_BARE: Final = "n=user,r=rOprNGfwEbeRWgbNEkqO"
_RFC7677_SERVER_FIRST: Final = (
    "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
)
_RFC7677_CLIENT_FINAL_WITHOUT_PROOF: Final = (
    "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
)
_RFC7677_CLIENT_PROOF_B64: Final = "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
_RFC7677_SERVER_SIGNATURE_B64: Final = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
# The verifier PostgreSQL stores for "pencil" with that salt and 4096 iterations
# (derived from the vector above; the RFC test reproduces its proof and signature).
_RFC7677_VERIFIER: Final = (
    "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ=="
    "$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY="
    ":wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU="
)

# Exception text that would leak everything if a log line carried str(exc).
_LEAKY_DETAIL: Final = (
    f"connect postgresql://admino:{_OWNER_PASSWORD}@postgres:5432/admino failed; "
    f"PASSWORD 'SCRAM-SHA-256$4096:c2FsdA==$a2V5:a2V5' for {_APP_PASSWORD}"
)

# Signatures of the real functions, taken before any test patches them.
_INIT_POOL_SIGNATURE: Final = inspect.signature(db_mod.init_pool)
_RUN_MIGRATIONS_SIGNATURE: Final = inspect.signature(db_mod.run_migrations)
_MIGRATE_SIGNATURE: Final = inspect.signature(migrate_mod.migrate)
_SET_PASSWORD_SIGNATURE: Final = inspect.signature(migrate_mod.set_runtime_role_password)

_MIGRATE_SOURCE_PATH: Final = Path(migrate_mod.__file__)

_LEVELS: Final = "DEBUG|INFO|WARNING|ERROR|CRITICAL"
# TextFormatter: "<asctime> <LEVEL> <logger> [<request_id or ->] — <message>".
_TEXT_LINE_RE: Final = re.compile(
    rf"^\S+ (?:{_LEVELS})\s+\S+ \[[^\]]*\] " + re.escape(chr(0x2014)) + " "
)


# ---------------------------------------------------------------------------
# Independent SCRAM-SHA-256 computation (RFC 5802 section 3, written out)
# ---------------------------------------------------------------------------


def _hi(password: bytes, salt: bytes, iterations: int) -> bytes:
    """RFC 5802 ``Hi(str, salt, i)`` with HMAC-SHA-256, step by step.

    ``U1 := HMAC(str, salt + INT(1))``, ``Ui := HMAC(str, Ui-1)``,
    ``Hi := U1 XOR U2 XOR ... XOR Ui`` (INT(1) is the 4-byte big-endian 1).
    """
    u = hmac.digest(password, salt + (1).to_bytes(4, "big"), "sha256")
    accumulated = int.from_bytes(u, "big")
    for _ in range(iterations - 1):
        u = hmac.digest(password, u, "sha256")
        accumulated ^= int.from_bytes(u, "big")
    return accumulated.to_bytes(32, "big")


def _b64(raw: bytes) -> str:
    """Standard base64 with padding, as text."""
    return base64.b64encode(raw).decode("ascii")


def _expected_verifier(password: str, salt: bytes, iterations: int) -> str:
    """PostgreSQL's SCRAM-SHA-256 verifier, computed independently of admino.migrate."""
    # SaltedPassword := Hi(Normalize(password), salt, i); SASLprep is the identity for ASCII.
    salted_password = _hi(password.encode("utf-8"), salt, iterations)
    # ClientKey := HMAC(SaltedPassword, "Client Key"); StoredKey := H(ClientKey)
    client_key = hmac.digest(salted_password, b"Client Key", "sha256")
    stored_key = hashlib.sha256(client_key).digest()
    # ServerKey := HMAC(SaltedPassword, "Server Key")
    server_key = hmac.digest(salted_password, b"Server Key", "sha256")
    return f"SCRAM-SHA-256${iterations}:{_b64(salt)}${_b64(stored_key)}:{_b64(server_key)}"


@dataclass(frozen=True)
class _Verifier:
    """A parsed verifier."""

    iterations: int
    salt: bytes
    stored_key: bytes
    server_key: bytes


def _parse_verifier(verifier: str) -> _Verifier:
    """Parse a verifier, failing the test when it doesn't have PostgreSQL's format."""
    match = _VERIFIER_RE.fullmatch(verifier)
    assert match is not None, "not a SCRAM-SHA-256 verifier in PostgreSQL's format"
    return _Verifier(
        iterations=int(match["iterations"]),
        salt=base64.b64decode(match["salt"], validate=True),
        stored_key=base64.b64decode(match["stored_key"], validate=True),
        server_key=base64.b64decode(match["server_key"], validate=True),
    )


# ---------------------------------------------------------------------------
# Shared helpers and fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def connection_guards() -> Iterator[dict[str, AsyncMock]]:
    """Make any real asyncpg pool or connection fail the test (no network, ever)."""
    guards = {
        "create_pool": AsyncMock(side_effect=AssertionError("a real asyncpg pool was opened")),
        "connect": AsyncMock(side_effect=AssertionError("a real asyncpg connection was opened")),
    }
    with (
        patch.object(asyncpg, "create_pool", guards["create_pool"]),
        patch.object(asyncpg, "connect", guards["connect"]),
    ):
        yield guards


@pytest.fixture()
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Remove every PG_*/LOG_* variable (conftest sets PG_APP_PASSWORD for every test)."""
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.fixture()
def main_env(clean_env: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """A valid migrate configuration: owner and runtime passwords set, all else default."""
    clean_env.setenv("PG_PASSWORD", _OWNER_PASSWORD)
    clean_env.setenv("PG_APP_PASSWORD", _APP_PASSWORD)
    return clean_env


def _bound(signature: inspect.Signature, awaited: Any) -> list[Any]:
    """The values of a recorded call, bound to the real function's parameters, in order."""
    bound = signature.bind(*awaited.args, **awaited.kwargs)
    bound.apply_defaults()
    return list(bound.arguments.values())


def _assert_no_secrets(output: str, *secrets: str) -> None:
    """No secret (raw or percent-encoded), DSN, verifier or traceback in ``output``."""
    for secret in secrets:
        assert secret not in output
        assert quote(secret, safe="") not in output
        assert quote_plus(secret) not in output
    assert "postgresql://" not in output
    assert "SCRAM-SHA-256" not in output
    assert "Traceback" not in output


def _all_call_values(mock: MagicMock) -> list[str]:
    """repr() and str() of every positional and keyword argument of every recorded call."""
    values: list[str] = []
    for recorded in mock.mock_calls:
        _name, args, kwargs = recorded
        for value in (*args, *kwargs.values()):
            values.extend((repr(value), str(value)))
    return values


@dataclass
class _MainRun:
    """What one main() run returned and wrote, plus its mocks."""

    code: int
    output: str
    migrate: AsyncMock
    init_pool: AsyncMock


@pytest.fixture()
def run_main(
    capsys: pytest.CaptureFixture[str], connection_guards: dict[str, AsyncMock]
) -> Callable[..., _MainRun]:
    """Run ``migrate_mod.main()`` with ``migrate`` mocked; restore logging in the call phase.

    ``migrate_error`` makes the mocked migrate() raise. The returned output is what the
    configured handler wrote (stdout + stderr). The real asyncpg entry points stay
    guarded, so "nothing connects" is checked on three levels.
    """

    def _run(*, migrate_error: BaseException | None = None) -> _MainRun:
        fake_migrate = AsyncMock(side_effect=migrate_error)
        fake_init_pool = AsyncMock()
        capsys.readouterr()
        with (
            restored_logging(),
            patch.object(migrate_mod, "migrate", fake_migrate),
            patch.object(db_mod, "init_pool", fake_init_pool),
        ):
            code = migrate_mod.main()
        captured = capsys.readouterr()
        assert connection_guards["create_pool"].await_count == 0
        assert connection_guards["connect"].await_count == 0
        return _MainRun(
            code=code,
            output=captured.out + captured.err,
            migrate=fake_migrate,
            init_pool=fake_init_pool,
        )

    return _run


def _expected_owner_dsn(
    *,
    user: str = "admino",
    password: str = _OWNER_PASSWORD,
    host: str = "localhost",
    port: str = "5432",
    database: str = "admino",
) -> str:
    """The owner DSN the contract specifies."""
    return f"postgresql://{user}:{quote(password, safe='')}@{host}:{port}/{database}"


# ---------------------------------------------------------------------------
# owner_database_url_from_env()
# ---------------------------------------------------------------------------


class TestOwnerDatabaseUrlFromEnv:
    """The owner DSN: PG_USER (default admino) + PG_PASSWORD; never PG_APP_PASSWORD."""

    def test_migrate_owner_dsn_defaults_when_only_owner_password_set(
        self, clean_env: pytest.MonkeyPatch
    ) -> None:
        """Only PG_PASSWORD set → admino@localhost:5432/admino."""
        clean_env.setenv("PG_PASSWORD", "hunter2hunter2")

        assert migrate_mod.owner_database_url_from_env() == (
            "postgresql://admino:hunter2hunter2@localhost:5432/admino"
        )

    def test_migrate_owner_dsn_uses_overrides(self, clean_env: pytest.MonkeyPatch) -> None:
        """PG_HOST, PG_PORT, PG_USER and PG_DATABASE override the defaults."""
        clean_env.setenv("PG_HOST", "postgres")
        clean_env.setenv("PG_PORT", "6543")
        clean_env.setenv("PG_USER", "dbowner")
        clean_env.setenv("PG_DATABASE", "admino_prod")
        clean_env.setenv("PG_PASSWORD", "hunter2hunter2")

        assert migrate_mod.owner_database_url_from_env() == (
            "postgresql://dbowner:hunter2hunter2@postgres:6543/admino_prod"
        )

    @pytest.mark.parametrize(
        ("password", "encoded"),
        [
            ("s3cr3t/p@ss", "s3cr3t%2Fp%40ss"),
            ("a:b%c", "a%3Ab%25c"),
            ("p+q#r?s", "p%2Bq%23r%3Fs"),
            ("pw word", "pw%20word"),
        ],
        ids=["slash-at", "colon-percent", "plus-hash-question", "space"],
    )
    def test_migrate_owner_dsn_url_encodes_password(
        self, clean_env: pytest.MonkeyPatch, password: str, encoded: str
    ) -> None:
        """PG_PASSWORD is percent-encoded, never put in verbatim; a space is %20."""
        clean_env.setenv("PG_PASSWORD", password)

        assert migrate_mod.owner_database_url_from_env() == (
            f"postgresql://admino:{encoded}@localhost:5432/admino"
        )

    def test_migrate_owner_dsn_password_round_trips_through_unquote(
        self, clean_env: pytest.MonkeyPatch
    ) -> None:
        """Every printable ASCII character survives the DSN: decoding the password with
        ``unquote``, as asyncpg does, gives PG_PASSWORD back exactly (quote_plus's '+'
        for a space would come back as a literal '+')."""
        password = "".join(chr(code) for code in range(0x20, 0x7F))
        clean_env.setenv("PG_PASSWORD", password)

        url = migrate_mod.owner_database_url_from_env()

        assert url is not None
        assert unquote(urlsplit(url).password or "") == password

    @pytest.mark.parametrize("owner_password", [None, ""], ids=["unset", "empty"])
    def test_migrate_owner_dsn_without_owner_password_returns_none(
        self, clean_env: pytest.MonkeyPatch, owner_password: str | None
    ) -> None:
        """PG_PASSWORD unset or empty → None, even with PG_APP_PASSWORD set."""
        clean_env.setenv("PG_APP_PASSWORD", _APP_PASSWORD)
        if owner_password is not None:
            clean_env.setenv("PG_PASSWORD", owner_password)

        assert migrate_mod.owner_database_url_from_env() is None

    def test_migrate_owner_dsn_never_uses_app_password(self, clean_env: pytest.MonkeyPatch) -> None:
        """With both passwords set, the owner DSN carries PG_PASSWORD, not PG_APP_PASSWORD."""
        clean_env.setenv("PG_PASSWORD", "owner-Only-Pw-77")
        clean_env.setenv("PG_APP_PASSWORD", _APP_PASSWORD)

        url = migrate_mod.owner_database_url_from_env()

        assert url == "postgresql://admino:owner-Only-Pw-77@localhost:5432/admino"
        assert _APP_PASSWORD not in url


# ---------------------------------------------------------------------------
# scram_sha256_verifier()
# ---------------------------------------------------------------------------


class TestScramSha256Verifier:
    """PostgreSQL's SCRAM-SHA-256 verifier, computed with the standard library."""

    def test_migrate_scram_verifier_matches_rfc7677_vector(self) -> None:
        """ "pencil" with the RFC 7677 salt and 4096 iterations → the known verifier."""
        salt = base64.b64decode(_RFC7677_SALT_B64)

        verifier = migrate_mod.scram_sha256_verifier(_RFC7677_PASSWORD, salt=salt)

        assert verifier == _RFC7677_VERIFIER
        assert verifier == _expected_verifier(_RFC7677_PASSWORD, salt, 4096)

    def test_migrate_scram_verifier_authenticates_the_rfc7677_exchange(self) -> None:
        """The keys verify RFC 7677's client proof and reproduce its server signature.

        This is what PostgreSQL does with a stored verifier: ClientKey := ClientProof XOR
        HMAC(StoredKey, AuthMessage) must hash to StoredKey, and the server's signature is
        HMAC(ServerKey, AuthMessage).
        """
        salt = base64.b64decode(_RFC7677_SALT_B64)
        parsed = _parse_verifier(
            migrate_mod.scram_sha256_verifier(_RFC7677_PASSWORD, salt=salt, iterations=4096)
        )
        auth_message = ",".join(
            (
                _RFC7677_CLIENT_FIRST_BARE,
                _RFC7677_SERVER_FIRST,
                _RFC7677_CLIENT_FINAL_WITHOUT_PROOF,
            )
        ).encode("ascii")

        client_signature = hmac.digest(parsed.stored_key, auth_message, "sha256")
        client_proof = base64.b64decode(_RFC7677_CLIENT_PROOF_B64)
        client_key = bytes(a ^ b for a, b in zip(client_proof, client_signature, strict=True))
        server_signature = hmac.digest(parsed.server_key, auth_message, "sha256")

        assert hashlib.sha256(client_key).digest() == parsed.stored_key
        assert server_signature == base64.b64decode(_RFC7677_SERVER_SIGNATURE_B64)

    def test_migrate_scram_verifier_with_fixed_salt_matches_independent_computation(
        self,
    ) -> None:
        """A fixed salt gives exactly the step-by-step RFC 5802 result."""
        salt = bytes(range(16))

        verifier = migrate_mod.scram_sha256_verifier("Fixed-Salt-Pw-31", salt=salt)

        assert verifier == _expected_verifier("Fixed-Salt-Pw-31", salt, 4096)

    def test_migrate_scram_verifier_has_postgres_format(self) -> None:
        """``SCRAM-SHA-256$4096:<b64 salt>$<b64 StoredKey>:<b64 ServerKey>``, nothing else."""
        verifier = migrate_mod.scram_sha256_verifier("Format-Check-Pw-12")

        parsed = _parse_verifier(verifier)

        assert verifier.startswith("SCRAM-SHA-256$4096:")
        assert parsed.iterations == 4096
        assert len(parsed.stored_key) == 32
        assert len(parsed.server_key) == 32

    def test_migrate_scram_verifier_custom_iterations_appear_and_are_used(self) -> None:
        """iterations=8192 → the prefix says 8192 and the keys are derived with 8192."""
        salt = bytes(range(100, 116))

        verifier = migrate_mod.scram_sha256_verifier("Iterations-Pw-58", salt=salt, iterations=8192)

        assert verifier.startswith("SCRAM-SHA-256$8192:")
        assert verifier == _expected_verifier("Iterations-Pw-58", salt, 8192)

    def test_migrate_scram_verifier_default_salt_is_16_bytes_and_used(self) -> None:
        """Without a salt: a 16-byte salt, and the keys are the ones for that salt."""
        verifier = migrate_mod.scram_sha256_verifier("Default-Salt-Pw-64")

        parsed = _parse_verifier(verifier)

        assert len(parsed.salt) == 16
        assert verifier == _expected_verifier("Default-Salt-Pw-64", parsed.salt, 4096)

    def test_migrate_scram_verifier_default_salt_is_fresh_per_call(self) -> None:
        """Two calls with the same password differ (a random salt each time)."""
        first = _parse_verifier(migrate_mod.scram_sha256_verifier("Same-Pw-Twice-90"))
        second = _parse_verifier(migrate_mod.scram_sha256_verifier("Same-Pw-Twice-90"))

        assert first.salt != second.salt
        assert first.stored_key != second.stored_key
        assert first.server_key != second.server_key

    def test_migrate_scram_verifier_never_contains_the_plaintext(self) -> None:
        """The plaintext appears in no form (raw, base64, hex) in the verifier."""
        password = "Plaintext-Never-In-Verifier-26"

        verifier = migrate_mod.scram_sha256_verifier(password, salt=b"0123456789abcdef")

        assert password not in verifier
        assert _b64(password.encode("utf-8")) not in verifier
        assert password.encode("utf-8").hex() not in verifier.lower()


# ---------------------------------------------------------------------------
# check_runtime_password()
# ---------------------------------------------------------------------------

_CHECK_OWNER_PASSWORD: Final = "Owner-Check-Pw-6650"
_PRINTABLE_ASCII: Final = "".join(chr(code) for code in range(0x20, 0x7F))

# Characters outside printable ASCII 0x20..0x7E: C0 controls (NUL, tab, LF, CR, ESC,
# unit separator), DEL, C1 control, no-break space, a-umlaut, line separator, an emoji.
_NON_PRINTABLE_ASCII: Final[tuple[str, ...]] = tuple(
    chr(code)
    for code in (0x00, 0x09, 0x0A, 0x0D, 0x1B, 0x1F, 0x7F, 0x80, 0xA0, 0xE4, 0x2028, 0x1F600)
)


class TestCheckRuntimePassword:
    """PG_APP_PASSWORD must be set, printable ASCII, and differ from PG_PASSWORD."""

    def test_migrate_check_runtime_password_returns_valid_password(self) -> None:
        """A valid password comes back unchanged."""
        assert (
            migrate_mod.check_runtime_password(
                "Valid-Runtime-Pw-1", owner_password=_CHECK_OWNER_PASSWORD
            )
            == "Valid-Runtime-Pw-1"
        )

    @pytest.mark.parametrize(
        "password",
        [
            _PRINTABLE_ASCII,
            " ",
            "~",
            "with spaces inside",
            "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
        ],
        ids=["all-0x20-0x7e", "space", "tilde", "spaces", "punctuation"],
    )
    def test_migrate_check_runtime_password_accepts_printable_ascii(self, password: str) -> None:
        """Space and every character 0x20..0x7E are accepted."""
        assert (
            migrate_mod.check_runtime_password(password, owner_password=_CHECK_OWNER_PASSWORD)
            == password
        )

    @pytest.mark.parametrize("password", [None, ""], ids=["none", "empty"])
    def test_migrate_check_runtime_password_missing_raises_naming_variable(
        self, password: str | None
    ) -> None:
        """None or "" → ValueError that names PG_APP_PASSWORD and says it isn't set."""
        with pytest.raises(ValueError, match="PG_APP_PASSWORD") as raised:
            migrate_mod.check_runtime_password(password, owner_password=_CHECK_OWNER_PASSWORD)

        assert re.search(r"not set|unset|missing|empty", str(raised.value), re.IGNORECASE)

    @pytest.mark.parametrize(
        "bad_char", _NON_PRINTABLE_ASCII, ids=[f"U+{ord(c):04X}" for c in _NON_PRINTABLE_ASCII]
    )
    def test_migrate_check_runtime_password_outside_printable_ascii_raises(
        self, bad_char: str
    ) -> None:
        """Any character outside 0x20..0x7E → ValueError naming PG_APP_PASSWORD + printable ASCII.

        SCRAM's SASLprep is the identity only for ASCII, so the verifier computed here
        would not match what a client sends for such a password.
        """
        with pytest.raises(ValueError, match="PG_APP_PASSWORD") as raised:
            migrate_mod.check_runtime_password(
                f"Runtime{bad_char}Pw-42", owner_password=_CHECK_OWNER_PASSWORD
            )

        assert "printable ascii" in str(raised.value).lower()

    @pytest.mark.parametrize("bad_char", [chr(0x1F), chr(0x7F)], ids=["below-0x20", "above-0x7e"])
    def test_migrate_check_runtime_password_rejects_just_outside_the_range(
        self, bad_char: str
    ) -> None:
        """The range is exactly 0x20..0x7E: 0x1F and 0x7F alone are rejected."""
        with pytest.raises(ValueError, match="PG_APP_PASSWORD"):
            migrate_mod.check_runtime_password(bad_char, owner_password=_CHECK_OWNER_PASSWORD)

    def test_migrate_check_runtime_password_equal_to_owner_raises(self) -> None:
        """PG_APP_PASSWORD == PG_PASSWORD → ValueError: it must differ from PG_PASSWORD."""
        with pytest.raises(ValueError, match="PG_APP_PASSWORD") as raised:
            migrate_mod.check_runtime_password(
                _CHECK_OWNER_PASSWORD, owner_password=_CHECK_OWNER_PASSWORD
            )

        message = str(raised.value)
        assert re.search(r"\bPG_PASSWORD\b", message)
        assert re.search(r"differ|different|same|equal|identical", message, re.IGNORECASE)

    @pytest.mark.parametrize(
        ("password", "owner_password"),
        [
            ("Leak-Marker-" + chr(0xE4) + "-Pw-5521", _CHECK_OWNER_PASSWORD),
            ("Leak-Marker-" + chr(0x0A) + "-Pw-5521", _CHECK_OWNER_PASSWORD),
            ("Leak-Marker-" + chr(0x1F600) + "-Pw-5521", _CHECK_OWNER_PASSWORD),
            ("Leak-Marker-Same-Pw-5521", "Leak-Marker-Same-Pw-5521"),
        ],
        ids=["non-ascii", "newline", "emoji", "equal-to-owner"],
    )
    def test_migrate_check_runtime_password_message_never_contains_the_password(
        self, password: str, owner_password: str
    ) -> None:
        """The ValueError's message, repr and args carry no part of the password."""
        with pytest.raises(ValueError, match="PG_APP_PASSWORD") as raised:
            migrate_mod.check_runtime_password(password, owner_password=owner_password)

        rendered = " ".join((str(raised.value), repr(raised.value), repr(raised.value.args)))
        assert password not in rendered
        assert "Leak-Marker" not in rendered
        assert "Pw-5521" not in rendered


# ---------------------------------------------------------------------------
# set_runtime_role_password()
# ---------------------------------------------------------------------------

_ROLE_PASSWORD: Final = "Runtime-Plaintext-Pw-7Q"


def _connection() -> AsyncMock:
    """A connection whose format() query returns ``_FAKE_STATEMENT``."""
    conn = AsyncMock()
    conn.fetchval.return_value = _FAKE_STATEMENT
    return conn


class TestSetRuntimeRolePassword:
    """The server builds ALTER ROLE from the verifier; the plaintext never leaves Python."""

    async def test_migrate_set_password_asks_server_for_the_exact_statement(self) -> None:
        """One fetchval of exactly the contract's _ALTER_ROLE_SQL (whitespace aside)."""
        conn = _connection()

        await migrate_mod.set_runtime_role_password(conn, _ROLE_PASSWORD)

        conn.fetchval.assert_awaited_once()
        sql = conn.fetchval.await_args.args[0]
        assert " ".join(sql.split()) == _ALTER_ROLE_SQL

    async def test_migrate_set_password_lets_the_server_quote_identifier_and_literal(
        self,
    ) -> None:
        """format() with %I for the role and %L for the verifier, both bound as $n::text."""
        conn = _connection()

        await migrate_mod.set_runtime_role_password(conn, _ROLE_PASSWORD)

        sql = conn.fetchval.await_args.args[0]
        for fragment in ("format(", "%I", "%L", "$1::text", "$2::text"):
            assert fragment in sql

    @pytest.mark.parametrize("attribute", _ROLE_ATTRIBUTES)
    async def test_migrate_set_password_statement_pins_role_attribute(self, attribute: str) -> None:
        """LOGIN and every NO* attribute are in the statement; no un-negated privilege."""
        conn = _connection()

        await migrate_mod.set_runtime_role_password(conn, _ROLE_PASSWORD)

        sql = conn.fetchval.await_args.args[0]
        assert re.search(rf"\b{attribute}\b", sql)
        if attribute.startswith("NO"):
            assert re.search(rf"\b{attribute[2:]}\b", sql) is None

    async def test_migrate_set_password_binds_role_name_and_verifier(self) -> None:
        """The parameters are ("admino_app", <SCRAM verifier of the password, 4096 rounds>)."""
        conn = _connection()

        await migrate_mod.set_runtime_role_password(conn, _ROLE_PASSWORD)

        args = conn.fetchval.await_args.args
        assert len(args) == 3
        assert args[1] == _RUNTIME_ROLE
        parsed = _parse_verifier(args[2])
        assert parsed.iterations == 4096
        assert args[2] == _expected_verifier(_ROLE_PASSWORD, parsed.salt, 4096)

    async def test_migrate_set_password_executes_exactly_what_the_server_returned(
        self,
    ) -> None:
        """execute() runs the format() result verbatim, once, after the fetchval."""
        conn = _connection()

        await migrate_mod.set_runtime_role_password(conn, _ROLE_PASSWORD)

        conn.execute.assert_awaited_once_with(_FAKE_STATEMENT)
        names = [name for name, _args, _kwargs in conn.mock_calls]
        assert names.index("fetchval") < names.index("execute")

    async def test_migrate_set_password_plaintext_never_reaches_the_connection(self) -> None:
        """No argument of any call on the connection contains the plaintext password."""
        conn = _connection()

        await migrate_mod.set_runtime_role_password(conn, _ROLE_PASSWORD)

        values = _all_call_values(conn)
        assert len(conn.mock_calls) >= 2
        for value in values:
            assert _ROLE_PASSWORD not in value
            assert quote_plus(_ROLE_PASSWORD) not in value


# ---------------------------------------------------------------------------
# migrate()
# ---------------------------------------------------------------------------

_OWNER_DSN: Final = "postgresql://admino:owner-dsn-pw@postgres:5432/admino"


@dataclass
class _Deps:
    """The patched database functions, the pool and connection, and the call order."""

    pool: MagicMock
    conn: MagicMock
    init_pool: AsyncMock
    run_migrations: AsyncMock
    close_pool: AsyncMock
    events: list[str] = field(default_factory=list)


def _recorder(events: list[str], name: str) -> Callable[..., Any]:
    """A side_effect that logs ``name`` and lets the mock return its return_value."""

    def _record(*_args: Any, **_kwargs: Any) -> Any:
        events.append(name)
        return DEFAULT

    return _record


def _raiser(events: list[str], name: str, error: BaseException) -> Callable[..., Any]:
    """A side_effect that logs ``name`` and raises ``error``."""

    def _raise(*_args: Any, **_kwargs: Any) -> Any:
        events.append(name)
        raise error

    return _raise


@pytest.fixture()
def deps(mock_pool: MagicMock) -> Iterator[_Deps]:
    """Patch ``admino.database``'s init_pool/run_migrations/close_pool and record the order.

    init_pool returns ``mock_pool``; its connection's fetchval returns ``_FAKE_STATEMENT``.
    """
    events: list[str] = []
    conn = mock_pool._mock_conn
    conn.fetchval = AsyncMock(
        return_value=_FAKE_STATEMENT, side_effect=_recorder(events, "fetchval")
    )
    conn.execute = AsyncMock(side_effect=_recorder(events, "execute"))
    init_pool = AsyncMock(return_value=mock_pool, side_effect=_recorder(events, "init_pool"))
    run_migrations = AsyncMock(side_effect=_recorder(events, "run_migrations"))
    close_pool = AsyncMock(side_effect=_recorder(events, "close_pool"))
    with (
        patch.object(db_mod, "init_pool", init_pool),
        patch.object(db_mod, "run_migrations", run_migrations),
        patch.object(db_mod, "close_pool", close_pool),
    ):
        yield _Deps(
            pool=mock_pool,
            conn=conn,
            init_pool=init_pool,
            run_migrations=run_migrations,
            close_pool=close_pool,
            events=events,
        )


class TestMigrate:
    """migrate(): owner pool (1 connection) → migrations → runtime password → close."""

    async def test_migrate_opens_a_single_connection_pool_with_the_owner_dsn(
        self, deps: _Deps
    ) -> None:
        """init_pool(owner_dsn, min_size=1, max_size=1), once."""
        await migrate_mod.migrate(_OWNER_DSN, _APP_PASSWORD)

        deps.init_pool.assert_awaited_once()
        assert _bound(_INIT_POOL_SIGNATURE, deps.init_pool.await_args) == [_OWNER_DSN, 1, 1]

    async def test_migrate_runs_migrations_on_the_owner_pool(self, deps: _Deps) -> None:
        """run_migrations() gets the pool init_pool returned."""
        await migrate_mod.migrate(_OWNER_DSN, _APP_PASSWORD)

        deps.run_migrations.assert_awaited_once()
        assert _bound(_RUN_MIGRATIONS_SIGNATURE, deps.run_migrations.await_args) == [deps.pool]

    async def test_migrate_applies_migrations_before_setting_the_password(
        self, deps: _Deps
    ) -> None:
        """Order: init_pool, run_migrations (0018 creates the role), ALTER ROLE, close_pool."""
        await migrate_mod.migrate(_OWNER_DSN, _APP_PASSWORD)

        assert deps.events == ["init_pool", "run_migrations", "fetchval", "execute", "close_pool"]

    async def test_migrate_sets_the_password_on_an_acquired_connection(self, deps: _Deps) -> None:
        """set_runtime_role_password(conn, runtime_password) on a connection from the pool."""
        fake_set = AsyncMock()
        with patch.object(migrate_mod, "set_runtime_role_password", fake_set):
            await migrate_mod.migrate(_OWNER_DSN, _APP_PASSWORD)

        fake_set.assert_awaited_once()
        assert _bound(_SET_PASSWORD_SIGNATURE, fake_set.await_args) == [deps.conn, _APP_PASSWORD]
        deps.pool.acquire.assert_called_once()

    async def test_migrate_password_statement_carries_a_verifier_of_the_runtime_password(
        self, deps: _Deps
    ) -> None:
        """End to end: the format() parameters are admino_app + the runtime password's verifier."""
        await migrate_mod.migrate(_OWNER_DSN, _APP_PASSWORD)

        args = deps.conn.fetchval.await_args.args
        parsed = _parse_verifier(args[2])
        assert args[1] == _RUNTIME_ROLE
        assert args[2] == _expected_verifier(_APP_PASSWORD, parsed.salt, parsed.iterations)
        deps.conn.execute.assert_awaited_once_with(_FAKE_STATEMENT)

    async def test_migrate_closes_the_pool_on_success(self, deps: _Deps) -> None:
        """close_pool() is awaited exactly once after a successful run."""
        await migrate_mod.migrate(_OWNER_DSN, _APP_PASSWORD)

        deps.close_pool.assert_awaited_once()

    async def test_migrate_migration_failure_propagates_closes_pool_and_sets_no_password(
        self, deps: _Deps
    ) -> None:
        """run_migrations() raises → the error propagates, no ALTER ROLE, pool closed."""
        error = asyncpg.SyntaxOrAccessError("migration failed")
        deps.run_migrations.side_effect = _raiser(deps.events, "run_migrations", error)

        with pytest.raises(asyncpg.SyntaxOrAccessError):
            await migrate_mod.migrate(_OWNER_DSN, _APP_PASSWORD)

        assert deps.events == ["init_pool", "run_migrations", "close_pool"]
        deps.conn.fetchval.assert_not_awaited()
        deps.conn.execute.assert_not_awaited()

    @pytest.mark.parametrize("failing_step", ["fetchval", "execute"])
    async def test_migrate_password_failure_propagates_and_closes_pool(
        self, deps: _Deps, failing_step: str
    ) -> None:
        """The format() query or the ALTER ROLE raises → the error propagates, pool closed."""
        error = asyncpg.InsufficientPrivilegeError("permission denied to alter role")
        getattr(deps.conn, failing_step).side_effect = _raiser(deps.events, failing_step, error)

        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await migrate_mod.migrate(_OWNER_DSN, _APP_PASSWORD)

        deps.close_pool.assert_awaited_once()
        assert deps.events[-1] == "close_pool"

    async def test_migrate_pool_failure_propagates_and_runs_nothing(self, deps: _Deps) -> None:
        """init_pool() raises (database unreachable) → the error propagates, nothing runs."""
        deps.init_pool.side_effect = _raiser(
            deps.events, "init_pool", ConnectionRefusedError("refused")
        )

        with pytest.raises(ConnectionRefusedError):
            await migrate_mod.migrate(_OWNER_DSN, _APP_PASSWORD)

        deps.run_migrations.assert_not_awaited()
        deps.conn.fetchval.assert_not_awaited()


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------

_LEAKY_ERRORS: Final[tuple[type[BaseException], ...]] = (
    asyncpg.InvalidPasswordError,
    asyncpg.InsufficientPrivilegeError,
    asyncpg.PostgresError,
    ConnectionRefusedError,
    OSError,
    TimeoutError,
    ValueError,
    RuntimeError,
)


class TestMainRefusesUnsafeConfiguration:
    """main() validates everything before connecting: exit 1, nothing connects, no leak."""

    @pytest.mark.parametrize("owner_password", [None, ""], ids=["unset", "empty"])
    def test_migrate_main_without_owner_password_returns_1_and_connects_nothing(
        self,
        main_env: pytest.MonkeyPatch,
        run_main: Callable[..., _MainRun],
        owner_password: str | None,
    ) -> None:
        """PG_PASSWORD unset/empty → 1; migrate() and init_pool() never called."""
        main_env.delenv("PG_PASSWORD")
        if owner_password is not None:
            main_env.setenv("PG_PASSWORD", owner_password)

        run = run_main()

        assert run.code == 1
        run.migrate.assert_not_called()
        run.init_pool.assert_not_called()

    def test_migrate_main_without_owner_password_logs_error_naming_pg_password(
        self, main_env: pytest.MonkeyPatch, run_main: Callable[..., _MainRun]
    ) -> None:
        """The error names PG_PASSWORD and leaks nothing."""
        main_env.delenv("PG_PASSWORD")

        run = run_main()

        assert re.search(r"\bPG_PASSWORD\b", run.output)
        _assert_no_secrets(run.output, _APP_PASSWORD)

    def test_migrate_main_with_owner_user_equal_to_runtime_role_returns_1(
        self, main_env: pytest.MonkeyPatch, run_main: Callable[..., _MainRun]
    ) -> None:
        """PG_USER=admino_app → 1 (the owner can't be the runtime role); nothing connects."""
        main_env.setenv("PG_USER", _RUNTIME_ROLE)

        run = run_main()

        assert run.code == 1
        run.migrate.assert_not_called()
        run.init_pool.assert_not_called()
        assert "PG_USER" in run.output
        _assert_no_secrets(run.output, _OWNER_PASSWORD, _APP_PASSWORD)

    @pytest.mark.parametrize(
        "app_password",
        [
            None,
            "",
            "App-Runtime-" + chr(0xE4) + "-Pw-8823",
            "App-Runtime-" + chr(0x1F600) + "-Pw-8823",
            "App-Runtime-" + chr(0x0A) + "-Pw-8823",
            "App-Runtime-" + chr(0x7F) + "-Pw-8823",
            _OWNER_PASSWORD,
        ],
        ids=["unset", "empty", "non-ascii", "emoji", "newline", "del", "equal-to-owner"],
    )
    def test_migrate_main_with_invalid_app_password_returns_1_and_connects_nothing(
        self,
        main_env: pytest.MonkeyPatch,
        run_main: Callable[..., _MainRun],
        app_password: str | None,
    ) -> None:
        """A missing, non-printable-ASCII or owner-equal PG_APP_PASSWORD → 1, nothing runs.

        The log names PG_APP_PASSWORD (the check's fixed message) and leaks neither
        password.
        """
        main_env.delenv("PG_APP_PASSWORD")
        if app_password is not None:
            main_env.setenv("PG_APP_PASSWORD", app_password)

        run = run_main()

        assert run.code == 1
        run.migrate.assert_not_called()
        run.init_pool.assert_not_called()
        assert "PG_APP_PASSWORD" in run.output
        _assert_no_secrets(run.output, _OWNER_PASSWORD, *([app_password] if app_password else []))
        assert "App-Runtime-" not in run.output


class TestMainRunsMigrate:
    """main() with a valid configuration runs migrate(owner_dsn, app_password)."""

    def test_migrate_main_happy_path_returns_0_and_migrates_with_owner_dsn(
        self, main_env: pytest.MonkeyPatch, run_main: Callable[..., _MainRun]
    ) -> None:
        """Exit 0; migrate() awaited once with (owner DSN, PG_APP_PASSWORD verbatim)."""
        run = run_main()

        assert run.code == 0
        run.migrate.assert_awaited_once()
        assert _bound(_MIGRATE_SIGNATURE, run.migrate.await_args) == [
            _expected_owner_dsn(),
            _APP_PASSWORD,
        ]

    def test_migrate_main_passes_the_overridden_owner_dsn(
        self, main_env: pytest.MonkeyPatch, run_main: Callable[..., _MainRun]
    ) -> None:
        """PG_HOST/PG_PORT/PG_USER/PG_DATABASE end up in the owner DSN migrate() gets."""
        main_env.setenv("PG_HOST", "postgres")
        main_env.setenv("PG_PORT", "6543")
        main_env.setenv("PG_USER", "dbowner")
        main_env.setenv("PG_DATABASE", "admino_prod")

        run = run_main()

        assert run.code == 0
        assert _bound(_MIGRATE_SIGNATURE, run.migrate.await_args)[0] == _expected_owner_dsn(
            user="dbowner", host="postgres", port="6543", database="admino_prod"
        )

    def test_migrate_main_success_logs_an_info_line_without_secrets(
        self, main_env: pytest.MonkeyPatch, run_main: Callable[..., _MainRun]
    ) -> None:
        """Success writes an INFO line (text format by default) and no secret."""
        run = run_main()

        assert run.code == 0
        assert any(re.search(r"\bINFO\b", line) for line in run.output.splitlines())
        _assert_no_secrets(run.output, _OWNER_PASSWORD, _APP_PASSWORD)

    def test_migrate_main_log_level_from_env_is_honoured(
        self, main_env: pytest.MonkeyPatch, run_main: Callable[..., _MainRun]
    ) -> None:
        """LOG_LEVEL=ERROR → a successful run writes no INFO line."""
        main_env.setenv("LOG_LEVEL", "ERROR")

        run = run_main()

        assert run.code == 0
        assert not any(re.search(r"\bINFO\b", line) for line in run.output.splitlines())

    @pytest.mark.parametrize("error_type", _LEAKY_ERRORS, ids=lambda t: t.__name__)
    def test_migrate_main_migrate_failure_returns_1_and_logs_type_only(
        self,
        main_env: pytest.MonkeyPatch,
        run_main: Callable[..., _MainRun],
        error_type: type[BaseException],
    ) -> None:
        """A database/OS/timeout (or value/runtime) error → exit 1, the log names its type.

        The exception's message (a DSN with the owner password, a verifier, the app
        password) never reaches the log; nor does a traceback. Checked at DEBUG.
        """
        main_env.setenv("LOG_LEVEL", "DEBUG")

        run = run_main(migrate_error=error_type(_LEAKY_DETAIL))

        assert run.code == 1
        assert error_type.__name__ in run.output
        assert "ERROR" in run.output
        _assert_no_secrets(run.output, _OWNER_PASSWORD, _APP_PASSWORD)

    def test_migrate_main_text_format_by_default(
        self, main_env: pytest.MonkeyPatch, run_main: Callable[..., _MainRun]
    ) -> None:
        """Without LOG_FORMAT every line is admino's TextFormatter line."""
        run = run_main(migrate_error=asyncpg.InvalidPasswordError(_LEAKY_DETAIL))

        lines = [line for line in run.output.splitlines() if line]
        assert lines
        for line in lines:
            assert _TEXT_LINE_RE.match(line)

    def test_migrate_main_json_format_with_log_format_json(
        self, main_env: pytest.MonkeyPatch, run_main: Callable[..., _MainRun]
    ) -> None:
        """LOG_FORMAT=json → every line is a JsonFormatter object; the failure is an ERROR."""
        main_env.setenv("LOG_FORMAT", "json")

        run = run_main(migrate_error=asyncpg.InvalidPasswordError(_LEAKY_DETAIL))

        entries = [json.loads(line) for line in run.output.splitlines() if line]
        assert entries
        for entry in entries:
            assert {"ts", "level", "logger", "message", "request_id"} <= set(entry)
        assert any(entry["level"] == "ERROR" for entry in entries)
        assert "InvalidPasswordError" in run.output
        _assert_no_secrets(run.output, _OWNER_PASSWORD, _APP_PASSWORD)

    def test_migrate_main_real_migrate_logs_no_secret_or_statement(
        self,
        main_env: pytest.MonkeyPatch,
        deps: _Deps,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """End to end at DEBUG (database functions mocked): exit 0, no secret, no verifier.

        The mocked server returns a statement that contains a verifier, so a log line
        echoing the statement or the format() parameters is caught.
        """
        main_env.setenv("LOG_LEVEL", "DEBUG")

        capsys.readouterr()
        with restored_logging():
            code = migrate_mod.main()
        captured = capsys.readouterr()

        assert code == 0
        assert deps.events == ["init_pool", "run_migrations", "fetchval", "execute", "close_pool"]
        assert _bound(_INIT_POOL_SIGNATURE, deps.init_pool.await_args)[0] == (_expected_owner_dsn())
        _assert_no_secrets(captured.out + captured.err, _OWNER_PASSWORD, _APP_PASSWORD)


# ---------------------------------------------------------------------------
# Entry point and source checks
# ---------------------------------------------------------------------------


def _migrate_tree() -> ast.Module:
    """The parsed source of admino/migrate.py."""
    return ast.parse(_MIGRATE_SOURCE_PATH.read_text(encoding="utf-8"))


_SQL_KEYWORDS: Final = re.compile(
    r"\b(?:SELECT|ALTER|GRANT|REVOKE|CREATE|INSERT|UPDATE|DELETE|DROP|EXECUTE|ROLE)\b"
    r"|\bPASSWORD\s+'|\bformat\(",
)


def _constant_text(node: ast.AST) -> str:
    """The literal string parts of a str constant or an f-string, else ""."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            part.value
            for part in node.values
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
        )
    return ""


def _static(node: ast.AST) -> bool:
    """A str constant, or a ``+`` of str constants only (no runtime value)."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _static(node.left) and _static(node.right)
    return False


class TestEntryPointAndSource:
    """``python -m admino.migrate`` and the module's security constraints."""

    def test_migrate_module_runs_main_as_script(self) -> None:
        """The module ends with ``if __name__ == "__main__": sys.exit(main())``."""
        source = _MIGRATE_SOURCE_PATH.read_text(encoding="utf-8")

        assert re.search(
            r"""^if __name__ == ["']__main__["']:\s*\n\s+sys\.exit\(main\(\)\)""",
            source,
            re.MULTILINE,
        )

    def test_migrate_python_m_without_owner_password_exits_1(
        self, clean_env: pytest.MonkeyPatch, connection_guards: dict[str, AsyncMock]
    ) -> None:
        """Running the module as __main__ with no PG_PASSWORD exits with status 1, unconnected."""
        clean_env.setenv("PG_APP_PASSWORD", _APP_PASSWORD)

        with (
            restored_logging(),
            warnings.catch_warnings(),
            pytest.raises(SystemExit) as raised,
        ):
            warnings.simplefilter("ignore", RuntimeWarning)
            runpy.run_module("admino.migrate", run_name="__main__")

        assert raised.value.code == 1
        connection_guards["create_pool"].assert_not_called()
        connection_guards["connect"].assert_not_called()

    def test_migrate_source_has_no_dynamic_code_or_processes(self) -> None:
        """No eval/exec/compile/__import__, no importlib/subprocess, no os.system/popen."""
        tree = _migrate_tree()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec", "compile", "__import__"}
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in {"system", "popen", "execv", "execve", "spawnv"}
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in {"importlib", "subprocess"}
            if isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in {"importlib", "subprocess"}

    def test_migrate_source_has_no_shell_true(self) -> None:
        """``shell=True`` appears nowhere in the module."""
        source = _MIGRATE_SOURCE_PATH.read_text(encoding="utf-8")

        assert re.search(r"shell\s*=\s*True", source) is None

    def test_migrate_source_builds_no_sql_in_python(self) -> None:
        """No f-string, %-format, ``.format()`` or concatenation produces SQL text.

        The only dynamic SQL is the statement the SERVER's format() returns.
        """
        for node in ast.walk(_migrate_tree()):
            if isinstance(node, ast.JoinedStr):
                assert not _SQL_KEYWORDS.search(_constant_text(node))
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                assert not _SQL_KEYWORDS.search(_constant_text(node.left))
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and not _static(node):
                for operand in (node.left, node.right):
                    assert not _SQL_KEYWORDS.search(_constant_text(operand))
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
            ):
                receiver = node.func.value
                assert not _SQL_KEYWORDS.search(_constant_text(receiver))
                if isinstance(receiver, ast.Name):
                    assert "sql" not in receiver.id.lower()
