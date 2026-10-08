"""Old-to-new compatibility of admino's cryptography use across a ``cryptography`` upgrade (GH-289).

GH-289 moves ``cryptography`` from 44.0.2 to a newer release. Two kinds of stored
data were written under the old version and must keep working under the new one:
the Fernet ciphertext of OAuth refresh tokens (``oauth_tokens``) and the Argon2id
PHC strings of user passwords (``users.password_hash``).

What these tests pin down:
- A refresh token encrypted by ``oauth.encrypt_refresh_token`` under 44.0.2 still
  decrypts through ``oauth.decrypt_refresh_token``; with another key, or with one
  ciphertext character changed, it raises ``OAuthError`` (negative controls).
- A password hashed by ``passwords.hash_password`` under 44.0.2 still verifies
  through ``passwords.verify_password``, a wrong password doesn't, and
  ``passwords.needs_rehash`` keeps it (it was made with today's parameters, which
  ``parse_phc`` confirms field by field).
- A guard: ``uv.lock`` locks a ``cryptography`` strictly newer than the fixture's
  generating version, so these tests keep exercising the old-to-new path. CI and
  the Docker image install from ``uv.lock``.

The fixture ``tests/fixtures/cryptography_44_0_2_compat.json`` is data, made once
(2026-10-08) and committed; it records its generating versions (cryptography
44.0.2, Python 3.12.8). It was produced by a throwaway script run with an
interpreter that had cryptography 44.0.2 installed and ``PYTHONPATH=src``. The
script asserted ``cryptography.__version__ == "44.0.2"`` first, generated a fresh
key with ``Fernet.generate_key()`` and set it as ``OAUTH_ENCRYPTION_KEY``, then
called ``admino.oauth.encrypt_refresh_token`` on an obviously fake plaintext and
``admino.passwords.hash_password`` on an obviously fake password. It checked that
both round-trip on 44.0.2 and wrote the versions, the date, the key, the
plaintext, the token, the password and the PHC string as JSON. Do NOT regenerate
it with a newer cryptography: a fixture made by the new version proves nothing
about data written by the old one. A future upgrade adds a new fixture next to
this one.

On cryptography 44.0.2 the compatibility tests pass by construction; they mean
something once the lock moves past the fixture's version, which the guard
enforces.

Security notes:
- The fixture's Fernet key, refresh token and password are test-only values that
  protect nothing; no real credential is in this file or the fixture.
- Tests go through the production functions only; nothing is logged.
"""

from __future__ import annotations

import base64
import functools
import json
import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import pytest
from cryptography.fernet import Fernet

from admino import oauth, passwords
from admino.oauth import GOOGLE_SCOPES, OAuthError, OAuthToken

_TESTS_DIR: Final = Path(__file__).resolve().parent
_REPO_ROOT: Final = _TESTS_DIR.parent
_FIXTURE_PATH: Final = _TESTS_DIR / "fixtures" / "cryptography_44_0_2_compat.json"
_FIXTURE_GENERATOR_VERSION: Final = "44.0.2"
_RELEASE_RE: Final = re.compile(r"[0-9]+(?:\.[0-9]+)*")


@functools.cache
def _fixture() -> dict[str, Any]:
    """The committed compatibility fixture, parsed once."""
    data = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _fernet_value(name: str) -> str:
    """One string of the fixture's ``fernet`` section (key, plaintext, token)."""
    value = _fixture()["fernet"][name]
    assert isinstance(value, str)
    return value


def _argon2id_value(name: str) -> str:
    """One string of the fixture's ``argon2id`` section (password, phc)."""
    value = _fixture()["argon2id"][name]
    assert isinstance(value, str)
    return value


def _stored(encrypted: str) -> OAuthToken:
    """An OAuthToken as loaded from the database, carrying ``encrypted`` as its ciphertext."""
    now = datetime.now(UTC)
    return OAuthToken(
        provider="google",
        scopes=list(GOOGLE_SCOPES),
        encrypted_refresh_token=encrypted,
        email=None,
        created_at=now,
        last_refreshed_at=now,
    )


def _tampered(token: str) -> str:
    """The token with one character in the middle of its ciphertext replaced.

    The replacement comes from the urlsafe base64 alphabet, so the result is still
    well-formed base64 of the same length; only the authenticated payload differs.
    """
    index = len(token) // 2
    replacement = "A" if token[index] != "A" else "B"
    return token[:index] + replacement + token[index + 1 :]


def _release(version: str) -> tuple[int, ...]:
    """The numeric release segments of a version string, trailing zeros dropped.

    ``"50.0.2"`` -> ``(50, 0, 2)``; ``"44.0.2.0"`` compares equal to ``"44.0.2"``.
    """
    match = _RELEASE_RE.match(version)
    assert match is not None, f"not a release version: {version!r}"
    parts = [int(part) for part in match.group(0).split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


# ---------------------------------------------------------------------------
# The fixture itself
# ---------------------------------------------------------------------------


def test_cryptography_compat_fixture_records_44_0_2_as_generator() -> None:
    """The fixture says it was made under cryptography 44.0.2 (the old version)."""
    assert _fixture()["generated_with"]["cryptography"] == _FIXTURE_GENERATOR_VERSION


# ---------------------------------------------------------------------------
# Fernet: OAuth refresh tokens encrypted under 44.0.2
# ---------------------------------------------------------------------------


def test_cryptography_compat_fernet_token_from_44_0_2_decrypts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OAUTH_ENCRYPTION_KEY", _fernet_value("key"))

    plaintext = oauth.decrypt_refresh_token(_stored(_fernet_value("token")))

    assert plaintext == _fernet_value("plaintext")


def test_cryptography_compat_fernet_token_with_wrong_key_raises_oauth_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    other_key = Fernet.generate_key().decode("ascii")
    assert other_key != _fernet_value("key")
    monkeypatch.setenv("OAUTH_ENCRYPTION_KEY", other_key)

    with pytest.raises(OAuthError, match="Failed to decrypt"):
        oauth.decrypt_refresh_token(_stored(_fernet_value("token")))


def test_cryptography_compat_fernet_tampered_token_raises_oauth_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = _fernet_value("token")
    tampered = _tampered(token)
    assert base64.urlsafe_b64decode(tampered) != base64.urlsafe_b64decode(token)
    monkeypatch.setenv("OAUTH_ENCRYPTION_KEY", _fernet_value("key"))

    with pytest.raises(OAuthError, match="Failed to decrypt"):
        oauth.decrypt_refresh_token(_stored(tampered))


# ---------------------------------------------------------------------------
# Argon2id: password hashes made under 44.0.2
# ---------------------------------------------------------------------------


def test_cryptography_compat_argon2id_hash_from_44_0_2_verifies() -> None:
    assert passwords.verify_password(_argon2id_value("password"), _argon2id_value("phc")) is True


def test_cryptography_compat_argon2id_wrong_password_does_not_verify() -> None:
    password = _argon2id_value("password")
    wrong = password[:-1] + ("X" if password[-1] != "X" else "Y")

    assert passwords.verify_password(wrong, _argon2id_value("phc")) is False


def test_cryptography_compat_argon2id_hash_from_44_0_2_needs_no_rehash() -> None:
    assert passwords.needs_rehash(_argon2id_value("phc")) is False


def test_cryptography_compat_argon2id_hash_from_44_0_2_has_current_parameters() -> None:
    parsed = passwords.parse_phc(_argon2id_value("phc"))

    assert (
        parsed.memory_cost,
        parsed.iterations,
        parsed.lanes,
        len(parsed.salt),
        len(parsed.digest),
    ) == (
        passwords.ARGON2_MEMORY_COST_KIB,
        passwords.ARGON2_ITERATIONS,
        passwords.ARGON2_LANES,
        passwords.ARGON2_SALT_BYTES,
        passwords.ARGON2_HASH_BYTES,
    )


# ---------------------------------------------------------------------------
# Guard: the lock moves past the fixture's version
# ---------------------------------------------------------------------------


def test_cryptography_compat_uv_lock_locks_newer_cryptography_than_fixture() -> None:
    """uv.lock's cryptography is strictly newer than the fixture's generating version.

    Without this, a lock left at (or moved back to) 44.0.2 would turn the tests
    above into a same-version round trip.
    """
    lock = tomllib.loads((_REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    locked = [
        str(package["version"])
        for package in lock.get("package", [])
        if package.get("name") == "cryptography"
    ]
    generator = str(_fixture()["generated_with"]["cryptography"])

    assert locked, "uv.lock locks no cryptography package"
    assert [v for v in locked if _release(v) <= _release(generator)] == []
