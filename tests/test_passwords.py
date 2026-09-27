"""Tests for admino.passwords — Argon2id password hashing and the password policy (GH-149).

Passwords are hashed with Argon2id from the already-pinned ``cryptography``
package and stored as PHC strings (``$argon2id$v=19$m=…,t=…,p=…$salt$hash``,
standard base64 without padding). The policy rejects passwords shorter than 12
or longer than 128 characters, passwords in the bundled common-password list
(SecLists' NCSC top 100k, loaded once) and passwords equal to the email.

What these tests pin down:
- ``encode_phc`` / ``parse_phc`` round-trip, and ``parse_phc`` rejects every
  malformed or out-of-range string with a ValueError that never echoes it.
- ``hash_password`` uses the documented parameters (m=19456 KiB, t=2, p=1), a
  fresh 16-byte salt per call and a 32-byte Argon2id digest.
- ``verify_password`` verifies with the stored parameters (older hashes, and a
  reference argon2-cffi hash, still verify) and returns False instead of raising
  for a wrong password or a malformed stored string.
- ``needs_rehash`` is True exactly when the stored parameters differ from the
  current ones (or the string doesn't parse).
- The policy edges 11/12/128/129 (counted in characters), list hits
  (casefolded), the equals-email rule and the order of the checks.
- ``common_passwords()`` loads the bundled file once and caches it.

Real Argon2 calls cost ~200 ms at the current parameters, so hashes are built
once per module and cheap parameters are used where only behavior matters.

Security notes:
- Error messages never contain the password, the email or the stored hash.
- An out-of-range stored hash (e.g. absurd t) is refused before any Argon2 work.
"""

from __future__ import annotations

import base64
import builtins
import io
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from admino import passwords
from admino.passwords import (
    ARGON2_HASH_BYTES,
    ARGON2_ITERATIONS,
    ARGON2_LANES,
    ARGON2_MEMORY_COST_KIB,
    ARGON2_SALT_BYTES,
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PasswordPolicyError,
    check_password_policy,
    common_passwords,
    encode_phc,
    hash_password,
    needs_rehash,
    parse_phc,
    verify_password,
)

if TYPE_CHECKING:
    from collections.abc import Callable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PASSWORD = "correct horse battery staple"
_WRONG_PASSWORD = "correct horse battery stapler"
_CURRENT_PREFIX = "$argon2id$v=19$m=19456,t=2,p=1$"
_LIST_PATH = Path(passwords.__file__).resolve().parent / "resources" / "common_passwords.txt"

# The argon2-cffi documentation's example: PasswordHasher().hash("correct horse
# battery staple") with its defaults (m=65536, t=3, p=4). A hash written by the
# reference implementation must verify here too.
_REFERENCE_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$MIIRqgvgQbgj220jfp0MPA"
    "$YfwJSVjtjSU0zzV/P3S9nnQ/USre2wvJMjfCIjrTQbg"
)

# The OWASP alternative parameter set (m=12 MiB, t=3, p=1): an "older" hash.
_OLD_MEMORY_COST = 12288
_OLD_ITERATIONS = 3
_OLD_LANES = 1

# Bytes whose standard base64 contains '+' and '/', so the alphabet is pinned.
_SALT = bytes([0xFB, 0xEF, 0xFF] * 5 + [0xFE])
_DIGEST = bytes([0xFB, 0xFF, 0xBF] * 10 + [0x3E, 0x3F])

_MARKER = "Zx7SECRETmarker"  # appears in malformed inputs; must never be echoed

# Distinct, non-common passwords for the policy edges (length in characters).
_BASE = "Zq8#vT2!mL4xR7@pWc5&"


def _b64(data: bytes) -> str:
    """Standard base64 without padding (the PHC encoding)."""
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _phc(
    *,
    algorithm: str = "argon2id",
    version: str = "v=19",
    params: str = "m=19456,t=2,p=1",
    salt: str | None = None,
    digest: str | None = None,
) -> str:
    """Build a PHC-looking string field by field (for the malformed cases)."""
    salt_b64 = _b64(_SALT) if salt is None else salt
    digest_b64 = _b64(_DIGEST) if digest is None else digest
    return f"${algorithm}${version}${params}${salt_b64}${digest_b64}"


def _argon2id_digest(
    password: str, salt: bytes, *, memory_cost: int, iterations: int, lanes: int, length: int = 32
) -> bytes:
    """Compute an Argon2id digest independently of admino (the reference for the tests)."""
    kdf = Argon2id(
        salt=salt,
        length=length,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost,
    )
    return kdf.derive(password.encode("utf-8"))


def _password_of_length(length: int) -> str:
    """A distinctive, non-common password of exactly ``length`` characters."""
    return (_BASE * (length // len(_BASE) + 1))[:length]


# ---------------------------------------------------------------------------
# Module-scoped hashes (each costs one real Argon2 call)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def current_hash() -> str:
    """One hash of _PASSWORD with the current parameters."""
    return hash_password(_PASSWORD)


@pytest.fixture(scope="module")
def old_hash() -> str:
    """A hash of _PASSWORD with older (OWASP alternative) parameters, built independently."""
    salt = bytes(range(16))
    digest = _argon2id_digest(
        _PASSWORD,
        salt,
        memory_cost=_OLD_MEMORY_COST,
        iterations=_OLD_ITERATIONS,
        lanes=_OLD_LANES,
    )
    return encode_phc(
        memory_cost=_OLD_MEMORY_COST,
        iterations=_OLD_ITERATIONS,
        lanes=_OLD_LANES,
        salt=salt,
        digest=digest,
    )


# ---------------------------------------------------------------------------
# 1. Documented parameters
# ---------------------------------------------------------------------------


class TestPasswordParameters:
    """The Argon2id parameters and the policy bounds are the documented values."""

    def test_passwords_argon2_parameters_are_the_owasp_baseline(self) -> None:
        """m = 19 MiB (19456 KiB), t = 2, p = 1."""
        assert (ARGON2_MEMORY_COST_KIB, ARGON2_ITERATIONS, ARGON2_LANES) == (19456, 2, 1)

    def test_passwords_salt_and_digest_sizes(self) -> None:
        """A 16-byte salt and a 32-byte digest."""
        assert (ARGON2_SALT_BYTES, ARGON2_HASH_BYTES) == (16, 32)

    def test_passwords_policy_length_bounds(self) -> None:
        """Passwords are 12 to 128 characters long."""
        assert (MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH) == (12, 128)


# ---------------------------------------------------------------------------
# 2. PHC encoding and parsing
# ---------------------------------------------------------------------------


class TestEncodePhc:
    """encode_phc writes the PHC string with standard, unpadded base64."""

    def test_passwords_encode_phc_writes_the_phc_format(self) -> None:
        """$argon2id$v=19$m=<m>,t=<t>,p=<p>$<salt>$<hash>."""
        encoded = encode_phc(memory_cost=19456, iterations=2, lanes=1, salt=_SALT, digest=_DIGEST)

        assert encoded == f"$argon2id$v=19$m=19456,t=2,p=1${_b64(_SALT)}${_b64(_DIGEST)}"

    def test_passwords_encode_phc_uses_the_standard_alphabet(self) -> None:
        """'+' and '/' (standard base64), never the URL-safe '-' and '_'."""
        encoded = encode_phc(memory_cost=19456, iterations=2, lanes=1, salt=_SALT, digest=_DIGEST)
        salt_and_digest = encoded.rsplit("$", 2)[1:]

        assert any("+" in part or "/" in part for part in salt_and_digest)
        assert not any("-" in part or "_" in part for part in salt_and_digest)

    def test_passwords_encode_phc_has_no_padding(self) -> None:
        """PHC base64 carries no '=' padding (16 and 32 bytes would otherwise be padded)."""
        encoded = encode_phc(memory_cost=19456, iterations=2, lanes=1, salt=_SALT, digest=_DIGEST)

        assert "=" not in encoded.rsplit("$", 2)[1]
        assert "=" not in encoded.rsplit("$", 2)[2]


class TestParsePhc:
    """parse_phc reads back what encode_phc writes."""

    @pytest.mark.parametrize(
        ("memory_cost", "iterations", "lanes", "salt", "digest"),
        [
            pytest.param(19456, 2, 1, _SALT, _DIGEST, id="current-params"),
            pytest.param(
                65536, 3, 4, bytes(range(16)), bytes(range(32)), id="argon2-cffi-defaults"
            ),
            pytest.param(12288, 3, 1, b"\x00" * 8, b"\xff" * 4, id="minimum-salt-and-digest"),
            pytest.param(8, 1, 1, bytes(range(20)), bytes(range(64)), id="long-salt-and-digest"),
        ],
    )
    def test_passwords_parse_phc_round_trips_encode_phc(
        self, memory_cost: int, iterations: int, lanes: int, salt: bytes, digest: bytes
    ) -> None:
        """Every field survives encode → parse unchanged."""
        encoded = encode_phc(
            memory_cost=memory_cost, iterations=iterations, lanes=lanes, salt=salt, digest=digest
        )

        parsed = parse_phc(encoded)

        assert (parsed.memory_cost, parsed.iterations, parsed.lanes) == (
            memory_cost,
            iterations,
            lanes,
        )
        assert (parsed.salt, parsed.digest) == (salt, digest)

    def test_passwords_parse_phc_reads_a_reference_hash(self) -> None:
        """A hash written by argon2-cffi parses: m=65536, t=3, p=4, 16-byte salt, 32-byte hash."""
        parsed = parse_phc(_REFERENCE_HASH)

        assert (parsed.memory_cost, parsed.iterations, parsed.lanes) == (65536, 3, 4)
        assert (len(parsed.salt), len(parsed.digest)) == (16, 32)

    def test_passwords_parse_phc_result_is_frozen(self) -> None:
        """The parsed hash can't be modified after parsing."""
        parsed = parse_phc(_phc())

        with pytest.raises((AttributeError, TypeError, ValueError)):
            parsed.memory_cost = 8  # type: ignore[misc]


# Malformed or out-of-range PHC strings: parse_phc raises ValueError for each.
_MALFORMED: list[Any] = [
    pytest.param(_phc(algorithm="argon2i"), id="argon2i"),
    pytest.param(_phc(algorithm="argon2d"), id="argon2d"),
    pytest.param(_phc(algorithm="ARGON2ID"), id="upper-case-algorithm"),
    pytest.param(_phc(algorithm="scrypt", params="ln=16,r=8,p=1"), id="scrypt"),
    pytest.param(f"$2b$12${_b64(_SALT)}{_b64(_DIGEST)}", id="bcrypt"),
    pytest.param(_phc(version="v=16"), id="version-16"),
    pytest.param(_phc(version="v=20"), id="version-20"),
    pytest.param(_phc(version="v=abc"), id="version-not-a-number"),
    pytest.param(f"$argon2id$m=19456,t=2,p=1${_b64(_SALT)}${_b64(_DIGEST)}", id="missing-version"),
    pytest.param(f"$argon2id$v=19$m=19456,t=2,p=1${_b64(_DIGEST)}", id="missing-salt"),
    pytest.param(f"$argon2id$v=19${_b64(_SALT)}${_b64(_DIGEST)}", id="missing-params"),
    pytest.param(_phc() + "$extra", id="extra-field"),
    pytest.param(
        "argon2id$v=19$m=19456,t=2,p=1$" + _b64(_SALT) + "$" + _b64(_DIGEST), id="no-lead"
    ),
    pytest.param(_phc(params="m=19456,t=2"), id="missing-p"),
    pytest.param(_phc(params="t=2,p=1"), id="missing-m"),
    pytest.param(_phc(params="m=19456,p=1"), id="missing-t"),
    pytest.param(_phc(params="m=abc,t=2,p=1"), id="m-not-an-int"),
    pytest.param(_phc(params="m=19456,t=2.5,p=1"), id="t-not-an-int"),
    pytest.param(_phc(params="m=19456,t=2,p=one"), id="p-not-an-int"),
    pytest.param(_phc(params="m=-19456,t=2,p=1"), id="m-negative"),
    pytest.param(_phc(params="m=7,t=2,p=1"), id="m-below-8-per-lane"),
    pytest.param(_phc(params="m=15,t=1,p=2"), id="m-below-8-times-p"),
    pytest.param(_phc(params="m=19456,t=0,p=1"), id="t-zero"),
    pytest.param(_phc(params="m=19456,t=2,p=0"), id="p-zero"),
    pytest.param(_phc(params="m=2097152,t=2,p=1"), id="m-above-1-GiB"),
    pytest.param(_phc(params="m=99999999999999999999,t=2,p=1"), id="m-absurd"),
    pytest.param(_phc(params="m=19456,t=1000,p=1"), id="t-absurd"),
    pytest.param(_phc(params="m=19456,t=2,p=1000"), id="p-absurd"),
    pytest.param(_phc(salt="sa*lt!!notbase64"), id="salt-invalid-chars"),
    pytest.param(_phc(salt=_b64(_SALT).replace("+", "-").replace("/", "_")), id="salt-urlsafe"),
    pytest.param(_phc(salt="AAAAAAAAAAAAA"), id="salt-impossible-length"),
    # Valid base64 with four junk characters inside: a lax decoder that drops
    # non-alphabet characters would accept these; a strict one refuses them.
    pytest.param(
        _phc(salt=_b64(bytes(range(12)))[:8] + "!!!!" + _b64(bytes(range(12)))[8:]),
        id="salt-junk-inside",
    ),
    pytest.param(
        _phc(salt=_b64(bytes(range(12)))[:8] + "-_-_" + _b64(bytes(range(12)))[8:]),
        id="salt-urlsafe-inside",
    ),
    pytest.param(
        _phc(digest=_b64(bytes(range(32)))[:20] + "    " + _b64(bytes(range(32)))[20:]),
        id="digest-spaces-inside",
    ),
    pytest.param(_phc(digest="ha$h"), id="digest-invalid-chars"),
    pytest.param(_phc(salt=_b64(b"\x01" * 7)), id="salt-7-bytes"),
    pytest.param(_phc(digest=_b64(b"\x01" * 3)), id="digest-3-bytes"),
    pytest.param(_phc(salt=""), id="salt-empty"),
    pytest.param(_phc(digest=""), id="digest-empty"),
    pytest.param("", id="empty-string"),
    pytest.param("$", id="dollar-only"),
    pytest.param("not a hash at all", id="plain-text"),
]


class TestParsePhcRejects:
    """parse_phc raises ValueError on anything malformed, without echoing it."""

    @pytest.mark.parametrize("encoded", _MALFORMED)
    def test_passwords_parse_phc_rejects_malformed(self, encoded: str) -> None:
        """Another algorithm or version, missing/extra fields, bad params, bad base64,
        a short salt or digest: ValueError."""
        with pytest.raises(ValueError):
            parse_phc(encoded)

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(None, id="none"),
            pytest.param(_phc().encode("ascii"), id="bytes"),
            pytest.param(12345, id="int"),
        ],
    )
    def test_passwords_parse_phc_rejects_non_str(self, value: object) -> None:
        """A stored value that isn't a str is malformed: ValueError, not a crash."""
        with pytest.raises(ValueError):
            parse_phc(value)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "encoded",
        [
            pytest.param(_phc(algorithm="argon2i", salt=_MARKER), id="algorithm"),
            pytest.param(_phc(params=f"m={_MARKER},t=2,p=1"), id="params"),
            pytest.param(_phc(salt=f"{_MARKER}*!"), id="salt"),
            pytest.param(f"$argon2id${_MARKER}", id="truncated"),
        ],
    )
    def test_passwords_parse_phc_error_never_echoes_the_input(self, encoded: str) -> None:
        """The error message carries no part of the stored string."""
        with pytest.raises(ValueError) as exc_info:
            parse_phc(encoded)

        assert _MARKER not in str(exc_info.value)
        assert _MARKER not in repr(exc_info.value)


# ---------------------------------------------------------------------------
# 3. Hashing
# ---------------------------------------------------------------------------


class TestHashPassword:
    """hash_password writes an Argon2id PHC string with the current parameters."""

    def test_passwords_hash_starts_with_current_params_prefix(self, current_hash: str) -> None:
        """$argon2id$v=19$m=19456,t=2,p=1$..."""
        assert current_hash.startswith(_CURRENT_PREFIX)

    def test_passwords_hash_has_16_byte_salt_and_32_byte_digest(self, current_hash: str) -> None:
        """The stored salt is 16 bytes and the digest 32 bytes."""
        parsed = parse_phc(current_hash)

        assert (len(parsed.salt), len(parsed.digest)) == (16, 32)

    def test_passwords_hash_digest_is_argon2id_of_the_password(self, current_hash: str) -> None:
        """The digest is exactly Argon2id(password, stored salt, stored params) — not
        argon2i/argon2d, not a plain hash."""
        parsed = parse_phc(current_hash)
        expected = _argon2id_digest(
            _PASSWORD,
            parsed.salt,
            memory_cost=parsed.memory_cost,
            iterations=parsed.iterations,
            lanes=parsed.lanes,
            length=len(parsed.digest),
        )

        assert parsed.digest == expected

    def test_passwords_hash_never_contains_the_password(self, current_hash: str) -> None:
        """The stored string doesn't carry the password."""
        assert _PASSWORD not in current_hash

    def test_passwords_hash_uses_a_fresh_salt_each_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two hashes of the same password differ, and so do their salts.

        The cost constants are lowered to keep this fast where the implementation
        reads them at call time; the property holds either way.
        """
        monkeypatch.setattr(passwords, "ARGON2_MEMORY_COST_KIB", 8)
        monkeypatch.setattr(passwords, "ARGON2_ITERATIONS", 1)

        first = hash_password(_PASSWORD)
        second = hash_password(_PASSWORD)

        assert first != second
        assert parse_phc(first).salt != parse_phc(second).salt
        assert len(parse_phc(first).salt) == 16


# ---------------------------------------------------------------------------
# 4. Verification
# ---------------------------------------------------------------------------


class TestVerifyPassword:
    """verify_password checks with the stored parameters and never raises on bad input."""

    def test_passwords_verify_accepts_the_right_password(self, current_hash: str) -> None:
        """The hashed password verifies."""
        assert verify_password(_PASSWORD, current_hash) is True

    def test_passwords_verify_rejects_a_wrong_password(self, current_hash: str) -> None:
        """A different password returns False (no exception)."""
        assert verify_password(_WRONG_PASSWORD, current_hash) is False

    def test_passwords_verify_uses_the_stored_params_for_an_old_hash(self, old_hash: str) -> None:
        """A hash with older parameters still verifies: the stored m/t/p are used."""
        assert verify_password(_PASSWORD, old_hash) is True

    def test_passwords_verify_rejects_a_wrong_password_on_an_old_hash(self, old_hash: str) -> None:
        """An old hash doesn't accept a wrong password."""
        assert verify_password(_WRONG_PASSWORD, old_hash) is False

    def test_passwords_verify_accepts_a_reference_argon2_cffi_hash(self) -> None:
        """A hash written by the argon2 reference implementation (argon2-cffi) verifies."""
        assert verify_password(_PASSWORD, _REFERENCE_HASH) is True

    @pytest.mark.parametrize("encoded", _MALFORMED)
    def test_passwords_verify_malformed_stored_hash_returns_false(self, encoded: str) -> None:
        """A malformed or out-of-range stored string returns False without raising."""
        assert verify_password(_PASSWORD, encoded) is False

    def test_passwords_verify_refuses_out_of_range_params_before_hashing(self) -> None:
        """A stored hash with absurd params (t=1000) is refused even when its digest
        matches, so a forged row can't make login burn CPU or memory."""
        salt = bytes(range(16))
        digest = _argon2id_digest(_PASSWORD, salt, memory_cost=8, iterations=1000, lanes=1)
        encoded = encode_phc(memory_cost=8, iterations=1000, lanes=1, salt=salt, digest=digest)

        assert verify_password(_PASSWORD, encoded) is False

    def test_passwords_verify_rejects_a_truncated_digest(self, current_hash: str) -> None:
        """Dropping bytes from the stored digest makes verification fail, not pass."""
        parsed = parse_phc(current_hash)
        truncated = encode_phc(
            memory_cost=parsed.memory_cost,
            iterations=parsed.iterations,
            lanes=parsed.lanes,
            salt=parsed.salt,
            digest=parsed.digest[:16],
        )

        assert verify_password(_PASSWORD, truncated) is False


# ---------------------------------------------------------------------------
# 5. Rehash decision
# ---------------------------------------------------------------------------


def _encoded(**overrides: Any) -> str:
    """A PHC string with the current params unless overridden (no Argon2 work)."""
    fields: dict[str, Any] = {
        "memory_cost": 19456,
        "iterations": 2,
        "lanes": 1,
        "salt": bytes(range(16)),
        "digest": bytes(range(32)),
    }
    fields.update(overrides)
    return encode_phc(**fields)


class TestNeedsRehash:
    """needs_rehash is True exactly when the stored parameters differ from the current ones."""

    def test_passwords_needs_rehash_false_for_a_fresh_hash(self, current_hash: str) -> None:
        """A hash made by hash_password needs no rehash."""
        assert needs_rehash(current_hash) is False

    def test_passwords_needs_rehash_false_for_current_params(self) -> None:
        """Current m/t/p and a 32-byte digest: no rehash."""
        assert needs_rehash(_encoded()) is False

    @pytest.mark.parametrize(
        "overrides",
        [
            pytest.param({"memory_cost": 12288}, id="lower-memory"),
            pytest.param({"memory_cost": 65536}, id="higher-memory"),
            pytest.param({"iterations": 3}, id="other-iterations"),
            pytest.param({"lanes": 2}, id="other-lanes"),
            pytest.param({"digest": bytes(range(16))}, id="16-byte-digest"),
            pytest.param({"digest": bytes(range(64))}, id="64-byte-digest"),
        ],
    )
    def test_passwords_needs_rehash_true_when_params_differ(
        self, overrides: dict[str, Any]
    ) -> None:
        """Any difference in m, t, p or digest length asks for a rehash."""
        assert needs_rehash(_encoded(**overrides)) is True

    def test_passwords_needs_rehash_true_for_an_old_hash(self, old_hash: str) -> None:
        """The m=12288,t=3,p=1 hash is rehashed on the next login."""
        assert needs_rehash(old_hash) is True

    def test_passwords_needs_rehash_true_for_the_reference_hash(self) -> None:
        """The argon2-cffi default hash (m=65536,t=3,p=4) is rehashed to the current params."""
        assert needs_rehash(_REFERENCE_HASH) is True

    @pytest.mark.parametrize("encoded", _MALFORMED)
    def test_passwords_needs_rehash_true_for_malformed(self, encoded: str) -> None:
        """A string that doesn't parse asks for a rehash (and doesn't raise)."""
        assert needs_rehash(encoded) is True


# ---------------------------------------------------------------------------
# 6. Policy
# ---------------------------------------------------------------------------

_EMAIL = "alice.smith@example.com"


class TestPasswordPolicyLength:
    """12 to 128 characters, counted as characters (len(str)), checked first."""

    @pytest.mark.parametrize("length", [0, 1, 11])
    def test_passwords_policy_too_short(self, length: int) -> None:
        """Fewer than 12 characters: reason 'too_short'."""
        with pytest.raises(PasswordPolicyError) as exc_info:
            check_password_policy(_password_of_length(length), email=_EMAIL)

        assert exc_info.value.reason == "too_short"

    @pytest.mark.parametrize("length", [12, 13, 64, 127, 128])
    def test_passwords_policy_accepts_lengths_12_to_128(self, length: int) -> None:
        """12 and 128 are both inside the range: no error."""
        check_password_policy(_password_of_length(length), email=_EMAIL)

    @pytest.mark.parametrize("length", [129, 200, 10_000])
    def test_passwords_policy_too_long(self, length: int) -> None:
        """More than 128 characters: reason 'too_long'."""
        with pytest.raises(PasswordPolicyError) as exc_info:
            check_password_policy(_password_of_length(length), email=_EMAIL)

        assert exc_info.value.reason == "too_long"

    @pytest.mark.parametrize(
        ("password", "reason"),
        [
            pytest.param("€" * 11, "too_short", id="11-euro-signs"),
            pytest.param("€" * 12, None, id="12-euro-signs"),
            pytest.param("é" * 128, None, id="128-e-acute"),
            pytest.param("é" * 129, "too_long", id="129-e-acute"),
        ],
    )
    def test_passwords_policy_counts_characters_not_bytes(
        self, password: str, reason: str | None
    ) -> None:
        """12 three-byte characters are 12 characters: OK; 129 two-byte characters are too long."""
        if reason is None:
            check_password_policy(password, email=_EMAIL)
            return
        with pytest.raises(PasswordPolicyError) as exc_info:
            check_password_policy(password, email=_EMAIL)
        assert exc_info.value.reason == reason

    def test_passwords_policy_checks_length_before_the_list(self) -> None:
        """'password123' is in the list but only 11 characters: 'too_short' wins."""
        assert "password123" in common_passwords()
        with pytest.raises(PasswordPolicyError) as exc_info:
            check_password_policy("password123", email=_EMAIL)

        assert exc_info.value.reason == "too_short"

    def test_passwords_policy_checks_length_before_the_email(self) -> None:
        """A password equal to a short email is rejected as 'too_short'."""
        with pytest.raises(PasswordPolicyError) as exc_info:
            check_password_policy("a@b.example", email="a@b.example")

        assert exc_info.value.reason == "too_short"

    def test_passwords_policy_error_is_a_value_error(self) -> None:
        """PasswordPolicyError is a ValueError subclass."""
        assert issubclass(PasswordPolicyError, ValueError)


class TestPasswordPolicyList:
    """Passwords in the bundled common-password list are rejected, casefolded."""

    @pytest.mark.parametrize(
        "password",
        [
            pytest.param("q1w2e3r4t5y6", id="q1w2e3r4t5y6"),
            pytest.param("qwerty123456", id="qwerty123456"),
            pytest.param("QWERTY123456", id="upper-case"),
            pytest.param("Q1W2E3R4T5Y6", id="upper-case-q1w2"),
            pytest.param("QwErTy123456", id="mixed-case"),
        ],
    )
    def test_passwords_policy_rejects_list_hits(self, password: str) -> None:
        """A (casefolded) list entry is rejected with reason 'common'."""
        with pytest.raises(PasswordPolicyError) as exc_info:
            check_password_policy(password, email=_EMAIL)

        assert exc_info.value.reason == "common"

    def test_passwords_policy_accepts_a_non_list_password(self) -> None:
        """A long, unusual password passes."""
        check_password_policy("violet-Anchor-93-quartz", email=_EMAIL)


class TestPasswordPolicyEmail:
    """A password equal to the email (case-insensitively) is rejected."""

    @pytest.mark.parametrize(
        "password",
        [
            pytest.param(_EMAIL, id="identical"),
            pytest.param("Alice.Smith@Example.COM", id="different-case"),
            pytest.param(_EMAIL.upper(), id="upper-case"),
        ],
    )
    def test_passwords_policy_rejects_the_email(self, password: str) -> None:
        """reason 'equals_email'."""
        with pytest.raises(PasswordPolicyError) as exc_info:
            check_password_policy(password, email=_EMAIL)

        assert exc_info.value.reason == "equals_email"

    def test_passwords_policy_rejects_the_email_when_the_email_has_capitals(self) -> None:
        """The comparison casefolds both sides."""
        with pytest.raises(PasswordPolicyError) as exc_info:
            check_password_policy(_EMAIL, email="Alice.Smith@EXAMPLE.com")

        assert exc_info.value.reason == "equals_email"

    def test_passwords_policy_accepts_a_password_containing_the_email(self) -> None:
        """Only equality is refused, not containment."""
        check_password_policy(f"{_EMAIL}-violet-93", email=_EMAIL)

    def test_passwords_policy_email_is_keyword_only(self) -> None:
        """check_password_policy(password, email) positionally is a TypeError."""
        with pytest.raises(TypeError):
            check_password_policy("violet-Anchor-93-quartz", _EMAIL)  # type: ignore[misc]


class TestPasswordPolicyErrorsCarryNoSecrets:
    """No policy error repeats the password or the email."""

    @pytest.mark.parametrize(
        ("password", "email"),
        [
            pytest.param("Xk9#Qm2$Lp7", "zed.marker@example.com", id="too_short"),
            pytest.param("Xk9#Qm2$Lp7" * 12, "zed.marker@example.com", id="too_long"),
            pytest.param("QWERTY123456", "zed.marker@example.com", id="common"),
            pytest.param("zed.marker@example.com", "zed.marker@example.com", id="equals_email"),
        ],
    )
    def test_passwords_policy_error_never_contains_password_or_email(
        self, password: str, email: str
    ) -> None:
        """str(), repr() and args of the error hold neither value."""
        with pytest.raises(PasswordPolicyError) as exc_info:
            check_password_policy(password, email=email)

        rendered = f"{exc_info.value!s} {exc_info.value!r} {exc_info.value.args!r}"
        assert password not in rendered
        assert password.casefold() not in rendered.casefold()
        assert email not in rendered
        assert "zed.marker" not in rendered


# ---------------------------------------------------------------------------
# 7. The bundled common-password list
# ---------------------------------------------------------------------------


class _ReadSpy:
    """Counts opens of the common-password file through builtins.open and io.open."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.count = 0
        real_open: Callable[..., Any] = io.open

        def spying_open(file: Any, *args: Any, **kwargs: Any) -> Any:
            if Path(str(file)).name == _LIST_PATH.name:
                self.count += 1
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr(io, "open", spying_open)
        monkeypatch.setattr(builtins, "open", spying_open)


class TestCommonPasswords:
    """common_passwords() loads the bundled SecLists file once into a casefolded frozenset."""

    def test_passwords_common_list_file_is_bundled(self) -> None:
        """resources/common_passwords.txt ships next to the module."""
        assert _LIST_PATH.is_file()

    def test_passwords_common_passwords_is_a_frozenset(self) -> None:
        """An immutable set: nothing can add or drop entries at runtime."""
        assert isinstance(common_passwords(), frozenset)

    def test_passwords_common_passwords_loads_the_whole_list(self) -> None:
        """The NCSC top-100k list: well over 90,000 distinct entries."""
        assert len(common_passwords()) > 90_000

    def test_passwords_common_passwords_equals_the_casefolded_file(self) -> None:
        """Exactly the file's non-empty lines, casefolded (UTF-8)."""
        lines = _LIST_PATH.read_text(encoding="utf-8").splitlines()
        expected = frozenset(line.casefold() for line in lines if line)

        assert common_passwords() == expected

    def test_passwords_common_passwords_has_no_empty_entry(self) -> None:
        """An empty line would never match a policy-length password, but must not load."""
        assert "" not in common_passwords()

    @pytest.mark.parametrize("entry", ["q1w2e3r4t5y6", "qwerty123456", "password", "123456"])
    def test_passwords_common_passwords_contains_known_entries(self, entry: str) -> None:
        """Well-known entries of the list are present."""
        assert entry in common_passwords()

    def test_passwords_common_passwords_entries_are_casefolded(self) -> None:
        """Every entry is already casefolded, so lookups of casefolded input work."""
        assert all(entry == entry.casefold() for entry in common_passwords())

    def test_passwords_common_passwords_returns_the_same_object(self) -> None:
        """Cached: a second call returns the very same frozenset."""
        assert common_passwords() is common_passwords()

    def test_passwords_common_passwords_does_not_reread_the_file(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Once loaded, later calls never open the file again."""
        common_passwords()  # make sure it is loaded
        spy = _ReadSpy(monkeypatch)
        _LIST_PATH.read_text(encoding="utf-8")  # the spy sees reads through pathlib
        assert spy.count == 1
        spy.count = 0

        common_passwords()
        common_passwords()
        check_password_policy("violet-Anchor-93-quartz", email=_EMAIL)

        assert spy.count == 0
