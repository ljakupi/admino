"""Password hashing (Argon2id) and the password policy (GH-149).

Inputs: a plain-text password (and, for the policy, the account's email).
Outputs: a PHC string to store (``hash_password``), a verification result
(``verify_password``), a rehash decision (``needs_rehash``), or a
``PasswordPolicyError`` naming why a new password is refused.

Hashing uses Argon2id from the already-pinned ``cryptography`` package, at the
OWASP baseline: 19 MiB memory, 2 iterations, 1 lane, a fresh random 16-byte
salt per password and a 32-byte digest. The result is stored as a PHC string,
``$argon2id$v=19$m=<m>,t=<t>,p=<p>$<salt>$<hash>`` with standard base64 and
no padding (the argon2 reference encoding), so hashes written by the
reference implementation verify here too. Verification uses the parameters
stored in the hash; ``needs_rehash`` tells the login to re-hash a password
whose stored parameters differ from the current ones.

Policy: 12 to 128 characters; not in the bundled common-password list
(SecLists' NCSC top 100k in ``resources/common_passwords.txt``, loaded once
and matched case-insensitively); not equal to the email. There is no external
lookup.

Security notes:
- Argon2 costs ~200 ms of CPU: async callers run ``hash_password`` and
  ``verify_password`` through ``asyncio.to_thread``.
- ``parse_phc`` refuses anything malformed or out of range (another
  algorithm or version, missing or extra fields, absurd costs, non-canonical
  base64, a short salt or digest) before any Argon2 work, so a forged stored
  hash can't make a login burn CPU or memory. ``verify_password`` returns
  False for a malformed stored hash instead of raising.
- No error message carries the password, the email or the stored hash.
- Pure apart from reading the bundled list file once. No logging.
"""

from __future__ import annotations

import base64
import binascii
import functools
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

ARGON2_MEMORY_COST_KIB: Final = 19456  # 19 MiB (OWASP baseline)
ARGON2_ITERATIONS: Final = 2
ARGON2_LANES: Final = 1
ARGON2_SALT_BYTES: Final = 16
ARGON2_HASH_BYTES: Final = 32
MIN_PASSWORD_LENGTH: Final = 12
MAX_PASSWORD_LENGTH: Final = 128

# Bounds a stored hash must respect before any Argon2 work. The minimums are
# Argon2's own; the maximums refuse absurd costs from a forged row.
_MIN_SALT_BYTES: Final = 8
_MIN_DIGEST_BYTES: Final = 4
_MAX_MEMORY_COST_KIB: Final = 1024 * 1024  # 1 GiB
_MAX_ITERATIONS: Final = 100
_MAX_LANES: Final = 64
# The users.password_hash CHECK bound (migration 0004).
_MAX_PHC_LENGTH: Final = 512

# ASCII-only character classes: \d would also match non-ASCII digits.
_NUMBER: Final = r"(0|[1-9][0-9]{0,9})"
_PHC_RE: Final = re.compile(
    rf"\$argon2id\$v=19\$m={_NUMBER},t={_NUMBER},p={_NUMBER}"
    r"\$([A-Za-z0-9+/]*)\$([A-Za-z0-9+/]*)"
)

_COMMON_PASSWORDS_PATH: Final = Path(__file__).parent / "resources" / "common_passwords.txt"

PolicyReason = Literal["too_short", "too_long", "common", "equals_email"]

_POLICY_MESSAGES: Final[dict[PolicyReason, str]] = {
    "too_short": f"The password must be at least {MIN_PASSWORD_LENGTH} characters long.",
    "too_long": f"The password must be at most {MAX_PASSWORD_LENGTH} characters long.",
    "common": "The password is too common.",
    "equals_email": "The password must not be the email address.",
}


@dataclass(frozen=True, slots=True)
class PhcHash:
    """The fields of a parsed Argon2id PHC string."""

    memory_cost: int
    iterations: int
    lanes: int
    salt: bytes
    digest: bytes


class PasswordPolicyError(ValueError):
    """Raised when a new password breaks the policy; ``reason`` names the rule."""

    reason: PolicyReason

    def __init__(self, reason: PolicyReason) -> None:
        super().__init__(_POLICY_MESSAGES[reason])
        self.reason = reason


def _b64encode(data: bytes) -> str:
    """Standard base64 without padding (the PHC encoding)."""
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    """Decode unpadded standard base64 strictly; refuse non-canonical input."""
    padded = text + "=" * (-len(text) % 4)
    try:
        data = base64.b64decode(padded, validate=True)
    except binascii.Error:
        msg = "The stored password hash has invalid base64."
        raise ValueError(msg) from None
    # Re-encoding catches impossible lengths and non-zero trailing bits.
    if _b64encode(data) != text:
        msg = "The stored password hash has invalid base64."
        raise ValueError(msg)
    return data


def encode_phc(*, memory_cost: int, iterations: int, lanes: int, salt: bytes, digest: bytes) -> str:
    """Encode Argon2id parameters, salt and digest as a PHC string.

    Args:
        memory_cost: Memory in KiB (m).
        iterations: Number of passes (t).
        lanes: Degree of parallelism (p).
        salt: The random salt.
        digest: The Argon2id output.

    Returns:
        ``$argon2id$v=19$m=<m>,t=<t>,p=<p>$<salt>$<hash>`` (standard base64, no padding).
    """
    return (
        f"$argon2id$v=19$m={memory_cost},t={iterations},p={lanes}"
        f"${_b64encode(salt)}${_b64encode(digest)}"
    )


def parse_phc(encoded: str) -> PhcHash:
    """Parse and range-check an Argon2id PHC string.

    Args:
        encoded: The stored hash.

    Returns:
        The parsed fields.

    Raises:
        ValueError: If the value isn't a well-formed Argon2id (v=19) PHC string
            with in-range parameters, a salt of 8+ bytes and a digest of 4+
            bytes. The message never repeats the input.
    """
    if not isinstance(encoded, str) or len(encoded) > _MAX_PHC_LENGTH:
        msg = "The stored password hash is malformed."
        raise ValueError(msg)
    match = _PHC_RE.fullmatch(encoded)
    if match is None:
        msg = "The stored password hash is malformed."
        raise ValueError(msg)
    memory_cost, iterations, lanes = (int(match.group(i)) for i in (1, 2, 3))
    if not (
        1 <= lanes <= _MAX_LANES
        and 1 <= iterations <= _MAX_ITERATIONS
        and 8 * lanes <= memory_cost <= _MAX_MEMORY_COST_KIB
    ):
        msg = "The stored password hash has out-of-range parameters."
        raise ValueError(msg)
    salt = _b64decode(match.group(4))
    digest = _b64decode(match.group(5))
    if len(salt) < _MIN_SALT_BYTES or len(digest) < _MIN_DIGEST_BYTES:
        msg = "The stored password hash has a too short salt or digest."
        raise ValueError(msg)
    return PhcHash(
        memory_cost=memory_cost, iterations=iterations, lanes=lanes, salt=salt, digest=digest
    )


def hash_password(password: str) -> str:
    """Hash a password with Argon2id, the current parameters and a fresh salt.

    CPU-bound (~200 ms): async callers use ``asyncio.to_thread``.

    Args:
        password: The plain-text password.

    Returns:
        The PHC string to store.
    """
    salt = secrets.token_bytes(ARGON2_SALT_BYTES)
    kdf = Argon2id(
        salt=salt,
        length=ARGON2_HASH_BYTES,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_COST_KIB,
    )
    digest = kdf.derive(password.encode("utf-8"))
    return encode_phc(
        memory_cost=ARGON2_MEMORY_COST_KIB,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        salt=salt,
        digest=digest,
    )


def verify_password(password: str, encoded: str) -> bool:
    """Check a password against a stored PHC hash, using the stored parameters.

    CPU-bound (~200 ms at the current parameters): async callers use
    ``asyncio.to_thread``.

    Args:
        password: The plain-text password to check.
        encoded: The stored PHC string.

    Returns:
        True if the password matches; False on a mismatch, a malformed or
        out-of-range stored hash, or a password that can't be UTF-8 encoded.
    """
    try:
        parsed = parse_phc(encoded)
        key_material = password.encode("utf-8")
    except ValueError:  # UnicodeEncodeError is a ValueError too
        return False
    kdf = Argon2id(
        salt=parsed.salt,
        length=len(parsed.digest),
        iterations=parsed.iterations,
        lanes=parsed.lanes,
        memory_cost=parsed.memory_cost,
    )
    try:
        kdf.verify(key_material, parsed.digest)
    except InvalidKey:
        return False
    return True


def needs_rehash(encoded: str) -> bool:
    """Return True when a stored hash should be replaced by one with the current parameters.

    Args:
        encoded: The stored PHC string.

    Returns:
        True if m, t, p or the digest length differ from the current values,
        or the string doesn't parse.
    """
    try:
        parsed = parse_phc(encoded)
    except ValueError:
        return True
    return (parsed.memory_cost, parsed.iterations, parsed.lanes, len(parsed.digest)) != (
        ARGON2_MEMORY_COST_KIB,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
        ARGON2_HASH_BYTES,
    )


@functools.cache
def common_passwords() -> frozenset[str]:
    """Return the bundled common-password list, casefolded (read once, then cached).

    Raises:
        OSError: If the bundled file is missing or unreadable.
        UnicodeDecodeError: If the file isn't valid UTF-8.
    """
    text = _COMMON_PASSWORDS_PATH.read_text(encoding="utf-8")
    return frozenset(line.casefold() for line in text.splitlines() if line)


def check_password_policy(password: str, *, email: str) -> None:
    """Refuse a new password that breaks the policy.

    Checked in order: length (12 to 128 characters), the common-password list
    (case-insensitive), equality with the email (case-insensitive).

    Args:
        password: The new password.
        email: The account's email address.

    Raises:
        PasswordPolicyError: With reason ``too_short``, ``too_long``,
            ``common`` or ``equals_email``. Its message never contains the
            password or the email.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError("too_short")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError("too_long")
    folded = password.casefold()
    if folded in common_passwords():
        raise PasswordPolicyError("common")
    if folded == email.casefold():
        raise PasswordPolicyError("equals_email")
