"""Test API keys built at runtime (GH-264 contract section 6).

No key literal is ever written in a test file (GitHub push protection, gitleaks):
a key is a fixed prefix (``"sk-" + "proj-"``) plus a body drawn from a seeded
``random.Random`` over the key characters (``A-Z``, ``a-z``, ``0-9``, ``_``,
``-``), forced to hold a ``_`` and a ``-``. The same seed gives the same key on
every run.

``surviving_chunks`` is the "no part of the key survives" check: every
8-character chunk of the key's body (the part after its fixed prefix) that is
still in a text.

GH-270 contract section 4 adds the formats of the new rules (``KeyFormat``,
``NEW_KEY_FORMATS``): Stripe secret keys, Google API keys, GitHub fine-grained,
OAuth, user and refresh tokens, Hugging Face and Groq keys. Their prefixes are
concatenated from pieces too (``"hf" + "_"``) and their bodies drawn from a
seeded ``random.Random`` over the format's characters.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass
from typing import Final

KEY_CHARS: Final = string.ascii_letters + string.digits + "_-"
CHUNK_LENGTH: Final = 8


@dataclass(frozen=True, slots=True)
class ApiKey:
    """A test key: its fixed ``prefix`` (e.g. ``sk-proj-``) and its random ``body``."""

    prefix: str
    body: str

    @property
    def text(self) -> str:
        """The whole key."""
        return self.prefix + self.body


def api_key(prefix: str, total: int, *, seed: int) -> ApiKey:
    """A ``total``-character key: ``prefix`` and a seeded body of key characters.

    The body's characters at indexes 4 and 9 are ``_`` and ``-``, so every key
    holds both, and a ``_`` comes before today's 20-character minimum.
    """
    rng = random.Random(seed)  # noqa: S311 - a deterministic test key, not a secret
    chars = [rng.choice(KEY_CHARS) for _ in range(total - len(prefix))]
    chars[4], chars[9] = "_", "-"
    return ApiKey(prefix, "".join(chars))


def openai_project_key() -> ApiKey:
    """An OpenAI project key: ``sk-proj-`` and 156 key characters, 164 in all."""
    return api_key("sk-" + "proj-", 164, seed=164)


def anthropic_api03_key() -> ApiKey:
    """An Anthropic key: ``sk-ant-api03-`` and 95 key characters with ``_``, 108 in all."""
    return api_key("sk-" + "ant-api03-", 108, seed=108)


ALNUM_CHARS: Final = string.ascii_letters + string.digits


@dataclass(frozen=True, slots=True)
class KeyFormat:
    """A key format of a GH-270 rule (contract section 4).

    ``name`` is the test id, ``prefix`` the fixed start, ``minimum`` the
    shortest body the rule redacts and ``realistic`` the body length of a real
    key. A body is drawn from ``chars`` with a ``random.Random(seed)``, then
    ``forced`` puts fixed characters at fixed body indexes (the ``_`` and ``-``
    a Google key can hold, the ``_`` after the 22nd character of a GitHub
    fine-grained token), so every key holds its format's punctuation. Bodies of
    one format share their leading characters: the key of ``n`` characters is
    the key of ``n + 1`` without its last one.
    """

    name: str
    prefix: str
    chars: str
    minimum: int
    realistic: int
    seed: int
    forced: tuple[tuple[int, str], ...] = ()

    def key(self, length: int | None = None) -> ApiKey:
        """The prefix and a seeded body of ``length`` characters (default: ``realistic``)."""
        body_length = self.realistic if length is None else length
        rng = random.Random(self.seed)  # noqa: S311 - a deterministic test key, not a secret
        chars = [rng.choice(self.chars) for _ in range(body_length)]
        for index, char in self.forced:
            if index < body_length:
                chars[index] = char
        return ApiKey(self.prefix, "".join(chars))


STRIPE_LIVE: Final = KeyFormat("stripe-live", "sk" + "_live_", ALNUM_CHARS, 24, 99, seed=107)
STRIPE_TEST: Final = KeyFormat("stripe-test", "sk" + "_test_", ALNUM_CHARS, 24, 99, seed=108)
GOOGLE_API: Final = KeyFormat(
    "google-api", "AI" + "za", KEY_CHARS, 35, 35, seed=39, forced=((4, "_"), (9, "-"))
)
GITHUB_FINE_GRAINED: Final = KeyFormat(
    "github-fine-grained", "github" + "_pat_", ALNUM_CHARS, 82, 82, seed=93, forced=((22, "_"),)
)
GITHUB_OAUTH: Final = KeyFormat("github-oauth", "gh" + "o_", ALNUM_CHARS, 36, 36, seed=40)
GITHUB_USER: Final = KeyFormat("github-user", "gh" + "u_", ALNUM_CHARS, 36, 36, seed=41)
GITHUB_REFRESH: Final = KeyFormat("github-refresh", "gh" + "r_", ALNUM_CHARS, 36, 36, seed=42)
HUGGING_FACE: Final = KeyFormat("hugging-face", "hf" + "_", ALNUM_CHARS, 34, 34, seed=37)
GROQ: Final = KeyFormat("groq", "gs" + "k_", ALNUM_CHARS, 52, 52, seed=56)

NEW_KEY_FORMATS: Final = (
    STRIPE_LIVE,
    STRIPE_TEST,
    GOOGLE_API,
    GITHUB_FINE_GRAINED,
    GITHUB_OAUTH,
    GITHUB_USER,
    GITHUB_REFRESH,
    HUGGING_FACE,
    GROQ,
)


def surviving_chunks(text: str, key: ApiKey) -> list[str]:
    """Every 8-character chunk of ``key``'s body found in ``text`` (empty: none survived)."""
    body = key.body
    chunks = {body[i : i + CHUNK_LENGTH] for i in range(len(body) - CHUNK_LENGTH + 1)}
    return sorted(chunk for chunk in chunks if chunk in text)
