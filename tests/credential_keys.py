"""Test API keys built at runtime (GH-264 contract section 6).

No key literal is ever written in a test file (GitHub push protection, gitleaks):
a key is a fixed prefix (``"sk-" + "proj-"``) plus a body drawn from a seeded
``random.Random`` over the key characters (``A-Z``, ``a-z``, ``0-9``, ``_``,
``-``), forced to hold a ``_`` and a ``-``. The same seed gives the same key on
every run.

``surviving_chunks`` is the "no part of the key survives" check: every
8-character chunk of the key's body (the part after its fixed prefix) that is
still in a text.
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


def surviving_chunks(text: str, key: ApiKey) -> list[str]:
    """Every 8-character chunk of ``key``'s body found in ``text`` (empty: none survived)."""
    body = key.body
    chunks = {body[i : i + CHUNK_LENGTH] for i in range(len(body) - CHUNK_LENGTH + 1)}
    return sorted(chunk for chunk in chunks if chunk in text)
