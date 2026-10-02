"""Docs for per-user connections, residency gating and per-user memory (GH-162).

User-visible changes update docs/*.md in the same PR (#139 §5). These checks
read the combined text of docs/*.md and look for the statements GH-162 makes
true, per paragraph or sentence, case-insensitively, with several accepted
wordings, so the docs stay free to phrase them their own way:

- Connections are per user: one sentence says "connect" together with a
  per-user marker ("per user", "per-user", "each user", "every user", "their
  own", "your own", "private to").
- The data residency policy disables the Google/Microsoft tools: one
  paragraph names residency, Google or Microsoft, and a disabling word
  ("disable", "off", "unavailable", "blocked", "inactive", "can't", ...).
- Memory notes are per user: one sentence says "memory" with a per-user marker.
- Upgrading drops the stored tokens and memory so each user reconnects: one
  paragraph says "reconnect", "memory", a token / connection / account, a
  drop / delete / remove, and a per-user marker (each user reconnects their
  own accounts; nobody can do it for them).

Security notes:
- Operators must know that the upgrade discards the old install-wide token on
  purpose (it is never handed to some user), and that residency turns the
  Google and Microsoft tools off rather than only hiding them.
"""

from __future__ import annotations

import re
from pathlib import Path

_DOCS = Path(__file__).resolve().parent.parent / "docs"
_BLOCK_START = re.compile(r"^\s*(?:[-*+]\s|\d+[.)]\s|\||#)")
_PER_USER = re.compile(
    r"\b(?:per[- ]user|each user|every user|their own|your own|private to)\b", re.IGNORECASE
)
_CONNECT = re.compile(r"\bconnect", re.IGNORECASE)
_PROVIDER = re.compile(r"\b(?:google|microsoft)\b", re.IGNORECASE)
_MEMORY = re.compile(r"\bmemory\b", re.IGNORECASE)
_DISABLED = re.compile(
    r"\b(?:disabl\w*|off|unavailable|not available|block\w*|inactive|can't|cannot|"
    r"refus\w*|hidden|hides?)\b",
    re.IGNORECASE,
)


def _blocks_of(text: str) -> list[str]:
    """The paragraphs of a Markdown text; every list item, table row and heading is
    its own block. Whitespace collapsed."""
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            if current:
                blocks.append(current)
                current = []
            continue
        if _BLOCK_START.match(line) and current:
            blocks.append(current)
            current = []
        current.append(line.strip())
    if current:
        blocks.append(current)
    return [re.sub(r"\s+", " ", " ".join(block)) for block in blocks]


def _blocks() -> list[str]:
    """The blocks of every docs/*.md file."""
    paths = sorted(_DOCS.glob("*.md"))
    assert paths, "no docs/*.md"
    return [block for path in paths for block in _blocks_of(path.read_text(encoding="utf-8"))]


def _sentences() -> list[str]:
    return [sentence for block in _blocks() for sentence in re.split(r"(?<=[.!?])\s+", block)]


class TestDocsPerUserConnections:
    """docs/*.md describe GH-162's per-user model."""

    def test_docs_connections_are_per_user(self) -> None:
        matching = [s for s in _sentences() if _CONNECT.search(s) and _PER_USER.search(s)]

        assert matching, "no sentence says connections are per user"

    def test_docs_residency_disables_google_and_microsoft_tools(self) -> None:
        matching = [
            b
            for b in _blocks()
            if re.search(r"residency", b, re.IGNORECASE)
            and _PROVIDER.search(b)
            and _DISABLED.search(b)
        ]

        assert matching, "no paragraph says residency turns the Google/Microsoft tools off"

    def test_docs_memory_notes_are_per_user(self) -> None:
        matching = [s for s in _sentences() if _MEMORY.search(s) and _PER_USER.search(s)]

        assert matching, "no sentence says memory notes are per user"

    def test_docs_upgrade_drops_tokens_and_memory_so_users_reconnect(self) -> None:
        matching = [
            b
            for b in _blocks()
            if "reconnect" in b.lower()
            and _MEMORY.search(b)
            and re.search(r"\b(?:tokens?|connections?|accounts?)\b", b, re.IGNORECASE)
            and re.search(r"\b(?:drop|delet|remov)", b, re.IGNORECASE)
            and _PER_USER.search(b)
        ]

        assert matching, "no paragraph says the upgrade drops tokens and memory, users reconnect"
