"""Docs checks for GH-281's attachments root, ``make run``, stdout cap and init (contract A9).

User-visible and security-relevant changes update docs/*.md in the same PR (#139 §5).
Issue #281: "``make run`` sets ``ADMINO_ATTACHMENTS_ROOT`` ... the docs say so".
Contract A9 names what each file gains. These checks look for key terms, case
insensitive, in one section (the text between two headings of any level, headings in
code fences ignored) or one block (a paragraph, a top-level list item with its nested
items, a table row), never for a wording:

- docs/configuration.md: a section naming ``ADMINO_ATTACHMENTS_ROOT`` also gives the
  default ``/app/data/attachments`` and says the path must be absolute.
- docs/getting-started.md: a section naming ``ADMINO_ATTACHMENTS_ROOT`` also names
  ``make run`` and ``data/attachments`` (where native runs keep the uploads).
- docs/SECURITY.md: a block states the conversion child's stdout cap (4 KiB, or
  4096 bytes) with the word stdout / standard output / output; a block names
  ``init: true`` and that it reaps orphaned (zombie) processes.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

_DOCS: Final = Path(__file__).resolve().parent.parent / "docs"
_CONFIGURATION: Final = _DOCS / "configuration.md"
_GETTING_STARTED: Final = _DOCS / "getting-started.md"
_SECURITY: Final = _DOCS / "SECURITY.md"

_VARIABLE: Final = "ADMINO_ATTACHMENTS_ROOT"
_HEADING_RE: Final = re.compile(r"#{1,6} .+")
_FENCE_RE: Final = re.compile(r"\s*(```|~~~)")
_ABSOLUTE_RE: Final = re.compile(r"\babsolute\b", re.IGNORECASE)
_SPACE: Final = r"(?:\s|-|" + chr(0xA0) + r"|" + chr(0x202F) + r")?"
# 4 KiB (not 64 KiB) or 4096 / 4,096 bytes.
_CAP_RE: Final = re.compile(
    r"(?<![\w.,])4"
    + _SPACE
    + r"KiB\b|(?<![\w.,])4[,'"
    + chr(0x2019)
    + r"]?096"
    + _SPACE
    + r"bytes\b",
    re.IGNORECASE,
)
_OUTPUT_RE: Final = re.compile(r"\b(?:stdout|standard output|output)\b", re.IGNORECASE)
_INIT_RE: Final = re.compile(r"\binit:\s*true\b", re.IGNORECASE)
_REAP_RE: Final = re.compile(r"\b(?:reap\w*|orphan\w*|zombies?)\b", re.IGNORECASE)


def _sections(path: Path) -> list[str]:
    """The text between consecutive headings (any level; not inside code fences)."""
    sections: list[str] = []
    current: list[str] = []
    in_fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if _FENCE_RE.match(line):
            in_fence = not in_fence
        if not in_fence and _HEADING_RE.fullmatch(line):
            sections.append("\n".join(current))
            current = []
            continue
        current.append(line)
    sections.append("\n".join(current))
    return sections


def _blocks(path: Path) -> list[str]:
    """Paragraphs, top-level list items (their nested items included) and table rows."""
    blocks: list[str] = []
    for paragraph in re.split(r"\n\s*\n", path.read_text(encoding="utf-8")):
        current: list[str] = []
        for line in paragraph.splitlines():
            if (line.startswith(("- ", "* ")) or line.lstrip().startswith("|")) and current:
                blocks.append("\n".join(current))
                current = []
            current.append(line)
            if line.lstrip().startswith("|"):
                blocks.append("\n".join(current))
                current = []
        if current:
            blocks.append("\n".join(current))
    return [block for block in blocks if block.strip()]


def test_docs_attachments_root_configuration_documents_the_variable() -> None:
    """A section names ADMINO_ATTACHMENTS_ROOT, its default /app/data/attachments and
    that the path must be absolute."""
    sections = [section for section in _sections(_CONFIGURATION) if _VARIABLE in section]

    assert [
        section
        for section in sections
        if "/app/data/attachments" in section and _ABSOLUTE_RE.search(section)
    ] != [], f"no section of configuration.md documents {_VARIABLE} fully"


def test_docs_attachments_root_getting_started_says_where_make_run_keeps_uploads() -> None:
    """A section names ADMINO_ATTACHMENTS_ROOT with ``make run`` and data/attachments."""
    sections = [section for section in _sections(_GETTING_STARTED) if _VARIABLE in section]

    assert [
        section
        for section in sections
        if "make run" in section.lower() and "data/attachments" in section
    ] != [], f"no section of getting-started.md ties {_VARIABLE} to make run"


def test_docs_attachments_root_security_states_the_stdout_cap() -> None:
    """A block states the conversion child's output cap: 4 KiB or 4096 bytes."""
    blocks = [
        block for block in _blocks(_SECURITY) if _CAP_RE.search(block) and _OUTPUT_RE.search(block)
    ]

    assert blocks != [], "SECURITY.md doesn't state the 4 KiB stdout cap"


def test_docs_attachments_root_security_states_the_agents_init() -> None:
    """A block names ``init: true`` and that it reaps orphaned processes."""
    blocks = [
        block for block in _blocks(_SECURITY) if _INIT_RE.search(block) and _REAP_RE.search(block)
    ]

    assert blocks != [], "SECURITY.md doesn't state that the agent runs under an init"
