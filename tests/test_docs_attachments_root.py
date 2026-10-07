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

GH-281 audit fix round 1 (Decisions 11 and 12, contract A12; audit core M-1, L-1, L-3,
converters L-1, I-1):

- docs/configuration.md, in a section naming ``ADMINO_ATTACHMENTS_ROOT``: a block says
  the root must be a "dedicated" folder / directory; a block holds a sentence saying
  that changing it doesn't "move" the "existing" (or "already" stored) files. A block
  naming ``Range`` gives both download limits: 1,024 (or 1024) and 16.
- docs/SECURITY.md: a block says a compromised conversion child can "stop or kill" the
  agent's process and that it then needs a restart; a block says the container's init
  reaps a killed child's grandchildren (or orphans) "when they exit" and that they
  aren't killed (or keep running / outlive the call).
- src/admino/converters/runner.py: the module docstring no longer claims that "no
  process outlives the call" (whitespace and case ignored).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Final

_REPO: Final = Path(__file__).resolve().parent.parent
_DOCS: Final = _REPO / "docs"
_CONFIGURATION: Final = _DOCS / "configuration.md"
_GETTING_STARTED: Final = _DOCS / "getting-started.md"
_SECURITY: Final = _DOCS / "SECURITY.md"
_RUNNER: Final = _REPO / "src" / "admino" / "converters" / "runner.py"

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

# GH-281 audit fix round 1 (A12).
_DEDICATED_RE: Final = re.compile(r"\bdedicated\b", re.IGNORECASE)
_FOLDER_RE: Final = re.compile(r"\b(?:folder|directory|directories|root)\b", re.IGNORECASE)
_MOVE_RE: Final = re.compile(r"\bmov(?:e|es|ed|ing)\b", re.IGNORECASE)
_EXISTING_RE: Final = re.compile(r"\b(?:existing|already)\b", re.IGNORECASE)
_SENTENCE_END_RE: Final = re.compile(r"(?<=[.!?])\s+")
_RANGE_RE: Final = re.compile(r"\bRange\b")
_HEADER_LIMIT_RE: Final = re.compile(r"(?<![\d,.])1[,'" + chr(0x2019) + r"]?024(?!\d)")
_PART_LIMIT_RE: Final = re.compile(r"(?<![\d,.])16(?![\d,])")
_STOP_OR_KILL_RE: Final = re.compile(r"\bstop\w*\s+or\s+kill\w*", re.IGNORECASE)
_RESTART_RE: Final = re.compile(r"\brestart\w*", re.IGNORECASE)
_DESCENDANTS_RE: Final = re.compile(r"\b(?:grandchild\w*|orphan\w*)", re.IGNORECASE)
_REAPED_RE: Final = re.compile(r"\breap\w*", re.IGNORECASE)
_WHEN_THEY_EXIT_RE: Final = re.compile(
    r"\b(?:when|once|after|as)\s+they\s+(?:exit|end|finish)\w*", re.IGNORECASE
)
_NOT_KILLED_RE: Final = re.compile(
    r"(?:\bnot|n't|\bnever)\s+(?:\w+\s+){0,2}kill(?:ed)?\b"
    r"|\bkeeps?\s+running\b|\boutliv\w*|\bsurviv\w*",
    re.IGNORECASE,
)
_OVERCLAIM_RE: Final = re.compile(r"\bno\s+process(?:es)?\s+outlives?\b", re.IGNORECASE)


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
    return _split_blocks(path.read_text(encoding="utf-8"))


def _split_blocks(text: str) -> list[str]:
    """``text``'s paragraphs, top-level list items (nested items included) and table rows."""
    blocks: list[str] = []
    for paragraph in re.split(r"\n\s*\n", text):
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


def _root_section_blocks() -> list[str]:
    """The blocks of configuration.md's sections that name ADMINO_ATTACHMENTS_ROOT."""
    return [
        block
        for section in _sections(_CONFIGURATION)
        if _VARIABLE in section
        for block in _split_blocks(section)
    ]


def test_docs_attachments_root_configuration_says_the_root_is_a_dedicated_folder() -> None:
    """Audit L-3: the cleanup treats every UUID-named directory under the root as an
    organization's, so the root must be a dedicated folder."""
    blocks = [
        block
        for block in _root_section_blocks()
        if _DEDICATED_RE.search(block) and _FOLDER_RE.search(block)
    ]

    assert blocks != [], "configuration.md doesn't say the root must be a dedicated folder"


def test_docs_attachments_root_configuration_says_changing_it_moves_no_files() -> None:
    """Audit L-1: one sentence says that changing the setting doesn't move the existing
    (already stored) files."""
    sentences = [
        sentence
        for block in _root_section_blocks()
        for sentence in _SENTENCE_END_RE.split(block)
        if _MOVE_RE.search(sentence) and _EXISTING_RE.search(sentence)
    ]

    assert sentences != [], "configuration.md doesn't say a new root leaves the files behind"


def test_docs_attachments_root_configuration_states_the_range_limits() -> None:
    """Decision 11: a block naming ``Range`` gives 1,024 characters and 16 parts."""
    blocks = [
        block
        for block in _blocks(_CONFIGURATION)
        if _RANGE_RE.search(block)
        and _HEADER_LIMIT_RE.search(block)
        and _PART_LIMIT_RE.search(block)
    ]

    assert blocks != [], "configuration.md doesn't state the download's Range limits"


def test_docs_attachments_root_security_says_a_child_can_stop_or_kill_the_agent() -> None:
    """Converters audit L-1: under init the agent isn't PID 1, so a compromised child can
    stop or kill it, and a stopped agent needs a manual restart."""
    blocks = [
        block
        for block in _blocks(_SECURITY)
        if _STOP_OR_KILL_RE.search(block) and _RESTART_RE.search(block)
    ]

    assert blocks != [], "SECURITY.md doesn't say a conversion child can stop or kill the agent"


def test_docs_attachments_root_security_says_grandchildren_are_reaped_not_killed() -> None:
    """Converters audit I-1: a killed child's grandchildren aren't killed by the runner;
    the container's init reaps them when they exit."""
    blocks = [
        block
        for block in _blocks(_SECURITY)
        if _DESCENDANTS_RE.search(block)
        and _REAPED_RE.search(block)
        and _WHEN_THEY_EXIT_RE.search(block)
        and _NOT_KILLED_RE.search(block)
    ]

    assert blocks != [], "SECURITY.md doesn't say grandchildren are reaped, not killed"


def test_docs_attachments_root_runner_docstring_makes_no_outlive_claim() -> None:
    """Converters audit I-1: "no process outlives the call" isn't true for grandchildren."""
    docstring = ast.get_docstring(ast.parse(_RUNNER.read_text(encoding="utf-8")))
    flat = " ".join((docstring or "").split())

    assert (bool(flat), _OVERCLAIM_RE.findall(flat)) == (True, [])
