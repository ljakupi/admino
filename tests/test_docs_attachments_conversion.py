"""Docs checks for GH-188's document conversion (contract section 10).

User-visible and security-relevant changes update docs/*.md in the same PR (#139
§5). These checks read one section of each file and look for the codes and key
terms GH-188 adds, not for a wording, so the docs stay free to phrase them their own
way:

- docs/configuration.md, ``### Attachments`` (up to the next heading of level 1 to
  3; ``####`` subsections belong to it): the ``token_estimate`` field in backticks;
  every conversion failure code (the eight of
  ``admino.converters.common.CONVERSION_FAILURES``, read at test time, plus #187's
  ``file_missing`` and ``unsupported_type``) in backticks; and the 120-second
  per-file timeout, stated in the same paragraph, list item or table row as the
  conversion (``conversion_timeout``, a conversion word, the worker or the process;
  the section's existing 120-second upload deadline doesn't count).
- docs/SECURITY.md, ``## Attachments``: parsing in a separate process (a
  separate / short-lived / child / worker / dedicated process, or a subprocess);
  the zip-bomb guard (``archive_too_large`` and the word "bomb"); metadata
  stripping (one sentence with "metadata" and a strip / remove / without word).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

_DOCS: Final = Path(__file__).resolve().parent.parent / "docs"
_CONFIGURATION: Final = _DOCS / "configuration.md"
_SECURITY: Final = _DOCS / "SECURITY.md"

# #187's processing codes the Attachments section lists beside the conversion ones.
_PROCESSING_CODES: Final = ("file_missing", "unsupported_type")
_HEADING_RE: Final = re.compile(r"(#{1,6}) (.+?)\s*")
_FENCE_RE: Final = re.compile(r"\s*(```|~~~)")
_SECONDS_120_RE: Final = re.compile(
    r"\b120(?:\s|-|" + chr(0xA0) + r"|" + chr(0x202F) + r")?(?:s|sec|seconds?)\b",
    re.IGNORECASE,
)
_CONVERSION_RE: Final = re.compile(
    r"`conversion_timeout`|\bconver(?:t|ts|ted|ting|sion|sions)\b|\bworkers?\b"
    r"|\bprocess(?:es)?\b|\bsubprocess(?:es)?\b",
    re.IGNORECASE,
)
_SEPARATE_PROCESS_RE: Final = re.compile(
    r"\b(?:separate|short-lived|child|worker|dedicated|isolated)\b[\w ,-]{0,30}?"
    r"\bprocess(?:es)?\b|\bsubprocess(?:es)?\b",
    re.IGNORECASE,
)
_BOMB_RE: Final = re.compile(r"\bbombs?\b", re.IGNORECASE)
_METADATA_RE: Final = re.compile(r"\bmetadata\b", re.IGNORECASE)
_STRIP_RE: Final = re.compile(
    r"\b(?:strip\w*|remov\w*|without|drop\w*|delet\w*|discard\w*)\b", re.IGNORECASE
)


def _section(path: Path, title: str, level: int) -> str:
    """The text under the heading ``title`` of ``level``, up to the next heading of
    that level or a higher one (headings inside code fences don't count)."""
    lines = path.read_text(encoding="utf-8").splitlines()
    found: list[str] | None = None
    in_fence = False
    for line in lines:
        if _FENCE_RE.match(line):
            in_fence = not in_fence
        heading = None if in_fence else _HEADING_RE.fullmatch(line)
        if found is None:
            if heading and len(heading.group(1)) == level and heading.group(2) == title:
                found = []
            continue
        if heading and len(heading.group(1)) <= level:
            break
        found.append(line)
    assert found is not None, f"{path.name} has no {'#' * level} {title} section"
    return "\n".join(found)


def _blocks(text: str) -> list[str]:
    """Paragraphs, top-level list items (their nested items included) and table rows."""
    blocks: list[str] = []
    for paragraph in re.split(r"\n\s*\n", text):
        current: list[str] = []
        for line in paragraph.splitlines():
            if (line.startswith("- ") or line.lstrip().startswith("|")) and current:
                blocks.append("\n".join(current))
                current = []
            current.append(line)
            if line.lstrip().startswith("|"):
                blocks.append("\n".join(current))
                current = []
        if current:
            blocks.append("\n".join(current))
    return [block for block in blocks if block.strip()]


def _sentences(text: str) -> list[str]:
    return [
        sentence
        for block in _blocks(text)
        for sentence in re.split(r"(?<=[.!?])\s+", " ".join(block.split()))
    ]


def _configuration_attachments() -> str:
    return _section(_CONFIGURATION, "Attachments", 3)


def _security_attachments() -> str:
    return _section(_SECURITY, "Attachments", 2)


def test_docs_attachments_conversion_configuration_names_the_token_estimate_field() -> None:
    assert "`token_estimate`" in _configuration_attachments()


def test_docs_attachments_conversion_configuration_lists_every_failure_code() -> None:
    """The eight conversion codes and #187's processing codes, each in backticks."""
    from admino.converters import common

    codes = sorted(common.CONVERSION_FAILURES) + list(_PROCESSING_CODES)
    section = _configuration_attachments()

    assert len(common.CONVERSION_FAILURES) == 8
    assert {code: f"`{code}`" in section for code in codes} == dict.fromkeys(codes, True)


def test_docs_attachments_conversion_configuration_states_the_120_second_timeout() -> None:
    """In the same block as the conversion: the upload body's 120-second deadline,
    already documented, is another limit."""
    found = [
        block
        for block in _blocks(_configuration_attachments())
        if _SECONDS_120_RE.search(block) and _CONVERSION_RE.search(block)
    ]

    assert found, "no paragraph, item or row states the conversion's 120-second timeout"


def test_docs_attachments_conversion_security_names_the_separate_worker_process() -> None:
    found = [s for s in _sentences(_security_attachments()) if _SEPARATE_PROCESS_RE.search(s)]

    assert found, "SECURITY.md's Attachments section doesn't say parsing runs in its own process"


def test_docs_attachments_conversion_security_names_the_zip_bomb_guard() -> None:
    section = _security_attachments()

    assert "`archive_too_large`" in section
    assert _BOMB_RE.search(section) is not None


def test_docs_attachments_conversion_security_states_metadata_stripping() -> None:
    found = [
        s
        for s in _sentences(_security_attachments())
        if _METADATA_RE.search(s) and _STRIP_RE.search(s)
    ]

    assert found, "SECURITY.md's Attachments section doesn't say image metadata is stripped"
