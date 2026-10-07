"""Docs checks for GH-188's document conversion (contract sections 10 and 12.9).

User-visible and security-relevant changes update docs/*.md in the same PR (#139
§5). These checks read one section of each file and look for the codes and key
terms GH-188 adds, not for a wording, so the docs stay free to phrase them their own
way:

- docs/configuration.md, ``### Attachments`` (up to the next heading of level 1 to
  3; ``####`` subsections belong to it): the ``token_estimate`` field in backticks;
  every conversion failure code (the nine of
  ``admino.converters.common.CONVERSION_FAILURES``, ``output_too_large`` included
  since the audit fixes of contract 12, read at test time, plus #187's
  ``file_missing`` and ``unsupported_type``) in backticks; processing's
  ``storage_quota_exceeded`` (contract 12.4) as a ``failure_reason`` table row (its
  first cell; the upload error table has it in its second); the 120-second
  per-file timeout, stated in the same paragraph, list item or table row as the
  conversion (``conversion_timeout``, a conversion word, the worker or the process;
  the section's existing 120-second upload deadline doesn't count); derived files
  count toward the storage quota (a sentence naming the derived / converted files,
  the quota and counting, with no negation) and the 256 MiB per-file cap in the
  same block as ``output_too_large``.
- Neither docs/configuration.md nor docs/SECURITY.md (whole files) still says that
  derived / converted files don't count toward the quota (#188's first wording,
  reversed by Decision 15).
- docs/SECURITY.md, ``## Attachments``: parsing in a separate process (a
  separate / short-lived / child / worker / dedicated process, or a subprocess);
  the zip-bomb guard (``archive_too_large`` and the word "bomb"); metadata
  stripping (one sentence with "metadata" and a strip / remove / without word).
- docs/SECURITY.md, the "isn't a sandbox" limitation (the block, i.e. list item,
  holding "sandbox"; contract 12.9 and process audit I-1): what a compromised parser
  can still do, namely every organization's files, the network and DNS, and the
  follow-up options, Landlock and a separate converter container.
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
# Contract 12.4 / 12.9: the derived files and the storage quota.
_DERIVED_RE: Final = re.compile(
    r"\b(?:derived|converted)\b[\w ,-]{0,20}?\b(?:files?|parts?|artifacts?|artefacts?|bytes)\b",
    re.IGNORECASE,
)
# Up to four words (an apostrophe allowed: "the organization's storage") before "quota".
_TO_QUOTA: Final = r"(?:[\w'" + chr(0x2019) + r"]+\s+){0,4}?quotas?\b"
_INTO: Final = r"\s+(?:toward|towards|against|in|into|to)\s+"
# "count(s/ed) toward ... quota", "included in the quota", "the quota counts / includes".
_COUNTS_TOWARD_RE: Final = re.compile(
    r"\b(?:count(?:s|ed|ing)?|includ(?:e|es|ed|ing)|add(?:s|ed)?)"
    + _INTO
    + _TO_QUOTA
    + r"|\bquotas?\s+(?:now\s+|also\s+)?(?:counts?|includes?)\b",
    re.IGNORECASE,
)
# The reversed statement: "don't count toward the quota", "not counted in the quota",
# "outside the quota", "excluded from the quota".
_NOT_COUNTED_RE: Final = re.compile(
    r"(?:\bnot|\bnever|n['" + chr(0x2019) + r"]t)\s+(?:be\s+|been\s+)?"
    r"(?:count(?:s|ed|ing)?|includ\w*)"
    + _INTO
    + _TO_QUOTA
    + r"|\boutside\s+(?:of\s+)?"
    + _TO_QUOTA
    + r"|\bexclud\w*\s+from\s+"
    + _TO_QUOTA,
    re.IGNORECASE,
)
_MIB_256_RE: Final = re.compile(r"\b256(?:\s|" + chr(0xA0) + r"|" + chr(0x202F) + r")?MiB\b")
# Contract 12.9: the "not a sandbox" limitation names what a compromised parser reaches.
_SANDBOX_RE: Final = re.compile(r"\bsandbox(?:ed|es)?\b", re.IGNORECASE)
_APOSTROPHE: Final = "['" + chr(0x2019) + "]"
_EVERY_ORG_FILES_RE: Final = re.compile(
    r"\b(?:every|each|all|any) organi[sz]ation(?:" + _APOSTROPHE + r"s|s" + _APOSTROPHE + r"|s)?"
    r"[\w ,-]{0,40}?\bfiles\b"
    r"|\bfiles\b[\w ,-]{0,40}?\bof (?:every|each|all|any) organi[sz]ations?\b",
    re.IGNORECASE,
)
_NETWORK_RE: Final = re.compile(r"\bnetworks?\b", re.IGNORECASE)
_DNS_RE: Final = re.compile(r"\bDNS\b")
_LANDLOCK_RE: Final = re.compile(r"\bLandlock\b")
_SEPARATE_CONTAINER_RE: Final = re.compile(
    r"\b(?:separate|dedicated|own)\b[\w ,-]{0,40}?\bcontainers?\b", re.IGNORECASE
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
    """The nine conversion codes (contract 12: ``output_too_large`` added) and #187's
    processing codes, each in backticks."""
    from admino.converters import common

    codes = sorted(common.CONVERSION_FAILURES) + list(_PROCESSING_CODES)
    section = _configuration_attachments()

    assert len(common.CONVERSION_FAILURES) == 9
    assert "output_too_large" in common.CONVERSION_FAILURES
    assert {code: f"`{code}`" in section for code in codes} == dict.fromkeys(codes, True)


def _first_cells(text: str) -> list[str]:
    """The first cell of every Markdown table row of a text, stripped."""
    return [
        match.group(1).strip()
        for line in text.splitlines()
        if (match := re.match(r"\s*\|([^|]*)\|", line))
    ]


def test_docs_attachments_conversion_configuration_lists_storage_quota_exceeded_as_a_reason() -> (
    None
):
    """Contract 12.4: a conversion that would take the organization past its quota fails
    with ``storage_quota_exceeded``: a row of the ``failure_reason`` table (the code
    as its first cell), beside the upload refusal of the same name."""
    assert "`storage_quota_exceeded`" in _first_cells(_configuration_attachments())


def _derived_blocks(text: str) -> list[str]:
    """The blocks (paragraphs, list items, rows) of a text naming derived / converted
    files, whitespace collapsed (a list item's "They ..." sentence belongs to its
    subject)."""
    flat = (" ".join(block.split()) for block in _blocks(text))
    return [block for block in flat if _DERIVED_RE.search(block)]


def test_docs_attachments_conversion_configuration_counts_derived_files_in_the_quota() -> None:
    """Decision 15 (contract 12.4): a block of the Attachments section about the derived
    files says they count toward the storage quota, and no block of configuration.md or
    SECURITY.md about them still says they don't (count toward / are outside / are
    excluded from the quota)."""
    stated = [
        block
        for block in _derived_blocks(_configuration_attachments())
        if _COUNTS_TOWARD_RE.search(block) and not _NOT_COUNTED_RE.search(block)
    ]
    stale = {
        path.name: [
            block
            for block in _derived_blocks(path.read_text(encoding="utf-8"))
            if _NOT_COUNTED_RE.search(block)
        ]
        for path in (_CONFIGURATION, _SECURITY)
    }

    assert stated, "configuration.md doesn't say derived files count toward the quota"
    assert stale == {_CONFIGURATION.name: [], _SECURITY.name: []}


def test_docs_attachments_conversion_configuration_states_the_256_mib_derived_cap() -> None:
    """Contract 12.4: one file's derived files are capped at 256 MiB, stated in the same
    paragraph, list item or table row as ``output_too_large`` (the zip-bomb guard's
    256 MiB, already documented, is another limit)."""
    found = [
        block
        for block in _blocks(_configuration_attachments())
        if "`output_too_large`" in block and _MIB_256_RE.search(block)
    ]

    assert found, "no paragraph, item or row states the 256 MiB cap with output_too_large"


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


def test_docs_attachments_conversion_security_sandbox_limit_names_what_a_parser_reaches() -> None:
    """Contract 12.9 (process audit I-1): the "isn't a sandbox" limitation names what a
    compromised parser can still do (every organization's files on the shared volume,
    the internal network and DNS) and the follow-up options (Landlock, a separate
    converter container)."""
    blocks = [
        block
        for block in _blocks(_SECURITY.read_text(encoding="utf-8"))
        if _SANDBOX_RE.search(block)
    ]
    text = " ".join(" ".join(block.split()) for block in blocks)
    checks = {
        "every organization's files": _EVERY_ORG_FILES_RE,
        "network": _NETWORK_RE,
        "DNS": _DNS_RE,
        "Landlock": _LANDLOCK_RE,
        "separate container": _SEPARATE_CONTAINER_RE,
    }

    assert blocks, "SECURITY.md has no block saying the conversion process isn't a sandbox"
    assert {name: bool(rx.search(text)) for name, rx in checks.items()} == dict.fromkeys(
        checks, True
    )
