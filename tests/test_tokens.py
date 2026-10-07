"""Tests for ``admino.tokens`` (GH-188 contract section 2): the shared token estimator.

The estimate stored per attachment (and reused by #190's budgeting) comes from two
pure formulas. What these tests pin down:

- Constants: ``TEXT_BYTES_PER_TOKEN == 4``, ``IMAGE_PIXELS_PER_TOKEN == 750``.
- ``estimate_text_tokens(text)`` = the number of ASCII digits ``0-9`` plus
  ``ceil(rest / 4)`` where ``rest`` is the UTF-8 byte length minus those digits:
  the contract's examples exactly (``"abcd"`` 1, ``"abcde"`` 2, ``"2026"`` 4,
  ``"ab 12"`` 3, ``"é"`` 1, ``""`` 0); the ceiling is taken once over all
  non-digit bytes (not per run between digits); bytes, not characters, are
  counted (CJK, emoji, the euro sign); non-ASCII digits (superscript two,
  Arabic-Indic three, fullwidth one) are ordinary bytes, not digits.
- ``estimate_image_tokens(width, height)`` = ``ceil(width * height / 750)`` with
  the contract's examples, and ``ValueError`` for a width or height below 1.
- "Token estimate ranges" (issue Tests): 4,000 characters of English or German
  prose land at the formula's value inside a 800 to 1,300 sanity band; a
  numbers-heavy table costs far more per character; a scanned A4 page at
  150 dpi and the largest uploaded image (2048 x 2048) have fixed estimates.
- Purity: the module imports the standard library only (it is shared by the
  server and the conversion worker, and later by #190).

The module is imported inside the ``tokens`` fixture, so this file collects
before it exists and every test fails on its own.
"""

from __future__ import annotations

import ast
import inspect
import math
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType

# Non-ASCII digits: str.isdigit()/isdecimal() and re's \d all accept them.
_SUPERSCRIPT_TWO = chr(0x00B2)
_ARABIC_INDIC_THREE = chr(0x0663)
_FULLWIDTH_ONE = chr(0xFF11)

_ENGLISH = (
    "The committee met early on a cold Monday morning to review the plan for "
    "the next quarter. Most of the discussion was about the budget, the hiring "
    "schedule and the timeline for the new office, which should open in spring "
    "2027 with room for 45 people. Several members asked for clearer monthly "
    "reporting, and the chair agreed to circulate a short written summary after "
    "each meeting so that nobody has to rely on memory alone. "
)
_GERMAN = (
    "Die Kommission prüfte am Montagmorgen die Planung für das nächste Quartal. "
    "Im Mittelpunkt standen das Budget, die Einstellungen und der Zeitplan für "
    "das neue Büro, das im Frühling 2027 mit Platz für 45 Personen eröffnet "
    "werden soll. Mehrere Mitglieder wünschten sich eine übersichtlichere "
    "Berichterstattung, und die Vorsitzende sagte zu, nach jeder Sitzung eine "
    "kurze schriftliche Zusammenfassung zu verschicken. "
)


@pytest.fixture
def tokens() -> ModuleType:
    """Import ``admino.tokens`` lazily so a missing module fails each test."""
    import admino.tokens as module

    return module


def _prose(paragraph: str, length: int) -> str:
    """Repeat ``paragraph`` and cut it to exactly ``length`` characters."""
    text = (paragraph * (length // len(paragraph) + 1))[:length]
    assert len(text) == length
    return text


# --- constants ------------------------------------------------------------


def test_tokens_constants_have_the_contract_values(tokens: ModuleType) -> None:
    assert (tokens.TEXT_BYTES_PER_TOKEN, tokens.IMAGE_PIXELS_PER_TOKEN) == (4, 750)


# --- estimate_text_tokens -------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", 0),
        ("abcd", 1),
        ("abcde", 2),
        ("2026", 4),
        ("ab 12", 3),
        ("é", 1),
    ],
    ids=["empty", "four-bytes", "five-bytes", "digits", "mixed", "two-byte-char"],
)
def test_tokens_text_contract_examples_match(tokens: ModuleType, text: str, expected: int) -> None:
    result = tokens.estimate_text_tokens(text)
    assert (result, type(result)) == (expected, int)


def test_tokens_text_ceiling_is_taken_once_over_all_non_digit_bytes(
    tokens: ModuleType,
) -> None:
    # 4 digits + 4 single letters between them: 4 + ceil(4 / 4) = 5 (a per-run
    # ceiling would give 4 + 4 = 8).
    assert tokens.estimate_text_tokens("1a2b3c4d") == 5


def test_tokens_text_counts_every_ascii_digit_as_one_token(tokens: ModuleType) -> None:
    # 10 digits + "-" twice and "." once = 10 + ceil(3 / 4) = 11.
    assert tokens.estimate_text_tokens("0123-4567.89") == 11


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("日本語", 3),  # 9 bytes
        ("€", 1),  # 3 bytes
        ("€€€€", 3),  # 12 bytes
        ("😀😀", 2),  # 8 bytes
        ("ab€12", 4),  # 2 digits + ceil(5 / 4)
    ],
    ids=["cjk", "euro", "four-euros", "emoji", "mixed-multibyte"],
)
def test_tokens_text_counts_utf8_bytes_not_characters(
    tokens: ModuleType, text: str, expected: int
) -> None:
    assert tokens.estimate_text_tokens(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (_SUPERSCRIPT_TWO * 4, 2),  # 8 bytes, no ASCII digit
        (_ARABIC_INDIC_THREE * 4, 2),  # 8 bytes, no ASCII digit
        (_FULLWIDTH_ONE * 4, 3),  # 12 bytes, no ASCII digit
        ("1" + _SUPERSCRIPT_TWO * 2, 2),  # 1 digit + ceil(4 / 4)
    ],
    ids=["superscript-two", "arabic-indic-three", "fullwidth-one", "ascii-and-superscript"],
)
def test_tokens_text_non_ascii_digits_count_as_bytes(
    tokens: ModuleType, text: str, expected: int
) -> None:
    assert tokens.estimate_text_tokens(text) == expected


# --- estimate_image_tokens ------------------------------------------------


@pytest.mark.parametrize(
    ("width", "height", "expected"),
    [
        (1, 1, 1),
        (750, 1, 1),
        (751, 1, 2),
        (1, 751, 2),
        (2048, 1536, 4195),
    ],
    ids=["one-pixel", "exactly-750", "751-wide", "751-high", "2048x1536"],
)
def test_tokens_image_contract_examples_match(
    tokens: ModuleType, width: int, height: int, expected: int
) -> None:
    result = tokens.estimate_image_tokens(width, height)
    assert (result, type(result)) == (expected, int)


@pytest.mark.parametrize(
    ("width", "height"),
    [(0, 10), (10, 0), (-1, 10), (10, -5), (0, 0)],
    ids=["zero-width", "zero-height", "negative-width", "negative-height", "both-zero"],
)
def test_tokens_image_size_below_one_raises_value_error(
    tokens: ModuleType, width: int, height: int
) -> None:
    with pytest.raises(ValueError):
        tokens.estimate_image_tokens(width, height)


# --- token estimate ranges (issue: Tests) ---------------------------------


def _reference(text: str) -> int:
    digits = sum(text.count(d) for d in "0123456789")
    return digits + math.ceil((len(text.encode("utf-8")) - digits) / 4)


@pytest.mark.parametrize(
    ("paragraph", "expected"),
    [(_ENGLISH, 1041), (_GERMAN, 1070)],
    ids=["english", "german"],
)
def test_tokens_text_4000_chars_of_prose_land_in_the_documented_band(
    tokens: ModuleType, paragraph: str, expected: int
) -> None:
    text = _prose(paragraph, 4000)
    result = tokens.estimate_text_tokens(text)
    assert (result, _reference(text), 800 <= result <= 1300) == (expected, expected, True)


def test_tokens_text_numbers_heavy_table_costs_more_than_prose(tokens: ModuleType) -> None:
    # A CSV-like block of 4,000 characters, 3 of every 4 a digit.
    text = _prose("123,", 4000)
    result = tokens.estimate_text_tokens(text)
    assert (result, result > 2 * 1300) == (3000 + 250, True)


def test_tokens_image_scanned_a4_page_at_150_dpi_has_a_fixed_estimate(
    tokens: ModuleType,
) -> None:
    # A4 (595 x 842 pt) at 150 dpi renders to about 1240 x 1754 px.
    result = tokens.estimate_image_tokens(1240, 1754)
    assert (result, 2500 <= result <= 3500) == (2900, True)


def test_tokens_image_largest_uploaded_image_has_a_fixed_estimate(
    tokens: ModuleType,
) -> None:
    # 2048 px is the longest edge after downscaling (common.MAX_IMAGE_EDGE).
    assert tokens.estimate_image_tokens(2048, 2048) == 5593


# --- purity ---------------------------------------------------------------


def test_tokens_module_imports_the_standard_library_only(tokens: ModuleType) -> None:
    tree = ast.parse(Path(inspect.getfile(tokens)).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add("." * node.level + (node.module or "").split(".")[0])
    allowed = set(sys.stdlib_module_names) | {"__future__"}
    assert sorted(imported - allowed) == []
