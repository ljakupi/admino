"""Tests for invisible separators before a key (GH-270 contract sections 1 and 2).

An invisible character that the sanitizer removes, sitting between a word
character and a key (``a<SHY>sk-...``, ``a<ZWSP>sk-...``), used to glue the two
together once it was removed, so the key no longer started at a token start and
was shown in full (security audit N-1 and I-A). What this file pins:

- One removal set (Decision 1): ``models.sanitize_display_text`` (stored
  messages and the live reply) removes every character whose Unicode category
  is in ``models.CHAT_TITLE_BANNED_CATEGORIES`` (Cc, Cf, Cs, Zl, Zp) except tab,
  LF and CR. New in the message view: DEL, the soft hyphen, the word joiner,
  U+2061 to U+2064, U+180E, U+FFF9 to U+FFFB, tag characters and lone
  surrogates. Every other character is kept as today (NFKC still applies).
  ``models._CONTROL_CHAR_TABLE`` itself, and so the SSE data and the tool
  results sent to the model, doesn't change.
- Separator (Decision 2, criteria 1 and 3): a run of removed characters between
  an ASCII letter, digit or ``_`` and ``sk-`` is a separator. The key is
  redacted whole and the run removed, with nothing added:
  ``a<R>sk-proj-...`` gives ``a[CREDENTIAL_REDACTED]``. More removed characters
  may sit between the prefix's characters (``a<SHY>s<SHY>k-...``). The check
  runs on the NFKC form. This holds in message display text, model titles and
  fallback titles, for the prefixes ``a``, ``9``, ``_`` and ``key``, one removed
  character per class, at the start of the text and mid-sentence.
- When no key follows the run, the output is the text with the removed
  characters taken out (``ri<SHY>sk-free`` gives ``risk-free``). The accepted
  false positive ``ri<SHY>sk-free-investment-strategy-2026`` gives
  ``ri[CREDENTIAL_REDACTED]``. A key glued directly, with no run, is still not a
  key (GH-264 L-1).
- Split inside the body (criterion 2, GH-264 L-2): a key split 40 characters
  into its body by a removed character is joined and redacted whole, now in the
  message view too.

Titles are asserted on the marker and on ``surviving_chunks`` (no 8-character
chunk of the key's body left): their exact text may differ from the message
text only by the title cleanup (a leading ``_`` stripped, whitespace collapsed),
and ``truncate_title`` would hide a long leaked key mid-sentence, so the words
around it are short. Keys are built at runtime by tests/credential_keys.py; no
key literal is written here.
"""

from __future__ import annotations

import unicodedata
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import uuid4

import pytest

from admino import chat_titles, models
from admino.models import ChatMessageView, ChatResponse, SSEEvent
from tests.credential_keys import ApiKey, openai_project_key, surviving_chunks

if TYPE_CHECKING:
    from collections.abc import Callable

REDACTED = models._REDACTED

# Invisible characters, built with chr(): they are unreadable as literals.
SHY = chr(0x00AD)  # soft hyphen (Cf), outside the control table
WJ = chr(0x2060)  # word joiner (Cf), outside the control table
INVISIBLE_SEPARATOR = chr(0x2063)  # (Cf), outside the control table
MONGOLIAN_VOWEL_SEPARATOR = chr(0x180E)  # (Cf), outside the control table
ANNOTATION_ANCHOR = chr(0xFFF9)  # interlinear annotation anchor (Cf), outside the table
TAG_LATIN_A = chr(0xE0041)  # tag character (Cf), outside the control table
ZWSP = chr(0x200B)  # zero width space (Cf), in the control table
BOM = chr(0xFEFF)  # byte order mark (Cf), in the control table
LRM = chr(0x200E)  # left-to-right mark (Cf), in the control table
DEL = chr(0x7F)  # delete (Cc), outside the control table
VT = chr(0x0B)  # vertical tab (Cc, whitespace), in the control table
ESC = chr(0x1B)  # escape (Cc), in the control table
NEL = chr(0x85)  # next line (Cc, whitespace), in the control table
CSI = chr(0x9B)  # control sequence introducer (Cc), in the control table
LINE_SEP = chr(0x2028)  # (Zl), in the control table
PARA_SEP = chr(0x2029)  # (Zp), in the control table
SURROGATE = chr(0xD800)  # lone surrogate (Cs), outside the control table
NBSP = chr(0x00A0)
COMBINING_ACUTE = chr(0x0301)
VARIATION_SELECTOR_16 = chr(0xFE0F)
FULLWIDTH_A = chr(0xFF41)
FULLWIDTH_SK_HYPHEN = chr(0xFF53) + chr(0xFF4B) + chr(0xFF0D)  # fullwidth "sk-"

KEPT_CONTROLS = frozenset("\t\n\r")

# Criterion 3: the word characters a key used to be glued to.
PREFIXES = ("a", "9", "_", "key")

# One removed character per class (contract section 2), and one mixed run.
_RUNS = pytest.mark.parametrize(
    "run",
    [
        SHY,
        WJ,
        INVISIBLE_SEPARATOR,
        MONGOLIAN_VOWEL_SEPARATOR,
        ANNOTATION_ANCHOR,
        TAG_LATIN_A,
        ZWSP,
        BOM,
        LRM,
        DEL,
        VT,
        ESC,
        NEL,
        CSI,
        LINE_SEP,
        PARA_SEP,
        SURROGATE,
        SHY + ZWSP + DEL,
    ],
    ids=[
        "cf-soft-hyphen",
        "cf-word-joiner",
        "cf-invisible-separator",
        "cf-mongolian-vowel-separator",
        "cf-annotation-anchor",
        "cf-tag-character",
        "cf-zero-width-space",
        "cf-bom",
        "cf-lrm",
        "cc-del",
        "cc-vertical-tab",
        "cc-escape",
        "cc-nel",
        "cc-csi",
        "zl-line-separator",
        "zp-paragraph-separator",
        "cs-lone-surrogate",
        "mixed-shy-zwsp-del",
    ],
)
_POSITIONS = pytest.mark.parametrize("position", ["start", "mid-sentence"])
_TITLE_FUNCTIONS = pytest.mark.parametrize("function", ["sanitize_title", "fallback_title"])
FUNCTIONS = ("sanitize_display_text", "sanitize_title", "fallback_title")
_ALL_FUNCTIONS = pytest.mark.parametrize("function", FUNCTIONS)
# Characters that split a key inside its body (contract section 2).
_BODY_SPLITTERS = pytest.mark.parametrize(
    "char",
    [SHY, WJ, DEL, INVISIBLE_SEPARATOR, ZWSP],
    ids=["soft-hyphen", "word-joiner", "del", "invisible-separator", "zero-width-space"],
)


def _sanitizer(function: str) -> Callable[[str], str]:
    """The function under test, looked up when the test runs."""
    if function == "sanitize_display_text":
        return models.sanitize_display_text
    sanitizer: Callable[[str], str] = getattr(chat_titles, function)
    return sanitizer


def _place(position: str, core: str) -> str:
    """``core`` alone (the start of the text) or inside a short sentence."""
    return core if position == "start" else f"Rotate {core} today"


def _redacted_in_full(result: str, key: ApiKey) -> tuple[bool, list[str]]:
    """(the marker is present, the key's body chunks still in ``result``): ``(True, [])``."""
    return REDACTED in result, surviving_chunks(result, key)


def _stored_message(text: str) -> str:
    """The content a stored message shows (``ChatMessageView.content``)."""
    view = ChatMessageView(
        id=uuid4(),
        role="assistant",
        content=text,
        status="complete",
        created_at=datetime(2026, 10, 5, 12, tzinfo=UTC),
    )
    return view.content


def _live_reply(text: str) -> str:
    """The live reply of a chat turn (``ChatResponse.response``)."""
    return ChatResponse(chat_id=uuid4(), response=text).response


def _removal_set() -> list[str]:
    """Every character in ``CHAT_TITLE_BANNED_CATEGORIES`` except tab, LF and CR."""
    return [
        char
        for char in map(chr, range(0x110000))
        if char not in KEPT_CONTROLS
        and unicodedata.category(char) in models.CHAT_TITLE_BANNED_CATEGORIES
    ]


# ===========================================================================
# 1. One removal set (Decision 1)
# ===========================================================================


class TestRemovalSet:
    """The message view removes what a title removes: Cc, Cf, Cs, Zl, Zp but tab, LF, CR."""

    @pytest.mark.parametrize(
        "char",
        [
            DEL,
            SHY,
            WJ,
            chr(0x2061),
            chr(0x2062),
            INVISIBLE_SEPARATOR,
            chr(0x2064),
            MONGOLIAN_VOWEL_SEPARATOR,
            ANNOTATION_ANCHOR,
            chr(0xFFFA),
            chr(0xFFFB),
            TAG_LATIN_A,
            SURROGATE,
        ],
        ids=[
            "del",
            "soft-hyphen",
            "word-joiner",
            "function-application",
            "invisible-times",
            "invisible-separator",
            "invisible-plus",
            "mongolian-vowel-separator",
            "annotation-anchor",
            "annotation-separator",
            "annotation-terminator",
            "tag-character",
            "lone-surrogate",
        ],
    )
    def test_models_sanitize_display_text_removes_a_newly_removed_character(
        self, char: str
    ) -> None:
        assert models.sanitize_display_text(f"Bud{char}get") == "Budget"

    def test_models_sanitize_display_text_removes_every_banned_code_point(self) -> None:
        """Property: every Cc, Cf, Cs, Zl and Zp code point but tab, LF and CR is removed."""
        kept = [
            f"U+{ord(char):04X}"
            for char in _removal_set()
            if models.sanitize_display_text(f"Bud{char}get") != "Budget"
        ]
        assert kept == []

    def test_models_sanitize_display_text_keeps_every_code_point_outside_the_set(self) -> None:
        """Property: nothing outside the removal set is removed; NFKC is the only change.

        Planes 0, 1, 2 and 14 hold every category. Each character sits between
        two ``|`` so NFKC can't compose it with a neighbour.
        """
        removed = frozenset(_removal_set())
        planes = [*range(0x30000), *range(0xE0000, 0xE1000)]
        text = "|".join(char for char in map(chr, planes) if char not in removed)
        assert models.sanitize_display_text(text) == unicodedata.normalize("NFKC", text)

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("tab\there\nline\rend", "tab\there\nline\rend"),
            ("Budget review", "Budget review"),
            ("预算审查", "预算审查"),
            ("Trip " + chr(0x1F686) + " plan", "Trip " + chr(0x1F686) + " plan"),
            ("Café Zürich", "Café Zürich"),
            (f"Budget{NBSP}review", "Budget review"),
            (f"x{COMBINING_ACUTE}y", f"x{COMBINING_ACUTE}y"),
            (chr(0x2764) + VARIATION_SELECTOR_16, chr(0x2764) + VARIATION_SELECTOR_16),
        ],
        ids=[
            "tab-lf-cr",
            "letters",
            "cjk",
            "emoji",
            "accents",
            "nbsp-becomes-a-space-by-nfkc",
            "combining-mark",
            "variation-selector",
        ],
    )
    def test_models_sanitize_display_text_keeps_what_it_kept_before(
        self, text: str, expected: str
    ) -> None:
        assert models.sanitize_display_text(text) == expected

    def test_models_control_char_table_is_unchanged(self) -> None:
        """SSE data and tool results keep the soft hyphen and the word joiner: same table."""
        expected = (
            {code for code in range(32) if code not in (9, 10, 13)}
            | set(range(0x80, 0xA0))
            | set(range(0x200B, 0x2010))
            | set(range(0x202A, 0x202F))
            | {0x2028, 0x2029}
            | set(range(0x2066, 0x206A))
            | {0xFEFF}
        )
        table = models._CONTROL_CHAR_TABLE
        assert (set(table), set(table.values())) == (expected, {None})

    def test_models_sse_event_data_keeps_the_soft_hyphen_and_word_joiner(self) -> None:
        data = f"Bud{SHY}get {WJ}review"
        assert SSEEvent(event="token", data=data).data == data

    @pytest.mark.parametrize(
        "site",
        [_stored_message, _live_reply],
        ids=["stored-message", "live-reply"],
    )
    def test_models_message_display_sites_remove_the_set_and_redact_after_a_run(
        self, site: Callable[[str], str]
    ) -> None:
        key = openai_project_key()
        split = "a" + SHY + "s" + SHY + "k-" + key.text.removeprefix("sk-")
        assert (site(f"Bud{SHY}get{WJ}"), site(split)) == ("Budget", "a" + REDACTED)


# ===========================================================================
# 2. A run of removed characters before sk- is a separator (criterion 3 matrix)
# ===========================================================================


class TestSeparatorMatrix:
    """``a``, ``9``, ``_``, ``key`` + one removed character per class + a 164-char key."""

    @_RUNS
    @_POSITIONS
    def test_models_run_before_a_key_is_removed_and_the_key_redacted_whole(
        self, position: str, run: str
    ) -> None:
        key = openai_project_key()
        results = {
            word: models.sanitize_display_text(_place(position, word + run + key.text))
            for word in PREFIXES
        }
        assert results == {word: _place(position, word + REDACTED) for word in PREFIXES}

    @_RUNS
    @_POSITIONS
    @_TITLE_FUNCTIONS
    def test_chat_titles_run_before_a_key_is_redacted_whole_in_titles(
        self, function: str, position: str, run: str
    ) -> None:
        key = openai_project_key()
        sanitize = _sanitizer(function)
        results = {
            word: _redacted_in_full(sanitize(_place(position, word + run + key.text)), key)
            for word in PREFIXES
        }
        assert results == {word: (True, []) for word in PREFIXES}


# ===========================================================================
# 3. The run, the prefix and what follows (contract section 2)
# ===========================================================================

# "a", a removed run, then "sk-" with removed characters between its characters.
_SPLIT_PREFIXES = pytest.mark.parametrize(
    "split",
    ["a" + SHY + "s" + SHY + "k-", "a" + ZWSP + "s" + WJ + "k" + DEL + "-"],
    ids=["shy-between-s-and-k", "removed-character-in-every-gap"],
)


class TestSeparatorRules:
    """The lookahead past removed characters, the non-key cases and NFKC."""

    @_SPLIT_PREFIXES
    def test_models_lookahead_past_removed_characters_redacts_the_key(self, split: str) -> None:
        """Criterion 1: "right before" looks past further removed characters."""
        rest = openai_project_key().text.removeprefix("sk-")
        alone = models.sanitize_display_text(split + rest)
        in_sentence = models.sanitize_display_text(f"Rotate {split}{rest} today")
        assert (alone, in_sentence) == ("a" + REDACTED, f"Rotate a{REDACTED} today")

    @_SPLIT_PREFIXES
    @_TITLE_FUNCTIONS
    def test_chat_titles_lookahead_past_removed_characters_redacts_the_key(
        self, function: str, split: str
    ) -> None:
        key = openai_project_key()
        rest = key.text.removeprefix("sk-")
        sanitize = _sanitizer(function)
        results = (sanitize(split + rest), sanitize(f"Rotate {split}{rest} today"))
        assert [_redacted_in_full(result, key) for result in results] == [(True, [])] * 2

    @pytest.mark.parametrize(
        ("text", "expected"),
        [("ri" + SHY + "sk-free", "risk-free"), ("ask" + ZWSP + "-x", "ask-x")],
        ids=["risk-free", "ask-hyphen-x"],
    )
    def test_models_run_before_a_non_key_is_only_removed(self, text: str, expected: str) -> None:
        """Not a key after the run: the removed characters go, nothing is added."""
        assert models.sanitize_display_text(text) == expected

    @_ALL_FUNCTIONS
    def test_models_soft_hyphenated_long_word_is_the_accepted_false_positive(
        self, function: str
    ) -> None:
        """Criterion 2: the rule fails closed, so this ordinary word is redacted."""
        text = "ri" + SHY + "sk-free-investment-strategy-2026"
        assert _sanitizer(function)(text) == "ri" + REDACTED

    @pytest.mark.parametrize(
        "text",
        [
            FULLWIDTH_A + ZWSP + openai_project_key().text,
            "a" + ZWSP + FULLWIDTH_SK_HYPHEN + openai_project_key().text.removeprefix("sk-"),
        ],
        ids=["fullwidth-word-character", "fullwidth-sk-hyphen"],
    )
    def test_models_separator_check_runs_on_the_nfkc_form(self, text: str) -> None:
        assert models.sanitize_display_text(text) == "a" + REDACTED

    @pytest.mark.parametrize(
        "text",
        [
            FULLWIDTH_A + ZWSP + openai_project_key().text,
            "a" + ZWSP + FULLWIDTH_SK_HYPHEN + openai_project_key().text.removeprefix("sk-"),
        ],
        ids=["fullwidth-word-character", "fullwidth-sk-hyphen"],
    )
    @_TITLE_FUNCTIONS
    def test_chat_titles_separator_check_runs_on_the_nfkc_form(
        self, function: str, text: str
    ) -> None:
        key = openai_project_key()
        assert _redacted_in_full(_sanitizer(function)(text), key) == (True, [])

    def test_models_key_glued_directly_without_a_run_is_not_redacted(self) -> None:
        """GH-264 L-1, unchanged: ``ask-...`` is not a token start (a documented residual)."""
        text = f"Rotate a{openai_project_key().text} today"
        assert models.sanitize_display_text(text) == text


# ===========================================================================
# 4. A key split inside its body is joined and redacted whole (criterion 2)
# ===========================================================================


class TestSplitInsideTheBody:
    """GH-264 L-2 stays in both titles, and now holds in the message view too."""

    @_BODY_SPLITTERS
    def test_models_key_split_inside_its_body_is_redacted_whole_everywhere(self, char: str) -> None:
        """Message display text, model titles and fallback titles: one marker, no chunk."""
        key = openai_project_key()
        split = key.prefix + key.body[:40] + char + key.body[40:]
        results = {function: _sanitizer(function)(split) for function in FUNCTIONS}
        in_sentence = models.sanitize_display_text(f"Rotate {split} today")
        assert (results, in_sentence) == (
            dict.fromkeys(FUNCTIONS, REDACTED),
            f"Rotate {REDACTED} today",
        )

    def test_models_key_split_right_before_a_short_inner_sk_is_redacted_whole_everywhere(
        self,
    ) -> None:
        """The split falls before an ``sk-`` inside the body that isn't a key on its own.

        Decision 2: a run is a separator only when a key follows it, ``sk-`` and
        at least 20 key characters. ``sk-`` and 12 characters is not a key, so
        the run is only removed and the key is joined and redacted whole; a
        separator there would cut the key and leave its tail visible.
        """
        base = openai_project_key()
        key = ApiKey(base.prefix, base.body[:40] + "a" + "sk-" + base.body[40:52])
        split = key.prefix + key.body[:41] + SHY + key.body[41:]
        results = {function: _sanitizer(function)(split) for function in FUNCTIONS}
        assert (results, surviving_chunks("".join(results.values()), key)) == (
            dict.fromkeys(FUNCTIONS, REDACTED),
            [],
        )


# ===========================================================================
# 5. Separator boundaries: the word, the key minimum, the credential around the run
# ===========================================================================


def _alnum_body(length: int, step: int) -> str:
    """``length`` ASCII letters and digits in a fixed order: no key literal in the source."""
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(chars[(step * index + 3) % len(chars)] for index in range(length))


# Exactly 20 key characters with "_" and "-" (the sk- rule's minimum), no "sk-" inside.
_MINIMUM_RUN = "Zq7_Lm2-Pw9_Xc4-Rt6Y"


class TestSeparatorBoundaries:
    """An uppercase or mixed word, the 20-character minimum, other credentials split by the run."""

    @pytest.mark.parametrize("word", ["Z", "Key9"], ids=["uppercase-letter", "mixed-word"])
    def test_models_run_after_an_uppercase_or_mixed_word_is_a_separator(self, word: str) -> None:
        """Decision 2: any ASCII letter (either case), digit or ``_`` before the run."""
        key = openai_project_key()
        alone = models.sanitize_display_text(word + SHY + key.text)
        in_sentence = models.sanitize_display_text(f"Rotate {word}{ZWSP}{key.text} today")
        assert (alone, in_sentence) == (word + REDACTED, f"Rotate {word}{REDACTED} today")

    @pytest.mark.parametrize(
        "split_prefix",
        [
            pytest.param("a" + WJ + "sk-" + SHY + "proj-", id="removed-right-after-sk"),
            pytest.param("a" + ZWSP + "sk-pr" + DEL + "oj-", id="removed-inside-the-first-20"),
        ],
    )
    def test_models_key_after_a_run_counts_its_body_past_removed_characters(
        self, split_prefix: str
    ) -> None:
        """The key after the run is found past removed characters in its body too (Decision 2).

        ``split_prefix`` is ``a``, a run and ``sk-proj-`` with a removed character in it.
        """
        raw = split_prefix + openai_project_key().body
        results = {function: _sanitizer(function)(raw) for function in FUNCTIONS}
        assert results == dict.fromkeys(FUNCTIONS, "a" + REDACTED)

    @pytest.mark.parametrize(
        ("length", "expected"),
        [(20, "a" + REDACTED), (19, "ask-" + _MINIMUM_RUN[:19])],
        ids=["20-key-characters", "19-key-characters"],
    )
    def test_models_separator_needs_the_rules_minimum_of_20_key_characters(
        self, length: int, expected: str
    ) -> None:
        """``sk-`` and 20 key characters is a key after the run; 19 is not (the run only goes)."""
        raw = "a" + WJ + "sk-" + _MINIMUM_RUN[:length]
        results = {function: _sanitizer(function)(raw) for function in FUNCTIONS}
        assert results == dict.fromkeys(FUNCTIONS, expected)

    @pytest.mark.parametrize(
        ("head", "tail"),
        [
            pytest.param(
                "gh" + "p_" + _alnum_body(10, 7),
                "sk" + _alnum_body(26, 11),
                id="github-token-before-sk-without-hyphen",
            ),
            pytest.param(
                "GOC" + "SPX-" + _alnum_body(10, 13),
                "sk-" + _alnum_body(15, 17),
                id="google-client-secret-before-a-short-sk",
            ),
            pytest.param(
                "GOC" + "SPX-" + _alnum_body(10, 29),
                "sk-" + _alnum_body(19, 37),
                id="google-client-secret-before-an-sk-of-19",
            ),
            pytest.param(
                "xo" + "xb-" + _alnum_body(10, 19),
                "sk-" + _alnum_body(8, 23),
                id="slack-token-before-a-short-sk",
            ),
        ],
    )
    def test_models_credential_split_before_a_non_key_sk_is_joined_and_redacted_everywhere(
        self, head: str, tail: str
    ) -> None:
        """No key follows the run, so it is only removed and the credential it split joins again.

        A separator there would cut the GitHub token, the Google client secret or
        the Slack token below its own rule's minimum, or leave its tail visible.
        ``sk-`` and 19 key characters is one short of the ``sk-`` rule's minimum:
        no key follows there either, so the run is only removed.
        """
        raw = f"Use {head}{SHY}{tail} now"
        results = {function: _sanitizer(function)(raw) for function in FUNCTIONS}
        assert results == dict.fromkeys(FUNCTIONS, f"Use {REDACTED} now")

    @pytest.mark.parametrize(
        "char",
        [SHY, WJ, DEL, INVISIBLE_SEPARATOR],
        ids=["soft-hyphen", "word-joiner", "del", "invisible-separator"],
    )
    def test_models_message_view_joins_a_bearer_keyword_split_by_a_removed_character(
        self, char: str
    ) -> None:
        """The run isn't before a key, so it is only removed: the keyword joins again."""
        raw = f"Use Bea{char}rer abc123def456 now"
        assert models.sanitize_display_text(raw) == f"Use {REDACTED} now"

    def test_models_two_keys_after_runs_are_both_redacted_everywhere(self) -> None:
        key = openai_project_key()
        raw = f"a{SHY}{key.text} and b{ZWSP}{key.text}"
        results = {function: _sanitizer(function)(raw) for function in FUNCTIONS}
        assert results == dict.fromkeys(FUNCTIONS, f"a{REDACTED} and b{REDACTED}")
