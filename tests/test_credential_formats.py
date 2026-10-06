"""Tests for the new key formats and the rule order (GH-270 contract sections 3, 4 and 8).

``models._strip_credentials`` redacts known credential formats from text shown
to users: the message view (``models.sanitize_display_text``: stored messages
and the live reply) and chat titles (``chat_titles.sanitize_title`` for a
model's title, ``chat_titles.fallback_title`` for the first message). What
this file pins:

- New rules (Decision 4, criterion 5): Stripe ``sk_live_``/``sk_test_`` (24+
  of ``[A-Za-z0-9]``), Google ``AIza`` (35+ of ``[A-Za-z0-9_-]``), GitHub
  ``github_pat_`` (82+ of ``[A-Za-z0-9_]``), ``gho_``/``ghu_``/``ghr_`` (36+
  alphanumerics), Hugging Face ``hf_`` (34+) and Groq ``gsk_`` (52+). One
  realistic key per format becomes one ``[CREDENTIAL_REDACTED]``
  (``models._REDACTED``), alone and mid-sentence, in the message view and in
  both titles; the text around it is kept.
- A new rule matches only at a token start: the text start or after a space,
  a newline, ``(``, ``"``, ``=``, ``:``, ``-`` or a non-ASCII letter (Chinese,
  accented Latin: the ``sk-`` rule's ASCII lookbehind); not right after an
  ASCII letter, digit or ``_``. The whole run is redacted with no upper bound (a run
  2100 characters past the minimum leaves no tail: past every bound an existing
  rule uses). Near misses stay exactly as
  they are: the prefix glued to ``x``, ``_`` or ``2``, and a body one character
  short of the minimum. Each near miss is checked next to the same key at a
  token start (or at exactly the minimum), which is redacted: the pair pins
  where the boundary sits.
- Decision 2 for the new prefixes: ``a<ZWSP>`` + key and ``a<SHY>`` + a prefix
  split by a soft hyphen give ``a[CREDENTIAL_REDACTED]``: the removed
  characters separate the word from the key instead of gluing them together.
- Rule order (Decision 3, criterion 4): the ``sk-`` rule and the new rules run
  before the Bearer and JWT rules. ``Bearer`` + a key run over 2048 characters
  is one marker with no tail (the Bearer rule's 2048 bound cut it before), and
  a key directly followed by ``.<16 alnum>.<16 alnum>`` whose body holds an
  inner ``ey`` is redacted whole, its two dot segments kept (the JWT rule
  started at the inner ``ey`` and left the key's head visible). In
  ``models._CREDENTIAL_PATTERNS`` every pattern that matches an ``sk-`` key or
  a new-format key comes before the patterns that match a Bearer header and a
  JWT (each found by what it matches, not by index).
- Regression guards (they pass before GH-270 by design): ``Bearer`` + a
  164-character ``sk-proj-`` key is still exactly one marker, alone and in a
  sentence, in the message view and in titles; the existing ``ghp_``/``ghs_``
  rule still matches anywhere, glued to a word too; the rules GH-270 doesn't
  move keep their relative order.
- Titles redact before they trim edge characters (Decision 7): a model title
  strips leading and trailing quote and emphasis characters (``_``, ``*``,
  quotes, whitespace), and a Google ``AIza`` or GitHub ``github_pat_`` body may
  end in ``_``. A key of exactly the minimum length whose last body character
  is ``_`` is redacted whole in a model title and in a fallback title: alone, at
  the end of a sentence, mid-sentence, in ``**`` emphasis and in double quotes.
  Trimming first would cut the ``_``, leave the key one character short of its
  rule and show the rest. (A key glued right after a leading ``_`` is the
  documented "glued to ``_``" residual, so ``_..._`` is not a case here.)

Keys are built at runtime by tests/credential_keys.py (a prefix concatenated
from pieces, a seeded random body); no key literal is written in a test file.
"""

from __future__ import annotations

import random
import string
from typing import TYPE_CHECKING

import pytest

from admino import chat_titles, models
from tests.credential_keys import (
    ALNUM_CHARS,
    GITHUB_FINE_GRAINED,
    GOOGLE_API,
    HUGGING_FACE,
    KEY_CHARS,
    NEW_KEY_FORMATS,
    ApiKey,
    KeyFormat,
    api_key,
    openai_project_key,
    surviving_chunks,
)

if TYPE_CHECKING:
    from collections.abc import Callable

REDACTED = models._REDACTED
ZWSP = chr(0x200B)  # zero-width space: in _CONTROL_CHAR_TABLE
SHY = chr(0x00AD)  # soft hyphen: removed from the message view by GH-270 (Decision 1)

# The realistic key's total length per format (contract section 4's table).
_REALISTIC_TOTAL = {
    "stripe-live": 107,
    "stripe-test": 107,
    "google-api": 39,
    "github-fine-grained": 93,
    "github-oauth": 40,
    "github-user": 40,
    "github-refresh": 40,
    "hugging-face": 37,
    "groq": 56,
}
# The Bearer rule's bound is 2048 characters: these runs are longer.
_PAST_BEARER_BOUND = 2100
# Characters past the minimum of a "much longer" run: past every bound an existing rule
# uses (255 GitHub and Slack, 512 Google, 2048 Bearer and JWT), so no copied bound passes.
_FAR_PAST_THE_MINIMUM = _PAST_BEARER_BOUND

_FORMATS = pytest.mark.parametrize("fmt", NEW_KEY_FORMATS, ids=[f.name for f in NEW_KEY_FORMATS])
_TITLE_FUNCTIONS = pytest.mark.parametrize("function", ["sanitize_title", "fallback_title"])

# The existing GitHub rule (gh[ps]_ + 36 to 255 alphanumerics), unchanged by GH-270.
_GITHUB_CLASSIC = KeyFormat("github-classic", "gh" + "p_", ALNUM_CHARS, 36, 36, seed=36)
_GITHUB_SERVER = KeyFormat("github-server", "gh" + "s_", ALNUM_CHARS, 36, 36, seed=136)


def _display(text: str) -> str:
    """The message view of ``text`` (``models.sanitize_display_text``)."""
    return models.sanitize_display_text(text)


def _title(function: str, text: str) -> str:
    """``chat_titles.sanitize_title`` or ``chat_titles.fallback_title`` of ``text``."""
    title: Callable[[str], str] = getattr(chat_titles, function)
    return title(text)


# ===========================================================================
# 1. One realistic key per new format is redacted in full
# ===========================================================================


class TestRealisticKeys:
    """Each new format's realistic key is one marker in the message view (criterion 5)."""

    @_FORMATS
    def test_models_realistic_key_alone_is_redacted_whole(self, fmt: KeyFormat) -> None:
        key = fmt.key()
        assert len(key.text) == _REALISTIC_TOTAL[fmt.name]
        result = _display(key.text)
        assert result == REDACTED
        assert surviving_chunks(result, key) == []

    @_FORMATS
    def test_models_realistic_key_in_a_sentence_is_redacted_and_the_text_kept(
        self, fmt: KeyFormat
    ) -> None:
        key = fmt.key()
        result = _display(f"Please rotate {key.text}. It leaked yesterday.")
        assert result == f"Please rotate {REDACTED}. It leaked yesterday."
        assert surviving_chunks(result, key) == []


class TestRealisticKeysInTitles:
    """The same keys are redacted in full in a model title and in a fallback title."""

    @_FORMATS
    @_TITLE_FUNCTIONS
    def test_chat_titles_realistic_key_is_redacted_whole_alone_and_in_a_sentence(
        self, function: str, fmt: KeyFormat
    ) -> None:
        """The key mid-sentence is short of 80 characters once redacted, so no cut hides it."""
        key = fmt.key()
        alone = _title(function, key.text)
        in_sentence = _title(function, f"Rotate {key.text} today")
        assert (alone, in_sentence) == (REDACTED, f"Rotate {REDACTED} today")
        assert surviving_chunks(alone + in_sentence, key) == []


# ===========================================================================
# 2. Where a new-format key starts, how long it runs, and near misses
# ===========================================================================


class TestTokenStart:
    """A new-format key starts at a token start: not right after an ASCII letter, digit or ``_``."""

    @pytest.mark.parametrize(
        "before",
        ["", "key ", "key\n", "key(", 'key"', "key=", "key:", "key-"],
        ids=[
            "start-of-text",
            "space",
            "newline",
            "parenthesis",
            "double-quote",
            "equals",
            "colon",
            "hyphen",
        ],
    )
    @_FORMATS
    def test_models_new_format_key_after_a_token_start_is_redacted(
        self, fmt: KeyFormat, before: str
    ) -> None:
        key = fmt.key()
        assert _display(f"{before}{key.text} end") == f"{before}{REDACTED} end"

    @pytest.mark.parametrize("before", ["我的密钥是", "Clé"], ids=["cjk", "accented-latin"])
    @_FORMATS
    def test_models_new_format_key_after_a_non_ascii_letter_is_redacted(
        self, fmt: KeyFormat, before: str
    ) -> None:
        """Only an ASCII letter, digit or ``_`` keeps a prefix inside a word (the ``sk-`` rule).

        Python's Unicode ``\\b`` and ``\\w`` count these letters as word
        characters, so a rule built on them would leave the key in full.
        """
        key = fmt.key()
        assert (before[-1].isalpha(), before[-1].isascii()) == (True, False)
        result = _display(before + key.text)
        assert result == before + REDACTED
        assert surviving_chunks(result, key) == []

    @pytest.mark.parametrize("glue", ["x", "_", "2"], ids=["letter", "underscore", "digit"])
    @_FORMATS
    def test_models_new_format_prefix_inside_a_longer_word_is_kept(
        self, fmt: KeyFormat, glue: str
    ) -> None:
        """Glued to an ASCII letter, ``_`` or digit the prefix is part of a word, not a key.

        The same key at a token start is redacted (the pair pins the boundary).
        """
        key = fmt.key()
        glued = f"id {glue}{key.text} here"
        assert (_display(glued), _display(f"id {key.text} here")) == (
            glued,
            f"id {REDACTED} here",
        )

    @_FORMATS
    def test_models_new_format_body_one_short_of_the_minimum_is_kept(self, fmt: KeyFormat) -> None:
        """``minimum - 1`` body characters are not a key; exactly ``minimum`` are."""
        short, exact = fmt.key(fmt.minimum - 1), fmt.key(fmt.minimum)
        assert exact.body[:-1] == short.body
        kept = f"id {short.text} here"
        assert (_display(kept), _display(f"id {exact.text} here")) == (
            kept,
            f"id {REDACTED} here",
        )


class TestLongRuns:
    """The whole run is redacted, with no upper bound: a longer run never leaves a tail."""

    @_FORMATS
    def test_models_new_format_run_far_past_the_minimum_is_redacted_whole(
        self, fmt: KeyFormat
    ) -> None:
        key = fmt.key(fmt.minimum + _FAR_PAST_THE_MINIMUM)
        result = _display(f"Leaked: {key.text} (rotated)")
        assert result == f"Leaked: {REDACTED} (rotated)"
        assert surviving_chunks(result, key) == []


# ===========================================================================
# 3. Decision 2 for the new prefixes: removed characters separate, never glue
# ===========================================================================


def _after_zero_width_space(key: ApiKey) -> str:
    """``a`` + ZWSP + the key: without the ZWSP, ``a`` would glue onto the prefix."""
    return "a" + ZWSP + key.text


def _after_soft_hyphen_with_a_split_prefix(key: ApiKey) -> str:
    """``a`` + SHY + the prefix split by another SHY after its first character + the body."""
    return "a" + SHY + key.prefix[0] + SHY + key.prefix[1:] + key.body


_SEPARATED = pytest.mark.parametrize(
    "separate",
    [_after_zero_width_space, _after_soft_hyphen_with_a_split_prefix],
    ids=["a-zwsp-key", "a-shy-split-prefix"],
)


class TestSeparatorBeforeANewFormatKey:
    """A run of removed characters between a word character and a key start is a separator.

    Decision 2: the key is redacted and the run removed, nothing added, so
    ``a<ZWSP>hf_...`` gives ``a[CREDENTIAL_REDACTED]``; the check looks past
    removed characters inside the prefix too (``a<SHY>h<SHY>f_...``).
    """

    @_SEPARATED
    @_FORMATS
    def test_models_new_format_key_after_a_word_and_removed_characters_is_redacted(
        self, fmt: KeyFormat, separate: Callable[[ApiKey], str]
    ) -> None:
        key = fmt.key()
        raw = separate(key)
        alone, in_sentence = _display(raw), _display(f"Rotate {raw} today")
        assert (alone, in_sentence) == ("a" + REDACTED, f"Rotate a{REDACTED} today")
        assert surviving_chunks(alone + in_sentence, key) == []

    @_SEPARATED
    @_FORMATS
    @_TITLE_FUNCTIONS
    def test_chat_titles_new_format_key_after_a_word_and_removed_characters_is_redacted(
        self, function: str, fmt: KeyFormat, separate: Callable[[ApiKey], str]
    ) -> None:
        key = fmt.key()
        raw = separate(key)
        alone, in_sentence = _title(function, raw), _title(function, f"Rotate {raw} today")
        assert (REDACTED in alone, REDACTED in in_sentence) == (True, True)
        assert surviving_chunks(alone + in_sentence, key) == []


# ===========================================================================
# 4. Rule order: the sk- rule and the new rules run before Bearer and JWT
# ===========================================================================


def _bearer_sk_run() -> tuple[str, ApiKey]:
    """``Bearer `` + ``sk-`` + 2100 key characters (past the Bearer rule's 2048 bound)."""
    key = api_key("sk-", 3 + _PAST_BEARER_BOUND, seed=2100)
    return "Bearer " + key.text, key


def _bearer_new_format_run() -> tuple[str, ApiKey]:
    """``Bearer `` + ``hf_`` + 2100 alphanumerics: a new-format key over 2048 characters."""
    key = HUGGING_FACE.key(_PAST_BEARER_BOUND)
    return "Bearer " + key.text, key


_LOWER_ALNUM = string.ascii_lowercase + string.digits


def _key_then_two_dot_segments(prefix: str, body_chars: str, total: int) -> tuple[ApiKey, str]:
    """A key whose body holds an inner ``ey`` at index 10, and the two segments after it.

    Returns the key and the ``.<16>.<16>`` tail written right after it. The
    JWT rule's first possible start is that inner ``ey`` (nothing before it
    holds ``ey``), followed by more than 16 key characters, so before GH-270 it
    redacted from there and left the prefix and the body's first 10 characters
    visible. The segments are lowercase and digits: no rule matches them.
    """
    rng = random.Random(total)  # noqa: S311 - deterministic test data, not a secret
    head = "".join(rng.choice(ALNUM_CHARS) for _ in range(10))
    tail = "".join(rng.choice(body_chars) for _ in range(total - len(prefix) - 12))
    seg2, seg3 = ("".join(rng.choice(_LOWER_ALNUM) for _ in range(16)) for _ in range(2))
    key = ApiKey(prefix, head + "ey" + tail)
    assert ("ey" in prefix + head, len(tail) >= 16, len(key.text)) == (False, True, total)
    return key, f".{seg2}.{seg3}"


_TWO_SEGMENT_KEYS = pytest.mark.parametrize(
    ("prefix", "body_chars", "total"),
    [("sk-" + "proj-", KEY_CHARS, 164), ("hf" + "_", ALNUM_CHARS, 37)],
    ids=["sk-proj-164", "hugging-face-37"],
)


class TestRuleOrder:
    """Decision 3: a key is redacted whole before the Bearer and JWT rules can cut it."""

    @pytest.mark.parametrize(
        "make", [_bearer_sk_run, _bearer_new_format_run], ids=["sk-run", "hugging-face-run"]
    )
    def test_models_bearer_with_a_key_run_past_2048_is_one_marker(
        self, make: Callable[[], tuple[str, ApiKey]]
    ) -> None:
        """The Bearer rule stops at 2048 characters; redacting the key first leaves no tail."""
        raw, key = make()
        assert len(key.text) > 2048
        result = _display(raw)
        assert result == REDACTED
        assert surviving_chunks(result, key) == []

    @_TWO_SEGMENT_KEYS
    @pytest.mark.parametrize("sentence", [False, True], ids=["alone", "in-sentence"])
    def test_models_key_followed_by_two_dot_segments_is_redacted_whole(
        self, prefix: str, body_chars: str, total: int, sentence: bool
    ) -> None:
        """The key run ends at the dot; the two segments after it are no credential and stay."""
        key, segments = _key_then_two_dot_segments(prefix, body_chars, total)
        raw = key.text + segments
        expected = REDACTED + segments
        if sentence:
            raw, expected = f"token: {raw} end", f"token: {expected} end"
        result = _display(raw)
        assert result == expected
        assert surviving_chunks(result, key) == []

    @pytest.mark.parametrize("sentence", [False, True], ids=["alone", "in-sentence"])
    def test_models_bearer_with_a_realistic_key_is_still_one_marker(self, sentence: bool) -> None:
        """Regression guard (passes before GH-270): ``Bearer sk-...`` is exactly one marker."""
        key = openai_project_key()
        if sentence:
            raw, expected = f"Authorization: Bearer {key.text} ok", f"Authorization: {REDACTED} ok"
        else:
            raw, expected = f"Bearer {key.text}", REDACTED
        result = _display(raw)
        assert result == expected
        assert surviving_chunks(result, key) == []


def _lower_alnum(length: int, *, seed: int) -> str:
    """``length`` seeded lowercase letters and digits: no new rule matches them."""
    rng = random.Random(seed)  # noqa: S311 - deterministic test data, not a secret
    return "".join(rng.choice(_LOWER_ALNUM) for _ in range(length))


def _rule_indexes(sample: str) -> list[int]:
    """The indexes of the patterns in ``models._CREDENTIAL_PATTERNS`` that match in ``sample``."""
    return [i for i, rule in enumerate(models._CREDENTIAL_PATTERNS) if rule.search(sample)]


_BEARER_SAMPLE = "Bearer " + _lower_alnum(12, seed=1)
_JWT_SAMPLE = ".".join(
    ["ey" + _lower_alnum(20, seed=2), _lower_alnum(20, seed=3), _lower_alnum(20, seed=4)]
)
_AWS_KEY_CHARS = string.ascii_uppercase + string.digits
_AWS_KEY_BODY = "".join(random.Random(10).choice(_AWS_KEY_CHARS) for _ in range(16))  # noqa: S311

# One sample per rule GH-270 doesn't move, in the rules' order before GH-270.
_UNMOVED_RULE_SAMPLES = (
    "1//" + _lower_alnum(24, seed=5),  # Google OAuth refresh token
    "ya29." + _lower_alnum(24, seed=6),  # Google OAuth access token
    _JWT_SAMPLE,
    _BEARER_SAMPLE,
    "GOCSPX-" + _lower_alnum(24, seed=7),  # Google OAuth client secret
    "rk" + "_live_" + _lower_alnum(24, seed=8),  # Stripe restricted key (live)
    "rk" + "_test_" + _lower_alnum(24, seed=9),  # Stripe restricted key (test)
    _GITHUB_CLASSIC.key().text,  # GitHub ghp_
    "AK" + "IA" + _AWS_KEY_BODY,  # AWS access key ID
    "xo" + "xb-" + _lower_alnum(12, seed=11),  # Slack
)


class TestRuleOrderInThePatternList:
    """Decision 3 in ``models._CREDENTIAL_PATTERNS``, each rule found by what it matches.

    The behaviour above pins the order for ``sk-`` and ``hf_`` only. This pins it
    for every new rule: a single new rule left after Bearer or JWT would get its
    key cut the same way.
    """

    def test_models_sk_and_new_rules_come_before_the_bearer_and_jwt_rules(self) -> None:
        first_cutter = min(_rule_indexes(_BEARER_SAMPLE) + _rule_indexes(_JWT_SAMPLE))
        keys = {"sk-proj": openai_project_key()} | {f.name: f.key() for f in NEW_KEY_FORMATS}
        late = {
            name: indexes
            for name, key in keys.items()
            if not (indexes := _rule_indexes(key.text)) or max(indexes) >= first_cutter
        }
        assert late == {}

    def test_models_the_other_rules_keep_their_relative_order(self) -> None:
        """Regression guard (passes before GH-270): only the key rules move up."""
        firsts = [(_rule_indexes(sample) or [-1])[0] for sample in _UNMOVED_RULE_SAMPLES]
        assert -1 not in firsts
        assert firsts == sorted(set(firsts))


def _two_segment_case() -> tuple[str, ApiKey]:
    """The ``sk-proj-`` key with an inner ``ey``, directly followed by two dot segments."""
    key, segments = _key_then_two_dot_segments("sk-" + "proj-", KEY_CHARS, 164)
    return key.text + segments, key


class TestRuleOrderInTitles:
    """The same order cases in a model title and a fallback title: a marker, no key chunk."""

    @pytest.mark.parametrize(
        "make",
        [_bearer_sk_run, _bearer_new_format_run, _two_segment_case],
        ids=["bearer-sk-run", "bearer-hugging-face-run", "key-then-two-dot-segments"],
    )
    @_TITLE_FUNCTIONS
    def test_chat_titles_key_is_redacted_before_the_bearer_and_jwt_rules(
        self, function: str, make: Callable[[], tuple[str, ApiKey]]
    ) -> None:
        raw, key = make()
        result = _title(function, raw)
        assert REDACTED in result
        assert surviving_chunks(result, key) == []

    @_TITLE_FUNCTIONS
    def test_chat_titles_bearer_with_a_realistic_key_is_still_one_marker(
        self, function: str
    ) -> None:
        """Regression guard (passes before GH-270)."""
        key = openai_project_key()
        result = _title(function, f"Authorization: Bearer {key.text} ok")
        assert result == f"Authorization: {REDACTED} ok"
        assert surviving_chunks(result, key) == []


# ===========================================================================
# 5. The existing GitHub rule is unchanged
# ===========================================================================


class TestExistingGithubRule:
    """``ghp_``/``ghs_`` keep matching anywhere: GH-270 adds no token-start rule to them."""

    @pytest.mark.parametrize(
        "fmt", [_GITHUB_CLASSIC, _GITHUB_SERVER], ids=["github-classic", "github-server"]
    )
    def test_models_existing_github_token_glued_to_a_word_is_still_redacted(
        self, fmt: KeyFormat
    ) -> None:
        """Regression guard (passes before GH-270): ``x`` + ``ghp_`` + 36 alphanumerics."""
        key = fmt.key()
        result = _display(f"id x{key.text} here")
        assert result == f"id x{REDACTED} here"
        assert surviving_chunks(result, key) == []


# ===========================================================================
# 6. Titles redact before they trim edge characters (Decision 7)
# ===========================================================================


def _ending_in_underscore(fmt: KeyFormat) -> ApiKey:
    """``fmt``'s key with exactly its minimum body length, the last body character ``_``.

    Without that ``_`` the body is one character short of the rule's minimum.
    """
    key = fmt.key(fmt.minimum)
    return ApiKey(key.prefix, key.body[:-1] + "_")


# Where the key sits in the title text: ``{key}`` is replaced by the key.
_EDGE_PLACEMENTS = {
    "alone": "{key}",
    "end-of-sentence": "Rotate {key}",
    "mid-sentence": "Rotate {key} today",
    "bold": "**{key}**",
    "double-quotes": '"{key}"',
}
# What each title function makes of those texts once the key is redacted: a model
# title strips the surrounding emphasis and quotes, a fallback title keeps them.
_EXPECTED_TITLES = {
    "sanitize_title": {
        "alone": REDACTED,
        "end-of-sentence": f"Rotate {REDACTED}",
        "mid-sentence": f"Rotate {REDACTED} today",
        "bold": REDACTED,
        "double-quotes": REDACTED,
    },
    "fallback_title": {
        "alone": REDACTED,
        "end-of-sentence": f"Rotate {REDACTED}",
        "mid-sentence": f"Rotate {REDACTED} today",
        "bold": f"**{REDACTED}**",
        "double-quotes": f'"{REDACTED}"',
    },
}


class TestTitlesRedactBeforeTrimming:
    """Decision 7: a key whose body ends in ``_`` is redacted before the edges are trimmed.

    A model title strips trailing ``_``, ``*``, quotes and whitespace. Trimming
    before the redaction would cut the key's last ``_``, leave ``minimum - 1``
    body characters (no longer a key) and show them in full.
    """

    @pytest.mark.parametrize(
        "fmt", [GOOGLE_API, GITHUB_FINE_GRAINED], ids=["google-api", "github-fine-grained"]
    )
    @_TITLE_FUNCTIONS
    def test_chat_titles_key_ending_in_underscore_is_redacted_whole_wherever_it_sits(
        self, function: str, fmt: KeyFormat
    ) -> None:
        key = _ending_in_underscore(fmt)
        assert (len(key.body), key.body[-1]) == (fmt.minimum, "_")
        results = {
            placement: _title(function, text.format(key=key.text))
            for placement, text in _EDGE_PLACEMENTS.items()
        }
        assert results == _EXPECTED_TITLES[function]
        assert all(REDACTED in result for result in results.values())
        assert surviving_chunks(" ".join(results.values()), key) == []
