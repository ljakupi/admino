"""Tests for the widened ``sk-`` credential rule (GH-264 contract sections 1, 2 and 6).

``models._strip_credentials`` redacts known credential formats from text shown
to users. Its generic ``sk-`` pattern missed current key formats: OpenAI
``sk-proj-`` keys (about 164 characters, with ``_`` and ``-``) were not matched
at all and Anthropic ``sk-ant-api03-`` keys were cut at their first ``_``, so
the rest survived. What this file pins:

- A key is ``sk-`` at the start of the text or right after a character that is
  not an ASCII letter, an ASCII digit or ``_``, followed by a run of at least 20
  key characters (``A-Z``, ``a-z``, ``0-9``, ``_``, ``-``). The whole run
  becomes one ``[CREDENTIAL_REDACTED]`` (``models._REDACTED``); the text before
  and after it (spaces, ``.``, ``,``, ``)``, words) is kept as it is.
- Formats redacted in full: ``sk-proj-`` (164 characters), ``sk-svcacct-``,
  ``sk-admin-``, plain ``sk-`` with ``_``, ``sk-ant-api03-`` (108, with ``_``)
  and ``sk-ant-admin01-``; a 256-character key; a key ending in ``-``. A longer
  run (300 characters) fails closed: redacted whole, no tail left. No
  8-character chunk of a key's body survives anywhere.
- A key starts after a space, a newline, ``-``, ``(``, ``"``, ``'``, ``=`` or
  ``:``, and after a non-ASCII letter (Chinese, Japanese, accented Latin:
  security audit L-1). Not a key: ``sk-`` inside a word
  (``risk-free-investment-strategy-2026``, a long ``ask-...`` or ``Ask-...``
  word, ``_sk-...``, ``2sk-...``) and ``sk-`` followed by 19 key characters (20
  is redacted). Two keys in one text are two markers.
- ``models.sanitize_display_text`` is the public display-text sanitizer
  (``_sanitize_display_text`` before GH-264). The ``sanitize`` fixture looks it
  up when a test runs, so this file collects before the rename and every test
  fails on its own.
- The rule applies at every display site: a stored message
  (``ChatMessageView.content``), the live reply (``ChatResponse.response``) and
  the tool arguments of ``ToolCallRecord`` and ``PendingConfirmationSummary``.
  Chat titles (model and fallback) are pinned in tests/test_chat_titles.py.

Keys are built at runtime by tests/credential_keys.py (a fixed prefix and a
seeded random body); no key literal is written in a test file.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import uuid4

import pytest

from admino import models
from admino.models import (
    ChatMessageView,
    ChatResponse,
    PendingConfirmationSummary,
    ToolCallRecord,
)
from tests.credential_keys import (
    ApiKey,
    anthropic_api03_key,
    api_key,
    openai_project_key,
    surviving_chunks,
)

if TYPE_CHECKING:
    from collections.abc import Callable

REDACTED = models._REDACTED

# Key characters that follow a non-key prefix in the "not a key" cases: 30 of them,
# with "_" and "-", and no "sk-" inside.
_INNER_RUN = "Zq7_Lm2-Pw9_Xc4-Rt6_Yb1-Hn8_Kd"
# Exactly 20 key characters with "_" and "-": today's minimum length.
_MINIMUM_RUN = "Zq7_Lm2-Pw9_Xc4-Rt6Y"


@pytest.fixture()
def sanitize() -> Callable[[str], str]:
    """``models.sanitize_display_text``, looked up when the test runs (GH-264 renames it)."""
    function: Callable[[str], str] = models.sanitize_display_text
    return function


def _plain_key(total: int, seed: int) -> ApiKey:
    """A plain ``sk-`` key of ``total`` characters holding ``_`` and ``-``."""
    return api_key("sk-", total, seed=seed)


# ===========================================================================
# 1. Current key formats are redacted in full
# ===========================================================================


class TestKeyFormats:
    """Every current format, and every length up to 256 (longer: fail closed)."""

    @pytest.mark.parametrize(
        ("key", "total"),
        [
            (openai_project_key(), 164),
            (api_key("sk-" + "svcacct-", 164, seed=11), 164),
            (api_key("sk-" + "admin-", 164, seed=9), 164),
            (_plain_key(51, seed=51), 51),
            (anthropic_api03_key(), 108),
            (api_key("sk-" + "ant-admin01-", 108, seed=1501), 108),
        ],
        ids=[
            "openai-project-164",
            "openai-service-account",
            "openai-admin",
            "plain-with-underscore",
            "anthropic-api03-108",
            "anthropic-admin01",
        ],
    )
    def test_models_current_key_format_alone_is_redacted_whole(
        self, sanitize: Callable[[str], str], key: ApiKey, total: int
    ) -> None:
        assert (len(key.text), "_" in key.body, "-" in key.body) == (total, True, True)
        result = sanitize(key.text)
        assert result == REDACTED
        assert surviving_chunks(result, key) == []

    def test_models_key_of_256_characters_is_redacted_whole(
        self, sanitize: Callable[[str], str]
    ) -> None:
        key = _plain_key(256, seed=256)
        result = sanitize(key.text)
        assert result == REDACTED
        assert surviving_chunks(result, key) == []

    def test_models_run_of_300_characters_fails_closed_and_is_redacted_whole(
        self, sanitize: Callable[[str], str]
    ) -> None:
        """Longer than any key format: still one marker, never a cut with a tail left."""
        key = _plain_key(300, seed=300)
        result = sanitize(f"Leaked: {key.text} (rotated)")
        assert result == f"Leaked: {REDACTED} (rotated)"
        assert surviving_chunks(result, key) == []

    def test_models_key_ending_in_a_hyphen_is_redacted_with_it(
        self, sanitize: Callable[[str], str]
    ) -> None:
        """The whole run goes: its last key character too, even when it isn't a word character."""
        key = ApiKey("sk-", _plain_key(39, seed=39).body + "-")
        assert sanitize(f"Rotate {key.text} now") == f"Rotate {REDACTED} now"


# ===========================================================================
# 2. The text around a key is kept
# ===========================================================================


class TestKeyInText:
    """Only the key's run is replaced; the text before and after it stays."""

    def test_models_key_in_a_sentence_is_redacted_and_the_text_kept(
        self, sanitize: Callable[[str], str]
    ) -> None:
        key = openai_project_key()
        result = sanitize(f"Please rotate {key.text}. It leaked yesterday.")
        assert result == f"Please rotate {REDACTED}. It leaked yesterday."
        assert surviving_chunks(result, key) == []

    def test_models_punctuation_after_a_key_is_kept(self, sanitize: Callable[[str], str]) -> None:
        project, anthropic = openai_project_key(), anthropic_api03_key()
        plain = _plain_key(51, seed=51)
        text = f"Keys: {project.text}, ({anthropic.text}) and {plain.text}."
        assert sanitize(text) == f"Keys: {REDACTED}, ({REDACTED}) and {REDACTED}."

    def test_models_two_keys_in_one_text_become_two_markers(
        self, sanitize: Callable[[str], str]
    ) -> None:
        project, anthropic = openai_project_key(), anthropic_api03_key()
        result = sanitize(f"{project.text}\n{anthropic.text}")
        assert result == f"{REDACTED}\n{REDACTED}"
        assert surviving_chunks(result, project) + surviving_chunks(result, anthropic) == []


# ===========================================================================
# 3. Where a key starts, and the minimum length
# ===========================================================================


class TestKeyStart:
    """``sk-`` starts a key only at a token start: not after an ASCII letter, digit or ``_``."""

    @pytest.mark.parametrize(
        "before",
        ["", "key ", "key\n", "key-", "key(", 'key"', "key'", "key=", "key:"],
        ids=[
            "start-of-text",
            "space",
            "newline",
            "hyphen",
            "parenthesis",
            "double-quote",
            "single-quote",
            "equals",
            "colon",
        ],
    )
    def test_models_sk_after_a_non_word_character_starts_a_key(
        self, sanitize: Callable[[str], str], before: str
    ) -> None:
        key = _plain_key(40, seed=40)
        assert sanitize(f"{before}{key.text} end") == f"{before}{REDACTED} end"

    @pytest.mark.parametrize(
        "before",
        ["我的密钥是", "かぎは", "Clé"],
        ids=["cjk", "kana", "accented-latin"],
    )
    def test_models_sk_after_a_non_ascii_letter_starts_a_key(
        self, sanitize: Callable[[str], str], before: str
    ) -> None:
        """Security audit L-1: a key glued to Chinese, Japanese or accented text is redacted.

        Python's Unicode ``\\b`` counts these letters as word characters, so a
        key right after one was not redacted at all. Only an ASCII letter, an
        ASCII digit or ``_`` before ``sk-`` keeps it from starting a key.
        """
        key = openai_project_key()
        assert (before[-1].isalpha(), before[-1].isascii()) == (True, False)
        result = sanitize(before + key.text)
        assert result == before + REDACTED
        assert surviving_chunks(result, key) == []

    def test_models_sk_after_an_uppercase_ascii_letter_is_not_a_key(
        self, sanitize: Callable[[str], str]
    ) -> None:
        """Every ASCII letter keeps ``sk-`` inside a word, a capital at a sentence start too."""
        text = "Ask-me-anything-about-the-quarterly-budget-review starts at 10"
        assert sanitize(text) == text

    @pytest.mark.parametrize(
        "text",
        [
            "risk-free-investment-strategy-2026",
            "Join the ask-me-anything-about-the-quarterly-budget-review call",
            "_sk-" + _INNER_RUN,
            "2sk-" + _INNER_RUN,
        ],
        ids=["risk-free", "ask-hyphenated-word", "underscore-before", "digit-before"],
    )
    def test_models_sk_inside_a_word_is_not_a_key(
        self, sanitize: Callable[[str], str], text: str
    ) -> None:
        assert sanitize(text) == text

    def test_models_sk_with_19_key_characters_is_not_a_key(
        self, sanitize: Callable[[str], str]
    ) -> None:
        text = f"id sk-{_MINIMUM_RUN[:19]} here"
        assert sanitize(text) == text

    def test_models_sk_with_20_key_characters_is_a_key(
        self, sanitize: Callable[[str], str]
    ) -> None:
        assert sanitize(f"id sk-{_MINIMUM_RUN} here") == f"id {REDACTED} here"


# ===========================================================================
# 4. Every place credentials are redacted today
# ===========================================================================


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
    usage = {"used": 0, "max": 1, "percent": 0}  # GH-190: required on every reply
    return ChatResponse(chat_id=uuid4(), response=text, context_usage=usage).response


def _tool_call_args(text: str) -> str:
    """A string argument of a tool call record (``ToolCallRecord.args``)."""
    record = ToolCallRecord(
        tool="gmail", action="read", args={"note": text}, permission="allow", success=True
    )
    return str(record.args["note"])


def _pending_confirmation_args(text: str) -> str:
    """A string argument of a pending confirmation (``PendingConfirmationSummary.args``)."""
    summary = PendingConfirmationSummary(
        confirmation_id="c1",
        tool="gmail",
        action="send",
        args={"note": text},
        expires_at=datetime(2026, 10, 5, 12, tzinfo=UTC),
    )
    return str(summary.args["note"])


class TestDisplaySites:
    """The widened rule applies wherever ``_strip_credentials`` runs today."""

    @pytest.mark.parametrize(
        "site",
        [_stored_message, _live_reply, _tool_call_args, _pending_confirmation_args],
        ids=["stored-message", "live-reply", "tool-call-args", "pending-confirmation-args"],
    )
    def test_models_long_keys_are_redacted_in_full_at_every_display_site(
        self, site: Callable[[str], str]
    ) -> None:
        project, anthropic = openai_project_key(), anthropic_api03_key()
        result = site(f"Rotate {project.text} and {anthropic.text} today")
        assert result == f"Rotate {REDACTED} and {REDACTED} today"
        assert surviving_chunks(result, project) + surviving_chunks(result, anthropic) == []
