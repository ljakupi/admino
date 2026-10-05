"""Tests for automatic chat titles (``admino.chat_titles``, GH-179 contract section 3).

After a chat's first exchange the server asks the chat's model for a title in
the background. This file covers the pure parts of that module, the model call
and ``title_chat``'s signature; the background task's behaviour (``title_chat``),
the repository compare-and-set, the clients' per-call ``max_tokens`` and the
routes have their own files.

- Module surface (GH-264 contract sections 2 and 3): the two helpers this module
  takes from ``models`` are public, ``models.sanitize_display_text`` and
  ``models.CHAT_TITLE_BANNED_CATEGORIES`` (``{"Cc", "Cf", "Zl", "Zp", "Cs"}``);
  the private names are gone, no module under ``src/admino/`` names them, and
  this module imports no underscore-prefixed name from any ``admino`` module.
  Every keyword-only parameter of ``title_chat`` has no default,
  ``external_content`` included, so no caller can leave it out.

- ``build_title_messages(user, assistant)``: exactly a fixed system prompt and
  one user message ``"User:\\n{u}\\n\\nAssistant:\\n{a}"``, each excerpt stripped,
  then cut to ``TITLE_EXCERPT_CHARS`` (1000). Nothing else reaches the model.
- ``truncate_title``: at most ``TITLE_MAX_LENGTH`` (80) characters, cut at the
  last space before index 80 with an ellipsis (U+2026), or after 79 characters
  when the first word is longer.
- ``sanitize_title(raw)``: the model reply, in order: reasoning blocks removed,
  the first non-empty line, a leading heading marker / ``title:`` label
  dropped, surrounding quote and emphasis characters stripped (these two steps
  repeat until stable, so ``**Title:** X`` is ``X``), banned title characters
  (Cc, Cf, Cs, Zl, Zp; whitespace still separates words) removed before the
  redaction, so a key split by one is joined first (GH-264 security audit L-2),
  credentials redacted and control characters stripped as for a stored message
  (NFKC included), banned characters removed, whitespace collapsed, trailing
  dots removed, then truncated. ``""`` when nothing usable remains, else always
  a valid ``models.ChatTitle`` of at most 80 characters.
- ``fallback_title(user_message)``: the first user message, cleaned the same
  way (banned characters removed before the redaction), single-spaced and
  truncated (no markdown, label or quote stripping).
- Long keys (GH-264): a 164-character ``sk-proj-`` key and a 108-character
  ``sk-ant-api03-`` key with ``_`` become exactly one ``[CREDENTIAL_REDACTED]``
  in a model title and in a fallback title, alone or in a sentence whose text
  is kept; no 8-character chunk of either key survives. The keys are built at
  runtime (tests/credential_keys.py); the rule itself is pinned in
  tests/test_credential_redaction.py.
- The sanitizer cases are one per distinct rule (GH-264): one per character
  group for the quotes and emphasis stripped or kept, and one per Unicode
  category and removal path (the models control table or the banned-category
  step) for the characters removed.
- ``generate_title``: one ``llm_policy.chat`` call (looked up at call time) with
  those messages, no tools and ``max_tokens=TITLE_MAX_TOKENS`` (40), through
  the residency guard and the retries; the sanitized reply, or the fallback on
  an empty reply or any exception (``MemoryError`` / ``RecursionError`` and
  non-``Exception`` errors propagate).

The module is imported inside the ``ct`` fixture, so this file collects before
it exists and every test fails on its own. ``llm_policy._sleep`` and
``_random`` are replaced by recorders, so no test sleeps.
"""

from __future__ import annotations

import ast
import asyncio
import dataclasses
import inspect
import random
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import TypeAdapter, ValidationError

from admino import llm_policy, models
from admino.llm import LLMError, LLMResponse
from admino.models import LLMMessage, ToolCall
from tests.credential_keys import anthropic_api03_key, openai_project_key, surviving_chunks
from tests.log_capture import configured_logging

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType

    from tests.credential_keys import ApiKey

# Characters built with chr(): typographic quotes and invisible characters are
# unreadable (or flagged as ambiguous) as literals.
ELLIPSIS = chr(0x2026)
LDQUO, RDQUO = chr(0x201C), chr(0x201D)
LSQUO, RSQUO = chr(0x2018), chr(0x2019)
BDQUO = chr(0x201E)
LAQUO, RAQUO = chr(0x00AB), chr(0x00BB)
LSAQUO, RSAQUO = chr(0x2039), chr(0x203A)
NBSP = chr(0x00A0)
SHY = chr(0x00AD)  # soft hyphen (Cf), not in models' control table
ZWSP = chr(0x200B)  # zero width space (Cf), in the control table
RLO = chr(0x202E)  # right-to-left override (Cf), in the control table
RLI, PDI = chr(0x2067), chr(0x2069)  # bidi isolates (Cf), in the control table
WORD_JOINER = chr(0x2060)  # word joiner (Cf), not in the control table
DEL = chr(0x7F)  # delete (Cc), not in the control table
BOM = chr(0xFEFF)
LINE_SEP, PARA_SEP = chr(0x2028), chr(0x2029)
NEL = chr(0x0085)
SURROGATE = chr(0xD800)
OGHAM_SPACE = chr(0x1680)  # whitespace (Zs) that NFKC keeps

_MISSING = object()
_NOT_PASSED = object()

USER = "Plan my trip\nto Zurich"
USER_FALLBACK = "Plan my trip to Zurich"
ASSISTANT = "Here is a three-day plan for Zurich."

_TITLE_ADAPTER: TypeAdapter[str] = TypeAdapter(models.ChatTitle)


@pytest.fixture()
def ct() -> ModuleType:
    """The module under test, imported lazily (it doesn't exist before GH-179)."""
    from admino import chat_titles

    return chat_titles


@pytest.fixture()
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record llm_policy's retry delays instead of sleeping; no jitter."""
    recorded: list[float] = []

    async def _record(delay: float) -> None:
        recorded.append(delay)

    monkeypatch.setattr(llm_policy, "_sleep", _record)
    monkeypatch.setattr(llm_policy, "_random", lambda: 0.0)
    return recorded


# ---------------------------------------------------------------------------
# Fake clients
# ---------------------------------------------------------------------------


class TitleClient:
    """Stand-in LLM client whose ``chat`` takes the per-call ``max_tokens`` (contract 1).

    ``chat`` returns or raises the next scripted item (the last one repeats) and
    records the exact arguments of every call. ``max_tokens`` is ``_NOT_PASSED``
    when the caller left it out. ``provider`` is set unless it is ``_MISSING``.
    """

    def __init__(
        self, script: list[LLMResponse | BaseException], *, provider: object = "infomaniak"
    ) -> None:
        self._script = list(script)
        self.calls: list[dict[str, object]] = []
        if provider is not _MISSING:
            self.provider = provider

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: object = _NOT_PASSED,
    ) -> LLMResponse:
        self.calls.append(
            {"messages": messages, "tools": tools, "stream": stream, "max_tokens": max_tokens}
        )
        item = self._script[min(len(self.calls), len(self._script)) - 1]
        if isinstance(item, BaseException):
            raise item
        return item


class LegacyClient:
    """A client whose ``chat`` predates the per-call ``max_tokens`` (a TypeError then)."""

    provider = "infomaniak"

    def __init__(self) -> None:
        self.calls = 0

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        self.calls += 1
        return LLMResponse(content="Legacy title")


def _reply(content: str) -> LLMResponse:
    return LLMResponse(content=content, done=True)


def _err(code: str) -> LLMError:
    """A coded LLMError (fixed catalogue text)."""
    return LLMError("Fixed catalogue text.", code=code)


# ---------------------------------------------------------------------------
# The invariant every title must meet
# ---------------------------------------------------------------------------


def _invariant_violation(result: object) -> str | None:
    """Why ``result`` isn't ``""`` or a clean ChatTitle of at most 80 chars (None: fine)."""
    if type(result) is not str:
        return f"not a str: {type(result).__name__}"
    if result == "":
        return None
    if len(result) > 80:
        return f"longer than 80: {len(result)}"
    if result != result.strip():
        return "not stripped"
    if "  " in result or any(char.isspace() and char != " " for char in result):
        return "whitespace not collapsed to single spaces"
    try:
        validated = _TITLE_ADAPTER.validate_python(result)
    except ValidationError:
        return "refused by models.ChatTitle"
    if validated != result:
        return "changed by models.ChatTitle"
    return None


_ADVERSARIAL_CODEPOINTS = (
    0x00,
    0x07,
    0x08,
    0x0B,
    0x0C,
    0x1B,
    0x1C,
    0x1F,
    0x7F,
    0x85,
    0x9B,
    0xA0,
    0xAD,
    0x061C,
    0x1680,
    0x180E,
    0x2003,
    0x200B,
    0x200C,
    0x200D,
    0x200E,
    0x200F,
    0x202A,
    0x202E,
    0x2028,
    0x2029,
    0x2060,
    0x2066,
    0x2069,
    0x3000,
    0xFEFF,
    0xFFF9,
    0xD800,
    0xDBFF,
    0xDC00,
    0xDFFF,
    0xE0001,
)

_CORPUS_TOKENS: tuple[str, ...] = (
    "word",
    "Zurich",
    "Z" + chr(0xFC) + "rich",
    " ",
    "  ",
    "\t",
    "\n",
    "\r\n",
    "\r",
    ".",
    "...",
    ":",
    "#",
    "## ",
    "Title:",
    "titre :",
    "TITEL:",
    "<think>",
    "</think>",
    '"',
    "'",
    "`",
    "*",
    "**",
    "_",
    LDQUO,
    RDQUO,
    LSQUO,
    RSQUO,
    BDQUO,
    LAQUO,
    RAQUO,
    LSAQUO,
    RSAQUO,
    "sk-" + "a" * 24,
    "Bearer tok3n",
    ELLIPSIS,
    chr(0xFDFA),  # NFKC expands it to 18 characters
    chr(0xFF34),  # fullwidth T
    chr(0x1F600),
    "e" + chr(0x0301),
    *(chr(code) for code in _ADVERSARIAL_CODEPOINTS),
)


def _corpus() -> list[str]:
    """A broad, deterministic set of hostile inputs (same list on every run)."""
    corpus: list[str] = list(_CORPUS_TOKENS)
    for code in _ADVERSARIAL_CODEPOINTS:
        char = chr(code)
        corpus.extend([f"Bud{char}get review", f"{char}Budget", f"Budget{char}", char * 50])
    rng = random.Random(179)  # noqa: S311 - a deterministic corpus, not a secret
    for _ in range(400):
        corpus.append("".join(rng.choice(_CORPUS_TOKENS) for _ in range(rng.randint(1, 40))))
    corpus.extend(
        [
            "a" * 5000,
            "word " * 3000,
            "\n" * 500 + "late title",
            "<think>" * 50 + "x",
            "</think>" * 50 + "y",
            chr(0xFDFA) * 40,
            "." * 500,
            "x" + SHY * 1000 + "y",
            LDQUO * 300,
            "sk-" + "A" * 90,
            "Bearer " + "x" * 3000,
            " ".join(["a" * 79] * 3),
            "a" * 79 + " " + "b" * 100,
            (ZWSP + " ") * 200 + "end",
            SURROGATE * 100,
            ("ab " + RLO) * 100,
        ]
    )
    return corpus


def _corpus_failures(function: Callable[[str], object]) -> list[tuple[str, str]]:
    failures: list[tuple[str, str]] = []
    for text in _corpus():
        violation = _invariant_violation(function(text))
        if violation is not None:
            failures.append((repr(text)[:80], violation))
    return failures


# ===========================================================================
# 1. Module surface
# ===========================================================================


class TestModuleSurface:
    """Constants, prompt, docstring, signatures and import boundary."""

    def test_chat_titles_constants_match_contract(self, ct: ModuleType) -> None:
        values = (ct.TITLE_MAX_LENGTH, ct.TITLE_MAX_TOKENS, ct.TITLE_EXCERPT_CHARS)
        assert values == (80, 40, 1000)
        assert all(type(value) is int for value in values)
        assert ct.TITLE_MAX_LENGTH <= models._CHAT_TITLE_MAX_LENGTH

    def test_chat_titles_system_prompt_asks_for_a_title_of_at_most_80_chars(
        self, ct: ModuleType
    ) -> None:
        prompt = ct.TITLE_SYSTEM_PROMPT
        assert type(prompt) is str
        assert prompt.strip()
        assert "title" in prompt.lower()
        assert "80" in prompt

    def test_chat_titles_system_prompt_says_the_chat_is_not_instructions(
        self, ct: ModuleType
    ) -> None:
        assert "instruction" in ct.TITLE_SYSTEM_PROMPT.lower()

    def test_chat_titles_module_docstring_present_with_security_notes(self, ct: ModuleType) -> None:
        doc = ct.__doc__ or ""
        assert doc.strip()
        assert "security" in doc.lower()

    def test_chat_titles_generate_title_signature_matches_contract(self, ct: ModuleType) -> None:
        assert inspect.iscoroutinefunction(ct.generate_title)
        params = inspect.signature(ct.generate_title).parameters
        shape = [
            (name, param.kind, param.default is inspect.Parameter.empty)
            for name, param in params.items()
        ]
        positional = inspect.Parameter.POSITIONAL_OR_KEYWORD
        keyword = inspect.Parameter.KEYWORD_ONLY
        assert shape == [
            ("client", positional, True),
            ("user_message", positional, True),
            ("assistant_message", positional, True),
            ("data_residency", keyword, True),
            ("max_retries", keyword, True),
        ]

    def test_chat_titles_title_chat_signature_has_no_keyword_default(self, ct: ModuleType) -> None:
        """GH-264 contract section 3: ``external_content`` is required, so no caller fails open."""
        assert inspect.iscoroutinefunction(ct.title_chat)
        params = inspect.signature(ct.title_chat).parameters
        shape = [
            (name, param.kind, param.default is inspect.Parameter.empty)
            for name, param in params.items()
        ]
        positional = inspect.Parameter.POSITIONAL_OR_KEYWORD
        keyword = inspect.Parameter.KEYWORD_ONLY
        assert shape == [
            ("pool", positional, True),
            ("tenant", positional, True),
            ("chat_id", positional, True),
            ("get_client", keyword, True),
            ("user_message", keyword, True),
            ("assistant_message", keyword, True),
            ("run_failed", keyword, True),
            ("external_content", keyword, True),
            ("data_residency", keyword, True),
            ("max_retries", keyword, True),
        ]
        assert params["external_content"].annotation in (bool, "bool")

    def test_chat_titles_models_helpers_have_public_names(self) -> None:
        """GH-264 contract section 2: the display-text sanitizer and the banned categories."""
        assert callable(models.sanitize_display_text)
        banned = models.CHAT_TITLE_BANNED_CATEGORIES
        assert (type(banned), banned) == (frozenset, frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"}))

    def test_chat_titles_models_private_helper_names_are_removed(self) -> None:
        """Renamed, not aliased: the private names are gone from ``models``."""
        old = ("_sanitize_display_text", "_CHAT_TITLE_BANNED_CATEGORIES")
        assert [name for name in old if hasattr(models, name)] == []

    def test_chat_titles_imports_no_private_admino_name(self, ct: ModuleType) -> None:
        """No ``from admino.x import _name`` and no ``x._name`` on an imported admino module."""
        tree = ast.parse(inspect.getsource(ct))
        admino_modules: set[str] = set()
        private: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level or module == "admino" or module.startswith("admino."):
                    private.extend(
                        f"{module}.{alias.name}"
                        for alias in node.names
                        if alias.name.startswith("_")
                    )
                    if node.level or module == "admino":
                        # ``from admino import chats`` binds a module.
                        admino_modules.update(alias.asname or alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                admino_modules.update(
                    alias.asname or alias.name.split(".")[0]
                    for alias in node.names
                    if alias.name.split(".")[0] == "admino"
                )
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            root: ast.expr = node.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if (
                isinstance(root, ast.Name)
                and root.id in admino_modules
                and node.attr.startswith("_")
                and not node.attr.startswith("__")
            ):
                private.append(ast.unparse(node))
        assert private == []

    def test_chat_titles_no_module_names_the_old_private_helpers(self) -> None:
        """No module under src/admino/ names ``_sanitize_display_text`` or the old banned set."""
        package = Path(inspect.getfile(models)).parent
        old_name = re.compile(r"(?<!\w)(?:_sanitize_display_text|_CHAT_TITLE_BANNED_CATEGORIES)\b")
        hits = [
            f"{path.relative_to(package)}:{number}"
            for path in sorted(package.rglob("*.py"))
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if old_name.search(line)
        ]
        assert hits == []

    def test_chat_titles_imports_only_the_allowed_modules(self, ct: ModuleType) -> None:
        """Stdlib, chats, llm, llm_policy, logs, models; asyncpg / tenancy for typing only."""
        tree = ast.parse(inspect.getsource(ct))
        typing_only: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and (
                (isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING")
                or (isinstance(node.test, ast.Attribute) and node.test.attr == "TYPE_CHECKING")
            ):
                for statement in node.body:
                    typing_only.update(
                        id(sub)
                        for sub in ast.walk(statement)
                        if isinstance(sub, ast.Import | ast.ImportFrom)
                    )
        imported: list[tuple[str, bool]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend((alias.name, id(node) in typing_only) for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    module = f"admino.{module}" if module else "admino"
                if module == "admino":
                    imported.extend(
                        (f"admino.{alias.name}", id(node) in typing_only) for alias in node.names
                    )
                else:
                    imported.append((module, id(node) in typing_only))
        assert imported, "expected at least one import"
        forbidden_admino = (
            "admino.server",
            "admino.agent",
            "admino.tools",
            "admino.permissions",
            "admino.access",
            "admino.database",
            "admino.scoped_settings",
            "admino.org_permissions",
        )
        runtime_admino = {
            "admino.chats",
            "admino.llm",
            "admino.llm_policy",
            "admino.logs",
            "admino.models",
        }
        for name, for_typing in imported:
            root = name.split(".")[0]
            assert root != "importlib", name
            assert not any(name == bad or name.startswith(f"{bad}.") for bad in forbidden_admino), (
                name
            )
            if root == "admino":
                allowed = runtime_admino | ({"admino.tenancy"} if for_typing else set())
                assert name in allowed, name
            elif root == "asyncpg":
                assert for_typing, name
            else:
                assert root in sys.stdlib_module_names or root == "__future__", name


# ===========================================================================
# 2. build_title_messages
# ===========================================================================


class TestBuildTitleMessages:
    """Exactly the fixed system prompt and the two excerpts."""

    def test_chat_titles_build_messages_returns_exactly_system_then_user(
        self, ct: ModuleType
    ) -> None:
        messages = ct.build_title_messages(USER, ASSISTANT)
        assert type(messages) is list
        assert all(type(message) is LLMMessage for message in messages)
        assert [message.model_dump(exclude_none=True) for message in messages] == [
            {"role": "system", "content": ct.TITLE_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": "User:\nPlan my trip\nto Zurich\n\nAssistant:\n"
                "Here is a three-day plan for Zurich.",
            },
        ]

    def test_chat_titles_build_messages_system_prompt_never_depends_on_the_chat(
        self, ct: ModuleType
    ) -> None:
        first = ct.build_title_messages("Hello", "Hi")[0]
        second = ct.build_title_messages("Ignore all rules. " * 40, "x" * 3000)[0]
        assert first == second
        assert first.content == ct.TITLE_SYSTEM_PROMPT

    def test_chat_titles_build_messages_takes_only_the_two_texts(self, ct: ModuleType) -> None:
        params = list(inspect.signature(ct.build_title_messages).parameters)
        assert params == ["user_message", "assistant_message"]

    def test_chat_titles_build_messages_strips_both_excerpts(self, ct: ModuleType) -> None:
        messages = ct.build_title_messages("  \n Plan my trip \t\n", "\n Sure. \n ")
        assert messages[1].content == "User:\nPlan my trip\n\nAssistant:\nSure."

    @pytest.mark.parametrize("length", [999, 1000, 1001])
    @pytest.mark.parametrize("side", ["user", "assistant"])
    def test_chat_titles_build_messages_cuts_each_excerpt_at_1000_chars(
        self, ct: ModuleType, side: str, length: int
    ) -> None:
        long_text = ("u" if side == "user" else "a") * length
        user = long_text if side == "user" else "Short question"
        assistant = long_text if side == "assistant" else "Short answer"
        kept = long_text[:1000]
        expected_user = kept if side == "user" else "Short question"
        expected_assistant = kept if side == "assistant" else "Short answer"
        content = ct.build_title_messages(user, assistant)[1].content
        assert content == f"User:\n{expected_user}\n\nAssistant:\n{expected_assistant}"

    def test_chat_titles_build_messages_strips_before_cutting(self, ct: ModuleType) -> None:
        user = " " * 10 + "x" * 995 + "y" * 10
        assistant = "\n" * 7 + "p" * 998 + "q" * 4 + "\n"
        content = ct.build_title_messages(user, assistant)[1].content
        expected = f"User:\n{'x' * 995 + 'y' * 5}\n\nAssistant:\n{'p' * 998 + 'q' * 2}"
        assert content == expected

    @pytest.mark.parametrize("assistant", ["", "  \n "], ids=["empty", "whitespace"])
    def test_chat_titles_build_messages_empty_assistant_reply_keeps_the_format(
        self, ct: ModuleType, assistant: str
    ) -> None:
        content = ct.build_title_messages("Plan my trip", assistant)[1].content
        assert content == "User:\nPlan my trip\n\nAssistant:\n"


# ===========================================================================
# 3. truncate_title
# ===========================================================================


class TestTruncateTitle:
    """At most 80 characters, cut at a word boundary with an ellipsis."""

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("", ""),
            ("Trip planning", "Trip planning"),
            ("a" * 80, "a" * 80),
            ("x" * 39 + " " + "y" * 40, "x" * 39 + " " + "y" * 40),
            ("x" * 39 + " " + "y" * 41, "x" * 39 + ELLIPSIS),
            ("a" * 79 + " " + "b" * 5, "a" * 79 + ELLIPSIS),
            ("a" * 80 + " " + "b" * 5, "a" * 79 + ELLIPSIS),
            ("a" * 10 + " " + "c" * 69 + " " + "d" * 5, "a" * 10 + ELLIPSIS),
            ("a" * 100, "a" * 79 + ELLIPSIS),
            ("a" * 85 + " b c", "a" * 79 + ELLIPSIS),
            (
                "Planning a two week family trip through the Swiss Alps with trains,"
                " hikes and a budget spreadsheet",
                "Planning a two week family trip through the Swiss Alps with trains,"
                " hikes and a" + ELLIPSIS,
            ),
            (
                "Bitte hilf mir, meine Steuererkl" + chr(0xE4) + "rung f" + chr(0xFC) + "r 2025"
                " vorzubereiten, inklusive aller Belege und Abz" + chr(0xFC) + "ge",
                "Bitte hilf mir, meine Steuererkl" + chr(0xE4) + "rung f" + chr(0xFC) + "r 2025"
                " vorzubereiten, inklusive aller" + ELLIPSIS,
            ),
        ],
        ids=[
            "empty",
            "short",
            "exactly-80-no-space",
            "exactly-80-with-space",
            "81-cut-at-space",
            "space-at-index-79",
            "space-at-index-80-only",
            "space-at-index-80-and-earlier-space",
            "first-word-over-79",
            "first-word-over-79-then-words",
            "english-sentence",
            "german-sentence",
        ],
    )
    def test_chat_titles_truncate_title_cuts_at_word_boundary(
        self, ct: ModuleType, text: str, expected: str
    ) -> None:
        assert ct.truncate_title(text) == expected

    def test_chat_titles_truncate_title_ellipsis_is_one_character(self, ct: ModuleType) -> None:
        result = ct.truncate_title("alpha " * 30)
        assert result.endswith(ELLIPSIS)
        assert not result.endswith("...")

    def test_chat_titles_truncate_title_always_at_most_80_and_a_prefix(
        self, ct: ModuleType
    ) -> None:
        failures: list[tuple[int, int, int]] = []
        for word_length in range(1, 100):
            for words in (1, 2, 3, 7, 40):
                text = " ".join(["w" * word_length] * words)
                result = ct.truncate_title(text)
                fine = len(result) <= 80 and (
                    result == text or (result.endswith(ELLIPSIS) and text.startswith(result[:-1]))
                )
                if not fine:
                    failures.append((word_length, words, len(result)))
        assert failures == []


# ===========================================================================
# 4. sanitize_title
# ===========================================================================


class TestSanitizeReasoning:
    """Step 1: reasoning blocks never reach the title."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("<think>the user wants a title</think>Trip planning", "Trip planning"),
            ("<think>a</think>Budget <think>b</think>review", "Budget review"),
            ("<think>a</think><think>b</think>Tax return", "Tax return"),
            ("<think>\nline one\nline two\n</think>\nTrip planning", "Trip planning"),
            ("Weekly report <think>never closed", "Weekly report"),
            ("leaked reasoning</think>Tax return", "Tax return"),
            ("first\nsecond</think>\nTax return", "Tax return"),
        ],
        ids=[
            "closed",
            "several-inline",
            "several-adjacent",
            "multiline-block-before-title",
            "unclosed-drops-rest",
            "orphan-close-drops-before",
            "orphan-close-after-lines",
        ],
    )
    def test_chat_titles_sanitize_removes_reasoning(
        self, ct: ModuleType, raw: str, expected: str
    ) -> None:
        assert ct.sanitize_title(raw) == expected

    def test_chat_titles_sanitize_keeps_the_word_think(self, ct: ModuleType) -> None:
        assert ct.sanitize_title("How to think clearly") == "How to think clearly"


class TestSanitizeFirstLine:
    """Step 2: the first line with text wins."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("First line\nSecond line", "First line"),
            ("\n\n   \n\t\nActual title\nmore", "Actual title"),
            ("Title one\r\nTitle two", "Title one"),
            ("\rCR title\rnext", "CR title"),
        ],
        ids=["lf", "leading-blank-lines", "crlf", "cr"],
    )
    def test_chat_titles_sanitize_keeps_first_non_empty_line(
        self, ct: ModuleType, raw: str, expected: str
    ) -> None:
        assert ct.sanitize_title(raw) == expected


class TestSanitizeHeadingAndLabel:
    """Step 3: a leading heading marker and a leading title label are dropped."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("# Trip planning", "Trip planning"),
            ("### Trip planning", "Trip planning"),
            ("Title: Trip planning", "Trip planning"),
            ("title : Trip planning", "Trip planning"),
            ("TITLE:Trip planning", "Trip planning"),
            ("Titel: Steuererkl" + chr(0xE4) + "rung", "Steuererkl" + chr(0xE4) + "rung"),
            (
                "TiTrE : Voyage " + chr(0xE0) + " Gen" + chr(0xE8) + "ve",
                "Voyage " + chr(0xE0) + " Gen" + chr(0xE8) + "ve",
            ),
            ("## Title: Trip planning", "Trip planning"),
        ],
        ids=[
            "heading",
            "deep-heading",
            "label",
            "label-space-before-colon",
            "label-upper-no-space",
            "label-german",
            "label-french-mixed-case",
            "heading-then-label",
        ],
    )
    def test_chat_titles_sanitize_drops_heading_and_label(
        self, ct: ModuleType, raw: str, expected: str
    ) -> None:
        assert ct.sanitize_title(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        ["Title of the book", "Subtitle: Trip planning", "My title: Trip planning", "C# tips"],
        ids=["label-word-no-colon", "longer-word", "not-leading", "inner-hash"],
    )
    def test_chat_titles_sanitize_keeps_label_like_text_that_is_not_a_leading_label(
        self, ct: ModuleType, raw: str
    ) -> None:
        assert ct.sanitize_title(raw) == raw


class TestSanitizeQuotes:
    """Step 4: quote and emphasis characters are stripped from both ends.

    One case per character group the step names: ASCII quotes, markdown emphasis
    (a run of it), English typographic quotes, the German low-high pair and
    guillemets.
    """

    @pytest.mark.parametrize(
        ("opening", "closing"),
        [
            ('"', '"'),
            ("**", "**"),
            (LDQUO, RDQUO),
            (BDQUO, LDQUO),
            (LAQUO, RAQUO),
        ],
        ids=["double", "bold", "curly-double", "german-low-high", "guillemets"],
    )
    def test_chat_titles_sanitize_strips_surrounding_quotes(
        self, ct: ModuleType, opening: str, closing: str
    ) -> None:
        assert ct.sanitize_title(f"{opening}Trip planning{closing}") == "Trip planning"

    def test_chat_titles_sanitize_strips_nested_quotes_with_spaces(self, ct: ModuleType) -> None:
        raw = f' " **{LAQUO} Trip planning {RAQUO}** " '
        assert ct.sanitize_title(raw) == "Trip planning"

    @pytest.mark.parametrize(
        "raw",
        ['The "best" plan', "It's *really* good"],
        ids=["inner-double", "inner-emphasis"],
    )
    def test_chat_titles_sanitize_keeps_inner_quotes(self, ct: ModuleType, raw: str) -> None:
        assert ct.sanitize_title(raw) == raw


class TestSanitizeLabelBehindEmphasis:
    """Steps 3 and 4 repeat until neither changes the text.

    A label behind emphasis or quotes becomes leading once they are stripped, and
    goes too. A label is still only removed when it is leading.
    """

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("**Title:** Trip planning", "Trip planning"),
            ("__Titel:__ Reiseplanung", "Reiseplanung"),
            ('"Title: Budget"', "Budget"),
            ("# **Titre :** Budget", "Budget"),
            ('**Title:** "Titel: Reiseplanung"', "Reiseplanung"),
        ],
        ids=[
            "bold-label",
            "underscore-label-german",
            "quoted-label",
            "heading-bold-label-french",
            "label-behind-label-needs-three-rounds",
        ],
    )
    def test_chat_titles_sanitize_drops_a_label_behind_emphasis_or_quotes(
        self, ct: ModuleType, raw: str, expected: str
    ) -> None:
        assert ct.sanitize_title(raw) == expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("**My title:** X", "My title:** X"),
            ("**Title of the book**", "Title of the book"),
        ],
        ids=["label-not-leading", "label-word-without-colon"],
    )
    def test_chat_titles_sanitize_keeps_a_non_leading_label_behind_emphasis(
        self, ct: ModuleType, raw: str, expected: str
    ) -> None:
        """Only the emphasis at the ends goes; text that isn't a leading label stays."""
        assert ct.sanitize_title(raw) == expected


class TestSanitizeCredentialsAndCharacters:
    """Steps 5 and 6: redaction, NFKC and banned characters, whitespace collapse.

    The removed characters are one case per Unicode category and removal path:
    Cc and Cf removed by the models control table (NUL, RLO) or only as a banned
    category (DEL, the soft hyphen), Cs, and the line breaks Zl, Zp and Cc (NEL).
    """

    def test_chat_titles_sanitize_redacts_an_api_key(self, ct: ModuleType) -> None:
        raw = "Rotate sk-" + "a" * 24
        assert ct.sanitize_title(raw) == "Rotate " + models._REDACTED
        assert ct.sanitize_title(raw) == models.sanitize_display_text(raw)

    def test_chat_titles_sanitize_redacts_a_bearer_token(self, ct: ModuleType) -> None:
        raw = "Use Bearer abc123def456 now"
        assert ct.sanitize_title(raw) == f"Use {models._REDACTED} now"

    def test_chat_titles_sanitize_redacts_a_key_split_by_a_zero_width_space(
        self, ct: ModuleType
    ) -> None:
        raw = "Key sk-" + "a" * 10 + ZWSP + "a" * 14
        assert ct.sanitize_title(raw) == "Key " + models._REDACTED

    def test_chat_titles_sanitize_redacts_before_truncating(self, ct: ModuleType) -> None:
        """A 93-character key is redacted whole, not cut first and redacted with an ellipsis."""
        assert ct.sanitize_title("sk-" + "A" * 90) == models._REDACTED

    def test_chat_titles_sanitize_applies_nfkc(self, ct: ModuleType) -> None:
        fullwidth = "".join(chr(0xFF00 + ord(char) - 0x20) for char in "Trip")
        assert ct.sanitize_title(f"{fullwidth} planning") == "Trip planning"

    @pytest.mark.parametrize(
        "char",
        [chr(0x00), DEL, RLO, SHY, SURROGATE],
        ids=["nul", "del", "rlo", "soft-hyphen", "surrogate"],
    )
    def test_chat_titles_sanitize_removes_control_and_format_characters(
        self, ct: ModuleType, char: str
    ) -> None:
        assert ct.sanitize_title(f"{char}Bud{char}get review{char}") == "Budget review"

    @pytest.mark.parametrize(
        "char",
        [LINE_SEP, PARA_SEP, NEL],
        ids=["line-sep", "para-sep", "nel"],
    )
    def test_chat_titles_sanitize_removes_line_separators(self, ct: ModuleType, char: str) -> None:
        result = ct.sanitize_title(f"Budget{char}review")
        assert char not in result
        assert result in {"Budget", "Budgetreview", "Budget review"}

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Budget   review", "Budget review"),
            ("Budget\treview", "Budget review"),
            (f"Budget{NBSP}review", "Budget review"),
            (f"Budget{OGHAM_SPACE}{OGHAM_SPACE}review", "Budget review"),
            (f"Budget {SHY} review", "Budget review"),
            ("   Budget review   ", "Budget review"),
        ],
        ids=[
            "spaces",
            "tab",
            "nbsp",
            "unicode-space",
            "removed-char-between-spaces",
            "ends",
        ],
    )
    def test_chat_titles_sanitize_collapses_whitespace(
        self, ct: ModuleType, raw: str, expected: str
    ) -> None:
        assert ct.sanitize_title(raw) == expected


class TestSanitizeEnding:
    """Steps 7 and 8: trailing dots, then the length cap."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Trip planning.", "Trip planning"),
            ("Trip planning...", "Trip planning"),
            ("Trip planning" + ELLIPSIS, "Trip planning"),
            ("Node.js setup", "Node.js setup"),
            ("What is RAG?", "What is RAG?"),
            ("Release v2.0", "Release v2.0"),
        ],
        ids=["dot", "dots", "ellipsis-char", "inner-dot", "question-mark", "version"],
    )
    def test_chat_titles_sanitize_removes_trailing_dots_only(
        self, ct: ModuleType, raw: str, expected: str
    ) -> None:
        assert ct.sanitize_title(raw) == expected

    def test_chat_titles_sanitize_truncates_a_long_title(self, ct: ModuleType) -> None:
        raw = " ".join(["alpha"] * 20) + "."
        assert ct.sanitize_title(raw) == " ".join(["alpha"] * 13) + ELLIPSIS

    def test_chat_titles_sanitize_truncates_the_first_line_only(self, ct: ModuleType) -> None:
        raw = (
            "Planning a two week family trip through the Swiss Alps with trains,"
            " hikes and a budget spreadsheet\nSecond line"
        )
        expected = (
            "Planning a two week family trip through the Swiss Alps with trains,"
            " hikes and a" + ELLIPSIS
        )
        assert ct.sanitize_title(raw) == expected

    def test_chat_titles_sanitize_applies_every_step_in_order(self, ct: ModuleType) -> None:
        raw = (
            "<think>The user asks about Zurich.</think>\n\n"
            '## Title: "**Trip  planning\tto Zurich.**"\nSecond line'
        )
        assert ct.sanitize_title(raw) == "Trip planning to Zurich"


class TestSanitizeNothingUsable:
    """Empty results: the caller falls back."""

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "   ",
            "\n\t\r\n",
            "<think>only reasoning</think>",
            "<think>unclosed reasoning",
            "reasoning only</think>",
            '""',
            "**",
            LDQUO + RDQUO,
            "Title:",
            "...",
            ZWSP * 3,
            SURROGATE,
        ],
        ids=[
            "empty",
            "spaces",
            "whitespace",
            "only-think",
            "only-unclosed-think",
            "only-orphan-close",
            "only-quotes",
            "only-emphasis",
            "only-curly-quotes",
            "only-label",
            "only-dots",
            "only-zero-width",
            "only-surrogate",
        ],
    )
    def test_chat_titles_sanitize_returns_empty_when_nothing_usable(
        self, ct: ModuleType, raw: str
    ) -> None:
        assert ct.sanitize_title(raw) == ""


class TestSanitizeInvariant:
    """For ANY input: "" or a valid ChatTitle of at most 80 characters."""

    def test_chat_titles_sanitize_output_is_always_empty_or_a_valid_title(
        self, ct: ModuleType
    ) -> None:
        failures = _corpus_failures(ct.sanitize_title)
        assert not failures, (len(failures), failures[:5])


# ===========================================================================
# 5. fallback_title
# ===========================================================================


class TestFallbackTitle:
    """The first user message: redacted, cleaned, single-spaced, cut at a word."""

    @pytest.mark.parametrize(
        ("message", "expected"),
        [
            ("Plan a trip to Zurich", "Plan a trip to Zurich"),
            (
                "  line one\nline two\r\n\r\nline three\tfour  ",
                "line one line two line three four",
            ),
            ('# Title: "Budget" **review**', '# Title: "Budget" **review**'),
            (f"{LDQUO}Zitat{RDQUO} und _Notiz_", f"{LDQUO}Zitat{RDQUO} und _Notiz_"),
        ],
        ids=["plain", "newlines-and-tabs", "markdown-label-quotes-kept", "typographic-kept"],
    )
    def test_chat_titles_fallback_title_keeps_the_message_text(
        self, ct: ModuleType, message: str, expected: str
    ) -> None:
        assert ct.fallback_title(message) == expected

    def test_chat_titles_fallback_title_redacts_credentials(self, ct: ModuleType) -> None:
        message = "My key is sk-" + "a" * 24 + " and it fails"
        assert ct.fallback_title(message) == f"My key is {models._REDACTED} and it fails"

    def test_chat_titles_fallback_title_removes_banned_characters(self, ct: ModuleType) -> None:
        message = f"Bud{SHY}get{ZWSP} {RLO}review{SURROGATE}{BOM} {RLI}now{PDI}"
        assert ct.fallback_title(message) == "Budget review now"

    def test_chat_titles_fallback_title_applies_nfkc(self, ct: ModuleType) -> None:
        fullwidth = "".join(chr(0xFF00 + ord(char) - 0x20) for char in "Trip")
        assert ct.fallback_title(f"{fullwidth} planning") == "Trip planning"

    def test_chat_titles_fallback_title_cuts_a_long_message_at_a_word(self, ct: ModuleType) -> None:
        message = (
            "Planning a two week family trip\nthrough the Swiss Alps with trains,"
            " hikes and a budget spreadsheet, please help"
        )
        expected = (
            "Planning a two week family trip through the Swiss Alps with trains,"
            " hikes and a" + ELLIPSIS
        )
        assert ct.fallback_title(message) == expected

    @pytest.mark.parametrize(
        "message",
        ["", "   ", "\n\t\r\n", ZWSP * 3, SHY + RLO + BOM],
        ids=["empty", "spaces", "whitespace", "zero-width", "format-only"],
    )
    def test_chat_titles_fallback_title_returns_empty_when_nothing_remains(
        self, ct: ModuleType, message: str
    ) -> None:
        assert ct.fallback_title(message) == ""

    def test_chat_titles_fallback_title_output_is_always_empty_or_a_valid_title(
        self, ct: ModuleType
    ) -> None:
        failures = _corpus_failures(ct.fallback_title)
        assert not failures, (len(failures), failures[:5])


# ===========================================================================
# 5b. Credentials split by an invisible character (sanitize_title and fallback_title)
# ===========================================================================


def _split_credential(kind: str, char: str) -> tuple[str, str, str]:
    """(text with a credential split by ``char``, the same text joined, the expected title).

    ``models.sanitize_display_text`` keeps ``char``, so redacting the raw text
    misses the split credential; removing ``char`` joins it again.
    """
    if kind == "key":
        joined = "Key sk-" + "a" * 24
        return "Key sk-" + "a" * 10 + char + "a" * 14, joined, "Key " + models._REDACTED
    joined = "Use Bearer abc123def456 now"
    return f"Use Bea{char}rer abc123def456 now", joined, f"Use {models._REDACTED} now"


class TestSecondRedaction:
    """Step 6 (amended): a credential split by a banned character is redacted.

    A soft hyphen, a word joiner or DEL inside a credential hides it from
    ``models.sanitize_display_text`` (``models._CONTROL_CHAR_TABLE`` keeps
    them); removing them would hand a clean, unredacted credential to the title.
    """

    @pytest.mark.parametrize(
        "char", [SHY, WORD_JOINER, DEL], ids=["soft-hyphen", "word-joiner", "del"]
    )
    @pytest.mark.parametrize("kind", ["key", "bearer"])
    @pytest.mark.parametrize("function", ["sanitize_title", "fallback_title"])
    def test_chat_titles_credential_split_by_an_invisible_character_is_redacted(
        self, ct: ModuleType, function: str, kind: str, char: str
    ) -> None:
        raw, joined, expected = _split_credential(kind, char)
        assert models._REDACTED not in models.sanitize_display_text(raw)  # first pass misses it
        result = getattr(ct, function)(raw)
        assert result == expected == models.sanitize_display_text(joined)
        assert _invariant_violation(result) is None

    @pytest.mark.parametrize("function", ["sanitize_title", "fallback_title"])
    def test_chat_titles_split_token_is_redacted_before_truncating(
        self, ct: ModuleType, function: str
    ) -> None:
        """The marker is longer than ``Bearer x``: redacting after the cut would pass 80 chars."""
        raw = f"Use Bea{SHY}rer x " + " ".join(["word"] * 16)
        result = getattr(ct, function)(raw)
        assert result == f"Use {models._REDACTED} " + " ".join(["word"] * 10) + ELLIPSIS
        assert _invariant_violation(result) is None


class TestKeySplitPastTheMinimum:
    """Security audit L-2: a key split after its 20th key character is redacted whole.

    Split 40 characters into the body of the 164-character ``sk-proj-`` key, the
    part before the invisible character is already a key on its own. Redacting
    before the character goes would redact only that head; removing the
    character afterwards joins the tail (which doesn't start with ``sk-``) onto
    the marker, and no later pass can match it. The banned characters go before
    the redaction, so the key is joined first and becomes one marker.
    """

    @pytest.mark.parametrize(
        "char", [SHY, WORD_JOINER, DEL], ids=["soft-hyphen", "word-joiner", "del"]
    )
    @pytest.mark.parametrize("function", ["sanitize_title", "fallback_title"])
    def test_chat_titles_key_split_past_its_minimum_length_is_redacted_whole(
        self, ct: ModuleType, function: str, char: str
    ) -> None:
        key = openai_project_key()
        split = key.prefix + key.body[:40] + char + key.body[40:]
        alone = getattr(ct, function)(split)
        in_sentence = getattr(ct, function)(f"Rotate {split} today")
        assert (alone, in_sentence) == (models._REDACTED, f"Rotate {models._REDACTED} today")
        assert surviving_chunks(alone + in_sentence, key) == []


# ===========================================================================
# 5c. Long API keys in titles (GH-264)
# ===========================================================================

_LONG_KEYS = pytest.mark.parametrize(
    "key",
    [openai_project_key(), anthropic_api03_key()],
    ids=["openai-project-164", "anthropic-api03-108"],
)
_TITLE_FUNCTIONS = pytest.mark.parametrize("function", ["sanitize_title", "fallback_title"])


class TestLongKeys:
    """A current key format is redacted in full in a model title and in a fallback title.

    Before GH-264 the ``sk-proj-`` key wasn't matched at all and the
    ``sk-ant-api03-`` key only up to its first ``_``: about half of a live key
    showed in every chat list row.
    """

    @_LONG_KEYS
    @_TITLE_FUNCTIONS
    def test_chat_titles_long_key_alone_is_redacted_whole(
        self, ct: ModuleType, function: str, key: ApiKey
    ) -> None:
        result = getattr(ct, function)(key.text)
        assert result == models._REDACTED
        assert surviving_chunks(result, key) == []

    @_LONG_KEYS
    @_TITLE_FUNCTIONS
    def test_chat_titles_long_key_in_a_sentence_is_redacted_and_the_text_kept(
        self, ct: ModuleType, function: str, key: ApiKey
    ) -> None:
        result = getattr(ct, function)(f"Rotate {key.text} today")
        assert result == f"Rotate {models._REDACTED} today"
        assert surviving_chunks(result, key) == []


# ===========================================================================
# 6. generate_title and GeneratedTitle
# ===========================================================================


class TestGeneratedTitle:
    """The result type."""

    def test_chat_titles_generated_title_is_a_frozen_dataclass(self, ct: ModuleType) -> None:
        title = ct.GeneratedTitle("Trip planning", "model")
        assert dataclasses.is_dataclass(title)
        assert [field.name for field in dataclasses.fields(title)] == ["title", "source"]
        with pytest.raises(dataclasses.FrozenInstanceError):
            title.title = "Changed"  # type: ignore[misc]
        assert title == ct.GeneratedTitle("Trip planning", "model")


@pytest.mark.usefixtures("sleeps")
class TestGenerateTitleCall:
    """What reaches the client, and through which path."""

    async def test_chat_titles_generate_title_sends_exactly_the_title_messages(
        self, ct: ModuleType
    ) -> None:
        client = TitleClient([_reply("Zurich trip")])
        await ct.generate_title(client, USER, ASSISTANT, data_residency=False, max_retries=0)
        assert len(client.calls) == 1
        assert client.calls[0]["messages"] == ct.build_title_messages(USER, ASSISTANT)

    async def test_chat_titles_generate_title_sends_no_tools(self, ct: ModuleType) -> None:
        client = TitleClient([_reply("Zurich trip")])
        await ct.generate_title(client, USER, ASSISTANT, data_residency=False, max_retries=0)
        assert not client.calls[0]["tools"]

    async def test_chat_titles_generate_title_caps_output_at_title_max_tokens(
        self, ct: ModuleType
    ) -> None:
        client = TitleClient([_reply("Zurich trip")])
        await ct.generate_title(client, USER, ASSISTANT, data_residency=False, max_retries=0)
        max_tokens = client.calls[0]["max_tokens"]
        assert type(max_tokens) is int
        assert max_tokens == ct.TITLE_MAX_TOKENS == 40

    @pytest.mark.parametrize(
        ("data_residency", "max_retries"), [(True, 3), (False, 0)], ids=["residency", "open"]
    )
    async def test_chat_titles_generate_title_goes_through_llm_policy_chat(
        self,
        ct: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        data_residency: bool,
        max_retries: int,
    ) -> None:
        """llm_policy.chat is looked up at call time, with the flags passed through."""
        seen: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

        async def spy(*args: Any, **kwargs: Any) -> LLMResponse:
            seen.append((args, kwargs))
            return _reply("Spy title")

        def contract_shape(
            client: object,
            messages: object,
            tools: object = None,
            *,
            data_residency: object,
            max_retries: object,
            max_tokens: object = None,
        ) -> None:
            """The signature llm_policy.chat has after GH-179."""

        monkeypatch.setattr(llm_policy, "chat", spy)
        client = TitleClient([_reply("Client title")], provider="infomaniak")
        result = await ct.generate_title(
            client, USER, ASSISTANT, data_residency=data_residency, max_retries=max_retries
        )
        assert result == ct.GeneratedTitle("Spy title", "model")
        assert client.calls == []
        assert len(seen) == 1
        bound = inspect.signature(contract_shape).bind(*seen[0][0], **seen[0][1])
        arguments = bound.arguments
        assert arguments["client"] is client
        assert arguments["messages"] == ct.build_title_messages(USER, ASSISTANT)
        assert not arguments.get("tools")
        assert arguments["data_residency"] is data_residency
        assert type(arguments["max_retries"]) is int
        assert arguments["max_retries"] == max_retries
        assert type(arguments.get("max_tokens")) is int
        assert arguments["max_tokens"] == 40


@pytest.mark.usefixtures("sleeps")
class TestGenerateTitleResult:
    """The sanitized model title, or the fallback."""

    async def test_chat_titles_generate_title_returns_the_sanitized_model_title(
        self, ct: ModuleType
    ) -> None:
        client = TitleClient([_reply('<think>hm</think>\nTitle: "Zurich trip plan."\nmore')])
        result = await ct.generate_title(
            client, USER, ASSISTANT, data_residency=False, max_retries=0
        )
        assert result == ct.GeneratedTitle("Zurich trip plan", "model")

    async def test_chat_titles_generate_title_truncates_a_long_model_title(
        self, ct: ModuleType
    ) -> None:
        client = TitleClient([_reply(" ".join(["alpha"] * 30))])
        result = await ct.generate_title(
            client, USER, ASSISTANT, data_residency=False, max_retries=0
        )
        assert result == ct.GeneratedTitle(" ".join(["alpha"] * 13) + ELLIPSIS, "model")

    async def test_chat_titles_generate_title_ignores_tool_calls_and_uses_the_text(
        self, ct: ModuleType
    ) -> None:
        reply = LLMResponse(
            content="Zurich trip",
            tool_calls=[ToolCall(tool="gmail", action="search", args={"query": "zurich"})],
            done=True,
        )
        client = TitleClient([reply])
        result = await ct.generate_title(
            client, USER, ASSISTANT, data_residency=False, max_retries=0
        )
        assert result == ct.GeneratedTitle("Zurich trip", "model")

    @pytest.mark.parametrize(
        "content",
        ["", "   \n\t", "<think>only reasoning</think>", '""', "Title:"],
        ids=["empty", "whitespace", "only-think", "only-quotes", "only-label"],
    )
    async def test_chat_titles_generate_title_unusable_reply_falls_back(
        self, ct: ModuleType, content: str
    ) -> None:
        client = TitleClient([_reply(content)])
        result = await ct.generate_title(
            client, USER, ASSISTANT, data_residency=False, max_retries=0
        )
        assert result == ct.GeneratedTitle(USER_FALLBACK, "fallback")
        assert len(client.calls) == 1

    async def test_chat_titles_generate_title_tool_calls_without_text_fall_back(
        self, ct: ModuleType
    ) -> None:
        reply = LLMResponse(
            content="", tool_calls=[ToolCall(tool="gmail", action="search")], done=True
        )
        client = TitleClient([reply])
        result = await ct.generate_title(
            client, USER, ASSISTANT, data_residency=False, max_retries=0
        )
        assert result == ct.GeneratedTitle(USER_FALLBACK, "fallback")

    async def test_chat_titles_generate_title_empty_fallback_is_returned_empty(
        self, ct: ModuleType
    ) -> None:
        client = TitleClient([_err("provider_unavailable")])
        result = await ct.generate_title(
            client, "  \n ", ASSISTANT, data_residency=False, max_retries=0
        )
        assert result == ct.GeneratedTitle("", "fallback")


@pytest.mark.usefixtures("sleeps")
class TestGenerateTitleResidency:
    """The residency guard of llm_policy.chat: no call to a non-Swiss provider."""

    @pytest.mark.parametrize(
        "provider", ["anthropic", "openai", _MISSING], ids=["anthropic", "openai", "missing"]
    )
    async def test_chat_titles_generate_title_residency_non_swiss_falls_back_without_a_call(
        self, ct: ModuleType, provider: object
    ) -> None:
        client = TitleClient([_reply("Zurich trip")], provider=provider)
        result = await ct.generate_title(
            client, USER, ASSISTANT, data_residency=True, max_retries=3
        )
        assert result == ct.GeneratedTitle(USER_FALLBACK, "fallback")
        assert client.calls == []

    @pytest.mark.parametrize(
        ("data_residency", "provider"),
        [(True, "infomaniak"), (True, "vllm"), (False, "anthropic")],
        ids=["residency-infomaniak", "residency-vllm", "open-anthropic"],
    )
    async def test_chat_titles_generate_title_allowed_provider_is_called(
        self, ct: ModuleType, data_residency: bool, provider: str
    ) -> None:
        client = TitleClient([_reply("Zurich trip")], provider=provider)
        result = await ct.generate_title(
            client, USER, ASSISTANT, data_residency=data_residency, max_retries=0
        )
        assert result == ct.GeneratedTitle("Zurich trip", "model")
        assert len(client.calls) == 1


@pytest.mark.usefixtures("sleeps")
class TestGenerateTitleFailures:
    """Retries happen inside llm_policy.chat; every failure ends in the fallback."""

    async def test_chat_titles_generate_title_retries_a_retryable_error(
        self, ct: ModuleType, sleeps: list[float]
    ) -> None:
        client = TitleClient([_err("timeout"), _reply("Zurich trip")])
        result = await ct.generate_title(
            client, USER, ASSISTANT, data_residency=False, max_retries=1
        )
        assert result == ct.GeneratedTitle("Zurich trip", "model")
        assert [call["max_tokens"] for call in client.calls] == [40, 40]
        assert client.calls[1]["messages"] == ct.build_title_messages(USER, ASSISTANT)
        assert len(sleeps) == 1

    async def test_chat_titles_generate_title_without_retries_falls_back_after_one_call(
        self, ct: ModuleType, sleeps: list[float]
    ) -> None:
        client = TitleClient([_err("timeout"), _reply("Zurich trip")])
        result = await ct.generate_title(
            client, USER, ASSISTANT, data_residency=False, max_retries=0
        )
        assert result == ct.GeneratedTitle(USER_FALLBACK, "fallback")
        assert len(client.calls) == 1
        assert sleeps == []

    async def test_chat_titles_generate_title_exhausted_retries_fall_back(
        self, ct: ModuleType
    ) -> None:
        client = TitleClient([_err("rate_limited")])
        result = await ct.generate_title(
            client, USER, ASSISTANT, data_residency=False, max_retries=2
        )
        assert result == ct.GeneratedTitle(USER_FALLBACK, "fallback")
        assert len(client.calls) == 3

    @pytest.mark.parametrize("code", ["not_configured", "missing_model", "context_too_long"])
    async def test_chat_titles_generate_title_non_retryable_error_falls_back(
        self, ct: ModuleType, code: str
    ) -> None:
        client = TitleClient([_err(code), _reply("Zurich trip")])
        result = await ct.generate_title(
            client, USER, ASSISTANT, data_residency=False, max_retries=3
        )
        assert result == ct.GeneratedTitle(USER_FALLBACK, "fallback")
        assert len(client.calls) == 1

    async def test_chat_titles_generate_title_other_exception_falls_back(
        self, ct: ModuleType
    ) -> None:
        client = TitleClient([RuntimeError("provider exploded"), _reply("Zurich trip")])
        result = await ct.generate_title(
            client, USER, ASSISTANT, data_residency=False, max_retries=3
        )
        assert result == ct.GeneratedTitle(USER_FALLBACK, "fallback")
        assert len(client.calls) == 1

    async def test_chat_titles_generate_title_client_without_max_tokens_falls_back(
        self, ct: ModuleType
    ) -> None:
        client = LegacyClient()
        result = await ct.generate_title(
            client, USER, ASSISTANT, data_residency=False, max_retries=0
        )
        assert result == ct.GeneratedTitle(USER_FALLBACK, "fallback")
        assert client.calls == 0

    @pytest.mark.parametrize(
        "error",
        [MemoryError, RecursionError, asyncio.CancelledError],
        ids=["memory", "recursion", "cancelled"],
    )
    async def test_chat_titles_generate_title_fatal_errors_propagate(
        self, ct: ModuleType, error: type[BaseException]
    ) -> None:
        client = TitleClient([error()])
        with pytest.raises(error):
            await ct.generate_title(client, USER, ASSISTANT, data_residency=False, max_retries=0)

    async def test_chat_titles_generate_title_logs_nothing_and_no_content(
        self, ct: ModuleType
    ) -> None:
        """generate_title logs nothing itself; no content reaches any log.

        title_chat logs the outcome. Neither the messages, the reply, the title nor an
        error message may show up in a line another module writes (llm_policy's retry).
        """
        markers = ("CANARY-user-5b1f", "CANARY-reply-77d0", "CANARY-error-c3a9", "CANARY-asst-1e42")
        user = f"Plan {markers[0]} trip"
        assistant = f"Sure {markers[3]}"
        clients = [
            TitleClient([_reply(f"Trip {markers[1]}")]),
            TitleClient([_reply(f"<think>{markers[1]}</think>")]),
            TitleClient([RuntimeError(markers[2])]),
            TitleClient([LLMError(markers[2], 500)]),
            TitleClient([_err("timeout"), _reply(f"Trip {markers[1]}")]),
            TitleClient([_reply("Trip")], provider="anthropic"),
        ]
        with configured_logging("DEBUG", "json") as captured:
            for client in clients:
                await ct.generate_title(client, user, assistant, data_residency=True, max_retries=1)
            text = captured.text
            records = list(captured.records)
        assert [r.getMessage() for r in records if r.name.startswith("admino.chat_titles")] == []
        assert not any(marker in text for marker in markers)
        for record in records:
            rendered = " ".join(
                [
                    record.getMessage(),
                    repr(record.args),
                    record.exc_text or "",
                    str(record.exc_info),
                ]
            )
            assert not any(marker in rendered for marker in markers), record.getMessage()
