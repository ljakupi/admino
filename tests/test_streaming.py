"""Spec for ``admino.streaming`` and the SSE frame models of streamed chat turns (GH-8).

GH-8 contract sections C2 (``admino.streaming``), C5.2 (frames), C5.3 (the
``StreamErrorCode`` model), C3 (``AgentStatus``) and C5.7 (``ChatStopResponse``).

What is pinned here:

- ``admino.streaming`` imports only the standard library, ``admino.models`` and
  ``admino.logs`` (AST of the imported module's file: never server, agent,
  database, llm*, tools).
- ``RunStream`` is a dataclass with the fields ``on_delta``, ``on_tool_call`` and
  ``stop``, in that order; the two callbacks are required, ``stop`` defaults to
  a fresh, unset ``asyncio.Event`` per instance. ``MAX_DELTA_CHARS == 4096``.
- ``DisplayDeltas`` is the credential redaction of the live stream, tested
  adversarially. INVARIANT: for any feeds ``t1..tn`` then ``flush()``, the
  concatenation of every returned piece equals
  ``models.sanitize_display_text(t1 + ... + tn)``; every piece is a non-empty
  ``str`` of at most 4096 characters; and no piece holds an 8-character window
  of a planted secret that the display text doesn't show (no key is ever
  streamed in part). Checked for plain prose; every key format of
  tests/credential_keys.py plus the older rules (Google refresh/access tokens
  and client secrets, Stripe restricted keys, GitHub classic tokens, AWS key
  ids, Slack tokens, JWTs), split into two feeds at EVERY index and into seeded
  random multi-feed splits (empty feeds included), in a sentence, between
  tabs/newlines and alone; ``Bearer <token>`` with the token split anywhere,
  after spaces, LF, CRLF, tab, NBSP, U+3000, after a word that displays as
  nothing or as whitespace only (``Bearer <NBSP> tok``, ``Bearer <ZWSP> tok``),
  glued (``xBearer``), doubled (``Bearer Bearer``), fullwidth, split by a soft
  hyphen or followed by one; invisible runs before and inside keys (GH-270),
  including the removed characters that ``str.isspace`` calls whitespace (VT,
  FF, NEL, U+2028, U+001C): they are NOT word boundaries, so a key split by one
  is still redacted whole; fullwidth ``sk-`` keys; text without any ASCII
  whitespace (nothing before ``flush``); more than 4096 characters without
  whitespace (several bounded pieces at flush, a key across the cut redacted
  first); one feed of more than 4096 characters of words.
- Promptness, exactly as C2: the contract's examples verbatim; after each feed
  the pieces so far are ``sanitize_display_text(raw[:b])`` where ``b`` is just
  after the last ASCII whitespace (space, tab, LF, CR), moved back to the start
  of the last word while that word reads ``Bearer`` at its end once displayed
  (NFKC, invisible characters removed, trailing Unicode whitespace ignored),
  repeatedly (an oracle of that rule over many splits); a feed ending mid-word
  returns the text up to the last ASCII whitespace; NBSP, U+3000 and the other
  Unicode spaces are not boundaries, CR, LF and tab are; an empty feed returns
  ``[]``; ``flush()`` on nothing returns ``[]``; ``flush()`` resets (the next
  answer's invariant holds on its own). ``DisplayDeltas`` logs no text.
- A cut answer (C11, audit core L-1): ``flush(*, complete=True)``, keyword-only;
  ``complete=True`` is today's ``flush()``. ``complete=False`` drops the text
  after the answer's last ASCII whitespace and sends a held ``Bearer`` word (no
  token follows); nothing when the answer has no ASCII whitespace; it resets
  like ``flush()``. INVARIANT: the answer stopped at EVERY index (fed whole and
  split), the joined pieces equal ``sanitize_display_text(raw[:b])`` with ``b``
  just after the last ASCII whitespace; every key format cut at every index
  inside the key streams no 8-character window of it (the cut answer's display
  never shows one); the same for Bearer tokens, GH-270 separators and removed
  characters inside a key (VT, NEL, U+2028, U+001C: no boundary).
- SSE frames through the existing ``server._make_sse_event(name, payload)``:
  parsed per the SSE spec (CR, LF and CRLF end a line, a blank line ends an
  event), a frame is exactly ONE event of that name whose data ``json.loads``
  back to the payload, for payload strings holding a forged frame, lone CR,
  CRLF, U+2028, U+2029, U+0085, NUL and quotes; an event name with a newline,
  a CR, a colon-space injection or a space is refused (``ValidationError``
  from ``SSEEvent``). These frame tests pass before GH-8 (the helper exists):
  they are regression guards for the frames the stream now sends.
- models.py: ``StreamErrorCode`` holds exactly the ten C5.3 codes plus GH-25's
  ``malformed_response`` (eleven);
  ``ChatStopResponse(stopped=...)`` dumps to ``{"stopped": ...}`` and refuses
  extra fields and a missing ``stopped``; ``AgentStatus`` gains ``"stopped"``
  and keeps its four values (``AgentResult`` accepts it).

Contract gap resolved here (flagged in the hand-back): C2's promptness rule
looks at "the last word" only, so ``Bearer <ZWSP> tok`` (a word that displays
as nothing between ``Bearer`` and the token) would send ``Bearer`` before the
token arrives, while ``sanitize_display_text`` of the whole redacts the token:
the INVARIANT wins. The invariant tests include those inputs; the promptness
oracle runs only on inputs whose words all display as something.

Fake secrets are built at runtime (tests/credential_keys.py, seeded
``random.Random``); no key literal is written here. ``admino.streaming`` and
the new models are looked up inside the tests, so this file collects before
GH-8 and each test fails on its own.
"""

from __future__ import annotations

import ast
import asyncio
import dataclasses
import inspect
import itertools
import json
import random
import re
import string
import sys
import typing
import unicodedata
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest
from pydantic import ValidationError

from admino import models
from admino.models import sanitize_display_text
from tests.credential_keys import (
    ALNUM_CHARS,
    NEW_KEY_FORMATS,
    KeyFormat,
    anthropic_api03_key,
    api_key,
    openai_project_key,
)
from tests.log_capture import configured_logging

if TYPE_CHECKING:
    from collections.abc import Callable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX: Final = 4096  # MAX_DELTA_CHARS, the contract's literal
_WINDOW: Final = 8
_REDACTED: Final = "[CREDENTIAL_REDACTED]"
_ASCII_WS: Final = " \t\n\r"
_REMOVED_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})

# Characters built with chr(): unreadable or ambiguous as literals.
NBSP: Final = chr(0x00A0)
IDEOGRAPHIC_SPACE: Final = chr(0x3000)
OGHAM_SPACE: Final = chr(0x1680)
EM_SPACE: Final = chr(0x2003)
SHY: Final = chr(0x00AD)  # soft hyphen
ZWSP: Final = chr(0x200B)  # zero width space
WJ: Final = chr(0x2060)  # word joiner
VT: Final = chr(0x0B)
FF: Final = chr(0x0C)
NEL: Final = chr(0x85)
FILE_SEP: Final = chr(0x1C)
LINE_SEP: Final = chr(0x2028)
PARA_SEP: Final = chr(0x2029)
NUL: Final = chr(0)
FULLWIDTH_BEARER: Final = "".join(chr(ord(char) + 0xFEE0) for char in "Bearer")
FULLWIDTH_SK_HYPHEN: Final = chr(0xFF53) + chr(0xFF4B) + chr(0xFF0D)

_TOKEN_CHARS: Final = ALNUM_CHARS + "._~+/-"

_STREAM_ERROR_CODES: Final = frozenset(
    {
        "not_configured",
        "missing_model",
        "provider_unavailable",
        "rate_limited",
        "timeout",
        "residency_blocked",
        "context_too_long",
        "malformed_response",
        "rate_limit",
        "internal_error",
        "chat_not_found",
    }
)
_AGENT_STATUSES: Final = frozenset(
    {"final", "awaiting_confirmation", "limit_reached", "error", "stopped"}
)


# ---------------------------------------------------------------------------
# Fake secrets (built at runtime)
# ---------------------------------------------------------------------------


def _jwt() -> str:
    """A JWT-shaped token: three base64url segments, the first two starting ``ey``."""
    rng = random.Random(8080)  # noqa: S311 - a deterministic fake token, not a secret

    def segment(length: int) -> str:
        return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(length))

    return "e" + "y" + segment(34) + ".e" + "y" + segment(60) + "." + segment(43)


def _bearer_token(seed: int = 4040) -> str:
    rng = random.Random(seed)  # noqa: S311 - a deterministic fake token, not a secret
    return "".join(rng.choice(_TOKEN_CHARS) for _ in range(40))


def _all_keys() -> dict[str, str]:
    """Every key format the display redaction knows, by id: the whole key text."""
    keys = {
        "openai-project": openai_project_key().text,
        "anthropic": anthropic_api03_key().text,
    }
    keys.update({fmt.name: fmt.key().text for fmt in NEW_KEY_FORMATS})
    keys.update(
        {
            "google-refresh": api_key("1" + "//", 66, seed=801).text,
            "google-access": api_key("ya" + "29.", 95, seed=802).text,
            "google-client-secret": api_key("GOC" + "SPX-", 35, seed=803).text,
            "stripe-restricted": KeyFormat("x", "rk" + "_live_", ALNUM_CHARS, 20, 40, seed=804)
            .key()
            .text,
            "github-classic": KeyFormat("x", "gh" + "p_", ALNUM_CHARS, 36, 36, seed=805).key().text,
            "aws-key-id": KeyFormat(
                "x", "AK" + "IA", string.ascii_uppercase + string.digits, 16, 16, seed=806
            )
            .key()
            .text,
            "slack": KeyFormat("x", "xo" + "xb-", ALNUM_CHARS + "-", 10, 40, seed=807).key().text,
            "jwt": _jwt(),
        }
    )
    return keys


_KEYS: Final = _all_keys()
_KEY_IDS: Final = tuple(_KEYS)
_OPENAI: Final = openai_project_key()


# Bearer and the token in every separating form (C2); {t} is the token.
_BEARER_TEMPLATES: Final = {
    "space": "Use Bearer {t} now",
    "two-spaces": "Use Bearer  {t} now",
    "lf": "Use Bearer\n{t}\nnow",
    "crlf": "Use Bearer\r\n{t} now",
    "tab": "Use Bearer\t{t} now",
    "mixed-ascii": "Use Bearer \r\n\t {t} now",
    "nbsp": "Use Bearer" + NBSP + "{t} now",
    "ideographic-space": "Use Bearer" + IDEOGRAPHIC_SPACE + "{t} now",
    "trailing-nbsp": "Use Bearer" + NBSP + " {t} now",
    "nbsp-word": "Use Bearer " + NBSP + " {t} now",
    "ideographic-word": "Use Bearer " + IDEOGRAPHIC_SPACE + " {t} now",
    "zwsp-word": "Use Bearer " + ZWSP + " {t} now",
    "glued": "Use xBearer {t} now",
    "tripled": "Use Bearer Bearer Bearer {t} now",
    "fullwidth": "Use " + FULLWIDTH_BEARER + " {t} now",
    "soft-hyphen-inside": "Use Bea" + SHY + "rer {t} now",
    "soft-hyphen-after": "Use Bearer" + SHY + " {t} now",
    "line-start": "Header:\nBearer {t}\nnext line",
    "end-of-text": "the header is Bearer {t}",
    "text-start": "Bearer {t} is the header",
}

# GH-270 separators and NFKC prefixes before a key.
_SEPARATOR_TEXTS: Final[dict[str, Callable[[str], str]]] = {
    "shy-after-letter": lambda key: f"Key: a{SHY}{key} ok",
    "zwsp-after-word": lambda key: f"Key: key{ZWSP}{key} ok",
    "wj-after-digit": lambda key: f"Key: 9{WJ}{key} ok",
    "shy-after-underscore": lambda key: f"Key: _{SHY}{key} ok",
    "vt-after-letter": lambda key: f"Key: a{VT}{key} ok",
    "nel-after-letter": lambda key: f"Key: a{NEL}{key} ok",
    "shy-inside-prefix": lambda key: f"Key: a{SHY}s{SHY}k-{key[3:]} ok",
    "fullwidth-prefix": lambda key: f"Key: {FULLWIDTH_SK_HYPHEN}{key[3:]} ok",
    "fullwidth-after-letter": lambda key: f"Key: a{SHY}{FULLWIDTH_SK_HYPHEN}{key[3:]} ok",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _streaming() -> Any:
    """``admino.streaming`` (GH-8), imported lazily so this file collects without it."""
    from admino import streaming

    return streaming


def _first_difference(actual: str, expected: str) -> tuple[int, int, str, str] | None:
    """None when equal, else (lengths difference, first index, 20-char windows there)."""
    if actual == expected:
        return None
    index = next(
        (i for i, (a, b) in enumerate(zip(actual, expected, strict=False)) if a != b),
        min(len(actual), len(expected)),
    )
    return (
        len(actual) - len(expected),
        index,
        actual[max(0, index - 10) : index + 10],
        expected[max(0, index - 10) : index + 10],
    )


def _windows(secret: str) -> set[str]:
    return {secret[i : i + _WINDOW] for i in range(len(secret) - _WINDOW + 1)}


def _stream(feeds: list[str], deltas: Any = None) -> tuple[list[list[str]], list[str]]:
    """Feed every text to one answer, then flush: (pieces per feed, flushed pieces)."""
    deltas = _streaming().DisplayDeltas() if deltas is None else deltas
    per_feed = [deltas.feed(text) for text in feeds]
    return per_feed, deltas.flush()


def _problems(feeds: list[str], secrets: tuple[str, ...] = ()) -> list[str]:
    """Every way one answer's pieces break the C2 invariant (empty: none)."""
    raw = "".join(feeds)
    display = sanitize_display_text(raw)
    per_feed, flushed = _stream(feeds)
    pieces = [piece for batch in per_feed for piece in batch] + flushed
    problems = [
        f"bad piece {type(piece).__name__} of {len(piece)} chars"
        for piece in pieces
        if type(piece) is not str or not piece or len(piece) > _MAX
    ]
    difference = _first_difference("".join(map(str, pieces)), display)
    if difference is not None:
        problems.append(f"joined pieces != display text: {difference}")
    for secret in secrets:
        hidden = {window for window in _windows(secret) if window not in display}
        leaked = {window for piece in pieces for window in hidden if window in str(piece)}
        if leaked:
            problems.append(f"{len(leaked)} windows of a secret streamed")
    return problems


def _cuts(feeds: list[str]) -> list[int]:
    return list(itertools.accumulate(len(text) for text in feeds))[:-1]


def _two_feed_splits(text: str) -> list[list[str]]:
    """The text split into two feeds at every index (empty first or last feed included)."""
    return [[text[:index], text[index:]] for index in range(len(text) + 1)]


def _random_splits(text: str, seed: int, count: int = 40) -> list[list[str]]:
    """Seeded multi-feed splits: half by random cut points, half token-sized (1-6 chars);
    an empty feed is inserted now and then."""
    rng = random.Random(seed)  # noqa: S311 - deterministic splits, not a secret
    splits: list[list[str]] = []
    for number in range(count):
        if number % 2:
            bounds = [0]
            while bounds[-1] < len(text):
                bounds.append(min(len(text), bounds[-1] + rng.randint(1, 6)))
        else:
            wanted = rng.randint(1, max(1, min(12, len(text) - 1)))
            inner = sorted(rng.sample(range(1, len(text)), min(wanted, max(0, len(text) - 1))))
            bounds = [0, *inner, len(text)]
        feeds = [text[start:end] for start, end in itertools.pairwise(bounds)]
        if rng.random() < 0.3:
            feeds.insert(rng.randint(0, len(feeds)), "")
        splits.append(feeds)
    return splits


def _failures(
    splits: list[list[str]], secrets: tuple[str, ...] = ()
) -> list[tuple[list[int], list[str]]]:
    """(cut indexes, problems) of every split that breaks the invariant."""
    failures = []
    for feeds in splits:
        problems = _problems(feeds, secrets)
        if problems:
            failures.append((_cuts(feeds), problems))
    return failures


def _assert_fully_redacted(text: str, secrets: tuple[str, ...]) -> None:
    """Fixture guard: the display text of the whole input shows no window of any secret."""
    display = sanitize_display_text(text)
    for secret in secrets:
        assert not {window for window in _windows(secret) if window in display}, (
            "fixture: the display text must hide the secret",
            display[:120],
        )


def _shown(word: str) -> str:
    """A word as displayed before redaction: NFKC, removed characters taken out (C2)."""
    text = unicodedata.normalize("NFKC", word)
    return "".join(
        char
        for char in text
        if char in "\t\n\r" or unicodedata.category(char) not in _REMOVED_CATEGORIES
    )


def _after_last_ascii_ws(raw: str, end: int) -> int:
    return max(raw.rfind(char, 0, end) for char in _ASCII_WS) + 1


def _contract_boundary(raw: str) -> int:
    """C2's ``b``: after the last ASCII whitespace, moved back over Bearer-reading words."""
    boundary = _after_last_ascii_ws(raw, len(raw))
    while boundary > 0:
        word_end = len(raw[:boundary].rstrip(_ASCII_WS))
        start = _after_last_ascii_ws(raw, word_end)
        word = raw[start:word_end]
        if not word:
            break
        shown = _shown(word).rstrip()
        assert shown, "oracle inputs hold no word that displays as nothing"
        if not shown.endswith("Bearer"):
            break
        boundary = start
    return boundary


def _promptness_problems(feeds: list[str]) -> list[str]:
    """Where the pieces sent after a feed differ from sanitize_display_text(raw[:b])."""
    deltas = _streaming().DisplayDeltas()
    sent: list[str] = []
    raw = ""
    problems = []
    for number, text in enumerate(feeds):
        sent.extend(deltas.feed(text))
        raw += text
        expected = sanitize_display_text(raw[: _contract_boundary(raw)])
        difference = _first_difference("".join(sent), expected)
        if difference is not None:
            problems.append(f"after feed {number}: {difference}")
    sent.extend(deltas.flush())
    difference = _first_difference("".join(sent), sanitize_display_text(raw))
    if difference is not None:
        problems.append(f"after flush: {difference}")
    return problems


def _cut_boundary(raw: str) -> int:
    """C11's ``b`` of a cut answer: just after its last ASCII whitespace (0 when none)."""
    return _after_last_ascii_ws(raw, len(raw))


def _cut_problems(feeds: list[str], secrets: tuple[str, ...] = ()) -> list[str]:
    """Every way an answer cut after ``feeds`` (then ``flush(complete=False)``) breaks C11:
    the joined pieces must be ``sanitize_display_text(raw[:b])``, every piece a non-empty
    ``str`` of at most 4096 characters, and no piece may hold an 8-character window of a
    secret that this display text of the cut answer doesn't show."""
    raw = "".join(feeds)
    display = sanitize_display_text(raw[: _cut_boundary(raw)])
    deltas = _streaming().DisplayDeltas()
    pieces = [piece for text in feeds for piece in deltas.feed(text)]
    pieces += deltas.flush(complete=False)
    problems = [
        f"bad piece {type(piece).__name__} of {len(piece)} chars"
        for piece in pieces
        if type(piece) is not str or not piece or len(piece) > _MAX
    ]
    difference = _first_difference("".join(map(str, pieces)), display)
    if difference is not None:
        problems.append(f"joined pieces != display text of the cut answer: {difference}")
    for secret in secrets:
        hidden = {window for window in _windows(secret) if window not in display}
        leaked = {window for piece in pieces for window in hidden if window in str(piece)}
        if leaked:
            problems.append(f"{len(leaked)} windows of a secret streamed")
    return problems


def _cut_feeds(raw: str, seed: int) -> list[list[str]]:
    """The cut answer fed whole, then in two seeded splits (random cuts, token-sized)."""
    return [[raw], *_random_splits(raw, seed=seed, count=2)] if raw else [[raw]]


def _module_tree() -> ast.Module:
    """The parsed source of the imported module (the file that actually runs)."""
    return ast.parse(Path(inspect.getfile(_streaming())).read_text(encoding="utf-8"))


def _literal_values(annotation: Any) -> set[Any]:
    """Every value of a Literal, flattening nested Literals, unions and type aliases."""
    annotation = getattr(annotation, "__value__", annotation)
    values: set[Any] = set()
    for arg in typing.get_args(annotation):
        if typing.get_origin(arg) is not None or hasattr(arg, "__value__"):
            values |= _literal_values(arg)
        else:
            values.add(arg)
    return values


def _parse_sse(text: str) -> list[tuple[str, str]]:
    """Events of an SSE stream per the spec: (event type, data)."""
    events: list[tuple[str, str]] = []
    name, data = "", []
    for line in re.split(r"\r\n|\r|\n", text):
        if line == "":
            if data:
                events.append((name or "message", "\n".join(data)))
            name, data = "", []
            continue
        if line.startswith(":"):
            continue
        field, colon, value = line.partition(":")
        if colon and value.startswith(" "):
            value = value[1:]
        if field == "event":
            name = value
        elif field == "data":
            data.append(value)
    return events


# ===========================================================================
# 1. The module: isolation, RunStream, MAX_DELTA_CHARS
# ===========================================================================


class TestModule:
    """A small stdlib module: run control and the display deltas."""

    def test_streaming_imports_only_the_standard_library_models_and_logs(self) -> None:
        offenders: list[str] = []
        for node in ast.walk(_module_tree()):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    offenders.append(f"relative import level {node.level}")
                    continue
                module = node.module or ""
                names = (
                    [f"admino.{alias.name}" for alias in node.names]
                    if module == "admino"
                    else [module]
                )
            else:
                continue
            offenders.extend(
                name
                for name in names
                if name not in {"admino.models", "admino.logs"}
                and name.split(".")[0] not in sys.stdlib_module_names
            )

        assert offenders == []

    def test_streaming_max_delta_chars_is_4096(self) -> None:
        assert _streaming().MAX_DELTA_CHARS == _MAX

    async def test_streaming_run_stream_has_two_callbacks_and_a_fresh_unset_stop_event(
        self,
    ) -> None:
        """Each RunStream gets its own Event: stopping one run never stops another."""
        run_stream = _streaming().RunStream

        async def on_delta(text: str) -> None:
            return None

        async def on_tool_call(record: models.ToolCallRecord) -> None:
            return None

        first = run_stream(on_delta=on_delta, on_tool_call=on_tool_call)
        second = run_stream(on_delta, on_tool_call)

        assert dataclasses.is_dataclass(run_stream)
        assert [field.name for field in dataclasses.fields(run_stream)] == [
            "on_delta",
            "on_tool_call",
            "stop",
        ]
        assert (first.on_delta, first.on_tool_call) == (on_delta, on_tool_call)
        assert isinstance(first.stop, asyncio.Event)
        assert isinstance(second.stop, asyncio.Event)
        assert first.stop is not second.stop
        assert (first.stop.is_set(), second.stop.is_set()) == (False, False)

    def test_streaming_run_stream_requires_both_callbacks(self) -> None:
        run_stream = _streaming().RunStream

        async def on_delta(text: str) -> None:
            return None

        with pytest.raises(TypeError):
            run_stream(on_delta=on_delta)

    def test_streaming_display_deltas_logs_no_text(self) -> None:
        """No delta text, word or key reaches any log record, at DEBUG."""
        marker = "Pangolin-ledger-4711"
        key = _OPENAI.text
        with configured_logging("DEBUG", "text") as logs:
            _stream([f"{marker} and ", f"{key[:30]}", f"{key[30:]} Bearer ", "tok-9 end"])

        haystacks = [logs.text]
        for record in logs.records:
            haystacks.extend((record.getMessage(), repr(record.args)))
        hits = [
            text
            for text in haystacks
            if marker in text or "Pangolin" in text or any(w in text for w in _windows(key))
        ]
        assert hits == []


# ===========================================================================
# 2. DisplayDeltas: the invariant (credential redaction of the live stream)
# ===========================================================================


class TestInvariant:
    """The joined pieces are the display text; no secret is ever streamed in part."""

    def test_streaming_plain_prose_streams_its_display_text(self) -> None:
        text = (
            "Hello there! Here is the plan:\n\n1. Read the invoices.\r\n"
            "2. Sum the totals\tand report back.  Thanks, "
            + "caf"
            + chr(0xE9)
            + " "
            + chr(0x1F600)
            + " done."
        )
        splits = [[text], *_two_feed_splits(text), *_random_splits(text, seed=11)]

        assert _failures(splits) == []

    @pytest.mark.parametrize("key_id", _KEY_IDS)
    def test_streaming_key_split_at_every_index_is_never_streamed_in_part(
        self, key_id: str
    ) -> None:
        key = _KEYS[key_id]
        text = f"Here is the key {key} for you."
        _assert_fully_redacted(text, (key,))

        failures = _failures(_two_feed_splits(text), (key,))

        assert not failures, (len(failures), failures[:5])

    @pytest.mark.parametrize("key_id", _KEY_IDS)
    def test_streaming_key_in_random_multi_feed_splits_is_never_streamed_in_part(
        self, key_id: str
    ) -> None:
        """In a sentence, between tabs and newlines, alone, at the end without whitespace."""
        key = _KEYS[key_id]
        texts = (
            f"Use {key} now please.",
            f"a\t{key}\nb",
            f"\n{key}\n",
            key,
            f"Last one:  {key}",
            f"{key} {key}\r\n",
        )
        failures = []
        for number, text in enumerate(texts):
            _assert_fully_redacted(text, (key,))
            failures.extend(_failures(_random_splits(text, seed=100 + number), (key,)))

        assert not failures, (len(failures), failures[:5])

    @pytest.mark.parametrize("case", list(_BEARER_TEMPLATES))
    def test_streaming_bearer_token_split_anywhere_is_never_streamed(self, case: str) -> None:
        """The word that reads Bearer waits for the word after it, whatever separates them."""
        token = _bearer_token()
        text = _BEARER_TEMPLATES[case].format(t=token)
        _assert_fully_redacted(text, (token,))
        splits = [*_two_feed_splits(text), *_random_splits(text, seed=len(case))]

        failures = _failures(splits, (token,))

        assert not failures, (case, len(failures), failures[:5])

    def test_streaming_bearer_bearer_abc_streams_one_marker(self) -> None:
        """``Bearer Bearer abc``: the second Bearer is the token, abc is shown (C2)."""
        text = "Bearer Bearer abc def"
        splits = [*_two_feed_splits(text), *_random_splits(text, seed=3)]

        assert sanitize_display_text(text) == f"{_REDACTED} abc def"
        assert _failures(splits) == []

    @pytest.mark.parametrize("case", list(_SEPARATOR_TEXTS))
    def test_streaming_separator_or_fullwidth_prefix_before_a_key_never_streams_part(
        self, case: str
    ) -> None:
        """GH-270 separators (a run between a word and a key) and NFKC prefixes."""
        key = _OPENAI.text
        text = _SEPARATOR_TEXTS[case](key)
        _assert_fully_redacted(text, (key,))
        splits = [*_two_feed_splits(text), *_random_splits(text, seed=len(case) + 50)]

        failures = _failures(splits, (key,))

        assert not failures, (case, len(failures), failures[:5])

    @pytest.mark.parametrize("position", [12, 48], ids=["head-short", "head-redactable"])
    @pytest.mark.parametrize(
        "char",
        [SHY, ZWSP, WJ, VT, FF, NEL, FILE_SEP, LINE_SEP, PARA_SEP],
        ids=["shy", "zwsp", "wj", "vt", "ff", "nel", "u001c", "u2028", "u2029"],
    )
    def test_streaming_removed_character_inside_a_key_never_streams_part(
        self, char: str, position: int
    ) -> None:
        """A run inside a key joins it (GH-270): the key is redacted whole. VT, FF, NEL,
        U+001C and U+2028/2029 are whitespace to ``str.isspace`` but removed from the
        display, so they are no word boundary: cut there, a short head (12) would show
        unredacted, a long head (48) redacted alone would leave the tail visible."""
        key = _OPENAI.text
        text = f"Key: {key[:position]}{char}{key[position:]} ok"
        _assert_fully_redacted(text, (key,))
        splits = [*_two_feed_splits(text), *_random_splits(text, seed=position)]

        failures = _failures(splits, (key,))

        assert not failures, (len(failures), failures[:5])

    def test_streaming_text_without_ascii_whitespace_streams_only_at_flush(self) -> None:
        """NBSP, U+3000, VT, NEL and U+2028 inside the run are no boundaries either."""
        text = (
            "Total:"
            + NBSP
            + "1'234.50CHF;"
            + IDEOGRAPHIC_SPACE
            + "ref="
            + VT
            + "INV-2026-0042"
            + NEL
            + "status=paid"
            + LINE_SEP
            + "x" * 200
        )
        feeds = [text[i : i + 7] for i in range(0, len(text), 7)]

        per_feed, flushed = _stream(feeds)

        assert all(batch == [] for batch in per_feed), [b for b in per_feed if b][:3]
        assert _first_difference("".join(flushed), sanitize_display_text(text)) is None
        assert all(type(p) is str and 0 < len(p) <= _MAX for p in flushed)

    def test_streaming_text_over_4096_without_whitespace_flushes_bounded_pieces(self) -> None:
        rng = random.Random(4097)  # noqa: S311 - deterministic filler text
        text = "".join(rng.choice(string.ascii_letters + ",.;") for _ in range(10_000))
        feeds = [text[i : i + 1000] for i in range(0, len(text), 1000)]

        per_feed, flushed = _stream(feeds)

        assert all(batch == [] for batch in per_feed)
        assert len(flushed) >= 3
        assert all(type(p) is str and 0 < len(p) <= _MAX for p in flushed)
        assert _first_difference("".join(flushed), sanitize_display_text(text)) is None

    def test_streaming_key_across_the_4096_cut_is_redacted_before_cutting(self) -> None:
        """The cut is made in the display text: the raw key at index 4091 is never split."""
        key = _OPENAI.text
        text = "x" * 4090 + "," + key + "," + "y" * 5000
        _assert_fully_redacted(text, (key,))
        splits = [[text], [text[i : i + 1000] for i in range(0, len(text), 1000)]]

        assert _failures(splits, (key,)) == []

    def test_streaming_one_feed_of_words_over_4096_returns_bounded_pieces_at_once(
        self,
    ) -> None:
        text = "word salad " * 1000  # 11000 characters ending in a space
        deltas = _streaming().DisplayDeltas()

        pieces = deltas.feed(text)
        rest = deltas.flush()

        assert len(pieces) >= 3
        assert all(type(p) is str and 0 < len(p) <= _MAX for p in pieces)
        assert _first_difference("".join(pieces), sanitize_display_text(text)) is None
        assert rest == []


# ===========================================================================
# 3. DisplayDeltas: promptness (word by word, Bearer held)
# ===========================================================================


class TestPromptness:
    """What a feed returns at once: up to the last ASCII whitespace, Bearer words held."""

    @pytest.mark.parametrize(
        ("feeds", "expected"),
        [
            (["Hello wor", "ld "], [["Hello "], ["world "]]),
            (["x Bearer "], [["x "]]),
            (["Bearer Bearer ", "abc "], [[], [f"{_REDACTED} abc "]]),
        ],
        ids=["hello-world", "x-bearer", "bearer-bearer-abc"],
    )
    def test_streaming_contract_examples_verbatim(
        self, feeds: list[str], expected: list[list[str]]
    ) -> None:
        deltas = _streaming().DisplayDeltas()

        assert [deltas.feed(text) for text in feeds] == expected

    def test_streaming_feed_ending_mid_word_returns_up_to_the_last_ascii_whitespace(
        self,
    ) -> None:
        deltas = _streaming().DisplayDeltas()

        steps = [
            "".join(deltas.feed("one two thr")),
            "".join(deltas.feed("ee")),
            "".join(deltas.feed(" four")),
            "".join(deltas.flush()),
        ]

        assert steps == ["one two ", "", "three ", "four"]

    @pytest.mark.parametrize("space", [" ", "\t", "\n", "\r"], ids=["space", "tab", "lf", "cr"])
    def test_streaming_ascii_whitespace_ends_a_word(self, space: str) -> None:
        deltas = _streaming().DisplayDeltas()

        assert "".join(deltas.feed(f"alpha{space}be")) == f"alpha{space}"

    @pytest.mark.parametrize(
        "char",
        [NBSP, IDEOGRAPHIC_SPACE, EM_SPACE, OGHAM_SPACE, VT, FF, NEL, FILE_SEP, LINE_SEP],
        ids=["nbsp", "u3000", "em-space", "ogham", "vt", "ff", "nel", "u001c", "u2028"],
    )
    def test_streaming_non_ascii_or_removed_whitespace_does_not_end_a_word(self, char: str) -> None:
        """Only space, tab, LF and CR are boundaries; the word waits for one of them."""
        deltas = _streaming().DisplayDeltas()

        held = deltas.feed(f"alpha{char}beta{char}")
        released = "".join(deltas.feed(" "))

        assert (held, released) == ([], sanitize_display_text(f"alpha{char}beta{char} "))

    def test_streaming_empty_feed_returns_nothing(self) -> None:
        deltas = _streaming().DisplayDeltas()

        results = [
            deltas.feed(""),
            deltas.feed("abc"),
            deltas.feed(""),
            deltas.feed(" "),
            deltas.feed(""),
        ]

        assert results[0::2] == [[], [], []]
        assert "".join(results[3]) == "abc "

    def test_streaming_flush_on_nothing_returns_nothing(self) -> None:
        fresh = _streaming().DisplayDeltas()
        sent = _streaming().DisplayDeltas()
        sent_pieces = sent.feed("all sent ")

        assert fresh.flush() == []
        assert fresh.flush() == []
        assert "".join(sent_pieces) == "all sent "
        assert sent.flush() == []

    def test_streaming_flush_resets_for_the_next_answer(self) -> None:
        """The next answer is redacted and sent on its own: a held ``Bearer`` or a
        half word of the previous answer neither joins nor hides it."""
        deltas = _streaming().DisplayDeltas()
        token = _bearer_token(seed=5050)

        first = "".join(deltas.feed("it ends with Bearer")) + "".join(deltas.flush())
        second_feed = "".join(deltas.feed(f" {token} tail "))
        second = second_feed + "".join(deltas.flush())
        third = "".join(deltas.feed("abc")) + "".join(deltas.flush())
        fourth = "".join(deltas.feed("def "))

        assert (first, second, third, fourth) == (
            "it ends with Bearer",
            f" {token} tail ",
            "abc",
            "def ",
        )
        assert second_feed == f" {token} tail "

    @pytest.mark.parametrize(
        "text",
        [
            "The quick brown fox\njumps over\r\nthe lazy\tdog. ",
            "Send it with Bearer {t} and then Bearer {t} again\n",
            "Use xBearer {t} or " + FULLWIDTH_BEARER + " {t} or Bea" + SHY + "rer {t} end",
            "Bearer Bearer {t} after a double, Bearer" + NBSP + " {t} trailing",
            "Header:\r\nBearer\r\n{t}\r\nBearer\t\t{t}",
            "Here is the key {k} and here is {k}\nthanks",
            "Total:" + NBSP + "12 CHF, ref" + IDEOGRAPHIC_SPACE + "77 ok",
        ],
        ids=["prose", "bearer-twice", "bearer-forms", "bearer-double", "crlf-tabs", "keys", "nbsp"],
    )
    def test_streaming_pieces_after_each_feed_match_the_contract_boundary(self, text: str) -> None:
        """An oracle of C2's rule: after every feed the sent text is exactly
        sanitize_display_text(raw[:b]); nothing later, nothing more held back."""
        full = text.format(t=_bearer_token(seed=6060), k=_OPENAI.text)
        splits = [[full], *_two_feed_splits(full), *_random_splits(full, seed=len(full))]

        failures = [(_cuts(feeds), p) for feeds in splits if (p := _promptness_problems(feeds))]

        assert not failures, (len(failures), failures[:5])


# ===========================================================================
# 3b. DisplayDeltas: a cut answer (flush(complete=False), C11 / audit core L-1)
# ===========================================================================

# Answers stopped at every index (C11's invariant); secrets that must never stream in part.
_CUT_TEXTS: Final[dict[str, tuple[str, tuple[str, ...]]]] = {
    "prose": (
        "Hello there!  The plan:\n\n1. Read\tthe invoices.\r\n2. Sum caf"
        + chr(0xE9)
        + " "
        + chr(0x1F600)
        + " Total:"
        + NBSP
        + "12 CHF, ref"
        + IDEOGRAPHIC_SPACE
        + "77 done.",
        (),
    ),
    **{
        f"bearer-{case}": (template.format(t=_bearer_token()), (_bearer_token(),))
        for case, template in _BEARER_TEMPLATES.items()
    },
    **{
        f"separator-{case}": (build(_OPENAI.text), (_OPENAI.text,))
        for case, build in _SEPARATOR_TEXTS.items()
    },
    **{
        f"{name}-inside-a-key": (
            f"Key: {_OPENAI.text[:12]}{char}{_OPENAI.text[12:]} ok",
            (_OPENAI.text,),
        )
        for name, char in (("vt", VT), ("nel", NEL), ("u2028", LINE_SEP), ("u001c", FILE_SEP))
    },
}


class TestCutAnswer:
    """``flush(complete=False)`` ends an answer that didn't complete (stopped, or the run
    ended in an error or exception): the text after its last ASCII whitespace is dropped,
    the Bearer hold-back no longer applies (nothing follows), then it resets."""

    def test_streaming_flush_complete_is_keyword_only_and_true_is_todays_flush(self) -> None:
        """``flush(*, complete=True)``: True (the default) is exactly ``flush()``, the
        unfinished last word and a held Bearer word included."""
        display_deltas = _streaming().DisplayDeltas
        parameter = inspect.signature(display_deltas.flush).parameters.get("complete")
        texts = (
            "Hello wor",
            "x Bearer ",
            "x Bearer tok",
            f"Here is the key {_OPENAI.text}",
            "no-ascii-whitespace" + NBSP + "at-all",
        )
        mismatches = []
        for text in texts:
            for feeds in [[text], *_random_splits(text, seed=len(text), count=4)]:
                default, explicit = display_deltas(), display_deltas()
                by_default = [p for t in feeds for p in default.feed(t)] + default.flush()
                complete = [p for t in feeds for p in explicit.feed(t)]
                complete += explicit.flush(complete=True)
                if by_default != complete or "".join(complete) != sanitize_display_text(text):
                    mismatches.append(_cuts(feeds))

        assert parameter is not None
        assert (parameter.kind, parameter.default) == (inspect.Parameter.KEYWORD_ONLY, True)
        assert mismatches == []

    @pytest.mark.parametrize(
        ("feeds", "sent", "flushed"),
        [
            (["Hello wor"], ["Hello "], []),
            (["Here is the key ", _OPENAI.text[:6], _OPENAI.text[6:10]], ["Here is the key "], []),
            (["one two\tthr"], ["one two\t"], []),
            (["line one\r\nnext"], ["line one\r\n"], []),
            (["x Bearer "], ["x "], ["Bearer "]),
            (["x Bearer tok"], ["x "], ["Bearer "]),
            (["Bearer Bearer ", "abc"], [], [f"{_REDACTED} "]),
        ],
        ids=[
            "hello-wor",
            "key-prefix",
            "tab",
            "crlf",
            "held-bearer",
            "bearer-and-unfinished-token",
            "bearer-bearer",
        ],
    )
    def test_streaming_cut_flush_drops_the_unfinished_last_word(
        self, feeds: list[str], sent: list[str], flushed: list[str]
    ) -> None:
        """The contract's examples: ``"x Bearer "`` then ``flush(complete=False)`` sends
        ``"Bearer "`` (no token follows a cut answer); the text after the last ASCII
        whitespace (a key's first characters, a half word, a half token) is never sent."""
        deltas = _streaming().DisplayDeltas()

        pieces = [piece for text in feeds for piece in deltas.feed(text)]
        rest = deltas.flush(complete=False)

        assert (pieces, rest) == (sent, flushed)

    def test_streaming_cut_flush_without_ascii_whitespace_returns_nothing(self) -> None:
        """No ASCII whitespace in the whole answer: nothing was sent and the cut sends
        nothing (NBSP, U+3000, VT, NEL and U+2028 are no boundary); on a fresh instance too."""
        text = (
            "Total:"
            + NBSP
            + "1'234.50CHF;"
            + IDEOGRAPHIC_SPACE
            + "ref="
            + VT
            + "INV-2026"
            + NEL
            + LINE_SEP
            + _OPENAI.text[:12]
        )
        deltas = _streaming().DisplayDeltas()

        per_feed = [deltas.feed(text[i : i + 5]) for i in range(0, len(text), 5)]
        rest = deltas.flush(complete=False)

        assert all(batch == [] for batch in per_feed)
        assert rest == []
        assert _streaming().DisplayDeltas().flush(complete=False) == []

    def test_streaming_cut_flush_resets_for_the_next_answer(self) -> None:
        """After a cut the next feeds start a new answer: the dropped half word doesn't
        join the next text, and a ``Bearer`` sent by the cut doesn't redact the next
        answer's first word."""
        deltas = _streaming().DisplayDeltas()
        token = _bearer_token(seed=7070)

        first = "".join(deltas.feed("first answer unfini")) + "".join(deltas.flush(complete=False))
        second = "".join(deltas.feed("shed second ")) + "".join(deltas.flush(complete=False))
        third = "".join(deltas.feed("it ends with Bearer ")) + "".join(deltas.flush(complete=False))
        fourth = "".join(deltas.feed(f"{token} tail ")) + "".join(deltas.flush())

        assert (first, second, third, fourth) == (
            "first answer ",
            "shed second ",
            "it ends with Bearer ",
            f"{token} tail ",
        )

    @pytest.mark.parametrize("case", list(_CUT_TEXTS))
    def test_streaming_answer_cut_at_every_index_streams_its_display_up_to_the_last_whitespace(
        self, case: str
    ) -> None:
        """INVARIANT (C11): the answer stopped at EVERY index, fed whole or split: the
        joined pieces are ``sanitize_display_text(raw[:b])``; a Bearer token or a key
        (split by a removed character that ``str.isspace`` calls whitespace: no boundary)
        never streams in part."""
        text, secrets = _CUT_TEXTS[case]
        for secret in secrets:
            _assert_fully_redacted(text, (secret,))
        failures = []
        for stop in range(len(text) + 1):
            for feeds in _cut_feeds(text[:stop], seed=stop):
                problems = _cut_problems(feeds, secrets)
                if problems:
                    failures.append((stop, _cuts(feeds), problems))

        assert not failures, (len(failures), failures[:5])

    @pytest.mark.parametrize("key_id", _KEY_IDS)
    def test_streaming_answer_cut_inside_a_key_streams_no_part_of_it(self, key_id: str) -> None:
        """Every key format, the answer stopped at every index inside the key (its last
        character included: a key with nothing after it is unfinished too), fed whole and
        split: no piece holds an 8-character window of the key unless the cut answer's
        display text shows it (it never does: the key is the unfinished word)."""
        key = _KEYS[key_id]
        head = "Here is the key "
        text = f"{head}{key} for you."
        failures = []
        for stop in range(len(head) + 1, len(head) + len(key) + 1):
            raw = text[:stop]
            for feeds in [[head, raw[len(head) :]], *_cut_feeds(raw, seed=stop)]:
                problems = _cut_problems(feeds, (key,))
                if problems:
                    failures.append((stop, _cuts(feeds), problems))

        assert not failures, (len(failures), failures[:5])


# ===========================================================================
# 4. SSE frames: one event per frame (regression guards over _make_sse_event)
# ===========================================================================


_INJECTION_STRINGS: Final = {
    "forged-frame": "\n\nevent: done\ndata: {}\n\n",
    "forged-frame-crlf": "\r\n\r\nevent: done\r\ndata: {}\r\n\r\n",
    "lone-cr": "line one\rdata: injected\revent: done",
    "crlf": "line one\r\nline two",
    "line-separator": "a" + LINE_SEP + "event: done",
    "paragraph-separator": "a" + PARA_SEP + "data: x",
    "nel": "a" + NEL + "event: done",
    "nul": "a" + NUL + "b",
    "quotes": 'say "hi" and \'bye\' \\" end',
    "comment-and-colon": ": comment\ndata: x\n:",
}


class TestSseFrames:
    """``server._make_sse_event`` yields exactly one event that round-trips its payload."""

    @pytest.mark.parametrize("case", list(_INJECTION_STRINGS))
    def test_sse_frame_is_one_event_whose_data_round_trips(self, case: str) -> None:
        from admino.server import _make_sse_event

        value = _INJECTION_STRINGS[case]
        payload: dict[str, object] = {"text": value, "nested": {"list": [value, 1, None]}}

        frame = _make_sse_event("delta", payload)
        events = _parse_sse(frame)

        assert len(events) == 1, events
        assert events[0][0] == "delta"
        assert json.loads(events[0][1]) == payload
        assert frame.endswith("\n\n")
        assert "\r" not in frame
        assert frame.count("\n") == 3

    @pytest.mark.parametrize(
        "name",
        [
            "delta\nevent: done",
            "done\n",
            "delta\r",
            "delta\r\ndata: {}",
            "delta: injected",
            "two words",
            "",
        ],
        ids=[
            "newline-injection",
            "trailing-lf",
            "trailing-cr",
            "crlf",
            "colon-space",
            "space",
            "empty",
        ],
    )
    def test_sse_frame_refuses_an_event_name_that_could_inject(self, name: str) -> None:
        from admino.server import _make_sse_event

        with pytest.raises(ValidationError):
            _make_sse_event(name, {"text": "x"})


# ===========================================================================
# 5. models.py: StreamErrorCode, ChatStopResponse, AgentStatus
# ===========================================================================


class TestModels:
    """The stream's error codes, the stop answer and the stopped run status."""

    def test_models_stream_error_code_is_exactly_the_eleven_codes(self) -> None:
        values = _literal_values(models.StreamErrorCode)

        assert values == _STREAM_ERROR_CODES

    def test_models_chat_stop_response_dumps_only_stopped(self) -> None:
        response = models.ChatStopResponse

        assert response(stopped=True).model_dump() == {"stopped": True}
        assert response(stopped=False).model_dump(mode="json") == {"stopped": False}
        assert json.loads(response(stopped=True).model_dump_json()) == {"stopped": True}

    @pytest.mark.parametrize(
        "body",
        [{}, {"stopped": True, "chat_id": "x"}, {"stopped": True, "reason": "run_active"}],
        ids=["missing", "extra-chat-id", "extra-reason"],
    )
    def test_models_chat_stop_response_refuses_missing_or_extra_fields(
        self, body: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            models.ChatStopResponse.model_validate(body)

    def test_models_agent_status_gains_stopped_and_keeps_the_others(self) -> None:
        values = _literal_values(models.AgentStatus)
        result = models.AgentResult(status="stopped", response="partial text")

        assert values == _AGENT_STATUSES
        assert result.status == "stopped"
