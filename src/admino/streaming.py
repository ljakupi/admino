"""Run control and display deltas of streamed chat turns (GH-8).

Two small pieces the server and the agent share for a turn answered over SSE:

- ``RunStream``: what a streamed ``Agent.run`` reports to (each answer text
  piece, each tool-call record) and the ``asyncio.Event`` that stops it. The
  server builds one per streamed run; the stop event is the one
  ``ChatRuntime.stoppable`` registered, so ``POST /api/chats/{id}/stop`` and a
  client disconnect reach the run.
- ``DisplayDeltas``: turns one answer's raw text pieces (as the LLM client
  forwards them) into the ``delta`` texts the client is sent. It is the
  credential redaction of the live stream.

Inputs: raw answer text pieces (client-sanitized model output, untrusted).
Outputs: display text pieces of at most ``MAX_DELTA_CHARS`` characters, never
empty.

How ``DisplayDeltas`` stays exact: ``sanitize_display_text`` (NFKC, invisible
characters removed, credential rules) reads nothing across an ASCII
whitespace character except the ``Bearer`` rule, whose ``\\s+`` spans spaces.
So the text is settled at the last ASCII whitespace (space, tab, LF, CR) of
what was fed, except that a trailing word reading ``Bearer`` once displayed,
with the words that display as nothing or as whitespace after it, waits for
the next word (the token the rule would redact). Each settled segment is
cleaned on its own once, which equals cleaning the whole text, so the joined
pieces of an answer are exactly ``sanitize_display_text`` of its whole raw
text, and a key split across pieces is never sent in part. Linear: every raw
character is read once to find words and cleaned once.

Security notes:
- Imports only the standard library and ``admino.models``: never the server,
  agent, database, LLM or tool modules.
- Nothing is logged: no text, word or count of an answer.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

from admino.models import DELTA_MAX_LENGTH, normalize_display_text, sanitize_display_text

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from admino.models import ToolCallRecord

MAX_DELTA_CHARS: Final = DELTA_MAX_LENGTH

# One word: a run of characters that are not ASCII whitespace. NBSP, U+3000 and
# the removed whitespace (VT, FF, NEL, U+2028) are part of a word on purpose:
# once displayed they are a space or nothing, which the credential rules can read
# across.
_WORD: Final = re.compile(r"[^ \t\n\r]+")
_ASCII_WHITESPACE: Final = " \t\n\r"
_BEARER: Final = "Bearer"


@dataclass(slots=True)
class RunStream:
    """What a streamed agent run reports to, and the signal that stops it.

    ``on_delta`` gets each piece of raw answer text (as the LLM client
    sanitized it, never empty) in order; ``on_tool_call`` each tool-call record
    right after it is recorded. Setting ``stop`` stops the run (see
    ``Agent.run``); every instance has its own event.
    """

    on_delta: Callable[[str], Awaitable[None]]
    on_tool_call: Callable[[ToolCallRecord], Awaitable[None]]
    stop: asyncio.Event = field(default_factory=asyncio.Event)


class DisplayDeltas:
    """Turns one answer's raw text pieces into display-safe delta texts.

    ``feed`` returns what is settled now, ``flush`` the rest at the end of the
    answer. The concatenation of everything one answer returned equals
    ``sanitize_display_text`` of all its raw text (see the module docstring).
    """

    __slots__ = ("_held", "_tail")

    def __init__(self) -> None:
        """Start an answer with nothing fed."""
        # Raw text whose words are all read but not sent: a word reading Bearer,
        # then only further Bearer words and words that display as blank.
        self._held: list[str] = []
        # Raw text after the last ASCII whitespace fed: a word not ended yet.
        self._tail: list[str] = []

    def feed(self, text: str) -> list[str]:
        """Add the answer's next raw text; return the display pieces settled by it (maybe none)."""
        cut = max(text.rfind(char) for char in _ASCII_WHITESPACE) + 1
        if not cut:
            if text:
                self._tail.append(text)
            return []
        ended = "".join(self._tail) + text[:cut]
        self._tail = [text[cut:]] if cut < len(text) else []
        plain_seen = False
        bearer_at: int | None = None  # the first Bearer word after the last plain word
        for word in _WORD.finditer(ended):
            shown = normalize_display_text(word.group()).rstrip()
            if not shown:
                # Displays as nothing or whitespace: the Bearer rule reads across it.
                continue
            if shown.endswith(_BEARER):
                if bearer_at is None:
                    bearer_at = word.start()
            else:
                plain_seen, bearer_at = True, None
        if self._held and not plain_seen:
            self._held.append(ended)
            return []
        settle = len(ended) if bearer_at is None else bearer_at
        settled = "".join(self._held) + ended[:settle]
        self._held = [] if bearer_at is None else [ended[settle:]]
        return display_pieces(settled)

    def flush(self) -> list[str]:
        """End the answer: return the display pieces of everything not sent yet, then reset."""
        rest = "".join(self._held) + "".join(self._tail)
        self._held, self._tail = [], []
        return display_pieces(rest)


def display_pieces(raw: str) -> list[str]:
    """``raw``'s display text cut into pieces of at most ``MAX_DELTA_CHARS`` characters.

    Also the server's ``delta`` texts of a whole reply it sends at once (a run's
    limit notice, a denial), so they follow the same cleanup and bounds.
    """
    display = sanitize_display_text(raw)
    return [
        display[start : start + MAX_DELTA_CHARS]
        for start in range(0, len(display), MAX_DELTA_CHARS)
    ]
