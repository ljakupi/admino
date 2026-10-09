"""Untrusted-content boundary: third-party text is wrapped as data (GH-243, GH-189).

Tool results carry third-party content (emails, files, calendar events,
recalled memory notes), and so do the files the user attaches (GH-189). Before
such text reaches the model it is wrapped between a begin and an end marker
that carry a random boundary::

    <untrusted_content_{B} kind="{kind}" label="{label}">
    {text}
    </untrusted_content_{B}>

The base prompt (``prompt_assembly``) tells the model that wrapped content is
data, never instructions; the agent uses ``contains_wrapped`` to notice that a
run has received such content and then escalates its side-effecting actions to
confirmation (``tools.registry.dispatch_tool_call``). Slot 4 of the prompt
(``prompt_assembly.attachment_slot``) builds one block per attachment from the
same pieces, line by line, as its images are content parts of their own:
``markers`` gives the begin and end lines and ``sanitize_text`` sanitizes each
line between them.

Inputs: a kind (one of ``UNTRUSTED_KINDS``), a short label (e.g. ``gmail
message 18c2f``) and the formatted tool output or a line of a file.
Outputs: the wrapped string (``wrap``), the begin and end markers
(``markers``), the sanitized text (``sanitize_text``), whether a text holds a
begin marker (``contains_wrapped``), the end marker of a cut text's open block
(``open_block_end``), and the run's boundary (``run_boundary``).

The boundary ``B`` is 16 lowercase hex characters from ``secrets``. Inside a
``run_boundary()`` block every ``wrap`` uses the block's boundary (one per
agent run, kept in a ``ContextVar`` so concurrent runs never share one);
outside any block each ``wrap`` draws a fresh one.

Security notes:
- Pure: standard library only, nothing from ``admino``, no logging, no I/O,
  no clock or environment read. Content, labels and boundaries never reach a
  log line from here.
- The text is sanitized before it is wrapped: line breaks become ``"\\n"``;
  control characters but tab and newline, every invisible format character
  (Unicode ``Cf``: bidi overrides and isolates, direction marks, zero-width
  characters, BOM, tag characters) and lone surrogates are removed; then
  every case-insensitive ``untrusted_content`` becomes ``untrusted-content``.
  So the exact marker name doesn't survive inside the text, also when a copy
  is split by one of the removed characters, as those go first. ``wrap`` caps
  the text at ``MAX_CHARS`` characters; ``sanitize_text`` doesn't cap
  (attachments go in full). The label is capped at ``MAX_LABEL_CHARS`` on one
  line without quotes or angle brackets, so it can't leave its attribute.
- Limits: look-alike markers survive sanitization. These are homoglyphs
  (such as Cyrillic letters), a space or hyphen for the underscore,
  full-width brackets, combining marks (such as U+0301) and copies split by
  invisible characters that aren't format characters: the combining grapheme
  joiner U+034F, the variation selectors U+FE00-U+FE0F and U+E0100-U+E01EF,
  the Mongolian free variation selectors U+180B-U+180D and U+180F, the Khmer
  inherent vowels U+17B4 and U+17B5, and the Hangul fillers U+115F, U+1160,
  U+3164 and U+FFA0. The model may read them as markers. The random boundary
  is defence in depth only: the model isn't told the run's boundary, and the
  history holds blocks of earlier runs with other boundaries, so it can't
  tell a forged boundary from the real one. The wrapping is guidance to the
  model only. The enforcement is the dispatch escalation, which doesn't
  depend on the model recognising markers: once a run has received wrapped
  content, every side-effecting ``allow`` action needs the user's
  confirmation.
- A long tool result is cut (``context_budget.truncate_tool_result``). A cut
  inside a block would drop its end marker, and a look-alike close tag or a
  forged truncation note before the cut point would then pass as outside the
  block with nothing after it to contradict it. ``open_block_end`` names the
  end marker the cut appends, so a cut never leaves a block open. It reads
  the boundary from the text, never from the current run.
"""

from __future__ import annotations

import re
import secrets
import unicodedata
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Final, Literal, get_args

if TYPE_CHECKING:
    from collections.abc import Iterator

UntrustedKind = Literal["email", "file", "event", "memory", "attachment", "web"]
UNTRUSTED_KINDS: Final[frozenset[str]] = frozenset(get_args(UntrustedKind))
MAX_CHARS: Final[int] = 20_000
MAX_LABEL_CHARS: Final[int] = 100
TRUNCATION_MARKER: Final[str] = "[truncated]"

# None: no run is open, so each wrap draws a fresh boundary.
_RUN_BOUNDARY: Final[ContextVar[str | None]] = ContextVar("untrusted_run_boundary", default=None)

_LINE_BREAK_RE: Final = re.compile("\r\n?|[\u2028\u2029]")
_KEPT_CONTROLS: Final = frozenset("\n\t")
_REMOVED_CATEGORIES: Final = frozenset({"Cf", "Cs"})
# One pass is enough: the replacement can't combine with its neighbours into a
# new occurrence, as no suffix of the token is a prefix of the replacement or
# the other way round.
_MARKER_NAME_RE: Final = re.compile("untrusted_content", re.IGNORECASE)
_DEFANGED_MARKER_NAME: Final = "untrusted-content"
_WHITESPACE_RE: Final = re.compile(r"\s+")
_LABEL_REMOVED_RE: Final = re.compile('["<>]')
# Group 1 is the boundary, which names the block's end marker (``open_block_end``).
_BEGIN_MARKER_RE: Final = re.compile(r'<untrusted_content_([0-9a-f]{16}) kind="')


@contextmanager
def run_boundary() -> Iterator[str]:
    """Open a run: every ``wrap`` inside the block uses one fresh boundary.

    The previous boundary (or none) comes back when the block ends, also on
    an exception and for nested blocks.

    Yields:
        The run's boundary, 16 lowercase hex characters.
    """
    boundary = secrets.token_hex(8)
    token = _RUN_BOUNDARY.set(boundary)
    try:
        yield boundary
    finally:
        _RUN_BOUNDARY.reset(token)


def sanitize_text(text: str) -> str:
    """Return ``text`` sanitized as ``wrap`` sanitizes its body, without the cap.

    Line breaks become ``"\\n"``; control characters but tab and newline,
    format (``Cf``) characters and lone surrogates are removed; every
    case-insensitive ``untrusted_content`` becomes ``untrusted-content``.

    Args:
        text: Third-party content, such as a line of an attached file.

    Returns:
        The sanitized text, at any length.
    """
    text = _LINE_BREAK_RE.sub("\n", text)
    text = "".join(
        char
        for char in text
        if (category := unicodedata.category(char)) not in _REMOVED_CATEGORIES
        and (category != "Cc" or char in _KEPT_CONTROLS)
    )
    return _MARKER_NAME_RE.sub(_DEFANGED_MARKER_NAME, text)


def _sanitize_label(label: str) -> str:
    """One stripped line without quotes or angle brackets, capped; ``-`` when empty."""
    label = _WHITESPACE_RE.sub(" ", sanitize_text(label))
    label = _LABEL_REMOVED_RE.sub("", label).strip()[:MAX_LABEL_CHARS]
    return label or "-"


def markers(kind: UntrustedKind, label: str) -> tuple[str, str]:
    """Return the begin and end marker of one block, with one boundary.

    The boundary is the run's inside a ``run_boundary()`` block, else a fresh
    one for this pair.

    Args:
        kind: What the content is (one of ``UNTRUSTED_KINDS``).
        label: A short description such as a file name; sanitized to one line
            of at most ``MAX_LABEL_CHARS`` characters.

    Returns:
        ``(begin, end)``, each one line without a newline.

    Raises:
        ValueError: ``kind`` is not a known kind (the value is not echoed).
    """
    if kind not in UNTRUSTED_KINDS:
        msg = "Unknown untrusted content kind."
        raise ValueError(msg)
    boundary = _RUN_BOUNDARY.get() or secrets.token_hex(8)
    return (
        f'<untrusted_content_{boundary} kind="{kind}" label="{_sanitize_label(label)}">',
        f"</untrusted_content_{boundary}>",
    )


def wrap(kind: UntrustedKind, label: str, text: str) -> str:
    """Return ``text`` sanitized and wrapped between the run's begin and end markers.

    Args:
        kind: What the content is (one of ``UNTRUSTED_KINDS``).
        label: A short description such as ``gmail message 18c2f``; sanitized
            to one line of at most ``MAX_LABEL_CHARS`` characters.
        text: The third-party content; sanitized and capped at ``MAX_CHARS``
            characters (then ``"\\n[truncated]"`` follows).

    Returns:
        The begin marker, a newline, the sanitized text, a newline and the
        end marker.

    Raises:
        ValueError: ``kind`` is not a known kind (the value is not echoed).
    """
    begin, end = markers(kind, label)
    body = sanitize_text(text)
    if len(body) > MAX_CHARS:
        body = f"{body[:MAX_CHARS]}\n{TRUNCATION_MARKER}"
    return f"{begin}\n{body}\n{end}"


def contains_wrapped(text: str) -> bool:
    """Return whether ``text`` holds a begin marker of any boundary.

    The end marker is not required, so a cut-off wrap still counts.

    Args:
        text: A tool result or a history message's content.

    Returns:
        True when a begin marker is present.
    """
    return _BEGIN_MARKER_RE.search(text) is not None


def open_block_end(text: str) -> str | None:
    """Return the end marker of the last block in ``text`` when that block is open.

    Wraps never nest, so only the last begin marker can open a block that is
    still open; it is closed when its own end marker (the same boundary)
    occurs after it. A forged end marker (another boundary, a look-alike or
    defanged name) doesn't close it.

    Args:
        text: A tool result, possibly cut.

    Returns:
        ``</untrusted_content_<B>>`` for the last begin marker's boundary
        ``B`` when that end marker doesn't follow it; None when ``text`` holds
        no begin marker or its last block is closed.
    """
    matches = list(_BEGIN_MARKER_RE.finditer(text))
    if not matches:
        return None
    last = matches[-1]
    end = f"</untrusted_content_{last.group(1)}>"
    return end if text.find(end, last.end()) == -1 else None
