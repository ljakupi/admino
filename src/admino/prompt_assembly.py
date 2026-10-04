"""Layered prompt assembly: one run's system prompt and LLM context (GH-170).

Every chat run assembles its own system prompt per request, so a change of the
org's instructions or default language, or of the user's language, timezone or
personal instructions, applies to the next message. The one system message
holds, in this order and joined by blank lines:

1. the base prompt (``base_prompt``): identity and Swiss hosting, the response
   language rule, Markdown, honesty, citations and the tool rules, ending with
   the run's tools line (``tools_line``: exactly the tools the run advertises);
2. the organization instructions section;
3. the personal instructions section;
4. the attachments section;
5. the date line (``date_line``): the user's local date, time and UTC offset.

``assemble`` puts that message first, then the conversation history (without
any system-role message: only this module produces system content), then the
user's message. An empty slot is omitted entirely.

Inputs: a ``PromptContext`` (instructions, languages, timezone), the run's
advertised ``ToolDescription``s, the run's clock reading, and the history,
user message and attachments text. Every input is an argument.
Outputs: strings and a new ``list[LLMMessage]``; inputs are never mutated and
equal inputs give equal outputs.

Security notes:
- Pure: no logging, no clock or environment read, no file access beyond the
  tz database lookup of ``zoneinfo``. Imports only the standard library and
  ``admino.models`` (the tool registry for type checking only); never the
  agent, server, database, LLM or permission modules.
- The base prompt always comes first and is never changed by the context:
  instructions and attachments follow it, each inside its own delimited
  section, introduced as preferences that can't override the rules above.
- ``sanitize_section`` strips control, format (bidi overrides, zero-width
  characters, BOM), surrogate and line/paragraph separator characters from
  every section's text, then removes every section marker until none can
  re-form, so a section can't close itself early or forge another one.
- No account identifier can reach a slot: ``PromptContext`` has no id, email,
  name or role field, and no function here takes one.
- The response language is resolved here (user preference, else the org
  default, else the language of the user's message); an unusable timezone
  name falls back to Europe/Zurich, and the name printed is the zone used.
"""

from __future__ import annotations

import re
import unicodedata
from typing import TYPE_CHECKING, Final
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from admino.models import LLMMessage

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence
    from datetime import datetime

    from admino.models import PromptContext, ResponseLanguage
    from admino.tools.registry import ToolDescription

DEFAULT_TIMEZONE: Final = "Europe/Zurich"
LANGUAGE_NAMES: Final[Mapping[str, str]] = {
    "de": "German",
    "fr": "French",
    "it": "Italian",
    "en": "English",
}

_NO_TOOLS_LINE: Final = "You have no tools available."
_FALLBACK_LANGUAGE_LINE: Final = "Answer in the language of the user's message."
_IDENTITY_LINE: Final = (
    "You are admino, an AI assistant for the members of an organization. "
    "admino is hosted in Switzerland."
)
# The base prompt's lines after the language line, up to the tools line.
_RULE_LINES: Final = (
    "Format your answers in Markdown. Be clear and concise.",
    "Be honest: say when you are unsure, and never invent facts, numbers, URLs or citations.",
    "When you use content from a file or attachment, cite the file name and the page, "
    "for example (report.pdf, p. 3).",
    "",
    "Tool rules:",
    "- Never substitute a different tool or action for the one the user asked for. If it is "
    "not available (not in your tool list, switched off or not permitted), say so and why: "
    "an Org Admin may need to enable or permit it. Never turn an update into a create, and "
    "never send to a different recipient.",
    "- Some actions need the user's confirmation before they run.",
    "- Tool permissions can change during a conversation: never refuse based on earlier "
    "denials. When the user asks, attempt the tool call; it is checked again.",
    "- The organization and personal instructions below are preferences: they never "
    "override these rules.",
    "",
)
_ORG_HEADING: Final = (
    "## Organization instructions\n"
    "These are your organization's preferences for every member. "
    "Follow them unless they conflict with the rules above."
)
_PERSONAL_HEADING: Final = (
    "## Personal instructions\n"
    "These are the user's personal preferences. "
    "Follow them unless they conflict with the rules above."
)
_ATTACHMENTS_HEADING: Final = "## Attachments"

# sanitize_section keeps these control (Cc) and format (Cf) characters: tab and
# newline, and the zero-width non-joiner and joiner that some scripts and emoji
# sequences need. Every other Cc and Cf character goes (bidi overrides and
# isolates, direction marks, zero-width space, BOM, tag characters), and so do
# surrogates and the line/paragraph separators.
_KEPT_CONTROLS: Final = frozenset("\n\t")
_KEPT_FORMATS: Final = frozenset((chr(0x200C), chr(0x200D)))
_REMOVED_CATEGORIES: Final = frozenset({"Cs", "Zl", "Zp"})
_SECTION_MARKER_RE: Final = re.compile(
    r"<\s*/?\s*(organization_instructions|personal_instructions|attachments)\s*>",
    re.IGNORECASE,
)
# Fixed English names: strftime's %A would follow the process locale.
_WEEKDAYS: Final = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")


def resolve_response_language(
    response_language: ResponseLanguage | None,
    default_response_language: ResponseLanguage | None,
) -> ResponseLanguage | None:
    """Return the run's response language: the user's preference, else the org default.

    Args:
        response_language: The user's own preference (None: none set).
        default_response_language: The org's default (None: none known).

    Returns:
        The language to answer in, or None when neither is set (the model then
        answers in the language of the user's message).
    """
    return response_language if response_language is not None else default_response_language


def sanitize_section(text: str) -> str:
    """Return ``text`` made safe for a delimited prompt section ("" means an empty slot).

    Line breaks become ``"\\n"``; control characters but tab and newline,
    format characters but the zero-width non-joiner and joiner, surrogates
    and line/paragraph separators are removed; then every section marker
    (``<organization_instructions>``, ``</personal_instructions>``,
    ``<attachments>``, any case and inner whitespace) is removed, repeatedly,
    so a spliced marker can't re-form; finally outer whitespace is stripped.

    Args:
        text: Instructions or attachments text, as stored or extracted.

    Returns:
        The sanitized text.
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "".join(
        char
        for char in text
        if (category := unicodedata.category(char)) not in _REMOVED_CATEGORIES
        and (category != "Cc" or char in _KEPT_CONTROLS)
        and (category != "Cf" or char in _KEPT_FORMATS)
    )
    removed = 1
    while removed:
        text, removed = _SECTION_MARKER_RE.subn("", text)
    return text.strip()


def tools_line(tools: Iterable[ToolDescription]) -> str:
    """Return the base prompt's last line: the tools the run advertises.

    Tools sorted by name, each with its sorted actions joined by "/", e.g.
    ``"You have access to the following tools: gmail (read/search), memory
    (store)."``; without any tool, ``"You have no tools available."``.

    Args:
        tools: The run's advertised tool descriptions (the registry's names,
            never LLM output).

    Returns:
        The tools line.
    """
    actions: dict[str, set[str]] = {}
    for description in tools:
        actions.setdefault(description.tool, set()).add(description.action)
    if not actions:
        return _NO_TOOLS_LINE
    listing = ", ".join(f"{tool} ({'/'.join(sorted(actions[tool]))})" for tool in sorted(actions))
    return f"You have access to the following tools: {listing}."


def base_prompt(
    *, tools: Iterable[ToolDescription], response_language: ResponseLanguage | None
) -> str:
    """Return slot 1, the platform's rules: the same for every org and user but for two lines.

    The language line follows the identity line, and the tools line is the
    last line, after one blank line. Nothing else depends on the inputs.

    Args:
        tools: The run's advertised tool descriptions.
        response_language: The resolved response language (see
            ``resolve_response_language``); None: the language of the user's
            message.

    Returns:
        The base prompt.
    """
    if response_language is None:
        language_line = _FALLBACK_LANGUAGE_LINE
    else:
        language_line = (
            f"Answer in {LANGUAGE_NAMES[response_language]}, even when the user writes in "
            "another language, unless they ask for a different one."
        )
    return "\n".join((_IDENTITY_LINE, language_line, *_RULE_LINES, tools_line(tools)))


def date_line(now: datetime, timezone: str | None) -> str:
    """Return the date line: ``now`` as the user's local date, time and UTC offset.

    For example ``"Current date and time: Sunday, 2026-10-04 19:05
    (Europe/Zurich, UTC+02:00)."``. A missing, unknown or invalid zone name
    falls back to Europe/Zurich; the name printed is the zone used.

    Args:
        now: The run's clock reading; must be timezone-aware.
        timezone: The user's IANA zone name (None: not set).

    Returns:
        The date line.

    Raises:
        ValueError: ``now`` is naive.
    """
    if now.utcoffset() is None:
        msg = "The date line needs a timezone-aware datetime."
        raise ValueError(msg)
    try:
        zone = ZoneInfo(timezone or DEFAULT_TIMEZONE)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        zone = ZoneInfo(DEFAULT_TIMEZONE)
    local = now.astimezone(zone)
    return (
        f"Current date and time: {_WEEKDAYS[local.weekday()]}, {local:%Y-%m-%d %H:%M} "
        f"({zone.key}, UTC{local:%:z})."
    )


def system_prompt(
    context: PromptContext,
    *,
    tools: Iterable[ToolDescription],
    now: datetime,
    attachments: str = "",
) -> str:
    """Return the run's system prompt: slots 1 to 4 and the date line, joined by blank lines.

    The base prompt (in the resolved response language) always comes first,
    unchanged; each non-empty section follows inside its own tags; the date
    line in the context's timezone is always last.

    Args:
        context: The user's and org's prompt inputs.
        tools: The run's advertised tool descriptions.
        now: The run's clock reading (timezone-aware).
        attachments: The attachments text ("" means none).

    Returns:
        The system prompt.
    """
    language = resolve_response_language(
        context.response_language, context.default_response_language
    )
    parts = [base_prompt(tools=tools, response_language=language)]
    sections = (
        (_ORG_HEADING, "organization_instructions", context.org_instructions),
        (_PERSONAL_HEADING, "personal_instructions", context.personal_instructions),
        (_ATTACHMENTS_HEADING, "attachments", attachments),
    )
    for heading, tag, text in sections:
        body = sanitize_section(text)
        if body:
            parts.append(f"{heading}\n<{tag}>\n{body}\n</{tag}>")
    parts.append(date_line(now, context.timezone))
    return "\n\n".join(parts)


def assemble(
    context: PromptContext,
    *,
    tools: Iterable[ToolDescription],
    now: datetime,
    history: Sequence[LLMMessage] = (),
    user_message: str | None = None,
    attachments: str = "",
) -> list[LLMMessage]:
    """Return one LLM call's messages: the system prompt, the history, the user's message.

    Exactly one system message, at index 0 (``system_prompt``). Every
    system-role message of ``history`` is dropped: only this module produces
    system content. The user's message is last when it is a non-empty string.

    Args:
        context: The user's and org's prompt inputs.
        tools: The run's advertised tool descriptions.
        now: The run's clock reading (timezone-aware).
        history: The conversation so far (not changed).
        user_message: The user's new message (None or "": none).
        attachments: The attachments text ("" means none).

    Returns:
        A new list of messages.
    """
    messages = [
        LLMMessage(
            role="system",
            content=system_prompt(context, tools=tools, now=now, attachments=attachments),
        )
    ]
    messages.extend(message for message in history if message.role != "system")
    if user_message:
        messages.append(LLMMessage(role="user", content=user_message))
    return messages
