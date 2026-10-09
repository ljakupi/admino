"""Token-based context budget of every LLM call (GH-190): pure arithmetic.

Every LLM call's context must satisfy
``instructions + attachments + history + reserved output <= budget``, where
``budget = max_input_tokens - ceil(max_input_tokens * margin / 100)``. The
agent fits each call's history with ``fit`` (whole earlier turns, oldest
first; the current turn is always kept) and cuts long tool results with
``truncate_tool_result``; the server reports ``chat_usage`` and refuses a
turn whose attachments alone don't fit (``context_report``,
``overflow_reason``); the conversion worker refuses a file at upload with the
same numbers.

Inputs: messages, prompt inputs and tool policies (``admino.models``), stored
attachment estimates and sizes, the app config (``BudgetSettings``).
Outputs: token counts, ``Fit``, ``ContextUsage``, ``ContextReport``, a cut
tool result.

Counting uses ``admino.tokens``'s estimator, so a stored attachment estimate
and a message are counted alike:
- a message: its text (each text part of a content list; an image part counts
  0 here, since slot 4's images are counted through the attachments' stored
  estimates), its tool-call blocks as compact JSON, plus
  ``MESSAGE_OVERHEAD_TOKENS``;
- the instructions: the run's system prompt counted as one message, plus its
  tools payload as compact JSON.

Security notes: constants and pure functions only: no I/O, no logging and no
clock (the caller passes ``now``). Never imports the agent, the server, the
database, the chat or attachment repositories or an LLM module. A report names
files by id, never by name, and nothing here sees a file's content. A cut
never leaves an untrusted block open: a cut inside a wrapped block closes it
with the block's own end marker (``untrusted.open_block_end``) before the
marker, so a forged close tag or truncation note before the cut point stays
inside the block; a result the registry's 65,536-character slice left inside
a block is closed the same way, even when it fits the cap. A cut result is
never longer than ``MAX_TOOL_RESULT_CHARS``, the tool message's limit. The
cut is for the context only: the agent decides escalation and
``external_content`` on the full result.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from admino import prompt_assembly, untrusted
from admino.models import ContextReport, ContextUsage, TextContent
from admino.tokens import estimate_text_tokens
from admino.tools import registry

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime

    from admino.config import AppConfig
    from admino.models import (
        ContextRefusalReason,
        ContextReportItem,
        LLMMessage,
        PromptContext,
        ToolPolicy,
    )

MESSAGE_OVERHEAD_TOKENS: Final = 4
# The messages a turn reads when max_context_messages is 0 (no cap).
HISTORY_LOAD_LIMIT: Final = 200
TOOL_RESULT_MARKER: Final = "\n[tool result truncated to fit the context]"
# The longest tool result a message holds: LLMMessage.content's limit and the
# registry's slice length (_MAX_RESULT_LENGTH). A cut must stay within it, or
# the agent's tool message fails validation and the run aborts.
MAX_TOOL_RESULT_CHARS: Final = 65_536
CONTEXT_TOO_LONG_MESSAGE: Final = (
    "This message doesn't fit the model's context, even without the earlier messages. "
    "Shorten it or exclude some attachments."
)
MIB: Final = 1_048_576


@dataclass(frozen=True)
class BudgetSettings:
    """The budget's start-time settings, from config.yaml (never platform settings).

    ``reserved_output_tokens`` is ``llm.max_response_tokens``, the output cap
    every provider call gets; the margin, the per-turn byte cap (in bytes) and
    the tool-result cap come from the ``context`` section.
    """

    reserved_output_tokens: int
    safety_margin_percent: int
    max_turn_bytes: int
    max_tool_result_tokens: int

    @classmethod
    def from_config(cls, config: AppConfig) -> BudgetSettings:
        """Read the settings from the validated app config."""
        return cls(
            reserved_output_tokens=config.llm.max_response_tokens,
            safety_margin_percent=config.context.safety_margin_percent,
            max_turn_bytes=config.context.max_attachment_mb_per_turn * MIB,
            max_tool_result_tokens=config.context.max_tool_result_tokens,
        )


@dataclass(frozen=True)
class Fit:
    """One LLM call's history after the budget.

    ``messages`` holds the kept earlier turns (chronological), then the
    current part; ``used`` is the fixed tokens plus those messages' tokens;
    ``fits`` is False when the current part alone is over the limit.
    """

    messages: list[LLMMessage]
    used: int
    dropped_turns: int
    dropped_messages: int
    fits: bool


def budget_limit(max_input_tokens: int, margin_percent: int) -> int:
    """Return the token budget: the model's input limit minus the margin, rounded up.

    Args:
        max_input_tokens: The most input tokens the model accepts.
        margin_percent: The share kept back for estimation error (0 to 50).

    Returns:
        ``max_input_tokens - ceil(max_input_tokens * margin_percent / 100)``.
    """
    return max_input_tokens - (max_input_tokens * margin_percent + 99) // 100


def available_attachment_tokens(budget: int, reserved_output_tokens: int) -> int:
    """Return the tokens a turn's attachments may take: the budget minus the reply, at least 0."""
    return max(0, budget - reserved_output_tokens)


def compact_json(value: object) -> str:
    """Return ``value`` as JSON without spaces, non-ASCII kept, as counted for the budget."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def message_tokens(message: LLMMessage) -> int:
    """Estimate one message's tokens: its text, its tool-call blocks and the overhead.

    A content list counts its text parts only; ``tool_call_id`` isn't counted.
    """
    if isinstance(message.content, str):
        text_tokens = estimate_text_tokens(message.content)
    else:
        text_tokens = sum(
            estimate_text_tokens(part.text)
            for part in message.content
            if isinstance(part, TextContent)
        )
    tokens = MESSAGE_OVERHEAD_TOKENS + text_tokens
    if message.tool_use_blocks:
        tokens += estimate_text_tokens(compact_json(message.tool_use_blocks))
    return tokens


def prompt_tokens(system_prompt: str, tools_payload: Sequence[Mapping[str, object]]) -> int:
    """Estimate the instructions: the system prompt as one message plus the tools payload.

    Args:
        system_prompt: The call's system message text.
        tools_payload: The provider ``tools`` array (``registry.tools_payload``);
            an empty one adds nothing.

    Returns:
        The estimated tokens.
    """
    tokens = estimate_text_tokens(system_prompt) + MESSAGE_OVERHEAD_TOKENS
    if tools_payload:
        tokens += estimate_text_tokens(compact_json(list(tools_payload)))
    return tokens


def instructions_tokens(context: PromptContext, tool_policy: ToolPolicy, *, now: datetime) -> int:
    """Estimate a run's instructions as the agent builds them.

    The tools are the ones the policy advertises (disabled services and denied
    actions left out, as the agent lists them), the system prompt is
    ``prompt_assembly.system_prompt`` over them, dated ``now``.

    Args:
        context: The user's and org's prompt inputs.
        tool_policy: The org's tool policy for the run.
        now: The clock reading the date line uses (timezone-aware).

    Returns:
        ``prompt_tokens`` of that system prompt and its tools payload.
    """
    descriptions = registry.get_registered_tools(
        enabled_tools=tool_policy.enabled_tools or None,
        permissions_config=tool_policy.permissions,
        promoted=tool_policy.promoted,
    )
    system = prompt_assembly.system_prompt(context, tools=descriptions, now=now)
    return prompt_tokens(system, registry.tools_payload(descriptions))


def turns(messages: Sequence[LLMMessage]) -> list[list[LLMMessage]]:
    """Split messages into turns: each starts at a user message.

    The messages before the first user message form the first turn, and
    concatenating the turns gives the input back.
    """
    groups: list[list[LLMMessage]] = []
    for message in messages:
        if message.role == "user" or not groups:
            groups.append([message])
        else:
            groups[-1].append(message)
    return groups


def fit(
    history: Sequence[LLMMessage], *, current_idx: int | None, fixed_tokens: int, limit: int
) -> Fit:
    """Keep the newest whole earlier turns that fit the limit beside the current part.

    A turn is kept or dropped whole, so a tool call always travels with its
    results, and the kept turns are a suffix: once a turn doesn't fit, every
    older one is dropped too. The current part is always kept; when it alone
    (with ``fixed_tokens``) is over the limit, every earlier turn is dropped
    and ``fits`` is False.

    Args:
        history: The call's messages, chronological.
        current_idx: Where the current part starts (``history[current_idx:]``);
            None: no current part, every message is earlier history.
        fixed_tokens: The tokens besides the history (instructions,
            attachments, reserved output).
        limit: The budget.

    Returns:
        The fitted history and its counts; ``history`` is left unchanged.
    """
    split = len(history) if current_idx is None else current_idx
    earlier = list(history[:split])
    current = list(history[split:])
    earlier_turns = turns(earlier)
    used = fixed_tokens + sum(message_tokens(message) for message in current)
    if used > limit:
        return Fit(
            messages=current,
            used=used,
            dropped_turns=len(earlier_turns),
            dropped_messages=len(earlier),
            fits=False,
        )
    kept_turns = 0
    kept_messages = 0
    for turn in reversed(earlier_turns):
        cost = sum(message_tokens(message) for message in turn)
        if used + cost > limit:
            break
        used += cost
        kept_turns += 1
        kept_messages += len(turn)
    return Fit(
        messages=earlier[len(earlier) - kept_messages :] + current,
        used=used,
        dropped_turns=len(earlier_turns) - kept_turns,
        dropped_messages=len(earlier) - kept_messages,
        fits=True,
    )


def usage(used: int, budget: int) -> ContextUsage:
    """Return the usage figures: ``percent`` is ``used * 100 // budget`` (above 100 allowed)."""
    return ContextUsage(used=used, max=budget, percent=used * 100 // budget)


def chat_usage(
    history: Sequence[LLMMessage],
    *,
    instructions: int,
    attachment_tokens: int,
    reserved_output_tokens: int,
    budget: int,
) -> ContextUsage:
    """Return how full the chat's context is as its next turn starts.

    The stored history is fitted without a current part, so its newest turns
    are the ones counted; the instructions, the active attachments and the
    reserved output are always counted.

    Args:
        history: The chat's latest messages, as a turn loads them.
        instructions: ``instructions_tokens`` of the caller's run.
        attachment_tokens: The chat's active attachments' stored estimates.
        reserved_output_tokens: The tokens kept for the reply.
        budget: ``budget_limit`` of the platform model.

    Returns:
        The usage over ``budget``.
    """
    fitted = fit(
        history,
        current_idx=None,
        fixed_tokens=instructions + attachment_tokens + reserved_output_tokens,
        limit=budget,
    )
    return usage(fitted.used, budget)


def truncate_tool_result(text: str, max_tokens: int) -> str:
    """Cut a tool result to ``max_tokens`` and ``MAX_TOOL_RESULT_CHARS``, never inside a block.

    The text comes back unchanged when its estimate fits ``max_tokens``, its
    length fits ``MAX_TOOL_RESULT_CHARS`` and its last wrapped block is
    closed. Otherwise it is cut: the kept part is the longest prefix whose
    estimate and length, each with the marker's, fit. When that prefix ends
    inside a wrapped block (its begin marker kept, its end marker cut), the
    block is closed: the kept part is then the longest prefix that fits, by
    both bounds, with a newline, the block's end marker and the marker. That
    also closes a block the registry's own ``MAX_TOOL_RESULT_CHARS`` slice
    left open, even when the sliced text fits the cap. Below the closing's
    (or the marker's) own estimate the kept part is empty and the closing (or
    the marker) stays.

    Args:
        text: The tool result.
        max_tokens: The cap (``context.max_tool_result_tokens``).

    Returns:
        ``text`` itself when it fits, else ``prefix + TOOL_RESULT_MARKER`` or,
        for a cut inside a block, ``prefix + "\n" + end marker +
        TOOL_RESULT_MARKER``; a cut result is at most ``MAX_TOOL_RESULT_CHARS``
        characters long.

    Security notes: the result never ends with an untrusted block open, so
    text the content placed before the cut (a look-alike close tag, a forged
    truncation note) stays inside its block.
    """
    if (
        estimate_text_tokens(text) <= max_tokens
        and len(text) <= MAX_TOOL_RESULT_CHARS
        and untrusted.open_block_end(text) is None
    ):
        return text
    kept = text[: _longest_prefix(text, TOOL_RESULT_MARKER, max_tokens)]
    end = untrusted.open_block_end(kept)
    if end is None:
        return kept + TOOL_RESULT_MARKER
    closing = "\n" + end + TOOL_RESULT_MARKER
    return text[: _longest_prefix(text, closing, max_tokens)] + closing


def _longest_prefix(text: str, suffix: str, max_tokens: int) -> int:
    """Return the most characters of ``text`` that fit with ``suffix`` (0: none).

    A prefix fits when its estimate with ``suffix`` is within ``max_tokens``
    and its length with ``suffix`` within ``MAX_TOOL_RESULT_CHARS``.
    """
    # The estimate never shrinks as the prefix grows, so a binary search finds
    # the longest prefix that fits; the length bound caps where it starts.
    low, high = 0, max(0, min(len(text), MAX_TOOL_RESULT_CHARS - len(suffix)))
    while low < high:
        middle = (low + high + 1) // 2
        if estimate_text_tokens(text[:middle] + suffix) <= max_tokens:
            low = middle
        else:
            high = middle - 1
    return low


def context_report(
    items: Sequence[ContextReportItem], *, available_tokens: int, max_bytes: int
) -> ContextReport:
    """Return the per-file report of a turn's attachments, in the given order, with the sums.

    Args:
        items: The slot's files (ids and stored sizes only).
        available_tokens: ``available_attachment_tokens`` of the budget.
        max_bytes: The per-turn byte cap.

    Returns:
        The report.
    """
    attachments = list(items)
    return ContextReport(
        attachments=attachments,
        attachment_tokens=sum(item.token_estimate for item in attachments),
        available_tokens=available_tokens,
        attachment_bytes=sum(item.derived_bytes for item in attachments),
        max_bytes=max_bytes,
    )


def overflow_reason(report: ContextReport) -> ContextRefusalReason | None:
    """Return why the attachments alone don't fit, tokens before bytes; None when they do.

    Exactly at a limit is not over it.
    """
    if report.attachment_tokens > report.available_tokens:
        return "context_overflow"
    if report.attachment_bytes > report.max_bytes:
        return "attachment_bytes_exceeded"
    return None
