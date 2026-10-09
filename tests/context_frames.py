"""Test helper: the context frames a stored streamed chat run ends with (GH-190, Decision 4).

A stored run's stream ends ``[limit text deltas]``, ``confirm``, ``context_notice``
(only when the run's last LLM call dropped earlier turns), ``context_usage``,
``message_saved``, ``error``, ``title``, ``done`` (contract C11). The SSE specs
(tests/test_chat_context_stream_api.py and the GH-8 stream suites) pin the two context
frames with these helpers.

Inputs: a ``pytest.MonkeyPatch``, the FakeDb, a chat id, the attachment tokens of the
chat's active files and, when a test changes them, the budget figures.
Outputs:
- ``fix_instructions(monkeypatch)`` makes ``admino.context_budget.instructions_tokens``
  (the server calls it through the module attribute, contracts C1 and C11) answer
  ``INSTRUCTIONS``, so a frame's ``used`` depends on neither the tool registry, the
  prompt context nor the clock (the date line). Before GH-190 the module doesn't exist
  and nothing is patched: every helper below imports it, so a test that pins a context
  frame fails then, while the stream suites' other tests run as before.
- ``usage_payload(db, chat_id)`` is the ``context_usage`` payload of the chat as its
  next turn starts: ``context_budget.chat_usage`` over every stored message of the chat
  (the specs' chats hold fewer messages than the load limit, so a run's loaded messages
  plus the ones it stored are all of them), ``INSTRUCTIONS``, the given attachment
  tokens, the reserved output and the budget. The defaults are the specs' app: the
  reserved output is ``llm.max_response_tokens`` of tests/tenancy_world.py's config
  (4096, its default) and the budget is the default platform's ``max_input_tokens``
  (200 000) minus the default ``context.safety_margin_percent`` (10 %): 180 000.
- ``usage_frame`` and ``notice_frame`` build the ``(event, payload)`` frames.

Security notes: test infrastructure only; no I/O, the messages are the FakeDb's rows.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

from admino.models import LLMMessage

if TYPE_CHECKING:
    import uuid

    import pytest

    from tests.db_fakes import FakeDb

# The instructions' tokens every patched run counts (the system message and tools payload).
INSTRUCTIONS: Final = 2_345
# llm.max_response_tokens of tests/tenancy_world.py's make_config() (the field's default).
RESERVED_OUTPUT: Final = 4_096
# The default platform's llm.max_input_tokens (GH-242) and the default margin (Decision 1).
MAX_INPUT_TOKENS: Final = 200_000
MARGIN_PERCENT: Final = 10
# max_input_tokens - ceil(max_input_tokens * margin / 100).
BUDGET: Final = 180_000


def fix_instructions(monkeypatch: pytest.MonkeyPatch, tokens: int = INSTRUCTIONS) -> None:
    """Make ``admino.context_budget.instructions_tokens`` answer ``tokens`` (see the module)."""
    try:
        import admino.context_budget as context_budget
    except ModuleNotFoundError as exc:
        if exc.name != "admino.context_budget":
            raise
        # Before GH-190: no context frame is sent; the helpers below fail on the import.
        return

    def fixed(*_args: Any, **_kwargs: Any) -> int:
        return tokens

    monkeypatch.setattr(context_budget, "instructions_tokens", fixed)


def stored_history(db: FakeDb, chat_id: uuid.UUID) -> list[LLMMessage]:
    """The chat's stored messages by seq, as the agent's history holds them."""
    return [
        LLMMessage(
            role=row["role"],
            content=row["content"],
            tool_use_blocks=row["tool_use_blocks"],
            tool_call_id=row["tool_call_id"],
        )
        for row in db.messages_of(chat_id)
    ]


def usage_payload(
    db: FakeDb,
    chat_id: uuid.UUID,
    *,
    attachment_tokens: int = 0,
    instructions: int = INSTRUCTIONS,
    reserved_output_tokens: int = RESERVED_OUTPUT,
    budget: int = BUDGET,
) -> dict[str, int]:
    """The ``context_usage`` payload of the chat as its next turn starts (read now)."""
    from admino import context_budget

    usage = context_budget.chat_usage(
        stored_history(db, chat_id),
        instructions=instructions,
        attachment_tokens=attachment_tokens,
        reserved_output_tokens=reserved_output_tokens,
        budget=budget,
    )
    payload: dict[str, int] = usage.model_dump(mode="json")
    return payload


def usage_frame(
    db: FakeDb, chat_id: uuid.UUID, *, attachment_tokens: int = 0
) -> tuple[str, dict[str, Any]]:
    """The ``context_usage`` frame of a stored run of the chat (read now)."""
    return ("context_usage", usage_payload(db, chat_id, attachment_tokens=attachment_tokens))


def notice_frame(dropped_turns: int, dropped_messages: int) -> tuple[str, dict[str, Any]]:
    """The ``context_notice`` frame of a run whose last LLM call dropped earlier turns."""
    return (
        "context_notice",
        {"dropped_turns": dropped_turns, "dropped_messages": dropped_messages},
    )
