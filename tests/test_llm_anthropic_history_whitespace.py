"""Anthropic history: no whitespace-only text block (GH-278 Decision 1).

Anthropic rejects a text content block that is whitespace-only. A cut answer that
came before a tool call can be just whitespace, and so can a user message that
merges with a tool result. ``llm_anthropic._convert_messages_to_anthropic``
therefore never builds such a block. "Whitespace-only" means ``text.strip() ==
""`` (Python's ``str.strip``, so Unicode spaces count), as in GH-25 D11.

What these tests pin:

- An assistant message with ``tool_use_blocks`` sends its text block only when
  the text isn't whitespace-only. A whitespace-only text (``" "``, ``"\\n\\t "``,
  NBSP, IDEOGRAPHIC SPACE + EM SPACE) is dropped and the ``tool_use`` blocks are
  sent in their order, their names encoded (``memory.store`` ->
  ``memory__store``).
- An assistant message left with no block at all (whitespace-only or empty
  text, and no ``tool_use`` block with an id) is left out like a blank one (D11):
  the user messages around it merge.
- When a string merges with a block list (same-role neighbours), a
  whitespace-only string is dropped instead of becoming a text block, in both
  directions: a tool result list followed by a whitespace-only user message (a
  blank cut final answer between them is left out), and a whitespace-only user
  message followed by a tool result.
- Text that isn't whitespace-only is sent exactly as stored, never stripped
  (``" padded\\n"`` before a tool_use, ``" thanks \\n"`` after a tool result). The
  input ``LLMMessage`` list is unchanged, and the OpenAI-compatible converter
  still sends the same history unchanged.
- On the wire, ``AnthropicClient.chat()`` and a drained ``chat_stream()`` send a
  request body without a whitespace-only text block, the ``tool_use`` block
  kept.
- An invariant over every history of up to four messages built from user,
  assistant and tool messages (blank and non-blank texts, with and without
  tool_use blocks, with and without ids), for each blank variant: no content
  list holds a whitespace-only text block or is empty, same-role neighbours are
  merged, every tool_use id and tool_result id is sent in its order, every
  non-blank text is sent verbatim, and the input is unchanged.

Out of scope (Decision 1): a user's own whitespace-only message that forms a
whole turn on its own is sent as written today. Whether to refuse it is an
input-validation question for another issue, so no test here pins it either
way (the invariant leaves such histories out).

Security notes:
- Keys are built at runtime (``tests.credential_keys``); no key literal here.
- The SDK's retry sleep is a no-op, so a retrying client fails fast.
"""

from __future__ import annotations

import itertools
import json
from typing import TYPE_CHECKING, Any, Final

import anthropic._base_client as anthropic_base_client
import httpx
import pytest

from admino.config import LLMConfig
from admino.llm_anthropic import AnthropicClient, _convert_messages_to_anthropic
from admino.llm_openai import _convert_messages_to_openai
from admino.models import LLMMessage
from tests.credential_keys import api_key

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ANTHROPIC_KEY: Final = api_key("sk-" + "ant-", 48, seed=27801).text
_MODEL: Final = "wire-w1-model"
_SYSTEM: Final = "You are admino."

# Whitespace-only texts (``text.strip() == ""``) that are not empty: ASCII
# whitespace and non-ASCII spaces (NBSP; IDEOGRAPHIC SPACE + EM SPACE), built
# with chr() so the file stays ASCII.
_BLANKS: Final[dict[str, str]] = {
    "space": " ",
    "newline-tab-space": "\n\t ",
    "nbsp": chr(0xA0),
    "ideographic-and-em-space": chr(0x3000) + chr(0x2003),
}
# The same, plus the empty text (also whitespace-only by the definition).
_BLANKS_AND_EMPTY: Final[dict[str, str]] = {"empty": "", **_BLANKS}

# Stored tool_use blocks (dot notation, as the agent stores them) and what
# Anthropic gets for each (double-underscore names).
_STORE: Final[dict[str, Any]] = {
    "type": "tool_use",
    "id": "toolu_1",
    "name": "memory.store",
    "input": {"key": "k", "value": "v"},
}
_RECALL: Final[dict[str, Any]] = {
    "type": "tool_use",
    "id": "toolu_2",
    "name": "memory.recall",
    "input": {"key": "k"},
}
_CREATE: Final[dict[str, Any]] = {
    "type": "tool_use",
    "id": "toolu_3",
    "name": "google_calendar.create",
    "input": {"title": "Standup"},
}
_STORE_SENT: Final[dict[str, Any]] = {
    "type": "tool_use",
    "id": "toolu_1",
    "name": "memory__store",
    "input": {"key": "k", "value": "v"},
}
_RECALL_SENT: Final[dict[str, Any]] = {
    "type": "tool_use",
    "id": "toolu_2",
    "name": "memory__recall",
    "input": {"key": "k"},
}
_CREATE_SENT: Final[dict[str, Any]] = {
    "type": "tool_use",
    "id": "toolu_3",
    "name": "google_calendar__create",
    "input": {"title": "Standup"},
}


def _result_block(tool_use_id: str, content: str) -> dict[str, Any]:
    """The tool_result block Anthropic gets for a tool message."""
    return {"type": "tool_result", "tool_use_id": tool_use_id, "content": content}


def _dumps(messages: list[LLMMessage]) -> list[dict[str, Any]]:
    """The messages as plain dicts (to prove the converter never changes its input)."""
    return [message.model_dump() for message in messages]


def _system() -> LLMMessage:
    return LLMMessage(role="system", content=_SYSTEM)


def _user(content: str) -> LLMMessage:
    return LLMMessage(role="user", content=content)


def _assistant(content: str, blocks: list[dict[str, Any]] | None = None) -> LLMMessage:
    return LLMMessage(role="assistant", content=content, tool_use_blocks=blocks)


def _tool(tool_call_id: str, content: str) -> LLMMessage:
    return LLMMessage(role="tool", content=content, tool_call_id=tool_call_id)


def _convert(messages: list[LLMMessage]) -> tuple[tuple[str, list[dict[str, Any]]], bool]:
    """Convert ``messages``; also tell whether the input stayed unchanged."""
    before = _dumps(messages)
    converted = _convert_messages_to_anthropic(messages)
    return converted, _dumps(messages) == before


# ===========================================================================
# 1. Converter: whitespace-only text before tool_use blocks
# ===========================================================================


@pytest.mark.parametrize("blank", list(_BLANKS))
def test_llm_anthropic_history_whitespace_text_before_tool_use_dropped(blank: str) -> None:
    """A whitespace-only text before one tool_use: no text block, the tool_use kept."""
    messages = [
        _system(),
        _user("Store it"),
        _assistant(_BLANKS[blank], [_STORE]),
        _tool("toolu_1", "stored"),
    ]
    assert _convert(messages) == (
        (
            _SYSTEM,
            [
                {"role": "user", "content": "Store it"},
                {"role": "assistant", "content": [_STORE_SENT]},
                {"role": "user", "content": [_result_block("toolu_1", "stored")]},
            ],
        ),
        True,
    )


def test_llm_anthropic_history_whitespace_text_before_several_tool_uses_keeps_order() -> None:
    """A whitespace-only text before three tool_use blocks: the blocks only, in their order."""
    messages = [
        _system(),
        _user("Store, recall and plan"),
        _assistant(chr(0x3000) + chr(0x2003), [_STORE, _RECALL, _CREATE]),
        _tool("toolu_1", "stored"),
        _tool("toolu_2", "recalled"),
        _tool("toolu_3", "created"),
    ]
    assert _convert(messages) == (
        (
            _SYSTEM,
            [
                {"role": "user", "content": "Store, recall and plan"},
                {"role": "assistant", "content": [_STORE_SENT, _RECALL_SENT, _CREATE_SENT]},
                {
                    "role": "user",
                    "content": [
                        _result_block("toolu_1", "stored"),
                        _result_block("toolu_2", "recalled"),
                        _result_block("toolu_3", "created"),
                    ],
                },
            ],
        ),
        True,
    )


@pytest.mark.parametrize("blank", list(_BLANKS_AND_EMPTY))
def test_llm_anthropic_history_whitespace_text_and_tool_uses_without_id_left_out(
    blank: str,
) -> None:
    """Whitespace-only text and no tool_use block with an id: left out, the users merge."""
    without_id = {"type": "tool_use", "name": "memory.list", "input": {}}
    empty_id = {"type": "tool_use", "id": "", "name": "memory.list", "input": {}}
    messages = [
        _system(),
        _user("First question"),
        _assistant(_BLANKS_AND_EMPTY[blank], [without_id, empty_id]),
        _user("Second question"),
    ]
    assert _convert(messages) == (
        (_SYSTEM, [{"role": "user", "content": "First question\nSecond question"}]),
        True,
    )


# ===========================================================================
# 2. Converter: a whitespace-only string merging with a block list
# ===========================================================================


@pytest.mark.parametrize("blank", list(_BLANKS_AND_EMPTY))
def test_llm_anthropic_history_whitespace_user_after_tool_result_dropped(blank: str) -> None:
    """Tool result list, a blank cut final answer (left out), a whitespace-only user message.

    The user message merges into the tool result's user turn: the whitespace-only
    string is dropped, the tool_result block kept, and no text block is added.
    """
    messages = [
        _system(),
        _user("Store it"),
        _assistant("", [_STORE]),
        _tool("toolu_1", "stored"),
        _assistant(""),
        _user(_BLANKS_AND_EMPTY[blank]),
    ]
    assert _convert(messages) == (
        (
            _SYSTEM,
            [
                {"role": "user", "content": "Store it"},
                {"role": "assistant", "content": [_STORE_SENT]},
                {"role": "user", "content": [_result_block("toolu_1", "stored")]},
            ],
        ),
        True,
    )


@pytest.mark.parametrize("blank", list(_BLANKS_AND_EMPTY))
def test_llm_anthropic_history_whitespace_user_before_tool_result_dropped(blank: str) -> None:
    """A whitespace-only user message, then a tool result: the string is dropped, the block kept."""
    messages = [
        _system(),
        _user(_BLANKS_AND_EMPTY[blank]),
        _tool("toolu_9", "result"),
    ]
    assert _convert(messages) == (
        (_SYSTEM, [{"role": "user", "content": [_result_block("toolu_9", "result")]}]),
        True,
    )


# ===========================================================================
# 3. Converter: non-blank text verbatim, input and other providers unchanged
# ===========================================================================


def test_llm_anthropic_history_non_blank_text_kept_verbatim_beside_dropped_blank() -> None:
    """Two tool turns: a padded text is sent as stored, a whitespace-only one is dropped.

    A padded user message after a tool result becomes a text block as stored too.
    The input messages are not changed.
    """
    messages = [
        _system(),
        _user("Store it"),
        _assistant(" padded\n", [_STORE]),
        _tool("toolu_1", "stored"),
        _assistant("\n\t ", [_RECALL]),
        _tool("toolu_2", "recalled"),
        _user(" thanks \n"),
    ]
    assert _convert(messages) == (
        (
            _SYSTEM,
            [
                {"role": "user", "content": "Store it"},
                {
                    "role": "assistant",
                    "content": [{"type": "text", "text": " padded\n"}, _STORE_SENT],
                },
                {"role": "user", "content": [_result_block("toolu_1", "stored")]},
                {"role": "assistant", "content": [_RECALL_SENT]},
                {
                    "role": "user",
                    "content": [
                        _result_block("toolu_2", "recalled"),
                        {"type": "text", "text": " thanks \n"},
                    ],
                },
            ],
        ),
        True,
    )


def test_llm_anthropic_history_whitespace_dropped_for_anthropic_only() -> None:
    """The same history: Anthropic drops the whitespace-only text, OpenAI-compatible sends it.

    Decision 1 changes the Anthropic converter only; the OpenAI-compatible one
    (OpenAI, vLLM, Infomaniak) still replays the assistant message as stored.
    """
    messages = [
        _system(),
        _user("Store it"),
        _assistant("\n\t ", [_STORE]),
        _tool("toolu_1", "stored"),
    ]
    anthropic_sent = _convert_messages_to_anthropic(messages)
    openai_sent = _convert_messages_to_openai(messages)
    assert (anthropic_sent, openai_sent) == (
        (
            _SYSTEM,
            [
                {"role": "user", "content": "Store it"},
                {"role": "assistant", "content": [_STORE_SENT]},
                {"role": "user", "content": [_result_block("toolu_1", "stored")]},
            ],
        ),
        [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": "Store it"},
            {
                "role": "assistant",
                "content": "\n\t ",
                "tool_calls": [
                    {
                        "id": "toolu_1",
                        "type": "function",
                        "function": {
                            "name": "memory.store",
                            "arguments": json.dumps({"key": "k", "value": "v"}),
                        },
                    }
                ],
            },
            {"role": "tool", "content": "stored", "tool_call_id": "toolu_1"},
        ],
    )


# ===========================================================================
# 4. On the wire: chat() and chat_stream()
# ===========================================================================


def _frame(event: str, data: dict[str, Any]) -> bytes:
    """One Anthropic Messages SSE frame."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def _reply_message(text: str) -> dict[str, Any]:
    """An Anthropic ``message`` with one text block (a ``chat()`` body)."""
    return {
        "id": "msg_w1_01",
        "type": "message",
        "role": "assistant",
        "model": _MODEL,
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 12, "output_tokens": 3},
    }


def _reply_frames(text: str) -> list[bytes]:
    """A whole Anthropic stream answering ``text``."""
    start = _reply_message("")
    start["content"] = []
    start["stop_reason"] = None
    return [
        _frame("message_start", {"type": "message_start", "message": start}),
        _frame(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        _frame(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": text},
            },
        ),
        _frame("content_block_stop", {"type": "content_block_stop", "index": 0}),
        _frame(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 15},
            },
        ),
        _frame("message_stop", {"type": "message_stop"}),
    ]


class _Body(httpx.AsyncByteStream):
    """A response body yielding ``frames`` one by one."""

    def __init__(self, frames: list[bytes]) -> None:
        self._frames = frames

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield each frame."""
        for frame in self._frames:
            yield frame

    async def aclose(self) -> None:
        """Nothing to release."""


class _Wire:
    """Stands in for the network behind ``httpx.AsyncClient.send``.

    Each POST's JSON body is kept and answered with a plain reply (JSON for
    ``chat()``, SSE when the body asks to stream); anything else gets a 404.
    """

    def __init__(self) -> None:
        self.bodies: list[dict[str, Any]] = []

    async def send(self, request: httpx.Request) -> httpx.Response:
        """Record ``request`` and answer it."""
        await request.aread()
        if request.method != "POST":
            return httpx.Response(404, json={"error": "unexpected"}, request=request)
        body = json.loads(request.content)
        self.bodies.append(body)
        if body.get("stream"):
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=_Body(_reply_frames("Fine ")),
                request=request,
            )
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=json.dumps(_reply_message("Fine ")).encode(),
            request=request,
        )


@pytest.fixture()
def wire(monkeypatch: pytest.MonkeyPatch) -> _Wire:
    """Claude configured; every ``httpx.AsyncClient.send`` goes to the fake wire."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", _ANTHROPIC_KEY)
    for name in ("ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(name, raising=False)

    async def no_sleep(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(anthropic_base_client.AsyncAPIClient, "_sleep_for_retry", no_sleep)
    fake = _Wire()

    async def send(_client: httpx.AsyncClient, request: httpx.Request, **_: Any) -> httpx.Response:
        return await fake.send(request)

    monkeypatch.setattr(httpx.AsyncClient, "send", send)
    return fake


@pytest.fixture()
async def claude(wire: _Wire) -> AsyncIterator[AnthropicClient]:
    """An Anthropic client on the fake wire (closed after the test)."""
    client = AnthropicClient(
        LLMConfig(provider="anthropic", timeout_s=5, anthropic_model="claude-sonnet-4-6")
    )
    yield client
    await client.close()


async def _send(client: AnthropicClient, path: str, messages: list[LLMMessage]) -> None:
    """Send ``messages`` through ``chat()`` or a drained ``chat_stream()``."""
    if path == "chat":
        await client.chat(messages)
        return
    async for _item in client.chat_stream(messages):
        pass


def _blank_text_blocks(sent: list[dict[str, Any]]) -> list[str]:
    """Every whitespace-only text block in a content list of ``sent`` (by its repr)."""
    return [
        repr(block)
        for entry in sent
        if isinstance(entry.get("content"), list)
        for block in entry["content"]
        if block.get("type") == "text" and not block.get("text", "").strip()
    ]


@pytest.mark.parametrize("path", ["chat", "stream"])
async def test_llm_anthropic_history_whitespace_request_body_without_blank_text_block(
    path: str, wire: _Wire, claude: AnthropicClient
) -> None:
    """Claude's request body: no whitespace-only text block, the tool_use block present.

    The history: a whitespace-only text before a tool call, its result, a blank
    cut final answer (left out), then an NBSP-only user message (dropped while it
    merges with the tool result's turn).
    """
    messages = [
        _system(),
        _user("Store it"),
        _assistant(" ", [_STORE]),
        _tool("toolu_1", "stored"),
        _assistant(""),
        _user(chr(0xA0)),
    ]
    await _send(claude, path, messages)
    sent = wire.bodies[0]["messages"]
    assert (len(wire.bodies), wire.bodies[0].get("system"), _blank_text_blocks(sent), sent) == (
        1,
        _SYSTEM,
        [],
        [
            {"role": "user", "content": "Store it"},
            {"role": "assistant", "content": [_STORE_SENT]},
            {"role": "user", "content": [_result_block("toolu_1", "stored")]},
        ],
    )


# ===========================================================================
# 5. Invariant over generated histories
# ===========================================================================

# Message kinds of a generated history. "assistant-blank" (D11) and
# "assistant-blank-no-id" (Decision 1) are left out by the converter.
_KINDS: Final[tuple[str, ...]] = (
    "user",
    "user-blank",
    "assistant",
    "assistant-blank",
    "assistant-tool",
    "assistant-blank-tool",
    "assistant-blank-no-id",
    "tool",
)
_LEFT_OUT: Final = frozenset({"assistant-blank", "assistant-blank-no-id"})
_USER_TURN: Final = frozenset({"user", "user-blank", "tool"})
_MAX_LENGTH: Final = 4


def _generated(kind: str, position: int, blank: str) -> LLMMessage:
    """The message of ``kind`` at ``position`` (texts and ids unique per position)."""
    tag = f"m{position}"
    if kind == "user":
        return _user(f" {tag} question\n")
    if kind == "user-blank":
        return _user(blank)
    if kind == "assistant":
        return _assistant(f" {tag} answer\n")
    if kind == "assistant-blank":
        return _assistant(blank)
    if kind == "assistant-tool":
        call = {"type": "tool_use", "id": f"toolu_{tag}", "name": "memory.store", "input": {}}
        return _assistant(f" {tag} calling\n", [call])
    if kind == "assistant-blank-tool":
        calls = [
            {"type": "tool_use", "id": f"toolu_{tag}a", "name": "memory.store", "input": {}},
            {"type": "tool_use", "id": f"toolu_{tag}b", "name": "memory.recall", "input": {}},
        ]
        return _assistant(blank, calls)
    if kind == "assistant-blank-no-id":
        return _assistant(blank, [{"type": "tool_use", "name": "memory.list", "input": {}}])
    return _tool(f"toolu_r{tag}", "result")


def _blank_user_turn(kinds: tuple[str, ...]) -> bool:
    """True when whitespace-only user messages form a whole turn alone (out of scope)."""
    turn: list[str] = []
    for kind in [*(k for k in kinds if k not in _LEFT_OUT), None]:
        if kind in _USER_TURN:
            turn.append(kind)
            continue
        if turn and all(k == "user-blank" for k in turn):
            return True
        turn = []
    return False


def _problems(messages: list[LLMMessage]) -> list[str]:
    """What the converted history breaks (an empty list when it is sound)."""
    (_system_prompt, sent), unchanged = _convert(messages)
    problems: list[str] = [] if unchanged else ["input changed"]
    roles = [entry["role"] for entry in sent]
    if any(first == second for first, second in itertools.pairwise(roles)):
        problems.append("same-role neighbours")
    texts: list[str] = []
    tool_use_ids: list[str] = []
    tool_result_ids: list[str] = []
    for entry in sent:
        content = entry["content"]
        if isinstance(content, str):
            texts.append(content)
            continue
        if not content:
            problems.append("empty content list")
        for block in content:
            if block["type"] == "text":
                if not block["text"].strip():
                    problems.append(f"whitespace-only text block {block['text']!r}")
                texts.append(block["text"])
            elif block["type"] == "tool_use":
                tool_use_ids.append(block["id"])
            elif block["type"] == "tool_result":
                tool_result_ids.append(block["tool_use_id"])
    stored_tool_use_ids = [
        block["id"]
        for message in messages
        if message.role == "assistant"
        for block in message.tool_use_blocks or []
        if block.get("id")
    ]
    stored_result_ids = [message.tool_call_id for message in messages if message.role == "tool"]
    if tool_use_ids != stored_tool_use_ids:
        problems.append(f"tool_use ids {tool_use_ids} != {stored_tool_use_ids}")
    if tool_result_ids != stored_result_ids:
        problems.append(f"tool_result ids {tool_result_ids} != {stored_result_ids}")
    problems.extend(
        f"text {message.content!r} not sent verbatim"
        for message in messages
        if message.role in ("user", "assistant") and message.content.strip()
        if not any(message.content in text for text in texts)
    )
    return problems


def test_llm_anthropic_history_whitespace_invariant_over_generated_histories() -> None:
    """Every history of up to four messages, for each blank variant: a sound Anthropic history.

    No content list holds a whitespace-only text block or is empty; same-role
    neighbours are merged; every tool_use id (of a block with an id) and every
    tool_result id is sent in its order; every non-blank user / assistant text is
    sent verbatim; the input is unchanged. Histories in which whitespace-only user
    messages form a whole turn alone are out of scope and left out.
    """
    checked = 0
    failures: list[tuple[str, tuple[str, ...], list[str]]] = []
    for blank_name, blank in _BLANKS_AND_EMPTY.items():
        for length in range(1, _MAX_LENGTH + 1):
            for kinds in itertools.product(_KINDS, repeat=length):
                if _blank_user_turn(kinds):
                    continue
                checked += 1
                messages = [
                    _system(),
                    *(_generated(kind, i, blank) for i, kind in enumerate(kinds)),
                ]
                problems = _problems(messages)
                if problems:
                    failures.append((blank_name, kinds, problems))
    assert (checked > 15000, len(failures), failures[:3]) == (True, 0, [])
