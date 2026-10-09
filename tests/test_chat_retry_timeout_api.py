"""HTTP spec of retrying a streamed answer that timed out after text (GH-245 with GH-25 D9).

Issue #245, Decisions 1, 2 and 7 (second bullet); contract C1'b. A streamed run whose
LLM call times out after it forwarded text keeps that text as an assistant message
(GH-25 D9) right before the error reply. Since C1'b that partial is stored with the
failed answer's status ``error`` (``append_messages``: every non-last assistant message
without tool_use blocks of an ``error`` run), so ``delete_failed_turn``'s shape check,
which admits ``assistant`` ``error`` rows between the turn's user row and the failed
row, lets the retry replace the turn instead of refusing it (a 500 forever).

The app from ``create_app()`` runs against the FakeDb world of tests/tenancy_world.py
(its ``delete_failed_turn`` emulation follows the amended 0031 body) with the REAL
``admino.agent.Agent`` (the real tool-call recorder) around the scripted streaming LLM
of tests/test_chat_output_sanitization_api.py: per user message it plays the planned
answers in call order (deltas then the final response, or deltas then a ``timeout``),
so the retry's answer is planned under the same message. Every chat is user-titled
(no title call); the registry is empty.

Pinned:
- A streamed send that times out after text stores (and GET shows) the earlier
  exchange, then the user message ``complete``, the partial reply (the deltas sent)
  ``error`` and the error reply ``error``; GET says ``retryable: true``.
- POST /api/chats/{id}/retry of that chat, over JSON and over SSE, answers 200 (the
  JSON ``ChatResponse`` with ``status: "final"`` and the new answer; over SSE no
  ``error`` frame and ``message_saved{complete}``), the LLM is called once more with
  the same message, and the turn is replaced: the earlier exchange, the re-stored user
  message and the new answer, both ``complete``; GET says ``retryable: false``.
- A retry that itself times out after text is stored the same way (``U A(partial,
  error) A(error)`` in place of the first failed turn), is retryable again, and the
  next retry replaces it.

Security notes:
- Every message and answer is a fixed fake value. No network, no real PostgreSQL, no
  real LLM.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest

from admino import main as main_module
from admino.agent import Agent
from admino.models import AgentConfig
from admino.tools import registry
from tests.context_frames import fix_instructions
from tests.db_fakes import FakeDb
from tests.tenancy_world import (
    build_world,
    make_app,
    make_client,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)
from tests.test_chat_output_sanitization_api import (
    _SSE_ACCEPT,
    _TIMEOUT_MESSAGE,
    _chat,
    _detail,
    _failing,
    _joined,
    _names,
    _saved,
    _ScriptLLM,
    _send,
    _shown,
    _stream,
    _streamed,
    _timeout,
)

if TYPE_CHECKING:
    import uuid

    import httpx
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, World
    from tests.test_chat_output_sanitization_api import Step

_QUESTION: Final = "Plan the trip to Zurich"
_ANSWER: Final = "Here is the plan."
_EARLIER: Final = (
    ("user", "Earlier question", "complete"),
    ("assistant", "Earlier answer", "complete"),
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    """Orgs A and B (OA/ED/VI each) and a Super Admin, behind the fake database."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    return built


@pytest.fixture(autouse=True)
def _fixed_instructions(monkeypatch: pytest.MonkeyPatch) -> None:
    """GH-190: the instructions count a constant, so every run's budget is deterministic."""
    fix_instructions(monkeypatch)


@pytest.fixture(autouse=True)
def _empty_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty, unfrozen registry (any tool call is unknown); the old one is restored."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)


@pytest.fixture()
def llm() -> _ScriptLLM:
    return _ScriptLLM()


@pytest.fixture()
def client(world: World, llm: _ScriptLLM) -> TestClient:
    """The app around a REAL Agent (real tool-call recorder) and the scripted LLM."""
    agent = Agent(
        llm_client=llm,
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
    )
    return make_client(make_app(agent), raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _chat_with_history(db: FakeDb, account: Account) -> uuid.UUID:
    """A user-titled chat of ``account`` holding one completed exchange."""
    chat_id = _chat(db, account)
    for role, content, status in _EARLIER:
        db.add_chat_message(chat_id, role, content, status=status)
    return chat_id


def _retry(
    client: TestClient, account: Account, chat_id: uuid.UUID, *, sse: bool = False
) -> httpx.Response:
    """POST /api/chats/{chat_id}/retry as ``account`` (no body; streamed when ``sse``)."""
    return client.post(
        f"/api/chats/{chat_id}/retry",
        headers={**account.cookie, **(_SSE_ACCEPT if sse else {})},
    )


def _timed_out(partial: str, rest: str) -> list[Step]:
    """A streamed answer that sends ``partial`` and ``rest`` (cut mid-word), then times out."""
    return _failing(_timeout(), partial, rest)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_chat_retry_timeout_after_text_stores_the_partial_as_error_and_is_retryable(
    world: World, client: TestClient, llm: _ScriptLLM
) -> None:
    """C1'b: the partial reply (what the deltas showed) is stored ``error`` with the
    error reply; the user message stays ``complete``; GET says retryable."""
    editor = world.a["editor"]
    chat_id = _chat_with_history(world.db, editor)
    llm.plan(_QUESTION, _timed_out("Day one: ", "Zuri"))

    frames = _stream(_send(client, editor, chat_id, _QUESTION))

    detail = _detail(client, editor, chat_id)
    assert ("error", {"code": "timeout", "message": _TIMEOUT_MESSAGE}) in frames
    assert _shown(detail) == [
        *_EARLIER,
        ("user", _QUESTION, "complete"),
        ("assistant", _joined(frames), "error"),
        ("assistant", _TIMEOUT_MESSAGE, "error"),
    ]
    assert detail.json()["retryable"] is True


@pytest.mark.parametrize("sse", [False, True], ids=["json", "sse"])
def test_chat_retry_timeout_retry_replaces_the_timed_out_turn(
    world: World, client: TestClient, llm: _ScriptLLM, sse: bool
) -> None:
    """Decision 2 with C1'b: the retry of a turn that timed out after text answers 200
    (never the 500 of a refused delete) and replaces the whole turn, partial included."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _chat_with_history(db, editor)
    llm.plan(_QUESTION, _timed_out("Day one: ", "Zuri"), _streamed("Here is ", "the plan."))
    _stream(_send(client, editor, chat_id, _QUESTION))

    response = _retry(client, editor, chat_id, sse=sse)

    if sse:
        frames = _stream(response)
        assert "error" not in _names(frames)
        assert _saved(db, chat_id, "complete") in frames
    else:
        assert response.status_code == 200, response.text
        assert (response.json()["status"], response.json()["response"]) == ("final", _ANSWER)
    detail = _detail(client, editor, chat_id)
    assert _shown(detail) == [
        *_EARLIER,
        ("user", _QUESTION, "complete"),
        ("assistant", _ANSWER, "complete"),
    ]
    assert detail.json()["retryable"] is False
    assert llm.calls == [_QUESTION, _QUESTION]


def test_chat_retry_timeout_retry_that_times_out_after_text_again_is_retryable_again(
    world: World, client: TestClient, llm: _ScriptLLM
) -> None:
    """The retried run times out after text too: its turn replaces the first failed one,
    stored ``U A(partial, error) A(error)``, GET says retryable, and the next retry
    replaces it with the answer."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _chat_with_history(db, editor)
    llm.plan(
        _QUESTION,
        _timed_out("Day one: ", "Zuri"),
        _timed_out("Day two: ", "Ber"),
        _streamed("Here is ", "the plan."),
    )
    _stream(_send(client, editor, chat_id, _QUESTION))

    again = _stream(_retry(client, editor, chat_id, sse=True))
    between = _detail(client, editor, chat_id)
    final = _retry(client, editor, chat_id)

    assert ("error", {"code": "timeout", "message": _TIMEOUT_MESSAGE}) in again
    assert _shown(between) == [
        *_EARLIER,
        ("user", _QUESTION, "complete"),
        ("assistant", _joined(again), "error"),
        ("assistant", _TIMEOUT_MESSAGE, "error"),
    ]
    assert between.json()["retryable"] is True
    assert final.status_code == 200, final.text
    assert _shown(_detail(client, editor, chat_id)) == [
        *_EARLIER,
        ("user", _QUESTION, "complete"),
        ("assistant", _ANSWER, "complete"),
    ]
