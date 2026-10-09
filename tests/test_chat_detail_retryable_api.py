"""HTTP spec of GH-245's client signal: ``GET /api/chats/{chat_id}``'s ``retryable``.

Issue #245, criterion "A client can tell from the chat API whether the last answer
ended as error or interrupted, so it knows when to offer Retry", Decisions 1, 4 and
6; contract C3 (``ChatDetailResponse.retryable``) and C4's GET line
(``retryable = detail.latest_status in chats.RETRYABLE_STATUSES``, no new statement).

The app from ``create_app()`` runs against the FakeDb world of tests/tenancy_world.py
(org A's Editor reads their own chats). The agent is a stub bound to the real
``Agent.run`` signature that echoes the history it got plus the user message and a
final reply (only the agreement test runs it, through the retry route).

What is pinned:
- ``retryable`` is ``true`` exactly when the chat's latest message (highest seq, any
  role) ended as ``error`` or ``stopped``: on the assistant reply, on a ``tool`` row
  and on the user row itself (a stop before any output). Each message keeps its
  ``status``, which tells an error from a stop.
- ``retryable`` is ``false`` for a latest ``complete``, ``awaiting_confirmation`` (a
  live pending confirmation, and an expired one), ``limit_reached`` message, for an
  empty chat, for a failed answer followed by an org notice (a ``user`` message), and
  for an earlier failed turn followed by a complete one.
- It follows the latest message whatever page is read: a ``cursor`` page that doesn't
  hold the latest message reports the latest one's state, not its own messages'.
- Reading it adds no statement: the GET still runs exactly the owner check (S2), the
  page (S9'), the latest status (S15), the turn setup (T1) and the turn read (T2''),
  for a retryable chat and for one that isn't.
- It agrees with the retry route's status check: every chat it calls retryable is
  re-run by ``POST /api/chats/{chat_id}/retry`` (200), every other answers the 409
  ``not_retryable``.

``admino.chats.RETRYABLE_STATUSES`` and the retry route don't exist before GH-245;
nothing new is imported at module level, so the file collects either way.

Security notes: every id and text here is a fixed fake value. No network, no real
PostgreSQL, no LLM.
"""

from __future__ import annotations

import inspect
import re
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino.agent import Agent
from admino.models import AgentResult, LLMMessage
from tests.db_fakes import FakeDb
from tests.tenancy_world import (
    build_world,
    make_app,
    make_client,
    seed_pending_confirmation,
    stub_agent,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    import uuid
    from collections.abc import Callable
    from unittest.mock import MagicMock

    import httpx
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CALL_ID: Final = "call_245_search"
_TOOL_BLOCK: Final[dict[str, Any]] = {
    "type": "tool_use",
    "id": _CALL_ID,
    "name": "gmail.search",
    "input": {"query": "Offerte 245"},
}
_NOT_RETRYABLE: Final = {"detail": "The last answer can't be retried.", "reason": "not_retryable"}

# Statements that aren't the route's work: the session lookup and a settings read.
_NOT_WORK_SQL: Final = re.compile(r"\b(?:sessions|platform_settings)\b")
_OWNER_LOOKUP: Final = re.compile(
    r"select .+ from chats where id = \$1 and org_id = \$2 and owner_user_id = \$3"
    r" and deleted_at is null"
)
# What GET /api/chats/{chat_id} runs before GH-245 (tests/test_chat_detail_context_api.py).
_TODAYS_DETAIL_WORK: Final = ["owner-lookup", "page", "status", "turn-setup", "turn"]


# ---------------------------------------------------------------------------
# Seeds: one chat state each (as the server stores the run's messages)
# ---------------------------------------------------------------------------


def _ask(db: FakeDb, chat_id: uuid.UUID, text: str = "Offerte 245 bitte", **kw: Any) -> None:
    db.add_chat_message(chat_id, "user", text, **kw)


def _tool_turn(db: FakeDb, chat_id: uuid.UUID, tool_status: str) -> None:
    """A question, the assistant's tool call and the tool row stored ``tool_status``."""
    _ask(db, chat_id)
    db.add_chat_message(chat_id, "assistant", "", tool_use_blocks=[_TOOL_BLOCK])
    db.add_chat_message(
        chat_id, "tool", "Two emails found.", tool_call_id=_CALL_ID, status=tool_status
    )


def _answered(status: str) -> Callable[[FakeDb, uuid.UUID], None]:
    """A question and its answer stored with ``status``."""

    def seed(db: FakeDb, chat_id: uuid.UUID) -> None:
        _ask(db, chat_id)
        db.add_chat_message(chat_id, "assistant", "Die Offerte 245 ist", status=status)

    return seed


def _tool_row(status: str) -> Callable[[FakeDb, uuid.UUID], None]:
    def seed(db: FakeDb, chat_id: uuid.UUID) -> None:
        _tool_turn(db, chat_id, status)

    return seed


def _user_row(status: str) -> Callable[[FakeDb, uuid.UUID], None]:
    """Only the question, stored with ``status`` (a stop before any output)."""

    def seed(db: FakeDb, chat_id: uuid.UUID) -> None:
        _ask(db, chat_id, status=status)

    return seed


def _awaiting(db: FakeDb, chat_id: uuid.UUID) -> None:
    """A question and the assistant's tool call waiting for an approval."""
    _ask(db, chat_id)
    db.add_chat_message(
        chat_id,
        "assistant",
        "",
        tool_use_blocks=[_TOOL_BLOCK],
        status="awaiting_confirmation",
    )


def _empty(_db: FakeDb, _chat_id: uuid.UUID) -> None:
    """No message at all."""


def _error_then_org_notice(db: FakeDb, chat_id: uuid.UUID) -> None:
    """A failed answer followed by GH-66's org notice (a complete user message)."""
    _answered("error")(db, chat_id)
    _ask(db, chat_id, "Die Organisation hat gmail.send freigegeben.")


def _earlier_failure_then_complete(db: FakeDb, chat_id: uuid.UUID) -> None:
    """An older failed turn, then a complete one: the latest message decides."""
    _answered("error")(db, chat_id)
    _ask(db, chat_id, "Noch einmal bitte")
    db.add_chat_message(chat_id, "assistant", "Hier ist die Offerte 245.")


# state -> how its messages are seeded (_chat_in adds the live pending of one state).
_RETRYABLE: Final[dict[str, Callable[[FakeDb, uuid.UUID], None]]] = {
    "error-on-the-assistant-reply": _answered("error"),
    "error-on-a-tool-row": _tool_row("error"),
    "error-on-the-user-row": _user_row("error"),
    "stopped-on-the-assistant-reply": _answered("stopped"),
    "stopped-on-a-tool-row": _tool_row("stopped"),
    "stopped-on-the-user-row": _user_row("stopped"),
}
_NOT_RETRYABLE_STATES: Final[dict[str, Callable[[FakeDb, uuid.UUID], None]]] = {
    "complete": _answered("complete"),
    "awaiting-confirmation-pending": _awaiting,
    "awaiting-confirmation-expired": _awaiting,
    "limit-reached": _answered("limit_reached"),
    "empty-chat": _empty,
    "error-followed-by-an-org-notice": _error_then_org_notice,
    "earlier-failure-then-a-complete-turn": _earlier_failure_then_complete,
}
# The latest message's (role, status) of each retryable state.
_LATEST: Final[dict[str, tuple[str, str]]] = {
    "error-on-the-assistant-reply": ("assistant", "error"),
    "error-on-a-tool-row": ("tool", "error"),
    "error-on-the-user-row": ("user", "error"),
    "stopped-on-the-assistant-reply": ("assistant", "stopped"),
    "stopped-on-a-tool-row": ("tool", "stopped"),
    "stopped-on-the-user-row": ("user", "stopped"),
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    """Orgs A and B (OA/ED/VI each) and a Super Admin behind the fake database."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    return built


@pytest.fixture()
def agent() -> MagicMock:
    """A stub agent bound to ``Agent.run``'s signature: it answers ``Done.`` after the
    history it got and the user message (a final run)."""

    async def run(*args: Any, **kwargs: Any) -> AgentResult:
        bound = inspect.signature(Agent.run).bind(None, *args, **kwargs)
        history = list(bound.arguments["history"])
        return AgentResult(
            status="final",
            response="Done.",
            history=[
                *history,
                LLMMessage(role="user", content=bound.arguments["user_message"]),
                LLMMessage(role="assistant", content="Done."),
            ],
            tool_calls=[],
            pending_confirmation=None,
        )

    stub = stub_agent()
    stub.run.side_effect = run
    return stub


@pytest.fixture()
def client(world: World, agent: MagicMock) -> TestClient:
    """The app (built after the world: create_app clears the chat runtime)."""
    return make_client(make_app(agent))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _chat_in(world: World, owner: Account, state: str) -> uuid.UUID:
    """A titled chat of ``owner`` seeded in ``state`` (a live pending confirmation in
    the chat runtime for "awaiting-confirmation-pending"); its id."""
    chat_id = world.db.add_chat(owner.user_id, title="Retry 245", title_source="user")
    seeds = {**_RETRYABLE, **_NOT_RETRYABLE_STATES}
    seeds[state](world.db, chat_id)
    if state == "awaiting-confirmation-pending":
        seed_pending_confirmation(owner, chat_id, "conf-245")
    return chat_id


def _detail(
    client: TestClient, caller: Account, chat_id: uuid.UUID, **params: Any
) -> httpx.Response:
    return client.get(f"/api/chats/{chat_id}", params=params, headers=caller.cookie)


def _body(response: httpx.Response) -> dict[str, Any]:
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _kind(sql: str) -> str:
    """A detail request's statement: owner-lookup (S2), page (S9' / S11'), status (S15),
    turn-setup (T1), turn (T2''), else the SQL itself."""
    if _OWNER_LOOKUP.fullmatch(sql):
        return "owner-lookup"
    if "from chat_messages m" in sql and "as attachment_ids" in sql:
        return "page"
    if sql.startswith("select status from chat_messages"):
        return "status"
    if "from organizations o" in sql and "left join chats c" in sql:
        return "turn-setup"
    if "from chats c left join lateral" in sql:
        return "turn"
    return sql


def _work(db: FakeDb, since: int) -> list[str]:
    """The kinds of the statements after call ``since``, the session and settings aside."""
    return [
        _kind(call.normalized)
        for call in db.calls[since:]
        if not _NOT_WORK_SQL.search(call.normalized)
    ]


# ---------------------------------------------------------------------------
# 1. retryable follows the latest message (Decisions 1 and 6)
# ---------------------------------------------------------------------------


class TestChatDetailRetryable:
    """``true`` exactly when the latest message ended as ``error`` or ``stopped``."""

    @pytest.mark.parametrize("state", list(_RETRYABLE))
    def test_chat_detail_retryable_is_true_when_the_latest_message_failed(
        self, world: World, client: TestClient, state: str
    ) -> None:
        """A latest ``error`` / ``stopped`` message, whatever its role: ``retryable`` is
        true (a JSON bool), and the message's own ``status`` tells an error from a stop."""
        editor = world.a["editor"]
        chat_id = _chat_in(world, editor, state)

        body = _body(_detail(client, editor, chat_id))

        latest = body["messages"][-1]
        assert (body.get("retryable"), (latest["role"], latest["status"])) == (
            True,
            _LATEST[state],
        )

    @pytest.mark.parametrize("state", list(_NOT_RETRYABLE_STATES))
    def test_chat_detail_retryable_is_false_unless_the_latest_message_failed(
        self, world: World, client: TestClient, state: str
    ) -> None:
        """A latest ``complete``, ``awaiting_confirmation`` (pending or expired) or
        ``limit_reached`` message, an empty chat, a failed answer followed by an org
        notice and an earlier failure followed by a complete turn: ``retryable`` is
        false (a JSON bool, never null)."""
        editor = world.a["editor"]
        chat_id = _chat_in(world, editor, state)

        body = _body(_detail(client, editor, chat_id))

        assert body.get("retryable", "missing") is False

    @pytest.mark.parametrize(
        ("latest_status", "earlier_status", "page_size", "retryable"),
        [
            pytest.param("error", "complete", 1, True, id="failed-latest-not-on-the-page"),
            pytest.param("complete", "error", 2, False, id="complete-latest-failure-on-the-page"),
        ],
    )
    def test_chat_detail_retryable_follows_the_latest_message_on_a_cursor_page(
        self,
        world: World,
        client: TestClient,
        latest_status: str,
        earlier_status: str,
        page_size: int,
        retryable: bool,
    ) -> None:
        """Two turns; the earlier page (read with the latest page's ``next_cursor``)
        doesn't hold the latest message, and still reports the latest message's state:
        true when the latest answer failed though the page's messages are complete,
        false when only the page's earlier answer failed."""
        db = world.db
        editor = world.a["editor"]
        chat_id = db.add_chat(editor.user_id, title="Retry 245", title_source="user")
        _ask(db, chat_id, "Erste Frage 245")
        db.add_chat_message(chat_id, "assistant", "Erste Antwort 245", status=earlier_status)
        _ask(db, chat_id, "Zweite Frage 245")
        db.add_chat_message(chat_id, "assistant", "Zweite Antwort 245", status=latest_status)
        latest_page = _body(_detail(client, editor, chat_id, limit=page_size))
        assert latest_page["next_cursor"] is not None

        earlier = _body(
            _detail(client, editor, chat_id, limit=page_size, cursor=latest_page["next_cursor"])
        )

        statuses = [message["status"] for message in earlier["messages"]]
        expected_statuses = ["complete"] if page_size == 1 else ["complete", earlier_status]
        assert (statuses, latest_page.get("retryable"), earlier.get("retryable")) == (
            expected_statuses,
            retryable,
            retryable,
        )


# ---------------------------------------------------------------------------
# 2. No new statement (contract C4: the S15 status read already exists)
# ---------------------------------------------------------------------------


class TestChatDetailRetryableStatements:
    """``retryable`` comes from the latest status the GET already reads."""

    def test_chat_detail_retryable_adds_no_statement(
        self, world: World, client: TestClient
    ) -> None:
        """A retryable chat's GET and a complete chat's GET each run exactly today's
        S2, S9', S15, T1 and T2'' (no retry-target read, nothing else), and report
        ``retryable`` true and false."""
        db = world.db
        editor = world.a["editor"]
        failed = _chat_in(world, editor, "error-on-the-assistant-reply")
        complete = _chat_in(world, editor, "complete")

        since = len(db.calls)
        failed_body = _body(_detail(client, editor, failed))
        failed_work = _work(db, since)
        since = len(db.calls)
        complete_body = _body(_detail(client, editor, complete))
        complete_work = _work(db, since)

        assert (
            failed_body.get("retryable"),
            complete_body.get("retryable"),
            failed_work,
            complete_work,
        ) == (True, False, _TODAYS_DETAIL_WORK, _TODAYS_DETAIL_WORK)


# ---------------------------------------------------------------------------
# 3. The signal agrees with the retry route (Decision 6: the 409's rule)
# ---------------------------------------------------------------------------


class TestChatDetailRetryableAgreesWithRetry:
    """What the GET reports is what POST /api/chats/{chat_id}/retry does."""

    def test_chat_detail_retryable_agrees_with_the_retry_routes_status_check(
        self, world: World, client: TestClient
    ) -> None:
        """For every state: a chat reported retryable is re-run by the retry route
        (200); every other answers the 409 ``not_retryable``."""
        editor = world.a["editor"]
        outcomes: dict[str, tuple[Any, int, Any]] = {}
        for state in (*_RETRYABLE, *_NOT_RETRYABLE_STATES):
            chat_id = _chat_in(world, editor, state)
            retryable = _body(_detail(client, editor, chat_id)).get("retryable")
            retried = client.post(f"/api/chats/{chat_id}/retry", headers=editor.cookie)
            body = retried.json() if retried.status_code == 409 else None
            outcomes[state] = (retryable, retried.status_code, body)

        assert outcomes == {
            **dict.fromkeys(_RETRYABLE, (True, 200, None)),
            **dict.fromkeys(_NOT_RETRYABLE_STATES, (False, 409, _NOT_RETRYABLE)),
        }
