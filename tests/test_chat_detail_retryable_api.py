"""HTTP spec of ``GET /api/chats/{chat_id}``'s ``retryable`` (GH-245, GH-302).

Issue #245, criterion "A client can tell from the chat API whether the last answer
ended as error or interrupted, so it knows when to offer Retry", Decisions 1, 4 and
6; contract C3 (``ChatDetailResponse.retryable``). Issue #302, criterion
"``GET /api/chats/{id}`` computes ``retryable`` with the same predicate as the retry's
check: the latest status, a user message before it, and the turn shape", Decision 2;
contract C2 (``retryable = detail.latest_status in chats.RETRYABLE_STATUSES and await
chats.read_retry_target(pool, tenant, chat_id) is not None``) over C1's R1' (the
retry-target read with the turn-shape item ``turn_well_formed``).

The app from ``create_app()`` runs against the FakeDb world of tests/tenancy_world.py
(org A's Editor reads their own chats). The agent is a stub bound to the real
``Agent.run`` signature that echoes the history it got plus the user message and a
final reply (only the agreement tests run it, through the retry route).

What is pinned:
- ``retryable`` is ``true`` when the chat's latest message (highest seq, any role)
  ended as ``error`` or ``stopped`` in a well-formed turn: on the assistant reply, on
  a ``tool`` row and on the user row itself (a stop before any output). Each message
  keeps its ``status``, which tells an error from a stop.
- ``retryable`` is ``false`` for a latest ``complete``, ``awaiting_confirmation`` (a
  live pending confirmation, and an expired one), ``limit_reached`` message, for an
  empty chat, for a failed answer followed by an org notice (a ``user`` message), and
  for an earlier failed turn followed by a complete one.
- GH-302: ``retryable`` is ``false`` for every latest status when no user message
  comes before the latest row (the retry has nothing to re-send).
- GH-302: for each of contract C1's 22 turn shapes (the shapes validated on
  postgres:16 against ``delete_failed_turn``), ``retryable`` is the C1 result, and
  the retry agrees: a chat reported retryable is re-run (200), every other answers
  the 409 ``not_retryable``. A stopped turn and an approval turn whose tool-call
  assistant row has no tool_use blocks (NULL or ``[]``) are not retryable; their
  well-formed twins are.
- It follows the latest message whatever page is read: a ``cursor`` page that doesn't
  hold the latest message reports the latest one's state, not its own messages'.
- GH-302 (Decision 2; this replaces GH-245's "no new statement"): a chat whose latest
  status is ``error`` or ``stopped`` runs the owner check (S2), the page (S9', S11' on
  a cursor page), the latest status (S15), the retry-target read (R1', bound to the
  chat, the caller's org and the caller), the turn setup (T1) and the turn read (T2'')
  in that order; every other chat runs exactly today's S2, S9', S15, T1, T2''.
- Reading changes nothing (no chat, message, file or audit row).
- Another org's, a colleague's, a trashed and an unknown chat whose latest answer
  failed: the 404 ``chat_not_found`` after the owner check alone. A chat trashed
  between the latest-status read and R1' is the 404 from R1', nothing after it.
- It agrees with the retry route's status check (GH-245): every chat it calls
  retryable is re-run by ``POST /api/chats/{chat_id}/retry`` (200), every other
  answers the 409 ``not_retryable``.
- GH-304 (Decision 6, contract C7; #302 review suggestion 1): a well-formed failed
  turn whose ``seq`` range holds rows of another chat of the same owner and org (seq
  is one identity across chats; each such row would make the turn malformed if the
  shape check counted it) is still ``retryable: true``, with the other chat's rows
  inside the range only, on both sides of it and after it, and for a tool turn ending
  ``stopped``; the page holds the own chat's rows only.

Nothing new is imported at module level, so the file collects either way.

Security notes: every id and text here is a fixed fake value. No network, no real
PostgreSQL, no LLM.
"""

from __future__ import annotations

import copy
import inspect
import re
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino.agent import Agent
from admino.models import AgentResult, LLMMessage
from tests.db_fakes import FakeDb, norm
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
_CHAT_NOT_FOUND: Final = {"detail": "Chat not found", "reason": "chat_not_found"}
_T0: Final = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)

# Statements that aren't the route's work: the session lookup and a settings read.
_NOT_WORK_SQL: Final = re.compile(r"\b(?:sessions|platform_settings)\b")
_OWNER_LOOKUP: Final = re.compile(
    r"select .+ from chats where id = \$1 and org_id = \$2 and owner_user_id = \$3"
    r" and deleted_at is null"
)
# What GET /api/chats/{chat_id} runs for a chat whose latest status isn't error or
# stopped (unchanged since GH-266; tests/test_chat_detail_context_api.py).
_TODAYS_DETAIL_WORK: Final = ["owner-lookup", "page", "status", "turn-setup", "turn"]
# GH-302 (Decision 2, contract C2): a failed latest status adds R1' right after S15.
_FAILED_DETAIL_WORK: Final = [
    "owner-lookup",
    "page",
    "status",
    "retry-target",
    "turn-setup",
    "turn",
]


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
# GH-302: contract C1's turn shapes, row by row
# ---------------------------------------------------------------------------

# One stored row: (role, status, tool_use_blocks); None blocks are SQL NULL.
_Row = tuple[str, str, list[dict[str, Any]] | None]

_BLOCKS: Final[list[dict[str, Any]]] = [_TOOL_BLOCK]
_ASK: Final[_Row] = ("user", "complete", None)


def _reply(status: str, blocks: list[dict[str, Any]] | None = None) -> _Row:
    """An assistant row stored ``status`` (a tool call when ``blocks`` is given)."""
    return ("assistant", status, blocks)


def _result(status: str) -> _Row:
    """A tool row (the result of ``_CALL_ID``) stored ``status``."""
    return ("tool", status, None)


# shape -> (its rows in seq order, retryable): contract C1's 22 shapes
# (RUN_DIR/pg-probe-r1prime.py SHAPES; PostgreSQL's delete_failed_turn accepts the
# turn exactly when the shape is retryable).
_SHAPES: Final[dict[str, tuple[list[_Row], bool]]] = {
    # Well-formed failed turns: retryable.
    "error-reply": ([_ASK, _reply("error")], True),
    "tool-turn-ending-error": (
        [_ASK, _reply("complete", _BLOCKS), _result("complete"), _reply("error")],
        True,
    ),
    "tool-turn-ending-stopped": (
        [_ASK, _reply("complete", _BLOCKS), _result("complete"), _reply("stopped")],
        True,
    ),
    "stop-on-the-user-row": ([("user", "stopped", None)], True),
    "error-on-the-user-row": ([("user", "error", None)], True),
    "error-on-a-tool-row": ([_ASK, _reply("complete", _BLOCKS), _result("error")], True),
    "d9-partial": ([_ASK, _reply("error"), _reply("error")], True),
    "awaiting-with-blocks-then-error": (
        [_ASK, _reply("awaiting_confirmation", _BLOCKS), _result("complete"), _reply("error")],
        True,
    ),
    "earlier-malformed-turn-then-a-well-formed-failure": (
        [_ASK, _reply("complete"), _reply("stopped"), _ASK, _reply("error")],
        True,
    ),
    # Failed turns the store can't replace: not retryable.
    "stopped-turn-tool-call-without-blocks": (
        [_ASK, _reply("complete"), _result("complete"), _reply("stopped")],
        False,
    ),
    "stopped-turn-tool-call-with-empty-blocks": (
        [_ASK, _reply("complete", []), _result("complete"), _reply("stopped")],
        False,
    ),
    "approval-turn-without-blocks-ending-error": (
        [_ASK, _reply("awaiting_confirmation"), _result("complete"), _reply("error")],
        False,
    ),
    "approval-turn-without-blocks-ending-stopped": (
        [_ASK, _reply("awaiting_confirmation"), _reply("stopped")],
        False,
    ),
    "complete-no-block-reply-before-an-error": (
        [_ASK, _reply("complete"), _reply("error")],
        False,
    ),
    "limit-reached-mid-turn": ([_ASK, _reply("limit_reached"), _reply("error")], False),
    "tool-row-error-mid-turn": (
        [_ASK, _reply("complete", _BLOCKS), _result("error"), _reply("stopped")],
        False,
    ),
    "tool-row-stopped-mid-turn": (
        [_ASK, _reply("complete", _BLOCKS), _result("stopped"), _reply("stopped")],
        False,
    ),
    # Not retryable for another reason (the shape is fine).
    "complete-latest": ([_ASK, _reply("complete")], False),
    "error-then-an-org-notice": ([_ASK, _reply("error"), _ASK], False),
    "earlier-failure-then-complete": ([_ASK, _reply("error"), _ASK, _reply("complete")], False),
    "no-user-row": ([_reply("error")], False),
    "empty-chat": ([], False),
}

# Statement cases (Decision 2): rows, retryable, the GET's work.
_STATEMENT_CASES: Final[dict[str, tuple[list[_Row], bool, list[str]]]] = {
    "error": (_SHAPES["error-reply"][0], True, _FAILED_DETAIL_WORK),
    "stopped": (_SHAPES["tool-turn-ending-stopped"][0], True, _FAILED_DETAIL_WORK),
    "stopped-turn-tool-call-without-blocks": (
        _SHAPES["stopped-turn-tool-call-without-blocks"][0],
        False,
        _FAILED_DETAIL_WORK,
    ),
    "error-without-a-user-row": (_SHAPES["no-user-row"][0], False, _FAILED_DETAIL_WORK),
    "complete": (_SHAPES["complete-latest"][0], False, _TODAYS_DETAIL_WORK),
    "awaiting-confirmation": (
        [_ASK, _reply("awaiting_confirmation", _BLOCKS)],
        False,
        _TODAYS_DETAIL_WORK,
    ),
    "limit-reached": ([_ASK, _reply("limit_reached")], False, _TODAYS_DETAIL_WORK),
    "empty-chat": ([], False, _TODAYS_DETAIL_WORK),
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    """Orgs A and B (OA/ED each) and a Super Admin behind the fake database."""
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


@pytest.fixture()
def tolerant_client(world: World, agent: MagicMock) -> TestClient:
    """The same app, answering a server error as its 500 instead of raising it."""
    return make_client(make_app(agent), raise_server_exceptions=False)


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


def _shaped_chat(
    db: FakeDb, owner: Account, rows: list[_Row], *, deleted_at: datetime | None = None
) -> uuid.UUID:
    """A titled chat of ``owner`` holding ``rows`` in seq order; its id."""
    chat_id = db.add_chat(
        owner.user_id, title="Retry 302", title_source="user", deleted_at=deleted_at
    )
    for role, status, blocks in rows:
        if role == "user":
            db.add_chat_message(chat_id, "user", "Offerte 302 bitte", status=status)
        elif role == "tool":
            db.add_chat_message(
                chat_id, "tool", "Two emails found.", tool_call_id=_CALL_ID, status=status
            )
        else:
            db.add_chat_message(
                chat_id,
                "assistant",
                "Ich suche die Offerte 302.",
                tool_use_blocks=blocks,
                status=status,
            )
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
    retry-target (R1', the read with the turn-shape item), turn-setup (T1), turn
    (T2''), else the SQL itself."""
    if _OWNER_LOOKUP.fullmatch(sql):
        return "owner-lookup"
    if "as through_seq" in sql:
        # R1' (contract C1); GH-245's R1 without the shape item is not it.
        return "retry-target" if "as turn_well_formed" in sql else sql
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


def _retry_target_args(db: FakeDb, since: int) -> list[tuple[Any, ...]]:
    """The bound parameters of each R1' after call ``since``."""
    return [call.args for call in db.calls[since:] if _kind(call.normalized) == "retry-target"]


def _tables(db: FakeDb) -> dict[str, Any]:
    """A deep copy of the rows a read must not change."""
    return copy.deepcopy(
        {
            "chats": db.chats,
            "chat_messages": db.chat_messages,
            "attachments": db.attachments,
            "audit": db.audit,
            "chat_seq": db.chat_seq,
        }
    )


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
        ("status", "blocks"),
        [
            pytest.param("error", None, id="error"),
            pytest.param("stopped", None, id="stopped"),
            pytest.param("complete", None, id="complete"),
            pytest.param("awaiting_confirmation", _BLOCKS, id="awaiting-confirmation"),
            pytest.param("limit_reached", None, id="limit-reached"),
        ],
    )
    def test_chat_detail_retryable_is_false_without_a_user_message_before_the_latest_row(
        self,
        world: World,
        client: TestClient,
        status: str,
        blocks: list[dict[str, Any]] | None,
    ) -> None:
        """GH-302 (the retry's predicate): a chat whose only message is the assistant's,
        stored with any status, has no user message to re-send, so ``retryable`` is
        false (a JSON bool), also for a failed one."""
        editor = world.a["editor"]
        chat_id = _shaped_chat(world.db, editor, [_reply(status, blocks)])

        body = _body(_detail(client, editor, chat_id))

        assert (body["messages"][-1]["status"], body.get("retryable", "missing")) == (
            status,
            False,
        )

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
# 2. Statements (GH-302 Decision 2: R1' only for a failed latest status)
# ---------------------------------------------------------------------------


class TestChatDetailRetryableStatements:
    """A failed latest status adds the retry-target read; nothing else changes."""

    @pytest.mark.parametrize("case", list(_STATEMENT_CASES))
    def test_chat_detail_retryable_reads_the_retry_target_only_for_a_failed_latest_status(
        self, world: World, client: TestClient, case: str
    ) -> None:
        """GH-302 (replaces GH-245's ``test_chat_detail_retryable_adds_no_statement``):
        a chat whose latest status is ``error`` or ``stopped`` (well-formed, malformed
        or without a user row) runs S2, S9', S15, R1' (bound to the chat, org A and the
        Editor), T1 and T2'' in that order; a complete, awaiting, limit-reached and an
        empty chat run exactly today's five (no R1'). ``retryable`` is what R1' found."""
        db = world.db
        editor = world.a["editor"]
        rows, retryable, work = _STATEMENT_CASES[case]
        chat_id = _shaped_chat(db, editor, rows)
        expected_args = [(chat_id, world.org_a, editor.user_id)] if "retry-target" in work else []
        since = len(db.calls)

        body = _body(_detail(client, editor, chat_id))

        assert (body.get("retryable"), _work(db, since), _retry_target_args(db, since)) == (
            retryable,
            work,
            expected_args,
        )

    def test_chat_detail_retryable_cursor_page_of_a_failed_chat_reads_the_retry_target(
        self, world: World, client: TestClient
    ) -> None:
        """An earlier page (S11') of a chat whose latest answer failed: S2, S11', S15,
        R1', T1, T2'', and ``retryable`` true though the page holds no failed message."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _shaped_chat(db, editor, [_ASK, _reply("complete"), _ASK, _reply("error")])
        latest_page = _body(_detail(client, editor, chat_id, limit=2))
        since = len(db.calls)

        earlier = _body(
            _detail(client, editor, chat_id, limit=2, cursor=latest_page["next_cursor"])
        )

        statuses = [message["status"] for message in earlier["messages"]]
        assert (
            statuses,
            earlier.get("retryable"),
            _work(db, since),
            _retry_target_args(db, since),
        ) == (
            ["complete", "complete"],
            True,
            _FAILED_DETAIL_WORK,
            [(chat_id, world.org_a, editor.user_id)],
        )

    @pytest.mark.parametrize(
        "shape",
        [
            "error-reply",
            "stopped-turn-tool-call-without-blocks",
            "approval-turn-without-blocks-ending-error",
        ],
    )
    def test_chat_detail_retryable_read_changes_nothing(
        self, world: World, client: TestClient, shape: str
    ) -> None:
        """Reading a failed chat (well-formed or not) stores, changes and deletes no
        chat, message, file or audit row (the identity sequence doesn't move)."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _shaped_chat(db, editor, _SHAPES[shape][0])
        before = _tables(db)

        _body(_detail(client, editor, chat_id))

        assert _tables(db) == before

    @pytest.mark.parametrize("case", ["other-org", "colleague", "trashed", "unknown"])
    def test_chat_detail_retryable_unreachable_failed_chat_is_the_404_after_the_owner_check(
        self, world: World, client: TestClient, case: str
    ) -> None:
        """Another org's, a colleague's, a trashed and an unknown chat whose latest
        answer failed: the 404 ``chat_not_found`` after the owner check alone (no R1')."""
        db = world.db
        editor = world.a["editor"]
        if case == "unknown":
            chat_id = uuid.uuid4()
        else:
            owner = {
                "other-org": world.b["editor"],
                "colleague": world.a["org_admin"],
                "trashed": editor,
            }[case]
            chat_id = _shaped_chat(
                db,
                owner,
                _SHAPES["error-reply"][0],
                deleted_at=_T0 if case == "trashed" else None,
            )
        since = len(db.calls)

        response = _detail(client, editor, chat_id)

        assert (response.status_code, response.json(), _work(db, since)) == (
            404,
            _CHAT_NOT_FOUND,
            ["owner-lookup"],
        )

    def test_chat_detail_retryable_chat_trashed_before_the_retry_target_read_is_the_404(
        self, world: World, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The chat is trashed right after the latest-status read (S15): R1' finds no
        live chat, so the GET answers the 404 ``chat_not_found`` and runs nothing after
        R1' (contract C2)."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _shaped_chat(db, editor, _SHAPES["error-reply"][0])
        original = db.handle

        def handle(method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None) -> Any:
            result = original(method, sql, args, via, tx)
            if norm(sql).startswith("select status from chat_messages"):
                db.chats[chat_id]["deleted_at"] = _T0
                db.chats[chat_id]["trash_group_id"] = chat_id
            return result

        monkeypatch.setattr(db, "handle", handle)
        since = len(db.calls)

        response = _detail(client, editor, chat_id)

        assert (response.status_code, response.json(), _work(db, since)) == (
            404,
            _CHAT_NOT_FOUND,
            ["owner-lookup", "page", "status", "retry-target"],
        )


# ---------------------------------------------------------------------------
# 3. The signal agrees with the retry route (GH-245 Decision 6, GH-302 Decision 2)
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

    @pytest.mark.parametrize("shape", list(_SHAPES))
    def test_chat_detail_retryable_agrees_with_the_retry_for_each_turn_shape(
        self, world: World, tolerant_client: TestClient, shape: str
    ) -> None:
        """GH-302 (contract C1's 22 shapes): ``retryable`` is the shape's C1 result, and
        the retry agrees with it: a chat reported retryable is re-run (200), every other
        answers the 409 ``not_retryable`` (a malformed failed turn too, instead of
        running the model and failing at store time)."""
        rows, retryable = _SHAPES[shape]
        editor = world.a["editor"]
        chat_id = _shaped_chat(world.db, editor, rows)

        reported = _body(_detail(tolerant_client, editor, chat_id)).get("retryable", "missing")
        retried = tolerant_client.post(f"/api/chats/{chat_id}/retry", headers=editor.cookie)

        answer = (retried.status_code, retried.json() if retried.status_code == 409 else None)
        expected = (200, None) if retryable else (409, _NOT_RETRYABLE)
        assert (reported, answer) == (retryable, expected)


# ---------------------------------------------------------------------------
# 4. Another chat's rows inside the failed turn (GH-304 Decision 6, contract C7)
# ---------------------------------------------------------------------------

# One stored row placed in a chat: "mine" (the chat read) or "other" (another chat of
# the same owner and org).
_Placed = tuple[str, _Row]

# The own chat's well-formed failed turn interleaved with the other chat's rows, in
# insertion order (so seq order). Every "other" row strictly inside the own turn's range
# is malformed for the shape check (a user row, a complete no-block reply, a
# limit_reached or a stopped row), so counting it would make the turn not retryable.
_INTERLEAVED: Final[dict[str, list[_Placed]]] = {
    # The reviewer's draft (PR #303): the other chat's complete no-block reply mid-turn.
    "other-chats-complete-reply-mid-turn": [
        ("other", _ASK),
        ("mine", _ASK),
        ("other", _reply("complete")),
        ("mine", _reply("error")),
    ],
    # Before the range, between every own row and after the own latest row.
    "other-chats-rows-on-both-sides-of-a-tool-turn": [
        ("mine", _ASK),
        ("mine", _reply("complete")),
        ("other", _ASK),
        ("mine", _ASK),
        ("other", _reply("complete")),
        ("mine", _reply("complete", _BLOCKS)),
        ("other", _ASK),
        ("mine", _result("complete")),
        ("other", _reply("limit_reached")),
        ("mine", _reply("error")),
        ("other", _reply("complete")),
    ],
    "other-chats-rows-in-a-tool-turn-ending-stopped": [
        ("mine", _ASK),
        ("other", _ASK),
        ("mine", _reply("complete", _BLOCKS)),
        ("other", _reply("complete")),
        ("mine", _result("complete")),
        ("other", _reply("stopped")),
        ("mine", _reply("stopped")),
    ],
}


def _interleaved_chats(db: FakeDb, owner: Account, placed: list[_Placed]) -> uuid.UUID:
    """Two titled chats of ``owner`` seeded row by row in ``placed``'s order (the texts
    of ``_shaped_chat``); the own chat's id."""
    by_side = {
        "mine": db.add_chat(owner.user_id, title="Retry 304", title_source="user"),
        "other": db.add_chat(owner.user_id, title="Other 304", title_source="user"),
    }
    for side, (role, status, blocks) in placed:
        chat_id = by_side[side]
        if role == "user":
            db.add_chat_message(chat_id, "user", "Offerte 304 bitte", status=status)
        elif role == "tool":
            db.add_chat_message(
                chat_id, "tool", "Two emails found.", tool_call_id=_CALL_ID, status=status
            )
        else:
            db.add_chat_message(
                chat_id,
                "assistant",
                "Ich suche die Offerte 304.",
                tool_use_blocks=blocks,
                status=status,
            )
    return by_side["mine"]


class TestChatDetailRetryableInterleaved:
    """Another chat's rows inside the turn's seq range don't change ``retryable``."""

    @pytest.mark.parametrize("case", list(_INTERLEAVED))
    def test_chat_detail_retryable_other_chats_rows_inside_the_turn_keep_it_retryable(
        self, world: World, client: TestClient, case: str
    ) -> None:
        """GH-304 (C7): the own chat's page holds its own rows only (role and status in
        seq order), and ``retryable`` is ``true`` (a JSON bool) though the other chat's
        rows sit between the own turn's user row and its failed latest row."""
        editor = world.a["editor"]
        placed = _INTERLEAVED[case]
        chat_id = _interleaved_chats(world.db, editor, placed)

        body = _body(_detail(client, editor, chat_id))

        own = [(role, status) for side, (role, status, _) in placed if side == "mine"]
        page = [(message["role"], message["status"]) for message in body["messages"]]
        assert (page, body.get("retryable", "missing")) == (own, True)
