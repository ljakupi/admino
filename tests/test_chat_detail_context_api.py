"""HTTP spec of GH-190's reads: ``GET /api/chats/{chat_id}``'s ``context_usage`` and
message ``attachment_ids``, and ``GET /api/attachments/{attachment_id}``'s ``context_report``.

Issue #190, Decisions 1, 4, 7, 8, 12, 13 and 14; contract C1 (``chat_usage``,
``context_report``, ``instructions_tokens``, ``HISTORY_LOAD_LIMIT``), C2
(``ContextUsage``, ``ContextReport``, ``ChatDetailResponse``, ``ChatMessageView``),
C5 (``read_chat_detail``: S2, S9' / S11', S15), C6 (A12) and C11.

The app from ``create_app()`` (a stub agent: none of these routes runs the LLM)
runs against the FakeDb world of tests/tenancy_world.py. The instructions'
estimate is made deterministic by replacing ``admino.context_budget.instructions_tokens``
(the server calls it through the module attribute) with a recorder that answers
``_INSTRUCTIONS``; every other number is computed here from the contract's
formulas with ``admino.tokens.estimate_text_tokens``: a message costs 4 plus its
text plus its tool-call blocks as compact JSON, an attachment its stored
``token_estimate`` (NULL: 0), the budget is ``max_input_tokens`` (the stored
platform value) minus ``ceil(max_input_tokens * safety_margin_percent / 100)``
(config, default 10), the reserved output ``llm.max_response_tokens`` (config).

What is pinned:
- ``GET /api/chats/{chat_id}`` has no ``context`` key (the interim field of #176
  is gone) and has ``context_usage {used, max, percent}``: ``used`` = the
  instructions + the chat's active attachments (sent, live, ready, active:
  excluded, failed, trashed and unsent files don't count) + the history after the
  budget + the reserved output; ``max`` = the budget; ``percent`` = ``used * 100 //
  max`` (rounded down). The history is the chat's latest messages as a turn loads
  them (``max_context_messages``, or 200 without a cap), whole turns, the newest
  that fit (an older turn is never kept after a newer one was dropped); when the
  attachments alone don't fit, the history counts nothing and ``percent`` goes
  above 100. The instructions are estimated from the caller's prompt context and
  their org's tool policy at the server's clock (``server._utc_now``).
- Messages carry ``attachment_ids``: the message's live attachments, excluded ones
  included, trashed ones not, by ``created_at`` then ``id``; ``[]`` otherwise.
- Statements: the owner check (S2) first, then the page (S9' or S11'), the latest
  status (S15), the turn setup (T1) and the turn read (T2'', bound to the load
  limit), and nothing else (no count); a chat the caller can't reach runs the
  owner check only.
- ``GET /api/attachments/{attachment_id}`` of a file ``failed`` with
  ``context_overflow`` adds ``context_report``: the chat's live, ready, active
  files in upload order, then this file, each ``{attachment_id, token_estimate,
  derived_bytes}`` (NULL as 0), with ``attachment_tokens``, ``available_tokens``
  (the budget minus the reserved output, at least 0), ``attachment_bytes`` and
  ``max_bytes`` (``context.max_attachment_mb_per_turn`` MiB); one more statement.
  Any other file has ``context_report`` null and makes no extra statement.

New modules are imported inside fixtures and tests, so the file collects before
GH-190 is implemented.

Security notes: every id, text and name here is a fixed fake value. No network,
no real PostgreSQL, no LLM.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import org_permissions, scoped_settings, server
from admino.config import AppConfig
from admino.server import create_app
from admino.tenancy import TenantContext
from admino.tokens import estimate_text_tokens
from tests.conftest import default_test_platform_settings
from tests.db_fakes import ORG_ID, PUBLIC_URL, FakeDb
from tests.tenancy_world import (
    build_world,
    make_app,
    make_client,
    stub_agent,
    use_attachment_storage,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from pathlib import Path

    import httpx
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_INSTRUCTIONS: Final = 1_000
# make_config()'s llm.max_response_tokens (the config default).
_RESERVED: Final = 4096
_MIB: Final = 1_048_576
# The stored platform max_input_tokens of most tests, and its budget at the 10 % margin.
_MAX_INPUT: Final = 10_000
_BUDGET: Final = 9_000
_FIXED: Final = _INSTRUCTIONS + _RESERVED

_SUMMARY_KEYS: Final = frozenset({"id", "title", "title_source", "created_at", "last_activity_at"})
_DETAIL_KEYS: Final = _SUMMARY_KEYS | {
    "messages",
    "next_cursor",
    "pending_confirmation",
    "confirmation_status",
    "context_usage",
    # GH-245 (Decision 6): whether the chat's latest message failed (retry offered).
    "retryable",
}
_MESSAGE_KEYS: Final = frozenset(
    {
        "id",
        "role",
        "content",
        "tool_call_id",
        "tool_calls",
        "status",
        "created_at",
        "attachment_ids",
    }
)
_CHAT_NOT_FOUND: Final = {"detail": "Chat not found", "reason": "chat_not_found"}

_T0: Final = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
_NOW: Final = datetime(2026, 10, 9, 14, 30, tzinfo=UTC)
_CALL_ID: Final = "call_190_search"
_TOOL_BLOCK: Final[dict[str, Any]] = {
    "type": "tool_use",
    "id": _CALL_ID,
    "name": "gmail.search",
    "input": {"query": "flight to Zurich"},
}

# Statements that aren't the route's work: the session lookup and a settings read.
_NOT_WORK_SQL: Final = re.compile(r"\b(?:sessions|platform_settings)\b")
_OWNER_LOOKUP: Final = re.compile(
    r"select .+ from chats where id = \$1 and org_id = \$2 and owner_user_id = \$3"
    r" and deleted_at is null"
)
_ATTACHMENTS_SQL: Final = re.compile(r"\battachments\b")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    return tmp_path / "attachments"


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, root: Path) -> World:
    """Orgs A and B (OA/ED each) and a Super Admin behind the fake database; the
    stored platform ``max_input_tokens`` is ``_MAX_INPUT`` (cap 20, the test default)."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    use_attachment_storage(monkeypatch, built, root)
    _platform(monkeypatch, db, max_input_tokens=_MAX_INPUT)
    return built


@pytest.fixture()
def instructions(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, Any, Any]]:
    """``admino.context_budget.instructions_tokens`` answers ``_INSTRUCTIONS``; the list
    records each call's (prompt context, tool policy, now)."""
    from admino import context_budget

    calls: list[tuple[Any, Any, Any]] = []

    def fake(context: Any, tool_policy: Any, *, now: datetime) -> int:
        calls.append((context, tool_policy, now))
        return _INSTRUCTIONS

    monkeypatch.setattr(context_budget, "instructions_tokens", fake)
    return calls


@pytest.fixture()
def client(world: World, instructions: list[tuple[Any, Any, Any]]) -> TestClient:
    return make_client(make_app())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _platform(
    monkeypatch: pytest.MonkeyPatch,
    db: FakeDb,
    *,
    max_input_tokens: int | None = None,
    max_context_messages: int | None = None,
) -> None:
    """Store platform ``llm.max_input_tokens`` / ``limits.max_context_messages`` in the
    settings cache (and the row), keeping the rest of the current cache."""
    stored = scoped_settings._platform_cache or default_test_platform_settings()
    update: dict[str, Any] = {}
    row = db.platform_row()
    assert row is not None
    if max_input_tokens is not None:
        update["llm"] = stored.llm.model_copy(update={"max_input_tokens": max_input_tokens})
        row["max_input_tokens"] = max_input_tokens
    if max_context_messages is not None:
        update["limits"] = stored.limits.model_copy(
            update={"max_context_messages": max_context_messages}
        )
        row["max_context_messages"] = max_context_messages
    monkeypatch.setattr(scoped_settings, "_platform_cache", stored.model_copy(update=update))


def _config_app(**context: int) -> FastAPI:
    """The app with ``llm.max_response_tokens`` 1000 and the ``context`` section given."""
    config = AppConfig.model_validate(
        {
            "server": {"host": "127.0.0.1", "port": 8000, "public_url": PUBLIC_URL},
            "llm": {
                "provider": "anthropic",
                "anthropic_model": "claude-sonnet-4-6",
                "max_response_tokens": 1000,
            },
            "context": context,
        }
    )
    return create_app(agent=stub_agent(), config=config)


def _text(tokens: int, letter: str = "x") -> str:
    """An ASCII text without digits whose estimate is exactly ``tokens``."""
    return letter * (4 * tokens)


def _cost(content: str, blocks: list[dict[str, Any]] | None = None) -> int:
    """A message's tokens by the contract's rule: 4 + text + blocks as compact JSON."""
    cost = 4 + estimate_text_tokens(content)
    if blocks:
        cost += estimate_text_tokens(json.dumps(blocks, ensure_ascii=False, separators=(",", ":")))
    return cost


def _chat(db: FakeDb, account: Account, **fields: Any) -> uuid.UUID:
    return db.add_chat(account.user_id, title="Kontext 190", title_source="user", **fields)


def _turn(db: FakeDb, chat_id: uuid.UUID, question: int, answer: int) -> int:
    """Store a user message and its answer of the given estimates; the turn's tokens."""
    db.add_chat_message(chat_id, "user", _text(question, "q"))
    db.add_chat_message(chat_id, "assistant", _text(answer, "a"))
    return _cost(_text(question)) + _cost(_text(answer))


def _file(
    db: FakeDb,
    chat_id: uuid.UUID,
    *,
    created_at: datetime,
    status: str = "ready",
    token_estimate: int | None = None,
    derived_bytes: int | None = None,
    **fields: Any,
) -> uuid.UUID:
    """An attachments row of the chat (no file on disk: nothing here reads one)."""
    return db.add_attachment(
        chat_id,
        filename="Kontextdatei 190.pdf",
        kind="pdf",
        size_bytes=4096,
        status=status,
        page_count=2 if status == "ready" else None,
        token_estimate=token_estimate,
        derived_bytes=derived_bytes,
        created_at=created_at,
        **fields,
    )


def _detail(
    client: TestClient, caller: Account, chat_id: uuid.UUID | str, **params: Any
) -> httpx.Response:
    return client.get(f"/api/chats/{chat_id}", params=params, headers=caller.cookie)


def _usage(response: httpx.Response) -> Any:
    assert response.status_code == 200, response.text
    return response.json().get("context_usage")


def _expected_usage(used: int, budget: int = _BUDGET) -> dict[str, int]:
    return {"used": used, "max": budget, "percent": used * 100 // budget}


def _kind(sql: str) -> str:
    """A detail request's statement: owner-lookup (S2), page (S9' / S11'), status (S15),
    count (S10), turn-setup (T1), turn (T2''), else the SQL itself."""
    if _OWNER_LOOKUP.fullmatch(sql):
        return "owner-lookup"
    if "from chat_messages m" in sql and "as attachment_ids" in sql:
        return "page"
    if sql.startswith("select status from chat_messages"):
        return "status"
    if "count(*)" in sql and "chat_messages" in sql:
        return "count"
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


def _turn_binds(db: FakeDb, since: int) -> list[tuple[Any, ...]]:
    return [call.args for call in db.calls[since:] if _kind(call.normalized) == "turn"]


def _metadata(client: TestClient, caller: Account, file_id: uuid.UUID) -> httpx.Response:
    return client.get(f"/api/attachments/{file_id}", headers=caller.cookie)


# ---------------------------------------------------------------------------
# 1. context_usage replaces the interim context (Decisions 4 and 13)
# ---------------------------------------------------------------------------


class TestChatDetailContextUsage:
    """The chat as its next turn will start, against the budget."""

    def test_chat_detail_context_has_context_usage_and_no_interim_context(
        self, world: World, client: TestClient
    ) -> None:
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        _turn(world.db, chat_id, 3, 4)

        response = _detail(client, editor, chat_id)

        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == _DETAIL_KEYS
        assert "context" not in body
        assert set(body["context_usage"]) == {"used", "max", "percent"}

    def test_chat_detail_context_usage_counts_instructions_history_and_reserved_output(
        self, world: World, client: TestClient, instructions: list[tuple[Any, Any, Any]]
    ) -> None:
        """A tool turn (its call block counted as compact JSON, its result as text) and a
        plain turn, all fitting: used = instructions + history + reserved output."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        question, final = _text(30, "f"), _text(20, "r")
        db.add_chat_message(chat_id, "user", question)
        db.add_chat_message(chat_id, "assistant", "", tool_use_blocks=[_TOOL_BLOCK])
        db.add_chat_message(chat_id, "tool", "One email found.", tool_call_id=_CALL_ID)
        db.add_chat_message(chat_id, "assistant", final)
        plain_turn = _turn(db, chat_id, 10, 12)
        history = (
            _cost(question)
            + _cost("", [_TOOL_BLOCK])
            + _cost("One email found.")
            + _cost(final)
            + plain_turn
        )

        response = _detail(client, editor, chat_id)

        assert _usage(response) == _expected_usage(_FIXED + history)
        assert len(instructions) == 1

    def test_chat_detail_context_usage_of_an_empty_chat_is_instructions_and_reserved_output(
        self, world: World, client: TestClient
    ) -> None:
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)

        response = _detail(client, editor, chat_id)

        assert _usage(response) == _expected_usage(_FIXED)

    def test_chat_detail_context_usage_counts_the_active_attachments_estimates_only(
        self, world: World, client: TestClient
    ) -> None:
        """Of the chat's files only the sent, live, ready, active ones count (a NULL
        estimate as 0); an excluded, a failed, a trashed and an unsent file don't, nor
        does another chat's."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        request = db.add_chat_message(chat_id, "user", _text(10, "q"))
        db.add_chat_message(chat_id, "assistant", _text(10, "a"))
        sent: dict[str, Any] = {"message_id": request}
        _file(db, chat_id, created_at=_T0, token_estimate=700, **sent)
        _file(db, chat_id, created_at=_T0, token_estimate=None, **sent)
        _file(db, chat_id, created_at=_T0, token_estimate=900, active=False, **sent)
        _file(
            db,
            chat_id,
            created_at=_T0,
            status="failed",
            failure_reason="corrupted_file",
            token_estimate=300,
            **sent,
        )
        _file(db, chat_id, created_at=_T0, token_estimate=400, deleted_at=_T0, **sent)
        _file(db, chat_id, created_at=_T0, token_estimate=500)
        other = _chat(db, editor)
        other_request = db.add_chat_message(other, "user", "elsewhere")
        _file(db, other, created_at=_T0, token_estimate=800, message_id=other_request)

        response = _detail(client, editor, chat_id)

        assert _usage(response) == _expected_usage(_FIXED + 700 + 2 * _cost(_text(10)))

    def test_chat_detail_context_usage_history_is_the_latest_max_context_messages(
        self, world: World, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The stored cap 3: only the latest three messages count (a turn loads them)."""
        db = world.db
        _platform(monkeypatch, db, max_context_messages=3)
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        sizes = [(10, 20), (30, 40), (50, 60)]
        for question, answer in sizes:
            _turn(db, chat_id, question, answer)
        latest = _cost(_text(40)) + _cost(_text(50)) + _cost(_text(60))

        response = _detail(client, editor, chat_id)

        assert _usage(response) == _expected_usage(_FIXED + latest)

    def test_chat_detail_context_usage_without_a_cap_reads_the_latest_200_messages(
        self, world: World, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``max_context_messages`` 0 (no cap): the latest 200 of 202 messages count."""
        db = world.db
        _platform(monkeypatch, db, max_context_messages=0)
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        _turn(db, chat_id, 50, 50)
        for _ in range(100):
            _turn(db, chat_id, 1, 1)

        response = _detail(client, editor, chat_id)

        assert _usage(response) == _expected_usage(_FIXED + 200 * _cost(_text(1)))

    @pytest.mark.parametrize(("cap", "limit"), [(3, 3), (0, 200)])
    def test_chat_detail_context_turn_read_is_bound_to_the_load_limit(
        self,
        world: World,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        cap: int,
        limit: int,
    ) -> None:
        """The turn read's limit is ``max_context_messages``, or 200 without a cap."""
        db = world.db
        _platform(monkeypatch, db, max_context_messages=cap)
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        _turn(db, chat_id, 2, 2)
        since = len(db.calls)

        response = _detail(client, editor, chat_id)

        assert response.status_code == 200, response.text
        binds = _turn_binds(db, since)
        assert len(binds) == 1, binds
        assert [str(value) for value in binds[0]] == [
            str(chat_id),
            str(ORG_ID),
            str(editor.user_id),
            str(limit),
        ]

    def test_chat_detail_context_usage_keeps_only_the_newest_turns_that_fit(
        self, world: World, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Budget 5400 (max_input 6000), 304 tokens left after the fixed part: the newest
        turn (100) fits, the one before (250) doesn't, and the oldest (16) isn't kept
        after it although it would fit."""
        db = world.db
        _platform(monkeypatch, db, max_input_tokens=6_000)
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        assert _turn(db, chat_id, 2, 6) == 16
        assert _turn(db, chat_id, 100, 142) == 250
        assert _turn(db, chat_id, 40, 52) == 100

        response = _detail(client, editor, chat_id)

        assert _usage(response) == _expected_usage(_FIXED + 100, 5_400)

    def test_chat_detail_context_usage_percent_is_rounded_down(
        self, world: World, client: TestClient
    ) -> None:
        """used 5176 of 9000 is 57.51 %: the percent is 57 (not 58)."""
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        assert _turn(world.db, chat_id, 36, 36) == 80

        response = _detail(client, editor, chat_id)

        assert _usage(response) == {"used": 5_176, "max": _BUDGET, "percent": 57}

    def test_chat_detail_context_usage_is_above_100_when_the_attachments_alone_dont_fit(
        self, world: World, client: TestClient
    ) -> None:
        """An active file of 6000 tokens: the fixed part (11096) is above the budget, so
        no history counts and the percent is 123."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        request = db.add_chat_message(chat_id, "user", _text(40))
        db.add_chat_message(chat_id, "assistant", _text(40))
        _file(db, chat_id, created_at=_T0, token_estimate=6_000, message_id=request)

        response = _detail(client, editor, chat_id)

        assert _usage(response) == {"used": 11_096, "max": _BUDGET, "percent": 123}

    @pytest.mark.parametrize(
        ("max_input", "budget"), [(1_000, 900), (_MAX_INPUT, _BUDGET), (200_000, 180_000)]
    )
    def test_chat_detail_context_usage_max_is_the_stored_max_input_tokens_budget(
        self,
        world: World,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        max_input: int,
        budget: int,
    ) -> None:
        _platform(monkeypatch, world.db, max_input_tokens=max_input)
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)

        response = _detail(client, editor, chat_id)

        assert _usage(response) == _expected_usage(_FIXED, budget)

    def test_chat_detail_context_usage_uses_the_configs_margin_and_reserved_output(
        self,
        world: World,
        monkeypatch: pytest.MonkeyPatch,
        instructions: list[tuple[Any, Any, Any]],
    ) -> None:
        """``context.safety_margin_percent`` 25 (rounded up: 10001 keeps 7500) and
        ``llm.max_response_tokens`` 1000 from the config."""
        _platform(monkeypatch, world.db, max_input_tokens=10_001)
        client = make_client(_config_app(safety_margin_percent=25))
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)

        response = _detail(client, editor, chat_id)

        assert _usage(response) == _expected_usage(_INSTRUCTIONS + 1_000, 7_500)

    def test_chat_detail_context_instructions_get_the_callers_context_policy_and_clock(
        self,
        world: World,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        instructions: list[tuple[Any, Any, Any]],
    ) -> None:
        """One estimate of the caller's prompt context (their org's instructions) and
        their org's tool policy, at ``server._utc_now()``."""
        db = world.db
        assert db.org_settings_row(ORG_ID) is not None
        db.org_settings[ORG_ID]["instructions"] = "Antworte immer auf Deutsch, 190."
        monkeypatch.setattr(server, "_utc_now", lambda: _NOW)
        editor = world.a["editor"]
        tenant = TenantContext(org_id=ORG_ID, user_id=editor.user_id, role="editor")
        expected_context = asyncio.run(scoped_settings.load_prompt_context(db.pool, tenant))
        expected_policy = asyncio.run(org_permissions.load_tool_policy(db.pool, tenant))
        chat_id = _chat(db, editor)

        response = _detail(client, editor, chat_id)

        assert response.status_code == 200, response.text
        assert instructions == [(expected_context, expected_policy, _NOW)]
        assert expected_context.org_instructions == "Antworte immer auf Deutsch, 190."


# ---------------------------------------------------------------------------
# 2. Messages carry their attachment ids (Decision 12)
# ---------------------------------------------------------------------------


class TestChatDetailAttachmentIds:
    """Each message lists its live files, excluded ones too, by created_at then id."""

    def test_chat_detail_messages_carry_their_live_attachment_ids(
        self, world: World, client: TestClient
    ) -> None:
        """A user message with an excluded file, an active one, two tied on created_at and
        a trashed one: its ids are the four live ones in (created_at, id) order; the
        answer and a message without files have ``[]``."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        request = db.add_chat_message(chat_id, "user", "Four files")
        db.add_chat_message(chat_id, "assistant", "Read them.")
        db.add_chat_message(chat_id, "user", "No files now")
        later = _T0 + timedelta(minutes=2)
        active = _file(db, chat_id, created_at=_T0 + timedelta(minutes=1), message_id=request)
        excluded = _file(db, chat_id, created_at=_T0, active=False, message_id=request)
        tied = sorted(_file(db, chat_id, created_at=later, message_id=request) for _ in range(2))
        _file(db, chat_id, created_at=_T0, deleted_at=later, message_id=request)

        response = _detail(client, editor, chat_id)

        assert response.status_code == 200, response.text
        messages = response.json()["messages"]
        assert all(set(message) == _MESSAGE_KEYS for message in messages)
        assert [message["attachment_ids"] for message in messages] == [
            [str(excluded), str(active), *(str(file_id) for file_id in tied)],
            [],
            [],
        ]
        assert messages[0]["id"] == str(request)


# ---------------------------------------------------------------------------
# 3. Statements (Decisions 13 and 14)
# ---------------------------------------------------------------------------


class TestChatDetailStatements:
    """The owner check first, the page, the latest status, the setup and the turn read."""

    @pytest.mark.parametrize("page", ["latest", "cursor"])
    def test_chat_detail_runs_owner_check_page_status_setup_and_turn_read_only(
        self, world: World, client: TestClient, page: str
    ) -> None:
        """Exactly S2, S9' (or S11' on a cursor page), S15, T1 and T2'', in this order: no
        message count, nothing else."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        _turn(db, chat_id, 3, 3)
        _turn(db, chat_id, 3, 3)
        params: dict[str, Any] = {}
        if page == "cursor":
            latest = _detail(client, editor, chat_id, limit=1)
            assert latest.status_code == 200, latest.text
            params = {"limit": 1, "cursor": latest.json()["next_cursor"]}
        since = len(db.calls)

        response = _detail(client, editor, chat_id, **params)

        assert response.status_code == 200, response.text
        assert _work(db, since) == ["owner-lookup", "page", "status", "turn-setup", "turn"]

    @pytest.mark.parametrize("case", ["other-org", "colleague", "trashed", "unknown"])
    def test_chat_detail_unreachable_chat_runs_only_the_owner_check(
        self,
        world: World,
        client: TestClient,
        instructions: list[tuple[Any, Any, Any]],
        case: str,
    ) -> None:
        """Another org's, a colleague's, a trashed and an unknown chat: the 404 after the
        owner check alone, and no estimate."""
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
            chat_id = _chat(db, owner, deleted_at=_T0 if case == "trashed" else None)
            _turn(db, chat_id, 2, 2)
        since = len(db.calls)

        response = _detail(client, editor, chat_id)

        assert (response.status_code, response.json()) == (404, _CHAT_NOT_FOUND)
        assert _work(db, since) == ["owner-lookup"]
        assert instructions == []


# ---------------------------------------------------------------------------
# 4. GET /api/attachments/{attachment_id}: context_report (Decision 7)
# ---------------------------------------------------------------------------


def _report_item(file_id: uuid.UUID, tokens: int, size: int) -> dict[str, Any]:
    return {"attachment_id": str(file_id), "token_estimate": tokens, "derived_bytes": size}


class TestAttachmentContextReport:
    """A file refused for the context shows the report; any other file doesn't."""

    def test_chat_detail_context_report_of_a_context_overflow_file(
        self, world: World, client: TestClient
    ) -> None:
        """The chat's live, ready, active files (sent or not) in upload order, then the
        refused file itself (NULLs as 0); not an excluded, trashed, failed, processing or
        another chat's file. available_tokens 9000 - 4096, max_bytes 64 MiB; A6 and one
        more statement (A12)."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        request = db.add_chat_message(chat_id, "user", "Files")
        at = [_T0 + timedelta(minutes=minute) for minute in range(9)]
        refused = _file(
            db,
            chat_id,
            created_at=at[0],
            status="failed",
            failure_reason="context_overflow",
            token_estimate=9_000,
        )
        unsent = _file(db, chat_id, created_at=at[1], token_estimate=1_500)
        sent = _file(
            db,
            chat_id,
            created_at=at[2],
            token_estimate=3_000,
            derived_bytes=1_000,
            message_id=request,
        )
        no_estimate = _file(db, chat_id, created_at=at[3], derived_bytes=200)
        _file(db, chat_id, created_at=at[4], token_estimate=999, derived_bytes=9, active=False)
        _file(db, chat_id, created_at=at[5], token_estimate=777, deleted_at=at[8])
        _file(db, chat_id, created_at=at[6], status="failed", failure_reason="corrupted_file")
        _file(db, chat_id, created_at=at[7], status="processing")
        _file(db, _chat(db, editor), created_at=at[1], token_estimate=4_444, derived_bytes=44)
        since = len(db.calls)

        response = _metadata(client, editor, refused)

        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["status"], body["failure_reason"], body["token_estimate"]) == (
            "failed",
            "context_overflow",
            9_000,
        )
        assert body["context_report"] == {
            "attachments": [
                _report_item(unsent, 1_500, 0),
                _report_item(sent, 3_000, 1_000),
                _report_item(no_estimate, 0, 200),
                _report_item(refused, 9_000, 0),
            ],
            "attachment_tokens": 13_500,
            "available_tokens": _BUDGET - _RESERVED,
            "attachment_bytes": 1_200,
            "max_bytes": 64 * _MIB,
        }
        assert (
            len([call for call in db.calls[since:] if _ATTACHMENTS_SQL.search(call.normalized)])
            == 2
        )

    @pytest.mark.parametrize(
        ("app_case", "max_input", "available", "max_bytes"),
        [
            pytest.param("config", 10_001, 7_500 - 1_000, 2 * _MIB, id="config-values"),
            pytest.param("default", 1_000, 0, 64 * _MIB, id="budget-below-reserved"),
        ],
    )
    def test_chat_detail_context_report_limits_come_from_the_platform_and_the_config(
        self,
        world: World,
        monkeypatch: pytest.MonkeyPatch,
        instructions: list[tuple[Any, Any, Any]],
        app_case: str,
        max_input: int,
        available: int,
        max_bytes: int,
    ) -> None:
        """``available_tokens`` is the stored ``max_input_tokens``'s budget at the config's
        margin minus the config's reserved output (at least 0); ``max_bytes`` the config's
        ``max_attachment_mb_per_turn`` MiB."""
        _platform(monkeypatch, world.db, max_input_tokens=max_input)
        app = (
            _config_app(safety_margin_percent=25, max_attachment_mb_per_turn=2)
            if app_case == "config"
            else make_app()
        )
        client = make_client(app)
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        refused = _file(
            world.db,
            chat_id,
            created_at=_T0,
            status="failed",
            failure_reason="context_overflow",
            token_estimate=7_777,
        )

        response = _metadata(client, editor, refused)

        assert response.status_code == 200, response.text
        report = response.json()["context_report"]
        assert report is not None
        assert (report["available_tokens"], report["max_bytes"]) == (available, max_bytes)

    @pytest.mark.parametrize(
        "case", ["uploaded", "processing", "ready", "ready-excluded", "failed-corrupted"]
    )
    def test_chat_detail_context_report_is_null_for_any_other_file(
        self, world: World, client: TestClient, case: str
    ) -> None:
        """Every file but a context_overflow failure: ``context_report`` null (the key is
        there) and only the attachment's own read (A6) on attachments."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        _file(db, chat_id, created_at=_T0, token_estimate=100)
        fields: dict[str, Any] = {}
        status = case
        if case == "ready-excluded":
            status, fields = "ready", {"active": False}
        elif case == "failed-corrupted":
            status, fields = "failed", {"failure_reason": "corrupted_file"}
        file_id = _file(
            db,
            chat_id,
            created_at=_T0 + timedelta(minutes=1),
            status=status,
            token_estimate=50 if status == "ready" else None,
            **fields,
        )
        since = len(db.calls)

        response = _metadata(client, editor, file_id)

        assert response.status_code == 200, response.text
        body = response.json()
        assert "context_report" in body
        assert body["context_report"] is None
        on_attachments = [
            call for call in db.calls[since:] if _ATTACHMENTS_SQL.search(call.normalized)
        ]
        assert len(on_attachments) == 1, [call.normalized for call in on_attachments]
