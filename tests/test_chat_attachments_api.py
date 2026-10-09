"""HTTP spec of sending files with a chat message (GH-187, contract sections 3.4 and 4 "Send").

The app from ``create_app()`` runs against the FakeDb world of
tests/tenancy_world.py (orgs A and B with an Org Admin, an Editor and a Viewer
each, all with real session cookies). The agent is a stub (the pattern of
tests/test_chat_turns_api.py and tests/test_chat_stream_api.py): its ``run``
binds every call to ``Agent.run``'s signature, records it, plays one delta into
a ``RunStream`` when it gets one, awaits a one-shot ``during`` hook and answers
a final ``AgentResult`` whose history is the history it received plus the
user message plus one assistant reply. Attachment rows are seeded with
``FakeDb.add_attachment``. GH-189 (Decision 7): only a ``ready`` file is sent, and
its derived files are read under the chat's hold, so the sendable files (``_files``)
are seeded ready with their derived files (tests/attachment_derived.py) under a
``tmp_path`` attachments root; the stub's signature has ``Agent.run``'s
``attachments`` keyword (C11).

What is pinned (``POST /api/chats/{chat_id}/messages`` with ``attachment_ids``):
- Success, JSON and SSE: the run happens once, and every listed attachment's
  ``message_id`` is the stored user message's id (not the reply's); a file of
  the chat that isn't listed stays unsent. The send runs exactly one lookup
  (A8'), the turn read (T2', which reads the chat's sent files since GH-189's
  Decision 13) and one link (A9) naming attachments, the link in the
  transaction of the turn's message INSERTs. A message sent while a ``tool_use`` was dangling
  (the turn stores the synthetic cancelled result first) links the user
  message too. A file trashed during the run isn't linked and the turn is
  stored; a chat trashed during the run is the 404 ``chat_not_found`` with
  nothing stored and nothing linked.
- 422 ``{"detail": "Too many files for one message", "reason":
  "too_many_files"}`` for more ids than the platform's ``max_files_per_message``
  (seeded in the settings cache and the platform row), decided before any
  statement naming attachments; exactly the limit is sent.
- A chat the caller can't reach (another org's, a colleague's, a trashed, an
  unknown one) is the 404 ``chat_not_found`` even when the ids are that chat's
  own files, with no statement naming attachments. A listed id of another
  org's, a colleague's or another chat's file of the caller, a trashed file or
  an unknown id is the 404 ``{"detail": "Attachment not found", "reason":
  "attachment_not_found"}`` (one body for all); a file already sent is the 409
  ``{"detail": "Attachment already sent", "reason":
  "attachment_already_sent"}``. Every refusal: no run, no message stored,
  nothing linked; with ``Accept: text/event-stream`` each is the same JSON error.
- Validation: 51 ids, a repeated id and a non-UUID are FastAPI's 422 on the
  ``attachment_ids`` field (``too_long``, the duplicate check's field-level
  error, ``uuid_parsing`` at the index), never echoing the input, with no run
  and no attachment statement.
- No ``attachment_ids`` (left out or ``[]``): the same statements as a send
  without the key, the turn read (T2') the only one naming attachments, and as
  many as before GH-189 (GH-244's budget untouched).
- The legacy ``POST /api/message`` refuses ``attachment_ids`` (422
  ``extra_forbidden``) while the chat route takes them.

New names (``ChatMessageCreate.attachment_ids``, the error bodies) are used
through HTTP only, so the file collects before GH-187 is implemented.

Security notes:
- Owner-private chats and files: another user's or another org's attachment
  answers the same 404 as an unknown id, and nothing of it changes.
- Every id, message and name here is a fixed fake value. No network, no real
  PostgreSQL, no real LLM.
"""

from __future__ import annotations

import inspect
import re
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import attachments, scoped_settings, server
from admino.models import AgentConfig, AgentResult, LLMMessage, PendingConfirmation
from tests.attachment_derived import write_derived
from tests.conftest import default_test_platform_settings
from tests.db_fakes import FakeDb, plain
from tests.tenancy_world import (
    CHAT_NOT_FOUND,
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
    from collections.abc import Awaitable, Callable, Sequence
    from pathlib import Path
    from unittest.mock import MagicMock

    import httpx
    from fastapi.testclient import TestClient

    from tests.db_fakes import Call
    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TOO_MANY_FILES: Final = {"detail": "Too many files for one message", "reason": "too_many_files"}
_ATTACHMENT_NOT_FOUND: Final = {"detail": "Attachment not found", "reason": "attachment_not_found"}
_ALREADY_SENT: Final = {"detail": "Attachment already sent", "reason": "attachment_already_sent"}
_SSE_ACCEPT: Final = {"Accept": "text/event-stream"}
_MESSAGE: Final = "Please read the attached files"
_REPLY: Final = "I have the files."
_UNKNOWN: Final = uuid.UUID("3f2b9c1e-7a4d-4e8f-b6a5-0c1d2e3f4a5b")
_NOT_A_UUID: Final = "attachment-marker-187-heron"
_PAST: Final = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)

_ATTACHMENTS_SQL: Final = re.compile(r"\battachments\b")
_LINK_SQL: Final = re.compile(r"^update attachments set message_id\b")
_MESSAGE_INSERT_SQL: Final = re.compile(r"^insert into chat_messages\b")
# GH-189 (Decision 13): the turn read (T2', chats.load_turn) names attachments too.
_TURN_SQL: Final = re.compile(r"\bfrom chats c left join lateral\b")
# Today's statements of a send without files in a chat without sent files (GH-244).
_STATEMENTS_WITHOUT_FILES: Final = 6


# ---------------------------------------------------------------------------
# The stub agent
# ---------------------------------------------------------------------------


def _run_signature(
    user_message: str,
    session_id: str,
    *,
    history: list[LLMMessage],
    principal: Any,
    tool_policy: Any,
    pending_confirmation: PendingConfirmation | None = None,
    agent_config: AgentConfig | None = None,
    prompt_context: Any = None,
    earlier_external_content: bool = False,
    stream: Any = None,
    attachments: Sequence[Any] = (),
) -> None:
    """``Agent.run``'s signature (GH-189: with ``attachments``); every stub call is bound
    to it."""


class _Script:
    """The stub agent's ``run``: records each call and answers one final reply."""

    def __init__(self) -> None:
        self.runs: list[dict[str, Any]] = []
        # Awaited once, inside the next run, before it answers (then cleared).
        self.during: Callable[[], Awaitable[None]] | None = None

    async def run(self, *args: Any, **kwargs: Any) -> AgentResult:
        bound = inspect.signature(_run_signature).bind(*args, **kwargs)
        bound.apply_defaults()
        arguments = dict(bound.arguments)
        self.runs.append(arguments)
        if arguments["stream"] is not None:
            await arguments["stream"].on_delta(_REPLY)
        during, self.during = self.during, None
        if during is not None:
            await during()
        return AgentResult(
            status="final",
            response=_REPLY,
            history=[
                *arguments["history"],
                LLMMessage(role="user", content=arguments["user_message"]),
                LLMMessage(role="assistant", content=_REPLY),
            ],
            tool_calls=[],
            pending_confirmation=None,
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> World:
    """Orgs A and B (OA/ED/VI each) and a Super Admin, behind the fake database; the
    attachments root is under ``tmp_path`` (GH-189: a sent file's derived files)."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    use_attachment_storage(monkeypatch, built, tmp_path / "attachments")
    return built


@pytest.fixture()
def script() -> _Script:
    return _Script()


@pytest.fixture()
def agent(script: _Script) -> MagicMock:
    """A stub agent whose ``run`` (an AsyncMock) plays ``script``."""
    stub = stub_agent()
    stub.run.side_effect = script.run
    return stub


@pytest.fixture()
def client(world: World, agent: MagicMock) -> TestClient:
    """The app around the stub agent; an escaping exception becomes the app's 500."""
    return make_client(make_app(agent), raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _chat(db: FakeDb, account: Account, **fields: Any) -> uuid.UUID:
    """A user-titled chat of ``account`` (no title step runs after a turn)."""
    return db.add_chat(account.user_id, title="Files 187", title_source="user", **fields)


def _files(db: FakeDb, chat_id: uuid.UUID, count: int) -> list[uuid.UUID]:
    """``count`` unsent, live, ready attachments of the chat (one-page PDFs), each with
    its derived files under ``attachments.attachments_root()`` (GH-189, Decision 7:
    only a ready file is sent, and its derived files must be readable)."""
    chat = db.chat_row(chat_id)
    assert chat is not None
    root = attachments.attachments_root()
    ids: list[uuid.UUID] = []
    for index in range(count):
        file_id = db.add_attachment(
            chat_id,
            created_at=_PAST,
            status="ready",
            page_count=1,
            token_estimate=8,
            derived_bytes=64,
        )
        parts = [("text", f"Page one of file {index}", 1)]
        write_derived(root, plain(chat["org_id"]), file_id, kind="pdf", parts=parts, page_count=1)
        ids.append(file_id)
    return ids


def _send(
    client: TestClient,
    account: Account,
    chat_id: uuid.UUID,
    ids: list[Any] | None,
    *,
    sse: bool = False,
) -> httpx.Response:
    """POST /api/chats/{chat_id}/messages with ``attachment_ids`` (None: the key left out)."""
    body: dict[str, Any] = {"message": _MESSAGE}
    if ids is not None:
        body["attachment_ids"] = [str(value) for value in ids]
    return client.post(
        f"/api/chats/{chat_id}/messages",
        headers={**account.cookie, **(_SSE_ACCEPT if sse else {})},
        json=body,
    )


def _files_limit(monkeypatch: pytest.MonkeyPatch, db: FakeDb, limit: int) -> None:
    """The platform's ``max_files_per_message``: in the settings cache (GH-160) and the row."""
    stored = default_test_platform_settings()
    files = stored.files.model_copy(update={"max_files_per_message": limit})
    monkeypatch.setattr(
        scoped_settings, "_platform_cache", stored.model_copy(update={"files": files})
    )
    row = db.platform_row()
    assert row is not None
    row["max_files_per_message"] = limit


def _linked_to(db: FakeDb, attachment_id: uuid.UUID) -> uuid.UUID | None:
    """The message an attachment is linked to (None: unsent)."""
    row = db.attachment_row(attachment_id)
    assert row is not None
    return None if row["message_id"] is None else plain(row["message_id"])


def _messages(db: FakeDb, chat_id: uuid.UUID) -> list[tuple[str, str]]:
    """The chat's stored messages by seq: (role, content)."""
    return [(row["role"], row["content"]) for row in db.messages_of(chat_id)]


def _user_message_id(db: FakeDb, chat_id: uuid.UUID) -> uuid.UUID:
    """The id of the chat's one stored message with the sent text."""
    (found,) = [
        plain(row["id"])
        for row in db.messages_of(chat_id)
        if (row["role"], row["content"]) == ("user", _MESSAGE)
    ]
    return found


def _calls_since(db: FakeDb, since: int, pattern: re.Pattern[str]) -> list[Call]:
    return [call for call in db.calls[since:] if pattern.search(call.normalized)]


def _event_names(text: str) -> list[str]:
    """The ``event:`` names of an SSE body, in order."""
    return [
        line.split(":", 1)[1].strip()
        for line in re.split(r"\r\n|\r|\n", text)
        if line.startswith("event:")
    ]


def _assert_refused(
    world: World,
    script: _Script,
    chat_id: uuid.UUID,
    rows: dict[uuid.UUID, dict[str, Any] | None],
) -> None:
    """No run, no message stored in the chat, every listed attachment row unchanged."""
    assert script.runs == []
    assert _messages(world.db, chat_id) == []
    assert {attachment_id: world.db.attachment_row(attachment_id) for attachment_id in rows} == (
        rows
    )


def _rows(db: FakeDb, ids: list[uuid.UUID]) -> dict[uuid.UUID, dict[str, Any] | None]:
    return {attachment_id: db.attachment_row(attachment_id) for attachment_id in ids}


# ---------------------------------------------------------------------------
# 1. Success: the stored user message carries the files
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sse", [False, True], ids=["json", "sse"])
def test_chat_attachments_api_send_links_the_files_to_the_stored_user_message(
    world: World, client: TestClient, script: _Script, sse: bool
) -> None:
    """The run happens; both listed files carry the user message's id, the unlisted one
    stays unsent; one lookup, the turn read (T2', GH-189 Decision 13) and one link name
    attachments, the link in the transaction of the turn's message INSERTs."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    first, second, unlisted = _files(db, chat_id, 3)
    since = len(db.calls)

    response = _send(client, editor, chat_id, [first, second], sse=sse)

    assert response.status_code == 200, response.text
    if sse:
        assert response.headers["content-type"].startswith("text/event-stream")
        events = _event_names(response.text)
        assert ("message_saved" in events, events[-1]) == (True, "done")
    else:
        assert response.json()["response"] == _REPLY
    assert len(script.runs) == 1
    assert _messages(db, chat_id) == [("user", _MESSAGE), ("assistant", _REPLY)]
    user_id = _user_message_id(db, chat_id)
    assert [_linked_to(db, file_id) for file_id in (first, second, unlisted)] == [
        user_id,
        user_id,
        None,
    ]
    statements = _calls_since(db, since, _ATTACHMENTS_SQL)
    assert [
        "turn" if _TURN_SQL.search(call.normalized) else call.normalized.split(" ", 1)[0]
        for call in statements
    ] == ["select", "turn", "update"]
    (link,) = _calls_since(db, since, _LINK_SQL)
    inserts = _calls_since(db, since, _MESSAGE_INSERT_SQL)
    assert link.tx is not None
    assert {(call.via, call.tx) for call in inserts} == {(link.via, link.tx)}


def test_chat_attachments_api_send_after_a_dangling_tool_use_links_the_user_message(
    world: World, client: TestClient, script: _Script
) -> None:
    """The chat's last stored message is an unanswered tool_use: the turn stores the
    synthetic cancelled result first, then the user message, which carries the file."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    block = {"type": "tool_use", "id": "call-187-p", "name": "memory.store", "input": {}}
    db.add_chat_message(chat_id, "user", "Store a note")
    db.add_chat_message(
        chat_id, "assistant", "", tool_use_blocks=[block], status="awaiting_confirmation"
    )
    (file_id,) = _files(db, chat_id, 1)

    response = _send(client, editor, chat_id, [file_id])

    assert response.status_code == 200, response.text
    assert _messages(db, chat_id)[2:] == [
        ("tool", server._CANCELLED_TOOL_RESULT_MSG),
        ("user", _MESSAGE),
        ("assistant", _REPLY),
    ]
    assert _linked_to(db, file_id) == _user_message_id(db, chat_id)


def test_chat_attachments_api_file_trashed_during_the_run_is_not_linked(
    world: World, client: TestClient, script: _Script
) -> None:
    """A file trashed after the check (during the run) no longer matches the link: the
    turn is stored and only the other file is linked."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    kept, trashed = _files(db, chat_id, 2)

    async def trash_file() -> None:
        db.attachments[uuid.UUID(int=trashed.int)]["deleted_at"] = datetime.now(UTC)

    script.during = trash_file

    response = _send(client, editor, chat_id, [kept, trashed])

    assert response.status_code == 200, response.text
    assert (_linked_to(db, kept), _linked_to(db, trashed)) == (
        _user_message_id(db, chat_id),
        None,
    )


def test_chat_attachments_api_chat_trashed_during_the_run_links_nothing(
    world: World, client: TestClient, script: _Script
) -> None:
    """The chat goes to the trash during the run: the 404 ``chat_not_found``, no message
    stored, the files unsent."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    ids = _files(db, chat_id, 2)

    async def trash_chat() -> None:
        db.chats[uuid.UUID(int=chat_id.int)]["deleted_at"] = datetime.now(UTC)

    script.during = trash_chat

    response = _send(client, editor, chat_id, ids)

    assert (response.status_code, response.json()) == (404, CHAT_NOT_FOUND)
    assert len(script.runs) == 1
    assert _messages(db, chat_id) == []
    assert [_linked_to(db, file_id) for file_id in ids] == [None, None]


# ---------------------------------------------------------------------------
# 2. Files per message
# ---------------------------------------------------------------------------


def test_chat_attachments_api_more_files_than_the_limit_get_422_before_any_lookup(
    world: World, client: TestClient, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Limit 2: three ids are the 422 ``too_many_files`` before any statement naming
    attachments (no run, nothing stored or linked); exactly two are sent."""
    db = world.db
    _files_limit(monkeypatch, db, 2)
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    ids = _files(db, chat_id, 3)
    rows = _rows(db, ids)
    since = len(db.calls)

    refused = _send(client, editor, chat_id, ids)

    assert (refused.status_code, refused.json()) == (422, _TOO_MANY_FILES)
    assert _calls_since(db, since, _ATTACHMENTS_SQL) == []
    _assert_refused(world, script, chat_id, rows)

    accepted = _send(client, editor, chat_id, ids[:2])

    assert accepted.status_code == 200, accepted.text
    user_id = _user_message_id(db, chat_id)
    assert [_linked_to(db, file_id) for file_id in ids] == [user_id, user_id, None]


# ---------------------------------------------------------------------------
# 3. Refusals: the chat, the files
# ---------------------------------------------------------------------------


def _out_of_reach_chat(world: World, case: str) -> tuple[uuid.UUID, list[uuid.UUID]]:
    """A chat the Editor of org A can't send to, and the ids sent (its own files)."""
    db = world.db
    if case == "unknown":
        return _UNKNOWN, [_UNKNOWN]
    owner = {
        "other-org": world.b["editor"],
        "colleague": world.a["org_admin"],
        "trashed": world.a["editor"],
    }[case]
    chat_id = _chat(db, owner, deleted_at=_PAST if case == "trashed" else None)
    return chat_id, _files(db, chat_id, 1)


@pytest.mark.parametrize("case", ["other-org", "colleague", "trashed", "unknown"])
def test_chat_attachments_api_chat_out_of_reach_is_chat_not_found(
    world: World, client: TestClient, script: _Script, case: str
) -> None:
    """The chat's 404 wins, even with that chat's own files listed: no statement names
    attachments, no run, nothing stored or linked."""
    db = world.db
    chat_id, ids = _out_of_reach_chat(world, case)
    rows = _rows(db, [file_id for file_id in ids if file_id != _UNKNOWN])
    since = len(db.calls)

    response = _send(client, world.a["editor"], chat_id, ids)

    assert (response.status_code, response.json()) == (404, CHAT_NOT_FOUND)
    assert _calls_since(db, since, _ATTACHMENTS_SQL) == []
    assert script.runs == []
    assert _rows(db, list(rows)) == rows
    if case != "unknown":
        assert _messages(db, chat_id) == []


def _file_out_of_reach(world: World, chat_id: uuid.UUID, case: str) -> uuid.UUID:
    """An attachment id the Editor of org A can't send in ``chat_id``."""
    db = world.db
    editor = world.a["editor"]
    if case == "unknown":
        return _UNKNOWN
    if case == "trashed":
        return db.add_attachment(chat_id, created_at=_PAST, deleted_at=_PAST)
    owner_chat = {
        "other-org": _chat(db, world.b["editor"]),
        "colleague": _chat(db, world.a["org_admin"]),
        "other-chat": _chat(db, editor),
    }[case]
    return db.add_attachment(owner_chat, created_at=_PAST)


@pytest.mark.parametrize("case", ["other-org", "colleague", "other-chat", "trashed", "unknown"])
def test_chat_attachments_api_file_out_of_reach_is_attachment_not_found(
    world: World, client: TestClient, script: _Script, case: str
) -> None:
    """One 404 body for another org's file, a colleague's, one of the caller's other
    chat, a trashed one and an unknown id; the sendable file listed beside it stays
    unsent; no run, nothing stored."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    (fresh,) = _files(db, chat_id, 1)
    bad = _file_out_of_reach(world, chat_id, case)
    rows = _rows(db, [fresh] if bad == _UNKNOWN else [fresh, bad])

    response = _send(client, editor, chat_id, [fresh, bad])

    assert (response.status_code, response.json()) == (404, _ATTACHMENT_NOT_FOUND)
    _assert_refused(world, script, chat_id, rows)


def test_chat_attachments_api_file_already_sent_is_409(
    world: World, client: TestClient, script: _Script
) -> None:
    """A file linked to an earlier message: the 409 ``attachment_already_sent``; it keeps
    its message, the other file stays unsent, no run, no new message."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    earlier = db.add_chat_message(chat_id, "user", "Earlier, with the file")
    sent = db.add_attachment(chat_id, created_at=_PAST, message_id=earlier)
    (fresh,) = _files(db, chat_id, 1)
    rows = _rows(db, [fresh, sent])

    response = _send(client, editor, chat_id, [fresh, sent])

    assert (response.status_code, response.json()) == (409, _ALREADY_SENT)
    assert script.runs == []
    assert _messages(db, chat_id) == [("user", "Earlier, with the file")]
    assert _rows(db, [fresh, sent]) == rows
    assert _linked_to(db, sent) == earlier


@pytest.mark.parametrize(
    "refusal", ["too-many-files", "chat-not-found", "attachment-not-found", "already-sent"]
)
def test_chat_attachments_api_sse_refusals_are_the_json_errors(
    world: World,
    client: TestClient,
    script: _Script,
    monkeypatch: pytest.MonkeyPatch,
    refusal: str,
) -> None:
    """With ``Accept: text/event-stream`` every refusal is the same JSON error (status,
    body, content type), with no run and nothing linked."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    (fresh,) = _files(db, chat_id, 1)
    target, ids, expected = chat_id, [fresh], (404, _ATTACHMENT_NOT_FOUND)
    if refusal == "too-many-files":
        _files_limit(monkeypatch, db, 1)
        ids, expected = [fresh, *_files(db, chat_id, 1)], (422, _TOO_MANY_FILES)
    elif refusal == "chat-not-found":
        target, ids = _out_of_reach_chat(world, "colleague")
        expected = (404, CHAT_NOT_FOUND)
    elif refusal == "attachment-not-found":
        ids = [fresh, _UNKNOWN]
    else:
        earlier = db.add_chat_message(chat_id, "user", "Earlier")
        ids = [fresh, db.add_attachment(chat_id, created_at=_PAST, message_id=earlier)]
        expected = (409, _ALREADY_SENT)
    rows = _rows(db, [file_id for file_id in ids if file_id != _UNKNOWN])

    response = _send(client, editor, target, ids, sse=True)

    assert (response.status_code, response.json()) == expected
    assert response.headers["content-type"].startswith("application/json")
    assert script.runs == []
    assert _rows(db, list(rows)) == rows


# ---------------------------------------------------------------------------
# 4. Validation of attachment_ids
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", ["51-ids", "repeated", "not-a-uuid"])
def test_chat_attachments_api_invalid_attachment_ids_get_422_without_echo(
    world: World, client: TestClient, script: _Script, case: str
) -> None:
    """FastAPI's one 422 error on the field (``too_long``; the duplicate check's own
    field-level error; ``uuid_parsing`` at the index); the input isn't echoed; no run,
    no attachment statement."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    (fresh,) = _files(db, chat_id, 1)
    cases: dict[str, list[Any]] = {
        "51-ids": [uuid.UUID(int=index + 1) for index in range(51)],
        "repeated": [fresh, fresh],
        "not-a-uuid": [fresh, _NOT_A_UUID],
    }
    ids = cases[case]
    # The duplicate check's error type is the implementation's (a ValueError gives
    # "value_error"): any field-level refusal but today's "extra_forbidden".
    expected = {
        "51-ids": (["body", "attachment_ids"], "too_long"),
        "repeated": (["body", "attachment_ids"], "<field-level>"),
        "not-a-uuid": (["body", "attachment_ids", "1"], "uuid_parsing"),
    }[case]
    since = len(db.calls)

    response = _send(client, editor, chat_id, ids)

    assert response.status_code == 422
    errors = [
        (error["loc"], "<field-level>" if case == "repeated" else error["type"])
        for error in response.json()["detail"]
        if error["type"] != "extra_forbidden"
    ]
    assert (errors, len(response.json()["detail"])) == ([expected], 1)
    assert _NOT_A_UUID not in response.text
    assert str(fresh) not in response.text
    assert str(uuid.UUID(int=51)) not in response.text
    assert script.runs == []
    assert _calls_since(db, since, _ATTACHMENTS_SQL) == []
    assert _linked_to(db, fresh) is None


# ---------------------------------------------------------------------------
# 5. Sends without files, and the legacy route
# ---------------------------------------------------------------------------


def test_chat_attachments_api_send_without_files_issues_todays_statements(
    world: World, client: TestClient, script: _Script
) -> None:
    """The key left out and ``[]``: both turns run with the same statements, as many as
    before GH-189, the turn read (T2', Decision 13) the only one naming attachments; the
    chats' unsent files stay unsent."""
    db = world.db
    editor = world.a["editor"]
    without, empty = _chat(db, editor), _chat(db, editor)
    files = [*_files(db, without, 1), *_files(db, empty, 1)]
    statements: list[list[str]] = []
    for chat_id, ids in ((without, None), (empty, [])):
        since = len(db.calls)
        response = _send(client, editor, chat_id, ids)
        assert response.status_code == 200, response.text
        statements.append([call.normalized for call in db.calls[since:]])

    assert statements[0] == statements[1]
    assert len(statements[0]) == _STATEMENTS_WITHOUT_FILES
    assert [
        bool(_TURN_SQL.search(sql)) for sql in statements[0] if _ATTACHMENTS_SQL.search(sql)
    ] == [True]
    assert [_linked_to(db, file_id) for file_id in files] == [None, None]
    assert len(script.runs) == 2


def test_chat_attachments_api_only_the_chat_route_takes_attachment_ids(
    world: World, client: TestClient, script: _Script
) -> None:
    """The legacy POST /api/message refuses the key (422 ``extra_forbidden``, no run);
    the same file sent through the chat route is linked."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    (file_id,) = _files(db, chat_id, 1)

    legacy = client.post(
        "/api/message",
        headers=editor.cookie,
        json={"message": _MESSAGE, "session_id": "legacy-187", "attachment_ids": [str(file_id)]},
    )

    assert legacy.status_code == 422
    assert [(error["loc"], error["type"]) for error in legacy.json()["detail"]] == [
        (["body", "attachment_ids"], "extra_forbidden")
    ]
    assert script.runs == []
    assert _linked_to(db, file_id) is None

    sent = _send(client, editor, chat_id, [file_id])

    assert sent.status_code == 200, sent.text
    assert _linked_to(db, file_id) == _user_message_id(db, chat_id)
