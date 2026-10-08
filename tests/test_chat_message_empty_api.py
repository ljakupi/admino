"""HTTP spec of blank chat messages (GH-286, Decisions 2 to 4).

The app from ``create_app()`` runs against the FakeDb world of
tests/tenancy_world.py (orgs A and B with an Org Admin, an Editor and a Viewer
each, plus a Super Admin, all with real session cookies). The agent is the stub
of tests/test_chat_attachments_api.py (``_Script``): it binds every call to
``Agent.run``'s signature, records it and answers one final reply whose history
is the history it received plus the user message plus the reply.

What is pinned:
- Blank means ``message.strip() == ""`` (Python's ``str.strip``): the empty
  string, spaces, tab and line feed, U+00A0, U+3000, U+2028, U+001C, U+0085 and
  a run of 4000 spaces (the stored ``max_message_length``) are blank. A
  message holding anything else (a zero-width space U+200B, a padded word) is
  not blank: it runs, and the agent and the stored user message get it exactly
  as typed, never trimmed.
- ``POST /api/chats/{chat_id}/messages`` without files (``attachment_ids``
  absent or ``[]``) and the legacy ``POST /api/message`` refuse a blank message
  with the 422 ``{"detail": "Message is empty", "reason": "message_empty"}``
  (fixed text, the input never echoed), as JSON also with ``Accept:
  text/event-stream``. Nothing happens: no statement but the session lookup
  (no chat read, created or titled), nothing stored or changed in any table
  (no audit row), nothing in the chat runtime, no agent run, and no log record
  beyond the ones a body-validation 422 of the same route logs, none of them
  holding the text.
- The order: 401 without a session, the Viewer's and the Super Admin's 403
  and the CSRF 403 come first; then body validation (an unknown key, more than
  32768 characters, a repeated attachment id: the usual 422 list, which no
  longer names ``message`` for ``""``); then the per-user ``/api/message``
  rate limit (a 429 comes before ``message_empty``, and the refused blank
  message spends the bucket); then ``message_empty``.
- The check comes before the chat lookup: another org's, a colleague's, a
  trashed and an unknown chat id get the identical 422.
- A blank message (``""`` or whitespace only) with at least one attachment id
  is accepted: it runs, the file is linked to the stored user message and the
  text is stored and passed to the agent as sent (the provider gets the blank
  text alone until #189). ``too_many_files``, ``attachment_not_found`` and
  ``attachment_already_sent`` apply to it as today.
- Both operations document the 422 in OpenAPI: the description names
  ``message_empty`` next to the validation error and the body is the example;
  the chat route keeps its ``text/event-stream`` 200.
- ``docs/configuration.md`` names ``message_empty`` in its Chats section.

New behaviour is reached through HTTP only, so the file collects before GH-286
is implemented and each test fails on its own.

Security notes:
- A refusal before the chat lookup can't tell whether a chat exists.
- Every id, message and name here is a fixed fake value. No network, no real
  PostgreSQL, no real LLM.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import server
from tests.db_fakes import FakeDb, plain
from tests.tenancy_world import (
    FORBIDDEN,
    UNAUTHORIZED,
    build_world,
    chat_runtime_state,
    make_app,
    make_client,
    seed_chat,
    stub_agent,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)
from tests.test_chat_attachments_api import _files, _files_limit, _linked_to, _messages, _Script

if TYPE_CHECKING:
    from unittest.mock import MagicMock

    import httpx
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EMPTY: Final = {"detail": "Message is empty", "reason": "message_empty"}
_CSRF_REFUSED: Final = {"detail": "Cross-origin request refused"}
_RATE_LIMITED: Final = {"detail": "Rate limit exceeded"}
_TOO_MANY_FILES: Final = {"detail": "Too many files for one message", "reason": "too_many_files"}
_ATTACHMENT_NOT_FOUND: Final = {"detail": "Attachment not found", "reason": "attachment_not_found"}
_ALREADY_SENT: Final = {"detail": "Attachment already sent", "reason": "attachment_already_sent"}
_SSE_ACCEPT: Final = {"Accept": "text/event-stream"}
_CROSS_SITE: Final = {"Sec-Fetch-Site": "cross-site"}
_CHAT_PATH: Final = "/api/chats/{chat_id}/messages"
_LEGACY_PATH: Final = "/api/message"
_LEGACY_SESSION: Final = "legacy-286-plover"
_TEXT: Final = "Summarise the plover survey"
_REPLY: Final = "I have the files."
_UNKNOWN: Final = uuid.UUID("5b0e6c2a-9d41-4f7e-8a3c-2e1f0d9c8b7a")
_PAST: Final = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
_ROUTES: Final = ("chat", "legacy")

# Blank: str.strip() leaves nothing (Decision 2). Built with chr() so every code point
# is explicit in the source.
_BLANKS: Final[tuple[tuple[str, str], ...]] = (
    ("empty", ""),
    ("space", " "),
    ("tab-line-feed", chr(0x09) + chr(0x0A)),
    ("no-break-space", chr(0xA0)),
    ("ideographic-space", chr(0x3000)),
    ("line-separator", chr(0x2028)),
    ("file-separator", chr(0x1C)),
    ("next-line", chr(0x85)),
    ("4000-spaces", " " * 4000),
)
# Not blank: sent exactly as typed, never trimmed.
_NOT_BLANKS: Final[tuple[tuple[str, str], ...]] = (
    ("zero-width-space", chr(0x200B)),
    ("padded-word", " hi "),
)
# A blank message no log line could hold by chance (the log scan's needle).
_TELLTALE: Final = (
    chr(0x2029) + chr(0x3000) + chr(0x1F) + chr(0x85) + chr(0x205F) + chr(0x2007) + chr(0xA0)
)

# What require_session runs for every request: the session lookup and the
# last_seen_at refresh. Anything else is the route's own database work.
_SESSION_SQL: Final = re.compile(
    r"\bfrom sessions s join users u\b|^update sessions set last_seen_at\b"
)
# The attributes every LogRecord has; anything else came in through ``extra=``.
_STANDARD_RECORD_ATTRS: Final = frozenset(
    vars(logging.LogRecord("n", logging.INFO, "p", 1, "m", None, None))
) | {"message", "asctime"}


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
    return db.add_chat(account.user_id, title="Plovers 286", title_source="user", **fields)


def _post(
    client: TestClient,
    route: str,
    account: Account | None,
    message: str,
    *,
    chat_id: uuid.UUID,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
) -> httpx.Response:
    """POST ``message`` on ``route``: "chat" to ``chat_id``'s messages, "legacy" to
    /api/message with ``_LEGACY_SESSION`` (``chat_id`` unused). ``body`` adds keys; no
    account sends no session cookie."""
    if route == "chat":
        url = _CHAT_PATH.format(chat_id=chat_id)
        payload: dict[str, Any] = {"message": message}
    else:
        url = _LEGACY_PATH
        payload = {"message": message, "session_id": _LEGACY_SESSION}
    cookie = account.cookie if account is not None else {}
    return client.post(url, headers={**cookie, **(headers or {})}, json={**payload, **(body or {})})


def _outcome(response: httpx.Response) -> tuple[int, Any, bool]:
    """(status, JSON body, whether the answer is JSON)."""
    content_type = response.headers.get("content-type", "")
    body = response.json() if content_type.startswith("application/json") else response.text
    return response.status_code, body, content_type.startswith("application/json")


def _route_statements(db: FakeDb, since: int) -> list[str]:
    """The statements after the first ``since`` calls other than the session lookup."""
    return [
        call.normalized for call in db.calls[since:] if not _SESSION_SQL.search(call.normalized)
    ]


def _state(world: World) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Every table and what the chat runtime holds."""
    return world.db.snapshot(), chat_runtime_state(world.db)


def _errors(response: httpx.Response) -> tuple[int, list[tuple[tuple[str, ...], str]]]:
    """A validation 422 as (status, [(loc, type)]); any other answer as (status, [])."""
    detail = response.json().get("detail")
    if not isinstance(detail, list):
        return response.status_code, []
    return response.status_code, [(tuple(error["loc"]), error["type"]) for error in detail]


def _user_message_id(db: FakeDb, chat_id: uuid.UUID) -> uuid.UUID:
    """The id of the chat's one stored user message."""
    (found,) = [plain(row["id"]) for row in db.messages_of(chat_id) if row["role"] == "user"]
    return found


def _app_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """Every captured app record: not the client's httpx lines (they name request URLs)
    and not the client's event loop setup (``asyncio``'s "Using selector")."""
    return [
        record
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore", "asyncio"))
    ]


def _shape(records: list[logging.LogRecord]) -> list[tuple[str, int, str]]:
    """Each record's logger, level and message template (never its values)."""
    return [(record.name, record.levelno, str(record.msg)) for record in records]


def _record_text(record: logging.LogRecord) -> str:
    """Everything a record carries: the message, its arguments, exception and stack
    text, and every ``extra=`` attribute."""
    parts = [str(record.msg), record.getMessage(), repr(record.args)]
    if record.exc_info:
        parts.append(logging.Formatter().formatException(record.exc_info))
    parts.extend(str(value) for value in (record.exc_text, record.stack_info) if value)
    parts.extend(
        repr(value) for key, value in vars(record).items() if key not in _STANDARD_RECORD_ATTRS
    )
    return "\n".join(parts)


def _holding(records: list[logging.LogRecord], text: str) -> list[str]:
    """The records holding ``text`` raw, JSON-escaped or as its repr / ascii escapes."""
    forms = {text, json.dumps(text)[1:-1], repr(text)[1:-1], ascii(text)[1:-1]}
    return [
        record.getMessage()
        for record in records
        if any(form in _record_text(record) for form in forms)
    ]


# ---------------------------------------------------------------------------
# 1. What is blank, on both routes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", _ROUTES)
@pytest.mark.parametrize("text", [text for _, text in _BLANKS], ids=[name for name, _ in _BLANKS])
def test_chat_message_empty_blank_message_without_files_is_422_message_empty(
    world: World, client: TestClient, script: _Script, route: str, text: str
) -> None:
    """Every blank text (``str.strip()`` leaves nothing) on both routes: the 422
    ``message_empty`` as JSON, no statement but the session lookup, no run."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    since = len(db.calls)

    response = _post(client, route, editor, text, chat_id=chat_id)

    assert (_outcome(response), _route_statements(db, since), script.runs) == (
        (422, _EMPTY, True),
        [],
        [],
    )


@pytest.mark.parametrize("route", _ROUTES)
@pytest.mark.parametrize(
    "text", [text for _, text in _NOT_BLANKS], ids=[name for name, _ in _NOT_BLANKS]
)
def test_chat_message_empty_not_blank_message_runs_exactly_as_typed(
    world: World, client: TestClient, script: _Script, route: str, text: str
) -> None:
    """A space alone is ``message_empty``; a zero-width space or a padded word is not
    blank: it runs once, and the agent and the stored user message get it untrimmed."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)

    blank = _post(client, route, editor, " ", chat_id=chat_id)
    sent = _post(client, route, editor, text, chat_id=chat_id)

    assert (_outcome(blank), sent.status_code) == ((422, _EMPTY, True), 200), sent.text
    stored_chat = uuid.UUID(sent.json()["chat_id"])
    assert ([run["user_message"] for run in script.runs], _messages(db, stored_chat)) == (
        [text],
        [("user", text), ("assistant", _REPLY)],
    )


# ---------------------------------------------------------------------------
# 2. A refusal does nothing
# ---------------------------------------------------------------------------

# (route, the blank text, extra body keys, extra headers, a stored legacy chat first)
_NOTHING_CASES: Final[dict[str, tuple[str, str, dict[str, Any], dict[str, str], bool]]] = {
    "chat-no-attachment-ids": ("chat", "", {}, {}, False),
    "chat-empty-attachment-ids": ("chat", " ", {"attachment_ids": []}, {}, False),
    "chat-event-stream": ("chat", " ", {}, _SSE_ACCEPT, False),
    "chat-event-stream-empty-ids": ("chat", "", {"attachment_ids": []}, _SSE_ACCEPT, False),
    "legacy-new-session": ("legacy", " ", {}, {}, False),
    "legacy-stored-chat": ("legacy", "", {}, {}, True),
    "legacy-event-stream": ("legacy", " ", {}, _SSE_ACCEPT, True),
}


@pytest.mark.parametrize("case", list(_NOTHING_CASES))
def test_chat_message_empty_refusal_reads_writes_and_runs_nothing(
    world: World, client: TestClient, script: _Script, case: str
) -> None:
    """The JSON 422 ``message_empty`` (also for ``Accept: text/event-stream``), with no
    statement but the session lookup: no chat read, created (a new legacy session id
    gets no chat) or titled, every table unchanged (no message, no audit row), the chat
    runtime unchanged, no run."""
    route, text, body, headers, legacy_chat = _NOTHING_CASES[case]
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    if legacy_chat:
        seed_chat(
            db,
            editor,
            title="Legacy 286",
            messages=[("user", "Earlier")],
            legacy_session_id=_LEGACY_SESSION,
        )
    before = _state(world)
    since = len(db.calls)

    response = _post(client, route, editor, text, chat_id=chat_id, headers=headers, body=body)

    assert _outcome(response) == (422, _EMPTY, True)
    assert (_route_statements(db, since), script.runs) == ([], [])
    assert _state(world) == before


@pytest.mark.parametrize("route", _ROUTES)
def test_chat_message_empty_refusal_logs_only_what_a_validation_422_logs(
    world: World,
    client: TestClient,
    script: _Script,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    """Every logger at DEBUG: the refusal logs the same records (logger, level,
    template) as the route's body-validation 422 (an unknown key) and no record holds
    the blank text in any form, its arguments or ``extra=`` fields included."""
    caplog.set_level(logging.DEBUG)
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)

    caplog.clear()
    reference = _post(client, route, editor, _TEXT, chat_id=chat_id, body={"smuggled": 1})
    expected = _shape(_app_records(caplog))
    caplog.clear()
    response = _post(client, route, editor, _TELLTALE, chat_id=chat_id)
    records = _app_records(caplog)

    assert (reference.status_code, expected != []) == (422, True)
    assert (_outcome(response), _shape(records), _holding(records, _TELLTALE)) == (
        (422, _EMPTY, True),
        expected,
        [],
    )
    assert script.runs == []


# ---------------------------------------------------------------------------
# 3. The order: authentication, role and CSRF; body validation; rate limit
# ---------------------------------------------------------------------------

_FIRST_REFUSALS: Final[dict[str, tuple[int, dict[str, str]]]] = {
    "no-session": (401, UNAUTHORIZED),
    "viewer": (403, FORBIDDEN),
    "super-admin": (403, FORBIDDEN),
    "cross-site": (403, _CSRF_REFUSED),
}


@pytest.mark.parametrize("case", list(_FIRST_REFUSALS))
@pytest.mark.parametrize("route", _ROUTES)
def test_chat_message_empty_auth_role_and_csrf_refusals_come_first(
    world: World, client: TestClient, script: _Script, route: str, case: str
) -> None:
    """A blank message without a session, from a Viewer or the Super Admin, or
    cross-site gets that refusal (no route statement, nothing changed); the Editor's
    same blank message is then ``message_empty``."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    sender: Account | None = {
        "no-session": None,
        "viewer": world.a["viewer"],
        "super-admin": world.super_admin,
        "cross-site": editor,
    }[case]
    headers = _CROSS_SITE if case == "cross-site" else {}
    before = _state(world)
    since = len(db.calls)

    refused = _post(client, route, sender, " ", chat_id=chat_id, headers=headers)

    assert (refused.status_code, refused.json()) == _FIRST_REFUSALS[case]
    assert (_route_statements(db, since), script.runs, _state(world)) == ([], [], before)
    control = _post(client, route, editor, " ", chat_id=chat_id)
    assert _outcome(control) == (422, _EMPTY, True)


@pytest.mark.parametrize("route", _ROUTES)
def test_chat_message_empty_body_validation_comes_before_message_empty(
    world: World, client: TestClient, script: _Script, route: str
) -> None:
    """A blank message with an unknown key, more than 32768 spaces or (chat route) a
    repeated attachment id gets the usual 422 list naming only that field; ``""`` is
    no longer a validation error. No route statement, no run."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    cases: dict[str, tuple[str, dict[str, Any]]] = {
        "unknown-key": ("", {"smuggled": 1}),
        "too-long": (" " * 32769, {}),
    }
    expected: dict[str, tuple[int, list[tuple[tuple[str, ...], str]]]] = {
        "unknown-key": (422, [(("body", "smuggled"), "extra_forbidden")]),
        "too-long": (422, [(("body", "message"), "string_too_long")]),
    }
    if route == "chat":
        cases["repeated-id"] = ("", {"attachment_ids": [str(_UNKNOWN), str(_UNKNOWN)]})
        expected["repeated-id"] = (422, [(("body", "attachment_ids"), "value_error")])
    since = len(db.calls)

    found = {
        name: _errors(_post(client, route, editor, text, chat_id=chat_id, body=body))
        for name, (text, body) in cases.items()
    }

    assert found == expected
    assert (_route_statements(db, since), script.runs) == ([], [])


@pytest.mark.parametrize("route", _ROUTES)
def test_chat_message_empty_refusal_spends_the_rate_bucket_and_429_comes_first(
    world: World,
    client: TestClient,
    script: _Script,
    monkeypatch: pytest.MonkeyPatch,
    route: str,
) -> None:
    """``/api/message`` with burst 1 and no refill to speak of: the blank message is
    ``message_empty`` and spends the token, so the next blank message is the 429 (not
    ``message_empty``) and so is a valid one; nothing runs."""
    monkeypatch.setitem(server._RATE_LIMITS, "/api/message", (0.0001, 1))
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)

    first = _post(client, route, editor, " ", chat_id=chat_id)
    second = _post(client, route, editor, " ", chat_id=chat_id)
    valid = _post(client, route, editor, _TEXT, chat_id=chat_id)

    assert [_outcome(response) for response in (first, second, valid)] == [
        (422, _EMPTY, True),
        (429, _RATE_LIMITED, True),
        (429, _RATE_LIMITED, True),
    ]
    assert script.runs == []


# ---------------------------------------------------------------------------
# 4. Before the chat lookup: every chat id gets the same answer
# ---------------------------------------------------------------------------


def _unreachable_chat(world: World, case: str) -> uuid.UUID:
    """A chat id the Editor of org A can't reach."""
    db = world.db
    if case == "unknown":
        return _UNKNOWN
    if case == "trashed":
        return _chat(db, world.a["editor"], deleted_at=_PAST)
    owner = world.b["editor"] if case == "other-org" else world.a["org_admin"]
    return _chat(db, owner)


@pytest.mark.parametrize("case", ["other-org", "colleague", "trashed", "unknown"])
def test_chat_message_empty_unreachable_chat_gets_the_identical_422(
    world: World, client: TestClient, script: _Script, case: str
) -> None:
    """Another org's, a colleague's, a trashed and an unknown chat id: the same 422
    ``message_empty`` as the caller's own chat, no route statement, nothing changed."""
    db = world.db
    editor = world.a["editor"]
    own = _post(client, "chat", editor, " ", chat_id=_chat(db, editor))
    chat_id = _unreachable_chat(world, case)
    before = _state(world)
    since = len(db.calls)

    response = _post(client, "chat", editor, " ", chat_id=chat_id)

    assert (_outcome(response), _outcome(own)) == ((422, _EMPTY, True), (422, _EMPTY, True))
    assert (_route_statements(db, since), script.runs, _state(world)) == ([], [], before)


# ---------------------------------------------------------------------------
# 5. A blank message with files is accepted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    ["", " " + chr(0x09) + chr(0x0A) + chr(0x3000)],
    ids=["empty", "whitespace-only"],
)
def test_chat_message_empty_blank_message_with_a_file_runs_and_links_it(
    world: World, client: TestClient, script: _Script, text: str
) -> None:
    """Without files the blank text is ``message_empty``; with one attachment id it
    runs once with the text as sent, the stored user message holds that text and the
    file is linked to it."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    (file_id,) = _files(db, chat_id, 1)

    alone = _post(client, "chat", editor, text, chat_id=chat_id)
    sent = _post(
        client, "chat", editor, text, chat_id=chat_id, body={"attachment_ids": [str(file_id)]}
    )

    assert (_outcome(alone), sent.status_code) == ((422, _EMPTY, True), 200), sent.text
    assert ([run["user_message"] for run in script.runs], _messages(db, chat_id)) == (
        [text],
        [("user", text), ("assistant", _REPLY)],
    )
    assert _linked_to(db, file_id) == _user_message_id(db, chat_id)


@pytest.mark.parametrize(
    "refusal", ["too-many-files", "attachment-not-found", "attachment-already-sent"]
)
def test_chat_message_empty_blank_message_with_files_keeps_the_file_refusals(
    world: World,
    client: TestClient,
    script: _Script,
    monkeypatch: pytest.MonkeyPatch,
    refusal: str,
) -> None:
    """``""`` with files gets the file refusals of today, not ``message_empty``: more
    ids than ``max_files_per_message`` (1 here) is ``too_many_files``, an unknown id
    ``attachment_not_found``, a file sent earlier ``attachment_already_sent``; no run."""
    db = world.db
    _files_limit(monkeypatch, db, 1)
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    if refusal == "too-many-files":
        ids, expected = _files(db, chat_id, 2), (422, _TOO_MANY_FILES, True)
    elif refusal == "attachment-not-found":
        ids, expected = [_UNKNOWN], (404, _ATTACHMENT_NOT_FOUND, True)
    else:
        earlier = db.add_chat_message(chat_id, "user", "Earlier, with the file")
        ids = [db.add_attachment(chat_id, created_at=_PAST, message_id=earlier)]
        expected = (409, _ALREADY_SENT, True)

    response = _post(
        client, "chat", editor, "", chat_id=chat_id, body={"attachment_ids": [str(i) for i in ids]}
    )

    assert (_outcome(response), script.runs) == (expected, [])


# ---------------------------------------------------------------------------
# 6. The contract: OpenAPI and the docs
# ---------------------------------------------------------------------------


def _documented_422(path: str) -> tuple[bool, bool, Any]:
    """(the 422's description names message_empty, it names the validation error, its
    JSON example) of ``POST path``."""
    responses = make_app().openapi()["paths"][path]["post"]["responses"]
    documented = responses.get("422", {})
    description = documented.get("description", "")
    return (
        "message_empty" in description,
        "validation" in description.lower(),
        documented.get("content", {}).get("application/json", {}).get("example"),
    )


def test_chat_message_empty_openapi_chat_route_documents_the_422() -> None:
    """The chat route's 422 names ``message_empty`` beside the validation error with the
    body as its example, and its 200 still lists ``text/event-stream``."""
    responses = make_app().openapi()["paths"][_CHAT_PATH]["post"]["responses"]

    assert (
        _documented_422(_CHAT_PATH),
        "text/event-stream" in responses.get("200", {}).get("content", {}),
    ) == ((True, True, _EMPTY), True)


def test_chat_message_empty_openapi_legacy_route_documents_the_422() -> None:
    """The legacy route's 422 names ``message_empty`` beside the validation error with
    the body as its example."""
    assert _documented_422(_LEGACY_PATH) == (True, True, _EMPTY)


def test_chat_message_empty_docs_name_the_code_in_the_chats_section() -> None:
    """``docs/configuration.md``'s Chats section (up to the next ``## `` heading, the
    message routes and their attachments included) names ``message_empty``."""
    text = (Path(__file__).resolve().parents[1] / "docs" / "configuration.md").read_text(
        encoding="utf-8"
    )
    start = text.index("\n## Chats\n")
    end = text.find("\n## ", start + 1)
    section = text[start:] if end == -1 else text[start:end]

    assert "message_empty" in section
