"""HTTP spec of attachment exclusion, ``PATCH /api/attachments/{attachment_id}`` (GH-190).

Issue #190, Decision 10 (exclusion) and the "Stuck chat" criterion; contract C2
(``AttachmentUpdateRequest``, ``AttachmentSummary.active``), C6
(``attachments.set_active``), C8 (``file.exclude`` / ``file.include``), C10
(``attachments.active``), C11 (the route and its rate limit). Tracker #139 §5:
every role, another org's and a colleague's file, CSRF, the per-user rate limit,
422 without echo, content-free audit rows and logs.

The app from ``create_app()`` runs against the FakeDb world of
tests/tenancy_world.py (orgs A and B with an Org Admin and an Editor each, plus a
Super Admin, real session cookies). Attachment rows are seeded with
``FakeDb.add_attachment`` (``active=False`` seeds an excluded file: the fake
models migration 0030 once it ships); a ready file's derived files are written
with tests/attachment_derived.py under a ``tmp_path`` attachments root. The agent
is a stub bound to ``Agent.run``'s signature that records what each run gets.

What is pinned:
- ``{"active": false}`` excludes the caller's own live attachment and
  ``{"active": true}`` includes it again: 200 with exactly its
  ``AttachmentSummary`` (``active`` the new value, ``context_report`` null), the
  row's flag changed, and one ``file.exclude`` / ``file.include`` audit row
  (member actor, org, ``file`` target, the id, the client IP, no metadata, no
  file name). The same value again is 200 with nothing written and no audit row.
- Any status: uploaded, processing, ready, failed and a ready file whose derived
  files are missing.
- The body is ``{"active": <strict bool>}`` and nothing else: a string, a
  number, null, a missing key, an extra key or a non-object is 422 without echo
  and changes nothing.
- 404 ``attachment_not_found`` for another org's, a colleague's (an Org Admin's
  request on an Editor's file too), a trashed and an unknown attachment, nothing
  changed; a non-UUID id is 422.
- Roles (``chat.send``): the Org Admin and the Editor may; the Super Admin gets
  403 and nothing changes. No session: 401.
- CSRF: a cross-site ``Origin`` or ``Sec-Fetch-Site`` is refused (403), the
  same request from the app's origin succeeds.
- Rate limit ``/api/attachments/patch`` (0.5, 5), per user: an empty bucket is
  429 with nothing changed, a colleague still patches.
- The route declares ``AttachmentSummary`` and takes ``AttachmentUpdateRequest``.
- No log record carries the file name.
- Stuck chat: an earlier sent image while the stored ``llm.image_input`` is
  false makes every send the 422 ``image_input_unsupported``, and a sent file
  whose derived files are missing the 503 ``storage_unavailable``; once the file
  is excluded the next send goes through (the run gets no slot). An approval
  refused by either keeps its confirmation and goes through after the exclusion.
- Exclusion keeps the history: the file stays linked to its message (listed in
  that message's ``attachment_ids`` and by ``GET /api/chats/{chat_id}/attachments``),
  earlier assistant rows keep their ``included_attachment_ids``, and including it
  again returns it to its original place in the slot.

New names are reached through HTTP or looked up at test time, so the file
collects before GH-190 is implemented.

Security notes: every id, name and text here is a fixed fake value under
``tmp_path``. No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import inspect
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import scoped_settings, server
from admino.models import AgentResult, LLMMessage, PendingConfirmation, ToolCall
from tests.attachment_derived import png_bytes, write_derived
from tests.conftest import default_test_platform_settings
from tests.db_fakes import ORG_ID, FakeDb, plain
from tests.tenancy_world import (
    CLIENT_IP,
    FORBIDDEN,
    UNAUTHORIZED,
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
    from collections.abc import Sequence
    from pathlib import Path
    from unittest.mock import MagicMock

    import httpx
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, MemberRole, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PATCH_KEY: Final = "/api/attachments/patch"
_NOT_FOUND: Final = {"detail": "Attachment not found", "reason": "attachment_not_found"}
_CSRF_REFUSED: Final = {"detail": "Cross-origin request refused"}
_RATE_LIMITED: Final = {"detail": "Rate limit exceeded"}
_IMAGE_UNSUPPORTED: Final = {
    "detail": "The current model does not accept image input",
    "reason": "image_input_unsupported",
}
_STORAGE_UNAVAILABLE: Final = {
    "detail": "Attachment storage is unavailable",
    "reason": "storage_unavailable",
}
_FOREIGN_ORIGIN: Final = "https://evil.example"
# TestClient sends ``Host: testserver``: an Origin with that host is same-origin.
_SAME_ORIGIN: Final = "http://testserver"

_SUMMARY_KEYS: Final = frozenset(
    {
        "id",
        "chat_id",
        "message_id",
        "filename",
        "kind",
        "size_bytes",
        "status",
        "failure_reason",
        "page_count",
        "token_estimate",
        "active",
        "context_report",
        "created_at",
    }
)

# Every seeded file name holds this marker (never in a log record or an audit row).
_NAME_MARK: Final = "Heronledger Mandant 190"
# A value marker: a 422 never repeats it.
_ECHO: Final = "ECHOMARK190"
_TEXT: Final = "Ledger notes 190: totals and dates."
_MESSAGE: Final = "What changed since last week?"
_REPLY: Final = "Nothing important, 190."
_PAST: Final = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)

_BOOK: Final = "Book the heron offsite for Friday 190"
_BOOK_CALL: Final = ToolCall(
    tool="google_calendar",
    action="create",
    args={"title": "Offsite 190"},
    tool_call_id="call-190-book",
)
_BOOK_BLOCK: Final = {
    "type": "tool_use",
    "id": "call-190-book",
    "name": "google_calendar.create",
    "input": {"title": "Offsite 190"},
}
_CONFIRMATION_ID: Final = "confirm-190-heron"

# The attributes every LogRecord has; anything else came in through ``extra=``.
_STANDARD_RECORD_ATTRS: Final = frozenset(
    vars(logging.LogRecord("n", logging.INFO, "p", 1, "m", None, None))
) | {"message", "asctime"}


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
    agent_config: Any = None,
    prompt_context: Any = None,
    earlier_external_content: bool = False,
    stream: Any = None,
    attachments: Sequence[Any] = (),
) -> None:
    """``Agent.run``'s signature (GH-189's ``attachments`` included); every call binds to it."""


class _Script:
    """The stub agent's ``run``: records each call's arguments and answers one final reply.

    A turn answers the user message plus the reply; a resumed confirmation the
    approved call's tool result plus the reply.
    """

    def __init__(self) -> None:
        self.runs: list[dict[str, Any]] = []

    async def run(self, *args: Any, **kwargs: Any) -> AgentResult:
        bound = inspect.signature(_run_signature).bind(*args, **kwargs)
        bound.apply_defaults()
        arguments = dict(bound.arguments)
        arguments["history"] = [message.model_copy(deep=True) for message in arguments["history"]]
        self.runs.append(arguments)
        if arguments["stream"] is not None:
            await arguments["stream"].on_delta(_REPLY)
        pending = arguments["pending_confirmation"]
        if pending is not None:
            new = [
                LLMMessage(
                    role="tool", content="Booked 190.", tool_call_id=pending.tool_call.tool_call_id
                ),
                LLMMessage(role="assistant", content=_REPLY),
            ]
        else:
            new = [
                LLMMessage(role="user", content=arguments["user_message"]),
                LLMMessage(role="assistant", content=_REPLY),
            ]
        return AgentResult(
            status="final",
            response=_REPLY,
            history=[*kwargs["history"], *new],
            tool_calls=[],
            pending_confirmation=None,
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    """The attachments root of the test."""
    return tmp_path / "attachments"


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, root: Path) -> World:
    """Orgs A and B (OA/ED each) and a Super Admin behind the fake database, the
    attachments root at ``root``, every rate-limit bucket roomy."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    use_attachment_storage(monkeypatch, built, root)
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
    """The app around the stub agent (built after the world: create_app clears the runtime)."""
    return make_client(make_app(agent))


# ---------------------------------------------------------------------------
# Helpers: seeding
# ---------------------------------------------------------------------------


def _chat(db: FakeDb, account: Account) -> uuid.UUID:
    """A user-titled chat of ``account`` (no title step runs after a turn)."""
    return db.add_chat(account.user_id, title="Ledgers 190", title_source="user")


def _org_of(db: FakeDb, chat_id: uuid.UUID) -> uuid.UUID:
    chat = db.chat_row(chat_id)
    assert chat is not None
    return plain(chat["org_id"])


def _file(
    db: FakeDb,
    root: Path,
    chat_id: uuid.UUID,
    *,
    shape: str = "txt",
    status: str = "ready",
    derived: bool = True,
    message_id: uuid.UUID | None = None,
    created_at: datetime = _PAST,
    **fields: Any,
) -> uuid.UUID:
    """An attachment of the chat (``shape`` "txt" or "png") named after ``_NAME_MARK``,
    its original under ``<root>/<org>/<id>``; a ready one (unless ``derived`` is False)
    also has its derived files. ``fields`` go to ``add_attachment`` (active, deleted_at)."""
    kind = "png" if shape == "png" else "txt"
    ready = status == "ready"
    file_id = db.add_attachment(
        chat_id,
        filename=f"{_NAME_MARK} {shape}.{kind}",
        kind=kind,
        size_bytes=len(_TEXT),
        status=status,
        failure_reason="corrupted_file" if status == "failed" else None,
        token_estimate=40 if ready else None,
        derived_bytes=256 if ready else None,
        message_id=message_id,
        created_at=created_at,
        **fields,
    )
    org_dir = root / str(_org_of(db, chat_id))
    org_dir.mkdir(parents=True, exist_ok=True)
    (org_dir / str(file_id)).write_bytes(_TEXT.encode())
    if ready and derived:
        parts: list[tuple[Any, ...]] = (
            [("image", png_bytes(), "image/png", None, None)]
            if shape == "png"
            else [("text", _TEXT, None)]
        )
        write_derived(root, _org_of(db, chat_id), file_id, kind=kind, parts=parts)
    return file_id


def _sent(
    db: FakeDb, root: Path, chat_id: uuid.UUID, *, text: str = "Earlier, with a file", **fields: Any
) -> tuple[uuid.UUID, uuid.UUID]:
    """A file sent with an earlier (answered) user message of the chat: (file, message)."""
    message = db.add_chat_message(chat_id, "user", text)
    db.add_chat_message(chat_id, "assistant", "Noted.")
    return _file(db, root, chat_id, message_id=message, **fields), message


def _awaiting_chat(
    db: FakeDb, root: Path, account: Account, *, shape: str, derived: bool
) -> tuple[uuid.UUID, uuid.UUID, PendingConfirmation]:
    """A chat whose request (sent with one file) awaits the confirmation of
    google_calendar.create, held in ``server._chat_runtime`` (call after the app exists)."""
    chat_id = _chat(db, account)
    request = db.add_chat_message(chat_id, "user", _BOOK)
    db.add_chat_message(
        chat_id, "assistant", "", tool_use_blocks=[_BOOK_BLOCK], status="awaiting_confirmation"
    )
    file_id = _file(db, root, chat_id, shape=shape, derived=derived, message_id=request)
    now = datetime.now(UTC)
    pending = PendingConfirmation(
        confirmation_id=_CONFIRMATION_ID,
        session_id=str(chat_id),
        tool_call=_BOOK_CALL,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    server._chat_runtime.set_pending(chat_id, account.user_id, pending)
    return chat_id, file_id, pending


def _image_input(monkeypatch: pytest.MonkeyPatch, db: FakeDb, *, enabled: bool) -> None:
    """The stored platform ``llm.image_input``: in the settings cache and the row."""
    stored = default_test_platform_settings()
    llm = stored.llm.model_copy(update={"image_input": enabled})
    monkeypatch.setattr(scoped_settings, "_platform_cache", stored.model_copy(update={"llm": llm}))
    row = db.platform_row()
    assert row is not None
    row["image_input"] = enabled


# ---------------------------------------------------------------------------
# Helpers: requests and state
# ---------------------------------------------------------------------------


def _patch(
    client: TestClient,
    caller: Account | None,
    attachment_id: uuid.UUID | str,
    body: Any,
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """PATCH /api/attachments/{attachment_id} with ``body`` as JSON."""
    cookie = dict(caller.cookie) if caller is not None else {}
    return client.patch(
        f"/api/attachments/{attachment_id}", json=body, headers={**cookie, **(headers or {})}
    )


def _send(
    client: TestClient, account: Account, chat_id: uuid.UUID, text: str = _MESSAGE
) -> httpx.Response:
    """POST /api/chats/{chat_id}/messages (JSON), no files listed."""
    return client.post(
        f"/api/chats/{chat_id}/messages", headers=account.cookie, json={"message": text}
    )


def _approve(
    client: TestClient, account: Account, chat_id: uuid.UUID, confirmation_id: str
) -> httpx.Response:
    """Approve the chat's pending confirmation (JSON)."""
    return client.post(
        f"/api/confirm/{confirmation_id}",
        headers=account.cookie,
        json={"confirmation_id": confirmation_id, "approved": True, "chat_id": str(chat_id)},
    )


def _outcome(response: httpx.Response) -> tuple[int, Any]:
    """(status, JSON body) or (status, text) when the body isn't JSON."""
    try:
        body = response.json()
    except ValueError:
        body = response.text
    return response.status_code, body


def _flag(db: FakeDb, attachment_id: uuid.UUID) -> Any:
    """The stored ``active`` flag of an attachment ("missing" without the column)."""
    row = db.attachment_row(attachment_id)
    assert row is not None
    return row.get("active", "missing")


def _tables(db: FakeDb) -> dict[str, Any]:
    """Every table, deep-copied, a session's ``last_seen_at`` (the refresh) left out."""
    state = db.snapshot()
    state["sessions"] = {
        key: {column: value for column, value in row.items() if column != "last_seen_at"}
        for key, row in state["sessions"].items()
    }
    return state


def _writes_since(db: FakeDb, since: int) -> list[str]:
    """Data-changing statements after call ``since``, the session refresh aside."""
    return [
        call.normalized
        for call in db.calls[since:]
        if any(word in call.normalized for word in ("insert into", "delete from", " set "))
        and not call.normalized.startswith("update sessions")
    ]


def _exclusion_audit(db: FakeDb) -> list[dict[str, Any]]:
    """The file.exclude and file.include audit rows, in order."""
    return [row for row in db.audit_rows() if row["action"] in ("file.exclude", "file.include")]


def _expected_summary(db: FakeDb, attachment_id: uuid.UUID, *, active: bool) -> dict[str, Any]:
    """The AttachmentSummary of a stored row with ``active`` (created_at left out)."""
    row = db.attachment_row(attachment_id)
    assert row is not None
    return {
        "id": str(attachment_id),
        "chat_id": str(row["chat_id"]),
        "message_id": None if row["message_id"] is None else str(row["message_id"]),
        "filename": row["filename"],
        "kind": row["kind"],
        "size_bytes": row["size_bytes"],
        "status": row["status"],
        "failure_reason": row["failure_reason"],
        "page_count": row["page_count"],
        "token_estimate": row["token_estimate"],
        "active": active,
        "context_report": None,
    }


def _without_created_at(body: Any) -> Any:
    if not isinstance(body, dict):
        return body
    return {key: value for key, value in body.items() if key != "created_at"}


def _slot_ids(run: dict[str, Any]) -> list[uuid.UUID]:
    """The attachment ids a run got, in slot order."""
    return [uuid.UUID(str(attachment.id)) for attachment in run["attachments"]]


def _app_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """Every captured app record (not the client's httpx lines)."""
    return [
        record
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore", "asyncio", "PIL"))
    ]


def _record_text(record: logging.LogRecord) -> str:
    """Everything a record carries: message, arguments, exception, ``extra=`` fields."""
    parts = [str(record.msg), record.getMessage(), repr(record.args)]
    if record.exc_info:
        parts.append(logging.Formatter().formatException(record.exc_info))
    parts.extend(
        repr(value) for key, value in vars(record).items() if key not in _STANDARD_RECORD_ATTRS
    )
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# 1. PATCH: exclude, include, audit, idempotence, any status
# ---------------------------------------------------------------------------


class TestExclusionPatch:
    """The flag changes on the caller's own live attachment, audited once per change."""

    def test_attachment_exclusion_false_excludes_and_answers_the_summary(
        self, world: World, root: Path, client: TestClient
    ) -> None:
        """``{"active": false}`` on a sent ready file: 200 with exactly its summary
        (``active`` false, ``context_report`` null) and the row excluded."""
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        file_id, _ = _sent(world.db, root, chat_id)

        response = _patch(client, editor, file_id, {"active": False})

        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == _SUMMARY_KEYS
        assert _without_created_at(body) == _expected_summary(world.db, file_id, active=False)
        row = world.db.attachment_row(file_id)
        assert row is not None
        assert datetime.fromisoformat(body["created_at"]) == row["created_at"]
        assert _flag(world.db, file_id) is False

    def test_attachment_exclusion_true_includes_an_excluded_file_again(
        self, world: World, root: Path, client: TestClient
    ) -> None:
        """``{"active": true}`` on an excluded file: 200, ``active`` true, the row included."""
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        file_id, _ = _sent(world.db, root, chat_id, active=False)

        response = _patch(client, editor, file_id, {"active": True})

        assert response.status_code == 200, response.text
        assert _without_created_at(response.json()) == _expected_summary(
            world.db, file_id, active=True
        )
        assert _flag(world.db, file_id) is True

    @pytest.mark.parametrize(
        ("start", "value", "action"),
        [
            pytest.param(True, False, "file.exclude", id="exclude"),
            pytest.param(False, True, "file.include", id="include"),
        ],
    )
    def test_attachment_exclusion_change_records_one_content_free_audit_row(
        self,
        world: World,
        root: Path,
        client: TestClient,
        start: bool,
        value: bool,
        action: str,
    ) -> None:
        """One ``file.exclude`` / ``file.include`` row: member actor, the caller's org, a
        ``file`` target with the attachment's id, the client IP, no metadata, no name."""
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        file_id = _file(world.db, root, chat_id, active=start)

        response = _patch(client, editor, file_id, {"active": value})

        assert response.status_code == 200, response.text
        rows = _exclusion_audit(world.db)
        assert [row["action"] for row in rows] == [action]
        row = rows[0]
        assert (row["actor_kind"], str(row["actor_user_id"]), str(row["org_id"])) == (
            "member",
            str(editor.user_id),
            str(ORG_ID),
        )
        assert (row["target_type"], row["target_ids"]) == ("file", [str(file_id)])
        assert (row["ip"], row["metadata"]) == (CLIENT_IP, {})
        assert "heronledger" not in repr(row).casefold()

    @pytest.mark.parametrize(
        "value",
        [pytest.param(True, id="include-active"), pytest.param(False, id="exclude-excluded")],
    )
    def test_attachment_exclusion_same_value_again_writes_and_records_nothing(
        self, world: World, root: Path, client: TestClient, value: bool
    ) -> None:
        """Idempotent: the value the file already has is 200 with that value, no write
        statement, no audit row and every table as it was."""
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        file_id = _file(world.db, root, chat_id, active=value)
        before = _tables(world.db)
        since = len(world.db.calls)

        response = _patch(client, editor, file_id, {"active": value})

        assert response.status_code == 200, response.text
        assert response.json()["active"] is value
        assert _writes_since(world.db, since) == []
        assert _exclusion_audit(world.db) == []
        assert _tables(world.db) == before

    def test_attachment_exclusion_toggle_twice_records_two_rows_in_order(
        self, world: World, root: Path, client: TestClient
    ) -> None:
        """Exclude then include: two changes, ``file.exclude`` then ``file.include``."""
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        file_id = _file(world.db, root, chat_id)

        excluded = _patch(client, editor, file_id, {"active": False})
        included = _patch(client, editor, file_id, {"active": True})

        assert (excluded.status_code, included.status_code) == (200, 200)
        assert [row["action"] for row in _exclusion_audit(world.db)] == [
            "file.exclude",
            "file.include",
        ]
        assert _flag(world.db, file_id) is True

    @pytest.mark.parametrize(
        "case",
        ["uploaded", "processing", "ready", "failed", "ready-derived-missing"],
    )
    def test_attachment_exclusion_works_whatever_the_status(
        self, world: World, root: Path, client: TestClient, case: str
    ) -> None:
        """Every status, and a ready file whose derived files are missing: 200, excluded."""
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        status = "ready" if case.startswith("ready") else case
        file_id = _file(
            world.db, root, chat_id, status=status, derived=case != "ready-derived-missing"
        )

        response = _patch(client, editor, file_id, {"active": False})

        assert response.status_code == 200, response.text
        assert (response.json()["status"], response.json()["active"]) == (status, False)
        assert _flag(world.db, file_id) is False
        assert [row["action"] for row in _exclusion_audit(world.db)] == ["file.exclude"]


# ---------------------------------------------------------------------------
# 2. The body, not-found, roles, session, CSRF, rate limit, the route's models, logs
# ---------------------------------------------------------------------------

_BAD_BODIES: Final = [
    pytest.param({"active": "false"}, id="string-false"),
    pytest.param({"active": _ECHO}, id="string-marker"),
    pytest.param({"active": 0}, id="zero"),
    pytest.param({"active": 1}, id="one"),
    pytest.param({"active": None}, id="null"),
    pytest.param({}, id="missing-key"),
    pytest.param({"active": False, "note": _ECHO}, id="extra-key"),
    pytest.param([False], id="not-an-object"),
    pytest.param(_ECHO, id="a-string-body"),
]

_NOT_THE_CALLERS: Final = ["other-org", "colleague", "org-admin-on-editors", "trashed", "unknown"]


def _not_the_callers(world: World, root: Path, case: str) -> tuple[Account, uuid.UUID]:
    """(caller, an id that isn't the caller's own live attachment)."""
    a, b = world.a, world.b
    if case == "other-org":
        return a["editor"], _file(world.db, root, _chat(world.db, b["editor"]))
    if case == "colleague":
        return a["editor"], _file(world.db, root, _chat(world.db, a["org_admin"]))
    if case == "org-admin-on-editors":
        return a["org_admin"], _file(world.db, root, _chat(world.db, a["editor"]))
    if case == "trashed":
        trashed_at = datetime.now(UTC)
        chat_id = world.db.add_chat(a["editor"].user_id, deleted_at=trashed_at)
        return a["editor"], _file(world.db, root, chat_id, deleted_at=trashed_at)
    return a["editor"], uuid.uuid4()


class TestExclusionRefusals:
    """Everything that isn't a valid change of the caller's own file changes nothing."""

    @pytest.mark.parametrize("body", _BAD_BODIES)
    def test_attachment_exclusion_invalid_body_is_422_without_echo_and_changes_nothing(
        self, world: World, root: Path, client: TestClient, body: Any
    ) -> None:
        """Only a strict bool under ``active``, and nothing else: 422, no error with an
        ``input``, the marker never repeated, every table as it was."""
        editor = world.a["editor"]
        file_id = _file(world.db, root, _chat(world.db, editor))
        before = _tables(world.db)

        response = _patch(client, editor, file_id, body)

        assert response.status_code == 422, response.text
        errors = response.json()["detail"]
        assert isinstance(errors, list), errors
        assert all("input" not in error for error in errors), errors
        assert _ECHO not in response.text
        assert _tables(world.db) == before

    def test_attachment_exclusion_without_a_body_is_422(
        self, world: World, root: Path, client: TestClient
    ) -> None:
        editor = world.a["editor"]
        file_id = _file(world.db, root, _chat(world.db, editor))

        response = client.patch(f"/api/attachments/{file_id}", headers=editor.cookie)

        assert response.status_code == 422, response.text
        assert _flag(world.db, file_id) is True

    @pytest.mark.parametrize("case", _NOT_THE_CALLERS)
    def test_attachment_exclusion_not_the_callers_attachment_is_404_and_changes_nothing(
        self, world: World, root: Path, client: TestClient, case: str
    ) -> None:
        """Another org's, a colleague's, an Editor's file for the Org Admin, a trashed one
        and an unknown id: one 404 ``attachment_not_found``, the id not echoed, nothing
        changed."""
        caller, file_id = _not_the_callers(world, root, case)
        before = _tables(world.db)

        response = _patch(client, caller, file_id, {"active": False})

        assert _outcome(response) == (404, _NOT_FOUND)
        assert str(file_id) not in response.text
        assert _tables(world.db) == before

    def test_attachment_exclusion_non_uuid_id_is_422(
        self, world: World, client: TestClient
    ) -> None:
        response = _patch(client, world.a["editor"], "not-a-uuid", {"active": False})

        assert response.status_code == 422, response.text

    def test_attachment_exclusion_super_admin_is_403_and_changes_nothing(
        self, world: World, root: Path, client: TestClient
    ) -> None:
        """The Super Admin (no ``chat.send``) on an Editor's file: exactly 403 Forbidden, no
        statement on attachments, nothing changed."""
        file_id = _file(world.db, root, _chat(world.db, world.a["editor"]))
        before = _tables(world.db)
        since = len(world.db.calls)

        response = _patch(client, world.super_admin, file_id, {"active": False})

        assert _outcome(response) == (403, FORBIDDEN)
        assert [
            call.normalized for call in world.db.calls[since:] if "attachments" in call.normalized
        ] == []
        assert _tables(world.db) == before
        assert _NAME_MARK not in response.text

    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    def test_attachment_exclusion_org_admin_and_editor_may_exclude_their_own_file(
        self, world: World, root: Path, client: TestClient, role: MemberRole
    ) -> None:
        caller = world.a[role]
        file_id = _file(world.db, root, _chat(world.db, caller))

        response = _patch(client, caller, file_id, {"active": False})

        assert response.status_code == 200, response.text
        assert _flag(world.db, file_id) is False

    def test_attachment_exclusion_without_a_session_is_401_and_changes_nothing(
        self, world: World, root: Path, client: TestClient
    ) -> None:
        file_id = _file(world.db, root, _chat(world.db, world.a["editor"]))
        before = _tables(world.db)

        response = _patch(client, None, file_id, {"active": False})

        assert _outcome(response) == (401, UNAUTHORIZED)
        assert _tables(world.db) == before

    @pytest.mark.parametrize(
        "cross_site",
        [
            pytest.param({"Origin": _FOREIGN_ORIGIN}, id="foreign-origin"),
            pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sec-fetch-site"),
        ],
    )
    def test_attachment_exclusion_cross_site_patch_is_refused_and_same_origin_succeeds(
        self, world: World, root: Path, client: TestClient, cross_site: dict[str, str]
    ) -> None:
        """A cross-site PATCH is the CSRF 403 with nothing changed; the same PATCH from the
        app's own origin is 200 (the route exists)."""
        editor = world.a["editor"]
        file_id = _file(world.db, root, _chat(world.db, editor))
        before = _tables(world.db)

        refused = _patch(client, editor, file_id, {"active": False}, headers=cross_site)
        after_refusal = _tables(world.db)
        accepted = _patch(
            client, editor, file_id, {"active": False}, headers={"Origin": _SAME_ORIGIN}
        )

        assert _outcome(refused) == (403, _CSRF_REFUSED)
        assert after_refusal == before
        assert accepted.status_code == 200, accepted.text
        assert _flag(world.db, file_id) is False

    def test_attachment_exclusion_rate_limit_key_has_the_contract_value(self) -> None:
        assert server._RATE_LIMITS.get(_PATCH_KEY) == (0.5, 5)

    def test_attachment_exclusion_rate_limit_is_per_user(
        self, world: World, root: Path, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Burst 1 on ``/api/attachments/patch``: the Editor's second PATCH is 429 with
        nothing changed; a colleague (the Org Admin) still patches; the bucket is
        (route key, ``user:<id>``)."""
        monkeypatch.setitem(server._RATE_LIMITS, _PATCH_KEY, (0.001, 1))
        editor, admin = world.a["editor"], world.a["org_admin"]
        file_id = _file(world.db, root, _chat(world.db, editor))
        other_id = _file(world.db, root, _chat(world.db, admin))

        first = _patch(client, editor, file_id, {"active": False})
        before = _tables(world.db)
        limited = _patch(client, editor, file_id, {"active": True})
        after = _tables(world.db)
        colleague = _patch(client, admin, other_id, {"active": False})

        assert first.status_code == 200, first.text
        assert _outcome(limited) == (429, _RATE_LIMITED)
        assert after == before
        assert colleague.status_code == 200, colleague.text
        assert (_PATCH_KEY, f"user:{editor.user_id}") in server._rate_buckets

    def test_attachment_exclusion_route_declares_its_models(self) -> None:
        """PATCH /api/attachments/{attachment_id}: ``AttachmentSummary`` (200), body
        ``AttachmentUpdateRequest``."""
        from fastapi.routing import APIRoute

        from admino import models

        found = [
            (route.response_model, route.status_code or 200, route.body_field)
            for route in make_app().routes
            if isinstance(route, APIRoute)
            and route.path == "/api/attachments/{attachment_id}"
            and "PATCH" in route.methods
        ]

        assert len(found) == 1, found
        response_model, status, body_field = found[0]
        assert (response_model, status) == (models.AttachmentSummary, 200)
        assert body_field is not None
        assert body_field.field_info.annotation is models.AttachmentUpdateRequest

    def test_attachment_exclusion_logs_carry_no_file_name(
        self,
        world: World,
        root: Path,
        client: TestClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """An exclusion and an inclusion log no record holding the file's name."""
        editor = world.a["editor"]
        file_id = _file(world.db, root, _chat(world.db, editor))
        caplog.set_level(logging.DEBUG)

        excluded = _patch(client, editor, file_id, {"active": False})
        included = _patch(client, editor, file_id, {"active": True})

        assert (excluded.status_code, included.status_code) == (200, 200)
        leaks = [
            record.getMessage()
            for record in _app_records(caplog)
            if _NAME_MARK in _record_text(record)
            or json.dumps(_NAME_MARK)[1:-1] in _record_text(record)
        ]
        assert leaks == []


# ---------------------------------------------------------------------------
# 3. The stuck chat (Decision 10): exclusion unblocks the next turn
# ---------------------------------------------------------------------------


class TestStuckChat:
    """A file that can't be sent stops refusing every turn once it is excluded."""

    def test_attachment_exclusion_image_without_image_input_is_unblocked_by_excluding_it(
        self,
        world: World,
        root: Path,
        client: TestClient,
        script: _Script,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An earlier sent image while the stored ``llm.image_input`` is false: the send
        is the 422 ``image_input_unsupported`` with no run; after ``{"active": false}``
        the next send runs (no slot) and is answered; the file stays linked."""
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        image_id, message_id = _sent(world.db, root, chat_id, shape="png")
        _image_input(monkeypatch, world.db, enabled=False)

        refused = _send(client, editor, chat_id)
        runs_after_refusal = len(script.runs)
        patched = _patch(client, editor, image_id, {"active": False})
        answered = _send(client, editor, chat_id)

        assert _outcome(refused) == (422, _IMAGE_UNSUPPORTED)
        assert runs_after_refusal == 0
        assert patched.status_code == 200, patched.text
        assert answered.status_code == 200, answered.text
        assert answered.json()["status"] == "final"
        assert [_slot_ids(run) for run in script.runs] == [[]]
        row = world.db.attachment_row(image_id)
        assert row is not None
        assert plain(row["message_id"]) == message_id

    def test_attachment_exclusion_missing_derived_files_are_unblocked_by_excluding_the_file(
        self, world: World, root: Path, client: TestClient, script: _Script
    ) -> None:
        """An earlier sent file whose derived files are missing: the send is the 503
        ``storage_unavailable`` with no run; after the exclusion the next send runs (no
        slot) and is answered."""
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        file_id, _ = _sent(world.db, root, chat_id, derived=False)

        refused = _send(client, editor, chat_id)
        runs_after_refusal = len(script.runs)
        patched = _patch(client, editor, file_id, {"active": False})
        answered = _send(client, editor, chat_id)

        assert _outcome(refused) == (503, _STORAGE_UNAVAILABLE)
        assert runs_after_refusal == 0
        assert patched.status_code == 200, patched.text
        assert answered.status_code == 200, answered.text
        assert [_slot_ids(run) for run in script.runs] == [[]]

    @pytest.mark.parametrize(
        ("shape", "derived", "expected"),
        [
            pytest.param("png", True, (422, _IMAGE_UNSUPPORTED), id="image-input-off"),
            pytest.param("txt", False, (503, _STORAGE_UNAVAILABLE), id="derived-missing"),
        ],
    )
    def test_attachment_exclusion_refused_approval_keeps_its_confirmation_until_excluded(
        self,
        world: World,
        root: Path,
        client: TestClient,
        script: _Script,
        monkeypatch: pytest.MonkeyPatch,
        shape: str,
        derived: bool,
        expected: tuple[int, dict[str, str]],
    ) -> None:
        """The request's file refuses the approval (422 or 503) with no run and the
        confirmation still pending; after the exclusion the same approval resumes the
        run (the pending confirmation, no slot) and consumes the confirmation."""
        editor = world.a["editor"]
        chat_id, file_id, pending = _awaiting_chat(
            world.db, root, editor, shape=shape, derived=derived
        )
        _image_input(monkeypatch, world.db, enabled=False)

        refused = _approve(client, editor, chat_id, pending.confirmation_id)
        kept = server._chat_runtime.get_pending(chat_id)
        runs_after_refusal = len(script.runs)
        patched = _patch(client, editor, file_id, {"active": False})
        approved = _approve(client, editor, chat_id, pending.confirmation_id)

        assert _outcome(refused) == expected
        assert kept is not None
        assert kept.confirmation_id == pending.confirmation_id
        assert runs_after_refusal == 0
        assert patched.status_code == 200, patched.text
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "final"
        (run,) = script.runs
        assert run["pending_confirmation"] is not None
        assert run["pending_confirmation"].confirmation_id == pending.confirmation_id
        assert _slot_ids(run) == []
        assert server._chat_runtime.get_pending(chat_id) is None


# ---------------------------------------------------------------------------
# 4. Exclusion keeps the history (Decision 10)
# ---------------------------------------------------------------------------


class TestExclusionKeepsHistory:
    """An excluded file stays linked and listed; re-including restores its slot place."""

    def test_attachment_exclusion_file_stays_linked_and_listed_on_its_message(
        self, world: World, root: Path, client: TestClient
    ) -> None:
        """After the exclusion the file keeps its ``message_id``, the message lists it
        in ``attachment_ids`` (GET /api/chats/{chat_id}) and the chat's attachment list
        still holds it, with ``active`` false."""
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        file_id, message_id = _sent(world.db, root, chat_id)

        patched = _patch(client, editor, file_id, {"active": False})
        detail = client.get(f"/api/chats/{chat_id}", headers=editor.cookie)
        listed = client.get(f"/api/chats/{chat_id}/attachments", headers=editor.cookie)

        assert patched.status_code == 200, patched.text
        row = world.db.attachment_row(file_id)
        assert row is not None
        assert plain(row["message_id"]) == message_id
        assert detail.status_code == 200, detail.text
        messages = detail.json()["messages"]
        assert [message["attachment_ids"] for message in messages] == [[str(file_id)], []]
        assert messages[0]["id"] == str(message_id)
        assert listed.status_code == 200, listed.text
        assert [(item["id"], item["active"]) for item in listed.json()["attachments"]] == [
            (str(file_id), False)
        ]

    def test_attachment_exclusion_earlier_assistant_rows_keep_their_included_ids(
        self, world: World, root: Path, client: TestClient, script: _Script
    ) -> None:
        """An assistant row that recorded the file keeps its ``included_attachment_ids``
        after the exclusion and a new turn; the new turn's rows record no file."""
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        request = world.db.add_chat_message(chat_id, "user", "Read this, please")
        file_id = _file(world.db, root, chat_id, message_id=request)
        world.db.add_chat_message(
            chat_id, "assistant", "Read it.", included_attachment_ids=[file_id]
        )

        patched = _patch(client, editor, file_id, {"active": False})
        answered = _send(client, editor, chat_id)

        assert patched.status_code == 200, patched.text
        assert answered.status_code == 200, answered.text
        rows = world.db.messages_of(chat_id)
        # The request, the answer that recorded the file, the new turn's question and reply.
        assert [(row["role"], row["included_attachment_ids"]) for row in rows] == [
            ("user", None),
            ("assistant", [file_id]),
            ("user", None),
            ("assistant", None),
        ]
        assert [_slot_ids(run) for run in script.runs] == [[]]

    def test_attachment_exclusion_reinclusion_restores_the_original_slot_order(
        self, world: World, root: Path, client: TestClient, script: _Script
    ) -> None:
        """Two sent files, A (with the earlier message, uploaded last) and B: the slot is
        [A, B]; with A excluded [B]; with A included again [A, B] as before."""
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        first = world.db.add_chat_message(chat_id, "user", "First file")
        world.db.add_chat_message(chat_id, "assistant", "Got it.")
        second = world.db.add_chat_message(chat_id, "user", "Second file")
        world.db.add_chat_message(chat_id, "assistant", "Got that too.")
        file_b = _file(world.db, root, chat_id, message_id=second, created_at=_PAST)
        file_a = _file(
            world.db, root, chat_id, message_id=first, created_at=_PAST + timedelta(minutes=5)
        )

        baseline = _send(client, editor, chat_id, "Turn with both")
        excluded = _patch(client, editor, file_a, {"active": False})
        without = _send(client, editor, chat_id, "Turn without A")
        included = _patch(client, editor, file_a, {"active": True})
        restored = _send(client, editor, chat_id, "Turn with A again")

        assert [response.status_code for response in (baseline, without, restored)] == [
            200,
            200,
            200,
        ]
        assert (excluded.status_code, included.status_code) == (200, 200)
        assert [_slot_ids(run) for run in script.runs] == [
            [file_a, file_b],
            [file_b],
            [file_a, file_b],
        ]
