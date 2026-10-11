"""HTTP spec of GH-189's send rules on ``POST /api/chats/{chat_id}/messages`` (Decision 7).

The app from ``create_app()`` runs against the FakeDb world of
tests/tenancy_world.py (orgs A and B with an Org Admin and an Editor each, all
with real session cookies). The agent is the stub of
tests/test_chat_attachments_api.py (``_Script``): it binds every call to
``Agent.run``'s signature (``attachments`` included, C11), records it and answers
one final reply. Attachment rows are seeded with ``FakeDb.add_attachment``; a
ready file's derived files (``<root>/<org_id>/<id>.d/``) are written with
tests/attachment_derived.py under a ``tmp_path`` attachments root
(``organizations.ATTACHMENTS_ROOT``, read through ``attachments.attachments_root()``).

What is pinned (Decisions 7 and 8, contract C5, C6 and C12):
- A listed file whose status isn't ``ready`` (``uploaded``, ``processing``,
  ``failed``) is the 409 ``{"detail": "Attachment is not ready", "reason":
  "attachment_not_ready"}``, also beside a ready file in either order.
- The order: ``attachment_not_found`` beats ``attachment_already_sent``, which
  beats ``attachment_not_ready``; the three come before the chat's hold, so a
  not-ready file of a busy chat is ``attachment_not_ready``, not ``run_active``.
- Under the hold the derived files of every active attachment (the chat's sent,
  live, ready files plus the listed ones) are read: a missing ``<id>.d`` or a
  broken manifest is the 503 ``{"detail": "Attachment storage is unavailable",
  "reason": "storage_unavailable"}``, for a listed file and for one sent with
  an earlier message. Then, with the stored platform ``llm.image_input`` false,
  an active attachment holding an image part (a PNG, a PDF whose parts hold an
  image, an earlier sent image while the message lists text files or none) is
  the 422 ``{"detail": "The current model does not accept image input",
  "reason": "image_input_unsupported"}``. Both come under the hold (a busy chat
  answers ``run_active`` first), and the 503 comes before the 422.
- Every refusal: exactly the fixed body, the same JSON with ``Accept:
  text/event-stream``, no run, nothing stored, linked or audited (every table
  unchanged), the chat's pending confirmation kept, and no log record holding a
  file name, the attachments root or the files' text.
- Accepted: a ready file with its derived files is linked to the stored user
  message and passed to the run (its id, kind, page count and converted text);
  with ``image_input`` false text-only files run (earlier sent ones included,
  in upload order); with ``image_input`` true image files run. Files outside the
  chat's active set (another chat's, a trashed one, an unlisted unsent one) are
  never read: their broken derived files refuse nothing.
- OpenAPI: the operation documents the 409 (``attachment_not_ready`` beside
  ``run_active`` and ``attachment_already_sent``), the 422
  (``image_input_unsupported``) and the 503 (``storage_unavailable``), the 409
  and 503 bodies as examples.

New behaviour is reached through HTTP only (new names such as
``AttachmentContent.has_images`` are read from the run's arguments at test time),
so the file collects before GH-189 is implemented.

Security notes:
- A refusal never echoes input and logs no name or content; another tenant's
  file stays ``attachment_not_found`` (tests/test_chat_attachments_api.py).
- Every id, name and text here is a fixed fake value under ``tmp_path``. No
  network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import json
import logging
import shutil
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import httpx
import pytest

from admino import scoped_settings, server
from tests.attachment_derived import png_bytes, write_derived
from tests.conftest import default_test_platform_settings
from tests.db_fakes import FakeDb, plain
from tests.tenancy_world import (
    CLIENT_IP,
    build_world,
    chat_runtime_state,
    make_app,
    make_client,
    seed_pending_confirmation,
    stub_agent,
    use_attachment_storage,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)
from tests.test_chat_attachments_api import _linked_to, _Script

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_NOT_READY: Final = {"detail": "Attachment is not ready", "reason": "attachment_not_ready"}
_IMAGE_UNSUPPORTED: Final = {
    "detail": "The current model does not accept image input",
    "reason": "image_input_unsupported",
}
_STORAGE_UNAVAILABLE: Final = {
    "detail": "Attachment storage is unavailable",
    "reason": "storage_unavailable",
}
_NOT_FOUND: Final = {"detail": "Attachment not found", "reason": "attachment_not_found"}
_ALREADY_SENT: Final = {"detail": "Attachment already sent", "reason": "attachment_already_sent"}
_RUN_ACTIVE: Final = {
    "detail": "A message is already running in this chat.",
    "reason": "run_active",
}
_SSE_ACCEPT: Final = {"Accept": "text/event-stream"}
_PATH: Final = "/api/chats/{chat_id}/messages"
_MESSAGE: Final = "Compare the attached ledgers"
_UNKNOWN: Final = uuid.UUID("7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f")
_CONFIRMATION_ID: Final = "confirm-189-send-rules"
_PAST: Final = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
_FAILURE_REASON: Final = "corrupted_file"

# Log needles: every seeded file name holds _NAME_MARK, every derived text part (and
# image label) _TEXT_MARK, every broken manifest _MANIFEST_MARK.
_NAME_MARK: Final = "heron-189-ledger"
_TEXT_MARK: Final = "kestrel-189-total-4471"
_MANIFEST_MARK: Final = "plover-189-manifest"

# The attributes every LogRecord has; anything else came in through ``extra=``.
_STANDARD_RECORD_ATTRS: Final = frozenset(
    vars(logging.LogRecord("n", logging.INFO, "p", 1, "m", None, None))
) | {"message", "asctime"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    """The attachments root of the test."""
    return tmp_path / "attachments"


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, root: Path) -> World:
    """Orgs A and B (OA/ED each) and a Super Admin, behind the fake database, with
    the attachments root at ``root``."""
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
    """The app around the stub agent; an escaping exception becomes the app's 500."""
    return make_client(make_app(agent), raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helpers: files and their derived files
# ---------------------------------------------------------------------------


def _chat(db: FakeDb, account: Account) -> uuid.UUID:
    """A user-titled chat of ``account`` (no title step runs after a turn)."""
    return db.add_chat(account.user_id, title="Ledgers 189", title_source="user")


def _shape(shape: str) -> tuple[str, int | None, list[tuple[Any, ...]]]:
    """(kind, page count, derived parts) of a seeded file shape."""
    if shape == "pdf":
        return "pdf", 2, [("text", f"Page one {_TEXT_MARK}", 1), ("text", "Page two", 2)]
    if shape == "txt":
        return "txt", None, [("text", f"Notes {_TEXT_MARK}", None)]
    if shape == "png":
        return "png", None, [("image", png_bytes(), "image/png", None, None)]
    assert shape == "pdf-with-image", shape
    label = f"[{_NAME_MARK} {_TEXT_MARK} - page 1]"
    return (
        "pdf",
        1,
        [("text", f"Chart {_TEXT_MARK}", 1), ("image", png_bytes(), "image/png", 1, label)],
    )


def _org_of(db: FakeDb, chat_id: uuid.UUID) -> uuid.UUID:
    chat = db.chat_row(chat_id)
    assert chat is not None
    return plain(chat["org_id"])


def _file(
    db: FakeDb,
    root: Path,
    chat_id: uuid.UUID,
    shape: str = "pdf",
    *,
    status: str = "ready",
    message_id: uuid.UUID | None = None,
    created_at: datetime = _PAST,
    deleted_at: datetime | None = None,
) -> uuid.UUID:
    """An attachment of the chat named after ``_NAME_MARK``; a ready one with its derived
    files under ``root`` (a not-ready one has none)."""
    kind, pages, parts = _shape(shape)
    ready = status == "ready"
    file_id = db.add_attachment(
        chat_id,
        filename=f"{_NAME_MARK}-{shape}.{kind}",
        kind=kind,
        status=status,
        failure_reason=_FAILURE_REASON if status == "failed" else None,
        page_count=pages if ready else None,
        token_estimate=40 if ready else None,
        derived_bytes=256 if ready else None,
        message_id=message_id,
        created_at=created_at,
        deleted_at=deleted_at,
    )
    if ready:
        write_derived(root, _org_of(db, chat_id), file_id, kind=kind, parts=parts, page_count=pages)
    return file_id


def _sent_earlier(
    db: FakeDb, root: Path, chat_id: uuid.UUID, shape: str, **fields: Any
) -> uuid.UUID:
    """A ready file sent with an earlier user message of the chat (answered)."""
    earlier = db.add_chat_message(chat_id, "user", "Earlier, with a file")
    db.add_chat_message(chat_id, "assistant", "Noted.")
    return _file(db, root, chat_id, shape, message_id=earlier, **fields)


def _break(db: FakeDb, root: Path, chat_id: uuid.UUID, file_id: uuid.UUID, how: str) -> None:
    """``missing``: remove the file's ``<id>.d``; ``manifest``: make its manifest unreadable
    JSON (holding ``_MANIFEST_MARK``)."""
    derived = root / str(_org_of(db, chat_id)) / f"{file_id}.d"
    if how == "missing":
        shutil.rmtree(derived)
        return
    assert how == "manifest", how
    (derived / "manifest.json").write_bytes(b'{"version": 1, "kind": "' + _MANIFEST_MARK.encode())


def _image_input(monkeypatch: pytest.MonkeyPatch, db: FakeDb, *, enabled: bool) -> None:
    """The stored platform ``llm.image_input``: in the settings cache (GH-160) and the row."""
    stored = default_test_platform_settings()
    llm = stored.llm.model_copy(update={"image_input": enabled})
    monkeypatch.setattr(scoped_settings, "_platform_cache", stored.model_copy(update={"llm": llm}))
    row = db.platform_row()
    assert row is not None
    row["image_input"] = enabled


# ---------------------------------------------------------------------------
# Helpers: requests, state, logs
# ---------------------------------------------------------------------------


def _body(ids: list[uuid.UUID]) -> dict[str, Any]:
    """The send's body: ``_MESSAGE`` and, when there are any, the ids."""
    body: dict[str, Any] = {"message": _MESSAGE}
    if ids:
        body["attachment_ids"] = [str(file_id) for file_id in ids]
    return body


def _send(
    client: TestClient,
    account: Account,
    chat_id: uuid.UUID,
    ids: list[uuid.UUID],
    *,
    sse: bool = False,
) -> httpx.Response:
    return client.post(
        _PATH.format(chat_id=chat_id),
        headers={**account.cookie, **(_SSE_ACCEPT if sse else {})},
        json=_body(ids),
    )


def _async_client(app: FastAPI) -> httpx.AsyncClient:
    """A client running the app in the test's event loop (the chat's hold is held there)."""
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(CLIENT_IP, 50189))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def _post(
    http: httpx.AsyncClient, account: Account, chat_id: uuid.UUID, ids: list[uuid.UUID]
) -> httpx.Response:
    return await http.post(_PATH.format(chat_id=chat_id), headers=account.cookie, json=_body(ids))


def _answer(response: httpx.Response) -> tuple[int, Any]:
    return response.status_code, response.json()


def _state(world: World) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Every table and what the chat runtime holds."""
    return world.db.snapshot(), chat_runtime_state(world.db)


def _changed(world: World, before: tuple[dict[str, Any], dict[str, Any] | None]) -> list[str]:
    """The tables (and ``runtime``) that differ from ``before``."""
    tables, runtime = _state(world)
    changed = [name for name, rows in tables.items() if rows != before[0].get(name)]
    return [*changed, "runtime"] if runtime != before[1] else changed


def _app_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """Every captured app record (not the client's httpx lines or event loop setup)."""
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
    parts.extend(str(value) for value in (record.exc_text, record.stack_info) if value)
    parts.extend(
        repr(value) for key, value in vars(record).items() if key not in _STANDARD_RECORD_ATTRS
    )
    return "\n".join(parts)


def _leaks(records: list[logging.LogRecord], needles: tuple[str, ...]) -> list[str]:
    """The records holding any needle, raw or JSON-escaped."""
    forms = {form for needle in needles for form in (needle, json.dumps(needle)[1:-1])}
    return [
        record.getMessage()
        for record in records
        if any(form in _record_text(record) for form in forms)
    ]


def _passed(script: _Script) -> list[uuid.UUID]:
    """The attachment ids the one run got, in order."""
    (run,) = script.runs
    return [plain(attachment.id) for attachment in run["attachments"]]


# ---------------------------------------------------------------------------
# The refusal cases (Decision 7)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Scene:
    """A refused send: the chat, the listed ids and the expected (status, body)."""

    chat_id: uuid.UUID
    ids: list[uuid.UUID]
    expected: tuple[int, dict[str, str]]


_REFUSALS: Final = (
    "not-ready-uploaded",
    "not-ready-processing",
    "not-ready-failed",
    "storage-missing",
    "storage-broken-manifest",
    "earlier-storage-missing",
    "earlier-storage-broken-manifest",
    "image-png",
    "image-in-pdf",
    "earlier-image-with-text-file",
    "earlier-image-no-files",
)


def _refusal(world: World, root: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> _Scene:
    """Seed one refusal case in a new chat of the Editor of org A."""
    db = world.db
    chat_id = _chat(db, world.a["editor"])
    later = _PAST + timedelta(hours=1)
    if case.startswith("not-ready-"):
        status = case.removeprefix("not-ready-")
        return _Scene(chat_id, [_file(db, root, chat_id, status=status)], (409, _NOT_READY))
    if case.startswith("storage-"):
        file_id = _file(db, root, chat_id)
        _break(db, root, chat_id, file_id, "missing" if case == "storage-missing" else "manifest")
        return _Scene(chat_id, [file_id], (503, _STORAGE_UNAVAILABLE))
    if case.startswith("earlier-storage-"):
        earlier = _sent_earlier(db, root, chat_id, "pdf")
        how = "missing" if case == "earlier-storage-missing" else "manifest"
        _break(db, root, chat_id, earlier, how)
        # The missing case sends text only; the manifest case also lists a sound file.
        ids = [] if how == "missing" else [_file(db, root, chat_id, "txt", created_at=later)]
        return _Scene(chat_id, ids, (503, _STORAGE_UNAVAILABLE))
    _image_input(monkeypatch, db, enabled=False)
    if case == "image-png":
        ids = [_file(db, root, chat_id, "png")]
    elif case == "image-in-pdf":
        ids = [_file(db, root, chat_id, "pdf-with-image")]
    else:
        _sent_earlier(db, root, chat_id, "png")
        listed = case == "earlier-image-with-text-file"
        ids = [_file(db, root, chat_id, "txt", created_at=later)] if listed else []
    return _Scene(chat_id, ids, (422, _IMAGE_UNSUPPORTED))


@pytest.mark.parametrize("case", _REFUSALS)
def test_chat_send_rules_refusal_is_the_fixed_body_and_changes_nothing(
    world: World,
    client: TestClient,
    script: _Script,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    """Exactly the fixed body; no run; every table unchanged (no message stored, no file
    linked, no audit row) and the chat's pending confirmation kept."""
    editor = world.a["editor"]
    scene = _refusal(world, root, monkeypatch, case)
    pending = seed_pending_confirmation(editor, scene.chat_id, _CONFIRMATION_ID)
    before = _state(world)

    response = _send(client, editor, scene.chat_id, scene.ids)

    assert _answer(response) == scene.expected
    assert (script.runs, _changed(world, before)) == ([], [])
    assert server._chat_runtime.get_pending(scene.chat_id) == pending


@pytest.mark.parametrize("case", _REFUSALS)
def test_chat_send_rules_refusal_with_event_stream_is_the_same_json(
    world: World,
    client: TestClient,
    script: _Script,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    """With ``Accept: text/event-stream`` the refusal is the same JSON (status, body,
    content type), with no run and nothing changed."""
    scene = _refusal(world, root, monkeypatch, case)
    before = world.db.snapshot()

    response = _send(client, world.a["editor"], scene.chat_id, scene.ids, sse=True)

    content_type = response.headers["content-type"].split(";")[0]
    body = response.json() if content_type == "application/json" else response.text
    assert (response.status_code, body, content_type) == (*scene.expected, "application/json")
    assert (script.runs, world.db.snapshot() == before) == ([], True)


@pytest.mark.parametrize("case", _REFUSALS)
def test_chat_send_rules_refusal_logs_no_name_path_or_content(
    world: World,
    client: TestClient,
    script: _Script,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    case: str,
) -> None:
    """Every logger at DEBUG: the refusal's records hold no file name, no path under the
    attachments root and none of the files' text or manifest bytes."""
    scene = _refusal(world, root, monkeypatch, case)
    caplog.set_level(logging.DEBUG)
    caplog.clear()

    response = _send(client, world.a["editor"], scene.chat_id, scene.ids)

    needles = (_NAME_MARK, _TEXT_MARK, _MANIFEST_MARK, str(root))
    assert (_answer(response), _leaks(_app_records(caplog), needles)) == (scene.expected, [])
    assert script.runs == []


# ---------------------------------------------------------------------------
# The order of the file checks
# ---------------------------------------------------------------------------

# The listed files, in order, and the answer; the not-ready file alone is then 409.
_ORDER_CASES: Final[dict[str, tuple[tuple[str, ...], tuple[int, dict[str, str]]]]] = {
    "not-found-first": (("unknown", "sent", "not-ready"), (404, _NOT_FOUND)),
    "already-sent-before-not-ready": (("sent", "not-ready"), (409, _ALREADY_SENT)),
}


@pytest.mark.parametrize("order", ["listed", "reversed"])
@pytest.mark.parametrize("case", list(_ORDER_CASES))
def test_chat_send_rules_not_found_beats_already_sent_beats_not_ready(
    world: World, client: TestClient, script: _Script, root: Path, case: str, order: str
) -> None:
    """An unknown id beats a sent file and a not-ready one (404); a sent file beats a
    not-ready one (409 ``attachment_already_sent``), whatever the id order; the not-ready
    file alone is then the 409 ``attachment_not_ready``. No run."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    files = {
        "unknown": _UNKNOWN,
        "sent": _sent_earlier(db, root, chat_id, "pdf"),
        "not-ready": _file(db, root, chat_id, status="processing"),
    }
    names, expected = _ORDER_CASES[case]
    ids = [files[name] for name in (names if order == "listed" else reversed(names))]

    response = _send(client, editor, chat_id, ids)
    alone = _send(client, editor, chat_id, [files["not-ready"]])

    assert (_answer(response), _answer(alone)) == (expected, (409, _NOT_READY))
    assert script.runs == []


@pytest.mark.parametrize("order", ["ready-first", "not-ready-first"])
def test_chat_send_rules_ready_file_beside_a_not_ready_one_is_409(
    world: World, client: TestClient, script: _Script, root: Path, order: str
) -> None:
    """A ready file listed beside an uploaded one, in either order: the 409
    ``attachment_not_ready``; neither file is linked, no run, no message."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    ready = _file(db, root, chat_id)
    waiting = _file(db, root, chat_id, status="uploaded")
    ids = [ready, waiting] if order == "ready-first" else [waiting, ready]

    response = _send(client, editor, chat_id, ids)

    assert _answer(response) == (409, _NOT_READY)
    assert (script.runs, db.messages_of(chat_id), _linked_to(db, ready)) == ([], [], None)


async def test_chat_send_rules_not_ready_is_answered_before_the_chats_hold(
    world: World, agent: MagicMock, script: _Script, root: Path
) -> None:
    """While the chat is held (a run going), a not-ready file is still the 409
    ``attachment_not_ready`` (checked before the hold); a ready file is ``run_active``."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    waiting = _file(db, root, chat_id, status="processing")
    ready = _file(db, root, chat_id)
    app = make_app(agent)

    async with _async_client(app) as http, server._chat_runtime.hold(chat_id, editor.user_id):
        not_ready = await _post(http, editor, chat_id, [waiting])
        busy = await _post(http, editor, chat_id, [ready])

    assert [_answer(not_ready), _answer(busy)] == [(409, _NOT_READY), (409, _RUN_ACTIVE)]
    assert script.runs == []


@pytest.mark.parametrize("case", ["storage-missing", "image-png"])
async def test_chat_send_rules_storage_and_image_checks_come_under_the_hold(
    world: World,
    agent: MagicMock,
    script: _Script,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    """While the chat is held, a send whose file would be the 503 or the 422 is
    ``run_active`` (those checks run under the hold); once the hold is free it gets its
    own refusal. No run."""
    scene = _refusal(world, root, monkeypatch, case)
    editor = world.a["editor"]
    app = make_app(agent)

    async with _async_client(app) as http:
        async with server._chat_runtime.hold(scene.chat_id, editor.user_id):
            busy = await _post(http, editor, scene.chat_id, scene.ids)
        free = await _post(http, editor, scene.chat_id, scene.ids)

    assert [_answer(busy), _answer(free)] == [(409, _RUN_ACTIVE), scene.expected]
    assert script.runs == []


@pytest.mark.parametrize("case", ["other-file-broken", "image-file-broken"])
def test_chat_send_rules_storage_unavailable_comes_before_image_input_unsupported(
    world: World,
    client: TestClient,
    script: _Script,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    """``image_input`` false and an image listed: a broken derived directory (another
    listed file's, or the image's own) is the 503, not the 422. No run."""
    db = world.db
    _image_input(monkeypatch, db, enabled=False)
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    image = _file(db, root, chat_id, "png")
    if case == "other-file-broken":
        other = _file(db, root, chat_id, created_at=_PAST + timedelta(hours=1))
        _break(db, root, chat_id, other, "missing")
        ids = [image, other]
    else:
        _break(db, root, chat_id, image, "missing")
        ids = [image]

    response = _send(client, editor, chat_id, ids)

    assert (_answer(response), script.runs) == ((503, _STORAGE_UNAVAILABLE), [])


# ---------------------------------------------------------------------------
# Accepted sends
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sse", [False, True], ids=["json", "sse"])
def test_chat_send_rules_ready_file_is_linked_and_passed_to_the_run(
    world: World, client: TestClient, script: _Script, root: Path, sse: bool
) -> None:
    """A ready PDF with its derived files: 200, the file linked to the stored user message,
    and the run gets it (id, kind, page count, its converted text)."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    file_id = _file(db, root, chat_id)

    response = _send(client, editor, chat_id, [file_id], sse=sse)

    assert response.status_code == 200, response.text
    (user_message,) = [row["id"] for row in db.messages_of(chat_id) if row["role"] == "user"]
    assert _linked_to(db, file_id) == plain(user_message)
    assert _passed(script) == [file_id]
    (passed,) = script.runs[0]["attachments"]
    texts = [part.text for part in passed.parts if part.type == "text"]
    assert (passed.kind, passed.page_count) == ("pdf", 2)
    assert any(_TEXT_MARK in text for text in texts), texts


def test_chat_send_rules_image_input_off_accepts_text_only_files(
    world: World,
    client: TestClient,
    script: _Script,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``image_input`` false, an earlier sent text file and a PDF and a text file listed
    (no image part anywhere): the run happens with all three, in upload order."""
    db = world.db
    _image_input(monkeypatch, db, enabled=False)
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    earlier = _sent_earlier(db, root, chat_id, "txt")
    pdf = _file(db, root, chat_id, "pdf", created_at=_PAST + timedelta(hours=1))
    txt = _file(db, root, chat_id, "txt", created_at=_PAST + timedelta(hours=2))

    response = _send(client, editor, chat_id, [txt, pdf])

    assert response.status_code == 200, response.text
    assert _passed(script) == [earlier, pdf, txt]


def test_chat_send_rules_image_input_on_accepts_image_files(
    world: World,
    client: TestClient,
    script: _Script,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``image_input`` true: a PNG and a PDF holding an image run; the run gets both, each
    with an image part."""
    db = world.db
    _image_input(monkeypatch, db, enabled=True)
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    png = _file(db, root, chat_id, "png")
    pdf = _file(db, root, chat_id, "pdf-with-image", created_at=_PAST + timedelta(hours=1))

    response = _send(client, editor, chat_id, [png, pdf])

    assert response.status_code == 200, response.text
    (run,) = script.runs
    assert [(plain(item.id), item.has_images) for item in run["attachments"]] == [
        (png, True),
        (pdf, True),
    ]


@pytest.mark.parametrize("case", ["other-chat", "trashed", "unlisted"])
def test_chat_send_rules_files_outside_the_active_set_are_not_read(
    world: World, client: TestClient, script: _Script, root: Path, case: str
) -> None:
    """A broken derived directory of a file outside the chat's active set (sent in another
    chat of the caller, sent here but trashed, or unsent here and not listed) refuses
    nothing: the listed file runs alone."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    if case == "other-chat":
        elsewhere = _chat(db, editor)
        broken = _sent_earlier(db, root, elsewhere, "pdf")
        _break(db, root, elsewhere, broken, "missing")
    elif case == "trashed":
        broken = _sent_earlier(db, root, chat_id, "pdf", deleted_at=_PAST)
        _break(db, root, chat_id, broken, "missing")
    else:
        broken = _file(db, root, chat_id)
        _break(db, root, chat_id, broken, "missing")
    listed = _file(db, root, chat_id, "txt", created_at=_PAST + timedelta(hours=1))

    response = _send(client, editor, chat_id, [listed])

    assert response.status_code == 200, response.text
    assert _passed(script) == [listed]


# ---------------------------------------------------------------------------
# OpenAPI
# ---------------------------------------------------------------------------


def _responses() -> dict[str, Any]:
    responses: dict[str, Any] = make_app().openapi()["paths"][_PATH]["post"]["responses"]
    return responses


def _documented_bodies(response: dict[str, Any]) -> list[Any]:
    """The JSON example and every named example's value of a documented response."""
    media = response.get("content", {}).get("application/json", {})
    bodies = [media["example"]] if "example" in media else []
    return [*bodies, *(item.get("value") for item in media.get("examples", {}).values())]


def test_chat_send_rules_openapi_documents_the_new_codes() -> None:
    """The 409 names ``attachment_not_ready`` beside ``run_active`` and
    ``attachment_already_sent``; the 422 names ``image_input_unsupported`` (beside
    ``message_empty``); the 503 names ``storage_unavailable``."""
    responses = _responses()
    described = {code: responses.get(code, {}).get("description", "") for code in responses}
    codes_409 = ("run_active", "attachment_already_sent", "attachment_not_ready")

    assert (
        [code for code in codes_409 if code in described.get("409", "")],
        [code for code in ("message_empty", "image_input_unsupported") if code in described["422"]],
        "storage_unavailable" in described.get("503", ""),
    ) == (list(codes_409), ["message_empty", "image_input_unsupported"], True)


def test_chat_send_rules_openapi_shows_the_409_and_503_bodies() -> None:
    """The documented 409 shows the ``attachment_not_ready`` body and the 503 the
    ``storage_unavailable`` body (as the example or one of the named examples)."""
    responses = _responses()

    assert (
        _NOT_READY in _documented_bodies(responses.get("409", {})),
        _STORAGE_UNAVAILABLE in _documented_bodies(responses.get("503", {})),
    ) == (True, True)
