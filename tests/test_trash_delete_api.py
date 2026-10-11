"""HTTP spec of deleting a chat or one file into the trash, or for good at retention 0 (GH-194).

Issue #194, Decisions 1 (owner-only scope), 2 (trash groups), 3 (deleting one
file), 4 (retention), 5 (retention 0) and 9 (audit); contract §2, §4
(``trash.delete_chat`` / ``trash.delete_attachment``), §6 and §7. Tracker #139
§5: every role, another org's and a colleague's item, CSRF, the per-user rate
limit, content-free audit rows and logs.

Routes: ``DELETE /api/attachments/{attachment_id}`` (new) and
``DELETE /api/chats/{chat_id}`` (now through ``trash.delete_chat``).

Harness: the FakeDb world of tests/tenancy_world.py behind ``create_app()``,
the attachments root under ``tmp_path``; the helpers (seeding with
``<id>``, ``<id>.part`` and ``<id>.d/`` on disk, state snapshots, audit tuples)
come from tests/test_trash_api.py. The agent is a stub that must not run.

What is pinned:
- Retention above 0: 204 with no body; the item is trashed (a file as its own
  group; a chat as its own group with its live files in the chat's group,
  while a file deleted on its own before keeps its group and stamp); the files
  stay on disk; one ``file.delete`` / ``chat.delete`` row (member, org, the
  id, the client IP, no metadata); the item is then listed by
  ``GET /api/trash`` and restorable. A deleted file is 404 on
  ``GET /api/attachments/{id}``, gone from its chat's list and its message's
  ``attachment_ids``, and a send naming it is the 404 ``attachment_not_found``.
  Any status, sent or not. The chat's pending confirmation is dropped.
- Retention 0 (the org's 0 within the bounds; a platform minimum above 0 wins):
  204, and the rows and the files (``<id>``, ``<id>.part``, ``<id>.d/``) are gone
  when the response arrives; the events are the delete then the purge, both by
  the member (``chat.purge`` with ``file_count``); a chat's pending confirmation
  is dropped too. A purge step that fails (its audit write refused) still
  answers 204, leaves the item trashed with its files, and logs a content-free
  warning. An org retention of 1 (the smallest above 0) only trashes, like any
  retention above 0 (review round 1, Suggestion 1).
- 404 ``attachment_not_found`` / ``chat_not_found`` (exact) for another org's, a
  colleague's (an Org Admin's request on an Editor's item included), an unknown,
  an already trashed item and a file of a trashed chat, nothing changed (rows,
  files, audit), at retention 0 too; a non-UUID id 422.
- Roles (``chat.send``): Org Admin and Editor may, the Super Admin 403,
  no session 401; CSRF; the ``/api/attachments/delete`` bucket (0.5, 5) per user
  and ``/api/chats/delete`` unchanged; the route's declared 204.
- No log record carries a title or a file name.

Security notes: every id, title, name and byte here is a fixed fake under
``tmp_path``. No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import server
from tests.db_fakes import ORG_ID, FakeDb
from tests.tenancy_world import (
    ATTACHMENT_NOT_FOUND,
    CHAT_NOT_FOUND,
    FORBIDDEN,
    UNAUTHORIZED,
    build_world,
    make_app,
    make_client,
    seed_pending_confirmation,
    stub_agent,
    use_attachment_storage,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)
from tests.test_trash_api import (
    _CSRF_REFUSED,
    _ECHO,
    _FOREIGN,
    _FOREIGN_ORIGIN,
    _GONE,
    _KEPT,
    _MARK,
    _RATE_LIMITED,
    _SAME_ORIGIN,
    _ago,
    _app_records,
    _chat,
    _event,
    _events,
    _file,
    _ids,
    _on_disk,
    _outcome,
    _record_text,
    _restore_chat,
    _restore_file,
    _set_bounds,
    _set_retention,
    _state,
    _trash_columns,
)

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

    import httpx
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, MemberRole, World

_CONFIRMATION_ID: Final = "confirm-194-trash"


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
def agent() -> MagicMock:
    """A stub agent (no test here lets it run)."""
    return stub_agent()


@pytest.fixture()
def client(world: World, agent: MagicMock) -> TestClient:
    """The app (built after the world: create_app clears the runtime)."""
    return make_client(make_app(agent))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _delete_file(
    client: TestClient, caller: Account | None, file_id: uuid.UUID | str, **headers: str
) -> httpx.Response:
    cookie = dict(caller.cookie) if caller is not None else {}
    return client.delete(f"/api/attachments/{file_id}", headers={**cookie, **headers})


def _delete_chat(
    client: TestClient, caller: Account | None, chat_id: uuid.UUID | str, **headers: str
) -> httpx.Response:
    cookie = dict(caller.cookie) if caller is not None else {}
    return client.delete(f"/api/chats/{chat_id}", headers={**cookie, **headers})


def _deleted(response: httpx.Response) -> tuple[int, bytes]:
    return response.status_code, response.content


def _foreign_live_file(world: World, case: str) -> tuple[Account, uuid.UUID]:
    """(caller, a live file that isn't the caller's own, or an unknown id)."""
    a, b = world.a, world.b
    if case == "other-org":
        owner, caller = b["editor"], a["editor"]
    elif case == "colleague":
        owner, caller = a["org_admin"], a["editor"]
    elif case == "org-admin-on-editors":
        owner, caller = a["editor"], a["org_admin"]
    else:
        return a["editor"], uuid.uuid4()
    return caller, _file(world.db, _chat(world.db, owner))


def _foreign_live_chat(world: World, case: str) -> tuple[Account, uuid.UUID]:
    """(caller, a live chat with a file that isn't the caller's own, or an unknown id)."""
    a, b = world.a, world.b
    if case == "other-org":
        owner, caller = b["editor"], a["editor"]
    elif case == "colleague":
        owner, caller = a["org_admin"], a["editor"]
    elif case == "org-admin-on-editors":
        owner, caller = a["editor"], a["org_admin"]
    else:
        return a["editor"], uuid.uuid4()
    chat_id = _chat(world.db, owner)
    _file(world.db, chat_id)
    return caller, chat_id


def _trash_warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """The WARNING records of ``admino.trash``."""
    return [
        record
        for record in caplog.records
        if record.name == "admino.trash" and record.levelno == logging.WARNING
    ]


def _leaks(caplog: pytest.LogCaptureFixture) -> list[str]:
    """App log records holding the title / file name canary."""
    return [
        record.getMessage()
        for record in _app_records(caplog)
        if _MARK in _record_text(record) or json.dumps(_MARK)[1:-1] in _record_text(record)
    ]


# ---------------------------------------------------------------------------
# 1. DELETE /api/attachments/{attachment_id}, retention above 0
# ---------------------------------------------------------------------------


_STATUSES: Final = [
    pytest.param({"status": "uploaded"}, False, id="uploaded-unsent"),
    pytest.param({"status": "processing"}, False, id="processing-unsent"),
    pytest.param(
        {"status": "ready", "token_estimate": 40, "derived_bytes": 256}, True, id="ready-sent"
    ),
    pytest.param(
        {"status": "failed", "failure_reason": "corrupted_file"}, False, id="failed-unsent"
    ),
]


class TestDeleteAttachment:
    """One file to the trash: its own group, files kept, audited, restorable."""

    @pytest.mark.parametrize(("fields", "sent"), _STATUSES)
    def test_trash_delete_attachment_moves_the_file_to_the_trash_as_its_own_item(
        self,
        world: World,
        root: Path,
        client: TestClient,
        fields: dict[str, Any],
        sent: bool,
    ) -> None:
        """204 with no body for any status, sent or not: the row trashed as its own group,
        its three entries kept on disk, one content-free ``file.delete``; then listed by
        ``GET /api/trash`` as an attachment of its chat and restorable."""
        db, editor = world.db, world.a["editor"]
        chat_id = _chat(db, editor)
        message = db.add_chat_message(chat_id, "user", "With a file 194") if sent else None
        file_id = _file(db, chat_id, message_id=message, **fields)

        response = _delete_file(client, editor, file_id)

        assert _deleted(response) == (204, b""), response.text
        assert _trash_columns(db.attachment_row(file_id)) == (True, str(file_id))
        assert _on_disk(root, ORG_ID, file_id) == _KEPT
        assert _events(db) == [_event("file.delete", editor, file_id)]
        assert _MARK.casefold() not in repr(db.audit_rows()).casefold()
        listed = client.get("/api/trash", headers=editor.cookie)
        assert _ids(listed) == [str(file_id)]
        assert listed.json()["items"][0]["chat_id"] == str(chat_id)
        restored = _restore_file(client, editor, file_id)
        assert restored.status_code == 200, restored.text
        assert _trash_columns(db.attachment_row(file_id)) == (False, None)

    def test_trash_delete_attachment_is_no_longer_read_listed_or_sent(
        self, world: World, client: TestClient, agent: MagicMock
    ) -> None:
        """After deleting a sent and an unsent file: both are 404 on
        ``GET /api/attachments/{id}``, the chat's list is empty, the message lists no
        file, and a send naming the unsent one is the 404 ``attachment_not_found``
        with no run."""
        db, editor = world.db, world.a["editor"]
        chat_id = _chat(db, editor)
        message = db.add_chat_message(chat_id, "user", "With a file 194")
        db.add_chat_message(chat_id, "assistant", "Noted 194.")
        sent = _file(db, chat_id, message_id=message)
        unsent = _file(db, chat_id)

        deleted = [_delete_file(client, editor, sent), _delete_file(client, editor, unsent)]
        reads = [
            client.get(f"/api/attachments/{file_id}", headers=editor.cookie)
            for file_id in (sent, unsent)
        ]
        listed = client.get(f"/api/chats/{chat_id}/attachments", headers=editor.cookie)
        detail = client.get(f"/api/chats/{chat_id}", headers=editor.cookie)
        send = client.post(
            f"/api/chats/{chat_id}/messages",
            headers=editor.cookie,
            json={"message": "Read this 194", "attachment_ids": [str(unsent)]},
        )

        assert [response.status_code for response in deleted] == [204, 204]
        assert [_outcome(read) for read in reads] == [(404, ATTACHMENT_NOT_FOUND)] * 2
        assert listed.status_code == 200, listed.text
        assert listed.json()["attachments"] == []
        assert detail.status_code == 200, detail.text
        assert [m["attachment_ids"] for m in detail.json()["messages"]] == [[], []]
        assert _outcome(send) == (404, ATTACHMENT_NOT_FOUND)
        agent.run.assert_not_awaited()

    @pytest.mark.parametrize("case", [*_FOREIGN, "already-trashed", "file-of-a-trashed-chat"])
    def test_trash_delete_attachment_not_the_callers_live_file_is_404_and_changes_nothing(
        self, world: World, client: TestClient, case: str
    ) -> None:
        """Another org's, a colleague's, an Editor's for the Org Admin, an unknown, an
        already trashed file and a file of a trashed chat: 404 ``attachment_not_found``,
        the id not echoed, nothing changed (rows, files, audit)."""
        if case == "already-trashed":
            caller = world.a["editor"]
            file_id = _file(world.db, _chat(world.db, caller), deleted_at=_ago(hours=1))
        elif case == "file-of-a-trashed-chat":
            caller = world.a["editor"]
            chat_id = _chat(world.db, caller, deleted_at=_ago(hours=1))
            file_id = _file(world.db, chat_id, deleted_at=_ago(hours=1))
        else:
            caller, file_id = _foreign_live_file(world, case)
        before = _state(world.db)

        response = _delete_file(client, caller, file_id)

        assert _outcome(response) == (404, ATTACHMENT_NOT_FOUND)
        assert str(file_id) not in response.text
        assert _state(world.db) == before


# ---------------------------------------------------------------------------
# 2. DELETE /api/chats/{chat_id}, retention above 0
# ---------------------------------------------------------------------------


class TestDeleteChat:
    """A chat to the trash with its live files as its group; restorable."""

    def test_trash_delete_chat_trashes_the_chat_and_its_live_files_as_one_group(
        self, world: World, root: Path, client: TestClient
    ) -> None:
        """204: the chat is its own group, its live files carry the chat's id, a file
        deleted on its own before keeps its group and stamp; every file stays on disk;
        one ``chat.delete``; listed (the chat and the earlier file); the chat's restore
        brings back its group only."""
        db, editor = world.db, world.a["editor"]
        chat_id = _chat(db, editor)
        grouped = _file(db, chat_id)
        solo = _file(db, chat_id, deleted_at=_ago(hours=5))
        solo_row = db.attachment_row(solo)
        assert solo_row is not None

        response = _delete_chat(client, editor, chat_id)

        assert _deleted(response) == (204, b""), response.text
        assert _trash_columns(db.chat_row(chat_id)) == (True, str(chat_id))
        assert _trash_columns(db.attachment_row(grouped)) == (True, str(chat_id))
        assert db.attachment_row(solo) == solo_row
        assert _on_disk(root, ORG_ID, grouped) == _KEPT
        assert _on_disk(root, ORG_ID, solo) == _KEPT
        assert _events(db) == [_event("chat.delete", editor, chat_id)]
        assert _ids(client.get("/api/trash", headers=editor.cookie)) == [str(chat_id), str(solo)]
        restored = _restore_chat(client, editor, chat_id)
        assert restored.status_code == 200, restored.text
        assert _trash_columns(db.attachment_row(grouped)) == (False, None)
        assert _trash_columns(db.attachment_row(solo)) == (True, str(solo))

    def test_trash_delete_chat_drops_the_chats_pending_confirmation(
        self, world: World, client: TestClient
    ) -> None:
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        seed_pending_confirmation(editor, chat_id, _CONFIRMATION_ID)

        response = _delete_chat(client, editor, chat_id)

        assert response.status_code == 204, response.text
        assert server._chat_runtime.get_pending(chat_id) is None
        assert _trash_columns(world.db.chat_row(chat_id)) == (True, str(chat_id))


# ---------------------------------------------------------------------------
# 3. Retention 0: trash and purge in the same request
# ---------------------------------------------------------------------------


class TestDeleteAtRetentionZero:
    """With an effective retention of 0 both deletes purge at once (Decision 5)."""

    def test_trash_delete_attachment_at_retention_zero_removes_row_and_files(
        self, world: World, root: Path, client: TestClient
    ) -> None:
        """204; the row and its three entries are gone; ``file.delete`` then
        ``file.purge``, both by the member; the trash lists nothing; the chat stays."""
        db, editor = world.db, world.a["editor"]
        _set_retention(db, 0)
        chat_id = _chat(db, editor)
        file_id = _file(db, chat_id)
        kept = _file(db, chat_id)

        response = _delete_file(client, editor, file_id)

        assert _deleted(response) == (204, b""), response.text
        assert db.attachment_row(file_id) is None
        assert _on_disk(root, ORG_ID, file_id) == _GONE
        assert _events(db) == [
            _event("file.delete", editor, file_id),
            _event("file.purge", editor, file_id),
        ]
        assert db.chat_row(chat_id) is not None
        assert _on_disk(root, ORG_ID, kept) == _KEPT
        assert _ids(client.get("/api/trash", headers=editor.cookie)) == []

    def test_trash_delete_chat_at_retention_zero_removes_rows_files_and_confirmation(
        self, world: World, root: Path, client: TestClient
    ) -> None:
        """204; the chat, its messages and every file of the chat (a file deleted on its
        own before included) are gone, rows and disk; ``chat.delete`` then
        ``chat.purge`` (``file_count`` 2), both by the member; the pending confirmation
        is dropped; another chat's file stays."""
        db, editor = world.db, world.a["editor"]
        _set_retention(db, 0)
        chat_id = _chat(db, editor)
        db.add_chat_message(chat_id, "user", "Question 194")
        grouped = _file(db, chat_id)
        solo = _file(db, chat_id, deleted_at=_ago(hours=1))
        other_file = _file(db, _chat(db, editor))
        seed_pending_confirmation(editor, chat_id, _CONFIRMATION_ID)

        response = _delete_chat(client, editor, chat_id)

        assert _deleted(response) == (204, b""), response.text
        assert db.chat_row(chat_id) is None
        assert db.messages_of(chat_id) == []
        assert (db.attachment_row(grouped), db.attachment_row(solo)) == (None, None)
        assert _on_disk(root, ORG_ID, grouped) == _GONE
        assert _on_disk(root, ORG_ID, solo) == _GONE
        assert _on_disk(root, ORG_ID, other_file) == _KEPT
        assert _events(db) == [
            _event("chat.delete", editor, chat_id),
            _event("chat.purge", editor, chat_id, metadata={"file_count": 2}),
        ]
        assert server._chat_runtime.get_pending(chat_id) is None

    @pytest.mark.parametrize("kind", ["chat", "attachment"])
    def test_trash_delete_with_a_platform_minimum_above_zero_only_trashes(
        self,
        world: World,
        root: Path,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        kind: str,
    ) -> None:
        """The org's 0 clamped up to a platform minimum of 3: the item is trashed and
        kept with its files, no purge event."""
        db, editor = world.db, world.a["editor"]
        _set_bounds(monkeypatch, db, low=3, high=90)
        _set_retention(db, 0)
        chat_id = _chat(db, editor)
        file_id = _file(db, chat_id)

        if kind == "chat":
            response = _delete_chat(client, editor, chat_id)
            item_id, row = chat_id, db.chat_row(chat_id)
        else:
            response = _delete_file(client, editor, file_id)
            item_id, row = file_id, db.attachment_row(file_id)

        assert response.status_code == 204, response.text
        assert _trash_columns(row) == (True, str(item_id))
        assert _on_disk(root, ORG_ID, file_id) == _KEPT
        assert [event[0] for event in _events(db)] == [
            f"{'chat' if kind == 'chat' else 'file'}.delete"
        ]

    def test_trash_delete_at_retention_one_only_trashes_the_chat_and_the_file(
        self,
        world: World,
        root: Path,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Review round 1, Suggestion 1: an org retention of 1 (the smallest above 0,
        inside the bounds 0 to 90) is not 0. Deleting a chat and then a file of another
        chat answers 204 each; both are trashed (the chat with its live file as its
        group, the file as its own), every file stays on disk, only the two deletes are
        audited (no purge); ``GET /api/trash`` lists both with ``retention_days`` 1, and
        each restore brings its item back."""
        db, editor = world.db, world.a["editor"]
        _set_bounds(monkeypatch, db, low=0, high=90)
        _set_retention(db, 1)
        chat_id = _chat(db, editor)
        grouped = _file(db, chat_id)
        file_id = _file(db, _chat(db, editor))

        deleted = [_delete_chat(client, editor, chat_id), _delete_file(client, editor, file_id)]
        listed = client.get("/api/trash", headers=editor.cookie)

        assert [_deleted(response) for response in deleted] == [(204, b"")] * 2
        assert [
            _trash_columns(db.chat_row(chat_id)),
            _trash_columns(db.attachment_row(grouped)),
            _trash_columns(db.attachment_row(file_id)),
        ] == [(True, str(chat_id)), (True, str(chat_id)), (True, str(file_id))]
        assert [_on_disk(root, ORG_ID, item) for item in (grouped, file_id)] == [_KEPT] * 2
        assert _events(db) == [
            _event("chat.delete", editor, chat_id),
            _event("file.delete", editor, file_id),
        ]
        assert (sorted(_ids(listed)), listed.json()["retention_days"]) == (
            sorted([str(chat_id), str(file_id)]),
            1,
        )
        restored = [_restore_chat(client, editor, chat_id), _restore_file(client, editor, file_id)]
        assert [response.status_code for response in restored] == [200, 200]
        assert [
            _trash_columns(db.chat_row(chat_id)),
            _trash_columns(db.attachment_row(grouped)),
            _trash_columns(db.attachment_row(file_id)),
        ] == [(False, None)] * 3

    @pytest.mark.parametrize("kind", ["chat", "attachment"])
    def test_trash_delete_at_retention_zero_with_a_failing_purge_still_answers_204(
        self,
        world: World,
        root: Path,
        client: TestClient,
        caplog: pytest.LogCaptureFixture,
        kind: str,
    ) -> None:
        """The purge's audit write is refused: 204 all the same, the item stays trashed
        (its own group) with its files on disk, only the delete event is recorded, the
        chat's confirmation is dropped, and ``admino.trash`` logs a warning without the
        title or the file name."""
        db, editor = world.db, world.a["editor"]
        _set_retention(db, 0)
        chat_id = _chat(db, editor)
        file_id = _file(db, chat_id)
        seed_pending_confirmation(editor, chat_id, _CONFIRMATION_ID)
        db.fail_audit_when = lambda row: row["action"] in ("chat.purge", "file.purge")
        caplog.set_level(logging.DEBUG)

        if kind == "chat":
            response = _delete_chat(client, editor, chat_id)
            item_id, row, action = chat_id, db.chat_row(chat_id), "chat.delete"
        else:
            response = _delete_file(client, editor, file_id)
            item_id, row, action = file_id, db.attachment_row(file_id), "file.delete"

        assert _deleted(response) == (204, b""), response.text
        assert _trash_columns(row) == (True, str(item_id))
        assert _on_disk(root, ORG_ID, file_id) == _KEPT
        assert _events(db) == [_event(action, editor, item_id)]
        if kind == "chat":
            assert server._chat_runtime.get_pending(chat_id) is None
        assert len(_trash_warnings(caplog)) == 1
        assert _leaks(caplog) == []

    @pytest.mark.parametrize("case", [*_FOREIGN, "already-trashed"])
    @pytest.mark.parametrize("kind", ["chat", "attachment"])
    def test_trash_delete_at_retention_zero_not_the_callers_is_404_and_changes_nothing(
        self, world: World, client: TestClient, kind: str, case: str
    ) -> None:
        """At retention 0 too: another org's, a colleague's, an Editor's for the Org Admin,
        an unknown and an already trashed item are the 404, nothing purged; the same
        caller's own live item is then purged at once (retention 0 is in force)."""
        _set_retention(world.db, 0)
        caller = world.a["editor"]
        if case == "already-trashed" and kind == "chat":
            item_id = _chat(world.db, caller, deleted_at=_ago(hours=1))
            _file(world.db, item_id, deleted_at=_ago(hours=1))
        elif case == "already-trashed":
            item_id = _file(world.db, _chat(world.db, caller), deleted_at=_ago(hours=1))
        elif kind == "chat":
            caller, item_id = _foreign_live_chat(world, case)
        else:
            caller, item_id = _foreign_live_file(world, case)
        own_chat = _chat(world.db, caller)
        own_file = _file(world.db, own_chat)
        before = _state(world.db)

        if kind == "chat":
            response = _delete_chat(client, caller, item_id)
            expected = (404, CHAT_NOT_FOUND)
        else:
            response = _delete_file(client, caller, item_id)
            expected = (404, ATTACHMENT_NOT_FOUND)
        after_refusal = _state(world.db)
        if kind == "chat":
            own = _delete_chat(client, caller, own_chat)
            own_row = world.db.chat_row(own_chat)
        else:
            own = _delete_file(client, caller, own_file)
            own_row = world.db.attachment_row(own_file)

        assert _outcome(response) == expected
        assert after_refusal == before
        assert (own.status_code, own_row) == (204, None), own.text


# ---------------------------------------------------------------------------
# 4. DELETE /api/attachments/{attachment_id}: roles, session, CSRF, ids, bucket, model, logs
# ---------------------------------------------------------------------------


class TestDeleteAttachmentGuards:
    """The new route's guards."""

    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    def test_trash_delete_attachment_org_admin_and_editor_may_delete_their_own_file(
        self, world: World, client: TestClient, role: MemberRole
    ) -> None:
        caller = world.a[role]
        file_id = _file(world.db, _chat(world.db, caller))

        response = _delete_file(client, caller, file_id)

        assert response.status_code == 204, response.text
        assert _trash_columns(world.db.attachment_row(file_id)) == (True, str(file_id))

    def test_trash_delete_attachment_super_admin_is_403_and_changes_nothing(
        self, world: World, client: TestClient
    ) -> None:
        """The Super Admin (no ``chat.send``) on an Editor's file: 403 Forbidden, nothing
        changed."""
        file_id = _file(world.db, _chat(world.db, world.a["editor"]))
        before = _state(world.db)

        response = _delete_file(client, world.super_admin, file_id)

        assert _outcome(response) == (403, FORBIDDEN)
        assert _state(world.db) == before

    def test_trash_delete_attachment_without_a_session_is_401_and_changes_nothing(
        self, world: World, client: TestClient
    ) -> None:
        file_id = _file(world.db, _chat(world.db, world.a["editor"]))
        before = _state(world.db)

        response = _delete_file(client, None, file_id)

        assert _outcome(response) == (401, UNAUTHORIZED)
        assert _state(world.db) == before

    def test_trash_delete_attachment_cross_site_is_refused_and_same_origin_succeeds(
        self, world: World, client: TestClient
    ) -> None:
        """A cross-site ``Origin`` and ``Sec-Fetch-Site`` are the CSRF 403 with nothing
        changed; the same DELETE from the app's origin is 204."""
        editor = world.a["editor"]
        file_id = _file(world.db, _chat(world.db, editor))
        before = _state(world.db)

        foreign = _delete_file(client, editor, file_id, Origin=_FOREIGN_ORIGIN)
        fetch_site = _delete_file(client, editor, file_id, **{"Sec-Fetch-Site": "cross-site"})
        after_refusals = _state(world.db)
        accepted = _delete_file(client, editor, file_id, Origin=_SAME_ORIGIN)

        assert [_outcome(foreign), _outcome(fetch_site)] == [(403, _CSRF_REFUSED)] * 2
        assert after_refusals == before
        assert accepted.status_code == 204, accepted.text

    def test_trash_delete_attachment_non_uuid_id_is_422_without_echo(
        self, world: World, client: TestClient
    ) -> None:
        response = _delete_file(client, world.a["editor"], f"{_ECHO}-not-a-uuid")

        assert response.status_code == 422, response.text
        assert _ECHO not in response.text

    def test_trash_delete_rate_limit_keys_have_the_contract_values(self) -> None:
        """``/api/attachments/delete`` (0.5, 5) is new; ``/api/chats/delete`` is unchanged."""
        keys = ("/api/attachments/delete", "/api/chats/delete")
        assert {key: server._RATE_LIMITS.get(key) for key in keys} == {
            "/api/attachments/delete": (0.5, 5),
            "/api/chats/delete": (0.5, 5),
        }

    def test_trash_delete_attachment_rate_limit_is_per_user(
        self, world: World, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Burst 1: the Editor's second DELETE is 429 with nothing changed, a colleague
        still deletes, the bucket is (``/api/attachments/delete``, ``user:<id>``)."""
        key = "/api/attachments/delete"
        monkeypatch.setitem(server._RATE_LIMITS, key, (0.001, 1))
        editor, admin = world.a["editor"], world.a["org_admin"]
        first_id = _file(world.db, _chat(world.db, editor))
        second_id = _file(world.db, _chat(world.db, editor))
        colleague_id = _file(world.db, _chat(world.db, admin))

        first = _delete_file(client, editor, first_id)
        before = _state(world.db)
        limited = _delete_file(client, editor, second_id)
        after = _state(world.db)
        colleague = _delete_file(client, admin, colleague_id)

        assert first.status_code == 204, first.text
        assert _outcome(limited) == (429, _RATE_LIMITED)
        assert after == before
        assert colleague.status_code == 204, colleague.text
        assert (key, f"user:{editor.user_id}") in server._rate_buckets

    def test_trash_delete_routes_declare_204_without_a_response_model(self) -> None:
        """DELETE /api/attachments/{attachment_id} (new) and DELETE /api/chats/{chat_id}."""
        from fastapi.routing import APIRoute

        found = {
            route.path: (route.response_model, route.status_code)
            for route in make_app().routes
            if isinstance(route, APIRoute)
            and "DELETE" in (route.methods or ())
            and route.path in ("/api/attachments/{attachment_id}", "/api/chats/{chat_id}")
        }

        assert found == {
            "/api/attachments/{attachment_id}": (None, 204),
            "/api/chats/{chat_id}": (None, 204),
        }

    @pytest.mark.parametrize("retention", [30, 0])
    def test_trash_delete_logs_carry_no_title_or_file_name(
        self,
        world: World,
        client: TestClient,
        caplog: pytest.LogCaptureFixture,
        retention: int,
    ) -> None:
        """Deleting a file and a chat (trashed, or purged at retention 0): no log record
        holds a title or a file name."""
        db, editor = world.db, world.a["editor"]
        _set_retention(db, retention)
        chat_id = _chat(db, editor)
        _file(db, chat_id)
        file_id = _file(db, _chat(db, editor))
        caplog.set_level(logging.DEBUG)

        statuses = [
            _delete_file(client, editor, file_id).status_code,
            _delete_chat(client, editor, chat_id).status_code,
        ]

        assert statuses == [204, 204]
        assert [event[0] for event in _events(db)][-1].endswith(
            "purge" if retention == 0 else "delete"
        )
        assert _leaks(caplog) == []
