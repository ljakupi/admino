"""HTTP spec of the member's trash routes (GH-194).

Issue #194, Decisions 1 (owner-only scope), 2 (trash groups), 4 (retention and
expiry), 6 (routes), 7 (purge) and 9 (audit); contract §2 (audit events), §3
(``TrashItem``, ``TrashListResponse``, ``TrashEmptyResponse``), §6 (routes,
buckets, error bodies, OpenAPI) and §7 (behaviour pins). Tracker #139 §5: every
role, another org's and a colleague's item, CSRF, a per-user rate limit per
route, 422 without echo, content-free audit rows and logs.

Routes: ``GET /api/trash``, ``POST /api/trash/chats/{chat_id}/restore``,
``POST /api/trash/attachments/{attachment_id}/restore``,
``DELETE /api/trash/chats/{chat_id}``, ``DELETE /api/trash/attachments/{attachment_id}``
and ``DELETE /api/trash``.

Harness: the app from ``create_app()`` runs against the FakeDb world of
tests/tenancy_world.py (orgs A and B with an Org Admin, an Editor and a Viewer
each, plus a Super Admin, real session cookies), with the attachments root
under ``tmp_path``. Trashed rows are seeded with ``FakeDb.add_chat`` /
``add_attachment(deleted_at=...)`` (the fake derives ``trash_group_id`` as
migration 0032's backfill does once it ships) at fixed offsets from now, so
expiry never waits; every seeded file has its original ``<id>``, a partial
``<id>.part`` and a derived ``<id>.d/`` tree on disk. The org's retention is
its ``org_settings`` row; the platform's trash bounds are the settings cache
and row.

What is pinned:
- The list: exactly ``{items, next_cursor, retention_days}``, each item exactly
  ``{item_type, id, name, chat_id, deleted_at, expires_at}``; only the
  caller's own trash items (a chat, a file deleted on its own), never a file
  that went with its chat, a live row, a colleague's or another org's; newest
  deletion first, keyset pages on ``(deleted_at, id)`` (a tie across a page
  included); ``item_type`` filters; expired items hidden; a changed retention
  applies at once; retention 0 lists nothing; the effective retention is the
  org's value clamped into the platform bounds (30 without a row). Listing
  writes nothing.
- Restore: 200 with exactly the ``ChatSummary`` / ``AttachmentSummary``
  (``context_report`` null), the chat's group back (a file deleted on its own
  before stays in the trash), every other column kept, one ``chat.restore`` /
  ``file.restore`` row; the caller's live item is 200 with nothing recorded;
  expired (retention 0 included) is 404; 409 ``chat_in_trash`` and
  ``restore_conflict`` with their exact bodies and nothing changed.
- Delete forever: 204, the rows gone (a chat's messages and every file of the
  chat), each file's ``<id>``, ``<id>.part`` and ``<id>.d/`` gone, one
  ``chat.purge`` (``file_count``) / ``file.purge`` row; expired items too; a
  live item or a file of a chat's group is 404; a refused audit write is a
  500 that removes no row and no file.
- Empty: 200 ``{chats, attachments}`` counting the purged items (chats first, so
  a file deleted on its own inside a purged chat isn't counted twice); a
  colleague's and another org's trash untouched.
- 404 ``chat_not_found`` / ``attachment_not_found`` (exact, the id not echoed)
  for another org's, a colleague's (an Org Admin's request on an Editor's
  item included) and an unknown item, nothing changed (rows, files, audit);
  a non-UUID id 422; ``limit`` 0/101, a bad ``item_type`` and an over-long
  cursor 422 without echo, an undecodable cursor the 422 ``invalid_cursor``.
- Roles: the Org Admin and the Editor may; the Viewer and the Super Admin get
  403 with nothing changed; no session 401. CSRF on every state change.
- Each route's own per-user bucket with the contract's (rate, burst).
- OpenAPI: each route's response model and status, the two restore routes'
  409 with one example per code.
- No log record carries a title or a file name.

New names (models, ``admino.trash``) are looked up at test time, so the file
collects before GH-194 is implemented.

Security notes: every id, title, name and byte here is a fixed fake under
``tmp_path``. No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import organizations, scoped_settings, server
from tests.conftest import default_test_platform_settings
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, plain
from tests.tenancy_world import (
    ATTACHMENT_NOT_FOUND,
    CHAT_NOT_FOUND,
    CLIENT_IP,
    FORBIDDEN,
    UNAUTHORIZED,
    attachment_files,
    build_world,
    make_app,
    make_client,
    seed_attachment,
    use_attachment_storage,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    import httpx
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, MemberRole, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CHAT_IN_TRASH: Final = {"detail": "The file's chat is in the trash", "reason": "chat_in_trash"}
_RESTORE_CONFLICT: Final = {
    "detail": "A live chat already uses this chat's session",
    "reason": "restore_conflict",
}
_INVALID_CURSOR: Final = {"detail": "Invalid cursor", "reason": "invalid_cursor"}
_CSRF_REFUSED: Final = {"detail": "Cross-origin request refused"}
_RATE_LIMITED: Final = {"detail": "Rate limit exceeded"}
_FOREIGN_ORIGIN: Final = "https://evil.example"
# TestClient sends ``Host: testserver``: an Origin with that host is same-origin.
_SAME_ORIGIN: Final = "http://testserver"

# Content canaries: a chat title and a file name (never in a log record or an audit row).
_MARK: Final = "Kestrelvault"
_TITLE: Final = f"{_MARK} Mandat 194"
_NAME: Final = f"{_MARK} Beleg 194.txt"
# A value marker: a 422 never repeats it.
_ECHO: Final = "ECHOMARK194"

_ITEM_KEYS: Final = frozenset({"item_type", "id", "name", "chat_id", "deleted_at", "expires_at"})
_CHAT_SUMMARY_KEYS: Final = frozenset(
    {"id", "title", "title_source", "created_at", "last_activity_at"}
)
_ATTACHMENT_SUMMARY_KEYS: Final = frozenset(
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
_TRASH_ACTIONS: Final = frozenset(
    {"chat.delete", "file.delete", "chat.restore", "file.restore", "chat.purge", "file.purge"}
)

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
    """Orgs A and B (OA/ED/VI each) and a Super Admin behind the fake database, the
    attachments root at ``root``, every rate-limit bucket roomy."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    use_attachment_storage(monkeypatch, built, root)
    return built


@pytest.fixture()
def client(world: World) -> TestClient:
    """The app (built after the world: create_app clears the runtime)."""
    return make_client(make_app())


@pytest.fixture()
def lenient_client(world: World) -> TestClient:
    """The app, answering a server error as a 500 instead of raising it."""
    return make_client(make_app(), raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helpers: time, retention, seeding
# ---------------------------------------------------------------------------


def _ago(*, days: float = 0, hours: float = 0) -> datetime:
    """An aware UTC timestamp ``days`` and ``hours`` before now."""
    return datetime.now(UTC) - timedelta(days=days, hours=hours)


def _org_settings_key(db: FakeDb, org_id: uuid.UUID) -> Any:
    """The key of the org's stored org_settings row."""
    (key,) = [key for key in db.org_settings if str(key) == str(org_id)]
    return key


def _set_retention(db: FakeDb, days: int, org_id: uuid.UUID = ORG_ID) -> None:
    """The org's stored ``trash_retention_days`` (its row, as a PATCH would leave it)."""
    db.org_settings[_org_settings_key(db, org_id)]["trash_retention_days"] = days


def _set_bounds(monkeypatch: pytest.MonkeyPatch, db: FakeDb, *, low: int, high: int) -> None:
    """The platform's trash bounds: in the settings cache and the row."""
    stored = default_test_platform_settings()
    retention = stored.retention.model_copy(update={"trash_min_days": low, "trash_max_days": high})
    monkeypatch.setattr(
        scoped_settings, "_platform_cache", stored.model_copy(update={"retention": retention})
    )
    row = db.platform_row()
    assert row is not None
    row["trash_min_days"], row["trash_max_days"] = low, high


def _org_of(db: FakeDb, chat_id: uuid.UUID) -> uuid.UUID:
    chat = db.chat_row(chat_id)
    assert chat is not None
    return plain(chat["org_id"])


def _chat(
    db: FakeDb,
    owner: Account,
    *,
    deleted_at: datetime | None = None,
    title: str = _TITLE,
    **fields: Any,
) -> uuid.UUID:
    """A chat of ``owner`` (trashed when ``deleted_at`` is given: its own trash group)."""
    return db.add_chat(
        owner.user_id,
        title=title,
        title_source="user" if title else "auto",
        deleted_at=deleted_at,
        **fields,
    )


def _file(db: FakeDb, chat_id: uuid.UUID, *, name: str = _NAME, **fields: Any) -> uuid.UUID:
    """An attachment of the chat with ``<id>``, ``<id>.part`` and ``<id>.d/`` on disk.

    ``fields`` go to ``add_attachment`` (deleted_at: the chat's group when the chat
    is trashed, else the file's own; status, message_id, active, trash_group_id).
    """
    file_id = seed_attachment(db, chat_id, filename=name, **fields)
    org_dir = Path(organizations.ATTACHMENTS_ROOT) / str(_org_of(db, chat_id))
    (org_dir / f"{file_id}.part").write_bytes(b"Partial upload 194\n")
    derived = org_dir / f"{file_id}.d"
    derived.mkdir()
    (derived / "text.txt").write_text("Derived text 194\n")
    (derived / "page-1.png").write_bytes(b"\x89PNG 194")
    return file_id


def _on_disk(root: Path, org_id: uuid.UUID, file_id: uuid.UUID) -> dict[str, bool]:
    """Which of the file's three entries exist."""
    base = root / str(org_id)
    return {
        "original": (base / str(file_id)).exists(),
        "part": (base / f"{file_id}.part").exists(),
        "derived": (base / f"{file_id}.d").exists(),
    }


_GONE: Final = {"original": False, "part": False, "derived": False}
_KEPT: Final = {"original": True, "part": True, "derived": True}


def _solo_file_in_trashed_chat(
    db: FakeDb, owner: Account, *, chat_at: datetime, file_at: datetime
) -> tuple[uuid.UUID, uuid.UUID]:
    """A trashed chat holding a file deleted on its own before it: (chat, file)."""
    chat_id = _chat(db, owner, deleted_at=chat_at)
    file_id = uuid.uuid4()
    _file(db, chat_id, attachment_id=file_id, deleted_at=file_at, trash_group_id=file_id)
    return chat_id, file_id


# ---------------------------------------------------------------------------
# Helpers: requests and state
# ---------------------------------------------------------------------------


def _list(client: TestClient, caller: Account, **params: Any) -> httpx.Response:
    return client.get("/api/trash", params=params, headers=caller.cookie)


def _restore_chat(
    client: TestClient, caller: Account, chat_id: uuid.UUID | str, **headers: str
) -> httpx.Response:
    return client.post(f"/api/trash/chats/{chat_id}/restore", headers={**caller.cookie, **headers})


def _restore_file(
    client: TestClient, caller: Account, file_id: uuid.UUID | str, **headers: str
) -> httpx.Response:
    return client.post(
        f"/api/trash/attachments/{file_id}/restore", headers={**caller.cookie, **headers}
    )


def _purge_chat(client: TestClient, caller: Account, chat_id: uuid.UUID | str) -> httpx.Response:
    return client.delete(f"/api/trash/chats/{chat_id}", headers=caller.cookie)


def _purge_file(client: TestClient, caller: Account, file_id: uuid.UUID | str) -> httpx.Response:
    return client.delete(f"/api/trash/attachments/{file_id}", headers=caller.cookie)


def _empty(client: TestClient, caller: Account) -> httpx.Response:
    return client.delete("/api/trash", headers=caller.cookie)


def _outcome(response: httpx.Response) -> tuple[int, Any]:
    """(status, JSON body) or (status, text) when the body isn't JSON."""
    try:
        body = response.json()
    except ValueError:
        body = response.text
    return response.status_code, body


def _tables(db: FakeDb) -> dict[str, Any]:
    """Every table, deep-copied, a session's ``last_seen_at`` (the refresh) left out."""
    state = db.snapshot()
    state["sessions"] = {
        key: {column: value for column, value in row.items() if column != "last_seen_at"}
        for key, row in state["sessions"].items()
    }
    return state


def _state(db: FakeDb) -> tuple[dict[str, Any], dict[str, bytes], list[str]]:
    """Tables, every file under the attachments root, and every path (directories too)."""
    root = Path(organizations.ATTACHMENTS_ROOT)
    paths = sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))
    return _tables(db), attachment_files(), paths


def _events(db: FakeDb) -> list[tuple[Any, ...]]:
    """The trash audit rows: (action, actor kind, actor, org, target type, ids, ip, metadata)."""
    return [
        (
            row["action"],
            row["actor_kind"],
            None if row["actor_user_id"] is None else str(row["actor_user_id"]),
            str(row["org_id"]),
            row["target_type"],
            row["target_ids"],
            row["ip"],
            row["metadata"],
        )
        for row in db.audit_rows()
        if row["action"] in _TRASH_ACTIONS
    ]


def _event(
    action: str,
    caller: Account,
    target_id: uuid.UUID,
    *,
    metadata: dict[str, Any] | None = None,
) -> tuple[Any, ...]:
    """One member event of contract §2: the caller, its org, the target, the client IP."""
    target_type = "chat" if action.startswith("chat.") else "file"
    return (
        action,
        "member",
        str(caller.user_id),
        str(caller.org_id),
        target_type,
        [str(target_id)],
        CLIENT_IP,
        metadata or {},
    )


def _expected_item(
    db: FakeDb, item_type: str, item_id: uuid.UUID, *, retention: int = 30
) -> dict[str, Any]:
    """The TrashItem of a stored row (timestamps as datetimes)."""
    if item_type == "chat":
        row = db.chat_row(item_id)
        assert row is not None
        name, chat_id = row["title"], None
    else:
        row = db.attachment_row(item_id)
        assert row is not None
        name, chat_id = row["filename"], str(row["chat_id"])
    return {
        "item_type": item_type,
        "id": str(item_id),
        "name": name,
        "chat_id": chat_id,
        "deleted_at": row["deleted_at"],
        "expires_at": row["deleted_at"] + timedelta(days=retention),
    }


def _items(body: dict[str, Any]) -> list[dict[str, Any]]:
    """The listed items with their timestamps parsed; every item has exactly the keys."""
    items = body["items"]
    assert all(set(item) == _ITEM_KEYS for item in items), items
    return [
        {
            **item,
            "deleted_at": datetime.fromisoformat(item["deleted_at"]),
            "expires_at": datetime.fromisoformat(item["expires_at"]),
        }
        for item in items
    ]


def _ids(response: httpx.Response) -> list[str]:
    assert response.status_code == 200, response.text
    return [item["id"] for item in response.json()["items"]]


def _expected_chat_summary(db: FakeDb, chat_id: uuid.UUID) -> dict[str, Any]:
    row = db.chat_row(chat_id)
    assert row is not None
    return {
        "id": str(chat_id),
        "title": row["title"],
        "title_source": row["title_source"],
        "created_at": row["created_at"],
        "last_activity_at": row["last_activity_at"],
    }


def _chat_summary(body: dict[str, Any]) -> dict[str, Any]:
    assert set(body) == _CHAT_SUMMARY_KEYS, body
    return {
        **body,
        "created_at": datetime.fromisoformat(body["created_at"]),
        "last_activity_at": datetime.fromisoformat(body["last_activity_at"]),
    }


def _expected_attachment_summary(db: FakeDb, file_id: uuid.UUID) -> dict[str, Any]:
    row = db.attachment_row(file_id)
    assert row is not None
    return {
        "id": str(file_id),
        "chat_id": str(row["chat_id"]),
        "message_id": None if row["message_id"] is None else str(row["message_id"]),
        "filename": row["filename"],
        "kind": row["kind"],
        "size_bytes": row["size_bytes"],
        "status": row["status"],
        "failure_reason": row["failure_reason"],
        "page_count": row["page_count"],
        "token_estimate": row["token_estimate"],
        "active": row["active"],
        "context_report": None,
        "created_at": row["created_at"],
    }


def _attachment_summary(body: dict[str, Any]) -> dict[str, Any]:
    assert set(body) == _ATTACHMENT_SUMMARY_KEYS, body
    return {**body, "created_at": datetime.fromisoformat(body["created_at"])}


def _trash_columns(row: dict[str, Any] | None) -> tuple[Any, Any]:
    """(deleted_at is set, trash_group_id) of a stored row."""
    assert row is not None
    group = row.get("trash_group_id", "missing")
    return row["deleted_at"] is not None, None if group is None else str(group)


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
# 1. GET /api/trash
# ---------------------------------------------------------------------------


class TestTrashList:
    """The caller's own trash items, newest deletion first, metadata only."""

    def test_trash_api_list_answers_exactly_the_callers_items_newest_first(
        self, world: World, client: TestClient
    ) -> None:
        """A trashed chat, a trashed chat with an empty title and a file deleted on its
        own: exactly those items (``name`` the title or the file name, ``chat_id`` the
        file's chat or null, ``expires_at`` = ``deleted_at`` + 30 days), newest first,
        ``next_cursor`` null, ``retention_days`` 30. A file that went with its chat, live
        rows, a colleague's and another org's trash are not listed."""
        db, editor = world.db, world.a["editor"]
        live = _chat(db, editor, title="Live 194")
        _file(db, live)
        chat = _chat(db, editor, deleted_at=_ago(hours=3))
        _file(db, chat, deleted_at=_ago(hours=3))
        untitled = _chat(db, editor, deleted_at=_ago(hours=2), title="")
        solo = _file(db, live, deleted_at=_ago(hours=1))
        _chat(db, world.a["org_admin"], deleted_at=_ago(hours=1))
        _file(db, _chat(db, world.a["org_admin"]), deleted_at=_ago(hours=1))
        _chat(db, world.b["editor"], deleted_at=_ago(hours=1))

        response = _list(client, editor)

        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == {"items", "next_cursor", "retention_days"}
        assert (body["next_cursor"], body["retention_days"]) == (None, 30)
        assert _items(body) == [
            _expected_item(db, "attachment", solo),
            _expected_item(db, "chat", untitled),
            _expected_item(db, "chat", chat),
        ]
        assert [item["name"] for item in body["items"]] == [_NAME, "", _TITLE]

    @pytest.mark.parametrize("item_type", ["chat", "attachment"])
    def test_trash_api_list_item_type_keeps_only_that_type(
        self, world: World, client: TestClient, item_type: str
    ) -> None:
        """``item_type=chat`` lists only the chats, ``attachment`` only the files."""
        db, editor = world.db, world.a["editor"]
        chat = _chat(db, editor, deleted_at=_ago(hours=2))
        solo = _file(db, _chat(db, editor), deleted_at=_ago(hours=1))

        response = _list(client, editor, item_type=item_type)

        assert _ids(response) == [str(chat if item_type == "chat" else solo)]
        assert {item["item_type"] for item in response.json()["items"]} == {item_type}

    def test_trash_api_list_pages_walk_every_item_once_a_tie_included(
        self, world: World, client: TestClient
    ) -> None:
        """``limit=2`` over five items, a chat and a file deleted at the same instant:
        three pages, newest first, a tie ordered by id descending, every item once, the
        last ``next_cursor`` null."""
        db, editor = world.db, world.a["editor"]
        live = _chat(db, editor)
        tie = _ago(hours=3)
        newest = _chat(db, editor, deleted_at=_ago(hours=1))
        second = _file(db, live, deleted_at=_ago(hours=2))
        tied = [_chat(db, editor, deleted_at=tie), _file(db, live, deleted_at=tie)]
        oldest = _chat(db, editor, deleted_at=_ago(hours=4))
        expected = [
            str(newest),
            str(second),
            *sorted((str(item) for item in tied), reverse=True),
            str(oldest),
        ]

        pages: list[list[str]] = []
        cursor: str | None = None
        for _ in range(5):
            params: dict[str, Any] = {"limit": 2}
            if cursor is not None:
                params["cursor"] = cursor
            response = _list(client, editor, **params)
            pages.append(_ids(response))
            cursor = response.json()["next_cursor"]
            if cursor is None:
                break

        assert [len(page) for page in pages] == [2, 2, 1]
        assert [item for page in pages for item in page] == expected
        assert cursor is None

    def test_trash_api_list_hides_expired_items_and_follows_a_changed_retention(
        self, world: World, client: TestClient
    ) -> None:
        """Retention 30: a chat trashed 29 days ago is listed, one trashed 31 days ago
        isn't. Lowered to 10: neither, ``retention_days`` 10. Raised to 90: both again
        (nothing was purged), newest first."""
        db, editor = world.db, world.a["editor"]
        recent = _chat(db, editor, deleted_at=_ago(days=29))
        old = _chat(db, editor, deleted_at=_ago(days=31))

        at_30 = _list(client, editor)
        _set_retention(db, 10)
        at_10 = _list(client, editor)
        _set_retention(db, 90)
        at_90 = _list(client, editor)

        assert (_ids(at_30), at_30.json()["retention_days"]) == ([str(recent)], 30)
        assert (_ids(at_10), at_10.json()["retention_days"]) == ([], 10)
        assert (_ids(at_90), at_90.json()["retention_days"]) == ([str(recent), str(old)], 90)
        assert _items(at_90.json()) == [
            _expected_item(db, "chat", recent, retention=90),
            _expected_item(db, "chat", old, retention=90),
        ]

    def test_trash_api_list_retention_zero_lists_nothing(
        self, world: World, client: TestClient
    ) -> None:
        """With an effective retention of 0 every trashed item is expired at once."""
        db, editor = world.db, world.a["editor"]
        _chat(db, editor, deleted_at=_ago(hours=0.01))
        _file(db, _chat(db, editor), deleted_at=_ago(hours=0.01))
        _set_retention(db, 0)

        response = _list(client, editor)

        assert _outcome(response) == (
            200,
            {"items": [], "next_cursor": None, "retention_days": 0},
        )

    @pytest.mark.parametrize(
        ("stored", "low", "high", "effective"),
        [
            pytest.param(0, 7, 90, 7, id="raised-to-the-platform-minimum"),
            pytest.param(60, 0, 45, 45, id="lowered-to-the-platform-maximum"),
            pytest.param(None, 0, 90, 30, id="no-org-settings-row-is-30"),
        ],
    )
    def test_trash_api_list_retention_is_the_org_value_clamped_into_the_platform_bounds(
        self,
        world: World,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        stored: int | None,
        low: int,
        high: int,
        effective: int,
    ) -> None:
        """``retention_days`` and each ``expires_at`` use the effective retention."""
        db, editor = world.db, world.a["editor"]
        chat = _chat(db, editor, deleted_at=_ago(hours=1))
        _set_bounds(monkeypatch, db, low=low, high=high)
        if stored is None:
            del db.org_settings[_org_settings_key(db, ORG_ID)]
        else:
            _set_retention(db, stored)

        response = _list(client, editor)

        assert response.status_code == 200, response.text
        assert response.json()["retention_days"] == effective
        assert _items(response.json()) == [_expected_item(db, "chat", chat, retention=effective)]

    def test_trash_api_list_writes_nothing(self, world: World, client: TestClient) -> None:
        """Listing records no audit row and changes no table."""
        db, editor = world.db, world.a["editor"]
        _chat(db, editor, deleted_at=_ago(hours=1))
        before = _tables(db)

        response = _list(client, editor)

        assert len(_ids(response)) == 1
        assert _tables(db) == before

    @pytest.mark.parametrize("case", ["garbage", "chat-list-cursor"])
    def test_trash_api_list_undecodable_cursor_is_422_invalid_cursor(
        self, world: World, client: TestClient, case: str
    ) -> None:
        """Garbage and a chat list's own cursor: the 422 ``invalid_cursor``, not echoed."""
        db, editor = world.db, world.a["editor"]
        if case == "garbage":
            cursor = f"{_ECHO}-not-a-cursor"
        else:
            _chat(db, editor)
            _chat(db, editor)
            page = client.get("/api/chats", params={"limit": 1}, headers=editor.cookie)
            assert page.status_code == 200, page.text
            cursor = page.json()["next_cursor"]
            assert cursor

        response = _list(client, editor, cursor=cursor)

        assert _outcome(response) == (422, _INVALID_CURSOR)
        assert cursor not in response.text

    @pytest.mark.parametrize(
        "params",
        [
            pytest.param({"limit": 0}, id="limit-0"),
            pytest.param({"limit": 101}, id="limit-101"),
            pytest.param({"limit": _ECHO}, id="limit-not-a-number"),
            pytest.param({"item_type": _ECHO}, id="unknown-item-type"),
            pytest.param({"item_type": "project"}, id="project-item-type"),
            pytest.param({"cursor": _ECHO + "x" * 200}, id="cursor-over-200"),
        ],
    )
    def test_trash_api_list_bad_query_is_422_without_echo(
        self, world: World, client: TestClient, params: dict[str, Any]
    ) -> None:
        """FastAPI's 422: no error carries an ``input``, the marker never comes back."""
        db, editor = world.db, world.a["editor"]
        _chat(db, editor, deleted_at=_ago(hours=1))

        response = _list(client, editor, **params)

        assert response.status_code == 422, response.text
        errors = response.json()["detail"]
        assert isinstance(errors, list), errors
        assert all("input" not in error for error in errors), errors
        assert _ECHO not in response.text


# ---------------------------------------------------------------------------
# 2. POST /api/trash/chats/{chat_id}/restore
# ---------------------------------------------------------------------------


def _foreign_chat(world: World, case: str) -> tuple[Account, uuid.UUID]:
    """(caller, a trashed chat id that isn't the caller's own, or an unknown id)."""
    a, b = world.a, world.b
    if case == "other-org":
        return a["editor"], _chat(world.db, b["editor"], deleted_at=_ago(hours=1))
    if case == "colleague":
        return a["editor"], _chat(world.db, a["org_admin"], deleted_at=_ago(hours=1))
    if case == "org-admin-on-editors":
        return a["org_admin"], _chat(world.db, a["editor"], deleted_at=_ago(hours=1))
    return a["editor"], uuid.uuid4()


def _foreign_file(world: World, case: str) -> tuple[Account, uuid.UUID]:
    """(caller, a trashed file of its own that isn't the caller's, or an unknown id)."""
    a, b = world.a, world.b
    if case == "other-org":
        owner, caller = b["editor"], a["editor"]
    elif case == "colleague":
        owner, caller = a["org_admin"], a["editor"]
    elif case == "org-admin-on-editors":
        owner, caller = a["editor"], a["org_admin"]
    else:
        return a["editor"], uuid.uuid4()
    return caller, _file(world.db, _chat(world.db, owner), deleted_at=_ago(hours=1))


_FOREIGN: Final = ["other-org", "colleague", "org-admin-on-editors", "unknown"]


class TestTrashRestoreChat:
    """The caller's trashed chat comes back with exactly its group."""

    def test_trash_api_restore_chat_answers_its_summary_and_restores_exactly_its_group(
        self, world: World, client: TestClient
    ) -> None:
        """200 with exactly the chat's ``ChatSummary`` (its activity time kept); the chat
        and the files of its group are live again (message link and exclusion flag
        kept), a file deleted on its own before the chat stays in the trash as its own
        item; its messages are untouched."""
        db, editor = world.db, world.a["editor"]
        activity = _ago(days=3)
        chat_id = _chat(db, editor, deleted_at=_ago(hours=2), last_activity_at=activity)
        message = db.add_chat_message(chat_id, "user", "Question 194")
        db.add_chat_message(chat_id, "assistant", "Answer 194")
        sent = _file(db, chat_id, message_id=message, deleted_at=_ago(hours=2))
        excluded = _file(db, chat_id, active=False, deleted_at=_ago(hours=2))
        solo = uuid.uuid4()
        _file(db, chat_id, attachment_id=solo, deleted_at=_ago(hours=5), trash_group_id=solo)
        expected = _expected_chat_summary(db, chat_id)

        response = _restore_chat(client, editor, chat_id)

        assert response.status_code == 200, response.text
        assert _chat_summary(response.json()) == expected
        assert expected["last_activity_at"] == activity
        assert _trash_columns(db.chat_row(chat_id)) == (False, None)
        assert _trash_columns(db.attachment_row(sent)) == (False, None)
        assert _trash_columns(db.attachment_row(excluded)) == (False, None)
        assert _trash_columns(db.attachment_row(solo)) == (True, str(solo))
        sent_row, excluded_row = db.attachment_row(sent), db.attachment_row(excluded)
        assert sent_row is not None
        assert excluded_row is not None
        assert (plain(sent_row["message_id"]), excluded_row["active"]) == (message, False)
        assert [m["content"] for m in db.messages_of(chat_id)] == ["Question 194", "Answer 194"]
        assert _ids(_list(client, editor)) == [str(solo)]

    def test_trash_api_restore_chat_records_one_content_free_chat_restore(
        self, world: World, client: TestClient
    ) -> None:
        """Exactly one ``chat.restore`` row: the member, the org, the chat, the client IP,
        no metadata, no title."""
        db, editor = world.db, world.a["editor"]
        chat_id = _chat(db, editor, deleted_at=_ago(hours=1))
        _file(db, chat_id, deleted_at=_ago(hours=1))

        response = _restore_chat(client, editor, chat_id)

        assert response.status_code == 200, response.text
        assert _events(db) == [_event("chat.restore", editor, chat_id)]
        assert _MARK.casefold() not in repr(db.audit_rows()).casefold()

    @pytest.mark.parametrize("case", ["live", "restored-twice"])
    def test_trash_api_restore_chat_of_a_live_chat_answers_it_and_records_nothing(
        self, world: World, client: TestClient, case: str
    ) -> None:
        """Idempotent: the caller's live chat (never trashed, or restored just before) is
        200 with its summary, no write and no audit row."""
        db, editor = world.db, world.a["editor"]
        if case == "live":
            chat_id = _chat(db, editor)
        else:
            chat_id = _chat(db, editor, deleted_at=_ago(hours=1))
            first = _restore_chat(client, editor, chat_id)
            assert first.status_code == 200, first.text
        before = _tables(db)

        response = _restore_chat(client, editor, chat_id)

        assert response.status_code == 200, response.text
        assert _chat_summary(response.json()) == _expected_chat_summary(db, chat_id)
        assert _tables(db) == before

    @pytest.mark.parametrize(
        ("retention", "deleted_days_ago"),
        [
            pytest.param(30, 30.01, id="expired-past-30-days"),
            pytest.param(0, 0.0001, id="retention-0"),
        ],
    )
    def test_trash_api_restore_chat_expired_is_404_and_changes_nothing(
        self, world: World, client: TestClient, retention: int, deleted_days_ago: float
    ) -> None:
        """An expired chat can't come back, even before the purge removes it."""
        db, editor = world.db, world.a["editor"]
        chat_id = _chat(db, editor, deleted_at=_ago(days=deleted_days_ago))
        _file(db, chat_id, deleted_at=_ago(days=deleted_days_ago))
        _set_retention(db, retention)
        before = _state(db)

        response = _restore_chat(client, editor, chat_id)

        assert _outcome(response) == (404, CHAT_NOT_FOUND)
        assert _state(db) == before

    def test_trash_api_restore_chat_of_a_taken_legacy_session_is_409_restore_conflict(
        self, world: World, client: TestClient
    ) -> None:
        """A legacy chat whose session has a live chat again: the exact 409
        ``restore_conflict``, nothing changed (the trashed chat stays in the trash)."""
        db, editor = world.db, world.a["editor"]
        trashed = _chat(db, editor, deleted_at=_ago(hours=1), legacy_session_id="legacy-194")
        _chat(db, editor, legacy_session_id="legacy-194")
        before = _state(db)

        response = _restore_chat(client, editor, trashed)

        assert _outcome(response) == (409, _RESTORE_CONFLICT)
        assert _state(db) == before

    @pytest.mark.parametrize("case", _FOREIGN)
    def test_trash_api_restore_chat_not_the_callers_is_404_and_changes_nothing(
        self, world: World, client: TestClient, case: str
    ) -> None:
        """Another org's, a colleague's, an Editor's for the Org Admin and an unknown chat:
        the same 404 ``chat_not_found``, the id not echoed, nothing changed."""
        caller, chat_id = _foreign_chat(world, case)
        before = _state(world.db)

        response = _restore_chat(client, caller, chat_id)

        assert _outcome(response) == (404, CHAT_NOT_FOUND)
        assert str(chat_id) not in response.text
        assert _state(world.db) == before


# ---------------------------------------------------------------------------
# 3. POST /api/trash/attachments/{attachment_id}/restore
# ---------------------------------------------------------------------------


class TestTrashRestoreAttachment:
    """The caller's file deleted on its own comes back into its live chat."""

    def test_trash_api_restore_attachment_answers_its_summary_and_keeps_its_columns(
        self, world: World, client: TestClient
    ) -> None:
        """200 with exactly its ``AttachmentSummary`` (``context_report`` null), its message
        link and exclusion flag kept; listed again in its chat; one content-free
        ``file.restore`` row."""
        db, editor = world.db, world.a["editor"]
        chat_id = _chat(db, editor)
        message = db.add_chat_message(chat_id, "user", "With a file 194")
        file_id = _file(db, chat_id, message_id=message, active=False, deleted_at=_ago(hours=1))
        expected = _expected_attachment_summary(db, file_id)

        response = _restore_file(client, editor, file_id)
        listed = client.get(f"/api/chats/{chat_id}/attachments", headers=editor.cookie)

        assert response.status_code == 200, response.text
        assert _attachment_summary(response.json()) == expected
        assert (expected["message_id"], expected["active"]) == (str(message), False)
        assert _trash_columns(db.attachment_row(file_id)) == (False, None)
        assert listed.status_code == 200, listed.text
        assert [item["id"] for item in listed.json()["attachments"]] == [str(file_id)]
        assert _events(db) == [_event("file.restore", editor, file_id)]
        assert _MARK.casefold() not in repr(db.audit_rows()).casefold()

    @pytest.mark.parametrize("case", ["live", "restored-twice"])
    def test_trash_api_restore_attachment_of_a_live_file_answers_it_and_records_nothing(
        self, world: World, client: TestClient, case: str
    ) -> None:
        """Idempotent: the caller's live file is 200 with its summary, nothing written."""
        db, editor = world.db, world.a["editor"]
        chat_id = _chat(db, editor)
        if case == "live":
            file_id = _file(db, chat_id)
        else:
            file_id = _file(db, chat_id, deleted_at=_ago(hours=1))
            first = _restore_file(client, editor, file_id)
            assert first.status_code == 200, first.text
        before = _tables(db)

        response = _restore_file(client, editor, file_id)

        assert response.status_code == 200, response.text
        assert _attachment_summary(response.json()) == _expected_attachment_summary(db, file_id)
        assert _tables(db) == before

    def test_trash_api_restore_attachment_whose_chat_is_in_the_trash_is_409_chat_in_trash(
        self, world: World, client: TestClient
    ) -> None:
        """A file deleted on its own, then its chat: the exact 409 ``chat_in_trash``,
        nothing changed; after the chat's restore the file's restore succeeds."""
        db, editor = world.db, world.a["editor"]
        chat_id, file_id = _solo_file_in_trashed_chat(
            db, editor, chat_at=_ago(hours=1), file_at=_ago(hours=2)
        )
        before = _state(db)

        refused = _restore_file(client, editor, file_id)
        after_refusal = _state(db)
        chat_back = _restore_chat(client, editor, chat_id)
        file_back = _restore_file(client, editor, file_id)

        assert _outcome(refused) == (409, _CHAT_IN_TRASH)
        assert after_refusal == before
        assert (chat_back.status_code, file_back.status_code) == (200, 200)
        assert _trash_columns(db.attachment_row(file_id)) == (False, None)

    def test_trash_api_restore_attachment_of_a_chats_group_is_404(
        self, world: World, client: TestClient
    ) -> None:
        """A file that went to the trash with its chat isn't an item: 404, nothing changed."""
        db, editor = world.db, world.a["editor"]
        chat_id = _chat(db, editor, deleted_at=_ago(hours=1))
        file_id = _file(db, chat_id, deleted_at=_ago(hours=1))
        before = _state(db)

        response = _restore_file(client, editor, file_id)

        assert _outcome(response) == (404, ATTACHMENT_NOT_FOUND)
        assert _state(db) == before

    @pytest.mark.parametrize(
        ("retention", "deleted_days_ago"),
        [
            pytest.param(30, 30.01, id="expired-past-30-days"),
            pytest.param(0, 0.0001, id="retention-0"),
        ],
    )
    def test_trash_api_restore_attachment_expired_is_404_and_changes_nothing(
        self, world: World, client: TestClient, retention: int, deleted_days_ago: float
    ) -> None:
        db, editor = world.db, world.a["editor"]
        file_id = _file(db, _chat(db, editor), deleted_at=_ago(days=deleted_days_ago))
        _set_retention(db, retention)
        before = _state(db)

        response = _restore_file(client, editor, file_id)

        assert _outcome(response) == (404, ATTACHMENT_NOT_FOUND)
        assert _state(db) == before

    @pytest.mark.parametrize("case", _FOREIGN)
    def test_trash_api_restore_attachment_not_the_callers_is_404_and_changes_nothing(
        self, world: World, client: TestClient, case: str
    ) -> None:
        caller, file_id = _foreign_file(world, case)
        before = _state(world.db)

        response = _restore_file(client, caller, file_id)

        assert _outcome(response) == (404, ATTACHMENT_NOT_FOUND)
        assert str(file_id) not in response.text
        assert _state(world.db) == before


# ---------------------------------------------------------------------------
# 4. DELETE /api/trash/chats/{chat_id} and /api/trash/attachments/{attachment_id}
# ---------------------------------------------------------------------------


class TestTrashDeleteForever:
    """Delete forever: the rows, then every file of them on disk; trash items only."""

    @pytest.mark.parametrize("deleted_days_ago", [0.05, 45.0], ids=["recent", "expired"])
    def test_trash_api_delete_chat_forever_removes_its_rows_and_files(
        self, world: World, root: Path, client: TestClient, deleted_days_ago: float
    ) -> None:
        """204 with no body; the chat, its messages and every file of the chat (its group
        and a file deleted on its own before it) are gone, rows and disk; one
        ``chat.purge`` with ``file_count`` 2. Another trashed chat stays. An expired chat
        is removed the same way."""
        db, editor = world.db, world.a["editor"]
        at = _ago(days=deleted_days_ago)
        chat_id, solo = _solo_file_in_trashed_chat(
            db, editor, chat_at=at, file_at=at - timedelta(hours=1)
        )
        db.add_chat_message(chat_id, "user", "Question 194")
        grouped = _file(db, chat_id, deleted_at=at)
        other = _chat(db, editor, deleted_at=at)
        other_file = _file(db, other, deleted_at=at)

        response = _purge_chat(client, editor, chat_id)

        assert (response.status_code, response.content) == (204, b""), response.text
        assert db.chat_row(chat_id) is None
        assert db.messages_of(chat_id) == []
        assert (db.attachment_row(grouped), db.attachment_row(solo)) == (None, None)
        assert _on_disk(root, ORG_ID, grouped) == _GONE
        assert _on_disk(root, ORG_ID, solo) == _GONE
        assert db.chat_row(other) is not None
        assert _on_disk(root, ORG_ID, other_file) == _KEPT
        assert _events(db) == [_event("chat.purge", editor, chat_id, metadata={"file_count": 2})]

    @pytest.mark.parametrize("deleted_days_ago", [0.05, 45.0], ids=["recent", "expired"])
    def test_trash_api_delete_attachment_forever_removes_its_row_and_files(
        self, world: World, root: Path, client: TestClient, deleted_days_ago: float
    ) -> None:
        """204; the file's row and its three entries on disk are gone; its live chat and
        another file stay; one ``file.purge`` without metadata."""
        db, editor = world.db, world.a["editor"]
        chat_id = _chat(db, editor)
        file_id = _file(db, chat_id, deleted_at=_ago(days=deleted_days_ago))
        kept = _file(db, chat_id)

        response = _purge_file(client, editor, file_id)

        assert (response.status_code, response.content) == (204, b""), response.text
        assert db.attachment_row(file_id) is None
        assert _on_disk(root, ORG_ID, file_id) == _GONE
        assert db.chat_row(chat_id) is not None
        assert _on_disk(root, ORG_ID, kept) == _KEPT
        assert _events(db) == [_event("file.purge", editor, file_id)]

    @pytest.mark.parametrize("case", ["live-chat", "unknown", *_FOREIGN[:3]])
    def test_trash_api_delete_chat_forever_of_no_trash_item_is_404_and_changes_nothing(
        self, world: World, client: TestClient, case: str
    ) -> None:
        """The caller's live chat, another org's, a colleague's, an Editor's for the Org
        Admin and an unknown chat: 404 ``chat_not_found``, nothing changed."""
        if case == "live-chat":
            caller = world.a["editor"]
            chat_id = _chat(world.db, caller)
            _file(world.db, chat_id)
        else:
            caller, chat_id = _foreign_chat(world, case)
        before = _state(world.db)

        response = _purge_chat(client, caller, chat_id)

        assert _outcome(response) == (404, CHAT_NOT_FOUND)
        assert str(chat_id) not in response.text
        assert _state(world.db) == before

    @pytest.mark.parametrize("case", ["live-file", "chats-group", "unknown", *_FOREIGN[:3]])
    def test_trash_api_delete_attachment_forever_of_no_trash_item_is_404_and_changes_nothing(
        self, world: World, client: TestClient, case: str
    ) -> None:
        """The caller's live file, a file that went with its chat, another org's, a
        colleague's, an Editor's for the Org Admin and an unknown file: 404
        ``attachment_not_found``, nothing changed."""
        caller = world.a["editor"]
        if case == "live-file":
            file_id = _file(world.db, _chat(world.db, caller))
        elif case == "chats-group":
            chat_id = _chat(world.db, caller, deleted_at=_ago(hours=1))
            file_id = _file(world.db, chat_id, deleted_at=_ago(hours=1))
        else:
            caller, file_id = _foreign_file(world, case)
        before = _state(world.db)

        response = _purge_file(client, caller, file_id)

        assert _outcome(response) == (404, ATTACHMENT_NOT_FOUND)
        assert str(file_id) not in response.text
        assert _state(world.db) == before

    @pytest.mark.parametrize("kind", ["chat", "attachment"])
    def test_trash_api_delete_forever_with_a_refused_audit_write_removes_nothing(
        self, world: World, lenient_client: TestClient, kind: str
    ) -> None:
        """The purge's audit write fails: a 500, the transaction rolled back, no row and
        no file removed."""
        db, editor = world.db, world.a["editor"]
        chat_id = _chat(db, editor, deleted_at=_ago(hours=1) if kind == "chat" else None)
        file_id = _file(db, chat_id, deleted_at=_ago(hours=1))
        db.fail_audit_when = lambda row: row["action"] in ("chat.purge", "file.purge")
        before = _state(db)

        if kind == "chat":
            response = _purge_chat(lenient_client, editor, chat_id)
        else:
            response = _purge_file(lenient_client, editor, file_id)

        assert response.status_code == 500, response.text
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 5. DELETE /api/trash
# ---------------------------------------------------------------------------


class TestTrashEmpty:
    """Empty the caller's trash: every item purged, one per transaction, counted."""

    def test_trash_api_empty_purges_every_item_of_the_caller_and_counts_them(
        self, world: World, root: Path, client: TestClient
    ) -> None:
        """Two trashed chats (one expired, one holding a file deleted on its own before it)
        and a file deleted on its own in a live chat: 200 ``{"chats": 2, "attachments":
        1}``; their rows and files gone; the live chat and file, a colleague's and another
        org's trash untouched; two ``chat.purge`` and one ``file.purge`` by the member."""
        db, editor = world.db, world.a["editor"]
        holder, inner = _solo_file_in_trashed_chat(
            db, editor, chat_at=_ago(hours=1), file_at=_ago(hours=2)
        )
        expired = _chat(db, editor, deleted_at=_ago(days=40))
        expired_file = _file(db, expired, deleted_at=_ago(days=40))
        live = _chat(db, editor)
        live_file = _file(db, live)
        solo = _file(db, live, deleted_at=_ago(hours=3))
        colleague_chat = _chat(db, world.a["org_admin"], deleted_at=_ago(hours=1))
        colleague_file = _file(db, colleague_chat, deleted_at=_ago(hours=1))
        foreign_chat = _chat(db, world.b["editor"], deleted_at=_ago(hours=1))
        foreign_file = _file(db, foreign_chat, deleted_at=_ago(hours=1))

        response = _empty(client, editor)

        assert _outcome(response) == (200, {"chats": 2, "attachments": 1})
        assert [db.chat_row(chat) for chat in (holder, expired)] == [None, None]
        assert [db.attachment_row(f) for f in (inner, expired_file, solo)] == [None] * 3
        for file_id in (inner, expired_file, solo):
            assert _on_disk(root, ORG_ID, file_id) == _GONE
        assert db.chat_row(live) is not None
        assert _on_disk(root, ORG_ID, live_file) == _KEPT
        assert _trash_columns(db.chat_row(colleague_chat)) == (True, str(colleague_chat))
        assert _on_disk(root, ORG_ID, colleague_file) == _KEPT
        assert db.chat_row(foreign_chat) is not None
        assert _on_disk(root, OTHER_ORG_ID, foreign_file) == _KEPT
        assert sorted(_events(db)) == sorted(
            [
                _event("chat.purge", editor, holder, metadata={"file_count": 1}),
                _event("chat.purge", editor, expired, metadata={"file_count": 1}),
                _event("file.purge", editor, solo),
            ]
        )

    def test_trash_api_empty_with_nothing_in_the_trash_is_zero_and_records_nothing(
        self, world: World, client: TestClient
    ) -> None:
        db, editor = world.db, world.a["editor"]
        _file(db, _chat(db, editor))
        before = _state(db)

        response = _empty(client, editor)

        assert _outcome(response) == (200, {"chats": 0, "attachments": 0})
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 6. Roles, session, CSRF, ids, rate limits, OpenAPI, logs (every route)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Op:
    """One trash route: its name, method, bucket key and contract (rate, burst)."""

    name: str
    method: str
    bucket: str
    limits: tuple[float, int]
    success: int


_LIST_OP: Final = _Op("list", "GET", "/api/trash/list", (1.0, 10), 200)
_RESTORE_CHAT_OP: Final = _Op("restore-chat", "POST", "/api/trash/chats/restore", (0.5, 5), 200)
_RESTORE_FILE_OP: Final = _Op(
    "restore-attachment", "POST", "/api/trash/attachments/restore", (0.5, 5), 200
)
_PURGE_CHAT_OP: Final = _Op("delete-chat", "DELETE", "/api/trash/chats/delete", (0.5, 5), 204)
_PURGE_FILE_OP: Final = _Op(
    "delete-attachment", "DELETE", "/api/trash/attachments/delete", (0.5, 5), 204
)
_EMPTY_OP: Final = _Op("empty", "DELETE", "/api/trash/empty", (0.2, 2), 200)
_OPS: Final = (
    _LIST_OP,
    _RESTORE_CHAT_OP,
    _RESTORE_FILE_OP,
    _PURGE_CHAT_OP,
    _PURGE_FILE_OP,
    _EMPTY_OP,
)
_STATE_OPS: Final = tuple(op for op in _OPS if op.method != "GET")
_ID_OPS: Final = (
    ("POST", "/api/trash/chats/{}/restore"),
    ("POST", "/api/trash/attachments/{}/restore"),
    ("DELETE", "/api/trash/chats/{}"),
    ("DELETE", "/api/trash/attachments/{}"),
)


def _op_param(op: _Op) -> Any:
    return pytest.param(op, id=op.name)


def _target(db: FakeDb, op: _Op, owner: Account) -> str:
    """Seed what ``op`` acts on for ``owner`` (a trashed chat or a file deleted on its
    own) and return the request path."""
    if op is _LIST_OP or op is _EMPTY_OP:
        _chat(db, owner, deleted_at=_ago(hours=1))
        return "/api/trash"
    if op in (_RESTORE_CHAT_OP, _PURGE_CHAT_OP):
        chat_id = _chat(db, owner, deleted_at=_ago(hours=1))
        _file(db, chat_id, deleted_at=_ago(hours=1))
        suffix = "/restore" if op is _RESTORE_CHAT_OP else ""
        return f"/api/trash/chats/{chat_id}{suffix}"
    file_id = _file(db, _chat(db, owner), deleted_at=_ago(hours=1))
    suffix = "/restore" if op is _RESTORE_FILE_OP else ""
    return f"/api/trash/attachments/{file_id}{suffix}"


def _call(
    client: TestClient, op: _Op, path: str, caller: Account | None, **headers: str
) -> httpx.Response:
    cookie = dict(caller.cookie) if caller is not None else {}
    return client.request(op.method, path, headers={**cookie, **headers})


class TestTrashGuards:
    """Every trash route: roles, session, CSRF, ids, its own bucket, its models, logs."""

    @pytest.mark.parametrize("op", [_op_param(op) for op in _OPS])
    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    def test_trash_api_org_admin_and_editor_may_use_every_route(
        self, world: World, client: TestClient, op: _Op, role: MemberRole
    ) -> None:
        caller = world.a[role]
        path = _target(world.db, op, caller)

        response = _call(client, op, path, caller)

        assert response.status_code == op.success, response.text

    @pytest.mark.parametrize("op", [_op_param(op) for op in _OPS])
    @pytest.mark.parametrize("role", ["viewer", "super_admin"])
    def test_trash_api_viewer_and_super_admin_are_403_and_change_nothing(
        self, world: World, client: TestClient, op: _Op, role: str
    ) -> None:
        """The Viewer on their own trash (from before a demotion) and the Super Admin on an
        Editor's: exactly 403 Forbidden, nothing changed."""
        caller = world.super_admin if role == "super_admin" else world.a["viewer"]
        owner = world.a["viewer"] if role == "viewer" else world.a["editor"]
        path = _target(world.db, op, owner)
        before = _state(world.db)

        response = _call(client, op, path, caller)

        assert _outcome(response) == (403, FORBIDDEN)
        assert _state(world.db) == before
        assert _MARK not in response.text

    @pytest.mark.parametrize("op", [_op_param(op) for op in _OPS])
    def test_trash_api_without_a_session_is_401_and_changes_nothing(
        self, world: World, client: TestClient, op: _Op
    ) -> None:
        path = _target(world.db, op, world.a["editor"])
        before = _state(world.db)

        response = _call(client, op, path, None)

        assert _outcome(response) == (401, UNAUTHORIZED)
        assert _state(world.db) == before

    @pytest.mark.parametrize("op", [_op_param(op) for op in _STATE_OPS])
    def test_trash_api_cross_site_state_change_is_refused_and_same_origin_succeeds(
        self, world: World, client: TestClient, op: _Op
    ) -> None:
        """A cross-site ``Origin`` and a ``Sec-Fetch-Site: cross-site`` are the CSRF 403
        with nothing changed; the same request from the app's origin succeeds."""
        editor = world.a["editor"]
        path = _target(world.db, op, editor)
        before = _state(world.db)

        foreign = _call(client, op, path, editor, Origin=_FOREIGN_ORIGIN)
        fetch_site = _call(client, op, path, editor, **{"Sec-Fetch-Site": "cross-site"})
        after_refusals = _state(world.db)
        accepted = _call(client, op, path, editor, Origin=_SAME_ORIGIN)

        assert [_outcome(foreign), _outcome(fetch_site)] == [(403, _CSRF_REFUSED)] * 2
        assert after_refusals == before
        assert accepted.status_code == op.success, accepted.text

    @pytest.mark.parametrize(("method", "template"), _ID_OPS)
    def test_trash_api_non_uuid_id_is_422_without_echo(
        self, world: World, client: TestClient, method: str, template: str
    ) -> None:
        response = client.request(
            method, template.format(f"{_ECHO}-not-a-uuid"), headers=world.a["editor"].cookie
        )

        assert response.status_code == 422, response.text
        errors = response.json()["detail"]
        assert all("input" not in error for error in errors), errors
        assert _ECHO not in response.text

    def test_trash_api_rate_limit_keys_have_the_contract_values(self) -> None:
        """Contract §6: each route's own bucket with its (rate, burst)."""
        assert {op.bucket: server._RATE_LIMITS.get(op.bucket) for op in _OPS} == {
            op.bucket: op.limits for op in _OPS
        }

    @pytest.mark.parametrize("op", [_op_param(op) for op in _OPS])
    def test_trash_api_rate_limit_is_per_user_and_per_route(
        self, world: World, client: TestClient, monkeypatch: pytest.MonkeyPatch, op: _Op
    ) -> None:
        """Burst 1 on the route's bucket: the Editor's second request is 429 with nothing
        changed, a colleague still gets through, the bucket is (route key,
        ``user:<id>``)."""
        monkeypatch.setitem(server._RATE_LIMITS, op.bucket, (0.001, 1))
        editor, admin = world.a["editor"], world.a["org_admin"]
        path = _target(world.db, op, editor)
        colleague_path = _target(world.db, op, admin)

        first = _call(client, op, path, editor)
        before = _state(world.db)
        limited = _call(client, op, path, editor)
        after = _state(world.db)
        colleague = _call(client, op, colleague_path, admin)

        assert first.status_code == op.success, first.text
        assert _outcome(limited) == (429, _RATE_LIMITED)
        assert after == before
        assert colleague.status_code == op.success, colleague.text
        assert (op.bucket, f"user:{editor.user_id}") in server._rate_buckets

    def test_trash_api_routes_declare_their_response_models(self) -> None:
        """Each route's response model and success status (contract §3, §6)."""
        from fastapi.routing import APIRoute

        from admino import models

        found = {
            (method, route.path): (route.response_model, route.status_code or 200)
            for route in make_app().routes
            if isinstance(route, APIRoute) and route.path.startswith("/api/trash")
            for method in route.methods or ()
        }

        assert found == {
            ("GET", "/api/trash"): (models.TrashListResponse, 200),
            ("DELETE", "/api/trash"): (models.TrashEmptyResponse, 200),
            ("POST", "/api/trash/chats/{chat_id}/restore"): (models.ChatSummary, 200),
            ("POST", "/api/trash/attachments/{attachment_id}/restore"): (
                models.AttachmentSummary,
                200,
            ),
            ("DELETE", "/api/trash/chats/{chat_id}"): (None, 204),
            ("DELETE", "/api/trash/attachments/{attachment_id}"): (None, 204),
        }

    @pytest.mark.parametrize(
        ("path", "examples"),
        [
            pytest.param(
                "/api/trash/chats/{chat_id}/restore",
                {"restore_conflict": {"value": _RESTORE_CONFLICT}},
                id="chat",
            ),
            pytest.param(
                "/api/trash/attachments/{attachment_id}/restore",
                {"chat_in_trash": {"value": _CHAT_IN_TRASH}},
                id="attachment",
            ),
        ],
    )
    def test_trash_api_restore_routes_document_their_409_with_one_example_per_code(
        self, path: str, examples: dict[str, Any]
    ) -> None:
        responses = make_app().openapi()["paths"][path]["post"]["responses"]

        assert responses["409"]["content"]["application/json"]["examples"] == examples

    def test_trash_api_logs_carry_no_title_or_file_name(
        self, world: World, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Listing, restoring, deleting forever and emptying: no log record holds a title
        or a file name (canaries)."""
        db, editor = world.db, world.a["editor"]
        chat_id = _chat(db, editor, deleted_at=_ago(hours=1))
        _file(db, chat_id, deleted_at=_ago(hours=1))
        live = _chat(db, editor)
        restored_file = _file(db, live, deleted_at=_ago(hours=1))
        purged_file = _file(db, live, deleted_at=_ago(hours=1))
        purged_chat = _chat(db, editor, deleted_at=_ago(hours=2))
        _file(db, purged_chat, deleted_at=_ago(hours=2))
        _chat(db, editor, deleted_at=_ago(hours=3))
        caplog.set_level(logging.DEBUG)

        statuses = [
            _list(client, editor).status_code,
            _restore_chat(client, editor, chat_id).status_code,
            _restore_file(client, editor, restored_file).status_code,
            _purge_file(client, editor, purged_file).status_code,
            _purge_chat(client, editor, purged_chat).status_code,
            _empty(client, editor).status_code,
        ]

        assert statuses == [200, 200, 200, 204, 204, 200]
        leaks = [
            record.getMessage()
            for record in _app_records(caplog)
            if _MARK in _record_text(record) or json.dumps(_MARK)[1:-1] in _record_text(record)
        ]
        assert leaks == []
