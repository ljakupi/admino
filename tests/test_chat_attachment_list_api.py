"""HTTP spec of ``GET /api/chats/{chat_id}/attachments`` (GH-190).

Issue #190, "From #187 / #188" (the list route for #191's Attachments panel) and
Decision 11; contract C2 (``AttachmentListResponse``, ``AttachmentSummary.active``),
C6 (``attachments.list_chat_attachments``: A11 / A11'), C11 (the route and its
rate limit), C12 (the route-table row). Tracker #139 §5: every role, another
org's and a colleague's chat, the per-user rate limit, 422 without echo,
operator blindness.

The app from ``create_app()`` (a stub agent) runs against the FakeDb world of
tests/tenancy_world.py (orgs A and B with an Org Admin and an Editor each, plus
a Super Admin, real session cookies). Attachment rows are seeded with
``FakeDb.add_attachment`` (``active=False`` needs migration 0030, which the fake
models once it ships).

What is pinned:
- 200 ``{"attachments": [...], "next_cursor": ...}``: the caller's live files of
  their own chat as ``AttachmentSummary`` items (exactly id, chat_id, message_id,
  filename, kind, size_bytes, status, failure_reason, page_count, token_estimate,
  active, context_report, created_at), oldest first (``created_at``, then
  ``id``), sent or not, active or not; trashed files and other chats' files are
  not listed. Metadata only: neither the stored bytes nor the converted text.
- Paging: ``limit`` 1 to 100, default 50 (0, 101, -1 and a non-number: 422);
  ``next_cursor`` walks every file once, in order, a tie on ``created_at`` across
  a page boundary included, and ends with null. A malformed cursor (garbage,
  base64url of other JSON, a cut real cursor, a chat or message cursor) is the
  422 ``{"detail": "Invalid cursor", "reason": "invalid_cursor"}`` that never
  echoes it and reads no attachment; one over 200 characters is a 422 without
  echo.
- Filters: ``status`` (each of the four) and ``active`` (true, false), alone,
  combined and across pages; an unknown status or a non-bool ``active`` is 422
  without echo.
- 404 ``chat_not_found`` for another org's, a colleague's (an Org Admin's request
  on an Editor's chat too), a trashed and an unknown chat, with no statement on
  attachments and no file name in the body; a non-UUID chat id is 422.
- Roles (``chat.send``): the Org Admin and the Editor list their own; the Super
  Admin (an Editor's chat) gets exactly 403 Forbidden, no statement on chats or
  attachments, never a file name. No session: 401.
- Rate limit ``/api/chats/attachments/list`` (1.0, 10), per user.
- The route declares ``AttachmentListResponse``.

New names are looked up at test time, so the file collects before GH-190 is
implemented.

Security notes: every id, name and text here is a fixed fake value under
``tmp_path``. No network, no real PostgreSQL, no LLM.
"""

from __future__ import annotations

import base64
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import server
from tests.attachment_derived import write_derived
from tests.db_fakes import FakeDb, plain
from tests.tenancy_world import (
    FORBIDDEN,
    UNAUTHORIZED,
    build_world,
    make_app,
    make_client,
    use_attachment_storage,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from pathlib import Path

    import httpx
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, MemberRole, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LIST_KEY: Final = "/api/chats/attachments/list"
_CHAT_NOT_FOUND: Final = {"detail": "Chat not found", "reason": "chat_not_found"}
_INVALID_CURSOR: Final = {"detail": "Invalid cursor", "reason": "invalid_cursor"}
_RATE_LIMITED: Final = {"detail": "Rate limit exceeded"}

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
_STATUSES: Final = ("uploaded", "processing", "ready", "failed")

_T0: Final = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
_ECHO: Final = "ECHOMARK190"
# Every seeded file name holds this marker; the stored bytes and converted text theirs.
_NAME_MARK: Final = "Kestrelbudget Akte 190"
_BYTES_MARK: Final = "Plovercontent 190 Kundenliste"
_TEXT_MARK: Final = "Sandpiperconverted 190 Summe"

_ATTACHMENTS_SQL: Final = re.compile(r"\battachments\b")
_CHAT_TABLES_SQL: Final = re.compile(r"\b(?:chats|attachments)\b")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def root(tmp_path: Path) -> Path:
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
def client(world: World) -> TestClient:
    return make_client(make_app())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _at(microseconds: int = 0, *, minutes: int = 0) -> datetime:
    return _T0 + timedelta(minutes=minutes, microseconds=microseconds)


def _chat(db: FakeDb, account: Account, **fields: Any) -> uuid.UUID:
    return db.add_chat(account.user_id, title="Akten 190", title_source="user", **fields)


def _seed(
    db: FakeDb,
    chat_id: uuid.UUID,
    *,
    created_at: datetime,
    status: str = "ready",
    **fields: Any,
) -> uuid.UUID:
    """An attachments row of the chat in ``status`` (a ready one with a page count, an
    estimate and derived bytes; a failed one with ``corrupted_file``)."""
    ready = status == "ready"
    fields.setdefault("page_count", 3 if ready else None)
    fields.setdefault("token_estimate", 120 if ready else None)
    fields.setdefault("derived_bytes", 512 if ready else None)
    return db.add_attachment(
        chat_id,
        filename=f"{_NAME_MARK} {created_at.microsecond}.pdf",
        kind="pdf",
        size_bytes=2048,
        status=status,
        failure_reason="corrupted_file" if status == "failed" else None,
        created_at=created_at,
        **fields,
    )


def _list(
    client: TestClient, caller: Account | None, chat_id: uuid.UUID | str, **params: Any
) -> httpx.Response:
    headers = dict(caller.cookie) if caller is not None else {}
    return client.get(f"/api/chats/{chat_id}/attachments", params=params, headers=headers)


def _outcome(response: httpx.Response) -> tuple[int, Any]:
    try:
        body = response.json()
    except ValueError:
        body = response.text
    return response.status_code, body


def _ids(response: httpx.Response) -> list[str]:
    assert response.status_code == 200, response.text
    return [item["id"] for item in response.json()["attachments"]]


def _order(db: FakeDb, ids: list[uuid.UUID]) -> list[str]:
    """``ids`` in the list order: their rows' (created_at, id)."""
    keys: list[tuple[datetime, uuid.UUID]] = []
    for file_id in ids:
        row = db.attachment_row(file_id)
        assert row is not None
        keys.append((row["created_at"], plain(row["id"])))
    return [str(file_id) for _, file_id in sorted(keys)]


def _expected(db: FakeDb, file_id: uuid.UUID, *, active: bool) -> dict[str, Any]:
    """The AttachmentSummary of a stored row (created_at left out)."""
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
        "active": active,
        "context_report": None,
    }


def _statements(db: FakeDb, since: int, pattern: re.Pattern[str]) -> list[str]:
    return [call.normalized for call in db.calls[since:] if pattern.search(call.normalized)]


def _walk(
    client: TestClient, caller: Account, chat_id: uuid.UUID, **params: Any
) -> tuple[list[str], list[int]]:
    """Every page from the first: (the ids in order, each page's size)."""
    ids: list[str] = []
    sizes: list[int] = []
    cursor: str | None = None
    for _ in range(50):
        query = dict(params) if cursor is None else {**params, "cursor": cursor}
        response = _list(client, caller, chat_id, **query)
        assert response.status_code == 200, response.text
        page = response.json()
        ids.extend(item["id"] for item in page["attachments"])
        sizes.append(len(page["attachments"]))
        cursor = page["next_cursor"]
        if cursor is None:
            return ids, sizes
    raise AssertionError("the cursor walk never ended")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# 1. The list: items, order, what is left out
# ---------------------------------------------------------------------------


class TestAttachmentList:
    """The caller's live files of their own chat, oldest first, metadata only."""

    def test_chat_attachment_list_returns_the_chats_files_as_summaries_oldest_first(
        self, world: World, client: TestClient
    ) -> None:
        """A sent ready file, an excluded failed one and an unsent uploaded one, stored out
        of order: exactly their summaries (``active`` each one's flag, ``context_report``
        null), oldest first, and no next page."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        message = db.add_chat_message(chat_id, "user", "With a file")
        unsent = _seed(db, chat_id, created_at=_at(minutes=2), status="uploaded")
        excluded = _seed(db, chat_id, created_at=_at(minutes=1), status="failed", active=False)
        sent = _seed(db, chat_id, created_at=_at(), message_id=message)

        response = _list(client, editor, chat_id)

        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == {"attachments", "next_cursor"}
        assert body["next_cursor"] is None
        assert all(set(item) == _SUMMARY_KEYS for item in body["attachments"])
        assert [
            {key: value for key, value in item.items() if key != "created_at"}
            for item in body["attachments"]
        ] == [
            _expected(db, sent, active=True),
            _expected(db, excluded, active=False),
            _expected(db, unsent, active=True),
        ]
        assert [datetime.fromisoformat(item["created_at"]) for item in body["attachments"]] == [
            _at(),
            _at(minutes=1),
            _at(minutes=2),
        ]

    def test_chat_attachment_list_breaks_a_created_at_tie_by_id(
        self, world: World, client: TestClient
    ) -> None:
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        tied = [_seed(db, chat_id, created_at=_at()) for _ in range(4)]

        response = _list(client, editor, chat_id)

        assert _ids(response) == sorted(str(file_id) for file_id in tied)

    def test_chat_attachment_list_leaves_out_trashed_files_and_other_chats_files(
        self, world: World, client: TestClient
    ) -> None:
        """A trashed file of the chat, a file of the caller's other chat and one of a
        colleague's chat are not listed."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        live = _seed(db, chat_id, created_at=_at())
        _seed(db, chat_id, created_at=_at(1), deleted_at=_at(minutes=9))
        _seed(db, _chat(db, editor), created_at=_at(2))
        _seed(db, _chat(db, world.a["org_admin"]), created_at=_at(3))

        response = _list(client, editor, chat_id)

        assert _ids(response) == [str(live)]

    def test_chat_attachment_list_of_a_chat_without_files_is_empty(
        self, world: World, client: TestClient
    ) -> None:
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)

        response = _list(client, editor, chat_id)

        assert _outcome(response) == (200, {"attachments": [], "next_cursor": None})

    def test_chat_attachment_list_items_hold_metadata_only(
        self, world: World, root: Path, client: TestClient
    ) -> None:
        """A ready file whose stored bytes and converted text carry markers: the list
        shows neither (only the summary keys)."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        file_id = _seed(db, chat_id, created_at=_at())
        org_dir = root / str(editor.org_id)
        org_dir.mkdir(parents=True, exist_ok=True)
        (org_dir / str(file_id)).write_bytes(_BYTES_MARK.encode())
        assert editor.org_id is not None
        write_derived(
            root, editor.org_id, file_id, kind="pdf", parts=[("text", _TEXT_MARK, 1)], page_count=1
        )

        response = _list(client, editor, chat_id)

        assert response.status_code == 200, response.text
        assert [set(item) for item in response.json()["attachments"]] == [set(_SUMMARY_KEYS)]
        assert _BYTES_MARK not in response.text
        assert _TEXT_MARK not in response.text

    def test_chat_attachment_list_route_declares_its_response_model(self) -> None:
        from fastapi.routing import APIRoute

        from admino import models

        found = [
            (route.response_model, route.status_code or 200)
            for route in make_app().routes
            if isinstance(route, APIRoute)
            and route.path == "/api/chats/{chat_id}/attachments"
            and "GET" in route.methods
        ]

        assert found == [(models.AttachmentListResponse, 200)]


# ---------------------------------------------------------------------------
# 2. Paging
# ---------------------------------------------------------------------------


class TestAttachmentListPaging:
    """``limit`` 1 to 100 (default 50) and an opaque cursor."""

    def test_chat_attachment_list_limit_defaults_to_50_and_accepts_1_and_100(
        self, world: World, client: TestClient
    ) -> None:
        """101 files: the default page holds the oldest 50, ``limit=100`` the oldest 100
        and ``limit=1`` the oldest one, each with a cursor; the page after the 100 holds
        the last file and ends the walk."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        files = [_seed(db, chat_id, created_at=_at(n)) for n in range(101)]
        expected = [str(file_id) for file_id in files]

        default = _list(client, editor, chat_id)
        hundred = _list(client, editor, chat_id, limit=100)
        one = _list(client, editor, chat_id, limit=1)
        assert hundred.status_code == 200, hundred.text
        last = _list(client, editor, chat_id, limit=100, cursor=hundred.json()["next_cursor"])

        assert (_ids(default), default.json()["next_cursor"] is not None) == (expected[:50], True)
        assert (_ids(hundred), hundred.json()["next_cursor"] is not None) == (
            expected[:100],
            True,
        )
        assert (_ids(one), one.json()["next_cursor"] is not None) == (expected[:1], True)
        assert (_ids(last), last.json()["next_cursor"]) == (expected[100:], None)

    @pytest.mark.parametrize("limit", ["0", "101", "-1", "many"])
    def test_chat_attachment_list_limit_out_of_bounds_is_422(
        self, world: World, client: TestClient, limit: str
    ) -> None:
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        _seed(world.db, chat_id, created_at=_at())

        response = _list(client, editor, chat_id, limit=limit)

        assert response.status_code == 422, response.text
        assert all("input" not in error for error in response.json()["detail"])

    @pytest.mark.parametrize("limit", [1, 2, 3])
    def test_chat_attachment_list_cursor_walk_returns_every_file_once_in_order(
        self, world: World, client: TestClient, limit: int
    ) -> None:
        """Seven files, microseconds apart, three of them tied on ``created_at`` (the tie
        spans a page boundary at every limit): the walk returns each once, in
        (``created_at``, ``id``) order, in pages of ``limit``."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        stamps = [_at(0), _at(1), _at(2), _at(3), _at(3), _at(3), _at(4)]
        files = [_seed(db, chat_id, created_at=stamp) for stamp in reversed(stamps)]

        ids, sizes = _walk(client, editor, chat_id, limit=limit)

        assert ids == _order(db, files)
        assert sizes == [limit] * (7 // limit) + ([7 % limit] if 7 % limit else [])

    @pytest.mark.parametrize(
        "case",
        [
            "marker",
            "percent-signs",
            "b64-empty-object",
            "b64-list",
            "b64-null",
            "b64-other-object",
            "aaaa",
            "non-ascii",
            "cut-real-cursor",
            "message-cursor",
            "chat-list-cursor",
        ],
    )
    def test_chat_attachment_list_invalid_cursor_is_422_invalid_cursor_without_echo(
        self, world: World, client: TestClient, case: str
    ) -> None:
        """Anything but a cursor of this list is the 422 ``invalid_cursor``: the value
        never comes back and no statement on attachments runs."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        _seed(db, chat_id, created_at=_at())
        _seed(db, chat_id, created_at=_at(1))
        if case == "cut-real-cursor":
            real = _list(client, editor, chat_id, limit=1)
            assert real.status_code == 200, real.text
            cursor = str(real.json()["next_cursor"])[:-4]
        elif case == "message-cursor":
            db.add_chat_message(chat_id, "user", "one")
            db.add_chat_message(chat_id, "assistant", "two")
            detail = client.get(f"/api/chats/{chat_id}?limit=1", headers=editor.cookie)
            assert detail.status_code == 200, detail.text
            cursor = str(detail.json()["next_cursor"])
        elif case == "chat-list-cursor":
            _chat(db, editor)
            chats = client.get("/api/chats?limit=1", headers=editor.cookie)
            assert chats.status_code == 200, chats.text
            cursor = str(chats.json()["next_cursor"])
        else:
            cursor = {
                "marker": _ECHO,
                "percent-signs": "%%%",
                "b64-empty-object": _b64(b"{}"),
                "b64-list": _b64(b"[]"),
                "b64-null": _b64(b"null"),
                "b64-other-object": _b64(b'{"x":1}'),
                "aaaa": "AAAA",
                "non-ascii": "curs" + chr(0xE9) + "r",
            }[case]
        since = len(db.calls)

        response = _list(client, editor, chat_id, cursor=cursor)

        assert _outcome(response) == (422, _INVALID_CURSOR)
        assert cursor not in response.text
        assert _statements(db, since, _ATTACHMENTS_SQL) == []

    def test_chat_attachment_list_overlong_cursor_is_422_without_echo(
        self, world: World, client: TestClient
    ) -> None:
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)
        cursor = _ECHO + "A" * (201 - len(_ECHO))

        response = _list(client, editor, chat_id, cursor=cursor)

        assert response.status_code == 422, response.text
        assert all("input" not in error for error in response.json()["detail"])
        assert _ECHO not in response.text


# ---------------------------------------------------------------------------
# 3. Filters
# ---------------------------------------------------------------------------


def _one_of_each(db: FakeDb, chat_id: uuid.UUID) -> dict[str, uuid.UUID]:
    """One file per status (active) plus an excluded ready one, interleaved in time."""
    files = {
        status: _seed(db, chat_id, created_at=_at(index * 2), status=status)
        for index, status in enumerate(_STATUSES)
    }
    files["ready-excluded"] = _seed(db, chat_id, created_at=_at(3), active=False)
    return files


class TestAttachmentListFilters:
    """``status`` and ``active`` narrow the list, alone, together and across pages."""

    @pytest.mark.parametrize("status", _STATUSES)
    def test_chat_attachment_list_status_filter_lists_only_that_status(
        self, world: World, client: TestClient, status: str
    ) -> None:
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        files = _one_of_each(db, chat_id)
        wanted = [files[status], *([files["ready-excluded"]] if status == "ready" else [])]

        response = _list(client, editor, chat_id, status=status)

        assert _ids(response) == _order(db, wanted)

    @pytest.mark.parametrize(
        ("active", "names"),
        [
            pytest.param("true", [*_STATUSES], id="active"),
            pytest.param("false", ["ready-excluded"], id="excluded"),
        ],
    )
    def test_chat_attachment_list_active_filter_lists_only_that_flag(
        self, world: World, client: TestClient, active: str, names: list[str]
    ) -> None:
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        files = _one_of_each(db, chat_id)

        response = _list(client, editor, chat_id, active=active)

        assert _ids(response) == _order(db, [files[name] for name in names])

    def test_chat_attachment_list_status_and_active_filters_combine(
        self, world: World, client: TestClient
    ) -> None:
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        files = _one_of_each(db, chat_id)

        excluded_ready = _list(client, editor, chat_id, status="ready", active="false")
        active_ready = _list(client, editor, chat_id, status="ready", active="true")

        assert _ids(excluded_ready) == [str(files["ready-excluded"])]
        assert _ids(active_ready) == [str(files["ready"])]

    def test_chat_attachment_list_filters_hold_across_pages(
        self, world: World, client: TestClient
    ) -> None:
        """``status=ready`` with ``limit=1``: the walk returns the three ready files only,
        in order, though other files sit between them."""
        db = world.db
        editor = world.a["editor"]
        chat_id = _chat(db, editor)
        ready = [
            _seed(db, chat_id, created_at=_at(0)),
            _seed(db, chat_id, created_at=_at(2)),
            _seed(db, chat_id, created_at=_at(4)),
        ]
        _seed(db, chat_id, created_at=_at(1), status="uploaded")
        _seed(db, chat_id, created_at=_at(3), status="failed")
        _seed(db, chat_id, created_at=_at(5), status="processing")

        ids, sizes = _walk(client, editor, chat_id, limit=1, status="ready")

        assert (ids, sizes) == (_order(db, ready), [1, 1, 1])

    @pytest.mark.parametrize(
        "params",
        [
            pytest.param({"status": _ECHO}, id="unknown-status"),
            pytest.param({"status": "deleted"}, id="not-a-status"),
            pytest.param({"active": _ECHO}, id="active-not-a-bool"),
        ],
    )
    def test_chat_attachment_list_invalid_filter_is_422_without_echo(
        self, world: World, client: TestClient, params: dict[str, str]
    ) -> None:
        editor = world.a["editor"]
        chat_id = _chat(world.db, editor)

        response = _list(client, editor, chat_id, **params)

        assert response.status_code == 422, response.text
        assert all("input" not in error for error in response.json()["detail"])
        assert _ECHO not in response.text


# ---------------------------------------------------------------------------
# 4. Not found, roles, session, rate limit
# ---------------------------------------------------------------------------

_NOT_THE_CALLERS: Final = ["other-org", "colleague", "org-admin-on-editors", "trashed", "unknown"]


def _not_the_callers(world: World, case: str) -> tuple[Account, uuid.UUID]:
    """(caller, a chat id that isn't the caller's live chat), the chat holding a file."""
    a, b = world.a, world.b
    if case == "unknown":
        return a["editor"], uuid.uuid4()
    owner, caller = {
        "other-org": (b["editor"], a["editor"]),
        "colleague": (a["org_admin"], a["editor"]),
        "org-admin-on-editors": (a["editor"], a["org_admin"]),
        "trashed": (a["editor"], a["editor"]),
    }[case]
    fields = {"deleted_at": _at(minutes=30)} if case == "trashed" else {}
    chat_id = _chat(world.db, owner, **fields)
    _seed(world.db, chat_id, created_at=_at())
    return caller, chat_id


class TestAttachmentListAccess:
    """Only the chat's owner lists its files; everyone else learns nothing."""

    @pytest.mark.parametrize("case", _NOT_THE_CALLERS)
    def test_chat_attachment_list_chat_not_the_callers_is_one_404(
        self, world: World, client: TestClient, case: str
    ) -> None:
        """Another org's, a colleague's, an Editor's chat for the Org Admin, a trashed and
        an unknown chat: 404 ``chat_not_found``, no file name, no statement on
        attachments."""
        caller, chat_id = _not_the_callers(world, case)
        since = len(world.db.calls)

        response = _list(client, caller, chat_id)

        assert _outcome(response) == (404, _CHAT_NOT_FOUND)
        assert _NAME_MARK not in response.text
        assert _statements(world.db, since, _ATTACHMENTS_SQL) == []

    def test_chat_attachment_list_non_uuid_chat_id_is_422(
        self, world: World, client: TestClient
    ) -> None:
        response = _list(client, world.a["editor"], "not-a-uuid")

        assert response.status_code == 422, response.text

    def test_chat_attachment_list_super_admin_is_403_and_sees_no_name(
        self, world: World, client: TestClient
    ) -> None:
        """The Super Admin (no chat.send) on an Editor's chat (operator blindness):
        exactly 403 Forbidden, no statement on chats or attachments, no file name."""
        chat_id = _chat(world.db, world.a["editor"])
        _seed(world.db, chat_id, created_at=_at())
        since = len(world.db.calls)

        response = _list(client, world.super_admin, chat_id)

        assert _outcome(response) == (403, FORBIDDEN)
        assert _statements(world.db, since, _CHAT_TABLES_SQL) == []
        assert _NAME_MARK not in response.text

    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    def test_chat_attachment_list_org_admin_and_editor_list_their_own(
        self, world: World, client: TestClient, role: MemberRole
    ) -> None:
        caller = world.a[role]
        chat_id = _chat(world.db, caller)
        file_id = _seed(world.db, chat_id, created_at=_at())

        response = _list(client, caller, chat_id)

        assert _ids(response) == [str(file_id)]

    def test_chat_attachment_list_without_a_session_is_401(
        self, world: World, client: TestClient
    ) -> None:
        chat_id = _chat(world.db, world.a["editor"])

        response = _list(client, None, chat_id)

        assert _outcome(response) == (401, UNAUTHORIZED)

    def test_chat_attachment_list_rate_limit_key_has_the_contract_value(self) -> None:
        assert server._RATE_LIMITS.get(_LIST_KEY) == (1.0, 10)

    def test_chat_attachment_list_rate_limit_is_per_user(
        self, world: World, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Burst 1 on ``/api/chats/attachments/list``: the Editor's second list is 429, the
        Org Admin still lists; the bucket is (route key, ``user:<id>``)."""
        monkeypatch.setitem(server._RATE_LIMITS, _LIST_KEY, (0.001, 1))
        editor, admin = world.a["editor"], world.a["org_admin"]
        chat_id = _chat(world.db, editor)
        other_chat = _chat(world.db, admin)

        first = _list(client, editor, chat_id)
        limited = _list(client, editor, chat_id)
        colleague = _list(client, admin, other_chat)

        assert first.status_code == 200, first.text
        assert _outcome(limited) == (429, _RATE_LIMITED)
        assert colleague.status_code == 200, colleague.text
        assert (_LIST_KEY, f"user:{editor.user_id}") in server._rate_buckets
