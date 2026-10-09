"""Tests for admino.trash: the member's trash service (GH-194, contract sections 2, 4, 5, 7).

Issue #194 (Decisions 1 to 7, 9 and 10) and its contract pin a new module
``admino.trash`` over migration 0031's trash groups. These tests cover the
member-facing functions (the retention purge job is tests/test_trash_purge_job.py):

- ``list_trash``: the caller's own items only (chats, and files of their own:
  a file that went to the trash with its chat is not an item), ``name`` (the
  title, empty allowed, or the file name), ``chat_id``, newest deletion first
  with the id breaking ties across both tables, ``limit`` and a keyset
  ``next_cursor`` across both tables (no item lost or repeated), the
  ``item_type`` filter (only the needed statement runs), a chat, message or
  attachment-list cursor and garbage are ``InvalidCursorError`` before any
  statement, ``retention_days`` / ``expires_at`` from the effective retention
  (30 without an org_settings row, the stored value, clamped into the
  platform's bounds), expiry at ``deleted_at <= now - retention`` exactly,
  retention 0 lists nothing, the contract's T1c / T1a forms (T1c' / T1a'
  after a cursor), nothing recorded.
- ``restore_chat``: the chat and exactly its group come back, every other
  column kept (activity time, message links, the exclusion flag); one
  ``chat.restore`` event in the same transaction; the caller's live chat is
  answered with nothing recorded; expired, another org's, a colleague's (an
  Org Admin's tenant on an Editor's chat included) and unknown chats are
  ``ChatNotFoundError`` with nothing changed; the legacy session key is
  ``RestoreConflictError``; an audit failure rolls back.
- ``restore_attachment``: a file of its own comes back (columns kept), its
  chat in the trash is ``ChatInTrashError``, a file of a chat's group is not
  found, a live file is answered with nothing recorded, expired / foreign /
  unknown are not found, ``file.restore``, A2 runs before T6.
- ``purge_chat`` / ``purge_attachment``: only items in the trash (expired ones
  included); the rows go (a chat's messages and every file of the chat) and,
  after the commit, exactly those files' ``<id>``, ``<id>.part`` and
  ``<id>.d/`` under ``root/<org_id>/`` (nothing else on disk changes);
  ``chat.purge`` with ``{"file_count": n}`` / ``file.purge``; an audit
  failure keeps rows and files.
- ``empty_trash``: every chat, then every file of its own, counted; another
  user's and another org's trash untouched; an item restored meanwhile is
  skipped and not counted; an empty trash is (0, 0).
- ``delete_chat`` / ``delete_attachment``: retention above 0 trashes only
  (False); retention 0 trashes and purges in the call (True, events delete
  then purge); a failing purge step leaves the item trashed (False) with one
  content-free warning; a failing retention read changes nothing.
- Logs: no title, file name or path in any record (canary values).

Harness: the real service over tests/db_fakes.py's FakeDb (migration 0031's
schema once it ships: the trash group column, CHECKs and grants, every
contract form, the chat DELETE cascade) and a ``tmp_path`` attachments root.
Time is injected (``now=``) and rows carry fixed ``deleted_at`` stamps.

Security notes:
- Owner-only V1 trash (Decision 1): every case of another org, another user
  and an Org Admin on an Editor's item answers the same not-found error and
  changes nothing (no row, no file, no event).
- Titles and file names are canaries: they never reach a log record.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import shutil
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import asyncpg
import pytest

from admino import attachments, chats, organizations, scoped_settings
from admino.access import MemberRole, Principal
from admino.audit_events import AuditRecordError
from admino.models import PlatformRetention
from admino.tenancy import TenantContext
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, Call, FakeDb, norm, plain

if TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP: Final = "203.0.113.194"
NOW: Final = datetime(2026, 10, 9, 12, 0, 0, 500000, tzinfo=UTC)
_US: Final = timedelta(microseconds=1)
_DAY: Final = timedelta(days=1)
_DEFAULT_RETENTION: Final = 30
_ACTIVITY: Final = datetime(2026, 9, 20, 7, 15, 0, 654321, tzinfo=UTC)
_CREATED: Final = datetime(2026, 9, 1, 8, 0, 0, 250000, tzinfo=UTC)
_UNKNOWN: Final = uuid.UUID("5d3c2b1a-0f9e-4d8c-a7b6-c5d4e3f2a1b0")
_SESSION: Final = "legacy-sess_194"
# Canaries: a title and file names are user content; no log record carries them.
_CANARY_TITLE: Final = "Canary-Title-Zebra-4711"
_CANARY_FILE: Final = "canary-file-quokka-4711.pdf"
_OLDER_FILE: Final = "older-canary-heron-4711.txt"
_CHAT_IN_TRASH_TEXT: Final = "The file's chat is in the trash."
_RESTORE_CONFLICT_TEXT: Final = "A live chat already uses this chat's session."

# Contract section 5, verbatim (whitespace free, tokens and their order not).
_T1C_HEAD: Final = (
    "SELECT id, title, deleted_at FROM chats WHERE org_id = $1 AND owner_user_id = $2"
    " AND deleted_at > $3 AND trash_group_id = id"
)
_T1C: Final = _T1C_HEAD + " ORDER BY deleted_at DESC, id DESC LIMIT $4"
_T1C_AFTER: Final = (
    _T1C_HEAD + " AND (deleted_at, id) < ($4, $5) ORDER BY deleted_at DESC, id DESC LIMIT $6"
)
_T1A_HEAD: Final = (
    "SELECT id, filename, chat_id, deleted_at FROM attachments WHERE org_id = $1"
    " AND owner_user_id = $2 AND deleted_at > $3 AND trash_group_id = id"
)
_T1A: Final = _T1A_HEAD + " ORDER BY deleted_at DESC, id DESC LIMIT $4"
_T1A_AFTER: Final = (
    _T1A_HEAD + " AND (deleted_at, id) < ($4, $5) ORDER BY deleted_at DESC, id DESC LIMIT $6"
)
_A2: Final = (
    "SELECT id FROM chats WHERE id = $1 AND org_id = $2 AND owner_user_id = $3"
    " AND deleted_at IS NULL FOR SHARE"
)
_CR_COLUMNS: Final = (
    "id",
    "org_id",
    "owner_user_id",
    "title",
    "title_source",
    "external_content",
    "created_at",
    "last_activity_at",
)
_AR_COLUMNS: Final = (
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
    "created_at",
)
_TRASH_COLUMNS: Final = frozenset({"deleted_at", "trash_group_id"})


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def trash() -> ModuleType:
    """admino.trash, imported per test (the module is new in GH-194)."""
    from admino import trash as module

    return module


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database."""
    return FakeDb()


@pytest.fixture()
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty attachments root (also ``organizations.ATTACHMENTS_ROOT``)."""
    path = tmp_path / "attachments-root"
    path.mkdir()
    monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", path)
    return path


@dataclass(frozen=True)
class _Member:
    """A stored member and the TenantContext of their session."""

    user_id: uuid.UUID
    tenant: TenantContext


def _member(db: FakeDb, *, org_id: uuid.UUID = ORG_ID, role: MemberRole = "editor") -> _Member:
    user_id = db.add_account(org_id=org_id, role=role)
    principal = Principal(user_id=user_id, kind="member", org_id=org_id, role=role)
    return _Member(user_id, TenantContext.from_principal(principal))


@dataclass(frozen=True)
class _People:
    """Alice and Bob (Editors) and an Org Admin of ORG_ID; Carol of OTHER_ORG_ID."""

    alice: _Member
    bob: _Member
    admin: _Member
    carol: _Member


def _people(db: FakeDb) -> _People:
    return _People(
        alice=_member(db),
        bob=_member(db),
        admin=_member(db, role="org_admin"),
        carol=_member(db, org_id=OTHER_ORG_ID),
    )


def _chat(
    db: FakeDb,
    owner: _Member,
    *,
    deleted_at: datetime | None = None,
    title: str = "",
    chat_id: uuid.UUID | None = None,
    **fields: Any,
) -> uuid.UUID:
    """A chat of ``owner`` (trashed as its own group when ``deleted_at`` is given)."""
    return db.add_chat(
        owner.user_id,
        chat_id=chat_id,
        title=title,
        title_source="user" if title else "auto",
        created_at=_CREATED,
        last_activity_at=_ACTIVITY,
        deleted_at=deleted_at,
        **fields,
    )


def _file(
    db: FakeDb,
    chat_id: uuid.UUID,
    *,
    deleted_at: datetime | None = None,
    own_group: bool = False,
    attachment_id: uuid.UUID | None = None,
    **fields: Any,
) -> uuid.UUID:
    """A file of the chat. Trashed: with its chat's group by default (0031's backfill),
    or as its own item (``own_group``: deleted on its own)."""
    attachment_id = attachment_id or uuid.uuid4()
    extra: dict[str, Any] = {}
    if own_group:
        extra["trash_group_id"] = attachment_id
    return db.add_attachment(
        chat_id,
        attachment_id=attachment_id,
        created_at=_CREATED,
        deleted_at=deleted_at,
        **extra,
        **fields,
    )


def _retention(db: FakeDb, org_id: uuid.UUID, days: int) -> None:
    """Store the org's trash retention (its org_settings row)."""
    db.add_org_settings(org_id, trash_retention_days=days)


def _bounds(monkeypatch: pytest.MonkeyPatch, low: int, high: int) -> None:
    """Narrow the platform's trash bounds (the cached platform settings)."""
    current = scoped_settings._platform_cache
    assert current is not None
    narrowed = current.model_copy(
        update={"retention": PlatformRetention(trash_min_days=low, trash_max_days=high)}
    )
    monkeypatch.setattr(scoped_settings, "_platform_cache", narrowed)


def _plain_args(call: Call) -> list[Any]:
    """A call's bind values, UUIDs as plain uuid.UUID."""
    return [plain(arg) if isinstance(arg, uuid.UUID) else arg for arg in call.args]


def _tokens(sql: str) -> str:
    """The SQL with whitespace collapsed, lowercased and none around punctuation."""
    return re.sub(r"\s*([(),=<>])\s*", r"\1", norm(sql))


def _audit(db: FakeDb) -> list[dict[str, Any]]:
    """The stored audit rows as comparable dicts."""
    return [
        {
            "action": row["action"],
            "actor_kind": row["actor_kind"],
            "actor_user_id": None if row["actor_user_id"] is None else plain(row["actor_user_id"]),
            "org_id": plain(row["org_id"]),
            "target_type": row["target_type"],
            "target_ids": row["target_ids"],
            "ip": row["ip"],
            "metadata": row["metadata"],
        }
        for row in db.audit
    ]


def _event(
    action: str,
    member: _Member,
    target_type: str,
    target: uuid.UUID,
    *,
    ip: str | None = _IP,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "action": action,
        "actor_kind": "member",
        "actor_user_id": member.user_id,
        "org_id": member.tenant.org_id,
        "target_type": target_type,
        "target_ids": [str(target)],
        "ip": ip,
        "metadata": metadata or {},
    }


def _items(page: Any) -> list[tuple[Any, ...]]:
    """A page's items as (type, id, name, chat_id, deleted_at, expires_at)."""
    return [
        (
            item.item_type,
            plain(item.id),
            item.name,
            None if item.chat_id is None else plain(item.chat_id),
            item.deleted_at,
            item.expires_at,
        )
        for item in page.items
    ]


def _ids(page: Any) -> list[uuid.UUID]:
    return [plain(item.id) for item in page.items]


def _plant(root: Path, org_id: uuid.UUID, attachment_id: uuid.UUID) -> None:
    """An attachment's original, partial upload and derived tree under ``root/<org_id>``."""
    org_dir = root / str(org_id)
    pages = org_dir / f"{attachment_id}.d" / "pages"
    pages.mkdir(parents=True, exist_ok=True)
    (org_dir / str(attachment_id)).write_bytes(b"original " + attachment_id.bytes)
    (org_dir / f"{attachment_id}.part").write_bytes(b"partial upload")
    (org_dir / f"{attachment_id}.d" / "text.txt").write_bytes(b"extracted text")
    (pages / "page-1.png").write_bytes(b"rendered page")


def _disk(root: Path) -> dict[str, bytes | None]:
    """Every entry under the root: relative path -> bytes (None for a directory)."""
    return {
        path.relative_to(root).as_posix(): (path.read_bytes() if path.is_file() else None)
        for path in sorted(root.rglob("*"))
    }


def _without(
    disk: dict[str, bytes | None], org_id: uuid.UUID, removed: list[uuid.UUID]
) -> dict[str, bytes | None]:
    """The disk minus each removed id's ``<id>``, ``<id>.part`` and ``<id>.d`` tree."""

    def gone(path: str) -> bool:
        for attachment_id in removed:
            base = f"{org_id}/{attachment_id}"
            if path in (base, f"{base}.part", f"{base}.d") or path.startswith(f"{base}.d/"):
                return True
        return False

    return {path: content for path, content in disk.items() if not gone(path)}


def _row_minus_trash(row: dict[str, Any] | None) -> dict[str, Any]:
    assert row is not None
    return {key: value for key, value in row.items() if key not in _TRASH_COLUMNS}


def _live(row: dict[str, Any] | None) -> bool:
    assert row is not None
    return row["deleted_at"] is None and row["trash_group_id"] is None


def _removal_probe(monkeypatch: pytest.MonkeyPatch, db: FakeDb) -> list[int]:
    """Record ``db.open_transactions`` at every file or tree removal."""
    seen: list[int] = []
    real_unlink = os.unlink
    real_rmtree = shutil.rmtree

    def unlink(path: Any, *args: Any, **kwargs: Any) -> None:
        seen.append(db.open_transactions)
        real_unlink(path, *args, **kwargs)

    def rmtree(path: Any, *args: Any, **kwargs: Any) -> None:
        seen.append(db.open_transactions)
        real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", unlink)
    monkeypatch.setattr(shutil, "rmtree", rmtree)
    return seen


# ---------------------------------------------------------------------------
# 1. list_trash
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ListWorld:
    people: _People
    live_chat: uuid.UUID
    live_file: uuid.UUID
    chat_titled: uuid.UUID  # trashed 1 day ago, the canary title
    chat_untitled: uuid.UUID  # trashed 2 days ago, title ""
    group_file: uuid.UUID  # went to the trash with chat_untitled
    own_file: uuid.UUID  # in the live chat, trashed on its own 3 days ago
    own_file_of_trashed_chat: uuid.UUID  # trashed on its own 4 days ago, its chat later


def _list_world(db: FakeDb) -> _ListWorld:
    people = _people(db)
    alice = people.alice
    live_chat = _chat(db, alice, title="Live plans")
    untitled = _chat(db, alice, deleted_at=NOW - 2 * _DAY)
    world = _ListWorld(
        people=people,
        live_chat=live_chat,
        live_file=_file(db, live_chat),
        chat_titled=_chat(db, alice, deleted_at=NOW - _DAY, title=_CANARY_TITLE),
        chat_untitled=untitled,
        group_file=_file(db, untitled, deleted_at=NOW - 2 * _DAY),
        own_file=_file(
            db, live_chat, deleted_at=NOW - 3 * _DAY, own_group=True, filename=_CANARY_FILE
        ),
        own_file_of_trashed_chat=_file(
            db, untitled, deleted_at=NOW - 4 * _DAY, own_group=True, filename=_OLDER_FILE
        ),
    )
    for other in (people.bob, people.admin, people.carol):
        chat = _chat(db, other, deleted_at=NOW - _DAY / 2, title="Someone else's")
        _file(db, _chat(db, other), deleted_at=NOW - _DAY / 3, own_group=True)
        _file(db, chat, deleted_at=NOW - _DAY / 2)
    return world


class TestListTrash:
    """The caller's own items, newest deletion first, keyset-paginated."""

    async def test_trash_list_returns_the_callers_chats_and_files_of_their_own(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """Alice's trashed chats (a title, an empty title) and her files of their own
        (one in a live chat, one in a trashed chat), newest first, each with its name,
        chat id and expiry; the file that went with its chat, live items and everyone
        else's trash are not listed."""
        world = _list_world(db)
        expires = timedelta(days=_DEFAULT_RETENTION)

        page = await trash.list_trash(
            db.pool, world.people.alice.tenant, limit=50, cursor=None, item_type=None, now=NOW
        )

        assert type(page) is trash.TrashPage
        assert _items(page) == [
            ("chat", world.chat_titled, _CANARY_TITLE, None, NOW - _DAY, NOW - _DAY + expires),
            ("chat", world.chat_untitled, "", None, NOW - 2 * _DAY, NOW - 2 * _DAY + expires),
            (
                "attachment",
                world.own_file,
                _CANARY_FILE,
                world.live_chat,
                NOW - 3 * _DAY,
                NOW - 3 * _DAY + expires,
            ),
            (
                "attachment",
                world.own_file_of_trashed_chat,
                _OLDER_FILE,
                world.chat_untitled,
                NOW - 4 * _DAY,
                NOW - 4 * _DAY + expires,
            ),
        ]
        assert (page.next_cursor, page.retention_days) == (None, _DEFAULT_RETENTION)

    @pytest.mark.parametrize("who", ["bob", "admin", "carol"])
    async def test_trash_list_never_shows_anyone_elses_items(
        self, trash: ModuleType, db: FakeDb, who: str
    ) -> None:
        """A colleague, the Org Admin and another org's member each see only their own
        trashed chat and file, never Alice's."""
        world = _list_world(db)
        member: _Member = getattr(world.people, who)

        page = await trash.list_trash(
            db.pool, member.tenant, limit=50, cursor=None, item_type=None, now=NOW
        )

        alice_ids = {
            world.chat_titled,
            world.chat_untitled,
            world.own_file,
            world.own_file_of_trashed_chat,
            world.group_file,
        }
        assert [item[0] for item in _items(page)] == ["attachment", "chat"]
        assert not alice_ids & set(_ids(page))
        for item_id in _ids(page):
            row = db.chat_row(item_id) or db.attachment_row(item_id)
            assert row is not None
            assert plain(row["owner_user_id"]) == member.user_id

    async def test_trash_list_breaks_deletion_time_ties_by_id_across_both_tables(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """Two items deleted at the same instant (a chat and a file) come by id
        descending, whichever table each lives in."""
        alice = _member(db)
        live = _chat(db, alice)
        stamp = NOW - _DAY
        chat_low = _chat(db, alice, deleted_at=stamp, chat_id=uuid.UUID(int=0x4 << 124))
        file_high = _file(
            db, live, deleted_at=stamp, own_group=True, attachment_id=uuid.UUID(int=0x8 << 124)
        )
        chat_high = _chat(db, alice, deleted_at=stamp - _US, chat_id=uuid.UUID(int=0xC << 124))
        file_low = _file(
            db,
            live,
            deleted_at=stamp - _US,
            own_group=True,
            attachment_id=uuid.UUID(int=0x2 << 124),
        )

        page = await trash.list_trash(
            db.pool, alice.tenant, limit=50, cursor=None, item_type=None, now=NOW
        )

        assert _ids(page) == [file_high, chat_low, chat_high, file_low]

    @pytest.mark.parametrize("limit", [1, 2, 3, 6, 7, 50])
    async def test_trash_list_cursor_walk_returns_every_item_once_in_order(
        self, trash: ModuleType, db: FakeDb, limit: int
    ) -> None:
        """Seven items a microsecond apart with ties across both tables: walking the
        cursors gives each exactly once in order, every page holds at most ``limit``
        items, and only the last page has no cursor (exactly ``limit`` left included)."""
        alice = _member(db)
        live = _chat(db, alice)
        stamp = NOW - _DAY
        stamps = [stamp, stamp, stamp - _US, stamp - _US, stamp - 2 * _US, stamp - 2 * _US]
        expected: list[tuple[datetime, uuid.UUID]] = []
        for index, deleted_at in enumerate([*stamps, stamp - 3 * _US]):
            if index % 2 == 0:
                item_id = _chat(db, alice, deleted_at=deleted_at)
            else:
                item_id = _file(db, live, deleted_at=deleted_at, own_group=True)
            expected.append((deleted_at, item_id))
        expected.sort(reverse=True)

        walked: list[uuid.UUID] = []
        cursors: list[str | None] = []
        cursor: str | None = None
        for _ in range(10):
            page = await trash.list_trash(
                db.pool, alice.tenant, limit=limit, cursor=cursor, item_type=None, now=NOW
            )
            assert 1 <= len(page.items) <= limit
            walked += _ids(page)
            cursors.append(page.next_cursor)
            cursor = page.next_cursor
            if cursor is None:
                break

        assert walked == [item_id for _, item_id in expected]
        assert all(isinstance(c, str) and 0 < len(c) <= 200 for c in cursors[:-1])
        assert cursors[-1] is None

    @pytest.mark.parametrize("item_type", ["chat", "attachment"])
    async def test_trash_list_item_type_filter_runs_only_that_tables_form(
        self, trash: ModuleType, db: FakeDb, item_type: str
    ) -> None:
        """``item_type`` lists only that type (walked with limit 1, the cursor form
        included), and no statement names the other table."""
        world = _list_world(db)
        db.calls.clear()

        walked: list[tuple[Any, ...]] = []
        cursor: str | None = None
        for _ in range(5):
            page = await trash.list_trash(
                db.pool,
                world.people.alice.tenant,
                limit=1,
                cursor=cursor,
                item_type=item_type,
                now=NOW,
            )
            walked += _items(page)
            cursor = page.next_cursor
            if cursor is None:
                break

        wanted = {
            "chat": [world.chat_titled, world.chat_untitled],
            "attachment": [world.own_file, world.own_file_of_trashed_chat],
        }[item_type]
        other_table = r"\bfrom attachments\b" if item_type == "chat" else r"\bfrom chats\b"
        assert [(item[0], item[1]) for item in walked] == [(item_type, i) for i in wanted]
        assert db.matching(other_table) == []

    async def test_trash_list_runs_the_contracts_t1_forms_with_the_cutoff(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """No cursor: T1c and T1a bound to (org, caller, now - 30 days, limit + 1);
        after a cursor: T1c' and T1a' with the last item's (deleted_at, id). Only
        SELECTs run and nothing is recorded."""
        world = _list_world(db)
        alice = world.people.alice
        cutoff = NOW - timedelta(days=_DEFAULT_RETENTION)
        db.calls.clear()

        first = await trash.list_trash(
            db.pool, alice.tenant, limit=1, cursor=None, item_type=None, now=NOW
        )
        first_calls = list(db.calls)
        db.calls.clear()
        await trash.list_trash(
            db.pool, alice.tenant, limit=1, cursor=first.next_cursor, item_type=None, now=NOW
        )
        second_calls = list(db.calls)

        def forms(calls: list[Call]) -> list[tuple[str, list[Any]]]:
            return [
                (_tokens(call.sql), _plain_args(call))
                for call in calls
                if re.search(r"\bfrom (chats|attachments)\b", call.normalized)
            ]

        scope = [ORG_ID, alice.user_id, cutoff]
        assert sorted(forms(first_calls)) == sorted(
            [(_tokens(_T1C), [*scope, 2]), (_tokens(_T1A), [*scope, 2])]
        )
        position = [NOW - _DAY, world.chat_titled]
        assert sorted(forms(second_calls)) == sorted(
            [
                (_tokens(_T1C_AFTER), [*scope, *position, 2]),
                (_tokens(_T1A_AFTER), [*scope, *position, 2]),
            ]
        )
        assert all(call.normalized.startswith("select") for call in first_calls + second_calls)
        assert db.audit == []

    async def test_trash_list_foreign_or_garbage_cursors_are_invalid_before_any_statement(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """A real chat-list, message and attachment-list cursor, a trash cursor whose
        stamp has no UTC equivalent and garbage: each InvalidCursorError, no statement."""
        alice = _member(db)
        chat_a = _chat(db, alice)
        _chat(db, alice)
        db.add_chat_message(chat_a, "user", "first")
        db.add_chat_message(chat_a, "assistant", "second")
        _file(db, chat_a)
        _file(db, chat_a)
        chat_page = await chats.list_chats(db.pool, alice.tenant, limit=1, cursor=None)
        detail = await chats.read_chat_detail(db.pool, alice.tenant, chat_a, limit=1, cursor=None)
        files = await attachments.list_chat_attachments(
            db.pool, alice.tenant, chat_a, limit=1, cursor=None, status=None, active=None
        )

        def encoded(value: object) -> str:
            raw = json.dumps(value).encode()
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        unbindable = encoded(
            {"kind": "trash", "deleted_at": "0001-01-01T00:00:00+23:00", "id": str(_UNKNOWN)}
        )
        cursors = [
            chat_page.next_cursor,
            detail.page.next_cursor,
            files.next_cursor,
            unbindable,
            encoded({"kind": "chats", "deleted_at": NOW.isoformat(), "id": str(_UNKNOWN)}),
            "not-a-cursor!",
            "%%%",
            encoded({}),
            "AAAA",
            "A" * 201,
        ]
        assert all(isinstance(cursor, str) for cursor in cursors)
        db.calls.clear()

        for cursor in cursors:
            with pytest.raises(chats.InvalidCursorError):
                await trash.list_trash(
                    db.pool, alice.tenant, limit=10, cursor=cursor, item_type=None, now=NOW
                )

        assert db.calls == []

    @pytest.mark.parametrize(
        ("stored", "bounds", "effective"),
        [
            (None, None, 30),
            (7, None, 7),
            (60, (0, 45), 45),
            (3, (10, 90), 10),
        ],
        ids=["no-row", "stored-7", "clamped-to-max", "clamped-to-min"],
    )
    async def test_trash_list_retention_and_expiry_follow_the_effective_retention(
        self,
        trash: ModuleType,
        db: FakeDb,
        monkeypatch: pytest.MonkeyPatch,
        stored: int | None,
        bounds: tuple[int, int] | None,
        effective: int,
    ) -> None:
        """``retention_days`` is the org's stored value (30 without a row) clamped into
        the platform's bounds; each ``expires_at`` is ``deleted_at`` plus it."""
        alice = _member(db)
        if stored is not None:
            _retention(db, ORG_ID, stored)
        if bounds is not None:
            _bounds(monkeypatch, *bounds)
        live = _chat(db, alice)
        chat_id = _chat(db, alice, deleted_at=NOW - _DAY)
        file_id = _file(db, live, deleted_at=NOW - 2 * _DAY, own_group=True)

        page = await trash.list_trash(
            db.pool, alice.tenant, limit=50, cursor=None, item_type=None, now=NOW
        )

        days = timedelta(days=effective)
        assert page.retention_days == effective
        assert [(plain(item.id), item.expires_at) for item in page.items] == [
            (chat_id, NOW - _DAY + days),
            (file_id, NOW - 2 * _DAY + days),
        ]

    async def test_trash_list_hides_items_expired_at_the_boundary(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """Deleted exactly ``retention`` days before now: expired and not listed; one
        microsecond later: listed (chats and files alike)."""
        alice = _member(db)
        live = _chat(db, alice)
        boundary = NOW - timedelta(days=_DEFAULT_RETENTION)
        _chat(db, alice, deleted_at=boundary)
        _file(db, live, deleted_at=boundary, own_group=True)
        chat_in = _chat(db, alice, deleted_at=boundary + _US, chat_id=uuid.UUID(int=1))
        file_in = _file(
            db, live, deleted_at=boundary + _US, own_group=True, attachment_id=uuid.UUID(int=2)
        )

        page = await trash.list_trash(
            db.pool, alice.tenant, limit=50, cursor=None, item_type=None, now=NOW
        )

        assert _ids(page) == [file_in, chat_in]

    async def test_trash_list_with_retention_zero_lists_nothing(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """Retention 0: the cutoff is now, every trashed item is expired."""
        alice = _member(db)
        _retention(db, ORG_ID, 0)
        live = _chat(db, alice)
        _chat(db, alice, deleted_at=NOW - _US)
        _file(db, live, deleted_at=NOW - _US, own_group=True)

        page = await trash.list_trash(
            db.pool, alice.tenant, limit=50, cursor=None, item_type=None, now=NOW
        )

        assert (page.items, page.next_cursor, page.retention_days) == ([], None, 0)


# ---------------------------------------------------------------------------
# 2. restore_chat
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _RestoreWorld:
    people: _People
    chat: uuid.UUID  # Alice's, trashed 2 days ago with two files (its group)
    message: uuid.UUID
    sent_file: uuid.UUID  # in the group: sent with the message, excluded, ready
    unsent_file: uuid.UUID  # in the group: unsent
    own_file: uuid.UUID  # trashed on its own 5 days ago, before the chat
    other_chat: uuid.UUID  # Alice's other trashed chat with a file of its group
    other_file: uuid.UUID


def _restore_world(db: FakeDb) -> _RestoreWorld:
    people = _people(db)
    alice = people.alice
    chat = _chat(
        db, alice, deleted_at=NOW - 2 * _DAY, title="Restored plans", external_content=True
    )
    message = db.add_chat_message(chat, "user", "with a file")
    db.add_chat_message(chat, "assistant", "seen")
    other_chat = _chat(db, alice, deleted_at=NOW - 3 * _DAY)
    return _RestoreWorld(
        people=people,
        chat=chat,
        message=message,
        sent_file=_file(
            db,
            chat,
            deleted_at=NOW - 2 * _DAY,
            message_id=message,
            status="ready",
            active=False,
            token_estimate=40,
            page_count=2,
        ),
        unsent_file=_file(db, chat, deleted_at=NOW - 2 * _DAY),
        own_file=_file(db, chat, deleted_at=NOW - 5 * _DAY, own_group=True),
        other_chat=other_chat,
        other_file=_file(db, other_chat, deleted_at=NOW - 3 * _DAY),
    )


class TestRestoreChat:
    """The chat and exactly its group come back, audited, or nothing changes."""

    async def test_trash_restore_chat_brings_back_the_chat_and_exactly_its_group(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """The chat and its two group files are live again with every other column as
        it was (activity time, message link, exclusion flag, status); the file trashed
        on its own and Alice's other trashed chat stay in the trash."""
        world = _restore_world(db)
        group = (world.chat, world.sent_file, world.unsent_file)
        kept = {
            item: (db.chat_row(item) or db.attachment_row(item))
            for item in (world.own_file, world.other_chat, world.other_file)
        }
        columns = {
            world.chat: _row_minus_trash(db.chat_row(world.chat)),
            world.sent_file: _row_minus_trash(db.attachment_row(world.sent_file)),
            world.unsent_file: _row_minus_trash(db.attachment_row(world.unsent_file)),
        }

        record = await trash.restore_chat(
            db.pool, world.people.alice.tenant, world.chat, ip=_IP, now=NOW
        )

        assert type(record) is chats.ChatRecord
        stored = db.chat_row(world.chat)
        assert stored is not None
        assert record.model_dump() == {column: stored[column] for column in _CR_COLUMNS}
        assert record.last_activity_at == _ACTIVITY
        assert all(_live(db.chat_row(item) or db.attachment_row(item)) for item in group)
        assert {
            world.chat: _row_minus_trash(db.chat_row(world.chat)),
            world.sent_file: _row_minus_trash(db.attachment_row(world.sent_file)),
            world.unsent_file: _row_minus_trash(db.attachment_row(world.unsent_file)),
        } == columns
        assert {item: (db.chat_row(item) or db.attachment_row(item)) for item in kept} == kept
        assert [row["seq"] for row in db.messages_of(world.chat)] == [1, 2]

    @pytest.mark.parametrize("ip", [_IP, None])
    async def test_trash_restore_chat_records_one_chat_restore_in_its_transaction(
        self, trash: ModuleType, db: FakeDb, ip: str | None
    ) -> None:
        """One ``chat.restore`` (the member, the chat, the client IP, no metadata) on the
        connection and committed transaction of the chat's restore."""
        world = _restore_world(db)
        alice = world.people.alice
        db.calls.clear()

        await trash.restore_chat(db.pool, alice.tenant, world.chat, ip=ip, now=NOW)

        assert _audit(db) == [_event("chat.restore", alice, "chat", world.chat, ip=ip)]
        (restore,) = db.matching(r"^update chats set deleted_at = null\b")
        (audit,) = db.matching(r"^insert into audit_events\b")
        assert restore.tx is not None
        assert (restore.via, restore.tx) == (audit.via, audit.tx)
        assert (restore.tx, "commit") in db.transactions

    async def test_trash_restore_chat_of_a_live_chat_answers_it_and_records_nothing(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """The caller's live chat: its record, no event, nothing changed (idempotent)."""
        alice = _member(db)
        chat_id = _chat(db, alice, title="Already live")
        before = db.snapshot()

        record = await trash.restore_chat(db.pool, alice.tenant, chat_id, ip=_IP, now=NOW)

        stored = db.chat_row(chat_id)
        assert stored is not None
        assert record.model_dump() == {column: stored[column] for column in _CR_COLUMNS}
        assert db.snapshot() == before

    async def test_trash_restore_chat_one_microsecond_before_expiry_restores_it(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """Deleted 30 days minus a microsecond ago: still restorable."""
        alice = _member(db)
        chat_id = _chat(db, alice, deleted_at=NOW - timedelta(days=_DEFAULT_RETENTION) + _US)

        await trash.restore_chat(db.pool, alice.tenant, chat_id, ip=_IP, now=NOW)

        assert _live(db.chat_row(chat_id))

    @pytest.mark.parametrize(
        "case", ["expired", "retention-zero", "other-org", "colleague", "org-admin", "unknown"]
    )
    async def test_trash_restore_chat_out_of_reach_is_not_found_and_changes_nothing(
        self, trash: ModuleType, db: FakeDb, case: str
    ) -> None:
        """Expired (exactly at the cutoff), retention 0, another org's, a colleague's,
        the Org Admin on an Editor's and an unknown chat: ChatNotFoundError, nothing
        changed, no event."""
        world = _restore_world(db)
        people = world.people
        tenant, target = people.alice.tenant, world.chat
        if case == "expired":
            target = _chat(db, people.alice, deleted_at=NOW - timedelta(days=_DEFAULT_RETENTION))
        elif case == "retention-zero":
            _retention(db, ORG_ID, 0)
        elif case == "other-org":
            target = _chat(db, people.carol, deleted_at=NOW - _DAY)
        elif case == "colleague":
            target = _chat(db, people.bob, deleted_at=NOW - _DAY)
        elif case == "org-admin":
            tenant = people.admin.tenant
        else:
            target = _UNKNOWN
        before = db.snapshot()

        with pytest.raises(chats.ChatNotFoundError) as caught:
            await trash.restore_chat(db.pool, tenant, target, ip=_IP, now=NOW)

        assert type(caught.value) is chats.ChatNotFoundError
        assert db.snapshot() == before

    async def test_trash_restore_chat_whose_legacy_session_has_a_live_chat_conflicts(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """A trashed legacy chat whose session already has a live chat:
        RestoreConflictError with its fixed text, nothing changed, no event."""
        alice = _member(db)
        trashed = _chat(db, alice, deleted_at=NOW - _DAY, legacy_session_id=_SESSION)
        _file(db, trashed, deleted_at=NOW - _DAY)
        _chat(db, alice, legacy_session_id=_SESSION)
        before = db.snapshot()

        with pytest.raises(trash.RestoreConflictError) as caught:
            await trash.restore_chat(db.pool, alice.tenant, trashed, ip=_IP, now=NOW)

        assert str(caught.value) == _RESTORE_CONFLICT_TEXT
        assert db.snapshot() == before

    async def test_trash_restore_chat_another_unique_violation_propagates(
        self, trash: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A unique violation on another constraint is not a restore conflict: it
        propagates as the driver raised it, nothing changed."""
        world = _restore_world(db)
        real = db.handle

        def handle(method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None) -> Any:
            if norm(sql).startswith("update chats set deleted_at = null"):
                db.calls.append(Call(method, sql, args, via, tx))
                error = asyncpg.exceptions.UniqueViolationError("duplicate key value")
                error.constraint_name = "chats_pkey"
                raise error
            return real(method, sql, args, via, tx)

        before = db.snapshot()
        monkeypatch.setattr(db, "handle", handle)

        with pytest.raises(asyncpg.exceptions.UniqueViolationError):
            await trash.restore_chat(
                db.pool, world.people.alice.tenant, world.chat, ip=_IP, now=NOW
            )

        assert db.snapshot() == before

    async def test_trash_restore_chat_audit_failure_rolls_the_group_back(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """The audit write fails: AuditRecordError and the chat and its group stay
        trashed."""
        world = _restore_world(db)
        before = db.snapshot()
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await trash.restore_chat(
                db.pool, world.people.alice.tenant, world.chat, ip=_IP, now=NOW
            )

        assert len(db.matching(r"^update chats set deleted_at = null\b")) == 1
        assert db.snapshot() == before


# ---------------------------------------------------------------------------
# 3. restore_attachment
# ---------------------------------------------------------------------------


class TestRestoreAttachment:
    """A file of its own comes back into its live chat, audited."""

    async def test_trash_restore_attachment_brings_back_a_file_of_its_own(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """The file is live again with every other column kept (message link, flag,
        status, estimates); the record is its AR columns; the chat is untouched."""
        alice = _member(db)
        chat_id = _chat(db, alice)
        message = db.add_chat_message(chat_id, "user", "sent with a file")
        file_id = _file(
            db,
            chat_id,
            deleted_at=NOW - 2 * _DAY,
            own_group=True,
            message_id=message,
            status="ready",
            active=False,
            page_count=3,
            token_estimate=12,
        )
        columns = _row_minus_trash(db.attachment_row(file_id))
        chat_before = db.chat_row(chat_id)

        record = await trash.restore_attachment(db.pool, alice.tenant, file_id, ip=_IP, now=NOW)

        stored = db.attachment_row(file_id)
        assert type(record) is attachments.AttachmentRecord
        assert stored is not None
        assert record.model_dump() == {column: stored[column] for column in _AR_COLUMNS}
        assert _live(stored)
        assert _row_minus_trash(stored) == columns
        assert db.chat_row(chat_id) == chat_before

    async def test_trash_restore_attachment_records_file_restore_after_a2_before_t6(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """T4, then A2 (the chat locked FOR SHARE, bound to the chat, org and caller),
        then T6, then one ``file.restore`` (member, file, IP, no metadata), all on one
        connection in the committed transaction."""
        alice = _member(db)
        chat_id = _chat(db, alice)
        file_id = _file(db, chat_id, deleted_at=NOW - _DAY, own_group=True)
        db.calls.clear()

        await trash.restore_attachment(db.pool, alice.tenant, file_id, ip=_IP, now=NOW)

        assert _audit(db) == [_event("file.restore", alice, "file", file_id)]
        (lock,) = [call for call in db.calls if _tokens(call.sql) == _tokens(_A2)]
        (restore,) = db.matching(r"^update attachments set deleted_at = null\b")
        (audit,) = db.matching(r"^insert into audit_events\b")
        order = [id(call) for call in db.calls]
        assert order.index(id(lock)) < order.index(id(restore)) < order.index(id(audit))
        assert _plain_args(lock) == [chat_id, ORG_ID, alice.user_id]
        assert lock.tx is not None
        assert {(lock.via, lock.tx), (restore.via, restore.tx)} == {(audit.via, audit.tx)}
        assert (lock.tx, "commit") in db.transactions

    async def test_trash_restore_attachment_whose_chat_is_trashed_is_chat_in_trash(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """A file deleted on its own before its chat: ChatInTrashError with its fixed
        text, nothing changed, no event (restore the chat first)."""
        alice = _member(db)
        chat_id = _chat(db, alice, deleted_at=NOW - _DAY)
        file_id = _file(db, chat_id, deleted_at=NOW - 3 * _DAY, own_group=True)
        before = db.snapshot()

        with pytest.raises(trash.ChatInTrashError) as caught:
            await trash.restore_attachment(db.pool, alice.tenant, file_id, ip=_IP, now=NOW)

        assert str(caught.value) == _CHAT_IN_TRASH_TEXT
        assert db.snapshot() == before

    async def test_trash_restore_attachment_of_a_chats_group_is_not_found(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """A file that went to the trash with its chat is not an item:
        AttachmentNotFoundError (not ChatInTrashError), nothing changed."""
        alice = _member(db)
        chat_id = _chat(db, alice, deleted_at=NOW - _DAY)
        file_id = _file(db, chat_id, deleted_at=NOW - _DAY)
        before = db.snapshot()

        with pytest.raises(attachments.AttachmentNotFoundError) as caught:
            await trash.restore_attachment(db.pool, alice.tenant, file_id, ip=_IP, now=NOW)

        assert type(caught.value) is attachments.AttachmentNotFoundError
        assert db.snapshot() == before

    async def test_trash_restore_attachment_of_a_live_file_answers_it_and_records_nothing(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """The caller's live file: its record, no event, nothing changed (idempotent)."""
        alice = _member(db)
        file_id = _file(db, _chat(db, alice), status="ready", token_estimate=5)
        before = db.snapshot()

        record = await trash.restore_attachment(db.pool, alice.tenant, file_id, ip=_IP, now=NOW)

        stored = db.attachment_row(file_id)
        assert stored is not None
        assert record.model_dump() == {column: stored[column] for column in _AR_COLUMNS}
        assert db.snapshot() == before

    @pytest.mark.parametrize(
        "case", ["expired", "retention-zero", "other-org", "colleague", "org-admin", "unknown"]
    )
    async def test_trash_restore_attachment_out_of_reach_is_not_found(
        self, trash: ModuleType, db: FakeDb, case: str
    ) -> None:
        """Expired (exactly at the cutoff), retention 0, another org's, a colleague's,
        the Org Admin on an Editor's and an unknown file: AttachmentNotFoundError,
        nothing changed, no event."""
        people = _people(db)
        alice_chat = _chat(db, people.alice)
        tenant = people.alice.tenant
        target = _file(db, alice_chat, deleted_at=NOW - _DAY, own_group=True)
        if case == "expired":
            boundary = NOW - timedelta(days=_DEFAULT_RETENTION)
            target = _file(db, alice_chat, deleted_at=boundary, own_group=True)
        elif case == "retention-zero":
            _retention(db, ORG_ID, 0)
        elif case == "other-org":
            target = _file(db, _chat(db, people.carol), deleted_at=NOW - _DAY, own_group=True)
        elif case == "colleague":
            target = _file(db, _chat(db, people.bob), deleted_at=NOW - _DAY, own_group=True)
        elif case == "org-admin":
            tenant = people.admin.tenant
        else:
            target = _UNKNOWN
        before = db.snapshot()

        with pytest.raises(attachments.AttachmentNotFoundError) as caught:
            await trash.restore_attachment(db.pool, tenant, target, ip=_IP, now=NOW)

        assert type(caught.value) is attachments.AttachmentNotFoundError
        assert db.snapshot() == before

    async def test_trash_restore_attachment_audit_failure_rolls_back(
        self, trash: ModuleType, db: FakeDb
    ) -> None:
        """The audit write fails: AuditRecordError, the file stays trashed."""
        alice = _member(db)
        file_id = _file(db, _chat(db, alice), deleted_at=NOW - _DAY, own_group=True)
        before = db.snapshot()
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await trash.restore_attachment(db.pool, alice.tenant, file_id, ip=_IP, now=NOW)

        assert len(db.matching(r"^update attachments set deleted_at = null\b")) == 1
        assert db.snapshot() == before


# ---------------------------------------------------------------------------
# 4. purge_chat / purge_attachment
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _PurgeWorld:
    people: _People
    chat: uuid.UUID  # Alice's trashed chat, two messages
    group_files: tuple[uuid.UUID, uuid.UUID]  # went to the trash with it (one sent)
    own_file_in_chat: uuid.UUID  # trashed on its own before the chat
    live_chat: uuid.UUID
    live_file: uuid.UUID
    own_file: uuid.UUID  # Alice's file of its own, trashed, in the live chat
    carol_file: uuid.UUID


def _purge_world(db: FakeDb, root: Path) -> _PurgeWorld:
    """The purge world with every file planted, plus decoys: a stray file in Alice's org
    dir and, in the other org's dir, entries named like the chat's files."""
    people = _people(db)
    alice = people.alice
    chat = _chat(db, alice, deleted_at=NOW - _DAY, title=_CANARY_TITLE)
    message = db.add_chat_message(chat, "user", "files")
    db.add_chat_message(chat, "assistant", "ok")
    live_chat = _chat(db, alice)
    world = _PurgeWorld(
        people=people,
        chat=chat,
        group_files=(
            _file(db, chat, deleted_at=NOW - _DAY, filename=_CANARY_FILE),
            _file(db, chat, deleted_at=NOW - _DAY, message_id=message, status="ready"),
        ),
        own_file_in_chat=_file(db, chat, deleted_at=NOW - 3 * _DAY, own_group=True),
        live_chat=live_chat,
        live_file=_file(db, live_chat),
        own_file=_file(db, live_chat, deleted_at=NOW - 2 * _DAY, own_group=True),
        carol_file=_file(db, _chat(db, people.carol, deleted_at=NOW - _DAY), deleted_at=NOW),
    )
    for file_id in (*world.group_files, world.own_file_in_chat, world.live_file, world.own_file):
        _plant(root, ORG_ID, file_id)
    _plant(root, OTHER_ORG_ID, world.carol_file)
    for decoy in (*world.group_files, world.own_file):
        _plant(root, OTHER_ORG_ID, decoy)
    (root / str(ORG_ID) / "unrelated.bin").write_bytes(b"not an attachment")
    return world


class TestPurgeChat:
    """Delete forever: the chat's rows, then exactly its files."""

    async def test_trash_purge_chat_removes_its_rows_and_exactly_its_files(
        self, trash: ModuleType, db: FakeDb, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The chat, its messages and every file of the chat (its group and the one
        trashed on its own) are gone, and after the commit their ``<id>``, ``.part`` and
        ``.d/`` under root/ORG_ID; everything else on disk and in the tables stays."""
        world = _purge_world(db, root)
        chat_files = [*world.group_files, world.own_file_in_chat]
        disk = _disk(root)
        kept = {
            item: db.attachment_row(item)
            for item in (world.live_file, world.own_file, world.carol_file)
        }
        removals = _removal_probe(monkeypatch, db)

        result = await trash.purge_chat(
            db.pool, world.people.alice.tenant, world.chat, root=root, ip=_IP
        )

        assert result is None
        assert db.chat_row(world.chat) is None
        assert db.messages_of(world.chat) == []
        assert [db.attachment_row(item) for item in chat_files] == [None, None, None]
        assert {item: db.attachment_row(item) for item in kept} == kept
        assert _live(db.chat_row(world.live_chat))
        assert _disk(root) == _without(disk, ORG_ID, chat_files)
        assert removals
        assert set(removals) == {0}

    async def test_trash_purge_chat_records_chat_purge_with_the_file_count(
        self, trash: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """One ``chat.purge`` (member, chat, IP, ``{"file_count": 3}``) on the connection
        and committed transaction of the chat's DELETE."""
        world = _purge_world(db, root)
        alice = world.people.alice
        db.calls.clear()

        await trash.purge_chat(db.pool, alice.tenant, world.chat, root=root, ip=_IP)

        assert _audit(db) == [
            _event("chat.purge", alice, "chat", world.chat, metadata={"file_count": 3})
        ]
        (delete,) = db.matching(r"^delete from chats\b")
        (audit,) = db.matching(r"^insert into audit_events\b")
        assert delete.tx is not None
        assert (delete.via, delete.tx) == (audit.via, audit.tx)
        assert (delete.tx, "commit") in db.transactions

    async def test_trash_purge_chat_removes_an_expired_chat_too(
        self, trash: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """A chat trashed 100 days ago (long expired) is still deleted forever."""
        alice = _member(db)
        chat_id = _chat(db, alice, deleted_at=NOW - 100 * _DAY)
        file_id = _file(db, chat_id, deleted_at=NOW - 100 * _DAY)
        _plant(root, ORG_ID, file_id)

        await trash.purge_chat(db.pool, alice.tenant, chat_id, root=root, ip=_IP)

        assert (db.chat_row(chat_id), db.attachment_row(file_id)) == (None, None)
        assert _disk(root) == {str(ORG_ID): None}

    @pytest.mark.parametrize("case", ["live", "other-org", "colleague", "org-admin", "unknown"])
    async def test_trash_purge_chat_not_in_the_callers_trash_is_not_found(
        self, trash: ModuleType, db: FakeDb, root: Path, case: str
    ) -> None:
        """Alice's live chat, another org's, a colleague's and an unknown chat, and the
        Org Admin on Alice's trashed chat: ChatNotFoundError, no row, file or event
        changed."""
        world = _purge_world(db, root)
        people = world.people
        tenant, target = people.alice.tenant, world.chat
        if case == "live":
            target = world.live_chat
        elif case == "other-org":
            target = _chat(db, people.carol, deleted_at=NOW - _DAY)
            _plant(root, OTHER_ORG_ID, _file(db, target, deleted_at=NOW - _DAY))
        elif case == "colleague":
            target = _chat(db, people.bob, deleted_at=NOW - _DAY)
            _plant(root, ORG_ID, _file(db, target, deleted_at=NOW - _DAY))
        elif case == "org-admin":
            tenant = people.admin.tenant
        else:
            target = _UNKNOWN
        before, disk = db.snapshot(), _disk(root)

        with pytest.raises(chats.ChatNotFoundError) as caught:
            await trash.purge_chat(db.pool, tenant, target, root=root, ip=_IP)

        assert type(caught.value) is chats.ChatNotFoundError
        assert db.snapshot() == before
        assert _disk(root) == disk

    async def test_trash_purge_chat_audit_failure_keeps_rows_and_files(
        self, trash: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """The audit write fails after the DELETE: AuditRecordError, every row back and
        no file removed."""
        world = _purge_world(db, root)
        before, disk = db.snapshot(), _disk(root)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await trash.purge_chat(
                db.pool, world.people.alice.tenant, world.chat, root=root, ip=_IP
            )

        assert len(db.matching(r"^delete from chats\b")) == 1
        assert db.snapshot() == before
        assert _disk(root) == disk


class TestPurgeAttachment:
    """Delete forever: a file of its own, its row then its files."""

    async def test_trash_purge_attachment_removes_its_row_and_exactly_its_files(
        self, trash: ModuleType, db: FakeDb, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The row goes and, after the commit, its ``<id>``, ``.part`` and ``.d/`` under
        root/ORG_ID; its chat, the other rows and every other entry on disk stay."""
        world = _purge_world(db, root)
        before = db.snapshot()
        disk = _disk(root)
        removals = _removal_probe(monkeypatch, db)

        result = await trash.purge_attachment(
            db.pool, world.people.alice.tenant, world.own_file, root=root, ip=_IP
        )

        assert result is None
        after = db.snapshot()
        assert world.own_file not in {plain(key) for key in after["attachments"]}
        assert {
            key: row for key, row in before["attachments"].items() if plain(key) != world.own_file
        } == (after["attachments"])
        assert after["chats"] == before["chats"]
        assert _disk(root) == _without(disk, ORG_ID, [world.own_file])
        assert removals
        assert set(removals) == {0}

    async def test_trash_purge_attachment_records_file_purge_in_its_transaction(
        self, trash: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """One ``file.purge`` (member, file, IP, no metadata) on the connection and
        committed transaction of the DELETE."""
        world = _purge_world(db, root)
        alice = world.people.alice
        db.calls.clear()

        await trash.purge_attachment(db.pool, alice.tenant, world.own_file, root=root, ip=_IP)

        assert _audit(db) == [_event("file.purge", alice, "file", world.own_file)]
        (delete,) = db.matching(r"^delete from attachments\b")
        (audit,) = db.matching(r"^insert into audit_events\b")
        assert delete.tx is not None
        assert (delete.via, delete.tx) == (audit.via, audit.tx)
        assert (delete.tx, "commit") in db.transactions

    async def test_trash_purge_attachment_removes_an_expired_file_too(
        self, trash: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """A file trashed 100 days ago is still deleted forever."""
        alice = _member(db)
        file_id = _file(db, _chat(db, alice), deleted_at=NOW - 100 * _DAY, own_group=True)
        _plant(root, ORG_ID, file_id)

        await trash.purge_attachment(db.pool, alice.tenant, file_id, root=root, ip=_IP)

        assert db.attachment_row(file_id) is None
        assert _disk(root) == {str(ORG_ID): None}

    @pytest.mark.parametrize(
        "case", ["live", "chat-group", "other-org", "colleague", "org-admin", "unknown"]
    )
    async def test_trash_purge_attachment_not_an_item_of_the_callers_trash_is_not_found(
        self, trash: ModuleType, db: FakeDb, root: Path, case: str
    ) -> None:
        """Alice's live file, a file that went with its chat, another org's, a
        colleague's and an unknown file, and the Org Admin on Alice's file:
        AttachmentNotFoundError, no row, file or event changed."""
        world = _purge_world(db, root)
        people = world.people
        tenant, target = people.alice.tenant, world.own_file
        if case == "live":
            target = world.live_file
        elif case == "chat-group":
            target = world.group_files[0]
        elif case == "other-org":
            target = _file(db, _chat(db, people.carol), deleted_at=NOW - _DAY, own_group=True)
            _plant(root, OTHER_ORG_ID, target)
        elif case == "colleague":
            target = _file(db, _chat(db, people.bob), deleted_at=NOW - _DAY, own_group=True)
            _plant(root, ORG_ID, target)
        elif case == "org-admin":
            tenant = people.admin.tenant
        else:
            target = _UNKNOWN
        before, disk = db.snapshot(), _disk(root)

        with pytest.raises(attachments.AttachmentNotFoundError) as caught:
            await trash.purge_attachment(db.pool, tenant, target, root=root, ip=_IP)

        assert type(caught.value) is attachments.AttachmentNotFoundError
        assert db.snapshot() == before
        assert _disk(root) == disk

    async def test_trash_purge_attachment_audit_failure_keeps_row_and_files(
        self, trash: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """The audit write fails: AuditRecordError, the row back and no file removed."""
        world = _purge_world(db, root)
        before, disk = db.snapshot(), _disk(root)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await trash.purge_attachment(
                db.pool, world.people.alice.tenant, world.own_file, root=root, ip=_IP
            )

        assert len(db.matching(r"^delete from attachments\b")) == 1
        assert db.snapshot() == before
        assert _disk(root) == disk


# ---------------------------------------------------------------------------
# 5. empty_trash
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _EmptyWorld:
    people: _People
    chats: tuple[uuid.UUID, ...]  # Alice's three trashed chats (one expired), by id
    group_file: uuid.UUID  # went with the first chat
    own_file_in_trashed_chat: uuid.UUID  # its own item, in the second chat
    own_file: uuid.UUID  # its own item, in the live chat
    live_chat: uuid.UUID
    live_file: uuid.UUID


def _empty_world(db: FakeDb, root: Path) -> _EmptyWorld:
    people = _people(db)
    alice = people.alice
    first = _chat(db, alice, deleted_at=NOW - _DAY, chat_id=uuid.UUID(int=0x1 << 124))
    second = _chat(db, alice, deleted_at=NOW - 2 * _DAY, chat_id=uuid.UUID(int=0x2 << 124))
    expired = _chat(db, alice, deleted_at=NOW - 100 * _DAY, chat_id=uuid.UUID(int=0x3 << 124))
    live_chat = _chat(db, alice)
    world = _EmptyWorld(
        people=people,
        chats=(first, second, expired),
        group_file=_file(db, first, deleted_at=NOW - _DAY),
        own_file_in_trashed_chat=_file(db, second, deleted_at=NOW - 3 * _DAY, own_group=True),
        own_file=_file(db, live_chat, deleted_at=NOW - _DAY, own_group=True),
        live_chat=live_chat,
        live_file=_file(db, live_chat),
    )
    for file_id in (
        world.group_file,
        world.own_file_in_trashed_chat,
        world.own_file,
        world.live_file,
    ):
        _plant(root, ORG_ID, file_id)
    for other in (people.bob, people.admin, people.carol):
        chat = _chat(db, other, deleted_at=NOW - _DAY)
        _plant(root, other.tenant.org_id, _file(db, chat, deleted_at=NOW - _DAY))
        own = _file(db, _chat(db, other), deleted_at=NOW - _DAY, own_group=True)
        _plant(root, other.tenant.org_id, own)
    return world


def _rows_of(db: FakeDb, owner: _Member) -> dict[str, Any]:
    """Every chats and attachments row of one owner (by id)."""
    return {
        "chats": {
            plain(key): row
            for key, row in db.chats.items()
            if plain(row["owner_user_id"]) == owner.user_id
        },
        "attachments": {
            plain(key): row
            for key, row in db.attachments.items()
            if plain(row["owner_user_id"]) == owner.user_id
        },
    }


class TestEmptyTrash:
    """Every chat, then every file of its own, one item per transaction."""

    async def test_trash_empty_purges_every_chat_then_every_file_of_its_own(
        self, trash: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """Alice's three trashed chats (one expired) and her file of its own in a live
        chat go: (3, 1). The file of its own inside a trashed chat goes with its chat
        (the chats come first) and isn't counted as a file. Events: three chat.purge in
        id order, then one file.purge. Live items and everyone else's trash stay."""
        world = _empty_world(db, root)
        alice = world.people.alice
        others = {
            name: _rows_of(db, getattr(world.people, name)) for name in ("bob", "admin", "carol")
        }
        purged = [world.group_file, world.own_file_in_trashed_chat, world.own_file]
        disk = _disk(root)

        result = await trash.empty_trash(db.pool, alice.tenant, root=root, ip=_IP)

        assert type(result) is trash.EmptiedTrash
        assert (result.chats, result.attachments) == (3, 1)
        assert [db.chat_row(chat_id) for chat_id in world.chats] == [None, None, None]
        assert [db.attachment_row(item) for item in purged] == [None, None, None]
        assert _live(db.chat_row(world.live_chat))
        assert _live(db.attachment_row(world.live_file))
        assert {
            name: _rows_of(db, getattr(world.people, name)) for name in ("bob", "admin", "carol")
        } == others
        assert _disk(root) == _without(disk, ORG_ID, purged)
        assert _audit(db) == [
            _event("chat.purge", alice, "chat", world.chats[0], metadata={"file_count": 1}),
            _event("chat.purge", alice, "chat", world.chats[1], metadata={"file_count": 1}),
            _event("chat.purge", alice, "chat", world.chats[2], metadata={"file_count": 0}),
            _event("file.purge", alice, "file", world.own_file),
        ]

    async def test_trash_empty_purges_each_item_in_its_own_transaction(
        self, trash: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """Each item's DELETE and its event share one committed transaction, and no two
        items share one."""
        world = _empty_world(db, root)
        db.calls.clear()

        await trash.empty_trash(db.pool, world.people.alice.tenant, root=root, ip=_IP)

        deletes = db.matching(r"^delete from (chats|attachments)\b")
        audits = db.matching(r"^insert into audit_events\b")
        assert len(deletes) == len(audits) == 4
        assert [(call.via, call.tx) for call in deletes] == [(call.via, call.tx) for call in audits]
        assert len({call.tx for call in deletes}) == 4
        assert all((call.tx, "commit") in db.transactions for call in deletes)

    async def test_trash_empty_skips_items_restored_meanwhile(
        self, trash: ModuleType, db: FakeDb, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The first chat is restored right after the chat list is read and the file of
        its own right after the file list is read: both are skipped and not counted,
        and their rows and files stay."""
        world = _empty_world(db, root)
        first, file_id = world.chats[0], world.own_file
        real = db.handle

        def restore(table: dict[uuid.UUID, dict[str, Any]], item: uuid.UUID) -> None:
            row = table[item]
            row["deleted_at"] = None
            row["trash_group_id"] = None

        def handle(method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None) -> Any:
            result = real(method, sql, args, via, tx)
            n = norm(sql)
            if re.match(r"select id from chats\b.*\border by id$", n):
                restore(db.chats, first)
                restore(db.attachments, world.group_file)
            elif re.match(r"select id from attachments\b.*\border by id$", n):
                restore(db.attachments, file_id)
            return result

        monkeypatch.setattr(db, "handle", handle)
        disk = _disk(root)

        result = await trash.empty_trash(db.pool, world.people.alice.tenant, root=root, ip=_IP)

        assert (result.chats, result.attachments) == (2, 0)
        assert _live(db.chat_row(first))
        assert _live(db.attachment_row(world.group_file))
        assert _live(db.attachment_row(file_id))
        assert _disk(root) == _without(disk, ORG_ID, [world.own_file_in_trashed_chat])
        assert [row["action"] for row in db.audit] == ["chat.purge", "chat.purge"]

    @pytest.mark.parametrize("who", ["alice-empty", "admin"])
    async def test_trash_empty_of_an_empty_trash_purges_nothing(
        self, trash: ModuleType, db: FakeDb, root: Path, who: str
    ) -> None:
        """An empty trash (Alice's with only live items, or a new Org Admin's while
        Alice's and her colleagues' trash is full): (0, 0), nothing written, no file
        removed."""
        if who == "admin":
            _empty_world(db, root)
            tenant = _member(db, role="org_admin").tenant
        else:
            alice = _member(db)
            _plant(root, ORG_ID, _file(db, _chat(db, alice)))
            tenant = alice.tenant
        before, disk = db.snapshot(), _disk(root)

        result = await trash.empty_trash(db.pool, tenant, root=root, ip=_IP)

        assert (result.chats, result.attachments) == (0, 0)
        assert db.snapshot() == before
        assert _disk(root) == disk


# ---------------------------------------------------------------------------
# 6. delete_chat / delete_attachment (retention 0: purged in the call)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _DeleteWorld:
    people: _People
    chat: uuid.UUID  # Alice's live chat, canary title, one message
    file: uuid.UUID  # its live file (canary name), planted
    own_file: uuid.UUID  # of the chat, trashed on its own earlier, planted


def _delete_world(db: FakeDb, root: Path) -> _DeleteWorld:
    people = _people(db)
    chat = _chat(db, people.alice, title=_CANARY_TITLE)
    db.add_chat_message(chat, "user", "hello")
    world = _DeleteWorld(
        people=people,
        chat=chat,
        file=_file(db, chat, filename=_CANARY_FILE),
        own_file=_file(db, chat, deleted_at=NOW - 2 * _DAY, own_group=True, filename=_OLDER_FILE),
    )
    _plant(root, ORG_ID, world.file)
    _plant(root, ORG_ID, world.own_file)
    return world


def _warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.levelno >= logging.WARNING]


class TestDeleteChat:
    """DELETE /api/chats/{id}'s service: trash, and with retention 0 purge at once."""

    async def test_trash_delete_chat_with_retention_only_trashes(
        self, trash: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """Retention 30: False; the chat is its own group, its live file joins it, the
        file trashed earlier keeps its own group; files stay; one chat.delete."""
        world = _delete_world(db, root)
        alice = world.people.alice
        own_before = db.attachment_row(world.own_file)
        disk = _disk(root)

        purged = await trash.delete_chat(db.pool, alice.tenant, world.chat, root=root, ip=_IP)

        chat_row, file_row = db.chat_row(world.chat), db.attachment_row(world.file)
        assert purged is False
        assert chat_row is not None
        assert file_row is not None
        assert chat_row["deleted_at"] is not None
        assert plain(chat_row["trash_group_id"]) == world.chat
        assert file_row["deleted_at"] is not None
        assert plain(file_row["trash_group_id"]) == world.chat
        assert db.attachment_row(world.own_file) == own_before
        assert _disk(root) == disk
        assert _audit(db) == [_event("chat.delete", alice, "chat", world.chat)]

    async def test_trash_delete_chat_with_retention_zero_purges_in_the_call(
        self, trash: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """Retention 0: True; no row of the chat (messages, both files) and none of its
        files' entries left; events chat.delete then chat.purge (file_count 2)."""
        world = _delete_world(db, root)
        alice = world.people.alice
        _retention(db, ORG_ID, 0)
        disk = _disk(root)

        purged = await trash.delete_chat(db.pool, alice.tenant, world.chat, root=root, ip=_IP)

        assert purged is True
        assert db.chat_row(world.chat) is None
        assert db.messages_of(world.chat) == []
        assert (db.attachment_row(world.file), db.attachment_row(world.own_file)) == (None, None)
        assert _disk(root) == _without(disk, ORG_ID, [world.file, world.own_file])
        assert _audit(db) == [
            _event("chat.delete", alice, "chat", world.chat),
            _event("chat.purge", alice, "chat", world.chat, metadata={"file_count": 2}),
        ]

    async def test_trash_delete_chat_failing_purge_keeps_the_trash_and_warns(
        self,
        trash: ModuleType,
        db: FakeDb,
        root: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Retention 0 and the purge's DELETE fails: False, the chat and its file stay
        trashed, no file removed, and one warning naming the chat id and the exception's
        class only (no title, file name, path or exception text)."""
        world = _delete_world(db, root)
        _retention(db, ORG_ID, 0)
        db.fail_sql = r"^delete from chats\b"
        disk = _disk(root)
        caplog.set_level(logging.DEBUG)

        purged = await trash.delete_chat(
            db.pool, world.people.alice.tenant, world.chat, root=root, ip=_IP
        )

        chat_row = db.chat_row(world.chat)
        assert purged is False
        assert chat_row is not None
        assert chat_row["deleted_at"] is not None
        assert [row["action"] for row in db.audit] == ["chat.delete"]
        assert _disk(root) == disk
        (warning,) = _warnings(caplog)
        text = warning.getMessage()
        assert str(world.chat) in text
        assert "DeadlockDetectedError" in text
        assert warning.exc_info is None
        for leak in (_CANARY_TITLE, _CANARY_FILE, str(root), "deadlock detected"):
            assert leak.casefold() not in text.casefold()

    async def test_trash_delete_chat_failing_retention_read_changes_nothing(
        self, trash: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """The org retention read fails: the driver's error propagates and nothing is
        trashed (no statement on chats or attachments)."""
        world = _delete_world(db, root)
        db.fail_sql = r"\bfrom org_settings\b"
        before = db.snapshot()
        db.calls.clear()

        with pytest.raises(asyncpg.exceptions.DeadlockDetectedError):
            await trash.delete_chat(
                db.pool, world.people.alice.tenant, world.chat, root=root, ip=_IP
            )

        assert db.matching(r"\b(chats|attachments)\b") == []
        assert db.snapshot() == before

    @pytest.mark.parametrize("days", [30, 0])
    async def test_trash_delete_chat_of_a_colleague_is_not_found(
        self, trash: ModuleType, db: FakeDb, root: Path, days: int
    ) -> None:
        """Bob's live chat (also with retention 0): ChatNotFoundError, nothing changed,
        nothing purged."""
        world = _delete_world(db, root)
        _retention(db, ORG_ID, days)
        bob_chat = _chat(db, world.people.bob)
        before, disk = db.snapshot(), _disk(root)

        with pytest.raises(chats.ChatNotFoundError):
            await trash.delete_chat(db.pool, world.people.alice.tenant, bob_chat, root=root, ip=_IP)

        assert db.snapshot() == before
        assert _disk(root) == disk


class TestDeleteAttachment:
    """DELETE /api/attachments/{id}'s service: trash, and with retention 0 purge at once."""

    async def test_trash_delete_attachment_with_retention_only_trashes(
        self, trash: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """Retention 30: False; the file is its own group; its chat stays live; files
        stay; one file.delete."""
        world = _delete_world(db, root)
        alice = world.people.alice
        chat_before = db.chat_row(world.chat)
        disk = _disk(root)

        purged = await trash.delete_attachment(db.pool, alice.tenant, world.file, root=root, ip=_IP)

        row = db.attachment_row(world.file)
        assert purged is False
        assert row is not None
        assert row["deleted_at"] is not None
        assert plain(row["trash_group_id"]) == world.file
        assert db.chat_row(world.chat) == chat_before
        assert _disk(root) == disk
        assert _audit(db) == [_event("file.delete", alice, "file", world.file)]

    async def test_trash_delete_attachment_with_retention_zero_purges_in_the_call(
        self, trash: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """Retention 0: True; its row and its entries on disk are gone; events
        file.delete then file.purge; the chat and the other file stay."""
        world = _delete_world(db, root)
        alice = world.people.alice
        _retention(db, ORG_ID, 0)
        chat_before = db.chat_row(world.chat)
        own_before = db.attachment_row(world.own_file)
        disk = _disk(root)

        purged = await trash.delete_attachment(db.pool, alice.tenant, world.file, root=root, ip=_IP)

        assert purged is True
        assert db.attachment_row(world.file) is None
        assert (db.chat_row(world.chat), db.attachment_row(world.own_file)) == (
            chat_before,
            own_before,
        )
        assert _disk(root) == _without(disk, ORG_ID, [world.file])
        assert _audit(db) == [
            _event("file.delete", alice, "file", world.file),
            _event("file.purge", alice, "file", world.file),
        ]

    async def test_trash_delete_attachment_failing_purge_keeps_the_trash_and_warns(
        self,
        trash: ModuleType,
        db: FakeDb,
        root: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Retention 0 and the purge's DELETE fails: False, the file stays trashed, no
        file removed, one warning with the file id and the exception's class only."""
        world = _delete_world(db, root)
        _retention(db, ORG_ID, 0)
        db.fail_sql = r"^delete from attachments\b"
        disk = _disk(root)
        caplog.set_level(logging.DEBUG)

        purged = await trash.delete_attachment(
            db.pool, world.people.alice.tenant, world.file, root=root, ip=_IP
        )

        row = db.attachment_row(world.file)
        assert purged is False
        assert row is not None
        assert row["deleted_at"] is not None
        assert [audit["action"] for audit in db.audit] == ["file.delete"]
        assert _disk(root) == disk
        (warning,) = _warnings(caplog)
        text = warning.getMessage()
        assert str(world.file) in text
        assert "DeadlockDetectedError" in text
        assert warning.exc_info is None
        for leak in (_CANARY_TITLE, _CANARY_FILE, str(root), "deadlock detected"):
            assert leak.casefold() not in text.casefold()

    async def test_trash_delete_attachment_failing_retention_read_changes_nothing(
        self, trash: ModuleType, db: FakeDb, root: Path
    ) -> None:
        """The org retention read fails: the driver's error propagates, nothing
        trashed (no statement on attachments)."""
        world = _delete_world(db, root)
        db.fail_sql = r"\bfrom org_settings\b"
        before = db.snapshot()
        db.calls.clear()

        with pytest.raises(asyncpg.exceptions.DeadlockDetectedError):
            await trash.delete_attachment(
                db.pool, world.people.alice.tenant, world.file, root=root, ip=_IP
            )

        assert db.matching(r"\battachments\b") == []
        assert db.snapshot() == before

    @pytest.mark.parametrize("days", [30, 0])
    async def test_trash_delete_attachment_of_a_colleague_is_not_found(
        self, trash: ModuleType, db: FakeDb, root: Path, days: int
    ) -> None:
        """Bob's live file (also with retention 0): AttachmentNotFoundError, nothing
        changed, nothing purged."""
        world = _delete_world(db, root)
        _retention(db, ORG_ID, days)
        bob_file = _file(db, _chat(db, world.people.bob))
        _plant(root, ORG_ID, bob_file)
        before, disk = db.snapshot(), _disk(root)

        with pytest.raises(attachments.AttachmentNotFoundError):
            await trash.delete_attachment(
                db.pool, world.people.alice.tenant, bob_file, root=root, ip=_IP
            )

        assert db.snapshot() == before
        assert _disk(root) == disk


# ---------------------------------------------------------------------------
# 7. Logs: no title, file name or path
# ---------------------------------------------------------------------------


class TestTrashLogs:
    """Every function of the module over canary titles and file names."""

    async def test_trash_functions_log_no_title_file_name_or_path(
        self,
        trash: ModuleType,
        db: FakeDb,
        root: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """List, both restores, both purges, empty, and both deletes with retention 0
        whose purge fails (the warnings): no record's message, arguments or extra
        fields carry a title, a file name or the root path."""
        caplog.set_level(logging.DEBUG)
        world = _delete_world(db, root)
        alice = world.people.alice
        tenant = alice.tenant
        trashed = _chat(db, alice, deleted_at=NOW - _DAY, title=_CANARY_TITLE)
        group_file = _file(db, trashed, deleted_at=NOW - _DAY, filename=_CANARY_FILE)
        _plant(root, ORG_ID, group_file)

        await trash.list_trash(db.pool, tenant, limit=50, cursor=None, item_type=None, now=NOW)
        await trash.restore_chat(db.pool, tenant, trashed, ip=_IP, now=NOW)
        await trash.restore_attachment(db.pool, tenant, world.own_file, ip=_IP, now=NOW)
        await trash.delete_attachment(db.pool, tenant, world.own_file, root=root, ip=_IP)
        await trash.purge_attachment(db.pool, tenant, world.own_file, root=root, ip=_IP)
        await trash.delete_chat(db.pool, tenant, trashed, root=root, ip=_IP)
        await trash.purge_chat(db.pool, tenant, trashed, root=root, ip=_IP)
        _retention(db, ORG_ID, 0)
        db.fail_sql = r"^delete from (chats|attachments)\b"
        await trash.delete_attachment(db.pool, tenant, world.file, root=root, ip=_IP)
        await trash.delete_chat(db.pool, tenant, world.chat, root=root, ip=_IP)
        db.fail_sql = None
        await trash.empty_trash(db.pool, tenant, root=root, ip=_IP)

        assert len(_warnings(caplog)) == 2
        standard = set(vars(logging.LogRecord("", logging.INFO, "", 0, "", (), None)))
        for record in caplog.records:
            extra = {key: value for key, value in vars(record).items() if key not in standard}
            text = " ".join(
                [record.getMessage(), str(record.msg), repr(record.args), repr(extra)]
            ).casefold()
            for leak in (_CANARY_TITLE, _CANARY_FILE, _OLDER_FILE, str(root)):
                assert leak.casefold() not in text, record.name
        assert db.chat_row(world.chat) is None
        assert db.attachment_row(world.file) is None
