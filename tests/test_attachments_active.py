"""Tests for admino.attachments under GH-190: exclusion, the chat's list, the active files.

Issue #190, Decisions 7, 10 and 11 (and "Stuck chat"); contract C6 and C8. Migration
0030 adds ``attachments.active``. ``set_active`` excludes or includes the caller's
own live attachment whatever its status, in one transaction with its
``file.exclude`` / ``file.include`` audit event, and records nothing when the
value doesn't change. ``list_chat_attachments`` pages through the caller's live
attachments of their own chat, oldest first, with ``status`` and ``active``
filters. ``ready_active_attachments`` (A12) is what the upload check and the
context report count. ``check_sendable`` (A8'') still refuses over every listed
id but returns only the active ones, with their estimate and derived bytes.
Everything runs against tests/db_fakes.py, which runs the contract's forms and
models migration 0030 once it ships (until then a statement naming ``active``
and ``add_attachment(active=False)`` are UndefinedColumnError).

What these tests pin down:
- ``AuditAction.FILE_EXCLUDE`` / ``FILE_INCLUDE`` (``file.exclude`` /
  ``file.include``, org scope) follow ``FILE_RESTORE`` in the catalog.
- ``set_active(pool, tenant, attachment_id, active, *, ip)``: excluding and
  including work for every status (uploaded, processing, ready, failed) and
  for a sent file (it stays linked); the result is the record with the new
  value, equal to the stored row; one committed transaction on one connection
  runs A10a (the R columns ``FOR UPDATE``, bound to the id, the caller's org and
  the caller), A10b (bound to the id, the org and the strict bool), then the
  audit insert: action file.exclude / file.include, member actor, the caller's
  org, target type ``file``, target id the attachment, the IP, no metadata, no
  file name anywhere. The same value again: A10a alone, no UPDATE, no audit
  row, the record unchanged. Another org's, a colleague's, a trashed and an
  unknown id: ``AttachmentNotFoundError`` after A10a, nothing written. A failed
  audit write raises ``AuditRecordError`` and rolls the change back.
- ``list_chat_attachments(executor, tenant, chat_id, *, limit, cursor, status,
  active)``: the owner check (S2) first: another org's, a colleague's, a
  trashed and an unknown chat are ``chats.ChatNotFoundError`` with no A11 (a bad
  cursor too); the live files oldest first (``created_at``, then ``id``),
  trashed ones never; ``limit`` and ``next_cursor`` walk every file exactly
  once with microsecond-apart stamps and a created_at tie across page
  boundaries; ``next_cursor`` None on the last page (exactly ``limit`` left
  included), at most 200 base64url characters; the ``status`` and ``active``
  filters alone and together (also across pages); garbage, a truncated cursor
  and another list's cursor (chats, messages) are ``chats.InvalidCursorError``
  after S2 alone; the exact A11 / A11' forms and binds (``limit + 1``).
  ``AttachmentPage`` has exactly ``attachments`` and ``next_cursor``.
- ``ready_active_attachments(executor, tenant, chat_id)``: exactly A12, bound to
  the chat, the org and the caller; the chat's live, ready, active files (sent
  or not) in upload order as ``chats.ActiveAttachment`` with token estimate and
  derived bytes (NULL as None); never an excluded, uploaded, processing,
  failed or trashed file or another chat's; a colleague's or another org's
  chat gives ``[]``.
- ``check_sendable`` (A8''): the exact form; an excluded file next to an active
  one is accepted and left out of the result, only excluded files give ``[]``;
  an excluded file is still refused when it is trashed (not found), sent
  (already sent) or not ready; the result carries the estimate and the derived
  bytes.
- A5' / A6': an upload's record is active; ``get_attachment`` reports an
  excluded file's flag.
- No content in logs: no file name in a log line or in the audit table.

New names are looked up when a test runs, so this file collects before they
exist and every test fails on its own.
"""

from __future__ import annotations

import inspect
import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import attachments as attachments_module
from admino import chats
from admino.audit_events import AuditRecordError
from admino.tenancy import TenantContext
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, plain
from tests.log_capture import configured_logging

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path
    from types import ModuleType

    from tests.db_fakes import Call

NAME_CANARY: Final = 'NAME-CANARY-190n salary list "Q3".xlsx'
_IP: Final = "203.0.113.90"
_QUOTA: Final = 1_000_000
_UNKNOWN: Final = uuid.UUID("71900000-0000-4000-8000-0000000000aa")
_STATUSES: Final = ("uploaded", "processing", "ready", "failed")
_NOT_FOUND_CASES: Final = ("other-org", "colleague", "trashed", "unknown")

_T0: Final = datetime(2026, 10, 9, 10, 0, 0, 250000, tzinfo=UTC)
_US: Final = timedelta(microseconds=1)

# The R columns of contract C6 (A5', A6', A10a, A11, A11'): ``active`` before created_at.
_R_COLUMNS: Final = (
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

# Contract C6, as verified on postgres:16.
A8_SECOND: Final = """
    SELECT id, message_id, status, filename, kind, page_count, token_estimate, derived_bytes, active
    FROM attachments
    WHERE id = ANY($1::uuid[]) AND chat_id = $2 AND org_id = $3 AND owner_user_id = $4
      AND deleted_at IS NULL
    ORDER BY created_at, id
"""
A10A: Final = """
    SELECT id, chat_id, message_id, filename, kind, size_bytes, status, failure_reason,
           page_count, token_estimate, active, created_at
    FROM attachments
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
    FOR UPDATE
"""
A10B: Final = "UPDATE attachments SET active = $3 WHERE id = $1 AND org_id = $2"
_A11_HEAD: Final = """
    SELECT id, chat_id, message_id, filename, kind, size_bytes, status, failure_reason,
           page_count, token_estimate, active, created_at
    FROM attachments
    WHERE chat_id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
      AND status = coalesce($4, status) AND active = coalesce($5, active)
"""
A11: Final = _A11_HEAD + " ORDER BY created_at, id LIMIT $6"
A11_AFTER: Final = _A11_HEAD + " AND (created_at, id) > ($6, $7) ORDER BY created_at, id LIMIT $8"
A12: Final = """
    SELECT id, filename, kind, page_count, token_estimate, derived_bytes
    FROM attachments
    WHERE chat_id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
      AND status = 'ready' AND active
    ORDER BY created_at, id
"""
S2: Final = """
    SELECT id, org_id, owner_user_id, title, title_source, external_content,
        created_at, last_activity_at
    FROM chats
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
"""

_GARBAGE_CURSORS: Final = (
    "not-a-cursor",
    "%%%",
    "e30",  # base64url of {}
    "W10",  # base64url of []
    "bnVsbA",  # base64url of null
    "eyJ4IjoxfQ",  # base64url of {"x":1}
    "AAAA",
    chr(0xFC),
    "x" * 201,
)


def _canon(sql: str) -> str:
    """Lowercased, whitespace collapsed and dropped around ( ) , = [ ] (tokens kept)."""
    text = re.sub(r"\s+", " ", sql.strip().lower()).rstrip(";").strip()
    return re.sub(r"\s*([(),=\[\]])\s*", r"\1", text)


_FORMS: Final = {
    "A8''": _canon(A8_SECOND),
    "A10a": _canon(A10A),
    "A10b": _canon(A10B),
    "A11": _canon(A11),
    "A11'": _canon(A11_AFTER),
    "A12": _canon(A12),
    "S2": _canon(S2),
}


def _form(call: Call) -> str:
    """The contract form of a recorded statement, "audit" for the audit insert, else SQL."""
    text = _canon(call.sql)
    if text.startswith("insert into audit_events"):
        return "audit"
    return next((label for label, form in _FORMS.items() if form == text), call.normalized)


def _forms(calls: list[Call]) -> list[str]:
    return [_form(call) for call in calls]


def _uuid(value: Any) -> uuid.UUID:
    assert isinstance(value, uuid.UUID), value
    return plain(value)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def att() -> ModuleType:
    """admino.attachments (its new names are looked up when a test runs)."""
    return attachments_module


@dataclass(frozen=True)
class _World:
    db: FakeDb
    member: uuid.UUID
    colleague: uuid.UUID
    outsider: uuid.UUID
    chat: uuid.UUID
    other_chat: uuid.UUID
    colleague_chat: uuid.UUID
    foreign_chat: uuid.UUID
    trashed_chat: uuid.UUID
    message: uuid.UUID  # a user message of ``chat``

    @property
    def tenant(self) -> TenantContext:
        return TenantContext(org_id=ORG_ID, user_id=self.member, role="editor")


@pytest.fixture()
def world() -> _World:
    db = FakeDb()
    db.add_org(ORG_ID, storage_quota_bytes=_QUOTA)
    db.add_org(OTHER_ORG_ID, storage_quota_bytes=_QUOTA)
    member = db.add_account(org_id=ORG_ID)
    colleague = db.add_account(org_id=ORG_ID)
    outsider = db.add_account(org_id=OTHER_ORG_ID)
    chat = db.add_chat(member, title="Board")
    message = db.add_chat_message(chat, "user", "Earlier, with a file")
    return _World(
        db=db,
        member=member,
        colleague=colleague,
        outsider=outsider,
        chat=chat,
        other_chat=db.add_chat(member),
        colleague_chat=db.add_chat(colleague),
        foreign_chat=db.add_chat(outsider),
        trashed_chat=db.add_chat(member, deleted_at=_T0),
        message=message,
    )


def _add(world: _World, chat_id: uuid.UUID | None = None, **values: Any) -> uuid.UUID:
    """An attachments row (the caller's chat by default) named with the canary."""
    values.setdefault("filename", NAME_CANARY)
    if values.get("status") == "failed":
        values.setdefault("failure_reason", "corrupted_file")
    return world.db.add_attachment(world.chat if chat_id is None else chat_id, **values)


def _row(world: _World, attachment_id: uuid.UUID) -> dict[str, Any]:
    row = world.db.attachment_row(attachment_id)
    assert row is not None
    return row


def _record_of_row(row: dict[str, Any]) -> dict[str, Any]:
    """The R columns of a stored row, ids as plain UUIDs."""
    return {
        column: plain(row[column]) if isinstance(row[column], uuid.UUID) else row[column]
        for column in _R_COLUMNS
    }


def _dump(record: Any) -> dict[str, Any]:
    return {
        column: plain(value) if isinstance(value, uuid.UUID) else value
        for column, value in record.model_dump().items()
    }


def _foreign(world: _World, case: str) -> uuid.UUID:
    """An attachment id the caller may not reach."""
    return {
        "other-org": lambda: _add(world, world.foreign_chat, status="ready"),
        "colleague": lambda: _add(world, world.colleague_chat, status="ready"),
        "trashed": lambda: _add(world, status="ready", deleted_at=_T0),
        "unknown": lambda: _UNKNOWN,
    }[case]()


def _foreign_chat(world: _World, case: str) -> uuid.UUID:
    """A chat id the caller may not reach."""
    return {
        "other-org": world.foreign_chat,
        "colleague": world.colleague_chat,
        "trashed": world.trashed_chat,
        "unknown": _UNKNOWN,
    }[case]


async def _set(att: ModuleType, world: _World, attachment_id: uuid.UUID, active: bool) -> Any:
    return await att.set_active(world.db.pool, world.tenant, attachment_id, active, ip=_IP)


# ---------------------------------------------------------------------------
# 1. The audit actions (C8)
# ---------------------------------------------------------------------------


def test_attachments_active_audit_actions_follow_file_restore_with_org_scope() -> None:
    from admino import audit_events

    actions = list(audit_events.AuditAction)
    restore = actions.index(audit_events.AuditAction.FILE_RESTORE)

    assert [action.value for action in actions[restore + 1 : restore + 3]] == [
        "file.exclude",
        "file.include",
    ]
    assert (
        audit_events.AuditAction.FILE_EXCLUDE.value,
        audit_events.AuditAction.FILE_INCLUDE.value,
    ) == ("file.exclude", "file.include")
    assert {
        audit_events.ACTION_SCOPES[audit_events.AuditAction.FILE_EXCLUDE],
        audit_events.ACTION_SCOPES[audit_events.AuditAction.FILE_INCLUDE],
    } == {"org"}


# ---------------------------------------------------------------------------
# 2. set_active
# ---------------------------------------------------------------------------


def test_attachments_active_set_active_signature(att: ModuleType) -> None:
    parameters = inspect.signature(att.set_active).parameters

    assert list(parameters) == ["pool", "tenant", "attachment_id", "active", "ip"]
    assert parameters["ip"].kind is inspect.Parameter.KEYWORD_ONLY
    assert inspect.iscoroutinefunction(att.set_active)


@pytest.mark.parametrize("status", _STATUSES)
@pytest.mark.parametrize("direction", ["exclude", "include"])
async def test_attachments_active_set_active_changes_the_flag_whatever_the_status(
    att: ModuleType, world: _World, status: str, direction: str
) -> None:
    """Stuck chat: a failed or unfinished file can be excluded (and included again)."""
    new = direction == "include"
    attachment_id = _add(world, status=status, active=not new)

    record = await _set(att, world, attachment_id, new)

    row = _row(world, attachment_id)
    assert isinstance(record, att.AttachmentRecord)
    assert (record.active, row["active"]) == (new, new)
    assert _dump(record) == _record_of_row(row)
    assert [audit["action"] for audit in world.db.audit] == [f"file.{direction}"]


@pytest.mark.parametrize(
    ("start", "new", "action"), [(True, False, "exclude"), (False, True, "include")]
)
async def test_attachments_active_set_active_records_one_content_free_event(
    att: ModuleType, world: _World, start: bool, new: bool, action: str
) -> None:
    attachment_id = _add(world, status="ready", active=start)

    await _set(att, world, attachment_id, new)

    (row,) = world.db.audit
    assert {
        "action": row["action"],
        "actor_kind": row["actor_kind"],
        "actor_user_id": plain(row["actor_user_id"]),
        "org_id": plain(row["org_id"]),
        "target_type": row["target_type"],
        "target_ids": row["target_ids"],
        "ip": row["ip"],
        "metadata": row["metadata"],
    } == {
        "action": f"file.{action}",
        "actor_kind": "member",
        "actor_user_id": world.member,
        "org_id": ORG_ID,
        "target_type": "file",
        "target_ids": [str(attachment_id)],
        "ip": _IP,
        "metadata": {},
    }
    assert NAME_CANARY not in json.dumps(world.db.audit, default=str)


@pytest.mark.parametrize("new", [False, True], ids=["exclude", "include"])
async def test_attachments_active_set_active_runs_a10a_a10b_and_the_audit_in_one_transaction(
    att: ModuleType, world: _World, new: bool
) -> None:
    attachment_id = _add(world, status="ready", active=not new)
    world.db.calls.clear()

    await _set(att, world, attachment_id, new)

    calls = world.db.calls
    assert _forms(calls) == ["A10a", "A10b", "audit"]
    assert len({(call.via, call.tx) for call in calls}) == 1
    assert calls[0].tx is not None
    assert world.db.transactions == [(calls[0].tx, "commit")]
    lock, update = calls[0], calls[1]
    assert (_uuid(lock.args[0]), _uuid(lock.args[1]), _uuid(lock.args[2])) == (
        attachment_id,
        ORG_ID,
        world.member,
    )
    assert (_uuid(update.args[0]), _uuid(update.args[1])) == (attachment_id, ORG_ID)
    assert update.args[2] is new


@pytest.mark.parametrize("value", [True, False], ids=["already-active", "already-excluded"])
async def test_attachments_active_set_active_same_value_writes_and_records_nothing(
    att: ModuleType, world: _World, value: bool
) -> None:
    """Idempotent: the record back, no UPDATE, no audit row."""
    attachment_id = _add(world, status="ready", active=value)
    before = world.db.snapshot()
    world.db.calls.clear()

    record = await _set(att, world, attachment_id, value)

    assert _forms(world.db.calls) == ["A10a"]
    assert world.db.snapshot() == before
    assert world.db.audit == []
    assert record.active is value
    assert _dump(record) == _record_of_row(_row(world, attachment_id))


async def test_attachments_active_set_active_keeps_a_sent_file_linked(
    att: ModuleType, world: _World
) -> None:
    """An excluded file stays linked to its message (and listed)."""
    attachment_id = _add(world, status="ready", message_id=world.message)

    record = await _set(att, world, attachment_id, False)

    row = _row(world, attachment_id)
    assert (plain(row["message_id"]), row["active"]) == (world.message, False)
    assert (record.message_id, record.active) == (world.message, False)


@pytest.mark.parametrize("case", _NOT_FOUND_CASES)
@pytest.mark.parametrize("new", [False, True], ids=["exclude", "include"])
async def test_attachments_active_set_active_anything_but_the_callers_live_file_is_not_found(
    att: ModuleType, world: _World, case: str, new: bool
) -> None:
    attachment_id = _foreign(world, case)
    before = world.db.snapshot()
    world.db.calls.clear()

    with pytest.raises(att.AttachmentNotFoundError) as caught:
        await _set(att, world, attachment_id, new)

    assert type(caught.value) is att.AttachmentNotFoundError
    assert str(caught.value) == "Attachment not found."
    assert _forms(world.db.calls) == ["A10a"]
    assert world.db.snapshot() == before
    assert world.db.audit == []


async def test_attachments_active_set_active_audit_failure_rolls_the_change_back(
    att: ModuleType, world: _World
) -> None:
    attachment_id = _add(world, status="ready")
    world.db.fail_audit = True

    with pytest.raises(AuditRecordError):
        await _set(att, world, attachment_id, False)

    assert _row(world, attachment_id)["active"] is True
    assert world.db.audit == []
    assert [outcome for _, outcome in world.db.transactions] == ["rollback:AuditRecordError"]


async def test_attachments_active_set_active_logs_no_file_name(
    att: ModuleType, world: _World
) -> None:
    attachment_id = _add(world, status="failed")
    with configured_logging("DEBUG", "text") as logs:
        await _set(att, world, attachment_id, False)
        with pytest.raises(att.AttachmentNotFoundError):
            await _set(att, world, _foreign(world, "colleague"), False)
        logged = logs.text + "\n".join(record.getMessage() for record in logs.records)

    assert _row(world, attachment_id)["active"] is False
    assert NAME_CANARY not in logged


# ---------------------------------------------------------------------------
# 3. list_chat_attachments
# ---------------------------------------------------------------------------


async def _list(
    att: ModuleType,
    world: _World,
    chat_id: uuid.UUID | None = None,
    *,
    limit: int = 50,
    cursor: str | None = None,
    status: str | None = None,
    active: bool | None = None,
) -> Any:
    return await att.list_chat_attachments(
        world.db.pool,
        world.tenant,
        world.chat if chat_id is None else chat_id,
        limit=limit,
        cursor=cursor,
        status=status,
        active=active,
    )


async def _walk(
    att: ModuleType,
    world: _World,
    *,
    limit: int,
    status: str | None = None,
    active: bool | None = None,
) -> tuple[list[list[uuid.UUID]], list[str | None]]:
    """Every page's ids and every next_cursor, following the cursors to the end."""
    pages: list[list[uuid.UUID]] = []
    cursors: list[str | None] = []
    cursor: str | None = None
    for _ in range(50):
        page = await _list(att, world, limit=limit, cursor=cursor, status=status, active=active)
        pages.append([record.id for record in page.attachments])
        cursors.append(page.next_cursor)
        cursor = page.next_cursor
        if cursor is None:
            return pages, cursors
    pytest.fail("the cursor walk never ended")


@dataclass(frozen=True)
class _Listing:
    order: list[uuid.UUID]  # every live file of the chat, oldest first
    ready: list[uuid.UUID]
    excluded: list[uuid.UUID]
    trashed: uuid.UUID


def _seed_listing(world: _World, *, with_excluded: bool) -> _Listing:
    """Seven live files of the caller's chat, one microsecond apart, with a tie group of
    three at _T0 + 2 µs (stored in reverse id order), plus a trashed one and other
    chats' files. ``with_excluded``: two of them are excluded (needs migration 0030)."""
    tie_c = uuid.UUID("c1900000-0000-4000-8000-0000000000c3")
    tie_a = uuid.UUID("a1900000-0000-4000-8000-0000000000c1")
    tie_b = uuid.UUID("b1900000-0000-4000-8000-0000000000c2")
    excluded_flag: dict[str, Any] = {"active": False} if with_excluded else {}
    f4 = _add(world, status="ready", created_at=_T0 + 3 * _US, **excluded_flag)
    _add(world, attachment_id=tie_c, status="failed", created_at=_T0 + 2 * _US)
    _add(world, attachment_id=tie_a, status="ready", created_at=_T0 + 2 * _US)
    _add(world, attachment_id=tie_b, status="uploaded", created_at=_T0 + 2 * _US)
    f1 = _add(world, status="ready", message_id=world.message, created_at=_T0 + _US)
    f0 = _add(world, status="processing", created_at=_T0, **excluded_flag)
    f5 = _add(world, status="ready", created_at=_T0 + 4 * _US)
    trashed = _add(world, status="ready", created_at=_T0 + _US, deleted_at=_T0 + 9 * _US)
    _add(world, world.other_chat, status="ready", created_at=_T0 + _US)
    _add(world, world.colleague_chat, status="ready", created_at=_T0 + _US)
    _add(world, world.foreign_chat, status="ready", created_at=_T0 + _US)
    order = [f0, f1, tie_a, tie_b, tie_c, f4, f5]
    return _Listing(
        order=order,
        ready=[f1, tie_a, f4, f5],
        excluded=[f0, f4] if with_excluded else [],
        trashed=trashed,
    )


def test_attachments_active_list_signature_and_page_model(att: ModuleType) -> None:
    parameters = inspect.signature(att.list_chat_attachments).parameters

    assert list(parameters)[:3] == ["executor", "tenant", "chat_id"]
    assert {
        name for name, parameter in parameters.items()
        if parameter.kind is inspect.Parameter.KEYWORD_ONLY
    } == {"limit", "cursor", "status", "active"}  # fmt: skip
    assert set(att.AttachmentPage.model_fields) == {"attachments", "next_cursor"}


async def test_attachments_active_list_returns_live_files_oldest_first(
    att: ModuleType, world: _World
) -> None:
    """created_at, then id (the tie group by id, though stored in reverse); the trashed
    file and other chats' files never."""
    listing = _seed_listing(world, with_excluded=False)

    page = await _list(att, world)

    assert [record.id for record in page.attachments] == listing.order
    assert listing.trashed not in [record.id for record in page.attachments]
    assert page.next_cursor is None
    assert all(isinstance(record, att.AttachmentRecord) for record in page.attachments)
    first = page.attachments[0]
    assert _dump(first) == _record_of_row(_row(world, listing.order[0]))


@pytest.mark.parametrize("limit", [1, 2, 3])
async def test_attachments_active_list_cursor_walk_returns_every_file_once_in_order(
    att: ModuleType, world: _World, limit: int
) -> None:
    """Limit 2 and 3 split the tie group across pages; limit 1 cuts it at every row."""
    listing = _seed_listing(world, with_excluded=False)

    pages, cursors = await _walk(att, world, limit=limit)

    assert [item for page in pages for item in page] == listing.order
    assert all(len(page) == limit for page in pages[:-1])
    assert 1 <= len(pages[-1]) <= limit
    assert cursors[-1] is None
    assert all(
        isinstance(cursor, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,200}", cursor)
        for cursor in cursors[:-1]
    )


async def test_attachments_active_list_exactly_limit_left_has_no_cursor(
    att: ModuleType, world: _World
) -> None:
    listing = _seed_listing(world, with_excluded=False)

    page = await _list(att, world, limit=len(listing.order))

    assert ([record.id for record in page.attachments], page.next_cursor) == (
        listing.order,
        None,
    )


async def test_attachments_active_list_status_filter_alone(att: ModuleType, world: _World) -> None:
    listing = _seed_listing(world, with_excluded=False)

    pages, _ = await _walk(att, world, limit=1, status="ready")

    assert [item for page in pages for item in page] == listing.ready


async def test_attachments_active_list_active_filter_alone(att: ModuleType, world: _World) -> None:
    listing = _seed_listing(world, with_excluded=True)

    excluded = await _list(att, world, active=False)
    included = await _list(att, world, active=True)

    assert [record.id for record in excluded.attachments] == listing.excluded
    assert [record.active for record in excluded.attachments] == [False, False]
    assert [record.id for record in included.attachments] == [
        item for item in listing.order if item not in listing.excluded
    ]


async def test_attachments_active_list_status_and_active_filters_together(
    att: ModuleType, world: _World
) -> None:
    """Ready and excluded: only f4; ready and active over pages of one."""
    listing = _seed_listing(world, with_excluded=True)

    both = await _list(att, world, status="ready", active=False)
    pages, _ = await _walk(att, world, limit=1, status="ready", active=True)

    assert [record.id for record in both.attachments] == [listing.order[5]]
    assert [item for page in pages for item in page] == [
        item for item in listing.ready if item not in listing.excluded
    ]


async def test_attachments_active_list_first_page_is_a11_with_its_binds(
    att: ModuleType, world: _World
) -> None:
    _seed_listing(world, with_excluded=False)
    world.db.calls.clear()

    await _list(att, world, limit=2, status="failed", active=True)

    calls = world.db.calls
    assert _forms(calls) == ["S2", "A11"]
    args = calls[1].args
    assert len(args) == 6
    assert (_uuid(args[0]), _uuid(args[1]), _uuid(args[2])) == (world.chat, ORG_ID, world.member)
    assert args[3] == "failed"
    assert args[4] is True
    assert (type(args[5]), args[5]) == (int, 3)


async def test_attachments_active_list_without_filters_binds_nulls(
    att: ModuleType, world: _World
) -> None:
    _seed_listing(world, with_excluded=False)
    world.db.calls.clear()

    await _list(att, world, limit=5)

    args = world.db.calls[1].args
    assert (args[3] is None, args[4] is None, args[5]) == (True, True, 6)


async def test_attachments_active_list_next_page_is_a11_prime_from_the_last_row(
    att: ModuleType, world: _World
) -> None:
    listing = _seed_listing(world, with_excluded=False)
    first = await _list(att, world, limit=3)
    last = _row(world, listing.order[2])
    world.db.calls.clear()

    await _list(att, world, limit=3, cursor=first.next_cursor, status="ready")

    calls = world.db.calls
    assert _forms(calls) == ["S2", "A11'"]
    args = calls[1].args
    assert len(args) == 8
    assert (_uuid(args[0]), _uuid(args[1]), _uuid(args[2])) == (world.chat, ORG_ID, world.member)
    assert (args[3], args[4] is None) == ("ready", True)
    assert (args[5], _uuid(args[6]), args[7]) == (last["created_at"], listing.order[2], 4)


@pytest.mark.parametrize("cursor", [None, "not-a-cursor"], ids=["no-cursor", "bad-cursor"])
@pytest.mark.parametrize("case", _NOT_FOUND_CASES)
async def test_attachments_active_list_foreign_chat_is_not_found_after_the_owner_check(
    att: ModuleType, world: _World, case: str, cursor: str | None
) -> None:
    chat_id = _foreign_chat(world, case)
    if case != "unknown":
        _add(world, chat_id, status="ready")
    world.db.calls.clear()

    with pytest.raises(chats.ChatNotFoundError) as caught:
        await _list(att, world, chat_id, cursor=cursor)

    assert type(caught.value) is chats.ChatNotFoundError
    assert _forms(world.db.calls) == ["S2"]


async def _other_cursors(att: ModuleType, world: _World) -> dict[str, str]:
    """A truncated attachments cursor, a chat-list cursor and a message cursor."""
    _seed_listing(world, with_excluded=False)
    page = await _list(att, world, limit=1)
    assert page.next_cursor is not None
    db = world.db
    db.add_chat(world.member)
    chat_page = await chats.list_chats(db.pool, world.tenant, limit=1, cursor=None)
    db.add_chat_message(world.chat, "assistant", "second")
    detail = await chats.read_chat_detail(db.pool, world.tenant, world.chat, limit=1, cursor=None)
    assert chat_page.next_cursor is not None
    assert detail.page.next_cursor is not None
    return {
        "truncated": page.next_cursor[:-4],
        "chat-list": chat_page.next_cursor,
        "messages": detail.page.next_cursor,
    }


@pytest.mark.parametrize("kind", ["truncated", "chat-list", "messages", *_GARBAGE_CURSORS])
async def test_attachments_active_list_invalid_or_foreign_cursor_is_invalid(
    att: ModuleType, world: _World, kind: str
) -> None:
    cursors = await _other_cursors(att, world)
    cursor = cursors.get(kind, kind)
    world.db.calls.clear()

    with pytest.raises(chats.InvalidCursorError):
        await _list(att, world, cursor=cursor)

    assert _forms(world.db.calls) == ["S2"]


async def test_attachments_active_list_records_carry_the_flag(
    att: ModuleType, world: _World
) -> None:
    excluded = _add(world, status="ready", active=False, created_at=_T0)
    included = _add(world, status="ready", created_at=_T0 + _US)

    page = await _list(att, world)

    assert [(record.id, record.active) for record in page.attachments] == [
        (excluded, False),
        (included, True),
    ]


# ---------------------------------------------------------------------------
# 4. ready_active_attachments (A12)
# ---------------------------------------------------------------------------


async def test_attachments_active_ready_active_are_the_chats_live_ready_active_files(
    att: ModuleType, world: _World
) -> None:
    """Sent or not, in upload order (a created_at tie by id), with estimate and bytes."""
    late = _add(world, status="ready", token_estimate=40, derived_bytes=400,
                created_at=_T0 + 2 * _US)  # fmt: skip
    tie_high = _add(world, attachment_id=uuid.UUID("91900000-0000-4000-8000-0000000000d2"),
                    filename="b.csv", kind="csv", status="ready", message_id=world.message,
                    created_at=_T0 + _US)  # fmt: skip
    tie_low = _add(world, attachment_id=uuid.UUID("11900000-0000-4000-8000-0000000000d1"),
                   filename="a.pdf", kind="pdf", status="ready", page_count=2,
                   token_estimate=0, derived_bytes=0, created_at=_T0 + _US)  # fmt: skip
    for noise in (
        {"status": "ready", "active": False, "token_estimate": 9},
        {"status": "uploaded"},
        {"status": "processing"},
        {"status": "failed", "failure_reason": "context_overflow", "token_estimate": 9},
        {"status": "ready", "deleted_at": _T0, "token_estimate": 9},
    ):
        _add(world, created_at=_T0, **noise)
    _add(world, world.other_chat, status="ready", token_estimate=9)

    result = await att.ready_active_attachments(world.db.pool, world.tenant, world.chat)

    active = chats.ActiveAttachment
    assert type(result) is list
    assert result == [
        active(
            id=tie_low,
            filename="a.pdf",
            kind="pdf",
            page_count=2,
            token_estimate=0,
            derived_bytes=0,
        ),  # fmt: skip
        active(
            id=tie_high,
            filename="b.csv",
            kind="csv",
            page_count=None,
            token_estimate=None,
            derived_bytes=None,
        ),  # fmt: skip
        active(
            id=late,
            filename=NAME_CANARY,
            kind="pdf",
            page_count=None,
            token_estimate=40,
            derived_bytes=400,
        ),  # fmt: skip
    ]


async def test_attachments_active_ready_active_is_one_a12_statement(
    att: ModuleType, world: _World
) -> None:
    _add(world, status="ready")
    world.db.calls.clear()

    await att.ready_active_attachments(world.db.pool, world.tenant, world.chat)

    calls = world.db.calls
    assert _forms(calls) == ["A12"]
    assert calls[0].method == "fetch"
    assert [_uuid(arg) for arg in calls[0].args] == [world.chat, ORG_ID, world.member]


@pytest.mark.parametrize("case", ["other-org", "colleague"])
async def test_attachments_active_ready_active_of_someone_elses_chat_is_empty(
    att: ModuleType, world: _World, case: str
) -> None:
    chat_id = _foreign_chat(world, case)
    _add(world, chat_id, status="ready", token_estimate=5)

    result = await att.ready_active_attachments(world.db.pool, world.tenant, chat_id)

    assert result == []


# ---------------------------------------------------------------------------
# 5. check_sendable (A8''): refusals over every id, the active ones returned
# ---------------------------------------------------------------------------


async def _sendable(att: ModuleType, world: _World, ids: list[uuid.UUID]) -> Any:
    return await att.check_sendable(world.db.pool, world.tenant, world.chat, ids)


async def test_attachments_active_check_sendable_returns_only_the_active_files(
    att: ModuleType, world: _World
) -> None:
    excluded = _add(world, status="ready", token_estimate=7, created_at=_T0, active=False)
    included = _add(world, filename="a.pdf", status="ready", page_count=1, token_estimate=1200,
                    derived_bytes=4096, created_at=_T0 + _US)  # fmt: skip
    world.db.calls.clear()

    result = await _sendable(att, world, [excluded, included])

    assert _forms(world.db.calls) == ["A8''"]
    assert result == [
        chats.ActiveAttachment(
            id=included,
            filename="a.pdf",
            kind="pdf",
            page_count=1,
            token_estimate=1200,
            derived_bytes=4096,
        )  # fmt: skip
    ]


async def test_attachments_active_check_sendable_only_excluded_files_give_empty_list(
    att: ModuleType, world: _World
) -> None:
    excluded = _add(world, status="ready", active=False)

    assert await _sendable(att, world, [excluded]) == []


@pytest.mark.parametrize(
    ("fault", "error"),
    [
        ({"status": "ready", "deleted_at": _T0}, "AttachmentNotFoundError"),
        ({"status": "ready", "message_id": "sent"}, "AttachmentAlreadySentError"),
        ({"status": "processing"}, "AttachmentNotReadyError"),
        ({"status": "failed"}, "AttachmentNotReadyError"),
    ],
    ids=["trashed", "sent", "processing", "failed"],
)
async def test_attachments_active_check_sendable_still_refuses_an_excluded_file(
    att: ModuleType, world: _World, fault: dict[str, Any], error: str
) -> None:
    values = dict(fault)
    if values.get("message_id") == "sent":
        values["message_id"] = world.message
    fine = _add(world, status="ready")
    excluded = _add(world, active=False, **values)

    with pytest.raises(getattr(att, error)) as caught:
        await _sendable(att, world, [fine, excluded])

    assert type(caught.value) is getattr(att, error)


# ---------------------------------------------------------------------------
# 6. A5' / A6': the record carries the flag
# ---------------------------------------------------------------------------


async def test_attachments_active_get_attachment_reports_the_flag(
    att: ModuleType, world: _World
) -> None:
    excluded = _add(world, status="ready", active=False)
    included = _add(world, status="ready")

    records = [
        await att.get_attachment(world.db.pool, world.tenant, attachment_id)
        for attachment_id in (excluded, included)
    ]

    assert [record.active for record in records] == [False, True]
    assert _dump(records[0]) == _record_of_row(_row(world, excluded))


async def test_attachments_active_upload_record_is_active(
    att: ModuleType, world: _World, tmp_path: Path
) -> None:
    data = b"# Notes\n\nRevenue is up.\n"

    async def body() -> AsyncIterator[bytes]:
        yield data

    record = await att.upload_attachment(
        world.db.pool,
        world.tenant,
        world.chat,
        filename="notes.md",
        declared_length=len(data),
        body=body(),
        root=tmp_path / "attachments",
        max_bytes=4096,
        ip=_IP,
    )

    assert record.active is True
    assert _row(world, record.id)["active"] is True
    assert _dump(record) == _record_of_row(_row(world, record.id))
