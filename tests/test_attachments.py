"""Tests for ``admino.attachments`` (GH-187 contract section 3.3): the attachment
repository, its disk storage and the upload service, against the FakeDb and tmp_path.

What these tests pin down:
- ``attachments_root()`` is ``organizations.ATTACHMENTS_ROOT`` read at call time;
  ``attachment_path(root, org, id)`` is ``root/<org>/<id>``; ``AttachmentRecord`` has
  exactly the contract's R columns (GH-188 contract section 7: ``token_estimate``
  after ``page_count``; A5's RETURNING and A6's SELECT list them).
- ``upload_attachment`` refuses, with the exact ``AttachmentRefusedError.reason`` (or
  ``chats.ChatNotFoundError``) and NOTHING stored (no row, no file or ``.part`` under
  the root, no ``file.upload`` event):
  - ``empty_file`` (declared 0) and ``file_too_large`` (declared above max_bytes)
    before any statement;
  - another org's, a colleague's, a trashed and an unknown chat right after the
    owner check (``chats.get_chat``), before the quota lookup;
  - ``storage_quota_exceeded`` at the pre-check (A1 then A4: org-wide, trashed files
    included, other orgs excluded, the NUMERIC sum compared exactly: used + size ==
    quota is accepted, one byte more refused). GH-188 (contract 12.4, audit fix M-3):
    "used" is A4' = the originals AND the stored derived bytes (``size_bytes +
    coalesce(derived_bytes, 0)``, so a NULL counts 0): an org whose derived files fill
    the quota refuses an upload that would fit on originals alone, exactly at the
    boundary;
  all of these before the body is pulled once;
  - ``content_length_mismatch`` when the body runs past the declared length (it stops
    pulling right after the chunk that passed it) or ends short; a body that raises
    (a client disconnect) propagates unchanged;
  - the detection refusals (unsupported_type, corrupted_file, password_protected,
    legacy_office) propagate;
  - at commit: a chat trashed while the body streamed is ``ChatNotFoundError``, and
    another upload that filled the quota meanwhile is ``storage_quota_exceeded``
    (the quota is checked again under the org row lock); so are derived bytes a
    conversion stored meanwhile (GH-188: the commit check is A4' too);
  - an audit write failure is ``AuditRecordError`` with the row rolled back;
  - a disk failure (the root or the org directory is a regular file, a symlink
    planted at the partial file's name, a failing rename) is
    ``storage_unavailable``; the rename happens inside the transaction, so a failed
    rename stores no row.
- A stored upload: the returned record (status uploaded, kind detected from the
  content, never from the name; size; the sanitized filename as given; no message,
  reason, page count or token estimate); the statements, in order: the owner check, A1, A4 outside a
  transaction, then A2 (chat FOR SHARE, first), A3 (org FOR NO KEY UPDATE), A4, A5
  and the audit insert in one committed transaction on one connection; one
  ``file.upload`` event (member actor, the org, target the file, the ip, metadata
  exactly ``{"size_bytes": n}``); the file ``root/<org>/<id>`` holds exactly the
  bytes, mode 0600, its directory 0700, no ``.part`` left; detection ran in a worker
  thread on the complete ``<id>.part`` with the filename.
- ``get_attachment`` (A6) returns the caller's live attachment (a ready one with its
  page count and token estimate, GH-188); another org's, a
  colleague's, a trashed and an unknown one are ``AttachmentNotFoundError`` with one
  identical message carrying no id.
- ``org_storage`` (A7) returns ``(file_count, used_bytes)`` as ints: every row of the
  org (trashed included, colleagues' too), no other org's; ``(0, 0)`` for none.
  GH-188 (contract 12.4): A7' = used_bytes counts the originals plus the derived bytes
  (NULL derived bytes count 0).
- ``check_sendable`` (A8): no statement for no ids; None when every id is the
  caller's live, unsent attachment of this chat; any id that isn't (another chat,
  another org, a colleague's, trashed, unknown) is ``AttachmentNotFoundError``,
  which wins over an already-sent one; an already-sent id is
  ``AttachmentAlreadySentError``.
- ``remove_files`` removes ``<id>``, ``<id>.part`` and the ``<id>.d`` tree of each id
  under ``root/<org>`` and counts the removed entries; another org's directory and
  other ids stay; a symlink is unlinked, never followed (its target survives);
  missing entries are fine; an ``OSError`` is logged with its class name only (no
  path, no traceback), never raised, and the other entries are still removed.
- Logs: during an upload (stored or refused) no record carries the filename, the
  file's bytes or a path.

``admino.attachments`` and ``admino.attachment_types`` are imported inside fixtures,
so this file collects before they exist and each test fails on its own. Files live
under tmp_path; fixture content is built in code (no binary in the repo).
"""

from __future__ import annotations

import itertools
import os
import re
import stat
import struct
import threading
import traceback
import uuid
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import audit_events, chats, organizations
from admino.tenancy import TenantContext
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, Call, FakeDb
from tests.log_capture import CapturedLogs, configured_logging

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterable
    from types import ModuleType

_QUOTA: Final = 1_000_000
_MAX_BYTES: Final = 4096
_IP: Final = "203.0.113.87"
_NOW: Final = datetime.now(UTC)
_UNKNOWN_ID: Final = uuid.UUID("187a0c2e-1b2c-4d3e-8f40-5a6b7c8d9e01")
_FIXED_ID: Final = uuid.UUID("187a0c2e-1b2c-4d3e-8f40-5a6b7c8d9e02")

_R: Final = (
    "id, chat_id, message_id, filename, kind, size_bytes, status, failure_reason, "
    "page_count, token_estimate, created_at"
)
_R_COLUMNS: Final = tuple(column.strip() for column in _R.split(","))
# Literal pieces joined with the R column list (no SQL is built from input).
_SELECT: Final = "SELECT "
_A5_HEAD: Final = (
    "INSERT INTO attachments (id, org_id, chat_id, owner_user_id, filename, kind, "
    "size_bytes) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING "
)
_A6_TAIL: Final = (
    " FROM attachments WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL"
)
_FORMS: Final[dict[str, str]] = {
    "A1": "SELECT storage_quota_bytes FROM organizations WHERE id = $1",
    "A2": "SELECT id FROM chats WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 "
    "AND deleted_at IS NULL FOR SHARE",
    "A3": "SELECT storage_quota_bytes FROM organizations WHERE id = $1 FOR NO KEY UPDATE",
    # GH-188 (contract 12.4): A4' and A7' count the derived files too.
    "A4": "SELECT coalesce(sum(size_bytes + coalesce(derived_bytes, 0)), 0) FROM attachments "
    "WHERE org_id = $1",
    "A5": _A5_HEAD + _R,
    "A6": _SELECT + _R + _A6_TAIL,
    "A7": "SELECT count(*) AS file_count, coalesce(sum(size_bytes + coalesce(derived_bytes, 0)), "
    "0) AS used_bytes FROM attachments WHERE org_id = $1",
    "A8": "SELECT id, message_id FROM attachments WHERE id = ANY($1::uuid[]) AND chat_id = $2 "
    "AND org_id = $3 AND owner_user_id = $4 AND deleted_at IS NULL",
}

_PNG_SIGNATURE: Final = b"\x89PNG\r\n\x1a\n"
_CFB_MAGIC: Final = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_MARKDOWN: Final = b"# Board notes\n\nRevenue is up.\n"
_NAME_MARKER: Final = "ZZ-W2-NAME-187 board plan.txt"
_CONTENT_MARKER: Final = "ZZ-W2-CONTENT-187"

# Content that detection refuses, with the file name it is uploaded under.
_REFUSED_CONTENT: Final[tuple[tuple[str, bytes, str], ...]] = (
    ("unsupported_type", b"\x7fELF\x02\x01\x01\x00" + bytes(24), "readme.txt"),
    ("corrupted_file", b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n", "report.pdf"),
    (
        "password_protected",
        b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<< /Root 1 0 R /Encrypt 2 0 R >>\n%%EOF\n",
        "report.pdf",
    ),
    ("legacy_office", _CFB_MAGIC + bytes(504), "budget.doc"),
)


def _png() -> bytes:
    """The smallest PNG detection accepts: signature plus an IHDR chunk (33 bytes)."""
    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    chunk = b"IHDR" + header
    return (
        _PNG_SIGNATURE
        + struct.pack(">I", len(header))
        + chunk
        + struct.pack(">I", zlib.crc32(chunk))
    )


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def att() -> ModuleType:
    """The module under test, imported lazily (it doesn't exist before GH-187)."""
    import admino.attachments as module

    return module


@pytest.fixture
def at() -> ModuleType:
    import admino.attachment_types as module

    return module


@dataclass
class _World:
    db: FakeDb
    member: uuid.UUID
    colleague: uuid.UUID
    outsider: uuid.UUID
    chat: uuid.UUID
    tenant: TenantContext
    root: Path


@pytest.fixture
def world(tmp_path: Path) -> _World:
    """ORG_ID with a quota, its member (the caller) with a chat, a colleague, and a
    member of OTHER_ORG_ID; the attachments root under tmp_path (not created)."""
    db = FakeDb()
    db.add_org(ORG_ID, storage_quota_bytes=_QUOTA)
    db.add_org(OTHER_ORG_ID, storage_quota_bytes=_QUOTA)
    member = db.add_account(org_id=ORG_ID)
    colleague = db.add_account(org_id=ORG_ID)
    outsider = db.add_account(org_id=OTHER_ORG_ID)
    return _World(
        db=db,
        member=member,
        colleague=colleague,
        outsider=outsider,
        chat=db.add_chat(member),
        tenant=TenantContext(org_id=ORG_ID, user_id=member, role="editor"),
        root=tmp_path / "attachments",
    )


class _ClientGoneError(Exception):
    """What the body raises when the client goes away mid-upload."""


class _Body:
    """An upload body: an async generator that counts every chunk it hands out.

    ``hooks`` maps a pull number (1-based) to a callable run just before that chunk
    is handed out (a concurrent change while the upload streams).
    """

    def __init__(
        self, chunks: Iterable[bytes], hooks: dict[int, Callable[[], None]] | None = None
    ) -> None:
        self.chunks = chunks
        self.hooks = hooks or {}
        self.pulls = 0

    async def stream(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            self.pulls += 1
            hook = self.hooks.get(self.pulls)
            if hook is not None:
                hook()
            yield chunk


def _chunks(data: bytes, size: int = 7) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]


async def _upload(
    att: ModuleType,
    w: _World,
    body: _Body,
    *,
    filename: str = "notes.md",
    declared: int,
    chat: uuid.UUID | None = None,
    max_bytes: int = _MAX_BYTES,
) -> Any:
    return await att.upload_attachment(
        w.db.pool,
        w.tenant,
        w.chat if chat is None else chat,
        filename=filename,
        declared_length=declared,
        body=body.stream(),
        root=w.root,
        max_bytes=max_bytes,
        ip=_IP,
    )


def _canon_sql(sql: str) -> str:
    """Lowercased, whitespace collapsed and dropped around ( ) , = (tokens kept)."""
    text = re.sub(r"\s+", " ", sql.strip().lower()).rstrip(";").strip()
    return re.sub(r"\s*([(),=])\s*", r"\1", text)


_CANON_FORMS: Final = {label: _canon_sql(form) for label, form in _FORMS.items()}
_GET_CHAT_RE: Final = re.compile(
    r"select .+ from chats where id=\$1 and org_id=\$2 and owner_user_id=\$3 "
    r"and deleted_at is null"
)


def _label(call: Call) -> str:
    """The contract form a recorded statement is (get_chat, A1..A8, audit), else its SQL."""
    text = _canon_sql(call.sql)
    for label, form in _CANON_FORMS.items():
        if text == form:
            return label
    if text.startswith("insert into audit_events"):
        return "audit"
    if _GET_CHAT_RE.fullmatch(text):
        return "get_chat"
    return text


def _labels(db: FakeDb) -> list[tuple[str, bool]]:
    """(form, inside a transaction) of every statement, in order."""
    return [(_label(call), call.tx is not None) for call in db.calls]


_PRE_CHECK: Final = [("get_chat", False), ("A1", False), ("A4", False)]


def _left_on_disk(root: Path) -> list[str]:
    """Every entry below an org directory of the root (org directories themselves may
    exist), relative to the root."""
    if not root.is_dir():
        return []
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.parent != root)


def _stored(w: _World) -> tuple[list[str], int, list[str]]:
    """(attachment row ids, file.upload events, files on disk): what an upload left."""
    return (
        sorted(str(row_id) for row_id in w.db.attachments),
        len(w.db.audit_rows("file.upload")),
        _left_on_disk(w.root),
    )


def _patch_both(
    monkeypatch: pytest.MonkeyPatch, att: ModuleType, owner: Any, name: str, value: Any
) -> None:
    """Patch a function where it is defined and, if imported by name, in attachments."""
    monkeypatch.setattr(owner, name, value)
    if hasattr(att, name):
        monkeypatch.setattr(att, name, value)


def _log_text(logs: CapturedLogs) -> str:
    """The formatted output plus every raw record's message, args and traceback."""
    parts = [logs.text]
    for record in logs.records:
        parts.append(record.getMessage())
        parts.append(repr(record.args))
        if record.exc_info:
            parts.append("".join(traceback.format_exception(*record.exc_info)))
        if record.exc_text:
            parts.append(record.exc_text)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# 1. Root, paths and the record
# ---------------------------------------------------------------------------


class TestAttachmentsLayout:
    """Where files live and what a record holds."""

    def test_attachments_root_reads_organizations_root_at_call_time(
        self, att: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Every caller goes through it, so the org purge and the uploads agree."""
        seen = []
        for name in ("first", "second"):
            monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", tmp_path / name)
            seen.append(att.attachments_root())

        assert seen == [tmp_path / "first", tmp_path / "second"]

    def test_attachments_path_is_root_org_id(self, att: ModuleType, tmp_path: Path) -> None:
        assert att.attachment_path(tmp_path, ORG_ID, _FIXED_ID) == (
            tmp_path / str(ORG_ID) / str(_FIXED_ID)
        )

    def test_attachments_record_has_exactly_the_r_columns(self, att: ModuleType) -> None:
        assert tuple(att.AttachmentRecord.model_fields) == _R_COLUMNS

    def test_attachments_errors_are_lookup_and_plain_errors(self, att: ModuleType) -> None:
        assert issubclass(att.AttachmentNotFoundError, LookupError)
        assert issubclass(att.AttachmentAlreadySentError, Exception)
        assert not issubclass(att.AttachmentAlreadySentError, LookupError)


# ---------------------------------------------------------------------------
# 2. A stored upload
# ---------------------------------------------------------------------------


class TestAttachmentsUploadStored:
    """What a successful upload returns, runs, records and writes."""

    async def test_attachments_upload_returns_the_uploaded_record(
        self, att: ModuleType, world: _World
    ) -> None:
        """Status uploaded, the kind from the content (a PNG named .pdf is png), the
        size, the filename as given; max_bytes equal to the size is accepted."""
        data = _png()

        record = await _upload(
            att,
            world,
            _Body(_chunks(data)),
            filename="scan.pdf",
            declared=len(data),
            max_bytes=len(data),
        )
        row = world.db.attachment_row(record.id)

        assert isinstance(record, att.AttachmentRecord)
        assert row is not None
        assert record.model_dump() == {
            "id": record.id,
            "chat_id": world.chat,
            "message_id": None,
            "filename": "scan.pdf",
            "kind": "png",
            "size_bytes": len(data),
            "status": "uploaded",
            "failure_reason": None,
            "page_count": None,
            "token_estimate": None,
            "created_at": row["created_at"],
        }
        assert (row["org_id"], row["owner_user_id"], row["deleted_at"]) == (
            ORG_ID,
            world.member,
            None,
        )

    async def test_attachments_upload_runs_the_contract_statements_in_order(
        self, att: ModuleType, world: _World
    ) -> None:
        """Owner check, A1, A4 outside a transaction; then A2 (the chat lock first), A3
        (the org lock), A4, A5 and the audit insert in one committed transaction on one
        connection, each bound to the caller's ids."""
        data = _MARKDOWN

        record = await _upload(att, world, _Body(_chunks(data)), declared=len(data))
        in_tx = [call for call in world.db.calls if call.tx is not None]
        args = {_label(call): call.args for call in world.db.calls if _label(call) != "audit"}

        assert _labels(world.db) == [
            *_PRE_CHECK,
            ("A2", True),
            ("A3", True),
            ("A4", True),
            ("A5", True),
            ("audit", True),
        ]
        assert len({(call.tx, call.via) for call in in_tx}) == 1
        assert world.db.transactions == [(in_tx[0].tx, "commit")]
        assert args == {
            "get_chat": (world.chat, ORG_ID, world.member),
            "A1": (ORG_ID,),
            "A4": (ORG_ID,),
            "A2": (world.chat, ORG_ID, world.member),
            "A3": (ORG_ID,),
            "A5": (record.id, ORG_ID, world.chat, world.member, "notes.md", "md", len(data)),
        }

    async def test_attachments_upload_records_one_file_upload_event(
        self, att: ModuleType, world: _World
    ) -> None:
        """file.upload by the member, in the org, on the file, with the ip and the size
        only (no name, no kind)."""
        data = _MARKDOWN

        record = await _upload(att, world, _Body(_chunks(data)), declared=len(data))
        rows = world.db.audit_rows("file.upload")

        assert len(rows) == 1
        assert {
            key: rows[0][key]
            for key in (
                "org_id",
                "actor_user_id",
                "actor_kind",
                "target_type",
                "target_ids",
                "ip",
                "metadata",
            )
        } == {
            "org_id": ORG_ID,
            "actor_user_id": world.member,
            "actor_kind": "member",
            "target_type": "file",
            "target_ids": [str(record.id)],
            "ip": _IP,
            "metadata": {"size_bytes": len(data)},
        }

    async def test_attachments_upload_writes_the_file_0600_in_a_0700_directory(
        self, att: ModuleType, world: _World
    ) -> None:
        """root/<org>/<id> holds exactly the bytes; the id names the file; no .part."""
        data = _MARKDOWN * 40

        record = await _upload(att, world, _Body(_chunks(data, 64)), declared=len(data))
        org_dir = world.root / str(ORG_ID)
        stored = org_dir / str(record.id)

        assert sorted(entry.name for entry in org_dir.iterdir()) == [str(record.id)]
        assert stored.read_bytes() == data
        assert stat.S_IMODE(stored.stat().st_mode) == 0o600
        assert stat.S_IMODE(org_dir.stat().st_mode) == 0o700

    async def test_attachments_upload_detects_the_complete_part_file_in_a_thread(
        self,
        att: ModuleType,
        at: ModuleType,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """detect_kind runs off the event loop's thread, on <id>.part holding every byte,
        with the filename (which picks among the text kinds: notes.md is md)."""
        data = _MARKDOWN
        seen: list[tuple[bool, Path, bytes | None, str]] = []
        real = at.detect_kind
        loop_thread = threading.get_ident()

        def spy(path: Path, filename: str) -> Any:
            path = Path(path)
            content = path.read_bytes() if path.exists() else None
            seen.append((threading.get_ident() != loop_thread, path, content, filename))
            return real(path, filename)

        _patch_both(monkeypatch, att, at, "detect_kind", spy)

        record = await _upload(att, world, _Body(_chunks(data)), declared=len(data))

        assert seen == [(True, world.root / str(ORG_ID) / f"{record.id}.part", data, "notes.md")]
        assert record.kind == "md"

    @pytest.mark.parametrize("size", [40, 41], ids=["fills-the-quota", "one-byte-over"])
    async def test_attachments_upload_quota_counts_the_org_including_trash(
        self, att: ModuleType, world: _World, size: int
    ) -> None:
        """Used is every attachment of the org (a trashed one and a colleague's
        included, another org's not), summed as NUMERIC: used + size == quota is
        stored, one byte more is storage_quota_exceeded at the pre-check."""
        db = world.db
        db.add_org(ORG_ID, storage_quota_bytes=100)
        db.add_attachment(world.chat, filename="a.txt", kind="txt", size_bytes=30)
        db.add_attachment(world.chat, filename="b.txt", kind="txt", size_bytes=20, deleted_at=_NOW)
        db.add_attachment(db.add_chat(world.colleague), filename="c.txt", kind="txt", size_bytes=10)
        db.add_attachment(db.add_chat(world.outsider), filename="d.txt", kind="txt", size_bytes=900)
        body = _Body([b"q" * size])
        outcome: str

        try:
            record = await _upload(att, world, body, filename="q.txt", declared=size)
        except Exception as exc:
            outcome = getattr(exc, "reason", type(exc).__name__)
        else:
            outcome = f"stored:{record.size_bytes}"

        expected = "stored:40" if size == 40 else "storage_quota_exceeded"
        assert (outcome, body.pulls) == (expected, 1 if size == 40 else 0)


# ---------------------------------------------------------------------------
# 3. Refusals before the body is read
# ---------------------------------------------------------------------------


class TestAttachmentsUploadRefusedEarly:
    """Each refusal that needs no body byte stores nothing and reads nothing."""

    @pytest.mark.parametrize(
        ("declared", "reason"),
        [(0, "empty_file"), (_MAX_BYTES + 1, "file_too_large")],
        ids=["empty", "too-large"],
    )
    async def test_attachments_upload_size_refusal_runs_no_statement(
        self, att: ModuleType, at: ModuleType, world: _World, declared: int, reason: str
    ) -> None:
        body = _Body([b"x"])

        with pytest.raises(at.AttachmentRefusedError) as caught:
            await _upload(att, world, body, declared=declared)

        assert (caught.value.reason, world.db.calls, body.pulls) == (reason, [], 0)
        assert _stored(world) == ([], 0, [])

    @pytest.mark.parametrize("chat_kind", ["other-org", "colleague", "trashed", "unknown"])
    async def test_attachments_upload_foreign_chat_is_not_found_before_the_quota(
        self, att: ModuleType, world: _World, chat_kind: str
    ) -> None:
        """Another org's, a colleague's, a trashed or an unknown chat: ChatNotFoundError
        after the owner check alone (no quota lookup), nothing pulled or stored."""
        db = world.db
        chat = {
            "other-org": lambda: db.add_chat(world.outsider),
            "colleague": lambda: db.add_chat(world.colleague),
            "trashed": lambda: db.add_chat(world.member, deleted_at=_NOW),
            "unknown": lambda: _UNKNOWN_ID,
        }[chat_kind]()
        body = _Body([b"hello"])

        with pytest.raises(chats.ChatNotFoundError):
            await _upload(att, world, body, filename="a.txt", declared=5, chat=chat)

        assert (_labels(db), body.pulls) == ([("get_chat", False)], 0)
        assert _stored(world) == ([], 0, [])

    async def test_attachments_upload_quota_precheck_refuses_before_reading(
        self, att: ModuleType, at: ModuleType, world: _World
    ) -> None:
        """A1 then A4 on the pool: used + declared above the quota is
        storage_quota_exceeded, no transaction, nothing pulled or written."""
        db = world.db
        db.add_org(ORG_ID, storage_quota_bytes=100)
        existing = db.add_attachment(world.chat, filename="a.txt", kind="txt", size_bytes=60)
        body = _Body([b"x" * 41])

        with pytest.raises(at.AttachmentRefusedError) as caught:
            await _upload(att, world, body, filename="b.txt", declared=41)

        assert (caught.value.reason, _labels(db), body.pulls) == (
            "storage_quota_exceeded",
            _PRE_CHECK,
            0,
        )
        assert _stored(world) == ([str(existing)], 0, [])

    async def test_attachments_upload_quota_precheck_counts_stored_derived_bytes(
        self, att: ModuleType, at: ModuleType, world: _World
    ) -> None:
        """GH-188 (contract 12.4): quota 100, a file of 10 bytes with no derived bytes yet
        (NULL counts 0) and a ready one of 5 bytes with 54 derived bytes: used is 69.
        32 bytes are refused at the pre-check (nothing pulled), though the originals
        alone (15) leave room; exactly 31 is accepted and stored."""
        db = world.db
        db.add_org(ORG_ID, storage_quota_bytes=100)
        db.add_attachment(world.chat, filename="a.txt", kind="txt", size_bytes=10)
        db.add_attachment(
            world.chat,
            filename="b.txt",
            kind="txt",
            size_bytes=5,
            status="ready",
            page_count=1,
            token_estimate=2,
            derived_bytes=54,
        )
        outcomes: dict[int, Any] = {}
        for declared in (32, 31):
            body = _Body([b"x" * declared])
            db.calls.clear()
            try:
                await _upload(att, world, body, filename="c.txt", declared=declared)
            except at.AttachmentRefusedError as exc:
                outcomes[declared] = (exc.reason, _labels(db), body.pulls)
            else:
                outcomes[declared] = "stored"

        assert outcomes == {32: ("storage_quota_exceeded", _PRE_CHECK, 0), 31: "stored"}
        assert len(db.attachments) == 3


# ---------------------------------------------------------------------------
# 4. Refusals while or after streaming
# ---------------------------------------------------------------------------


class TestAttachmentsUploadRefusedLate:
    """A refusal after the partial file exists removes it and stores nothing."""

    async def test_attachments_upload_body_past_declared_length_stops_at_once(
        self, att: ModuleType, at: ModuleType, world: _World
    ) -> None:
        """A lying Content-Length: the body is read until the chunk that passes the
        declared 10 bytes (the second of 6), and not one chunk more."""
        body = _Body(itertools.repeat(b"x" * 6, 1000))

        with pytest.raises(at.AttachmentRefusedError) as caught:
            await _upload(att, world, body, filename="a.txt", declared=10)

        assert (caught.value.reason, body.pulls) == ("content_length_mismatch", 2)
        assert _labels(world.db) == _PRE_CHECK
        assert _stored(world) == ([], 0, [])

    async def test_attachments_upload_body_shorter_than_declared_is_refused(
        self, att: ModuleType, at: ModuleType, world: _World
    ) -> None:
        body = _Body([b"x" * 6])

        with pytest.raises(at.AttachmentRefusedError) as caught:
            await _upload(att, world, body, filename="a.txt", declared=10)

        assert caught.value.reason == "content_length_mismatch"
        assert _labels(world.db) == _PRE_CHECK
        assert _stored(world) == ([], 0, [])

    async def test_attachments_upload_body_error_propagates_and_cleans_up(
        self, att: ModuleType, world: _World
    ) -> None:
        """A client that goes away mid-body: its error propagates unchanged."""

        def gone() -> None:
            raise _ClientGoneError

        body = _Body([b"x" * 6, b"y" * 6], hooks={2: gone})

        with pytest.raises(_ClientGoneError):
            await _upload(att, world, body, filename="a.txt", declared=12)

        assert _stored(world) == ([], 0, [])

    @pytest.mark.parametrize(
        ("reason", "data", "filename"),
        _REFUSED_CONTENT,
        ids=[reason for reason, _, _ in _REFUSED_CONTENT],
    )
    async def test_attachments_upload_detection_refusal_stores_nothing(
        self,
        att: ModuleType,
        at: ModuleType,
        world: _World,
        reason: str,
        data: bytes,
        filename: str,
    ) -> None:
        """The content decides (an executable named .txt is unsupported); the refusal
        comes before the commit transaction."""
        with pytest.raises(at.AttachmentRefusedError) as caught:
            await _upload(att, world, _Body(_chunks(data)), filename=filename, declared=len(data))

        assert caught.value.reason == reason
        assert _labels(world.db) == _PRE_CHECK
        assert _stored(world) == ([], 0, [])

    async def test_attachments_upload_chat_trashed_while_streaming_is_not_found(
        self, att: ModuleType, world: _World
    ) -> None:
        """The owner check runs again under the chat lock (A2) at commit: a chat
        trashed meanwhile is ChatNotFoundError, rolled back, nothing stored."""
        db = world.db

        def trash() -> None:
            db.chats[world.chat]["deleted_at"] = datetime.now(UTC)

        body = _Body([b"a" * 5, b"b" * 5], hooks={2: trash})

        with pytest.raises(chats.ChatNotFoundError):
            await _upload(att, world, body, filename="a.txt", declared=10)

        assert [label for label, in_tx in _labels(db) if in_tx] == ["A2"]
        assert [outcome for _, outcome in db.transactions] == ["rollback:ChatNotFoundError"]
        assert _stored(world) == ([], 0, [])

    async def test_attachments_upload_quota_filled_while_streaming_is_refused(
        self, att: ModuleType, at: ModuleType, world: _World
    ) -> None:
        """Another upload stored while this one streamed fills the quota: the check
        under the org lock refuses it (storage_quota_exceeded), the other one stays."""
        db = world.db
        db.add_org(ORG_ID, storage_quota_bytes=100)
        others: list[uuid.UUID] = []

        def parallel_upload() -> None:
            others.append(
                db.add_attachment(world.chat, filename="p.txt", kind="txt", size_bytes=70)
            )

        body = _Body([b"a" * 20, b"b" * 20], hooks={2: parallel_upload})

        with pytest.raises(at.AttachmentRefusedError) as caught:
            await _upload(att, world, body, filename="a.txt", declared=40)

        assert caught.value.reason == "storage_quota_exceeded"
        assert [label for label, in_tx in _labels(db) if in_tx] == ["A2", "A3", "A4"]
        assert _stored(world) == ([str(others[0])], 0, [])

    async def test_attachments_upload_derived_bytes_stored_while_streaming_are_refused(
        self, att: ModuleType, at: ModuleType, world: _World
    ) -> None:
        """GH-188 (contract 12.4): quota 100, a 10-byte file being converted. A 40-byte
        upload passes the pre-check (50); while it streams the conversion finishes and
        stores 55 derived bytes. The check under the org lock (A4') counts them:
        10 + 55 + 40 > 100 is storage_quota_exceeded, rolled back, nothing stored."""
        db = world.db
        db.add_org(ORG_ID, storage_quota_bytes=100)
        converting = db.add_attachment(
            world.chat, filename="p.pdf", kind="pdf", size_bytes=10, status="processing"
        )

        def conversion_done() -> None:
            db.attachments[converting].update(
                status="ready", page_count=1, token_estimate=3, derived_bytes=55
            )

        body = _Body([b"a" * 20, b"b" * 20], hooks={2: conversion_done})

        with pytest.raises(at.AttachmentRefusedError) as caught:
            await _upload(att, world, body, filename="a.txt", declared=40)

        assert caught.value.reason == "storage_quota_exceeded"
        assert _labels(db) == [*_PRE_CHECK, ("A2", True), ("A3", True), ("A4", True)]
        assert [outcome for _, outcome in db.transactions] == ["rollback:AttachmentRefusedError"]
        assert _stored(world) == ([str(converting)], 0, [])

    async def test_attachments_upload_audit_failure_rolls_back_and_cleans_up(
        self, att: ModuleType, world: _World
    ) -> None:
        """A failed file.upload write: AuditRecordError, the row rolled back, no file."""
        world.db.fail_audit = True

        with pytest.raises(audit_events.AuditRecordError):
            await _upload(att, world, _Body([_MARKDOWN]), declared=len(_MARKDOWN))

        assert [outcome for _, outcome in world.db.transactions] == ["rollback:AuditRecordError"]
        assert _stored(world) == ([], 0, [])

    async def test_attachments_upload_failed_rename_stores_no_row(
        self, att: ModuleType, at: ModuleType, world: _World, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """os.replace(<id>.part, <id>) runs before the commit: when it fails the upload is
        storage_unavailable and the transaction rolls back (no row, no event, no file)."""
        real_replace = os.replace

        def failing_replace(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
            if os.fspath(src).endswith(".part"):
                raise PermissionError(13, "Permission denied", os.fspath(src))
            real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", failing_replace)

        with pytest.raises(at.AttachmentRefusedError) as caught:
            await _upload(att, world, _Body([_MARKDOWN]), declared=len(_MARKDOWN))

        assert caught.value.reason == "storage_unavailable"
        assert [outcome.split(":")[0] for _, outcome in world.db.transactions] == ["rollback"]
        assert _stored(world) == ([], 0, [])

    async def test_attachments_upload_oserror_while_detecting_is_unavailable(
        self,
        att: ModuleType,
        at: ModuleType,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Reading the partial file back fails (a disk error): storage_unavailable, the
        partial file removed, nothing stored."""

        def unreadable(path: Path, filename: str) -> Any:
            raise OSError(5, "Input/output error", os.fspath(path))

        _patch_both(monkeypatch, att, at, "detect_kind", unreadable)

        with pytest.raises(at.AttachmentRefusedError) as caught:
            await _upload(att, world, _Body([_MARKDOWN]), declared=len(_MARKDOWN))

        assert caught.value.reason == "storage_unavailable"
        assert _stored(world) == ([], 0, [])

    @pytest.mark.parametrize("blocked", ["root", "org-directory"])
    async def test_attachments_upload_unusable_storage_is_unavailable(
        self, att: ModuleType, at: ModuleType, world: _World, blocked: str
    ) -> None:
        """The root, or the org's directory, is a regular file: storage_unavailable, no
        row, no event, and the file in the way is left as it was."""
        in_the_way = world.root if blocked == "root" else world.root / str(ORG_ID)
        in_the_way.parent.mkdir(parents=True, exist_ok=True)
        in_the_way.write_bytes(b"not a directory")

        with pytest.raises(at.AttachmentRefusedError) as caught:
            await _upload(att, world, _Body([_MARKDOWN]), declared=len(_MARKDOWN))

        assert caught.value.reason == "storage_unavailable"
        assert sorted(str(row_id) for row_id in world.db.attachments) == []
        assert world.db.audit_rows("file.upload") == []
        assert in_the_way.read_bytes() == b"not a directory"

    async def test_attachments_upload_never_follows_a_planted_part_symlink(
        self,
        att: ModuleType,
        at: ModuleType,
        world: _World,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The partial file is created exclusively without following a symlink: a link
        planted at <id>.part makes the upload storage_unavailable, and the link's
        target outside the root keeps its content."""
        target = tmp_path / "outside.txt"
        target.write_bytes(b"keep")
        org_dir = world.root / str(ORG_ID)
        org_dir.mkdir(parents=True, mode=0o700)
        (org_dir / f"{_FIXED_ID}.part").symlink_to(target)
        _patch_both(monkeypatch, att, uuid, "uuid4", lambda: _FIXED_ID)

        with pytest.raises(at.AttachmentRefusedError) as caught:
            await _upload(att, world, _Body([_MARKDOWN]), declared=len(_MARKDOWN))

        assert caught.value.reason == "storage_unavailable"
        assert target.read_bytes() == b"keep"
        assert sorted(str(row_id) for row_id in world.db.attachments) == []


# ---------------------------------------------------------------------------
# 5. Logs
# ---------------------------------------------------------------------------


class TestAttachmentsUploadLogs:
    """No filename, file content or path reaches a log record."""

    @pytest.mark.parametrize(
        "outcome", ["stored", "content_length_mismatch", "unsupported_type", "storage_unavailable"]
    )
    async def test_attachments_upload_logs_no_name_content_or_path(
        self, att: ModuleType, world: _World, tmp_path: Path, outcome: str
    ) -> None:
        data = _CONTENT_MARKER.encode() + b" quarterly numbers\n"
        declared = len(data)
        if outcome == "content_length_mismatch":
            declared = len(data) + 5
        elif outcome == "unsupported_type":
            data = _CONTENT_MARKER.encode() + bytes(16)
            declared = len(data)
        elif outcome == "storage_unavailable":
            world.root.write_bytes(b"not a directory")

        with configured_logging("DEBUG", "json") as logs:
            try:
                await _upload(att, world, _Body([data]), filename=_NAME_MARKER, declared=declared)
            except Exception as exc:
                result = getattr(exc, "reason", type(exc).__name__)
            else:
                result = "stored"
            text = _log_text(logs)

        assert result == outcome
        assert _NAME_MARKER not in text
        assert _CONTENT_MARKER not in text
        assert str(tmp_path) not in text


# ---------------------------------------------------------------------------
# 6. get_attachment
# ---------------------------------------------------------------------------


class TestAttachmentsGet:
    """The caller's live attachment, or one identical not-found error."""

    async def test_attachments_get_returns_the_callers_live_attachment(
        self, att: ModuleType, world: _World
    ) -> None:
        db = world.db
        attachment = db.add_attachment(
            world.chat,
            filename="q3.xlsx",
            kind="xlsx",
            size_bytes=1234,
            status="failed",
            failure_reason="corrupted_file",
        )
        row = db.attachment_row(attachment)
        assert row is not None

        record = await att.get_attachment(db.pool, world.tenant, attachment)

        assert record.model_dump() == {column: row[column] for column in _R_COLUMNS}
        assert [(_label(call), call.args) for call in db.calls] == [
            ("A6", (attachment, ORG_ID, world.member))
        ]

    async def test_attachments_get_returns_a_ready_files_page_count_and_token_estimate(
        self, att: ModuleType, world: _World
    ) -> None:
        """GH-188: a converted file's estimate (and page count) come back with it."""
        db = world.db
        attachment = db.add_attachment(
            world.chat,
            filename="Bericht.pdf",
            kind="pdf",
            size_bytes=4096,
            status="ready",
            page_count=3,
            token_estimate=4195,
        )

        record = await att.get_attachment(db.pool, world.tenant, attachment)

        assert (record.status, record.page_count, record.token_estimate) == ("ready", 3, 4195)

    @staticmethod
    def _foreign(world: _World, kind: str) -> uuid.UUID:
        db = world.db
        if kind == "other-org":
            return db.add_attachment(db.add_chat(world.outsider))
        if kind == "colleague":
            return db.add_attachment(db.add_chat(world.colleague))
        if kind == "trashed":
            return db.add_attachment(world.chat, deleted_at=_NOW)
        return _UNKNOWN_ID

    @pytest.mark.parametrize("kind", ["other-org", "colleague", "trashed", "unknown"])
    async def test_attachments_get_anything_else_is_not_found(
        self, att: ModuleType, world: _World, kind: str
    ) -> None:
        attachment = self._foreign(world, kind)

        with pytest.raises(att.AttachmentNotFoundError) as caught:
            await att.get_attachment(world.db.pool, world.tenant, attachment)

        text = str(caught.value)
        assert str(attachment) not in text
        assert attachment.hex not in text

    async def test_attachments_get_not_found_message_is_identical(
        self, att: ModuleType, world: _World
    ) -> None:
        """Nothing tells another org's file from a colleague's, a trashed or no file."""
        messages = set()
        for kind in ("other-org", "colleague", "trashed", "unknown"):
            with pytest.raises(att.AttachmentNotFoundError) as caught:
                await att.get_attachment(world.db.pool, world.tenant, self._foreign(world, kind))
            messages.add(str(caught.value))

        assert len(messages) == 1


# ---------------------------------------------------------------------------
# 7. org_storage
# ---------------------------------------------------------------------------


class TestAttachmentsOrgStorage:
    """(file_count, used_bytes) of one org, as ints."""

    async def test_attachments_org_storage_counts_every_file_of_the_org(
        self, att: ModuleType, world: _World
    ) -> None:
        """Live, trashed and a colleague's file count; another org's don't; the NUMERIC
        sum comes back as an int."""
        db = world.db
        db.add_attachment(world.chat, size_bytes=10)
        db.add_attachment(world.chat, size_bytes=20, deleted_at=_NOW)
        db.add_attachment(db.add_chat(world.colleague), size_bytes=5)
        db.add_attachment(db.add_chat(world.outsider), size_bytes=1000)

        result = await att.org_storage(db.pool, ORG_ID)

        assert (result, [type(value) for value in result]) == ((3, 35), [int, int])
        assert [(_label(call), call.args) for call in db.calls] == [("A7", (ORG_ID,))]

    async def test_attachments_org_storage_counts_derived_bytes_null_as_zero(
        self, att: ModuleType, world: _World
    ) -> None:
        """GH-188 (contract 12.4, A7'): used_bytes is the originals plus the derived bytes
        of every file of the org (a NULL counts 0, the row's size still counts; trashed
        and colleagues' files too); another org's derived bytes don't count."""
        db = world.db
        db.add_attachment(world.chat, size_bytes=10)
        db.add_attachment(
            world.chat,
            size_bytes=20,
            status="ready",
            page_count=2,
            token_estimate=9,
            derived_bytes=300,
        )
        db.add_attachment(world.chat, size_bytes=5, derived_bytes=7, deleted_at=_NOW)
        db.add_attachment(db.add_chat(world.colleague), size_bytes=1, derived_bytes=0)
        db.add_attachment(db.add_chat(world.outsider), size_bytes=1000, derived_bytes=5000)

        result = await att.org_storage(db.pool, ORG_ID)

        assert (result, [type(value) for value in result]) == ((4, 343), [int, int])
        assert [(_label(call), call.args) for call in db.calls] == [("A7", (ORG_ID,))]

    async def test_attachments_org_storage_is_zero_without_files(
        self, att: ModuleType, world: _World
    ) -> None:
        db = world.db
        db.add_attachment(db.add_chat(world.outsider), size_bytes=1000)

        result = await att.org_storage(db.pool, ORG_ID)

        assert (result, [type(value) for value in result]) == ((0, 0), [int, int])


# ---------------------------------------------------------------------------
# 8. check_sendable
# ---------------------------------------------------------------------------


class TestAttachmentsCheckSendable:
    """Every id must be the caller's live, unsent attachment of this chat."""

    async def test_attachments_check_sendable_without_ids_runs_no_statement(
        self, att: ModuleType, world: _World
    ) -> None:
        result = await att.check_sendable(world.db.pool, world.tenant, world.chat, [])

        assert (result, world.db.calls) == (None, [])

    async def test_attachments_check_sendable_accepts_the_callers_unsent_files(
        self, att: ModuleType, world: _World
    ) -> None:
        db = world.db
        ids = [db.add_attachment(world.chat), db.add_attachment(world.chat)]

        result = await att.check_sendable(db.pool, world.tenant, world.chat, ids)

        assert result is None
        assert [_label(call) for call in db.calls] == ["A8"]
        assert set(db.calls[0].args[0]) == set(ids)
        assert db.calls[0].args[1:] == (world.chat, ORG_ID, world.member)

    @pytest.mark.parametrize("kind", ["other-chat", "other-org", "colleague", "trashed", "unknown"])
    async def test_attachments_check_sendable_missing_id_is_not_found(
        self, att: ModuleType, world: _World, kind: str
    ) -> None:
        """Next to one fine id: another of the caller's chats, another org's, a
        colleague's, a trashed or an unknown attachment."""
        db = world.db
        fine = db.add_attachment(world.chat)
        missing = {
            "other-chat": lambda: db.add_attachment(db.add_chat(world.member)),
            "other-org": lambda: db.add_attachment(db.add_chat(world.outsider)),
            "colleague": lambda: db.add_attachment(db.add_chat(world.colleague)),
            "trashed": lambda: db.add_attachment(world.chat, deleted_at=_NOW),
            "unknown": lambda: _UNKNOWN_ID,
        }[kind]()

        with pytest.raises(att.AttachmentNotFoundError):
            await att.check_sendable(db.pool, world.tenant, world.chat, [fine, missing])

    async def test_attachments_check_sendable_not_found_wins_over_already_sent(
        self, att: ModuleType, world: _World
    ) -> None:
        db = world.db
        message = db.add_chat_message(world.chat, "user", "See the file")
        sent = db.add_attachment(world.chat, message_id=message)

        with pytest.raises(att.AttachmentNotFoundError):
            await att.check_sendable(db.pool, world.tenant, world.chat, [sent, _UNKNOWN_ID])

    async def test_attachments_check_sendable_already_sent_is_refused(
        self, att: ModuleType, world: _World
    ) -> None:
        """A file another message carried can't be sent again; the error names no id."""
        db = world.db
        message = db.add_chat_message(world.chat, "user", "See the file")
        sent = db.add_attachment(world.chat, message_id=message)
        fine = db.add_attachment(world.chat)

        with pytest.raises(att.AttachmentAlreadySentError) as caught:
            await att.check_sendable(db.pool, world.tenant, world.chat, [fine, sent])

        assert str(sent) not in str(caught.value)


# ---------------------------------------------------------------------------
# 9. remove_files
# ---------------------------------------------------------------------------


def _make_entries(root: Path, org_id: uuid.UUID, attachment_id: uuid.UUID) -> None:
    """<id>, <id>.part and an <id>.d tree with a nested file."""
    org_dir = root / str(org_id)
    org_dir.mkdir(parents=True, exist_ok=True)
    (org_dir / str(attachment_id)).write_bytes(b"original")
    (org_dir / f"{attachment_id}.part").write_bytes(b"partial")
    derived = org_dir / f"{attachment_id}.d" / "pages"
    derived.mkdir(parents=True)
    (derived / "1.txt").write_bytes(b"page one")


def _names_under(directory: Path) -> list[str]:
    return sorted(str(p.relative_to(directory)) for p in directory.rglob("*"))


class TestAttachmentsRemoveFiles:
    """Removing an attachment's files never reaches outside root/<org>."""

    async def test_attachments_remove_files_removes_the_three_entries_of_each_id(
        self, att: ModuleType, tmp_path: Path
    ) -> None:
        """Two ids: six entries removed (a tree counts once); a kept id of the same org
        and the same names in another org's directory stay."""
        root = tmp_path / "attachments"
        doomed = [uuid.uuid4(), uuid.uuid4()]
        kept = uuid.uuid4()
        for attachment_id in [*doomed, kept]:
            _make_entries(root, ORG_ID, attachment_id)
        for attachment_id in doomed:
            _make_entries(root, OTHER_ORG_ID, attachment_id)
        other_before = _names_under(root / str(OTHER_ORG_ID))

        removed = await att.remove_files(root, ORG_ID, doomed)

        assert removed == 6
        assert sorted(p.name for p in (root / str(ORG_ID)).iterdir()) == sorted(
            [str(kept), f"{kept}.part", f"{kept}.d"]
        )
        assert _names_under(root / str(OTHER_ORG_ID)) == other_before

    async def test_attachments_remove_files_unlinks_symlinks_without_following(
        self, att: ModuleType, tmp_path: Path
    ) -> None:
        """<id> linking to a file, <id>.d linking to a directory outside the root, and a
        link inside a real <id>.d tree: every link goes, every target (and the outside
        directory's content) survives."""
        root = tmp_path / "attachments"
        org_dir = root / str(ORG_ID)
        org_dir.mkdir(parents=True)
        outside_file = tmp_path / "outside.txt"
        outside_file.write_bytes(b"keep")
        outside_dir = tmp_path / "outside-dir"
        outside_dir.mkdir()
        (outside_dir / "inner.txt").write_bytes(b"keep too")
        attachment_id = uuid.uuid4()
        (org_dir / str(attachment_id)).symlink_to(outside_file)
        (org_dir / f"{attachment_id}.d").symlink_to(outside_dir, target_is_directory=True)
        nested = uuid.uuid4()
        tree = org_dir / f"{nested}.d" / "pages"
        tree.mkdir(parents=True)
        (tree / "escape").symlink_to(outside_dir, target_is_directory=True)

        removed = await att.remove_files(root, ORG_ID, [attachment_id, nested])

        assert removed == 3
        assert list(org_dir.iterdir()) == []
        assert outside_file.read_bytes() == b"keep"
        assert (outside_dir / "inner.txt").read_bytes() == b"keep too"

    async def test_attachments_remove_files_missing_entries_are_fine(
        self, att: ModuleType, tmp_path: Path
    ) -> None:
        """No file for the id, or no org directory at all: nothing removed, no error."""
        root = tmp_path / "attachments"
        (root / str(ORG_ID)).mkdir(parents=True)

        counts = [
            await att.remove_files(root, ORG_ID, [uuid.uuid4()]),
            await att.remove_files(root, OTHER_ORG_ID, [uuid.uuid4()]),
            await att.remove_files(root, ORG_ID, []),
        ]

        assert counts == [0, 0, 0]

    async def test_attachments_remove_files_logs_an_oserror_by_class_and_continues(
        self, att: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An entry that can't be removed: not raised, logged as its class name only
        (no path, no traceback), and the other entries are still removed."""
        root = tmp_path / "attachments"
        stuck = uuid.uuid4()
        other = uuid.uuid4()
        org_dir = root / str(ORG_ID)
        org_dir.mkdir(parents=True)
        (org_dir / str(stuck)).write_bytes(b"stuck")
        (org_dir / str(other)).write_bytes(b"other")
        (org_dir / f"{other}.part").write_bytes(b"partial")
        real_unlink = os.unlink

        def refusing_unlink(path: Any, *args: Any, **kwargs: Any) -> None:
            if os.path.basename(os.fspath(path)) == str(stuck):
                raise PermissionError(13, "Permission denied", os.fspath(path))
            real_unlink(path, *args, **kwargs)

        monkeypatch.setattr(os, "unlink", refusing_unlink)
        monkeypatch.setattr(os, "remove", refusing_unlink)

        with configured_logging("DEBUG", "json") as logs:
            removed = await att.remove_files(root, ORG_ID, [stuck, other])
            text = _log_text(logs)
            mentions = [r for r in logs.records if "PermissionError" in r.getMessage()]

        assert removed == 2
        assert sorted(p.name for p in org_dir.iterdir()) == [str(stuck)]
        assert mentions
        assert all(record.exc_info is None for record in logs.records)
        assert str(tmp_path) not in text
