"""HTTP spec of the attachment routes (GH-187, contract sections 3.2, 3.3, 4 and 6).

``POST /api/chats/{chat_id}/attachments`` (one file as the raw request body),
``GET /api/attachments/{attachment_id}`` (metadata) and
``GET /api/attachments/{attachment_id}/content`` (the stored original). The app
from ``create_app()`` (a stub agent) runs against the FakeDb world of
tests/tenancy_world.py (orgs A and B with an Org Admin, an Editor and a Viewer
each, plus a Super Admin, all with real session cookies), with both orgs given a
storage quota and ``organizations.ATTACHMENTS_ROOT`` pointing into ``tmp_path``.
The real ``admino.attachments``, ``admino.attachment_types``, ``admino.chats``
and ``admino.audit_events`` run; ``server._processing`` is replaced (after
``create_app``) by a recorder of its ``submit(...)`` calls.

What these tests pin down:
- Upload success, for each of the nine kinds: 201 with exactly an
  ``AttachmentSummary`` (status ``uploaded``, ``token_estimate`` null (GH-188),
  ``active`` true and ``context_report`` null (GH-190), the kind detected from the
  bytes,
  never from the lying ``Content-Type`` sent, the sanitized filename: path
  traversal, NFD, zero-width, CR/LF and bidi overrides in the header), the row
  of the caller's org and owner, the file at ``<root>/<org_id>/<id>`` (bytes
  equal, mode 0600 in a 0700 directory, no ``.part`` left, the name only in the
  DB), exactly one content-free ``file.upload`` audit row (member actor,
  ``file`` target, ``{"size_bytes": n}``, the client IP) and exactly one
  ``submit(pool, root, id, org_id)`` once the row and the file exist.
- Every refusal of contract section 4 with its status and exact body
  ``{"detail": <fixed text>, "reason": <code>}`` (404s use the chat routes'
  ``chat_not_found`` body), nothing stored (no row, no file, no ``.part``, no
  audit row) and no submit: ``invalid_filename`` (missing header, ``%FF``, raw
  non-ASCII, only dots, over 4096 characters), 411 ``content_length_required``
  (none, chunked, non-numeric, negative, 19 digits), ``empty_file``,
  ``file_too_large`` (``max_file_size_mb`` counts MiB: exactly 1 MiB passes, one
  byte more doesn't), ``chat_not_found`` (another org's, a colleague's, a
  trashed, an unknown chat: one body), ``storage_quota_exceeded`` (used plus
  declared over the quota; an exact fit passes; every row of the org counts),
  ``content_length_mismatch`` both ways, the detection codes with spoofed names
  (415 ``unsupported_type`` / ``legacy_office``, 422 ``password_protected`` /
  ``corrupted_file``), the commit-time 404 and 413 (the chat trashed, the quota
  taken while the body streams) and 503 ``storage_unavailable``.
- "Before any body byte is read", with raw ASGI calls whose ``receive`` counts
  what it hands out: steps 1 to 8 never ask ``receive`` for a body message; a
  body longer than its ``Content-Length`` is not read past the first chunk that
  passes it; a short body and a client disconnect store nothing.
- Order: 429 before the header check, the header before ``Content-Length``,
  every ``Content-Length`` check before any statement (an unknown chat
  included; the session lookup and a platform settings read aside), the chat
  404 before any quota statement.
- Section 5: 401 without a session; a Viewer and the Super Admin 403 before any
  statement (the upload spends no bucket); a cross-origin POST is the CSRF 403;
  per-user buckets: the upload's burst is the platform ``max_files_per_message``
  (refill 0.5/s), the GET routes have ``/api/attachments/get`` (5.0, 50) and
  ``/api/attachments/content/get`` (2.0, 30); the routes declare their response
  models.
- Metadata and download: the owner's live attachment only (GH-188: a ready row
  answers its ``token_estimate``, a failed one null; GH-190: ``active`` true and, for
  a file not refused for the context, ``context_report`` null); another org's, a
  colleague's (an Org Admin included), a trashed and an unknown attachment, and
  a row whose file is gone (or is a directory, not a regular file: regression
  guard), are one 404 ``attachment_not_found``; a non-UUID id
  is 422 like the chat routes. Downloads: the stored bytes, ``Content-Type`` per
  kind (text kinds with ``charset=utf-8``), ``Content-Disposition`` exactly
  ``attachment; filename*=UTF-8''`` plus the percent-encoded download name (the
  kind's extension appended when the stored one doesn't fit), ``Cache-Control:
  no-store``, ``X-Content-Type-Options: nosniff``; any status downloads.
- Logs: across uploads, refusals and a download, no record carries the
  filename, the raw header or the content (the success line carries the id).
- GH-281 (Decision 6, contract G1 to G6), download ``Range`` errors: a ``Range`` the
  file response would reject (malformed: no ``=``, another unit, no valid range, a
  start after the end; unsatisfiable: a start at or past the size) is the 416 JSON
  body ``{"detail": "Range not satisfiable", "reason": "range_not_satisfiable"}``
  with ``Content-Range: bytes */<size>``, never Starlette's plain-text 400/416, also
  when a matching ``If-Range`` (the ETag or Last-Modified) makes the Range apply; the
  body never echoes the header. The route's OpenAPI responses document the 416 with
  that body as its example. Regression guards: valid single and multiple ranges stay
  206; a stale ``If-Range`` still means the whole file (200), whatever the Range; the
  rate limit, then the ownership 404 (another org's, a colleague's, a trashed, an
  unknown attachment, a row whose file is gone) come before the Range, with no
  ``Content-Range``.
- GH-281 audit fix round 1 (Decision 11, contract G7): when the Range applies (no
  ``If-Range`` or a matching one), a header longer than ``server._MAX_RANGE_HEADER_CHARS``
  (1,024) characters, or one served as more than ``server._MAX_RANGES`` (16) parts once
  overlapping ranges are merged, is the same 416 (same body, ``Content-Range: bytes
  */<size>``, never an echo). Both limits are read at call time; the OpenAPI 416
  description names them. Regression guards: 16 separate ranges are the 206 multipart,
  a header of exactly 1,024 characters is served, a stale ``If-Range`` still means the
  whole file and the ownership 404 comes first. Overlapping ranges count once (folded
  into a RED test: 17 ranges merging into 16 parts, or 40 into one, are served).
- GH-281 audit fix round 1 (Decision 12, contract A10): an upload into a missing
  attachments root creates it with mode 0700 (its missing parents keep the default
  mode; the org directory 0700 and the file 0600 as before), under a umask of 022; an
  existing root's mode is left alone (regression guard).

New modules are imported inside the tests, so the file collects before they
exist. No network, no real PostgreSQL, no LLM; files only under ``tmp_path``.

Security notes: emails and session tokens are fixed fake values from the
world; the markers are fake content, never secrets.
"""

from __future__ import annotations

import asyncio
import inspect
import io
import json
import os
import re
import stat
import struct
import uuid
import zipfile
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import organizations, scoped_settings, server
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb
from tests.log_capture import configured_logging
from tests.tenancy_world import (
    CLIENT_IP,
    FORBIDDEN,
    UNAUTHORIZED,
    build_world,
    make_app,
    make_client,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence

    import httpx
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from starlette.types import Message

    from tests.tenancy_world import Account, MemberRole, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MIB: Final = 1_048_576
_QUOTA: Final = 64 * _MIB

_UPLOAD_KEY: Final = "/api/chats/attachments/create"
_GET_KEY: Final = "/api/attachments/get"
_CONTENT_KEY: Final = "/api/attachments/content/get"

_CHAT_NOT_FOUND: Final = {"detail": "Chat not found", "reason": "chat_not_found"}
_ATTACHMENT_NOT_FOUND: Final = {"detail": "Attachment not found", "reason": "attachment_not_found"}
_CSRF_REFUSED: Final = {"detail": "Cross-origin request refused"}
_RATE_LIMITED: Final = {"detail": "Rate limit exceeded"}

_FOREIGN_ORIGIN: Final = "https://evil.example"
# TestClient sends ``Host: testserver``: an Origin with that host is same-origin.
_SAME_ORIGIN: Final = "http://testserver"

# The contract's fixed refusal texts (section 3.2) and their statuses (section 4).
_DETAILS: Final[dict[str, str]] = {
    "invalid_filename": "Invalid attachment name",
    "content_length_required": "Content-Length is required",
    "empty_file": "The file is empty",
    "content_length_mismatch": "The body doesn't match Content-Length",
    "file_too_large": "The file is too large",
    "storage_quota_exceeded": "The organization's storage quota is full",
    "unsupported_type": "This file type isn't supported",
    "legacy_office": "Legacy Office files aren't supported: save as .docx or .xlsx",
    "password_protected": "The file is password-protected",
    "corrupted_file": "The file is corrupted",
    "storage_unavailable": "Attachment storage is unavailable",
}
_STATUS: Final[dict[str, int]] = {
    "invalid_filename": 400,
    "content_length_required": 411,
    "empty_file": 400,
    "content_length_mismatch": 400,
    "file_too_large": 413,
    "storage_quota_exceeded": 413,
    "unsupported_type": 415,
    "legacy_office": 415,
    "password_protected": 422,
    "corrupted_file": 422,
    "storage_unavailable": 503,
}

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
        # GH-190: whether the file is in later turns' slot, and the report of a file
        # refused for the context (null otherwise).
        "active",
        "context_report",
        "created_at",
    }
)
_MEDIA_TYPES: Final[dict[str, str]] = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "csv": "text/csv; charset=utf-8",
    "txt": "text/plain; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
    "png": "image/png",
    "jpeg": "image/jpeg",
    "webp": "image/webp",
}

# A statement of the session lookup (every authenticated request runs it) or a read of
# the platform settings (the file limits; normally answered from the primed cache).
_NOT_WORK_SQL: Final = re.compile(r"\b(?:sessions|platform_settings)\b")
# A statement of the quota check (A1, A3, A4).
_QUOTA_SQL: Final = re.compile(r"storage_quota_bytes|sum\(size_bytes\)")

# Characters built with chr() so they survive editing tools verbatim.
_E_ACUTE: Final = chr(0xE9)
_RESUME: Final = f"R{_E_ACUTE}sum{_E_ACUTE} Q3.pdf"

# Markers that must never reach a log record.
_LOG_NAME: Final = "Quokkabudget Geheim 187.txt"
_LOG_HEADER: Final = "Quokkabudget%20Geheim%20187.txt"
_LOG_CONTENT: Final = b"Wombatledger 187 Mandantenliste\n"

_TEXT: Final = b"Termin am Montag um neun.\n"

# ---------------------------------------------------------------------------
# Fixture files (built in memory, stdlib only)
# ---------------------------------------------------------------------------

_PDF_HEAD: Final = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
_PNG_SIGNATURE: Final = b"\x89PNG\r\n\x1a\n"
_JPEG_HEAD: Final = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
_CFB_MAGIC: Final = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
# A Windows executable's first bytes (DOS header with NULs, then the PE signature).
_EXE: Final = (
    b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + bytes(44) + b"PE\x00\x00"
)
_DOCX_NAMES: Final = ("[Content_Types].xml", "_rels/.rels", "word/document.xml")
_XLSX_NAMES: Final = ("[Content_Types].xml", "_rels/.rels", "xl/workbook.xml")


def _pdf(trailer: bytes = b"/Root 1 0 R") -> bytes:
    return _PDF_HEAD + b"trailer\n<< " + trailer + b" >>\nstartxref\n9\n%%EOF\n"


def _png(chunk_type: bytes = b"IHDR") -> bytes:
    """The PNG signature, one 13-byte header chunk (``chunk_type``) and IEND."""
    data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    header = struct.pack(">I", len(data)) + chunk_type + data
    header += struct.pack(">I", zlib.crc32(chunk_type + data))
    iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND"))
    return _PNG_SIGNATURE + header + iend


def _jpeg() -> bytes:
    return _JPEG_HEAD + bytes(16) + b"\xff\xd9"


def _webp() -> bytes:
    body = b"WEBP" + b"VP8L" + struct.pack("<I", 6) + b"\x2f\x00\x00\x00\x00\x00"
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _zip(names: Sequence[str], *, encrypted: str | None = None) -> bytes:
    """A ZIP of ``names``; ``encrypted`` gets flag bit 0 in the central directory."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in names:
            archive.writestr(name, "<x>" + name + "</x>")
        if encrypted is not None:
            # zipfile resets flag_bits while writing an entry; the central directory
            # is written at close() from the ZipInfo, so set it here.
            archive.getinfo(encrypted).flag_bits |= 0x1
    return buffer.getvalue()


def _cfb(*names: str) -> bytes:
    """An OLE/CFB file: header sector, then one directory sector with ``names``."""
    header = (_CFB_MAGIC + bytes(16) + b"\x3e\x00\x03\x00\xfe\xff\x09\x00").ljust(512, b"\x00")
    entries = b"".join(name.encode("utf-16-le").ljust(64, b"\x00") + bytes(64) for name in names)
    return header + entries.ljust(1024, b"\x00")


# kind -> (a name with one of its extensions, the bytes, a Content-Type that lies).
_KIND_FILES: Final[dict[str, tuple[str, bytes, str]]] = {
    "pdf": ("Jahresbericht.pdf", _pdf(), "image/png"),
    "docx": ("Vertrag.docx", _zip(_DOCX_NAMES), "application/pdf"),
    "xlsx": ("Budget.xlsx", _zip(_XLSX_NAMES), "text/csv"),
    "csv": ("Zahlen.csv", b"name,amount\nAlpha,12\nBeta,7\n", "text/markdown"),
    "txt": ("Notizen.txt", _TEXT, "text/csv"),
    "md": ("Agenda.markdown", b"# Agenda\n\n- Budget\n", "text/plain"),
    "png": ("Scan.png", _png(), "application/pdf"),
    "jpeg": ("Foto.jpeg", _jpeg(), "image/webp"),
    "webp": ("Bild.webp", _webp(), "image/jpeg"),
}
_KINDS: Final = list(_KIND_FILES)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _submit_signature(pool: Any, root: Any, attachment_id: Any, org_id: Any) -> None:
    """The parameters of the contract's ``ProcessingPool.submit`` (names a recorded call)."""


@dataclass
class _Processing:
    """Stands in for ``server._processing``: records each ``submit(pool, root, id, org)``
    and whether the attachment's row and final file existed at that moment."""

    db: FakeDb
    calls: list[tuple[Any, Any, Any, Any]] = field(default_factory=list)
    stored_at_submit: list[tuple[bool, bool]] = field(default_factory=list)

    def submit(self, *args: Any, **kwargs: Any) -> None:
        bound = inspect.signature(_submit_signature).bind(*args, **kwargs).arguments
        call = (bound["pool"], bound["root"], bound["attachment_id"], bound["org_id"])
        self.calls.append(call)
        attachment_id = uuid.UUID(str(call[2]))
        final = Path(call[1]) / str(call[3]) / str(attachment_id)
        row = self.db.attachment_row(attachment_id)
        self.stored_at_submit.append((row is not None, final.is_file()))

    async def join(self) -> None:
        return None

    async def close(self) -> None:
        return None


@dataclass(frozen=True)
class _Env:
    """The world, the attachment root, the app and its client, the submit recorder and
    the rate limits as they were before the roomy override."""

    world: World
    root: Path
    app: FastAPI
    client: TestClient
    processing: _Processing
    original_limits: dict[str, tuple[float, int]]
    original_default: tuple[float, int]


@pytest.fixture()
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> _Env:
    """Orgs A and B (OA/ED/VI each, a 64 MiB storage quota) and a Super Admin behind the
    fake database; the attachment root in tmp_path; every rate-limit bucket roomy."""
    db = FakeDb()
    world = build_world(db)
    for org_id in (ORG_ID, OTHER_ORG_ID):
        db.add_org(org_id, storage_quota_bytes=_QUOTA)
    original_limits = dict(server._RATE_LIMITS)
    original_default = server._DEFAULT_RATE_LIMIT
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    root = tmp_path / "attachments"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", root)
    app = make_app()
    processing = _Processing(db)
    # After create_app (it installs a fresh pool); routes look it up at call time.
    monkeypatch.setattr(server, "_processing", processing, raising=False)
    return _Env(
        world=world,
        root=root,
        app=app,
        client=make_client(app),
        processing=processing,
        original_limits=original_limits,
        original_default=original_default,
    )


@pytest.fixture()
def umask_022() -> Iterator[None]:
    """A process umask of 022 for the test (a directory made with the default mode is
    then 0755), restored afterwards."""
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _set_files(env: _Env, monkeypatch: pytest.MonkeyPatch, **files: int) -> None:
    """Store platform file limits in the platform row and in the primed settings cache."""
    row = env.world.db.platform_row()
    assert row is not None
    row.update(files)
    stored = scoped_settings._platform_cache
    assert stored is not None
    updated = stored.model_copy(update={"files": stored.files.model_copy(update=files)})
    monkeypatch.setattr(scoped_settings, "_platform_cache", updated)


def _real_upload_bucket(env: _Env, monkeypatch: pytest.MonkeyPatch) -> None:
    """Undo the roomy override for the upload bucket (its rate and fallback)."""
    if _UPLOAD_KEY in env.original_limits:
        monkeypatch.setitem(server._RATE_LIMITS, _UPLOAD_KEY, env.original_limits[_UPLOAD_KEY])
    else:
        monkeypatch.delitem(server._RATE_LIMITS, _UPLOAD_KEY, raising=False)
    monkeypatch.setattr(server, "_DEFAULT_RATE_LIMIT", env.original_default)


def _upload_path(chat_id: uuid.UUID | str) -> str:
    return f"/api/chats/{chat_id}/attachments"


def _upload(
    client: TestClient,
    caller: Account | None,
    chat_id: uuid.UUID | str,
    data: bytes = _TEXT,
    *,
    name: str | bytes | None = "notes.txt",
    content_type: str = "application/octet-stream",
    length: str | None = None,
    origin: str | None = None,
) -> httpx.Response:
    """POST the raw body; ``length`` replaces the Content-Length httpx would send."""
    headers: dict[str, str | bytes] = dict(caller.cookie) if caller is not None else {}
    if name is not None:
        headers["X-Attachment-Name"] = name
    headers["Content-Type"] = content_type
    if length is not None:
        headers["Content-Length"] = length
    if origin is not None:
        headers["Origin"] = origin
    return client.post(_upload_path(chat_id), content=data, headers=headers)


def _cookie(caller: Account | None) -> dict[str, str]:
    return dict(caller.cookie) if caller is not None else {}


def _metadata(client: TestClient, caller: Account | None, attachment_id: Any) -> httpx.Response:
    return client.get(f"/api/attachments/{attachment_id}", headers=_cookie(caller))


def _content(client: TestClient, caller: Account | None, attachment_id: Any) -> httpx.Response:
    return client.get(f"/api/attachments/{attachment_id}/content", headers=_cookie(caller))


def _outcome(response: httpx.Response) -> tuple[int, Any]:
    """(status, JSON body) or (status, text) when the body isn't JSON."""
    try:
        body = response.json()
    except ValueError:
        body = response.text
    return response.status_code, body


def _refused(reason: str) -> tuple[int, dict[str, str]]:
    return _STATUS[reason], {"detail": _DETAILS[reason], "reason": reason}


def _files(root: Path) -> list[str]:
    """Every non-directory entry under ``root`` (a ``.part`` included), relative."""
    if not root.is_dir():
        return []
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_symlink() or not path.is_dir()
    )


def _state(env: _Env) -> dict[str, Any]:
    """The attachments and audit tables, the files on disk and the submits so far."""
    tables = env.world.db.snapshot()
    return {
        "attachments": tables["attachments"],
        "audit": tables["audit"],
        "files": _files(env.root),
        "submitted": list(env.processing.calls),
    }


def _work(db: FakeDb, since: int) -> list[str]:
    """The statements after the first ``since`` calls, the session lookup and a platform
    settings read left out."""
    return [
        call.normalized for call in db.calls[since:] if not _NOT_WORK_SQL.search(call.normalized)
    ]


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _seed(
    env: _Env,
    owner: Account,
    data: bytes = _TEXT,
    *,
    filename: str = "notes.txt",
    kind: str = "txt",
    status: str = "uploaded",
    failure_reason: str | None = None,
    page_count: int | None = None,
    token_estimate: int | None = None,
    trashed: bool = False,
    write: bool = True,
) -> uuid.UUID:
    """A stored attachment of ``owner`` (in a new chat of theirs) and its file on disk."""
    db = env.world.db
    deleted_at = datetime.now(UTC) if trashed else None
    chat = db.add_chat(owner.user_id, deleted_at=deleted_at)
    attachment = db.add_attachment(
        chat,
        filename=filename,
        kind=kind,
        size_bytes=len(data),
        status=status,
        failure_reason=failure_reason,
        page_count=page_count,
        token_estimate=token_estimate,
        deleted_at=deleted_at,
    )
    if write:
        assert owner.org_id is not None
        org_dir = env.root / str(owner.org_id)
        org_dir.mkdir(mode=0o700, exist_ok=True)
        (org_dir / str(attachment)).write_bytes(data)
    return attachment


def _assert_stored_upload(
    env: _Env,
    response: httpx.Response,
    caller: Account,
    chat_id: uuid.UUID,
    data: bytes,
    *,
    kind: str,
    filename: str,
) -> None:
    """The 201 summary, the row, the file, the one audit row and the one submit."""
    assert response.status_code == 201, response.text
    body = response.json()
    assert set(body) == _SUMMARY_KEYS
    attachment_id = uuid.UUID(body["id"])
    assert {key: body[key] for key in _SUMMARY_KEYS - {"id", "created_at"}} == {
        "chat_id": str(chat_id),
        "message_id": None,
        "filename": filename,
        "kind": kind,
        "size_bytes": len(data),
        "status": "uploaded",
        "failure_reason": None,
        "page_count": None,
        "token_estimate": None,
        "active": True,
        "context_report": None,
    }
    row = env.world.db.attachment_row(attachment_id)
    assert row is not None
    assert (str(row["org_id"]), str(row["owner_user_id"]), str(row["chat_id"])) == (
        str(caller.org_id),
        str(caller.user_id),
        str(chat_id),
    )
    assert (row["filename"], row["kind"], row["size_bytes"], row["status"]) == (
        filename,
        kind,
        len(data),
        "uploaded",
    )
    assert (row["message_id"], row["deleted_at"]) == (None, None)
    assert _ts(body["created_at"]) == row["created_at"]
    org_dir = env.root / str(caller.org_id)
    assert _files(env.root) == [f"{caller.org_id}/{attachment_id}"]
    stored = org_dir / str(attachment_id)
    assert stored.read_bytes() == data
    assert (stat.S_IMODE(stored.stat().st_mode), stat.S_IMODE(org_dir.stat().st_mode)) == (
        0o600,
        0o700,
    )
    audits = env.world.db.audit_rows("file.upload")
    assert len(audits) == 1
    audit = audits[0]
    assert (audit["actor_kind"], str(audit["actor_user_id"]), str(audit["org_id"])) == (
        "member",
        str(caller.user_id),
        str(caller.org_id),
    )
    assert (audit["target_type"], audit["target_ids"], audit["metadata"]) == (
        "file",
        [str(attachment_id)],
        {"size_bytes": len(data)},
    )
    assert audit["ip"] == CLIENT_IP
    assert len(env.processing.calls) == 1
    pool, root, submitted_id, org_id = env.processing.calls[0]
    assert pool is env.world.db.pool
    assert (Path(root), str(submitted_id), str(org_id)) == (
        env.root,
        str(attachment_id),
        str(caller.org_id),
    )
    assert env.processing.stored_at_submit == [(True, True)]


# ---------------------------------------------------------------------------
# Raw ASGI: a receive that counts the body messages it hands out
# ---------------------------------------------------------------------------


@dataclass
class _Wire:
    """The request body of a raw ASGI call, one message per chunk.

    ``asked`` counts every ``receive()`` call, ``handed`` the body messages
    handed out. After the last chunk it sends ``http.disconnect`` when
    ``disconnect`` is set, else it blocks (a client that sent everything).
    ``during(n)`` runs right before chunk ``n`` (1-based) is handed out.
    """

    chunks: Sequence[bytes]
    disconnect: bool = False
    during: Callable[[int], None] | None = None
    asked: int = 0
    handed: int = 0

    async def receive(self) -> Message:
        self.asked += 1
        if self.handed < len(self.chunks):
            if self.during is not None:
                self.during(self.handed + 1)
            chunk = self.chunks[self.handed]
            self.handed += 1
            more = self.disconnect or self.handed < len(self.chunks)
            return {"type": "http.request", "body": chunk, "more_body": more}
        if self.disconnect:
            return {"type": "http.disconnect"}
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


async def _raw_upload(
    app: FastAPI,
    caller: Account | None,
    chat_id: uuid.UUID,
    wire: _Wire,
    *,
    length: bytes | None,
    name: bytes | None = b"notes.txt",
) -> tuple[int | None, Any]:
    """Run one upload through the whole ASGI app; (status, JSON body or None)."""
    headers = [(b"host", b"testserver"), (b"content-type", b"application/octet-stream")]
    if caller is not None:
        headers.append((b"cookie", caller.cookie["Cookie"].encode("ascii")))
    if name is not None:
        headers.append((b"x-attachment-name", name))
    if length is not None:
        headers.append((b"content-length", length))
    path = _upload_path(chat_id)
    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "root_path": "",
        "query_string": b"",
        "headers": headers,
        "client": (CLIENT_IP, 50000),
        "server": ("testserver", 80),
        "state": {},
    }
    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    await asyncio.wait_for(app(scope, wire.receive, send), timeout=10)
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    raw = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, (json.loads(raw) if raw else None)


# ---------------------------------------------------------------------------
# 1. Access: session, role, CSRF, per-user rate limits, response models
# ---------------------------------------------------------------------------

_ROUTES: Final = ["upload", "metadata", "content"]


def _call_route(
    env: _Env, route: str, caller: Account | None, chat_id: uuid.UUID, attachment_id: uuid.UUID
) -> httpx.Response:
    if route == "upload":
        return _upload(env.client, caller, chat_id)
    if route == "metadata":
        return _metadata(env.client, caller, attachment_id)
    return _content(env.client, caller, attachment_id)


class TestAttachmentsAccess:
    """401 without a session, the role gates, CSRF, per-user buckets, response models."""

    @pytest.mark.parametrize("route", _ROUTES)
    def test_attachments_api_without_a_session_is_401_and_does_no_work(
        self, env: _Env, route: str
    ) -> None:
        editor = env.world.a["editor"]
        attachment = _seed(env, editor)
        chat = env.world.db.add_chat(editor.user_id)
        before = _state(env)
        since = len(env.world.db.calls)

        response = _call_route(env, route, None, chat, attachment)

        assert _outcome(response) == (401, UNAUTHORIZED)
        assert _work(env.world.db, since) == []
        assert _state(env) == before

    @pytest.mark.parametrize("role", ["viewer", "super_admin"])
    @pytest.mark.parametrize("route", _ROUTES)
    def test_attachments_api_viewer_and_super_admin_are_403_before_any_work(
        self, env: _Env, route: str, role: str
    ) -> None:
        """The Viewer on their own chat and attachment (from before a demotion), the
        Super Admin on an Editor's: 403, no statement, nothing stored, no upload bucket."""
        caller = env.world.super_admin if role == "super_admin" else env.world.a["viewer"]
        owner = env.world.a["viewer"] if role == "viewer" else env.world.a["editor"]
        attachment = _seed(env, owner)
        chat = env.world.db.add_chat(owner.user_id)
        before = _state(env)
        since = len(env.world.db.calls)

        response = _call_route(env, route, caller, chat, attachment)

        assert _outcome(response) == (403, FORBIDDEN)
        assert _work(env.world.db, since) == []
        assert _state(env) == before
        assert [key for key in server._rate_buckets if key[0] == _UPLOAD_KEY] == []

    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    def test_attachments_api_org_admin_and_editor_use_every_route(
        self, env: _Env, role: MemberRole
    ) -> None:
        caller = env.world.a[role]
        chat = env.world.db.add_chat(caller.user_id)

        uploaded = _upload(env.client, caller, chat, _TEXT, name="Protokoll.txt")
        assert uploaded.status_code == 201, uploaded.text
        attachment_id = uploaded.json()["id"]
        metadata = _metadata(env.client, caller, attachment_id)
        content = _content(env.client, caller, attachment_id)

        assert _outcome(metadata) == (200, uploaded.json())
        assert (content.status_code, content.content) == (200, _TEXT)

    def test_attachments_api_cross_origin_upload_is_refused_and_same_origin_succeeds(
        self, env: _Env
    ) -> None:
        """A foreign Origin is the CSRF 403 with nothing stored and no statement; the same
        upload from the app's own origin is 201 (the route exists)."""
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)
        before = _state(env)
        since = len(env.world.db.calls)

        refused = _upload(env.client, caller, chat, origin=_FOREIGN_ORIGIN)
        refused_work = _work(env.world.db, since)
        after_refusal = _state(env)
        accepted = _upload(env.client, caller, chat, origin=_SAME_ORIGIN)

        assert _outcome(refused) == (403, _CSRF_REFUSED)
        assert refused_work == []
        assert after_refusal == before
        assert accepted.status_code == 201, accepted.text

    def test_attachments_api_upload_bucket_bursts_max_files_per_message_per_user(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Platform ``max_files_per_message`` 3: the Editor's fourth upload in a burst is
        429 with nothing stored, the Org Admin still uploads; the Editor's bucket is
        (route key, "user:<id>") with rate 0.5 and burst 3."""
        _real_upload_bucket(env, monkeypatch)
        _set_files(env, monkeypatch, max_files_per_message=3)
        caller = env.world.a["editor"]
        other = env.world.a["org_admin"]
        chat = env.world.db.add_chat(caller.user_id)
        other_chat = env.world.db.add_chat(other.user_id)

        burst = [_upload(env.client, caller, chat, b"Datei %d\n" % n) for n in range(3)]
        before = _state(env)
        limited = _upload(env.client, caller, chat, b"Datei 4\n")
        after = _state(env)
        unaffected = _upload(env.client, other, other_chat, b"Andere Datei\n")

        assert [response.status_code for response in burst] == [201, 201, 201]
        assert _outcome(limited) == (429, _RATE_LIMITED)
        assert after == before
        assert unaffected.status_code == 201, unaffected.text
        bucket = server._rate_buckets[(_UPLOAD_KEY, f"user:{caller.user_id}")]
        assert (bucket._rate, bucket._capacity) == (0.5, 3)

    def test_attachments_api_read_rate_limit_keys_have_the_contract_values(self) -> None:
        expected = {_GET_KEY: (5.0, 50), _CONTENT_KEY: (2.0, 30)}

        assert {key: server._RATE_LIMITS.get(key) for key in expected} == expected

    @pytest.mark.parametrize("route", ["metadata", "content"])
    def test_attachments_api_read_routes_have_their_own_per_user_bucket(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch, route: str
    ) -> None:
        """Burst 1 on the route's key: the Editor's second read is 429, the Org Admin
        isn't throttled, the other read route isn't either; the bucket is per user."""
        key = _GET_KEY if route == "metadata" else _CONTENT_KEY
        other_route = "content" if route == "metadata" else "metadata"
        monkeypatch.setitem(server._RATE_LIMITS, key, (0.001, 1))
        caller = env.world.a["editor"]
        other = env.world.a["org_admin"]
        attachment = _seed(env, caller)
        other_attachment = _seed(env, other)
        chat = env.world.db.add_chat(caller.user_id)

        first = _call_route(env, route, caller, chat, attachment)
        limited = _call_route(env, route, caller, chat, attachment)
        other_route_response = _call_route(env, other_route, caller, chat, attachment)
        unaffected = _call_route(env, route, other, chat, other_attachment)

        assert first.status_code == 200, first.text
        assert _outcome(limited) == (429, _RATE_LIMITED)
        assert other_route_response.status_code == 200, other_route_response.text
        assert unaffected.status_code == 200, unaffected.text
        assert (key, f"user:{caller.user_id}") in server._rate_buckets

    def test_attachments_api_routes_declare_the_contract_response_models(self) -> None:
        from fastapi.routing import APIRoute

        from admino import models

        expected = {
            ("POST", "/api/chats/{chat_id}/attachments"): (models.AttachmentSummary, 201),
            ("GET", "/api/attachments/{attachment_id}"): (models.AttachmentSummary, 200),
            ("GET", "/api/attachments/{attachment_id}/content"): (None, 200),
        }
        found: dict[tuple[str, str], tuple[Any, int]] = {}
        for route in make_app().routes:
            if not isinstance(route, APIRoute):
                continue
            for method in route.methods:
                if (method, route.path) in expected:
                    found[(method, route.path)] = (route.response_model, route.status_code or 200)

        assert found == expected


# ---------------------------------------------------------------------------
# 2. Upload success
# ---------------------------------------------------------------------------


class TestAttachmentsUpload:
    """201 AttachmentSummary; row, file, audit row and one submit; type from content."""

    @pytest.mark.parametrize("kind", _KINDS)
    def test_attachments_api_upload_of_each_kind_stores_it_and_submits_it_once(
        self, env: _Env, kind: str
    ) -> None:
        """The Content-Type sent names another kind: it is ignored."""
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)
        name, data, lying_type = _KIND_FILES[kind]

        response = _upload(env.client, caller, chat, data, name=name, content_type=lying_type)

        _assert_stored_upload(env, response, caller, chat, data, kind=kind, filename=name)

    def test_attachments_api_upload_kind_comes_from_content_not_name_or_type(
        self, env: _Env
    ) -> None:
        """PNG bytes named ``scan.pdf`` and declared ``application/pdf`` are a png; the
        name is stored as given."""
        caller = env.world.a["org_admin"]
        chat = env.world.db.add_chat(caller.user_id)
        data = _png()

        response = _upload(
            env.client, caller, chat, data, name="scan.pdf", content_type="application/pdf"
        )

        _assert_stored_upload(env, response, caller, chat, data, kind="png", filename="scan.pdf")

    @pytest.mark.parametrize(
        ("header", "data", "kind", "filename"),
        [
            pytest.param(
                "..%2Fprivat%5CRe%CC%81sume%CC%81%20Q3%E2%80%8B.pdf",
                _pdf(),
                "pdf",
                _RESUME,
                id="traversal-nfd-zero-width",
            ),
            pytest.param(
                "evil%0D%0AX-Injected%3A%201.txt",
                _TEXT,
                "txt",
                "evilX-Injected: 1.txt",
                id="crlf",
            ),
            pytest.param(
                "invoice%E2%80%AEtxt.exe", _TEXT, "txt", "invoicetxt.exe", id="bidi-override"
            ),
        ],
    )
    def test_attachments_api_upload_stores_the_sanitized_filename(
        self, env: _Env, header: str, data: bytes, kind: str, filename: str
    ) -> None:
        """Hostile names in the header: percent-decoded, NFC, last path segment, controls
        and format characters removed; the name lives only in the row, the file on disk
        is named by its id."""
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)

        response = _upload(env.client, caller, chat, data, name=header)

        _assert_stored_upload(env, response, caller, chat, data, kind=kind, filename=filename)

    @pytest.mark.usefixtures("umask_022")
    def test_attachments_api_upload_creates_a_missing_root_with_mode_0700(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """GH-281 Decision 12 (A10): the root and its parent don't exist; the upload
        creates the root 0700 (the parent keeps the umask's default 0755), the org
        directory 0700 and the file 0600."""
        parent = tmp_path / "missing-parent"
        root = parent / "missing-root"
        monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", root)
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)

        response = _upload(env.client, caller, chat)

        assert response.status_code == 201, response.text
        org_dir = root / str(caller.org_id)
        stored = org_dir / response.json()["id"]
        assert (
            stored.read_bytes(),
            [stat.S_IMODE(path.stat().st_mode) for path in (parent, root, org_dir, stored)],
        ) == (_TEXT, [0o755, 0o700, 0o700, 0o600])

    @pytest.mark.usefixtures("umask_022")
    def test_attachments_api_upload_leaves_an_existing_roots_mode_alone(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Regression guard (A10): an existing root with mode 0750 keeps it; the org
        directory is 0700 and the file 0600 as before."""
        root = tmp_path / "existing-root"
        root.mkdir()
        root.chmod(0o750)
        monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", root)
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)

        response = _upload(env.client, caller, chat)

        assert response.status_code == 201, response.text
        org_dir = root / str(caller.org_id)
        stored = org_dir / response.json()["id"]
        assert (
            stored.read_bytes(),
            [stat.S_IMODE(path.stat().st_mode) for path in (root, org_dir, stored)],
        ) == (_TEXT, [0o750, 0o700, 0o600])


# ---------------------------------------------------------------------------
# 3. Upload refusals (TestClient): status, exact body, nothing stored
# ---------------------------------------------------------------------------


class TestAttachmentsUploadRefusals:
    """Each documented refusal; nothing stored, no submit, the input never echoed."""

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param(None, id="missing"),
            pytest.param("Bericht%FF.txt", id="not-utf8"),
            pytest.param(f"R{_E_ACUTE}sum{_E_ACUTE}.txt".encode(), id="raw-non-ascii"),
            pytest.param("...", id="only-dots"),
            pytest.param("a" * 4097, id="over-4096"),
        ],
    )
    def test_attachments_api_upload_invalid_filename_is_400_before_any_work(
        self, env: _Env, name: str | bytes | None
    ) -> None:
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)
        before = _state(env)
        since = len(env.world.db.calls)

        response = _upload(env.client, caller, chat, name=name)

        assert _outcome(response) == _refused("invalid_filename")
        assert _work(env.world.db, since) == []
        assert _state(env) == before

    @pytest.mark.parametrize(
        "length",
        [
            pytest.param("12a", id="non-numeric"),
            pytest.param("-5", id="negative"),
            pytest.param("1" * 19, id="19-digits"),
        ],
    )
    def test_attachments_api_upload_bad_content_length_is_411(self, env: _Env, length: str) -> None:
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)
        before = _state(env)
        since = len(env.world.db.calls)

        response = _upload(env.client, caller, chat, length=length)

        assert _outcome(response) == _refused("content_length_required")
        assert _work(env.world.db, since) == []
        assert _state(env) == before

    @pytest.mark.parametrize("mode", ["header-removed", "chunked"])
    def test_attachments_api_upload_without_content_length_is_411(
        self, env: _Env, mode: str
    ) -> None:
        """No Content-Length header at all: removed from the request, or a chunked body."""
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)
        headers = {**caller.cookie, "X-Attachment-Name": "notes.txt"}
        content: Any = _TEXT if mode == "header-removed" else iter([_TEXT])
        request = env.client.build_request(
            "POST", _upload_path(chat), content=content, headers=headers
        )
        if mode == "header-removed":
            del request.headers["Content-Length"]
        assert "content-length" not in request.headers
        before = _state(env)
        since = len(env.world.db.calls)

        response = env.client.send(request)

        assert _outcome(response) == _refused("content_length_required")
        assert _work(env.world.db, since) == []
        assert _state(env) == before

    def test_attachments_api_upload_of_an_empty_body_is_400_empty_file(self, env: _Env) -> None:
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)
        before = _state(env)
        since = len(env.world.db.calls)

        response = _upload(env.client, caller, chat, b"")

        assert _outcome(response) == _refused("empty_file")
        assert _work(env.world.db, since) == []
        assert _state(env) == before

    def test_attachments_api_upload_size_limit_counts_mib_and_refuses_one_byte_more(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``max_file_size_mb`` 1: 1,048,577 bytes are 413 before any statement with
        nothing stored; exactly 1,048,576 bytes are stored."""
        _set_files(env, monkeypatch, max_file_size_mb=1)
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)
        before = _state(env)
        since = len(env.world.db.calls)

        over = _upload(env.client, caller, chat, b"a" * (_MIB + 1))
        over_work = _work(env.world.db, since)
        after_over = _state(env)
        at_limit = _upload(env.client, caller, chat, b"a" * _MIB)

        assert _outcome(over) == _refused("file_too_large")
        assert over_work == []
        assert after_over == before
        assert at_limit.status_code == 201, at_limit.text
        assert at_limit.json()["size_bytes"] == _MIB

    @pytest.mark.parametrize("case", ["other-org", "colleague", "trashed", "unknown"])
    def test_attachments_api_upload_to_a_chat_not_the_callers_is_one_404(
        self, env: _Env, case: str
    ) -> None:
        """Org B's chat, the Org Admin's chat of the same org, the caller's trashed chat
        and an unknown id: the chat routes' 404 body, nothing stored."""
        db = env.world.db
        caller = env.world.a["editor"]
        chats = {
            "other-org": lambda: db.add_chat(env.world.b["editor"].user_id),
            "colleague": lambda: db.add_chat(env.world.a["org_admin"].user_id),
            "trashed": lambda: db.add_chat(caller.user_id, deleted_at=datetime.now(UTC)),
            "unknown": uuid.uuid4,
        }
        chat = chats[case]()
        before = _state(env)

        response = _upload(env.client, caller, chat)

        assert _outcome(response) == (404, _CHAT_NOT_FOUND)
        assert _state(env) == before

    @pytest.mark.parametrize(
        ("size", "accepted"),
        [pytest.param(51, False, id="one-byte-over"), pytest.param(50, True, id="exact-fit")],
    )
    def test_attachments_api_upload_over_the_org_quota_is_413(
        self, env: _Env, size: int, accepted: bool
    ) -> None:
        """Quota 150 with 100 bytes used by a colleague's trashed file (every row of the
        org counts): 51 more bytes are 413 with nothing stored, 50 fit exactly."""
        db = env.world.db
        db.add_org(ORG_ID, storage_quota_bytes=150)
        _seed(env, env.world.a["org_admin"], b"x" * 100, trashed=True)
        caller = env.world.a["editor"]
        chat = db.add_chat(caller.user_id)
        before = _state(env)

        response = _upload(env.client, caller, chat, b"y" * size)

        if accepted:
            assert response.status_code == 201, response.text
        else:
            assert _outcome(response) == _refused("storage_quota_exceeded")
            assert _state(env) == before

    @pytest.mark.parametrize(
        ("reason", "name", "data", "content_type"),
        [
            pytest.param(
                "unsupported_type", "invoice.pdf", _EXE, "application/pdf", id="exe-named-pdf"
            ),
            pytest.param(
                "legacy_office",
                "budget.xlsx",
                _cfb("Root Entry", "Workbook"),
                _MEDIA_TYPES["xlsx"],
                id="xls-named-xlsx",
            ),
            pytest.param(
                "password_protected",
                "notes.txt",
                _pdf(b"/Root 1 0 R /Encrypt 5 0 R"),
                "text/plain",
                id="encrypted-pdf-named-txt",
            ),
            pytest.param(
                "password_protected",
                "contract.docx",
                _zip(_DOCX_NAMES, encrypted="word/document.xml"),
                _MEDIA_TYPES["docx"],
                id="encrypted-docx",
            ),
            pytest.param(
                "corrupted_file",
                "photo.jpg",
                _png(chunk_type=b"XXXX"),
                "image/jpeg",
                id="png-without-ihdr-named-jpg",
            ),
        ],
    )
    def test_attachments_api_upload_refused_by_type_detection_stores_nothing(
        self, env: _Env, reason: str, name: str, data: bytes, content_type: str
    ) -> None:
        """The body was streamed into a ``.part``: it is removed, no row, no audit row."""
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)
        before = _state(env)

        response = _upload(env.client, caller, chat, data, name=name, content_type=content_type)

        assert _outcome(response) == _refused(reason)
        assert _state(env) == before

    def test_attachments_api_upload_with_an_unusable_root_is_503(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The attachment root is a regular file: 503 ``storage_unavailable``, no row,
        no audit row, no submit, the file untouched."""
        blocker = env.root.parent / "not-a-directory"
        blocker.write_bytes(b"occupied")
        monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", blocker)
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)
        before = _state(env)

        response = _upload(env.client, caller, chat)

        assert _outcome(response) == _refused("storage_unavailable")
        assert _state(env) == before
        assert blocker.read_bytes() == b"occupied"

    def test_attachments_api_upload_with_a_non_uuid_chat_id_is_422(self, env: _Env) -> None:
        before = _state(env)

        response = _upload(env.client, env.world.a["editor"], "not-a-uuid")

        assert response.status_code == 422, response.text
        assert all("input" not in error for error in response.json()["detail"])
        assert _state(env) == before


# ---------------------------------------------------------------------------
# 4. Order of the checks (two faults per request)
# ---------------------------------------------------------------------------


class TestAttachmentsUploadOrder:
    """429, then the header, then Content-Length, then the chat, then the quota."""

    def test_attachments_api_upload_rate_limit_comes_before_the_header_check(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _real_upload_bucket(env, monkeypatch)
        _set_files(env, monkeypatch, max_files_per_message=1)
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)
        first = _upload(env.client, caller, chat)
        before = _state(env)

        response = _upload(env.client, caller, chat, name=None, length="abc")

        assert first.status_code == 201, first.text
        assert _outcome(response) == (429, _RATE_LIMITED)
        assert _state(env) == before

    def test_attachments_api_upload_header_check_comes_before_content_length(
        self, env: _Env
    ) -> None:
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)

        response = _upload(env.client, caller, chat, name="Bericht%FF.txt", length="-1")

        assert _outcome(response) == _refused("invalid_filename")

    @pytest.mark.parametrize(
        ("reason", "data", "length"),
        [
            pytest.param("content_length_required", _TEXT, "x1", id="bad-length"),
            pytest.param("empty_file", b"", None, id="empty"),
            pytest.param("file_too_large", b"a" * (_MIB + 1), None, id="too-large"),
        ],
    )
    def test_attachments_api_upload_content_length_checks_run_before_any_statement(
        self,
        env: _Env,
        monkeypatch: pytest.MonkeyPatch,
        reason: str,
        data: bytes,
        length: str | None,
    ) -> None:
        """An unknown chat as well: the Content-Length refusal wins, no statement runs."""
        _set_files(env, monkeypatch, max_file_size_mb=1)
        caller = env.world.a["editor"]
        since = len(env.world.db.calls)

        response = _upload(env.client, caller, uuid.uuid4(), data, length=length)

        assert _outcome(response) == _refused(reason)
        assert _work(env.world.db, since) == []

    def test_attachments_api_upload_chat_404_comes_before_any_quota_statement(
        self, env: _Env
    ) -> None:
        """Org B's chat with org A's quota at 0: 404, and no quota statement ran."""
        env.world.db.add_org(ORG_ID, storage_quota_bytes=0)
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(env.world.b["editor"].user_id)
        since = len(env.world.db.calls)

        response = _upload(env.client, caller, chat)

        assert _outcome(response) == (404, _CHAT_NOT_FOUND)
        assert [sql for sql in _work(env.world.db, since) if _QUOTA_SQL.search(sql)] == []


# ---------------------------------------------------------------------------
# 5. Raw ASGI: nothing read before the checks, the stream bounded by Content-Length
# ---------------------------------------------------------------------------

_EARLY_CASES: Final = [
    pytest.param("no-session", (401, UNAUTHORIZED), id="no-session"),
    pytest.param("viewer", (403, FORBIDDEN), id="viewer"),
    pytest.param("rate-limited", (429, _RATE_LIMITED), id="rate-limited"),
    pytest.param("no-name", _refused("invalid_filename"), id="invalid-filename"),
    pytest.param("no-length", _refused("content_length_required"), id="no-content-length"),
    pytest.param("zero-length", _refused("empty_file"), id="empty"),
    pytest.param("too-large", _refused("file_too_large"), id="too-large"),
    pytest.param("other-org-chat", (404, _CHAT_NOT_FOUND), id="chat-not-found"),
    pytest.param("quota", _refused("storage_quota_exceeded"), id="quota"),
]


class TestAttachmentsUploadStream:
    """Raw ASGI calls: what ``receive`` hands out, and what is left behind."""

    @pytest.mark.parametrize(("case", "expected"), _EARLY_CASES)
    async def test_attachments_api_upload_refusals_before_the_stream_read_no_body(
        self,
        env: _Env,
        monkeypatch: pytest.MonkeyPatch,
        case: str,
        expected: tuple[int, Any],
    ) -> None:
        """Steps 1 to 8: ``receive`` is never called, nothing is stored."""
        _real_upload_bucket(env, monkeypatch)
        _set_files(env, monkeypatch, max_file_size_mb=1, max_files_per_message=1)
        db = env.world.db
        caller: Account | None = env.world.a["editor"]
        chat = db.add_chat(env.world.a["editor"].user_id)
        length: bytes | None = b"16"
        name: bytes | None = b"notes.txt"
        if case == "no-session":
            caller = None
        elif case == "viewer":
            caller = env.world.a["viewer"]
            chat = db.add_chat(caller.user_id)
        elif case == "rate-limited":
            spent = await _raw_upload(env.app, caller, chat, _Wire([b"abcdefgh"] * 2), length=b"16")
            assert spent[0] == 201, spent
        elif case == "no-name":
            name = None
        elif case == "no-length":
            length = None
        elif case == "zero-length":
            length = b"0"
        elif case == "too-large":
            length = str(_MIB + 1).encode("ascii")
        elif case == "other-org-chat":
            chat = db.add_chat(env.world.b["editor"].user_id)
        elif case == "quota":
            db.add_org(ORG_ID, storage_quota_bytes=150)
            _seed(env, env.world.a["org_admin"], b"x" * 100)
            length = b"51"
        before = _state(env)
        wire = _Wire([b"abcdefgh"] * 8)

        outcome = await _raw_upload(env.app, caller, chat, wire, length=length, name=name)

        assert outcome == expected
        assert wire.asked == 0
        assert _state(env) == before

    async def test_attachments_api_upload_body_longer_than_declared_stops_at_once(
        self, env: _Env
    ) -> None:
        """Content-Length 10, chunks of 8: the second chunk passes it; nothing after it is
        read, the ``.part`` is removed, nothing stored."""
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)
        before = _state(env)
        wire = _Wire([b"abcdefgh"] * 6)

        outcome = await _raw_upload(env.app, caller, chat, wire, length=b"10")

        assert outcome == _refused("content_length_mismatch")
        assert wire.handed == 2
        assert _state(env) == before

    async def test_attachments_api_upload_body_shorter_than_declared_stores_nothing(
        self, env: _Env
    ) -> None:
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)
        before = _state(env)
        wire = _Wire([b"abcdefgh", b"ijklmnop"])

        outcome = await _raw_upload(env.app, caller, chat, wire, length=b"100")

        assert outcome == _refused("content_length_mismatch")
        assert wire.handed == 2
        assert _state(env) == before

    async def test_attachments_api_upload_client_disconnect_mid_body_stores_nothing(
        self, env: _Env
    ) -> None:
        """One chunk of 100 declared bytes, then ``http.disconnect``: no row, no file, no
        ``.part``, no audit row, no submit (what the server answers is not pinned)."""
        caller = env.world.a["editor"]
        chat = env.world.db.add_chat(caller.user_id)
        before = _state(env)
        wire = _Wire([b"abcdefgh" * 5], disconnect=True)

        await _raw_upload(env.app, caller, chat, wire, length=b"100")

        assert wire.handed == 1
        assert _state(env) == before

    async def test_attachments_api_upload_chat_trashed_while_streaming_is_404_at_commit(
        self, env: _Env
    ) -> None:
        """The chat is trashed between two chunks: the commit's chat lock finds nothing,
        404 ``chat_not_found``, the streamed file removed, nothing stored."""
        db = env.world.db
        caller = env.world.a["editor"]
        chat = db.add_chat(caller.user_id)
        before = _state(env)

        def trash(chunk: int) -> None:
            if chunk == 2:
                row = db.chats[next(key for key in db.chats if str(key) == str(chat))]
                row["deleted_at"] = datetime.now(UTC)

        wire = _Wire([b"Zeile eins\n", b"Zeile zwei\n"], during=trash)

        outcome = await _raw_upload(env.app, caller, chat, wire, length=b"22")

        assert outcome == (404, _CHAT_NOT_FOUND)
        assert wire.handed == 2
        assert _state(env) == before

    async def test_attachments_api_upload_quota_taken_while_streaming_is_413_at_commit(
        self, env: _Env
    ) -> None:
        """Quota 150, nothing used at the check; a colleague's 140-byte file lands
        between two chunks: the commit's quota check refuses the 22 bytes, nothing of
        this upload is stored."""
        db = env.world.db
        db.add_org(ORG_ID, storage_quota_bytes=150)
        caller = env.world.a["editor"]
        chat = db.add_chat(caller.user_id)
        colleague_chat = db.add_chat(env.world.a["org_admin"].user_id)
        taken: list[uuid.UUID] = []

        def take_quota(chunk: int) -> None:
            if chunk == 2:
                taken.append(db.add_attachment(colleague_chat, kind="txt", size_bytes=140))

        wire = _Wire([b"Zeile eins\n", b"Zeile zwei\n"], during=take_quota)
        files_before = _files(env.root)
        audit_before = db.snapshot()["audit"]

        outcome = await _raw_upload(env.app, caller, chat, wire, length=b"22")

        assert outcome == _refused("storage_quota_exceeded")
        assert [str(key) for key in db.attachments] == [str(taken[0])]
        assert _files(env.root) == files_before
        assert db.snapshot()["audit"] == audit_before
        assert env.processing.calls == []


# ---------------------------------------------------------------------------
# 6. GET /api/attachments/{id} and /content
# ---------------------------------------------------------------------------

_NOT_THE_CALLERS: Final = ["other-org", "colleague", "org-admin-on-editors", "trashed", "unknown"]


def _not_the_callers(env: _Env, case: str) -> tuple[Account, uuid.UUID]:
    """(caller, an attachment id that isn't the caller's live attachment)."""
    a, b = env.world.a, env.world.b
    if case == "other-org":
        return a["editor"], _seed(env, b["editor"])
    if case == "colleague":
        return a["editor"], _seed(env, a["org_admin"])
    if case == "org-admin-on-editors":
        return a["org_admin"], _seed(env, a["editor"])
    if case == "trashed":
        return a["editor"], _seed(env, a["editor"], trashed=True)
    return a["editor"], uuid.uuid4()


class TestAttachmentsRead:
    """The owner's live attachment only; one 404 for everything else."""

    def test_attachments_api_metadata_reflects_the_stored_row(self, env: _Env) -> None:
        """A ``ready`` row with a page count and a token estimate (GH-188), and a
        ``failed`` row with its reason (and no estimate)."""
        caller = env.world.a["editor"]
        ready = _seed(
            env,
            caller,
            _pdf(),
            filename="Bericht.pdf",
            kind="pdf",
            status="ready",
            page_count=7,
            token_estimate=4195,
        )
        failed = _seed(
            env,
            caller,
            _png(),
            filename="Scan.png",
            kind="png",
            status="failed",
            failure_reason="corrupted_file",
        )

        responses = {key: _metadata(env.client, caller, key) for key in (ready, failed)}

        for attachment_id, response in responses.items():
            assert response.status_code == 200, response.text
            body = response.json()
            row = env.world.db.attachment_row(attachment_id)
            assert row is not None
            assert set(body) == _SUMMARY_KEYS
            assert body == {
                "id": str(attachment_id),
                "chat_id": str(row["chat_id"]),
                "message_id": None,
                "filename": row["filename"],
                "kind": row["kind"],
                "size_bytes": row["size_bytes"],
                "status": row["status"],
                "failure_reason": row["failure_reason"],
                "page_count": row["page_count"],
                "token_estimate": row["token_estimate"],
                "active": True,
                "context_report": None,
                "created_at": body["created_at"],
            }
            assert _ts(body["created_at"]) == row["created_at"]
        assert [responses[key].json()["status"] for key in (ready, failed)] == ["ready", "failed"]
        assert (
            responses[ready].json()["page_count"],
            responses[ready].json()["token_estimate"],
            responses[failed].json()["failure_reason"],
            responses[failed].json()["token_estimate"],
        ) == (
            7,
            4195,
            "corrupted_file",
            None,
        )

    @pytest.mark.parametrize("case", _NOT_THE_CALLERS)
    @pytest.mark.parametrize("route", ["metadata", "content"])
    def test_attachments_api_read_of_an_attachment_not_the_callers_is_one_404(
        self, env: _Env, route: str, case: str
    ) -> None:
        caller, attachment = _not_the_callers(env, case)
        chat = env.world.db.add_chat(caller.user_id)

        response = _call_route(env, route, caller, chat, attachment)

        assert _outcome(response) == (404, _ATTACHMENT_NOT_FOUND)

    @pytest.mark.parametrize("route", ["metadata", "content"])
    def test_attachments_api_read_with_a_non_uuid_id_is_422(self, env: _Env, route: str) -> None:
        caller = env.world.a["editor"]
        path = "/api/attachments/not-a-uuid" + ("/content" if route == "content" else "")

        response = env.client.get(path, headers=caller.cookie)

        assert response.status_code == 422, response.text
        assert all("input" not in error for error in response.json()["detail"])

    @pytest.mark.parametrize("kind", _KINDS)
    def test_attachments_api_download_sends_the_bytes_with_the_kinds_headers(
        self, env: _Env, kind: str
    ) -> None:
        """Content-Type per kind; the stored name already fits the kind (``.jpeg`` and
        ``.markdown`` included), so it is the download name as it is."""
        caller = env.world.a["editor"]
        name, data, _ = _KIND_FILES[kind]
        attachment = _seed(env, caller, data, filename=name, kind=kind)

        response = _content(env.client, caller, attachment)

        assert (response.status_code, response.content) == (200, data)
        assert {
            header: response.headers.get(header)
            for header in (
                "content-type",
                "content-disposition",
                "cache-control",
                "x-content-type-options",
            )
        } == {
            "content-type": _MEDIA_TYPES[kind],
            "content-disposition": f"attachment; filename*=UTF-8''{name}",
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
        }

    @pytest.mark.parametrize(
        ("filename", "kind", "disposition"),
        [
            pytest.param(
                "page.html", "txt", "attachment; filename*=UTF-8''page.html.txt", id="html-as-txt"
            ),
            pytest.param(
                "scan.pdf", "png", "attachment; filename*=UTF-8''scan.pdf.png", id="pdf-name-png"
            ),
            pytest.param(
                _RESUME,
                "pdf",
                "attachment; filename*=UTF-8''R%C3%A9sum%C3%A9%20Q3.pdf",
                id="unicode-name",
            ),
            pytest.param(
                'x"; filename=evil.exe.txt',
                "txt",
                "attachment; filename*=UTF-8''x%22%3B%20filename%3Devil.exe.txt",
                id="header-injection",
            ),
        ],
    )
    def test_attachments_api_download_disposition_is_the_encoded_download_name(
        self, env: _Env, filename: str, kind: str, disposition: str
    ) -> None:
        caller = env.world.a["editor"]
        attachment = _seed(env, caller, _TEXT, filename=filename, kind=kind)

        response = _content(env.client, caller, attachment)

        assert response.status_code == 200, response.text
        assert response.headers.get("content-disposition") == disposition

    @pytest.mark.parametrize(
        ("status", "failure_reason", "page_count"),
        [
            pytest.param("uploaded", None, None, id="uploaded"),
            pytest.param("processing", None, None, id="processing"),
            pytest.param("ready", None, 3, id="ready"),
            pytest.param("failed", "corrupted_file", None, id="failed"),
        ],
    )
    def test_attachments_api_download_works_in_every_status(
        self, env: _Env, status: str, failure_reason: str | None, page_count: int | None
    ) -> None:
        caller = env.world.a["org_admin"]
        attachment = _seed(
            env,
            caller,
            _TEXT,
            status=status,
            failure_reason=failure_reason,
            page_count=page_count,
        )

        response = _content(env.client, caller, attachment)

        assert (response.status_code, response.content) == (200, _TEXT)

    def test_attachments_api_download_of_a_row_whose_file_is_gone_is_404(self, env: _Env) -> None:
        caller = env.world.a["editor"]
        attachment = _seed(env, caller, write=False)

        response = _content(env.client, caller, attachment)

        assert _outcome(response) == (404, _ATTACHMENT_NOT_FOUND)

    def test_attachments_api_download_of_a_non_regular_entry_is_404(self, env: _Env) -> None:
        """Regression guard: a directory at <root>/<org>/<id> (where the stored file
        belongs) is never served and is no 500: the same 404 as a missing file."""
        caller = env.world.a["editor"]
        attachment = _seed(env, caller, write=False)
        assert caller.org_id is not None
        org_dir = env.root / str(caller.org_id)
        org_dir.mkdir(mode=0o700, exist_ok=True)
        entry = org_dir / str(attachment)
        entry.mkdir(mode=0o700)
        (entry / "page-1.png").write_bytes(b"derived")

        response = _content(env.client, caller, attachment)

        assert _outcome(response) == (404, _ATTACHMENT_NOT_FOUND)


# ---------------------------------------------------------------------------
# 7. Logs
# ---------------------------------------------------------------------------


def test_attachments_api_logs_carry_no_filename_header_or_content(env: _Env) -> None:
    """An upload, a type refusal and a header refusal with a distinctive name and
    content marker, then the metadata and the download: no log record carries the
    name, the raw header or the content; the success line names the attachment id."""
    caller = env.world.a["editor"]
    chat = env.world.db.add_chat(caller.user_id)

    with configured_logging("DEBUG", "json") as logs:
        stored = _upload(env.client, caller, chat, _LOG_CONTENT, name=_LOG_HEADER)
        assert stored.status_code == 201, stored.text
        attachment_id = stored.json()["id"]
        refused_type = _upload(env.client, caller, chat, _EXE + _LOG_CONTENT, name=_LOG_HEADER)
        refused_name = _upload(env.client, caller, chat, _LOG_CONTENT, name=_LOG_HEADER + "%FF")
        metadata = _metadata(env.client, caller, attachment_id)
        content = _content(env.client, caller, attachment_id)

    assert _outcome(refused_type) == _refused("unsupported_type")
    assert _outcome(refused_name) == _refused("invalid_filename")
    assert (metadata.json()["filename"], content.content) == (_LOG_NAME, _LOG_CONTENT)
    assert attachment_id in logs.text
    texts = [logs.text, *(record.getMessage() for record in logs.records)]
    texts += [repr(record.args) for record in logs.records]
    combined = "\n".join(texts).casefold()
    forbidden = ["quokkabudget", "geheim%20187", "wombatledger", "mandantenliste"]
    assert [marker for marker in forbidden if marker in combined] == []


# ---------------------------------------------------------------------------
# 8. Download Range errors (GH-281, Decision 6, contract G1 to G6)
# ---------------------------------------------------------------------------

_RANGE_NOT_SATISFIABLE: Final = {
    "detail": "Range not satisfiable",
    "reason": "range_not_satisfiable",
}
_CONTENT_ROUTE: Final = "/api/attachments/{attachment_id}/content"
_SIZE: Final = len(_TEXT)
# (status, JSON body, media type, Content-Range) of the 416 for the seeded _TEXT file.
_REFUSED_RANGE: Final = (416, _RANGE_NOT_SATISFIABLE, "application/json", f"bytes */{_SIZE}")
# Ranges the file response would reject for _TEXT: malformed, then unsatisfiable.
_BAD_RANGES: Final = [
    pytest.param("bytes", id="no-equals-sign"),
    pytest.param("items=0-1", id="unit-not-bytes"),
    pytest.param("bytes=", id="no-range"),
    pytest.param("bytes=abc", id="not-a-range"),
    pytest.param("bytes=5-1", id="start-after-end"),
    pytest.param("0-1", id="no-unit"),
    pytest.param(f"bytes={_SIZE}-", id="start-at-the-size"),
    pytest.param(f"bytes={_SIZE + 100}-{_SIZE + 200}", id="past-the-end"),
]
# One malformed and one unsatisfiable Range, for the checks that come before it.
_ONE_OF_EACH: Final = [
    pytest.param("bytes=abc", id="malformed"),
    pytest.param(f"bytes={_SIZE}-", id="unsatisfiable"),
]
# An If-Range that is neither the file's ETag nor its Last-Modified.
_STALE_IF_RANGE: Final = '"0123456789abcdef0123456789abcdef"'


def _ranged(
    client: TestClient,
    caller: Account | None,
    attachment_id: Any,
    range_header: str,
    *,
    if_range: str | None = None,
) -> httpx.Response:
    """GET the content with ``Range: range_header`` (and ``If-Range`` when given)."""
    headers = {**_cookie(caller), "Range": range_header}
    if if_range is not None:
        headers["If-Range"] = if_range
    return client.get(f"/api/attachments/{attachment_id}/content", headers=headers)


def _range_outcome(response: httpx.Response) -> tuple[int, Any, str, str | None]:
    """(status, body, media type without parameters, Content-Range)."""
    status, body = _outcome(response)
    media_type = response.headers.get("content-type", "").partition(";")[0].strip()
    return status, body, media_type, response.headers.get("content-range")


class TestAttachmentsDownloadRange:
    """A Range the file response rejects is the 416 envelope; valid ranges unchanged."""

    @pytest.mark.parametrize("range_header", _BAD_RANGES)
    def test_attachments_api_download_bad_range_is_416_range_not_satisfiable(
        self, env: _Env, range_header: str
    ) -> None:
        caller = env.world.a["editor"]
        attachment = _seed(env, caller)

        response = _ranged(env.client, caller, attachment, range_header)

        assert _range_outcome(response) == _REFUSED_RANGE

    @pytest.mark.parametrize("validator", ["etag", "last-modified"])
    def test_attachments_api_download_bad_range_with_a_matching_if_range_is_416(
        self, env: _Env, validator: str
    ) -> None:
        """If-Range names the file's current ETag or Last-Modified, so the Range
        applies: a malformed one is the 416 too, never the plain-text 400."""
        caller = env.world.a["editor"]
        attachment = _seed(env, caller)
        current = _content(env.client, caller, attachment).headers[validator]

        response = _ranged(env.client, caller, attachment, "bytes=abc", if_range=current)

        assert _range_outcome(response) == _REFUSED_RANGE

    def test_attachments_api_download_416_never_echoes_the_range_header(self, env: _Env) -> None:
        caller = env.world.a["editor"]
        attachment = _seed(env, caller)
        marker = "quokkarange281"

        response = _ranged(env.client, caller, attachment, f"{marker}=0-1")

        echoed = [text for text in (response.text, *response.headers.values()) if marker in text]
        assert (_range_outcome(response), echoed) == (_REFUSED_RANGE, [])

    def test_attachments_api_download_openapi_documents_the_416(self) -> None:
        responses = make_app().openapi()["paths"][_CONTENT_ROUTE]["get"]["responses"]

        documented = responses.get("416", {})

        assert (
            "range_not_satisfiable" in documented.get("description", ""),
            documented.get("content", {}).get("application/json", {}).get("example"),
        ) == (True, _RANGE_NOT_SATISFIABLE)

    @pytest.mark.parametrize(
        ("range_header", "content_range", "data"),
        [
            pytest.param("bytes=0-9", f"bytes 0-9/{_SIZE}", _TEXT[:10], id="first-ten"),
            pytest.param(
                "bytes=-5", f"bytes {_SIZE - 5}-{_SIZE - 1}/{_SIZE}", _TEXT[-5:], id="last-five"
            ),
        ],
    )
    def test_attachments_api_download_valid_range_is_206_as_before(
        self, env: _Env, range_header: str, content_range: str, data: bytes
    ) -> None:
        """Regression guard (G2)."""
        caller = env.world.a["editor"]
        attachment = _seed(env, caller)

        response = _ranged(env.client, caller, attachment, range_header)

        assert (
            response.status_code,
            response.headers.get("content-range"),
            response.content,
        ) == (206, content_range, data)

    def test_attachments_api_download_two_ranges_are_206_multipart_as_before(
        self, env: _Env
    ) -> None:
        """Regression guard (G2): ``multipart/byteranges`` with both parts."""
        caller = env.world.a["editor"]
        attachment = _seed(env, caller)

        response = _ranged(env.client, caller, attachment, "bytes=0-1,4-5")

        content_type = response.headers.get("content-type", "")
        boundary = content_type.partition("; boundary=")[2]
        parts = [
            f"--{boundary}\r\nContent-Type: {_MEDIA_TYPES['txt']}\r\n"
            f"Content-Range: bytes {start}-{end}/{_SIZE}\r\n\r\n".encode()
            + _TEXT[start : end + 1]
            for start, end in ((0, 1), (4, 5))
        ]
        expected = b"\r\n".join(parts) + f"\r\n--{boundary}--".encode()
        assert (response.status_code, content_type.partition(";")[0], response.content) == (
            206,
            "multipart/byteranges",
            expected,
        )

    @pytest.mark.parametrize("range_header", _ONE_OF_EACH)
    def test_attachments_api_download_bad_range_with_a_stale_if_range_is_the_whole_file(
        self, env: _Env, range_header: str
    ) -> None:
        """Regression guard (G4): the Range is ignored, 200 with every byte."""
        caller = env.world.a["editor"]
        attachment = _seed(env, caller)

        response = _ranged(env.client, caller, attachment, range_header, if_range=_STALE_IF_RANGE)

        assert (response.status_code, response.content) == (200, _TEXT)

    @pytest.mark.parametrize("case", [*_NOT_THE_CALLERS, "file-gone"])
    @pytest.mark.parametrize("range_header", _ONE_OF_EACH)
    def test_attachments_api_download_bad_range_on_no_file_of_the_callers_is_404(
        self, env: _Env, range_header: str, case: str
    ) -> None:
        """Regression guard (G3): ownership and the file come before the Range; the 404
        carries no Content-Range (no size leaks)."""
        if case == "file-gone":
            caller = env.world.a["editor"]
            attachment = _seed(env, caller, write=False)
        else:
            caller, attachment = _not_the_callers(env, case)

        response = _ranged(env.client, caller, attachment, range_header)

        assert (_outcome(response), response.headers.get("content-range")) == (
            (404, _ATTACHMENT_NOT_FOUND),
            None,
        )

    def test_attachments_api_download_rate_limit_comes_before_the_range_check(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression guard (G3): burst 1, the second download with a malformed Range is
        the 429."""
        monkeypatch.setitem(server._RATE_LIMITS, _CONTENT_KEY, (0.001, 1))
        caller = env.world.a["editor"]
        attachment = _seed(env, caller)

        first = _content(env.client, caller, attachment)
        limited = _ranged(env.client, caller, attachment, "bytes=abc")

        assert (first.status_code, _outcome(limited)) == (200, (429, _RATE_LIMITED))


# ---------------------------------------------------------------------------
# 9. Download Range limits (GH-281 audit fix round 1, Decision 11, contract G7)
# ---------------------------------------------------------------------------

# A file wide enough for 17 one-byte ranges with a gap between each two (0, 2, ..., 32).
_WIDE: Final = _TEXT * 3
_WIDE_SIZE: Final = len(_WIDE)
_WIDE_REFUSED: Final = (416, _RANGE_NOT_SATISFIABLE, "application/json", f"bytes */{_WIDE_SIZE}")
_MAX_RANGES: Final = 16
_MAX_RANGE_HEADER_CHARS: Final = 1024
# The longest padded ``0-000...9`` range _range_of_length writes: its end stays far below
# int()'s 4,300-digit limit (past it Starlette drops the range).
_PADDED_RANGE_CHARS: Final = 1024
# Starlette 1.7 ignores a Range of more than 100 comma-separated ranges (the whole file).
_STARLETTE_MAX_RANGES: Final = 100


def _separate_ranges(count: int) -> str:
    """``bytes=0-0,2-2,4-4,...``: ``count`` one-byte ranges, none overlapping or adjacent
    to another, so each is its own multipart part."""
    return "bytes=" + ",".join(f"{2 * index}-{2 * index}" for index in range(count))


def _range_of_length(length: int) -> str:
    """A valid Range of exactly ``length`` characters for the first ten bytes, the same on
    every Starlette version: ``0-`` and an end of ``9`` padded with leading zeros, one such
    range up to ``_PADDED_RANGE_CHARS`` characters (1,024 and 1,025 are a single range),
    else as few equal copies as fit (they overlap, so one part), never more than
    Starlette 1.7's 100 ranges."""
    body = length - len("bytes=")
    count = -(-(body + 1) // (_PADDED_RANGE_CHARS + 1))  # ranges, a comma between two
    width, longer = divmod(body - (count - 1), count)
    ranges = ["0-" + "0" * (width + (index < longer) - 3) + "9" for index in range(count)]
    header = "bytes=" + ",".join(ranges)
    assert (len(header), width >= 3, count <= _STARLETTE_MAX_RANGES) == (length, True, True)
    return header


def _first_ten(response: httpx.Response) -> tuple[int, str | None, bytes]:
    return response.status_code, response.headers.get("content-range"), response.content


_FIRST_TEN: Final = (206, f"bytes 0-9/{_WIDE_SIZE}", _WIDE[:10])


def _multipart_parts(response: httpx.Response) -> tuple[int, str, list[str]]:
    """(status, media type, each part's Content-Range) of a multipart answer."""
    media_type = response.headers.get("content-type", "").partition(";")[0].strip()
    found = re.findall(rb"Content-Range: (bytes \d+-\d+/\d+)", response.content)
    return response.status_code, media_type, [value.decode() for value in found]


# The two ways past a limit: more than 16 parts, a header over 1,024 characters.
_TOO_MANY: Final = [
    pytest.param(_separate_ranges(17), id="seventeen-parts"),
    pytest.param(_range_of_length(1025), id="header-of-1025-chars"),
]


class TestAttachmentsDownloadRangeLimits:
    """Past 16 parts or 1,024 characters a Range that applies is the 416 envelope."""

    def test_attachments_api_download_range_limits_have_the_contract_values(self) -> None:
        assert (
            getattr(server, "_MAX_RANGES", None),
            getattr(server, "_MAX_RANGE_HEADER_CHARS", None),
        ) == (_MAX_RANGES, _MAX_RANGE_HEADER_CHARS)

    @pytest.mark.parametrize("count", [17, 39])
    def test_attachments_api_download_more_than_16_separate_ranges_is_416(
        self, env: _Env, count: int
    ) -> None:
        caller = env.world.a["editor"]
        attachment = _seed(env, caller, _WIDE)

        response = _ranged(env.client, caller, attachment, _separate_ranges(count))

        assert _range_outcome(response) == _WIDE_REFUSED

    def test_attachments_api_download_16_separate_ranges_are_206_multipart_as_before(
        self, env: _Env
    ) -> None:
        """Regression guard (G7): exactly 16 parts are served, every part's bytes."""
        caller = env.world.a["editor"]
        attachment = _seed(env, caller, _WIDE)

        response = _ranged(env.client, caller, attachment, _separate_ranges(_MAX_RANGES))

        content_type = response.headers.get("content-type", "")
        boundary = content_type.partition("; boundary=")[2]
        parts = [
            f"--{boundary}\r\nContent-Type: {_MEDIA_TYPES['txt']}\r\n"
            f"Content-Range: bytes {start}-{start}/{_WIDE_SIZE}\r\n\r\n".encode()
            + _WIDE[start : start + 1]
            for start in range(0, 2 * _MAX_RANGES, 2)
        ]
        expected = b"\r\n".join(parts) + f"\r\n--{boundary}--".encode()
        assert (response.status_code, content_type.partition(";")[0], response.content) == (
            206,
            "multipart/byteranges",
            expected,
        )

    def test_attachments_api_download_range_parts_are_counted_after_merging_overlaps(
        self, env: _Env
    ) -> None:
        """17 separate ranges are the 416, while 17 ranges of which two overlap (16 parts)
        and 40 overlapping ranges (one part) are served: the limit counts parts, not the
        ranges written."""
        caller = env.world.a["editor"]
        attachment = _seed(env, caller, _WIDE)
        chained = "bytes=" + ",".join(f"{index}-{index + 1}" for index in range(40))

        seventeen = _ranged(env.client, caller, attachment, _separate_ranges(17))
        sixteen_parts = _ranged(env.client, caller, attachment, _separate_ranges(16) + ",0-0")
        one_part = _ranged(env.client, caller, attachment, chained)

        assert (
            _range_outcome(seventeen),
            _multipart_parts(sixteen_parts),
            (one_part.status_code, one_part.headers.get("content-range"), one_part.content),
        ) == (
            _WIDE_REFUSED,
            (
                206,
                "multipart/byteranges",
                [f"bytes {start}-{start}/{_WIDE_SIZE}" for start in range(0, 32, 2)],
            ),
            (206, f"bytes 0-40/{_WIDE_SIZE}", _WIDE[:41]),
        )

    @pytest.mark.parametrize("length", [1025, 65_536])
    def test_attachments_api_download_range_header_over_1024_chars_is_416(
        self, env: _Env, length: int
    ) -> None:
        """A valid Range of the first ten bytes (one part, ``_range_of_length``) that is
        too long."""
        caller = env.world.a["editor"]
        attachment = _seed(env, caller, _WIDE)
        header = _range_of_length(length)

        response = _ranged(env.client, caller, attachment, header)

        assert (len(header), _range_outcome(response)) == (length, _WIDE_REFUSED)

    def test_attachments_api_download_range_header_of_exactly_1024_chars_is_served(
        self, env: _Env
    ) -> None:
        """Regression guard (G7): 1,024 characters are within the limit."""
        caller = env.world.a["editor"]
        attachment = _seed(env, caller, _WIDE)
        header = _range_of_length(_MAX_RANGE_HEADER_CHARS)

        response = _ranged(env.client, caller, attachment, header)

        assert (len(header), _first_ten(response)) == (_MAX_RANGE_HEADER_CHARS, _FIRST_TEN)

    def test_attachments_api_download_range_part_limit_is_read_at_call_time(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``server._MAX_RANGES`` lowered to 2: three parts are the 416, two still the 206."""
        monkeypatch.setattr(server, "_MAX_RANGES", 2, raising=False)
        caller = env.world.a["editor"]
        attachment = _seed(env, caller, _WIDE)

        three = _ranged(env.client, caller, attachment, _separate_ranges(3))
        two = _ranged(env.client, caller, attachment, _separate_ranges(2))

        assert (_range_outcome(three), _multipart_parts(two)) == (
            _WIDE_REFUSED,
            (
                206,
                "multipart/byteranges",
                [f"bytes 0-0/{_WIDE_SIZE}", f"bytes 2-2/{_WIDE_SIZE}"],
            ),
        )

    def test_attachments_api_download_range_header_limit_is_read_at_call_time(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``server._MAX_RANGE_HEADER_CHARS`` lowered to 20: 21 characters are the 416,
        20 still the 206."""
        monkeypatch.setattr(server, "_MAX_RANGE_HEADER_CHARS", 20, raising=False)
        caller = env.world.a["editor"]
        attachment = _seed(env, caller, _WIDE)

        over = _ranged(env.client, caller, attachment, _range_of_length(21))
        at = _ranged(env.client, caller, attachment, _range_of_length(20))

        assert (_range_outcome(over), _first_ten(at)) == (_WIDE_REFUSED, _FIRST_TEN)

    @pytest.mark.parametrize("range_header", _TOO_MANY)
    def test_attachments_api_download_range_past_a_limit_with_a_matching_if_range_is_416(
        self, env: _Env, range_header: str
    ) -> None:
        """If-Range names the file's current ETag, so the Range applies."""
        caller = env.world.a["editor"]
        attachment = _seed(env, caller, _WIDE)
        current = _content(env.client, caller, attachment).headers["etag"]

        response = _ranged(env.client, caller, attachment, range_header, if_range=current)

        assert _range_outcome(response) == _WIDE_REFUSED

    @pytest.mark.parametrize("range_header", _TOO_MANY)
    def test_attachments_api_download_range_past_a_limit_with_a_stale_if_range_is_whole_file(
        self, env: _Env, range_header: str
    ) -> None:
        """Regression guard (G7): the Range is ignored, 200 with every byte."""
        caller = env.world.a["editor"]
        attachment = _seed(env, caller, _WIDE)

        response = _ranged(env.client, caller, attachment, range_header, if_range=_STALE_IF_RANGE)

        assert (response.status_code, response.content) == (200, _WIDE)

    @pytest.mark.parametrize("case", ["other-org", "file-gone"])
    @pytest.mark.parametrize("range_header", _TOO_MANY)
    def test_attachments_api_download_range_past_a_limit_on_no_file_of_the_callers_is_404(
        self, env: _Env, range_header: str, case: str
    ) -> None:
        """Regression guard (G7): ownership and the file come first; no Content-Range."""
        caller = env.world.a["editor"]
        owner = env.world.b["editor"] if case == "other-org" else caller
        attachment = _seed(env, owner, _WIDE, write=case != "file-gone")

        response = _ranged(env.client, caller, attachment, range_header)

        assert (_outcome(response), response.headers.get("content-range")) == (
            (404, _ATTACHMENT_NOT_FOUND),
            None,
        )

    @pytest.mark.parametrize(
        "range_header",
        [
            pytest.param(_separate_ranges(17) + ",quokkalimit281", id="seventeen-parts"),
            pytest.param(
                _range_of_length(1025).replace("bytes=", "bytes=quokkalimit281,", 1),
                id="header-over-1024-chars",
            ),
        ],
    )
    def test_attachments_api_download_range_limit_416_never_echoes_the_header(
        self, env: _Env, range_header: str
    ) -> None:
        """The marker is a sub-range without ``-`` (ignored by the parser)."""
        caller = env.world.a["editor"]
        attachment = _seed(env, caller, _WIDE)

        response = _ranged(env.client, caller, attachment, range_header)

        echoed = [
            text for text in (response.text, *response.headers.values()) if "quokkalimit" in text
        ]
        assert (_range_outcome(response), echoed) == (_WIDE_REFUSED, [])

    def test_attachments_api_download_openapi_416_names_the_range_limits(self) -> None:
        """The 416's description names both limits: 16 parts and 1,024 characters."""
        responses = make_app().openapi()["paths"][_CONTENT_ROUTE]["get"]["responses"]
        description = responses.get("416", {}).get("description", "")

        assert (
            "range_not_satisfiable" in description,
            re.search(r"(?<![\d,.])16(?![\d,])", description) is not None,
            re.search(r"(?<![\d,.])1[,']?024(?!\d)", description) is not None,
        ) == (True, True, True)
