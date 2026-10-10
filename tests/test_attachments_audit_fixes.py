"""Security-audit round 1 fixes of GH-187 (contract section 7, issue Decision 18).

The four fixes, pinned against the FakeDb, ``tmp_path`` and the app from
``create_app()`` (raw ASGI calls whose ``receive`` the tests control, so an
upload can be held open mid-body):

F1, uploads in progress (server M-1):
- ``admino.attachments`` reserves each upload's declared length for its org,
  from the quota pre-check until the upload ends; the pre-check is
  ``used + reserved + declared > quota``. Pinned: of two uploads started
  together that don't fit together, one is refused (``storage_quota_exceeded``)
  before it asks for any body chunk and before a ``.part`` of its own exists
  (no await between the check and the reservation); one byte over the
  reservation is refused while an exact fit is stored (the commit check still
  counts stored rows only); the reservation is per org (another org's upload is
  unaffected) and org-wide (a colleague's upload counts); it holds while the
  upload is in detection; it is released on every outcome (stored,
  ``content_length_mismatch``, a body error, the task cancelled).
- ``attachments.STALL_TIMEOUT_S`` is 30.0: a body chunk that doesn't arrive
  within it ends the upload with ``content_length_mismatch``: no row, no file,
  no ``.part``, the reservation released. The timeout is per chunk: a slow body
  that keeps sending is stored.
- The upload route caps the uploads a user has open at the platform
  ``max_files_per_message``: one more answers 429 ``{"detail": "Rate limit
  exceeded"}`` without asking ``receive`` for anything and stores nothing (the
  token bucket is kept roomy, so the 429 is the cap); another user isn't
  affected; the slot is free again once an open upload ends (stored, refused,
  its chat gone, client disconnect, cancelled, stalled). Over HTTP the
  reservation is a 413 ``storage_quota_exceeded`` before the body is read.
F2, the ZIP central directory (core M-1):
- ``attachment_types.MAX_ZIP_DIRECTORY_BYTES`` is 2 MiB: a directory of
  exactly 2 MiB is listed; one byte more (that byte in the last entry's comment,
  where a silently truncated read still lists) and a directory of 20,000 tiny
  entries are ``corrupted_file``; a normal DOCX and XLSX are still detected.
  Detecting a ZIP with a 24 MiB directory never allocates near its size
  (tracemalloc peak below 8 MiB; listing it uncapped takes about 48 MiB).
- ``attachments.DETECT_CONCURRENCY`` is 2: five concurrent uploads never run
  more than two ``detect_kind`` calls at once, and all five are stored. A
  cancelled upload keeps its detection slot until its detection thread ends
  (regression guard): a waiting upload's detection starts only then.
F3, zipfile errors (core L-1): an entry whose "version needed to extract" is
unsupported (zipfile raises ``NotImplementedError``) and any other exception
from zipfile are ``corrupted_file`` (over HTTP 422, never a 500); a
``MemoryError`` propagates.
F4, after the commit (core L-2): an exception after the transaction committed
(a cancellation while the connection is released) leaves the row, the
``file.upload`` event and the file ``<id>``; so does an error that says nothing
about the commit (a RuntimeError from the release, regression guard); a commit
that fails still removes ``<id>`` and ``<id>.part`` (regression guard).

The new names are only looked up inside the tests (monkeypatched with
``raising=False``), so the file collects against the code before the fixes and
each test fails on its own. Files live under tmp_path; fixture files are built
in code (no binary in the repo). No network, no real PostgreSQL.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import inspect
import io
import json
import struct
import threading
import time
import tracemalloc
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import organizations, scoped_settings, server
from admino.tenancy import TenantContext
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb
from tests.tenancy_world import (
    CLIENT_IP,
    build_world,
    make_app,
    make_client,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    import uuid
    from collections.abc import AsyncIterator, Callable, Sequence
    from pathlib import Path
    from types import ModuleType

    import httpx
    from fastapi import FastAPI
    from starlette.types import Message, Receive

    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MIB: Final = 1_048_576
# The contract's MAX_ZIP_DIRECTORY_BYTES, spelled out (never read from the module).
_DIRECTORY_CAP: Final = 2 * _MIB
_QUOTA: Final = 100
_MAX_BYTES: Final = 4096
_IP: Final = "203.0.113.187"
# A stall timeout short enough for a test, long next to a loop turn.
_SHORT_STALL_S: Final = 0.05
# How long a test waits for something that must happen promptly.
_WAIT_S: Final = 3.0

_RATE_LIMITED: Final = (429, {"detail": "Rate limit exceeded"})
_LENGTH_MISMATCH: Final = (
    400,
    {"detail": "The body doesn't match Content-Length", "reason": "content_length_mismatch"},
)
_QUOTA_EXCEEDED: Final = (
    413,
    {"detail": "The organization's storage quota is full", "reason": "storage_quota_exceeded"},
)
_CORRUPTED: Final = (422, {"detail": "The file is corrupted", "reason": "corrupted_file"})
_CHAT_NOT_FOUND: Final = (404, {"detail": "Chat not found", "reason": "chat_not_found"})

_DOCX_NAMES: Final = ("[Content_Types].xml", "_rels/.rels", "word/document.xml")
_XLSX_NAMES: Final = ("[Content_Types].xml", "_rels/.rels", "xl/workbook.xml")
_DOCX_MEDIA_TYPE: Final = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

# A held HTTP upload: the first message, then the rest once the test ends it.
_HEAD: Final = b"Zeile eins\n"
_REST: Final = b"Zeile zwei\n"
_TEXT: Final = b"Termin am Montag um neun.\n"


# ---------------------------------------------------------------------------
# Fixture files (built in memory, stdlib only)
# ---------------------------------------------------------------------------


def _zip_of(names: Sequence[str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in names:
            archive.writestr(name, "<x>" + name + "</x>")
    return buffer.getvalue()


def _directory_size(data: bytes) -> int:
    """The central directory's size, from the end-of-central-directory record."""
    end = data.rfind(b"PK\x05\x06")
    return int(struct.unpack_from("<I", data, end + 12)[0])


def _docx_with_directory(size: int) -> bytes:
    """A DOCX whose central directory is exactly ``size`` bytes.

    The two DOCX entries, then empty entries whose per-entry comments (stored
    in the central directory only, so the file stays about ``size`` bytes)
    fill it. The last entry has a comment, so the directory's last byte is a
    comment byte: a reader that silently cuts the directory short still lists
    every entry.
    """
    fixed = ("[Content_Types].xml", "word/document.xml")
    filler = "customXml/item{:04d}.xml"
    head = 46 + len(filler.format(0))
    rest = size - sum(46 + len(name) for name in fixed)
    count = -(-rest // (head + 60_000))
    base, extra = divmod(rest - head * count, count)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name in fixed:
            archive.writestr(name, "<x/>")
        for index in range(count):
            entry = zipfile.ZipInfo(filler.format(index))
            entry.comment = b"c" * (base + (extra if index == count - 1 else 0))
            archive.writestr(entry, b"")
    data = buffer.getvalue()
    assert _directory_size(data) == size
    return data


def _docx_with_many_entries(count: int = 20_000) -> bytes:
    """A DOCX plus ``count`` tiny empty entries: a central directory just over 2 MiB."""
    names = [
        "[Content_Types].xml",
        "word/document.xml",
        *(f"customXml/{index:06d}".ljust(60, "x") for index in range(count)),
    ]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name in names:
            archive.writestr(name, b"")
    return buffer.getvalue()


def _with_unsupported_version(data: bytes) -> bytes:
    """Every central-directory entry needs version 25.5 to extract (byte 6 of its header)."""
    patched = bytearray(data)
    start = 0
    while (index := patched.find(b"PK\x01\x02", start)) != -1:
        patched[index + 6] = 0xFF
        start = index + 4
    return bytes(patched)


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


# ---------------------------------------------------------------------------
# Modules under test (imported lazily) and shared helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def att() -> ModuleType:
    import admino.attachments as module

    return module


@pytest.fixture
def at() -> ModuleType:
    import admino.attachment_types as module

    return module


def _patch_both(
    monkeypatch: pytest.MonkeyPatch, att: ModuleType, owner: Any, name: str, value: Any
) -> None:
    """Patch a function where it is defined and, if imported by name, in attachments."""
    monkeypatch.setattr(owner, name, value)
    if hasattr(att, name):
        monkeypatch.setattr(att, name, value)


async def _until(predicate: Callable[[], bool], seconds: float = _WAIT_S) -> bool:
    """Poll ``predicate`` on the loop until it holds or ``seconds`` pass; whether it held."""
    deadline = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        await asyncio.sleep(0.005)
    return True


def _detect(at: ModuleType, path: Path, filename: str) -> str:
    """The detected kind, or the refusal's reason."""
    try:
        return str(at.detect_kind(path, filename))
    except at.AttachmentRefusedError as exc:
        return str(exc.reason)


class _GatedDetection:
    """Stands in for ``detect_kind``: counts the calls running at once (and the
    peak), and holds each call in its worker thread until ``gate`` is set; then
    it runs the real detection. A call on the loop's own thread isn't held (it
    would block the loop)."""

    def __init__(self, real: Callable[[Path, str], Any]) -> None:
        self.real = real
        self.gate = threading.Event()
        self.entered = threading.Event()
        self.calls = 0
        self.running = 0
        self.peak = 0
        self._lock = threading.Lock()
        self._loop_thread = threading.get_ident()

    def __call__(self, path: Path, filename: str) -> Any:
        with self._lock:
            self.calls += 1
            self.running += 1
            self.peak = max(self.peak, self.running)
        self.entered.set()
        try:
            if threading.get_ident() != self._loop_thread:
                self.gate.wait(timeout=_WAIT_S + 2)
            return self.real(path, filename)
        finally:
            with self._lock:
                self.running -= 1


class _PerCallGatedDetection:
    """Stands in for ``detect_kind``: the n-th call (in the order the calls enter)
    waits in its worker thread until ``gates[n]`` is set, then runs the real
    detection. ``entered`` counts the calls that started."""

    def __init__(self, real: Callable[[Path, str], Any], calls: int = 8) -> None:
        self.real = real
        self.gates = [threading.Event() for _ in range(calls)]
        self.entered = 0
        self._lock = threading.Lock()

    def __call__(self, path: Path, filename: str) -> Any:
        with self._lock:
            index = self.entered
            self.entered += 1
        self.gates[index].wait(timeout=_WAIT_S + 2)
        return self.real(path, filename)

    def release_all(self) -> None:
        for gate in self.gates:
            gate.set()


# ---------------------------------------------------------------------------
# The upload service (admino.attachments) against the FakeDb
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _World:
    """ORG_ID (quota 100) with the member and a colleague, OTHER_ORG_ID (quota 100) with
    an outsider; one chat each; the attachments root under tmp_path (not created)."""

    db: FakeDb
    root: Path
    member: TenantContext
    colleague: TenantContext
    outsider: TenantContext
    chats: dict[uuid.UUID, uuid.UUID]


@pytest.fixture
def world(tmp_path: Path) -> _World:
    db = FakeDb()
    db.add_org(ORG_ID, storage_quota_bytes=_QUOTA)
    db.add_org(OTHER_ORG_ID, storage_quota_bytes=_QUOTA)
    tenants: dict[str, TenantContext] = {}
    chats: dict[uuid.UUID, uuid.UUID] = {}
    for name, org_id in (("member", ORG_ID), ("colleague", ORG_ID), ("outsider", OTHER_ORG_ID)):
        user_id = db.add_account(org_id=org_id)
        tenants[name] = TenantContext(org_id=org_id, user_id=user_id, role="editor")
        chats[user_id] = db.add_chat(user_id)
    return _World(
        db=db,
        root=tmp_path / "attachments",
        member=tenants["member"],
        colleague=tenants["colleague"],
        outsider=tenants["outsider"],
        chats=chats,
    )


class _ClientGoneError(Exception):
    """What a body raises when its client goes away mid-upload."""


class _CommitFailedError(Exception):
    """What the wrapped transaction raises in place of a successful COMMIT."""


class _ReleaseFailedError(RuntimeError):
    """What releasing the connection raises after a successful COMMIT: neither a
    cancellation nor a connection or socket error (the commit's outcome is known)."""


@dataclass
class _Body:
    """An upload body: ``chunks``, each after ``gap`` seconds (all of them only once
    ``gate`` is set, when given); with ``stall`` it then waits forever.
    ``started`` turns True when the upload asks for the first chunk."""

    chunks: Sequence[bytes]
    gap: float = 0.0
    stall: bool = False
    gate: asyncio.Event | None = None
    started: bool = False

    async def stream(self) -> AsyncIterator[bytes]:
        self.started = True
        if self.gate is not None:
            await self.gate.wait()
        for chunk in self.chunks:
            if self.gap:
                await asyncio.sleep(self.gap)
            yield chunk
        if self.stall:
            await asyncio.Event().wait()


class _HeldBody:
    """``head``, then it waits (``held`` set) until ``end(how)``: "rest" hands out
    ``tail`` (the body complete), "short" ends without it, "raise" raises
    ``_ClientGoneError``."""

    def __init__(self, head: bytes, tail: bytes) -> None:
        self.head = head
        self.tail = tail
        self.held = asyncio.Event()
        self._released = asyncio.Event()
        self._how = "rest"

    def end(self, how: str) -> None:
        self._how = how
        self._released.set()

    async def stream(self) -> AsyncIterator[bytes]:
        yield self.head
        self.held.set()
        await self._released.wait()
        if self._how == "raise":
            raise _ClientGoneError
        if self._how == "rest":
            yield self.tail


async def _upload(
    att: ModuleType,
    w: _World,
    body: AsyncIterator[bytes],
    *,
    declared: int,
    tenant: TenantContext | None = None,
) -> Any:
    """``upload_attachment`` of ``tenant`` (the member by default) into their own chat."""
    who = tenant or w.member
    return await att.upload_attachment(
        w.db.pool,
        who,
        w.chats[who.user_id],
        filename="notes.txt",
        declared_length=declared,
        body=body,
        root=w.root,
        max_bytes=_MAX_BYTES,
        ip=_IP,
    )


async def _try_upload(
    att: ModuleType,
    at: ModuleType,
    w: _World,
    body: AsyncIterator[bytes],
    *,
    declared: int,
    tenant: TenantContext | None = None,
) -> tuple[str, Any]:
    """("stored", the record) or ("refused", the reason)."""
    try:
        record = await _upload(att, w, body, declared=declared, tenant=tenant)
    except at.AttachmentRefusedError as exc:
        return "refused", exc.reason
    return "stored", record


async def _ended(at: ModuleType, task: asyncio.Task[Any]) -> str:
    """How a held upload ended: "stored", its refusal reason, "body_error" or "cancelled"."""
    try:
        await task
    except at.AttachmentRefusedError as exc:
        return str(exc.reason)
    except _ClientGoneError:
        return "body_error"
    except asyncio.CancelledError:
        return "cancelled"
    return "stored"


@contextlib.asynccontextmanager
async def _held(
    att: ModuleType, w: _World, *, declared: int, tenant: TenantContext | None = None
) -> AsyncIterator[tuple[_HeldBody, asyncio.Task[Any]]]:
    """An upload of ``declared`` bytes, held open mid-body (half of it written)."""
    half = declared // 2
    body = _HeldBody(b"a" * half, b"a" * (declared - half))
    task = asyncio.create_task(_upload(att, w, body.stream(), declared=declared, tenant=tenant))
    try:
        held = await _until(lambda: body.held.is_set() or task.done())
        assert held, "the held upload never asked for its second chunk"
        assert not task.done(), "the held upload ended before it was held"
        yield body, task
    finally:
        if not task.done():
            task.cancel()
        with contextlib.suppress(Exception, asyncio.CancelledError):
            await task


def _left_on_disk(root: Path) -> list[str]:
    """Every entry below an org directory of the root, relative to the root."""
    if not root.is_dir():
        return []
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.parent != root)


def _sizes(w: _World) -> list[int]:
    """The size of every stored attachments row, sorted."""
    return sorted(int(row["size_bytes"]) for row in w.db.attachments.values())


def _stored(w: _World) -> tuple[list[int], int, list[str]]:
    """(row sizes, file.upload events, entries on disk): what the uploads left."""
    return _sizes(w), len(w.db.audit_rows("file.upload")), _left_on_disk(w.root)


def _parts(w: _World) -> list[str]:
    return [entry for entry in _left_on_disk(w.root) if entry.endswith(".part")]


class TestAttachmentsReservation:
    """F1: an upload's declared length is reserved for its org until it ends."""

    async def test_attachments_concurrent_uploads_over_the_quota_refuse_one_before_its_body(
        self, att: ModuleType, at: ModuleType, world: _World
    ) -> None:
        """Quota 100, nothing stored: the member and a colleague each start an upload of
        60 at once (their bodies wait until one upload ended). The first reservation
        makes the other's pre-check refuse it, before it asks for a body chunk and
        before a .part of its own exists; the first is then stored."""
        go = asyncio.Event()
        bodies = [_Body([b"a" * 60], gate=go), _Body([b"b" * 60], gate=go)]
        tasks = [
            asyncio.create_task(_try_upload(att, at, world, body.stream(), declared=60, tenant=who))
            for body, who in zip(bodies, (world.member, world.colleague), strict=True)
        ]
        try:
            await _until(lambda: any(task.done() for task in tasks), seconds=1.0)
            on_disk_at_refusal = _left_on_disk(world.root)
        finally:
            go.set()
        outcomes = await asyncio.gather(*tasks)
        refused = [
            (outcome, body.started)
            for outcome, body in zip(outcomes, bodies, strict=True)
            if outcome[0] == "refused"
        ]
        stored = [outcome[1] for outcome in outcomes if outcome[0] == "stored"]

        assert refused == [(("refused", "storage_quota_exceeded"), False)]
        assert len(stored) == 1
        assert on_disk_at_refusal == [f"{ORG_ID}/{stored[0].id}.part"]
        assert _stored(world) == ([60], 1, [f"{ORG_ID}/{stored[0].id}"])

    async def test_attachments_reservation_refuses_one_byte_over_and_stores_an_exact_fit(
        self, att: ModuleType, at: ModuleType, world: _World
    ) -> None:
        """The member's 60 are held mid-body. A colleague's 41 (0 used + 60 reserved + 41
        > 100) is refused before its body; 40 fills the quota exactly and is stored
        while the 60 still stream (the commit check counts stored rows only, not the
        reservation); then the 60 end and are stored too (40 + 60 = 100)."""
        over = _Body([b"b" * 41])
        async with _held(att, world, declared=60) as (body, task):
            one_byte_over = await _try_upload(
                att, at, world, over.stream(), declared=41, tenant=world.colleague
            )
            exact_fit = await _try_upload(
                att, at, world, _Body([b"c" * 40]).stream(), declared=40, tenant=world.colleague
            )
            body.end("rest")
            first = await _ended(at, task)

        assert (one_byte_over, over.started) == (("refused", "storage_quota_exceeded"), False)
        assert (exact_fit[0], first) == ("stored", "stored")
        assert _sizes(world) == [40, 60]

    @pytest.mark.parametrize(
        "ending", ["stored", "content_length_mismatch", "body_error", "cancelled"]
    )
    async def test_attachments_reservation_is_released_when_the_upload_ends(
        self, att: ModuleType, at: ModuleType, world: _World, ending: str
    ) -> None:
        """While the member's 60 stream, a colleague's 50 is refused before its body.
        Once the 60 end (each way), their reservation is gone: an upload that fills
        exactly what is left (40 after a stored 60, else all 100) is stored, and no
        .part is left behind."""
        blocked = _Body([b"b" * 50])
        async with _held(att, world, declared=60) as (body, task):
            while_open = await _try_upload(
                att, at, world, blocked.stream(), declared=50, tenant=world.colleague
            )
            if ending == "cancelled":
                task.cancel()
            else:
                body.end(
                    {"stored": "rest", "content_length_mismatch": "short", "body_error": "raise"}[
                        ending
                    ]
                )
            ended = await _ended(at, task)
        left = _QUOTA - (60 if ending == "stored" else 0)
        after = await _try_upload(
            att, at, world, _Body([b"c" * left]).stream(), declared=left, tenant=world.colleague
        )

        assert (while_open, blocked.started) == (("refused", "storage_quota_exceeded"), False)
        assert (ended, after[0]) == (ending, "stored")
        assert _sizes(world) == sorted([left, *([60] if ending == "stored" else [])])
        assert _parts(world) == []

    async def test_attachments_reservation_is_per_org_and_org_wide(
        self, att: ModuleType, at: ModuleType, world: _World
    ) -> None:
        """While the member's 60 stream: the other org's upload of its whole quota (100)
        is stored (the reservation is the member's org's only), and a colleague's 50 in
        the member's org is refused before its body (it counts for the whole org)."""
        colleague_body = _Body([b"b" * 50])
        async with _held(att, world, declared=60) as (body, task):
            other_org = await _try_upload(
                att, at, world, _Body([b"d" * 100]).stream(), declared=100, tenant=world.outsider
            )
            same_org = await _try_upload(
                att, at, world, colleague_body.stream(), declared=50, tenant=world.colleague
            )
            body.end("rest")
            await _ended(at, task)

        assert (other_org[0], same_org, colleague_body.started) == (
            "stored",
            ("refused", "storage_quota_exceeded"),
            False,
        )

    async def test_attachments_reservation_holds_while_the_upload_is_detected(
        self, att: ModuleType, at: ModuleType, world: _World, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The member's 60 are fully received and held in type detection: a colleague's
        50 is still refused before its body (the reservation lasts until the upload
        ends, not until its body is in); the 60 are then stored."""
        detection = _GatedDetection(at.detect_kind)
        _patch_both(monkeypatch, att, at, "detect_kind", detection)
        first = asyncio.create_task(
            _try_upload(att, at, world, _Body([b"a" * 60]).stream(), declared=60)
        )
        second_body = _Body([b"b" * 50])
        second: asyncio.Task[tuple[str, Any]] | None = None
        try:
            assert await _until(detection.entered.is_set), "the upload never reached detection"
            second = asyncio.create_task(
                _try_upload(
                    att, at, world, second_body.stream(), declared=50, tenant=world.colleague
                )
            )
            await _until(second.done, seconds=1.0)
            refused_during_detection = second.done()
        finally:
            detection.gate.set()
        outcomes = await asyncio.gather(first, second)

        assert (refused_during_detection, outcomes[1], second_body.started) == (
            True,
            ("refused", "storage_quota_exceeded"),
            False,
        )
        assert outcomes[0][0] == "stored"


class TestAttachmentsStallTimeout:
    """F1: a body that stops sending ends the upload."""

    def test_attachments_stall_timeout_is_30_seconds(self, att: ModuleType) -> None:
        assert getattr(att, "STALL_TIMEOUT_S", None) == 30.0

    @pytest.mark.parametrize("chunks_first", [0, 1], ids=["before-the-first-chunk", "mid-body"])
    async def test_attachments_stalled_body_is_content_length_mismatch(
        self,
        att: ModuleType,
        at: ModuleType,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
        chunks_first: int,
    ) -> None:
        """No chunk within STALL_TIMEOUT_S (0.05 s here): content_length_mismatch, no row,
        no event, no file and no .part; its reservation is released (an upload of the
        whole quota is stored afterwards)."""
        monkeypatch.setattr(att, "STALL_TIMEOUT_S", _SHORT_STALL_S, raising=False)
        body = _Body([b"a" * 30] * chunks_first, stall=True)

        try:
            outcome = await asyncio.wait_for(
                _try_upload(att, at, world, body.stream(), declared=60), _WAIT_S
            )
        except TimeoutError:
            outcome = ("still streaming after", _WAIT_S)
        left = _stored(world)
        after = await _try_upload(
            att, at, world, _Body([b"c" * _QUOTA]).stream(), declared=_QUOTA, tenant=world.colleague
        )

        assert (outcome, left, after[0]) == (
            ("refused", "content_length_mismatch"),
            ([], 0, []),
            "stored",
        )

    async def test_attachments_stall_timeout_is_per_chunk_not_per_upload(
        self, att: ModuleType, at: ModuleType, world: _World, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Timeout 0.5 s: a body sending a chunk every 0.1 s for 0.8 s in all is stored;
        one that sends two chunks and then pauses is content_length_mismatch."""
        monkeypatch.setattr(att, "STALL_TIMEOUT_S", 0.5, raising=False)
        flowing = _Body([b"a" * 5] * 8, gap=0.1)
        stalling = _Body([b"b" * 5] * 2, gap=0.1, stall=True)

        stored = await asyncio.wait_for(
            _try_upload(att, at, world, flowing.stream(), declared=40), _WAIT_S
        )
        try:
            stalled = await asyncio.wait_for(
                _try_upload(att, at, world, stalling.stream(), declared=40), _WAIT_S
            )
        except TimeoutError:
            stalled = ("still streaming after", _WAIT_S)

        assert (stored[0], stalled) == ("stored", ("refused", "content_length_mismatch"))


class TestAttachmentsDetectConcurrency:
    """F2: upload-time type detection is bounded."""

    def test_attachments_detect_concurrency_is_2(self, att: ModuleType) -> None:
        assert getattr(att, "DETECT_CONCURRENCY", None) == 2

    async def test_attachments_upload_runs_at_most_two_detections_at_once(
        self, att: ModuleType, at: ModuleType, world: _World, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Five uploads at once, every detection held: two run, the others wait (none
        enters within 0.3 s); once released, all five are stored and the peak stayed 2."""
        detection = _GatedDetection(at.detect_kind)
        _patch_both(monkeypatch, att, at, "detect_kind", detection)
        tasks = [
            asyncio.create_task(
                _try_upload(att, at, world, _Body([b"t" * 10]).stream(), declared=10)
            )
            for _ in range(5)
        ]
        try:
            await _until(lambda: detection.calls >= 2)
            await asyncio.sleep(0.3)
            peak_while_held = detection.peak
        finally:
            detection.gate.set()
        outcomes = await asyncio.gather(*tasks)

        assert (peak_while_held, detection.peak) == (2, 2)
        assert ([outcome[0] for outcome in outcomes], detection.calls) == (["stored"] * 5, 5)

    async def test_attachments_cancelled_upload_keeps_its_detection_slot_until_its_thread_ends(
        self, att: ModuleType, at: ModuleType, world: _World, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression guard (Decision 18: at most 2 files type-checked at once): two
        uploads hold both detection slots and a third waits. Cancelling the first
        doesn't stop its detection thread, so the third's detection doesn't start
        (none within 0.3 s) until that thread is released; then it does, and the
        second and third are stored."""
        detection = _PerCallGatedDetection(at.detect_kind)
        _patch_both(monkeypatch, att, at, "detect_kind", detection)

        def start() -> asyncio.Task[tuple[str, Any]]:
            body = _Body([b"t" * 10]).stream()
            return asyncio.create_task(_try_upload(att, at, world, body, declared=10))

        first = start()
        others: list[asyncio.Task[tuple[str, Any]]] = []
        try:
            assert await _until(lambda: detection.entered >= 1), "no detection started"
            others.append(start())
            assert await _until(lambda: detection.entered >= 2), "no second detection"
            others.append(start())
            await asyncio.sleep(0.1)
            entered_before_cancel = detection.entered
            first.cancel()
            await asyncio.wait([first], timeout=_WAIT_S)
            first_cancelled = first.cancelled()
            await asyncio.sleep(0.3)
            entered_while_its_thread_runs = detection.entered
            detection.gates[0].set()
            started_once_it_ended = await _until(lambda: detection.entered >= 3)
        finally:
            detection.release_all()
        outcomes = await asyncio.gather(*others)

        assert (
            entered_before_cancel,
            first_cancelled,
            entered_while_its_thread_runs,
            started_once_it_ended,
        ) == (2, True, 2, True)
        assert [outcome[0] for outcome in outcomes] == ["stored", "stored"]


class TestAttachmentsAfterCommit:
    """F4: only an upload that didn't commit removes its files."""

    async def test_attachments_failure_after_the_commit_keeps_the_row_and_the_file(
        self, att: ModuleType, world: _World, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The transaction commits, then releasing the connection is cancelled: the
        cancellation propagates, and the row, its file.upload event and the file
        <id> (with the bytes) stay; no .part."""
        db = world.db
        real_acquire = db.pool.acquire

        @contextlib.asynccontextmanager
        async def acquire() -> AsyncIterator[Any]:
            async with real_acquire() as conn:
                yield conn
            if db.transactions and db.transactions[-1][1] == "commit":
                raise asyncio.CancelledError

        monkeypatch.setattr(db.pool, "acquire", acquire)
        data = b"Protokoll der Sitzung vom Montag.\n"

        with pytest.raises(asyncio.CancelledError):
            await _upload(att, world, _Body([data]).stream(), declared=len(data))
        ids = list(db.attachments)
        stored = world.root / str(ORG_ID) / str(ids[0]) if ids else None
        content = stored.read_bytes() if stored is not None and stored.exists() else None

        assert [outcome for _, outcome in db.transactions] == ["commit"]
        assert (len(ids), len(db.audit_rows("file.upload"))) == (1, 1)
        assert (_left_on_disk(world.root), content) == ([f"{ORG_ID}/{ids[0]}"], data)

    async def test_attachments_other_error_after_the_commit_keeps_the_row_and_the_file(
        self, att: ModuleType, world: _World, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression guard: the transaction commits, then releasing the connection
        raises a RuntimeError (not an unknown-commit-outcome error): it propagates, and
        the row, its file.upload event and the file <id> (with the bytes) stay; no
        .part. A committed upload never removes its file, whatever fails next."""
        db = world.db
        real_acquire = db.pool.acquire

        @contextlib.asynccontextmanager
        async def acquire() -> AsyncIterator[Any]:
            async with real_acquire() as conn:
                yield conn
            if db.transactions and db.transactions[-1][1] == "commit":
                raise _ReleaseFailedError

        monkeypatch.setattr(db.pool, "acquire", acquire)
        data = b"Protokoll der Sitzung vom Dienstag.\n"

        with pytest.raises(_ReleaseFailedError):
            await _upload(att, world, _Body([data]).stream(), declared=len(data))
        ids = list(db.attachments)
        stored = world.root / str(ORG_ID) / str(ids[0]) if ids else None
        content = stored.read_bytes() if stored is not None and stored.exists() else None

        assert [outcome for _, outcome in db.transactions] == ["commit"]
        assert (len(ids), len(db.audit_rows("file.upload"))) == (1, 1)
        assert (_left_on_disk(world.root), content) == ([f"{ORG_ID}/{ids[0]}"], data)

    async def test_attachments_failed_commit_removes_the_part_and_the_renamed_file(
        self, att: ModuleType, world: _World, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression guard: the COMMIT itself fails, after the rename into <id>: the
        transaction rolls back and neither <id> nor <id>.part is left (nothing marks
        the upload committed before the commit succeeded)."""
        db = world.db
        real_acquire = db.pool.acquire
        on_disk_at_commit: list[list[str]] = []

        @contextlib.asynccontextmanager
        async def acquire() -> AsyncIterator[Any]:
            async with real_acquire() as conn:
                real_transaction = conn.transaction

                @contextlib.asynccontextmanager
                async def failing_commit() -> AsyncIterator[None]:
                    async with real_transaction():
                        yield
                        on_disk_at_commit.append(_left_on_disk(world.root))
                        raise _CommitFailedError

                conn.transaction = failing_commit
                yield conn

        monkeypatch.setattr(db.pool, "acquire", acquire)
        data = b"Protokoll der Sitzung vom Montag.\n"

        with pytest.raises(_CommitFailedError):
            await _upload(att, world, _Body([data]).stream(), declared=len(data))

        assert [len(entries) for entries in on_disk_at_commit] == [1]
        assert not on_disk_at_commit[0][0].endswith(".part")
        assert [outcome for _, outcome in db.transactions] == ["rollback:_CommitFailedError"]
        assert _stored(world) == ([], 0, [])


# ---------------------------------------------------------------------------
# attachment_types: the ZIP central directory and zipfile's errors
# ---------------------------------------------------------------------------


class TestZipDirectoryCap:
    """F2: zipfile never reads more than 2 MiB of a central directory."""

    def test_attachment_types_zip_directory_cap_is_2_mib(self, at: ModuleType) -> None:
        assert getattr(at, "MAX_ZIP_DIRECTORY_BYTES", None) == 2 * 1024 * 1024

    def test_attachment_types_zip_directory_cap_boundary(
        self, at: ModuleType, tmp_path: Path
    ) -> None:
        """A directory of exactly 2 MiB is listed (docx); one byte more is corrupted_file,
        though that byte sits in the last entry's comment; a normal DOCX and XLSX are
        still detected."""
        files = {
            "directory-at-the-cap": _docx_with_directory(_DIRECTORY_CAP),
            "directory-one-byte-over": _docx_with_directory(_DIRECTORY_CAP + 1),
            "docx": _zip_of(_DOCX_NAMES),
            "xlsx": _zip_of(_XLSX_NAMES),
        }

        outcomes = {
            label: _detect(at, _write(tmp_path, f"{label}.part", data), "file.docx")
            for label, data in files.items()
        }

        assert outcomes == {
            "directory-at-the-cap": "docx",
            "directory-one-byte-over": "corrupted_file",
            "docx": "docx",
            "xlsx": "xlsx",
        }

    def test_attachment_types_zip_with_a_directory_of_many_tiny_entries_is_corrupted(
        self, at: ModuleType, tmp_path: Path
    ) -> None:
        """A DOCX padded with 20,000 empty entries: its directory passes 2 MiB."""
        data = _docx_with_many_entries()
        assert _directory_size(data) > _DIRECTORY_CAP

        assert _detect(at, _write(tmp_path, "many.part", data), "file.docx") == "corrupted_file"

    def test_attachment_types_zip_directory_is_never_read_past_the_cap(
        self, at: ModuleType, tmp_path: Path
    ) -> None:
        """A DOCX with a 24 MiB directory is corrupted_file, and detecting it allocates
        less than 8 MiB at peak (listing it uncapped takes about 48 MiB): the
        directory is refused while it is read, not after."""
        path = _write(tmp_path, "huge.part", _docx_with_directory(24 * _MIB))
        warm_up = _write(tmp_path, "warm.part", _zip_of(_DOCX_NAMES))
        assert _detect(at, warm_up, "file.docx") == "docx"

        tracemalloc.start()
        try:
            tracemalloc.reset_peak()
            outcome = _detect(at, path, "file.docx")
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        assert outcome == "corrupted_file"
        assert peak < 8 * _MIB, f"peak {peak / _MIB:.1f} MiB"

    def test_attachment_types_zipfile_is_given_a_read_capped_file(
        self, at: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """What zipfile.ZipFile receives is a file (the read-capped wrapper, not the path)
        whose every read from the start of a 24 MiB-directory archive, the unsized ones
        (read(), read(-1), read(None)) and one past the cap included, hands out at most
        2 MiB or refuses; the archive is corrupted_file."""
        path = _write(tmp_path, "huge.part", _docx_with_directory(24 * _MIB))
        real_zipfile = zipfile.ZipFile
        probes: dict[str, object] = {}

        def probing(file: Any, *args: Any, **kwargs: Any) -> Any:
            if not (hasattr(file, "read") and hasattr(file, "seek")):
                probes["given"] = type(file).__name__
                return real_zipfile(file, *args, **kwargs)
            sizes: tuple[tuple[str, int | None], ...] = (
                ("read()", -2),
                ("read(-1)", -1),
                ("read(None)", None),
                ("read(cap + 1)", _DIRECTORY_CAP + 1),
            )
            for label, size in sizes:
                file.seek(0)
                try:
                    data = file.read() if size == -2 else file.read(size)
                except Exception:
                    probes[label] = "capped"
                else:
                    probes[label] = "capped" if len(data) <= _DIRECTORY_CAP else len(data)
            file.seek(0)
            return real_zipfile(file, *args, **kwargs)

        monkeypatch.setattr(zipfile, "ZipFile", probing)
        if hasattr(at, "ZipFile"):
            monkeypatch.setattr(at, "ZipFile", probing)

        outcome = _detect(at, path, "file.docx")

        assert (outcome, probes) == (
            "corrupted_file",
            {
                "read()": "capped",
                "read(-1)": "capped",
                "read(None)": "capped",
                "read(cap + 1)": "capped",
            },
        )


class TestZipfileErrors:
    """F3: whatever zipfile raises while listing (MemoryError aside) is corrupted_file."""

    def test_attachment_types_zip_entry_with_an_unsupported_version_is_corrupted(
        self, at: ModuleType, tmp_path: Path
    ) -> None:
        """A DOCX whose entries need version 25.5 to extract: zipfile raises
        NotImplementedError while listing it; detection answers corrupted_file."""
        data = _with_unsupported_version(_zip_of(_DOCX_NAMES))
        with pytest.raises(NotImplementedError), zipfile.ZipFile(io.BytesIO(data)):
            pass

        assert _detect(at, _write(tmp_path, "v.part", data), "file.docx") == "corrupted_file"

    def test_attachment_types_any_zipfile_error_but_memory_error_is_corrupted(
        self, at: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """zipfile raising an exception nobody foresaw is corrupted_file; a MemoryError
        isn't swallowed."""

        class _UnforeseenZipError(Exception):
            pass

        path = _write(tmp_path, "z.part", _zip_of(_DOCX_NAMES))
        outcomes: dict[str, str] = {}
        for error in (_UnforeseenZipError, MemoryError):

            def raising(*args: Any, error: type[BaseException] = error, **kwargs: Any) -> Any:
                raise error

            monkeypatch.setattr(zipfile, "ZipFile", raising)
            if hasattr(at, "ZipFile"):
                monkeypatch.setattr(at, "ZipFile", raising)
            try:
                outcomes[error.__name__] = _detect(at, path, "file.docx")
            except MemoryError:
                outcomes[error.__name__] = "raised"

        assert outcomes == {"_UnforeseenZipError": "corrupted_file", "MemoryError": "raised"}


# ---------------------------------------------------------------------------
# HTTP: the app from create_app() against the tenancy world
# ---------------------------------------------------------------------------


def _submit_signature(pool: Any, root: Any, attachment_id: Any, org_id: Any) -> None:
    """The parameters of the contract's ``ProcessingPool.submit`` (names a recorded call)."""


@dataclass
class _Processing:
    """Stands in for ``server._processing``: records each ``submit(pool, root, id, org)``."""

    calls: list[tuple[Any, Any, Any, Any]] = field(default_factory=list)

    def submit(self, *args: Any, **kwargs: Any) -> None:
        bound = inspect.signature(_submit_signature).bind(*args, **kwargs).arguments
        self.calls.append((bound["pool"], bound["root"], bound["attachment_id"], bound["org_id"]))

    async def join(self) -> None:
        return None

    async def close(self) -> None:
        return None


@dataclass(frozen=True)
class _Env:
    world: World
    root: Path
    app: FastAPI
    processing: _Processing


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> _Env:
    """Orgs A and B (OA/ED each, a 64 MiB quota) behind the fake database, the
    attachments root in tmp_path, roomy rate limits, ``_processing`` recorded."""
    db = FakeDb()
    world = build_world(db)
    for org_id in (ORG_ID, OTHER_ORG_ID):
        db.add_org(org_id, storage_quota_bytes=64 * _MIB)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    root = tmp_path / "attachments"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", root)
    app = make_app()
    processing = _Processing()
    # After create_app (it installs a fresh pool); routes look it up at call time.
    monkeypatch.setattr(server, "_processing", processing, raising=False)
    return _Env(world=world, root=root, app=app, processing=processing)


def _set_files(env: _Env, monkeypatch: pytest.MonkeyPatch, **files: int) -> None:
    """Store platform file limits in the platform row and in the primed settings cache."""
    row = env.world.db.platform_row()
    assert row is not None
    row.update(files)
    stored = scoped_settings._platform_cache
    assert stored is not None
    updated = stored.model_copy(update={"files": stored.files.model_copy(update=files)})
    monkeypatch.setattr(scoped_settings, "_platform_cache", updated)


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


def _outcome(response: httpx.Response) -> tuple[int, Any]:
    try:
        body = response.json()
    except ValueError:
        body = response.text
    return response.status_code, body


def _trash(db: FakeDb, chat_id: uuid.UUID) -> None:
    row = db.chats[next(key for key in db.chats if str(key) == str(chat_id))]
    row["deleted_at"] = datetime.now(UTC)


@dataclass
class _Wire:
    """A raw-ASGI body handing out ``chunks`` (the last one ends it), then waiting
    forever; ``asked`` counts every ``receive()`` call."""

    chunks: Sequence[bytes]
    asked: int = 0

    async def receive(self) -> Message:
        self.asked += 1
        if self.asked <= len(self.chunks):
            more = self.asked < len(self.chunks)
            return {"type": "http.request", "body": self.chunks[self.asked - 1], "more_body": more}
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


class _HeldWire:
    """A raw-ASGI body: ``_HEAD`` (more to come), then it waits (``held`` set) until
    ``end(how)``: "rest" sends ``rest`` (the body complete), "over" more than
    declared, "disconnect" ``http.disconnect``. Never ended, it waits forever."""

    def __init__(self, rest: bytes = _REST) -> None:
        self.rest = rest
        self.asked = 0
        self.held = asyncio.Event()
        self._released = asyncio.Event()
        self._how = "rest"

    @property
    def length(self) -> int:
        """The Content-Length to declare: ``_HEAD`` plus ``rest``."""
        return len(_HEAD) + len(self.rest)

    def end(self, how: str) -> None:
        self._how = how
        self._released.set()

    async def receive(self) -> Message:
        self.asked += 1
        if self.asked == 1:
            return {"type": "http.request", "body": _HEAD, "more_body": True}
        if self.asked == 2:
            self.held.set()
            await self._released.wait()
            if self._how == "disconnect":
                return {"type": "http.disconnect"}
            if self._how == "over":
                return {"type": "http.request", "body": self.rest + b"!", "more_body": True}
            return {"type": "http.request", "body": self.rest, "more_body": False}
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


async def _raw_upload(
    app: FastAPI,
    caller: Account,
    chat_id: uuid.UUID,
    receive: Receive,
    *,
    length: int,
    name: bytes | None = b"notes.txt",
    timeout: float = 10.0,
) -> tuple[int | None, Any]:
    """One upload through the whole ASGI app: (status, JSON body or None), or
    (None, "no answer ...") when the app hasn't answered within ``timeout``."""
    headers = [
        (b"host", b"testserver"),
        (b"content-type", b"application/octet-stream"),
        (b"cookie", caller.cookie["Cookie"].encode("ascii")),
        (b"content-length", str(length).encode("ascii")),
    ]
    if name is not None:
        headers.append((b"x-attachment-name", name))
    path = f"/api/chats/{chat_id}/attachments"
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

    try:
        await asyncio.wait_for(app(scope, receive, send), timeout=timeout)
    except TimeoutError:
        return None, f"no answer within {timeout} s"
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    raw = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, (json.loads(raw) if raw else None)


async def _simple_upload(env: _Env, caller: Account, chat_id: uuid.UUID) -> tuple[int | None, Any]:
    wire = _Wire([_TEXT])
    return await _raw_upload(env.app, caller, chat_id, wire.receive, length=len(_TEXT))


async def _roomy_upload_bucket(
    env: _Env, monkeypatch: pytest.MonkeyPatch, *callers: Account
) -> None:
    """Create each caller's upload bucket with a burst of 50 (at the roomy rate), so no
    429 below comes from the token bucket. A nameless upload (400) creates it."""
    _set_files(env, monkeypatch, max_files_per_message=50)
    for caller in callers:
        chat = env.world.db.add_chat(caller.user_id)
        warm = await _raw_upload(env.app, caller, chat, _Wire([]).receive, length=1, name=None)
        assert warm[0] == 400, warm


@dataclass
class _Open:
    wire: _HeldWire
    task: asyncio.Task[tuple[int | None, Any]]
    chat: uuid.UUID


def _is_held(upload: _Open) -> bool:
    return upload.wire.held.is_set() or upload.task.done()


@contextlib.asynccontextmanager
async def _open_uploads(env: _Env, caller: Account, count: int) -> AsyncIterator[list[_Open]]:
    """``count`` uploads of ``caller``, each into a chat of its own, held open mid-body."""
    opened: list[_Open] = []
    try:
        for _ in range(count):
            wire = _HeldWire()
            chat = env.world.db.add_chat(caller.user_id)
            task = asyncio.create_task(
                _raw_upload(env.app, caller, chat, wire.receive, length=wire.length)
            )
            upload = _Open(wire=wire, task=task, chat=chat)
            opened.append(upload)
            assert await _until(functools.partial(_is_held, upload)), "upload never held"
            assert not task.done(), f"an upload to hold ended at once: {task.result()}"
        yield opened
    finally:
        for upload in opened:
            if not upload.task.done():
                upload.wire.end("rest")
        for upload in opened:
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await asyncio.wait_for(upload.task, _WAIT_S)


class TestAttachmentsApiOpenUploads:
    """F1 over HTTP: the per-user cap on open uploads, the reservation, the stall."""

    async def test_attachments_api_upload_over_the_open_upload_cap_is_429_unread(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """max_files_per_message 2 and two uploads of the Editor held mid-body: a third
        answers 429 without asking receive for anything, and stores nothing (no row,
        no event, no file or .part, no submit)."""
        editor = env.world.a["editor"]
        await _roomy_upload_bucket(env, monkeypatch, editor)
        _set_files(env, monkeypatch, max_files_per_message=2)
        chat = env.world.db.add_chat(editor.user_id)

        async with _open_uploads(env, editor, 2):
            before = _state(env)
            third = _Wire([_TEXT])
            outcome = await _raw_upload(env.app, editor, chat, third.receive, length=len(_TEXT))
            after = _state(env)

        assert (outcome, third.asked) == (_RATE_LIMITED, 0)
        assert after == before

    async def test_attachments_api_upload_open_upload_cap_is_per_user(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """While the Editor holds two (the cap), the Org Admin of the same org uploads
        (201); the Editor's own third is 429."""
        editor, org_admin = env.world.a["editor"], env.world.a["org_admin"]
        await _roomy_upload_bucket(env, monkeypatch, editor, org_admin)
        _set_files(env, monkeypatch, max_files_per_message=2)

        async with _open_uploads(env, editor, 2):
            colleague = await _simple_upload(
                env, org_admin, env.world.db.add_chat(org_admin.user_id)
            )
            own = await _simple_upload(env, editor, env.world.db.add_chat(editor.user_id))

        assert (colleague[0], own) == (201, _RATE_LIMITED)

    @pytest.mark.parametrize(
        ("ending", "status"),
        [
            ("stored", 201),
            ("refused", 400),
            ("chat-gone", 404),
            ("disconnect", None),
            ("cancelled", None),
        ],
    )
    async def test_attachments_api_upload_slot_is_freed_when_an_open_upload_ends(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch, ending: str, status: int | None
    ) -> None:
        """Cap 2, two held, a third is 429. One held upload then ends (stored; refused
        for a body past its Content-Length; 404 as its chat was trashed meanwhile; the
        client disconnects; the request is cancelled): the next upload is 201."""
        editor = env.world.a["editor"]
        await _roomy_upload_bucket(env, monkeypatch, editor)
        _set_files(env, monkeypatch, max_files_per_message=2)
        chat = env.world.db.add_chat(editor.user_id)

        async with _open_uploads(env, editor, 2) as opened:
            third = await _simple_upload(env, editor, chat)
            first = opened[0]
            if ending == "cancelled":
                first.task.cancel()
            elif ending == "chat-gone":
                _trash(env.world.db, first.chat)
                first.wire.end("rest")
            else:
                first.wire.end(
                    {"stored": "rest", "refused": "over", "disconnect": "disconnect"}[ending]
                )
            try:
                ended = (await asyncio.wait_for(first.task, _WAIT_S))[0]
            except asyncio.CancelledError:
                ended = None
            next_one = await _simple_upload(env, editor, chat)

        assert third == _RATE_LIMITED
        assert (ended if status is not None else None, next_one[0]) == (status, 201)

    async def test_attachments_api_upload_stalled_body_is_400_and_frees_the_slot(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Stall timeout 0.05 s, cap 1: a body that sends one chunk of 22 declared bytes
        and then nothing is 400 content_length_mismatch with nothing stored (no .part
        left); the user's next upload is 201."""
        import admino.attachments as attachments

        monkeypatch.setattr(attachments, "STALL_TIMEOUT_S", _SHORT_STALL_S, raising=False)
        editor = env.world.a["editor"]
        await _roomy_upload_bucket(env, monkeypatch, editor)
        _set_files(env, monkeypatch, max_files_per_message=1)
        chat = env.world.db.add_chat(editor.user_id)
        before = _state(env)
        stalled = _HeldWire()

        outcome = await _raw_upload(
            env.app, editor, chat, stalled.receive, length=stalled.length, timeout=_WAIT_S
        )
        left = _state(env)
        next_one = await _simple_upload(env, editor, chat)

        assert (outcome, stalled.held.is_set()) == (_LENGTH_MISMATCH, True)
        assert left == before
        assert next_one[0] == 201

    async def test_attachments_api_upload_reserved_quota_is_413_before_the_body(
        self, env: _Env
    ) -> None:
        """Quota 150, nothing stored: while the Editor's upload of 100 is held mid-body,
        the Org Admin's 60 is 413 storage_quota_exceeded without asking receive for
        anything, nothing of it stored; the Editor's upload is then stored."""
        db = env.world.db
        db.add_org(ORG_ID, storage_quota_bytes=150)
        editor, org_admin = env.world.a["editor"], env.world.a["org_admin"]
        wire = _HeldWire(rest=b"h" * (100 - len(_HEAD)))
        held = asyncio.create_task(
            _raw_upload(env.app, editor, db.add_chat(editor.user_id), wire.receive, length=100)
        )
        try:
            assert await _until(wire.held.is_set), "the upload of 100 was never held"
            before = _state(env)
            second = _Wire([b"s" * 60])
            refused = await _raw_upload(
                env.app, org_admin, db.add_chat(org_admin.user_id), second.receive, length=60
            )
            after = _state(env)
        finally:
            wire.end("rest")
        stored = await asyncio.wait_for(held, _WAIT_S)

        assert (refused, second.asked) == (_QUOTA_EXCEEDED, 0)
        assert after == before
        assert stored[0] == 201


class TestAttachmentsApiZipErrors:
    """F2/F3 over HTTP: a ZIP zipfile can't (or mustn't) list is 422, never a 500."""

    @pytest.mark.parametrize("case", ["unsupported-zip-version", "zip-directory-over-the-cap"])
    def test_attachments_api_upload_unlistable_zip_is_422_corrupted_file(
        self, env: _Env, case: str
    ) -> None:
        if case == "unsupported-zip-version":
            data = _with_unsupported_version(_zip_of(_DOCX_NAMES))
        else:
            data = _docx_with_many_entries()
        editor = env.world.a["editor"]
        chat = env.world.db.add_chat(editor.user_id)
        client = make_client(env.app, raise_server_exceptions=False)
        before = _state(env)

        response = client.post(
            f"/api/chats/{chat}/attachments",
            content=data,
            headers={
                **editor.cookie,
                "X-Attachment-Name": "Vertrag.docx",
                "Content-Type": _DOCX_MEDIA_TYPE,
            },
        )

        assert _outcome(response) == _CORRUPTED
        assert _state(env) == before
