"""Upload deadlines and the unknown commit outcome (GH-187 re-audit, contract section 8).

Pinned against the FakeDb, ``tmp_path`` and the app from ``create_app()`` (raw ASGI calls
whose ``receive`` the test controls):

F5, the total upload time (security-audit-fix1 L-1, issue Decision 18):
- ``attachments.UPLOAD_GRACE_S`` is 120.0 and ``attachments.UPLOAD_MIN_RATE_BYTES_S`` is
  32 KiB: besides the per-chunk ``STALL_TIMEOUT_S``, the whole body must arrive within
  ``UPLOAD_GRACE_S + declared_length / UPLOAD_MIN_RATE_BYTES_S``.
- With the constants patched small: a body that keeps sending (it never stalls) but runs
  past the total ends with ``content_length_mismatch`` (not before the grace): no row, no
  event, no file, no ``.part``, the reservation released (an upload of the org's whole
  quota is then stored).
- Each wait for a chunk ends at the earlier of the two deadlines: one long wait past the
  total ends at the total, long before the stall timeout; and (regression guard) a stall
  shorter than the total still ends the upload at the stall timeout.
- The total scales with the declared length: two bodies with the same chunk cadence and
  duration; the one declaring few bytes (a total of a tenth of the duration) is refused,
  the one declaring many (a total over 3x the duration) is stored although its body took
  twelve times the grace.
- Over HTTP the drip answers 400 ``content_length_mismatch``, stores nothing and frees the
  user's open-upload slot (cap 1: the next upload is 201).

F6, the unknown commit outcome (security-audit-fix1 L-2):
- An exception other than a server-reported PostgreSQL error that interrupts the COMMIT
  itself propagates, removes ``<id>.part`` and keeps ``<id>`` with its bytes: a
  cancellation, the lost connection (asyncpg raises ``ConnectionDoesNotExistError``
  itself, a ``PostgresError`` subclass no server sent), an ``InterfaceError`` and an
  ``OSError``. That holds whether the server applied the COMMIT (the row and the event
  stay) or not (no row; the 24 h stray-file sweep removes the file later).
- Regression guards: a COMMIT the server refuses (a ``SerializationError``) and a failure
  before the COMMIT was sent (a cancellation right after the rename) remove both ``<id>``
  and ``<id>.part``.

The new names are only read inside the tests (monkeypatched with ``raising=False``), so
the file collects against the code before the fixes. Files live under tmp_path; no
network, no real PostgreSQL. Timings keep margins of 3x or more.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

import asyncpg
import pytest

from admino import organizations, scoped_settings, server
from admino.tenancy import TenantContext
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb
from tests.tenancy_world import (
    CLIENT_IP,
    build_world,
    make_app,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Sequence
    from pathlib import Path
    from types import ModuleType

    from fastapi import FastAPI
    from starlette.types import Message, Receive

    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MIB: Final = 1_048_576
_QUOTA: Final = 4096
_MAX_BYTES: Final = 8192
_IP: Final = "203.0.113.187"
# How long a test waits for something that must happen promptly.
_WAIT_S: Final = 3.0
# The patched deadlines: a grace of 0.2 s with a rate that makes the declared part
# negligible (the total is the grace), and a stall timeout far off.
_GRACE_S: Final = 0.2
_FAST_RATE: Final = 10**9
_FAR_STALL_S: Final = 10.0
# A drip: one byte every 0.05 s, 40 of them (2 s in all, ten times the grace).
_DRIP_BYTES: Final = 40
_DRIP_GAP_S: Final = 0.05
# The bound on an upload that must end at the 0.2 s total (5x the total, half the drip).
_TOTAL_BOUND_S: Final = 1.0

_LENGTH_MISMATCH: Final = (
    400,
    {"detail": "The body doesn't match Content-Length", "reason": "content_length_mismatch"},
)
_TEXT: Final = b"Termin am Montag um neun.\n"
_DATA: Final = b"Protokoll der Sitzung vom Montag.\n"


# ---------------------------------------------------------------------------
# The upload service (admino.attachments) against the FakeDb
# ---------------------------------------------------------------------------


@pytest.fixture
def att() -> ModuleType:
    import admino.attachments as module

    return module


@pytest.fixture
def at() -> ModuleType:
    import admino.attachment_types as module

    return module


@dataclass(frozen=True)
class _World:
    """ORG_ID (quota 4096) with the member and a colleague, one chat each; the
    attachments root under tmp_path (not created)."""

    db: FakeDb
    root: Path
    member: TenantContext
    colleague: TenantContext
    chats: dict[uuid.UUID, uuid.UUID]


@pytest.fixture
def world(tmp_path: Path) -> _World:
    db = FakeDb()
    db.add_org(ORG_ID, storage_quota_bytes=_QUOTA)
    tenants: list[TenantContext] = []
    chats: dict[uuid.UUID, uuid.UUID] = {}
    for _ in range(2):
        user_id = db.add_account(org_id=ORG_ID)
        tenants.append(TenantContext(org_id=ORG_ID, user_id=user_id, role="editor"))
        chats[user_id] = db.add_chat(user_id)
    return _World(
        db=db,
        root=tmp_path / "attachments",
        member=tenants[0],
        colleague=tenants[1],
        chats=chats,
    )


@dataclass
class _Body:
    """An upload body: ``chunks``, each after ``gap`` seconds (plus ``pause_before`` of
    its index); with ``stall`` it then waits forever."""

    chunks: Sequence[bytes]
    gap: float = 0.0
    pause_before: dict[int, float] = field(default_factory=dict)
    stall: bool = False

    async def stream(self) -> AsyncIterator[bytes]:
        for index, chunk in enumerate(self.chunks):
            wait = self.gap + self.pause_before.get(index, 0.0)
            if wait:
                await asyncio.sleep(wait)
            yield chunk
        if self.stall:
            await asyncio.Event().wait()


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


async def _within(
    seconds: float,
    att: ModuleType,
    at: ModuleType,
    w: _World,
    body: AsyncIterator[bytes],
    *,
    declared: int,
) -> tuple[str, Any]:
    """``_try_upload`` bounded to ``seconds``; ("still streaming after", seconds) past it."""
    try:
        return await asyncio.wait_for(_try_upload(att, at, w, body, declared=declared), seconds)
    except TimeoutError:
        return "still streaming after", seconds


def _deadlines(
    monkeypatch: pytest.MonkeyPatch, att: ModuleType, *, grace: float, rate: int, stall: float
) -> None:
    monkeypatch.setattr(att, "UPLOAD_GRACE_S", grace, raising=False)
    monkeypatch.setattr(att, "UPLOAD_MIN_RATE_BYTES_S", rate, raising=False)
    monkeypatch.setattr(att, "STALL_TIMEOUT_S", stall, raising=False)


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


class TestAttachmentsUploadDeadline:
    """F5: the whole body must arrive within the grace plus its declared length's share."""

    def test_attachments_upload_deadline_constants_are_120_s_and_32_kib_per_s(
        self, att: ModuleType
    ) -> None:
        assert (
            getattr(att, "UPLOAD_GRACE_S", None),
            getattr(att, "UPLOAD_MIN_RATE_BYTES_S", None),
        ) == (120.0, 32 * 1024)

    async def test_attachments_upload_drip_past_the_total_deadline_is_content_length_mismatch(
        self, att: ModuleType, at: ModuleType, world: _World, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Grace 0.2 s (the total), stall timeout 10 s: a body of 40 one-byte chunks, one
        every 0.05 s (2 s in all, never a stall), is refused content_length_mismatch after
        the grace and within 1 s: no row, no event, no file, no .part; its reservation is
        released (the colleague's upload of the whole quota is then stored)."""
        _deadlines(monkeypatch, att, grace=_GRACE_S, rate=_FAST_RATE, stall=_FAR_STALL_S)
        drip = _Body([b"d"] * _DRIP_BYTES, gap=_DRIP_GAP_S)

        started = time.monotonic()
        outcome = await _within(_TOTAL_BOUND_S, att, at, world, drip.stream(), declared=40)
        elapsed = time.monotonic() - started
        left = _stored(world)
        after = await _try_upload(
            att, at, world, _Body([b"c" * _QUOTA]).stream(), declared=_QUOTA, tenant=world.colleague
        )

        assert (outcome, left, after[0]) == (
            ("refused", "content_length_mismatch"),
            ([], 0, []),
            "stored",
        )
        assert elapsed >= _GRACE_S * 0.75, f"refused after {elapsed:.3f} s, before the grace"

    @pytest.mark.parametrize(
        ("stall", "grace", "bound", "body"),
        [
            (
                _FAR_STALL_S,
                _GRACE_S,
                _TOTAL_BOUND_S,
                _Body([b"a" * 20, b"b" * 20], pause_before={1: 3.0}),
            ),
            (0.05, 2.0, 0.6, _Body([b"a" * 20], stall=True)),
        ],
        ids=["total-before-stall", "stall-before-total"],
    )
    async def test_attachments_upload_chunk_wait_ends_at_the_earlier_deadline(
        self,
        att: ModuleType,
        at: ModuleType,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
        stall: float,
        grace: float,
        bound: float,
        body: _Body,
    ) -> None:
        """40 declared bytes, 20 sent at once. total-before-stall: total 0.2 s, stall 10 s,
        the next chunk only after 3 s: refused within 1 s (the wait ends at the total, not
        at the stall timeout or the chunk). stall-before-total (regression guard): stall
        0.05 s, total 2 s, nothing more ever: refused within 0.6 s. Nothing is left."""
        _deadlines(monkeypatch, att, grace=grace, rate=_FAST_RATE, stall=stall)

        outcome = await _within(bound, att, at, world, body.stream(), declared=40)

        assert (outcome, _stored(world)) == (
            ("refused", "content_length_mismatch"),
            ([], 0, []),
        )

    async def test_attachments_upload_total_deadline_scales_with_the_declared_length(
        self, att: ModuleType, at: ModuleType, world: _World, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Grace 0.05 s, 1000 bytes/s, stall timeout 10 s; two bodies of ten chunks, one
        every 0.06 s (0.6 s in all), at once: declaring 10 bytes (a total of 0.06 s) is
        refused content_length_mismatch; declaring 2000 bytes (a total of 2.05 s) is
        stored, although its body took twelve times the grace."""
        _deadlines(monkeypatch, att, grace=0.05, rate=1000, stall=_FAR_STALL_S)
        small = _Body([b"s"] * 10, gap=0.06)
        large = _Body([b"l" * 200] * 10, gap=0.06)

        outcomes = await asyncio.wait_for(
            asyncio.gather(
                _try_upload(att, at, world, small.stream(), declared=10),
                _try_upload(att, at, world, large.stream(), declared=2000, tenant=world.colleague),
            ),
            _WAIT_S,
        )

        assert (outcomes[0], outcomes[1][0], _sizes(world)) == (
            ("refused", "content_length_mismatch"),
            "stored",
            [2000],
        )


# ---------------------------------------------------------------------------
# F6: an interrupted COMMIT
# ---------------------------------------------------------------------------


def _interrupt_commit(
    monkeypatch: pytest.MonkeyPatch, db: FakeDb, error: BaseException, *, applied: bool
) -> None:
    """The upload's transaction block runs; then its COMMIT is interrupted by ``error``.

    applied: the server applied the COMMIT (the FakeDb commits), and only its answer is
    lost; else the transaction rolls back (the COMMIT never took effect). Either way
    ``error`` comes out of the transaction's exit, as asyncpg's ``__aexit__`` raises it.
    """
    real_acquire = db.pool.acquire

    @contextlib.asynccontextmanager
    async def acquire() -> AsyncIterator[Any]:
        async with real_acquire() as conn:
            real_transaction = conn.transaction

            @contextlib.asynccontextmanager
            async def transaction() -> AsyncIterator[None]:
                if applied:
                    async with real_transaction():
                        yield
                    raise error
                async with real_transaction():
                    yield
                    raise error

            conn.transaction = transaction
            yield conn

    monkeypatch.setattr(db.pool, "acquire", acquire)


def _cancelled() -> BaseException:
    return asyncio.CancelledError()


def _connection_lost() -> BaseException:
    # What asyncpg raises itself when the connection drops mid-operation.
    return asyncpg.exceptions.ConnectionDoesNotExistError(
        "connection was closed in the middle of operation"
    )


def _interface_error() -> BaseException:
    return asyncpg.InterfaceError("cannot perform operation: connection is closed")


def _connection_reset() -> BaseException:
    return ConnectionResetError(54, "Connection reset by peer")


def _serialization_failure() -> BaseException:
    return asyncpg.exceptions.SerializationError(
        "could not serialize access due to read/write dependencies among transactions"
    )


def _content(root: Path, entry: str) -> bytes | None:
    path = root / entry
    return path.read_bytes() if path.is_file() else None


def _is_original(entry: str) -> bool:
    """``<ORG_ID>/<uuid>``: an original's file name (no ``.part``)."""
    org, _, name = entry.partition("/")
    try:
        parsed = uuid.UUID(name)
    except ValueError:
        return False
    return org == str(ORG_ID) and str(parsed) == name


class TestAttachmentsUnknownCommitOutcome:
    """F6: a COMMIT whose outcome is unknown keeps ``<id>``; a definite failure removes it."""

    @pytest.mark.parametrize(
        "make_error",
        [_cancelled, _connection_lost, _interface_error, _connection_reset],
        ids=["cancelled", "connection-lost", "interface-error", "connection-reset"],
    )
    async def test_attachments_interrupted_commit_keeps_the_stored_file(
        self,
        att: ModuleType,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
        make_error: Callable[[], BaseException],
    ) -> None:
        """The server applied the COMMIT, but its answer is lost to a cancellation, the
        lost connection, an InterfaceError or an OSError: the error propagates, and the
        row, its file.upload event and <id> with the bytes stay; no .part."""
        db = world.db
        error = make_error()
        _interrupt_commit(monkeypatch, db, error, applied=True)

        with pytest.raises(type(error)):
            await _upload(att, world, _Body([_DATA]).stream(), declared=len(_DATA))
        ids = list(db.attachments)
        entries = [f"{ORG_ID}/{attachment_id}" for attachment_id in ids]

        assert [outcome for _, outcome in db.transactions] == ["commit"]
        assert (len(ids), len(db.audit_rows("file.upload"))) == (1, 1)
        assert _left_on_disk(world.root) == entries
        assert _content(world.root, entries[0]) == _DATA

    async def test_attachments_interrupted_commit_not_applied_keeps_the_file_without_a_row(
        self, att: ModuleType, world: _World, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The connection drops during the COMMIT and the server never applied it (the
        transaction rolled back): the error propagates, no row and no event exist, and
        <id> is still kept with its bytes (the outcome looked unknown; the stray-file
        sweep removes it after 24 h); no .part."""
        db = world.db
        error = _connection_lost()
        _interrupt_commit(monkeypatch, db, error, applied=False)

        with pytest.raises(type(error)):
            await _upload(att, world, _Body([_DATA]).stream(), declared=len(_DATA))
        entries = _left_on_disk(world.root)

        assert [outcome for _, outcome in db.transactions] == [
            "rollback:ConnectionDoesNotExistError"
        ]
        assert (_sizes(world), len(db.audit_rows("file.upload"))) == ([], 0)
        assert [_is_original(entry) for entry in entries] == [True]
        assert _content(world.root, entries[0]) == _DATA

    @pytest.mark.parametrize("stage", ["server-refused-commit", "cancelled-before-commit"])
    async def test_attachments_definite_commit_failure_removes_the_part_and_the_file(
        self, att: ModuleType, world: _World, monkeypatch: pytest.MonkeyPatch, stage: str
    ) -> None:
        """Regression guards. server-refused-commit: the COMMIT is refused by the server
        (a SerializationError). cancelled-before-commit: a cancellation right after the
        rename into <id>, before the COMMIT was sent. Either way the transaction rolls
        back, the error propagates and neither <id> nor <id>.part is left."""
        db = world.db
        error: BaseException
        if stage == "server-refused-commit":
            error = _serialization_failure()
            _interrupt_commit(monkeypatch, db, error, applied=False)
        else:
            error = asyncio.CancelledError()
            real_replace = os.replace

            def replace_then_cancel(src: Any, dst: Any) -> None:
                real_replace(src, dst)
                if str(dst).startswith(str(world.root)):
                    raise error

            monkeypatch.setattr(os, "replace", replace_then_cancel)

        with pytest.raises(type(error)):
            await _upload(att, world, _Body([_DATA]).stream(), declared=len(_DATA))

        assert [outcome for _, outcome in db.transactions] == [f"rollback:{type(error).__name__}"]
        assert _stored(world) == ([], 0, [])


# ---------------------------------------------------------------------------
# HTTP: the app from create_app() against the tenancy world
# ---------------------------------------------------------------------------


@dataclass
class _Processing:
    """Stands in for ``server._processing``: records every ``submit`` call."""

    calls: list[Any] = field(default_factory=list)

    def submit(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append((args, kwargs))

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
    """Orgs A and B (OA/ED/VI each, a 64 MiB quota) behind the fake database, the
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


@dataclass
class _Wire:
    """A raw-ASGI body: ``chunks``, each after ``gap`` seconds (the last one ends it),
    then it waits forever."""

    chunks: Sequence[bytes]
    gap: float = 0.0
    asked: int = 0

    async def receive(self) -> Message:
        self.asked += 1
        if self.asked <= len(self.chunks):
            if self.gap:
                await asyncio.sleep(self.gap)
            more = self.asked < len(self.chunks)
            return {"type": "http.request", "body": self.chunks[self.asked - 1], "more_body": more}
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


class TestAttachmentsApiUploadDeadline:
    """F5 over HTTP: a drip past the total deadline ends the upload and frees its slot."""

    async def test_attachments_api_upload_drip_past_the_total_deadline_is_400_and_frees_the_slot(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Grace 0.2 s (the total), stall timeout 10 s, one open upload per user: a body
        of 40 one-byte chunks, one every 0.05 s (2 s in all), is 400
        content_length_mismatch within 1 s, with nothing stored (no row, no event, no file
        or .part, no submit); the user's next upload is 201."""
        import admino.attachments as attachments

        _deadlines(monkeypatch, attachments, grace=_GRACE_S, rate=_FAST_RATE, stall=_FAR_STALL_S)
        editor = env.world.a["editor"]
        # Create the upload bucket with a burst of 50 (a nameless upload is a 400), so no
        # 429 below comes from the token bucket; then one open upload per user.
        _set_files(env, monkeypatch, max_files_per_message=50)
        warm = await _raw_upload(
            env.app,
            editor,
            env.world.db.add_chat(editor.user_id),
            _Wire([]).receive,
            length=1,
            name=None,
        )
        assert warm[0] == 400, warm
        _set_files(env, monkeypatch, max_files_per_message=1)
        chat = env.world.db.add_chat(editor.user_id)
        before = _state(env)
        drip = _Wire([b"d"] * _DRIP_BYTES, gap=_DRIP_GAP_S)

        outcome = await _raw_upload(
            env.app, editor, chat, drip.receive, length=_DRIP_BYTES, timeout=_TOTAL_BOUND_S
        )
        left = _state(env)
        next_one = await _raw_upload(
            env.app, editor, chat, _Wire([_TEXT]).receive, length=len(_TEXT), timeout=_WAIT_S
        )

        assert outcome == _LENGTH_MISMATCH
        assert left == before
        assert next_one[0] == 201
