"""Tests for ``admino.attachment_gc`` (GH-187 contract §2 G1 to G3, §3.8; Decision 13).

Issue #187, "Testing": "Orphan GC after 24 h". Decision 13: the GC runs at startup
and then hourly; an attachment never sent within 24 h is deleted with its files,
recorded as a ``file.delete`` event by the system with ``{"orphan": true}``; leftover
files older than 24 h without a live row (an interrupted upload, a failed removal)
are deleted. Decision 11: ``<root>/<org_id>/<id>``, ``<id>.part`` and ``<id>.d/``.

What these tests pin down:

- ``ORPHAN_AGE == timedelta(hours=24)``, ``GC_INTERVAL_SECONDS == 3600.0`` (the
  default of ``run_gc_job``'s keyword-only ``interval_seconds``);
  ``collect_garbage``'s ``now`` is keyword-only and defaults to the current time.
- ``collect_garbage(pool, root, now=...)``, rows (G1, then per row G2 and the audit
  insert in one transaction of their own, then the files):
  - an unsent row created strictly before ``now - 24 h`` is deleted with ``<id>``,
    ``<id>.part`` and ``<id>.d/`` (a trashed one too), with one ``file.delete``
    audit row each: actor_kind system, no actor user, the row's org, target the
    file, metadata exactly ``{"orphan": True}``, no ip;
  - a row exactly 24 h old, a younger one and a sent one (message_id set) are kept
    with their files and get no audit row;
  - a row linked to a message between G1 and G2 is kept (G2 re-checks
    ``message_id IS NULL``): no audit row, files kept;
  - an audit failure for one row rolls that row back and keeps its files; it is
    logged by class name and the other rows are still collected.
- Stray entries (step 2): in each real directory under ``root`` named as a UUID
  (an org), the direct children older than 24 h by mtime named ``<uuid>``,
  ``<uuid>.part`` or ``<uuid>.d``: a ``.part`` is always removed; ``<uuid>`` and
  ``<uuid>.d`` are removed unless G3 (scoped to that org) finds the row, trashed
  rows included (their files wait for #194). Kept: younger entries, other names
  (``notes.txt``, ``<uuid>.tmp``; a UUID that isn't in the canonical lower-case
  form, e.g. upper-case or braced: regression guard), anything under a non-UUID
  directory, a plain file
  under ``root``, an org directory that is a symlink (never followed). A symlink in
  an org directory is unlinked; its target (a file or a directory) is untouched.
  The mtime cutoff comes from ``now``. A directory that can't be read doesn't stop
  the other directories.
- The statements: G1 with ``now - 24 h``, G2 with (id, org), then one G3 per org
  directory with its org and candidate uuids, in that order; the return value is
  the number of rows plus stray entries removed.
- Logs: no file name (the DB's) and no path, even when a removal fails with an
  OSError whose message holds the path.
- ``run_gc_job(pool, interval_seconds=...)``: ``collect_garbage(pool,
  attachments.attachments_root())`` at once, then after each interval, the root read
  at each run (``organizations.ATTACHMENTS_ROOT`` patched between runs); a failing
  run is logged by class name only and the job continues; a cancellation (during a
  run or a sleep) ends it.
- GH-281 (Decision 7, contract C1 to C3), the stray sweep in chunks:
  ``SWEEP_CHUNK_SIZE == 1000``, read at call time. An org directory's old
  ``<uuid>``/``<uuid>.d`` candidates are checked with ``ceil(n / SWEEP_CHUNK_SIZE)``
  G3 statements, each binding that directory's org and at most ``SWEEP_CHUNK_SIZE``
  ids; every candidate sits in exactly one chunk (2,500 strays: three statements);
  the rows found in any chunk keep their files; a directory without a candidate
  sends no G3. A chunk that raises skips its whole directory for the run (nothing in
  it removed, a ``.part`` included), logged as ``Attachment directory of org <id>
  couldn't be swept (<class name>).`` without the error's message; another org's
  directory is still swept (each org takes the failing role once).

The module is imported lazily (fixture ``gc``), so this file collects before it
exists and every test fails on its own. Everything on disk lives under
``tmp_path``; the sleeps of ``run_gc_job`` are replaced by recorders (no real wait)
and every job run is bounded by ``asyncio.wait_for``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import inspect
import json
import logging
import os
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import asyncpg
import pytest

from admino import organizations
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, norm

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path
    from types import ModuleType

_REAL_SLEEP = asyncio.sleep
_WAIT_S: Final = 5.0
_OLD: Final = timedelta(hours=25)
_YOUNG: Final = timedelta(hours=23)

# A stored name (DB only) and a message marker: neither may reach a log record.
_LEAK_NAME: Final = "Quarterly-salaries-2026.xlsx"
_LEAK_DIR: Final = "/srv/private-share-marker"

# --- Contract §2 forms -----------------------------------------------------------

_G1: Final = norm(
    "SELECT id, org_id FROM attachments WHERE message_id IS NULL AND created_at < $1 "
    "ORDER BY created_at, id"
)
_G2: Final = norm(
    "DELETE FROM attachments WHERE id = $1 AND org_id = $2 AND message_id IS NULL RETURNING id"
)
_G3: Final = norm("SELECT id FROM attachments WHERE org_id = $1 AND id = ANY($2::uuid[])")


# --- Fixtures and helpers ----------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _World:
    """Two orgs, each with a member and a chat; one sent message in org A's chat."""

    chat_id: uuid.UUID
    message_id: uuid.UUID
    other_chat_id: uuid.UUID


@pytest.fixture()
def gc() -> ModuleType:
    """The module under test, imported lazily (it doesn't exist before GH-187)."""
    import admino.attachment_gc as module

    return module


@pytest.fixture()
def db() -> FakeDb:
    return FakeDb()


@pytest.fixture()
def world(db: FakeDb) -> _World:
    user_id = db.add_account(org_id=ORG_ID)
    other_user_id = db.add_account(org_id=OTHER_ORG_ID)
    chat_id = db.add_chat(user_id)
    return _World(
        chat_id=chat_id,
        message_id=db.add_chat_message(chat_id, "user", "hello"),
        other_chat_id=db.add_chat(other_user_id),
    )


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    path = tmp_path / "attachments"
    path.mkdir()
    return path


@pytest.fixture()
def now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _canonical(value: Any) -> Any:
    """A plain uuid.UUID for any UUID (asyncpg's subclass included); others unchanged."""
    return uuid.UUID(int=value.int) if isinstance(value, uuid.UUID) else value


def _row(
    db: FakeDb,
    chat_id: uuid.UUID,
    created_at: datetime,
    *,
    message_id: uuid.UUID | None = None,
    deleted_at: datetime | None = None,
    filename: str = "a.pdf",
) -> uuid.UUID:
    return db.add_attachment(
        chat_id,
        filename=filename,
        size_bytes=10,
        status="ready",
        message_id=message_id,
        created_at=created_at,
        deleted_at=deleted_at,
    )


def _set_age(path: Path, now: datetime, age: timedelta) -> None:
    """Set an entry's own atime and mtime (a symlink's, not its target's) to now - age."""
    stamp = (now - age).timestamp()
    os.utime(path, (stamp, stamp), follow_symlinks=False)


def _entry(
    root: Path,
    org_id: uuid.UUID,
    name: str,
    now: datetime,
    *,
    age: timedelta | None = None,
    directory: bool = False,
) -> Path:
    """Create ``<root>/<org_id>/<name>`` (a file, or a directory with a file inside);
    with ``age``, its mtime is set to now - age (after its contents exist)."""
    path = root / str(org_id) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if directory:
        path.mkdir()
        (path / "page-1.png").write_bytes(b"derived")
    else:
        path.write_bytes(b"stored bytes")
    if age is not None:
        _set_age(path, now, age)
    return path


def _row_files(
    root: Path, org_id: uuid.UUID, attachment_id: uuid.UUID, now: datetime
) -> list[Path]:
    """A row's three entries (young): <id>, <id>.part and <id>.d/."""
    return [
        _entry(root, org_id, str(attachment_id), now),
        _entry(root, org_id, f"{attachment_id}.part", now),
        _entry(root, org_id, f"{attachment_id}.d", now, directory=True),
    ]


def _present(paths: list[Path]) -> list[bool]:
    return [os.path.lexists(path) for path in paths]


def _attachment_calls(db: FakeDb) -> list[tuple[str, tuple[Any, ...]]]:
    """(normalized SQL, args with canonical UUIDs) of every statement naming attachments."""
    return [
        (call.normalized, tuple(_canonical(arg) for arg in call.args))
        for call in db.calls
        if re.search(r"\battachments\b", call.normalized)
    ]


def _g3_calls(db: FakeDb) -> list[tuple[uuid.UUID, frozenset[uuid.UUID]]]:
    """(org, uuids) of every G3 statement."""
    return [
        (_canonical(args[0]), frozenset(_canonical(uuid.UUID(str(item))) for item in args[1]))
        for sql, args in _attachment_calls(db)
        if sql == _G3
    ]


def _file_deletes(db: FakeDb) -> list[dict[str, Any]]:
    """The file.delete audit rows, normalized (ids as strings), by target id."""
    rows = [
        {
            "org_id": str(row["org_id"]),
            "actor_kind": row["actor_kind"],
            "actor_user_id": row["actor_user_id"],
            "action": row["action"],
            "target_type": row["target_type"],
            "target_ids": row["target_ids"],
            "ip": row["ip"],
            # JSON text: {"orphan": 1} would equal {"orphan": True} as a dict.
            "metadata": json.dumps(row["metadata"], sort_keys=True),
        }
        for row in db.audit_rows("file.delete")
    ]
    return sorted(rows, key=lambda row: row["target_ids"])


def _orphan_audit(org_id: uuid.UUID, attachment_id: uuid.UUID) -> dict[str, Any]:
    return {
        "org_id": str(org_id),
        "actor_kind": "system",
        "actor_user_id": None,
        "action": "file.delete",
        "target_type": "file",
        "target_ids": [str(attachment_id)],
        "ip": None,
        "metadata": '{"orphan": true}',
    }


def _log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured record, formatted with its traceback (exc_info) if any."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(formatter.format(record) for record in caplog.records)


def _warnings_naming(caplog: pytest.LogCaptureFixture, name: str) -> list[logging.LogRecord]:
    return [
        record
        for record in caplog.records
        if record.levelno >= logging.WARNING and name in record.getMessage()
    ]


class _GcProbeError(Exception):
    """A failing GC run: its message names a file and a path."""


class _Unreadable:
    """chmod a directory for the block; always restore 0o700 (tmp_path cleanup)."""

    def __init__(self, path: Path, mode: int) -> None:
        self.path = path
        self.mode = mode

    def __enter__(self) -> Path:
        self.path.chmod(self.mode)
        return self.path

    def __exit__(self, *_exc: object) -> None:
        self.path.chmod(0o700)


# ---------------------------------------------------------------------------
# 1. Names and defaults
# ---------------------------------------------------------------------------


class TestNames:
    def test_attachment_gc_orphan_age_is_24_hours(self, gc: ModuleType) -> None:
        orphan_age = gc.ORPHAN_AGE

        assert orphan_age == timedelta(hours=24)

    def test_attachment_gc_interval_is_an_hour(self, gc: ModuleType) -> None:
        job = inspect.signature(gc.run_gc_job).parameters["interval_seconds"]

        assert (gc.GC_INTERVAL_SECONDS, job.kind, job.default) == (
            3600.0,
            inspect.Parameter.KEYWORD_ONLY,
            gc.GC_INTERVAL_SECONDS,
        )

    def test_attachment_gc_now_is_keyword_only_and_optional(self, gc: ModuleType) -> None:
        parameter = inspect.signature(gc.collect_garbage).parameters["now"]

        assert (parameter.kind, parameter.default) == (inspect.Parameter.KEYWORD_ONLY, None)


# ---------------------------------------------------------------------------
# 2. Orphan rows (G1, G2, the audit row, the files)
# ---------------------------------------------------------------------------


class TestOrphanRows:
    async def test_attachment_gc_unsent_row_older_than_24h_deleted_with_files(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime
    ) -> None:
        orphan = _row(db, world.chat_id, now - timedelta(hours=24, seconds=1))
        files = _row_files(root, ORG_ID, orphan, now)

        result = await gc.collect_garbage(db.pool, root, now=now)

        assert (result, db.attachment_row(orphan), _present(files)) == (
            1,
            None,
            [False, False, False],
        )

    async def test_attachment_gc_orphan_deletion_audited_as_system_with_orphan_flag(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime
    ) -> None:
        first = _row(db, world.chat_id, now - timedelta(hours=30))
        second = _row(db, world.other_chat_id, now - timedelta(hours=26))

        await gc.collect_garbage(db.pool, root, now=now)

        assert _file_deletes(db) == sorted(
            [_orphan_audit(ORG_ID, first), _orphan_audit(OTHER_ORG_ID, second)],
            key=lambda row: row["target_ids"],
        )

    @pytest.mark.parametrize(
        ("age", "sent"),
        [
            pytest.param(timedelta(hours=24), False, id="exactly-24h"),
            pytest.param(timedelta(hours=23, minutes=59), False, id="younger"),
            pytest.param(timedelta(hours=48), True, id="sent"),
        ],
    )
    async def test_attachment_gc_row_not_orphaned_is_kept_with_files(
        self,
        gc: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        now: datetime,
        age: timedelta,
        sent: bool,
    ) -> None:
        kept = _row(db, world.chat_id, now - age, message_id=world.message_id if sent else None)
        before = db.attachment_row(kept)
        files = _row_files(root, ORG_ID, kept, now)

        result = await gc.collect_garbage(db.pool, root, now=now)

        assert (result, db.attachment_row(kept), _present(files), _file_deletes(db)) == (
            0,
            before,
            [True, True, True],
            [],
        )

    async def test_attachment_gc_trashed_unsent_old_row_is_removed(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime
    ) -> None:
        trashed = _row(
            db,
            world.chat_id,
            now - timedelta(hours=30),
            deleted_at=now - timedelta(hours=2),
        )
        files = _row_files(root, ORG_ID, trashed, now)

        await gc.collect_garbage(db.pool, root, now=now)

        assert (db.attachment_row(trashed), _present(files), len(_file_deletes(db))) == (
            None,
            [False, False, False],
            1,
        )

    async def test_attachment_gc_row_linked_after_selection_is_kept(
        self,
        gc: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        now: datetime,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The message is stored (A9) between G1 and G2: G2 matches nothing, so the row,
        its files and the audit log stay as they are; the other orphan still goes."""
        linked = _row(db, world.chat_id, now - timedelta(hours=30))
        orphan = _row(db, world.chat_id, now - timedelta(hours=28))
        linked_files = _row_files(root, ORG_ID, linked, now)
        original = db.handle

        def handle(method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None) -> Any:
            result = original(method, sql, args, via, tx)
            if norm(sql) == _G1:
                db.attachments[linked]["message_id"] = world.message_id
            return result

        monkeypatch.setattr(db, "handle", handle)

        result = await gc.collect_garbage(db.pool, root, now=now)

        row = db.attachment_row(linked)
        assert row is not None
        assert (result, row["message_id"], _present(linked_files)) == (
            1,
            world.message_id,
            [True, True, True],
        )
        assert _file_deletes(db) == [_orphan_audit(ORG_ID, orphan)]
        assert db.attachment_row(orphan) is None

    async def test_attachment_gc_audit_failure_rolls_back_only_that_row(
        self,
        gc: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        now: datetime,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        refused = _row(db, world.chat_id, now - timedelta(hours=30))
        collected = _row(db, world.other_chat_id, now - timedelta(hours=28))
        refused_files = _row_files(root, ORG_ID, refused, now)
        collected_files = _row_files(root, OTHER_ORG_ID, collected, now)
        db.fail_audit_when = lambda row: row["target_ids"] == [str(refused)]

        result = await gc.collect_garbage(db.pool, root, now=now)

        assert db.attachment_row(refused) is not None
        assert (_present(refused_files), _present(collected_files)) == (
            [True, True, True],
            [False, False, False],
        )
        assert (result, db.attachment_row(collected), _file_deletes(db)) == (
            1,
            None,
            [_orphan_audit(OTHER_ORG_ID, collected)],
        )
        assert _warnings_naming(caplog, "AuditRecordError")

    async def test_attachment_gc_each_row_in_its_own_transaction(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime
    ) -> None:
        """G2 and its audit insert share one transaction; each row has its own."""
        _row(db, world.chat_id, now - timedelta(hours=30))
        _row(db, world.other_chat_id, now - timedelta(hours=28))

        await gc.collect_garbage(db.pool, root, now=now)

        deletes = [call for call in db.calls if call.normalized == _G2]
        audits = [
            call for call in db.calls if call.normalized.startswith("insert into audit_events")
        ]
        transactions = [call.tx for call in deletes]
        assert None not in transactions
        assert len(set(transactions)) == 2
        assert [(call.tx, call.via) for call in audits] == [(call.tx, call.via) for call in deletes]

    async def test_attachment_gc_now_defaults_to_the_current_time(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        current = datetime.now(UTC)
        old = _row(db, world.chat_id, current - timedelta(hours=25))
        young = _row(db, world.chat_id, current - timedelta(hours=23))

        await gc.collect_garbage(db.pool, root)

        assert (db.attachment_row(old), db.attachment_row(young) is not None) == (None, True)


# ---------------------------------------------------------------------------
# 3. The statements
# ---------------------------------------------------------------------------


class TestStatements:
    async def test_attachment_gc_issues_g1_g2_then_one_g3_per_org_dir(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime
    ) -> None:
        orphan = _row(db, world.chat_id, now - timedelta(hours=30))
        _row_files(root, ORG_ID, orphan, now)
        stray_a = uuid.uuid4()
        stray_b = uuid.uuid4()
        _entry(root, ORG_ID, str(stray_a), now, age=_OLD)
        _entry(root, OTHER_ORG_ID, str(stray_b), now, age=_OLD)
        db.calls.clear()

        await gc.collect_garbage(db.pool, root, now=now)

        calls = _attachment_calls(db)
        assert [sql for sql, _ in calls] == [_G1, _G2, _G3, _G3]
        assert (calls[0][1], calls[1][1]) == ((now - timedelta(hours=24),), (orphan, ORG_ID))
        assert set(_g3_calls(db)) == {
            (ORG_ID, frozenset({stray_a})),
            (OTHER_ORG_ID, frozenset({stray_b})),
        }

    async def test_attachment_gc_g3_asks_for_candidates_only(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime
    ) -> None:
        """One G3 per org dir; it names the old <uuid>/<uuid>.d candidates (a .part's
        uuid may be named too), never a young or unknown entry's."""
        stray = uuid.uuid4()
        derived = uuid.uuid4()
        part = uuid.uuid4()
        young = uuid.uuid4()
        other = uuid.uuid4()
        _entry(root, ORG_ID, str(stray), now, age=_OLD)
        _entry(root, ORG_ID, f"{derived}.d", now, age=_OLD, directory=True)
        _entry(root, ORG_ID, f"{part}.part", now, age=_OLD)
        _entry(root, ORG_ID, str(young), now, age=_YOUNG)
        _entry(root, ORG_ID, f"{uuid.uuid4()}.tmp", now, age=_OLD)
        _entry(root, OTHER_ORG_ID, str(other), now, age=_OLD)

        await gc.collect_garbage(db.pool, root, now=now)

        by_org = dict(_g3_calls(db))
        assert (len(_g3_calls(db)), set(by_org)) == (2, {ORG_ID, OTHER_ORG_ID})
        assert {stray, derived} <= by_org[ORG_ID] <= {stray, derived, part}
        assert by_org[OTHER_ORG_ID] == {other}


# ---------------------------------------------------------------------------
# 4. Stray entries
# ---------------------------------------------------------------------------


class TestStrayEntries:
    async def test_attachment_gc_old_entries_without_row_are_removed(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime
    ) -> None:
        stray = uuid.uuid4()
        part = uuid.uuid4()
        paths = [
            _entry(root, ORG_ID, str(stray), now, age=_OLD),
            _entry(root, ORG_ID, f"{stray}.d", now, age=_OLD, directory=True),
            _entry(root, ORG_ID, f"{part}.part", now, age=_OLD),
        ]

        result = await gc.collect_garbage(db.pool, root, now=now)

        assert (result, _present(paths)) == (3, [False, False, False])

    async def test_attachment_gc_live_rows_keep_files_but_not_their_part(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime
    ) -> None:
        """A sent row and a trashed one (its files wait for #194) keep <id> and <id>.d;
        an old <id>.part goes even though its row exists."""
        sent = _row(db, world.chat_id, now - timedelta(hours=48), message_id=world.message_id)
        trashed = _row(
            db,
            world.chat_id,
            now - timedelta(hours=48),
            message_id=world.message_id,
            deleted_at=now - timedelta(hours=30),
        )
        kept = [
            _entry(root, ORG_ID, str(sent), now, age=_OLD),
            _entry(root, ORG_ID, f"{sent}.d", now, age=_OLD, directory=True),
            _entry(root, ORG_ID, str(trashed), now, age=_OLD),
            _entry(root, ORG_ID, f"{trashed}.d", now, age=_OLD, directory=True),
        ]
        part = _entry(root, ORG_ID, f"{sent}.part", now, age=_OLD)

        result = await gc.collect_garbage(db.pool, root, now=now)

        assert (result, _present(kept), os.path.lexists(part)) == (1, [True] * 4, False)

    async def test_attachment_gc_young_entries_are_kept(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime
    ) -> None:
        paths = [
            _entry(root, ORG_ID, str(uuid.uuid4()), now),
            _entry(root, ORG_ID, f"{uuid.uuid4()}.part", now, age=_YOUNG),
            _entry(root, ORG_ID, f"{uuid.uuid4()}.d", now, age=_YOUNG, directory=True),
        ]

        result = await gc.collect_garbage(db.pool, root, now=now)

        assert (result, _present(paths)) == (0, [True, True, True])

    async def test_attachment_gc_unknown_names_are_kept(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime
    ) -> None:
        paths = [
            _entry(root, ORG_ID, "notes.txt", now, age=_OLD),
            _entry(root, ORG_ID, f"{uuid.uuid4()}.tmp", now, age=_OLD),
            _entry(root, ORG_ID, "not-a-uuid.part", now, age=_OLD),
        ]

        result = await gc.collect_garbage(db.pool, root, now=now)

        assert (result, _present(paths)) == (0, [True, True, True])

    async def test_attachment_gc_non_canonical_uuid_names_are_kept(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime
    ) -> None:
        """Regression guard: only the canonical lower-case form the app writes is a
        candidate. Old entries named with an upper-case or a braced form of a UUID
        that has no row (an upper-case ``.part`` too) aren't the app's and stay."""
        # Fixed ids holding letters, so the upper-case form always differs.
        upper = "5F0C2A9E-7B1D-4C3E-9A8F-0D6E1B2C3A4F"
        braced = "{c7d2e4f1-3a5b-4c6d-8e9f-a1b2c3d4e5f6}"
        upper_part = "E3B0C442-98FC-4C14-9AFB-F4C8996FB924.part"
        paths = [_entry(root, ORG_ID, name, now, age=_OLD) for name in (upper, braced, upper_part)]

        result = await gc.collect_garbage(db.pool, root, now=now)

        assert (result, _present(paths)) == (0, [True, True, True])

    async def test_attachment_gc_entries_outside_org_dirs_are_skipped(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime
    ) -> None:
        """A non-UUID directory under root isn't scanned; a plain file directly under
        root named as a UUID isn't an org directory."""
        in_other_dir = root / "lost+found" / str(uuid.uuid4())
        in_other_dir.parent.mkdir()
        in_other_dir.write_bytes(b"x")
        _set_age(in_other_dir, now, _OLD)
        plain_file = root / str(uuid.uuid4())
        plain_file.write_bytes(b"x")
        _set_age(plain_file, now, _OLD)

        result = await gc.collect_garbage(db.pool, root, now=now)

        assert (result, _present([in_other_dir, plain_file])) == (0, [True, True])

    async def test_attachment_gc_symlink_entry_is_unlinked_not_followed(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime, tmp_path: Path
    ) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        target_file = outside / "target.txt"
        target_file.write_bytes(b"keep me")
        target_dir = outside / "folder"
        target_dir.mkdir()
        (target_dir / "keep.txt").write_bytes(b"keep me too")
        for path in (target_file, target_dir):
            _set_age(path, now, _OLD)
        org_dir = root / str(ORG_ID)
        org_dir.mkdir()
        file_link = org_dir / str(uuid.uuid4())
        file_link.symlink_to(target_file)
        dir_link = org_dir / f"{uuid.uuid4()}.d"
        dir_link.symlink_to(target_dir, target_is_directory=True)
        for path in (file_link, dir_link):
            _set_age(path, now, _OLD)

        await gc.collect_garbage(db.pool, root, now=now)

        assert _present([file_link, dir_link]) == [False, False]
        assert (target_file.read_bytes(), (target_dir / "keep.txt").read_bytes()) == (
            b"keep me",
            b"keep me too",
        )

    async def test_attachment_gc_org_dir_symlink_is_skipped(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime, tmp_path: Path
    ) -> None:
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        stray = elsewhere / str(uuid.uuid4())
        stray.write_bytes(b"not under root")
        _set_age(stray, now, _OLD)
        _set_age(elsewhere, now, _OLD)
        link = root / str(OTHER_ORG_ID)
        link.symlink_to(elsewhere, target_is_directory=True)
        _set_age(link, now, _OLD)

        result = await gc.collect_garbage(db.pool, root, now=now)

        assert (result, _present([stray, link])) == (0, [True, True])

    async def test_attachment_gc_file_named_after_other_orgs_row_is_removed(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime
    ) -> None:
        """G3 is scoped to the directory's org: org B's sent row keeps its own entry alive,
        but not an entry of the same name in org A's directory."""
        sent_message = db.add_chat_message(world.other_chat_id, "user", "hi")
        other_row = _row(
            db, world.other_chat_id, now - timedelta(hours=48), message_id=sent_message
        )
        misplaced = _entry(root, ORG_ID, str(other_row), now, age=_OLD)
        own = _entry(root, OTHER_ORG_ID, str(other_row), now, age=_OLD)

        await gc.collect_garbage(db.pool, root, now=now)

        assert (os.path.lexists(misplaced), os.path.lexists(own)) == (False, True)

    async def test_attachment_gc_file_cutoff_comes_from_now(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path
    ) -> None:
        """A just-written stray is old for a GC run 48 h later."""
        later = datetime.now(UTC) + timedelta(hours=48)
        stray = root / str(ORG_ID) / str(uuid.uuid4())
        stray.parent.mkdir()
        stray.write_bytes(b"x")

        result = await gc.collect_garbage(db.pool, root, now=later)

        assert (result, os.path.lexists(stray)) == (1, False)


# ---------------------------------------------------------------------------
# 5. Count, failures and logs
# ---------------------------------------------------------------------------


class TestCountAndFailures:
    async def test_attachment_gc_returns_rows_plus_stray_entries_removed(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime
    ) -> None:
        first = _row(db, world.chat_id, now - timedelta(hours=30))
        second = _row(db, world.other_chat_id, now - timedelta(hours=26))
        _row_files(root, ORG_ID, first, now)
        _row_files(root, OTHER_ORG_ID, second, now)
        sent = _row(db, world.chat_id, now - timedelta(hours=48), message_id=world.message_id)
        stray = uuid.uuid4()
        _entry(root, ORG_ID, str(stray), now, age=_OLD)
        _entry(root, ORG_ID, f"{stray}.d", now, age=_OLD, directory=True)
        _entry(root, OTHER_ORG_ID, f"{uuid.uuid4()}.part", now, age=_OLD)
        _entry(root, ORG_ID, f"{sent}.part", now, age=_OLD)
        _entry(root, ORG_ID, str(sent), now, age=_OLD)
        _entry(root, ORG_ID, "notes.txt", now, age=_OLD)
        _entry(root, ORG_ID, str(uuid.uuid4()), now, age=_YOUNG)

        result = await gc.collect_garbage(db.pool, root, now=now)

        assert result == 6

    @pytest.mark.parametrize("blocked_org", ["org-a", "org-b"])
    async def test_attachment_gc_unreadable_org_dir_does_not_stop_the_others(
        self,
        gc: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        now: datetime,
        blocked_org: str,
    ) -> None:
        """Each org directory takes the unreadable role once, so whatever order the scan
        visits them in, one run meets the failure before the readable directory."""
        blocked_id, open_id = (
            (ORG_ID, OTHER_ORG_ID) if blocked_org == "org-a" else (OTHER_ORG_ID, ORG_ID)
        )
        blocked = _entry(root, blocked_id, str(uuid.uuid4()), now, age=_OLD)
        collected = _entry(root, open_id, str(uuid.uuid4()), now, age=_OLD)
        orphan = _row(db, world.chat_id, now - timedelta(hours=30))

        with _Unreadable(root / str(blocked_id), 0o000):
            result = await gc.collect_garbage(db.pool, root, now=now)

        assert (os.path.lexists(collected), db.attachment_row(orphan)) == (False, None)
        assert (result, os.path.lexists(blocked)) == (2, True)

    async def test_attachment_gc_logs_carry_no_filename_or_path(
        self,
        gc: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        now: datetime,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A row named like a real document is collected and a stray in a read-only
        directory can't be removed (its OSError message holds the path): the logs name
        the failure, never the stored name or any path."""
        caplog.set_level(logging.DEBUG)
        orphan = _row(db, world.chat_id, now - timedelta(hours=30), filename=_LEAK_NAME)
        _row_files(root, ORG_ID, orphan, now)
        stuck = _entry(root, OTHER_ORG_ID, str(uuid.uuid4()), now, age=_OLD)

        with _Unreadable(root / str(OTHER_ORG_ID), 0o500):
            await gc.collect_garbage(db.pool, root, now=now)

        text = _log_text(caplog)
        assert os.path.lexists(stuck)
        assert any(
            record.levelno >= logging.WARNING and record.name.startswith("admino")
            for record in caplog.records
        ), "the failed removal is logged"
        assert (_LEAK_NAME in text, str(root) in text) == (False, False)


# ---------------------------------------------------------------------------
# 6. run_gc_job
# ---------------------------------------------------------------------------


class _GcRecorder:
    """Replaces collect_garbage: records the root of each run by the contract's names."""

    def __init__(self, events: list[str], labels: dict[Path, str]) -> None:
        self.events = events
        self.labels = labels
        self.pools: list[Any] = []
        self.failures: list[BaseException] = []

    async def __call__(self, pool: Any, root: Path, *, now: datetime | None = None) -> int:
        self.pools.append(pool)
        self.events.append(f"gc {self.labels.get(root, str(root))}")
        if self.failures:
            raise self.failures.pop(0)
        return 0


def _sleep_recorder(
    events: list[str], *, stop_at: int, on_call: Callable[[int], None] | None = None
) -> Callable[[float], Any]:
    """A fake asyncio.sleep: records the delay, runs on_call(n), raises CancelledError on
    call ``stop_at``."""
    count = {"n": 0}

    async def fake_sleep(delay: float, *_args: Any, **_kwargs: Any) -> None:
        count["n"] += 1
        events.append(f"sleep {float(delay)!r}")
        if on_call is not None:
            on_call(count["n"])
        if count["n"] >= stop_at:
            raise asyncio.CancelledError
        await _REAL_SLEEP(0)

    return fake_sleep


@pytest.fixture()
def job_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Path, Path]]:
    """Two attachment roots; organizations.ATTACHMENTS_ROOT starts at the first."""
    first = tmp_path / "root-1"
    second = tmp_path / "root-2"
    first.mkdir()
    second.mkdir()
    monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", first)
    yield first, second


class TestRunGcJob:
    async def test_attachment_gc_job_runs_now_then_hourly(
        self,
        gc: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        job_roots: tuple[Path, Path],
    ) -> None:
        events: list[str] = []
        recorder = _GcRecorder(events, {job_roots[0]: "root-1"})
        pool = object()
        monkeypatch.setattr(gc, "collect_garbage", recorder)
        monkeypatch.setattr(asyncio, "sleep", _sleep_recorder(events, stop_at=2))

        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(gc.run_gc_job(pool), _WAIT_S)

        assert events == ["gc root-1", "sleep 3600.0", "gc root-1", "sleep 3600.0"]
        assert recorder.pools == [pool, pool]

    async def test_attachment_gc_job_reads_the_root_at_each_run(
        self,
        gc: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        job_roots: tuple[Path, Path],
    ) -> None:
        events: list[str] = []
        first, second = job_roots

        def move_root(call: int) -> None:
            if call == 1:
                monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", second)

        monkeypatch.setattr(
            gc, "collect_garbage", _GcRecorder(events, {first: "root-1", second: "root-2"})
        )
        monkeypatch.setattr(asyncio, "sleep", _sleep_recorder(events, stop_at=2, on_call=move_root))

        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(gc.run_gc_job(object(), interval_seconds=5.0), _WAIT_S)

        assert events == ["gc root-1", "sleep 5.0", "gc root-2", "sleep 5.0"]

    async def test_attachment_gc_job_failed_run_is_logged_and_job_continues(
        self,
        gc: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        job_roots: tuple[Path, Path],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        events: list[str] = []
        recorder = _GcRecorder(events, {job_roots[0]: "root-1"})
        recorder.failures.append(_GcProbeError(f"{job_roots[0]}/{_LEAK_NAME} in {_LEAK_DIR}"))
        monkeypatch.setattr(gc, "collect_garbage", recorder)
        monkeypatch.setattr(asyncio, "sleep", _sleep_recorder(events, stop_at=2))

        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(gc.run_gc_job(object(), interval_seconds=5.0), _WAIT_S)

        text = _log_text(caplog)
        assert events == ["gc root-1", "sleep 5.0", "gc root-1", "sleep 5.0"]
        assert _warnings_naming(caplog, "_GcProbeError")
        assert (_LEAK_NAME in text, _LEAK_DIR in text, str(job_roots[0]) in text) == (
            False,
            False,
            False,
        )

    async def test_attachment_gc_job_cancelled_run_ends_the_job(
        self,
        gc: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        job_roots: tuple[Path, Path],
    ) -> None:
        """A cancellation during a run isn't a failed run: it propagates, no sleep follows."""
        events: list[str] = []
        recorder = _GcRecorder(events, {job_roots[0]: "root-1"})
        recorder.failures.append(asyncio.CancelledError())
        monkeypatch.setattr(gc, "collect_garbage", recorder)
        monkeypatch.setattr(asyncio, "sleep", _sleep_recorder(events, stop_at=3))

        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(gc.run_gc_job(object()), _WAIT_S)

        assert events == ["gc root-1"]

    async def test_attachment_gc_job_task_cancel_stops_it(
        self,
        gc: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        job_roots: tuple[Path, Path],
    ) -> None:
        events: list[str] = []
        sleeping = asyncio.Event()

        async def blocking_sleep(delay: float, *_args: Any, **_kwargs: Any) -> None:
            sleeping.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(gc, "collect_garbage", _GcRecorder(events, {}))
        monkeypatch.setattr(asyncio, "sleep", blocking_sleep)
        task = asyncio.create_task(gc.run_gc_job(object()))
        await asyncio.wait_for(sleeping.wait(), _WAIT_S)

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, _WAIT_S)

        assert task.cancelled()

    async def test_attachment_gc_job_collects_under_the_attachments_root(
        self,
        gc: ModuleType,
        db: FakeDb,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
        job_roots: tuple[Path, Path],
    ) -> None:
        """End to end on the fake: the first run, before any sleep, deletes an orphan and
        its files under organizations.ATTACHMENTS_ROOT."""
        first = job_roots[0]
        current = datetime.now(UTC)
        orphan = _row(db, world.chat_id, current - timedelta(hours=30))
        files = _row_files(first, ORG_ID, orphan, current)
        monkeypatch.setattr(asyncio, "sleep", _sleep_recorder([], stop_at=1))

        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(gc.run_gc_job(db.pool), _WAIT_S)

        assert (db.attachment_row(orphan), _present(files)) == (None, [False, False, False])


# ---------------------------------------------------------------------------
# 7. The stray sweep in chunks (GH-281, Decision 7, contract C1 to C3)
# ---------------------------------------------------------------------------

_SWEEP_FAILED: Final = "Attachment directory of org {} couldn't be swept ({})."


def _g3_chunks(db: FakeDb) -> list[tuple[uuid.UUID, list[uuid.UUID]]]:
    """(the bound org, the bound ids in order) of every G3 statement."""
    return [
        (uuid.UUID(str(args[0])), [uuid.UUID(str(item)) for item in args[1]])
        for sql, args in _attachment_calls(db)
        if sql == _G3
    ]


def _strays(root: Path, org_id: uuid.UUID, now: datetime, count: int) -> list[str]:
    """``count`` old ``<uuid>`` files without a row in the org's directory; their names."""
    names = [str(uuid.uuid4()) for _ in range(count)]
    for name in names:
        _entry(root, org_id, name, now, age=_OLD)
    return names


def _live_files(
    db: FakeDb, chat_id: uuid.UUID, root: Path, org_id: uuid.UUID, now: datetime, count: int
) -> list[str]:
    """``count`` young unsent rows (no orphans) whose ``<id>`` files are old: candidates
    that G3 finds, so the sweep keeps them; their names."""
    names = [str(_row(db, chat_id, now - timedelta(hours=1))) for _ in range(count)]
    for name in names:
        _entry(root, org_id, name, now, age=_OLD)
    return names


def _names(root: Path, org_id: uuid.UUID) -> list[str]:
    """The entries left in the org's directory, sorted."""
    org_dir = root / str(org_id)
    return sorted(os.listdir(org_dir)) if org_dir.is_dir() else []


class TestSweepChunks:
    def test_attachment_gc_sweep_chunk_size_is_1000(self, gc: ModuleType) -> None:
        chunk_size = getattr(gc, "SWEEP_CHUNK_SIZE", None)

        assert chunk_size == 1000

    async def test_attachment_gc_more_than_1000_strays_are_checked_in_chunks_of_1000(
        self, gc: ModuleType, db: FakeDb, world: _World, root: Path, now: datetime
    ) -> None:
        """Org A's directory: 2,500 old strays and 10 old files of live rows (2,510
        candidates); org B's: a young entry and an unknown name only (no candidate).
        Three G3 statements, each binding org A and at most 1,000 ids, name every
        candidate exactly once; none for org B. The strays go, the live files stay."""
        strays = _strays(root, ORG_ID, now, 2500)
        live = _live_files(db, world.chat_id, root, ORG_ID, now, 10)
        _entry(root, OTHER_ORG_ID, str(uuid.uuid4()), now, age=_YOUNG)
        _entry(root, OTHER_ORG_ID, "notes.txt", now, age=_OLD)

        result = await gc.collect_garbage(db.pool, root, now=now)

        chunks = _g3_chunks(db)
        bound = [str(item) for _, ids in chunks for item in ids]
        assert [org for org, _ in chunks] == [ORG_ID, ORG_ID, ORG_ID]
        assert max(len(ids) for _, ids in chunks) <= 1000
        assert (len(bound), set(bound)) == (2510, {*strays, *live})
        assert (result, _names(root, ORG_ID)) == (2500, sorted(live))
        assert len(_names(root, OTHER_ORG_ID)) == 2

    async def test_attachment_gc_sweep_chunk_size_is_read_at_call_time(
        self,
        gc: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        now: datetime,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """SWEEP_CHUNK_SIZE patched to 2: org A's 5 candidates (4 of them live rows'
        files, so they meet in at least two chunks) take three G3 statements, org B's 3
        strays two; each binds its directory's org and at most 2 ids, every candidate
        once. The rows found in any chunk keep their files; every stray goes."""
        monkeypatch.setattr(gc, "SWEEP_CHUNK_SIZE", 2, raising=False)
        live = _live_files(db, world.chat_id, root, ORG_ID, now, 4)
        stray_a = _strays(root, ORG_ID, now, 1)
        stray_b = _strays(root, OTHER_ORG_ID, now, 3)

        result = await gc.collect_garbage(db.pool, root, now=now)

        chunks = _g3_chunks(db)
        by_org = {
            org: sorted(str(item) for bound, ids in chunks if bound == org for item in ids)
            for org in (ORG_ID, OTHER_ORG_ID)
        }
        assert sorted(str(org) for org, _ in chunks) == sorted(
            [str(ORG_ID)] * 3 + [str(OTHER_ORG_ID)] * 2
        )
        assert max(len(ids) for _, ids in chunks) <= 2
        assert by_org == {ORG_ID: sorted([*live, *stray_a]), OTHER_ORG_ID: sorted(stray_b)}
        assert (result, _names(root, ORG_ID), _names(root, OTHER_ORG_ID)) == (
            4,
            sorted(live),
            [],
        )

    @pytest.mark.parametrize("failing_org", ["org-a", "org-b"])
    async def test_attachment_gc_failing_chunk_skips_only_its_directory(
        self,
        gc: ModuleType,
        db: FakeDb,
        world: _World,
        root: Path,
        now: datetime,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        failing_org: str,
    ) -> None:
        """SWEEP_CHUNK_SIZE 2; the second G3 of one org's directory (5 strays and an old
        .part) raises: nothing of that directory is removed, one warning names the org
        and the error's class (never its message, which holds a path), and the other
        org's 3 strays still go. Each org takes the failing role once, so whatever order
        the directories are visited in, one run meets the failure first."""
        caplog.set_level(logging.DEBUG)
        monkeypatch.setattr(gc, "SWEEP_CHUNK_SIZE", 2, raising=False)
        failing, swept = (
            (ORG_ID, OTHER_ORG_ID) if failing_org == "org-a" else (OTHER_ORG_ID, ORG_ID)
        )
        stuck = _strays(root, failing, now, 5)
        part = f"{uuid.uuid4()}.part"
        _entry(root, failing, part, now, age=_OLD)
        _strays(root, swept, now, 3)
        failing_calls: list[str] = []
        original = db.handle

        def handle(method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None) -> Any:
            if norm(sql) == _G3 and uuid.UUID(str(args[0])) == failing:
                failing_calls.append(sql)
                if len(failing_calls) == 2:
                    raise asyncpg.exceptions.QueryCanceledError(
                        f"canceling statement due to statement timeout {_LEAK_DIR}"
                    )
            return original(method, sql, args, via, tx)

        monkeypatch.setattr(db, "handle", handle)

        result = await gc.collect_garbage(db.pool, root, now=now)

        warnings = [
            record.getMessage()
            for record in caplog.records
            if record.levelno >= logging.WARNING and record.name.startswith("admino")
        ]
        assert (result, _names(root, swept)) == (3, [])
        assert _names(root, failing) == sorted([*stuck, part])
        assert warnings == [_SWEEP_FAILED.format(failing, "QueryCanceledError")]
        assert _LEAK_DIR not in _log_text(caplog)
