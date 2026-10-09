"""Tests for the trash retention purge job (GH-194: ``trash.purge_expired`` and
``trash.run_purge_job``).

Issue #194, Decisions 4 (retention), 7 (purge), 8 (purge job) and 9 (audit); contract
§2 (the ``chat.purge`` / ``file.purge`` events of the job), §4 (``purge_expired``,
``run_purge_job``, ``PURGE_INTERVAL_SECONDS``, ``scoped_settings.trash_retention_days``)
and §5 (R1, J1 to J5, T8, T9).

What these tests pin down:

- ``PURGE_INTERVAL_SECONDS == 3600.0`` is the default of ``run_purge_job``'s keyword-only
  ``interval_seconds``; ``purge_expired(pool, root, *, now=None)``'s ``now`` is
  keyword-only and defaults to the current time.
- Only expired items go: ``deleted_at <= now - retention`` (exactly at the cutoff goes,
  one second younger stays), per org with that org's effective retention: 30 without
  an org_settings row, a stored value, a stored value clamped into narrowed platform
  bounds (both ways), 0 (everything in the org's trash). Live rows never go. One org's
  retention never purges another org's items (each org takes the retention-0 role once).
- A chat goes with its messages and every attachment row of the chat (a file of its own
  of that chat included, counted in ``file_count``); the org's expired files of their own
  come after its chats. A file of a trashed chat's group is not purged on its own (J4
  only selects a file whose group is itself).
- After each item's commit (not before it, and before the next item's lock), exactly the
  purged files' ``<id>``, ``<id>.part`` and ``<id>.d/`` go under ``root/<org_id>/``;
  nothing else on disk changes (another org's directory included).
- One transaction per item, its audit event inside it: ``chat.purge`` (system, no user,
  no IP, ``{"file_count": n}``) and ``file.purge`` (system, no metadata). An audit
  failure rolls back only that item (rows and files stay); the rest goes on.
- An item restored between J2/J4 and its lock (J3/J5 no row) is skipped and not counted;
  the return value is the number of items purged.
- An org whose retention read, J2 or J4 fails is logged (its id and the class name) and
  the next org is purged (the failing org is left for the next run); a J1 failure
  propagates. The statement order: J1, then per org R1 (then the platform read on a
  cold cache), J2, J3 / T8 / T9 / the audit insert per chat, J4, J5 / the audit insert
  per file.
- Logs carry ids and exception class names only: never a title, a file name, the root
  path or an exception's message.
- ``run_purge_job(pool)``: ``purge_expired(pool, attachments.attachments_root())`` at
  once, then after each interval, the root read at each run; a failed run is logged by
  class name only and the job goes on; a cancellation (during a run or a sleep) ends it.

Harness: the module is imported lazily (fixture ``trash``), so this file collects before
it exists and every test fails on its own. ``FakeDb`` (tests/db_fakes.py) models
migration 0031 once ``0031_*.sql`` ships. Time is injected (``now=``) and every seeded
row carries a fixed ``deleted_at``; disk entries live under ``tmp_path``; the job's
sleeps are recorders and every job run is bounded by ``asyncio.wait_for``.

Security notes: titles and file names are canaries that must never reach a log record;
every statement binds the org it acts on (the job binds each org in turn).
"""

from __future__ import annotations

import asyncio
import dataclasses
import inspect
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import organizations, scoped_settings
from tests.conftest import default_test_platform_settings
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, norm

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path
    from types import ModuleType

_REAL_SLEEP = asyncio.sleep
_WAIT_S: Final = 5.0

_NOW: Final = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
_CREATED: Final = _NOW - timedelta(days=200)
_SECOND: Final = timedelta(seconds=1)
_DAYS_30: Final = timedelta(days=30)

# Content canaries: a chat title, a file name, a path marker. None may reach a log record.
_LEAK_TITLE: Final = "Salary-negotiation-Mueller-2026"
_LEAK_NAME: Final = "Quarterly-salaries-2026.xlsx"
_LEAK_DIR: Final = "/srv/private-share-marker"

# --- Contract §5 forms (normalized) ------------------------------------------------

_J1: Final = norm(
    "SELECT org_id FROM chats WHERE deleted_at IS NOT NULL UNION SELECT org_id FROM "
    "attachments WHERE deleted_at IS NOT NULL ORDER BY org_id"
)
_R1: Final = norm("SELECT trash_retention_days FROM org_settings WHERE org_id = $1")
_J2: Final = norm(
    "SELECT id FROM chats WHERE org_id = $1 AND deleted_at <= $2 ORDER BY deleted_at, id"
)
_J3: Final = norm(
    "SELECT id FROM chats WHERE id = $1 AND org_id = $2 AND deleted_at <= $3 FOR UPDATE"
)
_T8: Final = norm("SELECT id FROM attachments WHERE chat_id = $1 AND org_id = $2")
_T9: Final = norm("DELETE FROM chats WHERE id = $1 AND org_id = $2")
_J4: Final = norm(
    "SELECT id FROM attachments WHERE org_id = $1 AND trash_group_id = id AND deleted_at <= $2 "
    "ORDER BY deleted_at, id"
)
_J5: Final = norm(
    "DELETE FROM attachments WHERE id = $1 AND org_id = $2 AND trash_group_id = id "
    "AND deleted_at <= $3 RETURNING id"
)
_FORMS: Final = {
    _J1: "J1",
    _R1: "R1",
    _J2: "J2",
    _J3: "J3",
    _T8: "T8",
    _T9: "T9",
    _J4: "J4",
    _J5: "J5",
}
_AUDIT_INSERT: Final = "insert into audit_events"
_PLATFORM_READ: Final = "select llm_provider"


# --- Fixtures and helpers ----------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _World:
    """Org A with two members, org B with one."""

    db: FakeDb
    user_a: uuid.UUID
    colleague_a: uuid.UUID
    user_b: uuid.UUID


@pytest.fixture()
def trash() -> ModuleType:
    """The module under test, imported lazily (it doesn't exist before GH-194)."""
    import admino.trash as module

    return module


@pytest.fixture()
def world() -> _World:
    db = FakeDb()
    return _World(
        db=db,
        user_a=db.add_account(org_id=ORG_ID),
        colleague_a=db.add_account(org_id=ORG_ID),
        user_b=db.add_account(org_id=OTHER_ORG_ID),
    )


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    path = tmp_path / "attachments"
    path.mkdir()
    return path


def _canonical(value: Any) -> Any:
    """A plain uuid.UUID for any UUID (asyncpg's subclass included); others unchanged."""
    return uuid.UUID(int=value.int) if isinstance(value, uuid.UUID) else value


def _chat(
    db: FakeDb,
    owner: uuid.UUID,
    deleted_at: datetime | None,
    *,
    title: str = "",
    messages: int = 1,
) -> uuid.UUID:
    """A chat of ``owner`` (trashed at ``deleted_at``, its own trash group) with messages."""
    chat_id = db.add_chat(owner, title=title, created_at=_CREATED, deleted_at=deleted_at)
    for index in range(messages):
        db.add_chat_message(chat_id, "user", f"message {index}", created_at=_CREATED)
    return chat_id


def _file(
    db: FakeDb,
    chat_id: uuid.UUID,
    deleted_at: datetime | None,
    *,
    own_group: bool = False,
    filename: str = "a.pdf",
) -> uuid.UUID:
    """An attachment of ``chat_id``. Trashed: the backfill's group (its trashed chat's,
    else its own), or its own with ``own_group`` (deleted on its own before its chat)."""
    attachment_id = uuid.uuid4()
    extra: dict[str, Any] = {"trash_group_id": attachment_id} if own_group else {}
    return db.add_attachment(
        chat_id,
        attachment_id=attachment_id,
        filename=filename,
        size_bytes=10,
        status="ready",
        created_at=_CREATED,
        deleted_at=deleted_at,
        **extra,
    )


def _on_disk(root: Path, org_id: uuid.UUID, attachment_id: uuid.UUID) -> set[str]:
    """Write ``<id>``, ``<id>.part`` and ``<id>.d/page-1.png`` under ``root/<org_id>/``;
    return their relative paths (the ``.d`` directory included)."""
    org_dir = root / str(org_id)
    org_dir.mkdir(parents=True, exist_ok=True)
    (org_dir / str(attachment_id)).write_bytes(b"stored bytes")
    (org_dir / f"{attachment_id}.part").write_bytes(b"partial upload")
    derived = org_dir / f"{attachment_id}.d"
    derived.mkdir()
    (derived / "page-1.png").write_bytes(b"rendered page")
    return _entries_of(org_id, attachment_id)


def _entries_of(org_id: uuid.UUID, attachment_id: uuid.UUID) -> set[str]:
    """The relative paths ``_on_disk`` writes for one attachment."""
    base = f"{org_id}/{attachment_id}"
    return {base, f"{base}.part", f"{base}.d", f"{base}.d/page-1.png"}


def _tree(root: Path) -> set[str]:
    """Every entry under ``root`` (files and directories), relative POSIX paths."""
    return {path.relative_to(root).as_posix() for path in root.rglob("*")}


def _purges(db: FakeDb) -> list[dict[str, Any]]:
    """The chat.purge and file.purge audit rows in insertion order, normalized."""
    return [
        {
            "org_id": str(row["org_id"]),
            "actor_kind": row["actor_kind"],
            "actor_user_id": row["actor_user_id"],
            "action": row["action"],
            "target_type": row["target_type"],
            "target_ids": row["target_ids"],
            "ip": row["ip"],
            # JSON text: {"file_count": True} would equal {"file_count": 1} as a dict.
            "metadata": json.dumps(row["metadata"], sort_keys=True),
        }
        for row in db.audit_rows()
        if row["action"] in {"chat.purge", "file.purge"}
    ]


def _chat_purge(org_id: uuid.UUID, chat_id: uuid.UUID, file_count: int) -> dict[str, Any]:
    return {
        "org_id": str(org_id),
        "actor_kind": "system",
        "actor_user_id": None,
        "action": "chat.purge",
        "target_type": "chat",
        "target_ids": [str(chat_id)],
        "ip": None,
        "metadata": json.dumps({"file_count": file_count}),
    }


def _file_purge(org_id: uuid.UUID, attachment_id: uuid.UUID) -> dict[str, Any]:
    return {
        "org_id": str(org_id),
        "actor_kind": "system",
        "actor_user_id": None,
        "action": "file.purge",
        "target_type": "file",
        "target_ids": [str(attachment_id)],
        "ip": None,
        "metadata": "{}",
    }


def _gone(db: FakeDb, chat_ids: list[uuid.UUID], file_ids: list[uuid.UUID]) -> list[bool]:
    """Per chat (row and messages) then per file (row): True when it was removed."""
    chats = [db.chat_row(chat) is None and db.messages_of(chat) == [] for chat in chat_ids]
    return chats + [db.attachment_row(attachment) is None for attachment in file_ids]


def _set_platform_bounds(monkeypatch: pytest.MonkeyPatch, min_days: int, max_days: int) -> None:
    """Make the cached platform settings carry these trash bounds (GH-160)."""
    data = default_test_platform_settings().model_dump()
    data["retention"] = {
        **data["retention"],
        "trash_min_days": min_days,
        "trash_max_days": max_days,
    }
    stored = scoped_settings.StoredPlatformSettings.model_validate(data)
    monkeypatch.setattr(scoped_settings, "_platform_cache", stored)


def _log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured record, formatted with its traceback (exc_info) if any."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(formatter.format(record) for record in caplog.records)


def _warnings_naming(caplog: pytest.LogCaptureFixture, *parts: str) -> list[logging.LogRecord]:
    """WARNING-or-above records of admino loggers whose message holds every part."""
    return [
        record
        for record in caplog.records
        if record.levelno >= logging.WARNING
        and record.name.startswith("admino")
        and all(part in record.getMessage() for part in parts)
    ]


class _PurgeProbeError(Exception):
    """A failing statement: its message names a title, a file and a path."""


def _probe_error() -> _PurgeProbeError:
    return _PurgeProbeError(f"{_LEAK_TITLE} / {_LEAK_NAME} in {_LEAK_DIR}")


def _hook(
    monkeypatch: pytest.MonkeyPatch,
    db: FakeDb,
    *,
    before: Callable[[str, tuple[Any, ...]], None] | None = None,
    after: Callable[[str, tuple[Any, ...]], None] | None = None,
) -> None:
    """Wrap ``db.handle``: ``before(normalized_sql, args)`` runs before a statement (it may
    raise), ``after(normalized_sql, args)`` once it has run."""
    original = db.handle

    def handle(method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None) -> Any:
        normalized = norm(sql)
        canonical_args = tuple(_canonical(arg) for arg in args)
        if before is not None:
            before(normalized, canonical_args)
        result = original(method, sql, args, via, tx)
        if after is not None:
            after(normalized, canonical_args)
        return result

    monkeypatch.setattr(db, "handle", handle)


# ---------------------------------------------------------------------------
# 1. Names and defaults
# ---------------------------------------------------------------------------


class TestNames:
    def test_trash_purge_job_interval_is_an_hour(self, trash: ModuleType) -> None:
        """PURGE_INTERVAL_SECONDS is 3600.0 and run_purge_job's keyword-only default."""
        parameter = inspect.signature(trash.run_purge_job).parameters["interval_seconds"]

        assert (trash.PURGE_INTERVAL_SECONDS, parameter.kind, parameter.default) == (
            3600.0,
            inspect.Parameter.KEYWORD_ONLY,
            3600.0,
        )

    def test_trash_purge_job_now_is_keyword_only_and_optional(self, trash: ModuleType) -> None:
        """purge_expired(pool, root, *, now=None)."""
        parameters = inspect.signature(trash.purge_expired).parameters

        assert [(name, p.kind, p.default) for name, p in parameters.items()] == [
            ("pool", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
            ("root", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
            ("now", inspect.Parameter.KEYWORD_ONLY, None),
        ]


# ---------------------------------------------------------------------------
# 2. Expiry: only expired items, per org with its own effective retention
# ---------------------------------------------------------------------------


class TestExpiry:
    @pytest.mark.parametrize(
        ("stored", "bounds", "effective"),
        [
            pytest.param(None, None, 30, id="no-org-settings-row-30"),
            pytest.param(7, None, 7, id="stored-7"),
            pytest.param(30, (0, 10), 10, id="stored-30-clamped-to-max-10"),
            pytest.param(2, (5, 90), 5, id="stored-2-clamped-to-min-5"),
            pytest.param(0, None, 0, id="stored-0-everything"),
        ],
    )
    async def test_trash_purge_job_purges_at_the_cutoff_and_keeps_one_second_younger(
        self,
        trash: ModuleType,
        world: _World,
        root: Path,
        monkeypatch: pytest.MonkeyPatch,
        stored: int | None,
        bounds: tuple[int, int] | None,
        effective: int,
    ) -> None:
        """A chat and a file of its own deleted exactly ``effective`` days before ``now``
        go; the pair deleted one second later stays, and so do a live chat and file. The
        effective retention is the stored value clamped into the platform bounds (30
        without an org_settings row), never the raw stored value."""
        db = world.db
        if stored is not None:
            db.add_org_settings(ORG_ID, trash_retention_days=stored)
        if bounds is not None:
            _set_platform_bounds(monkeypatch, *bounds)
        cutoff = _NOW - timedelta(days=effective)
        live_chat = _chat(db, world.user_a, None)
        expired_chat = _chat(db, world.user_a, cutoff)
        kept_chat = _chat(db, world.user_a, cutoff + _SECOND)
        expired_file = _file(db, live_chat, cutoff)
        kept_file = _file(db, live_chat, cutoff + _SECOND)
        live_file = _file(db, live_chat, None)

        result = await trash.purge_expired(db.pool, root, now=_NOW)

        assert (result, _gone(db, [expired_chat], [expired_file])) == (2, [True, True])
        assert _gone(db, [kept_chat, live_chat], [kept_file, live_file]) == [False] * 4

    @pytest.mark.parametrize("zero_org", ["org-a", "org-b"])
    async def test_trash_purge_job_one_orgs_retention_never_purges_another_orgs_items(
        self, trash: ModuleType, world: _World, root: Path, zero_org: str
    ) -> None:
        """One org has retention 0, the other none set (30): items both deleted an hour
        ago go only in the retention-0 org. Each org takes the zero role once, so a
        retention read once (or of the wrong org) fails one of the two runs."""
        db = world.db
        zero_id, default_id = (
            (ORG_ID, OTHER_ORG_ID) if zero_org == "org-a" else (OTHER_ORG_ID, ORG_ID)
        )
        db.add_org_settings(zero_id, trash_retention_days=0)
        owners = {ORG_ID: world.user_a, OTHER_ORG_ID: world.user_b}
        deleted = _NOW - timedelta(hours=1)
        purged_chat = _chat(db, owners[zero_id], deleted)
        purged_file = _file(db, _chat(db, owners[zero_id], None), deleted)
        kept_chat = _chat(db, owners[default_id], deleted)
        kept_file = _file(db, _chat(db, owners[default_id], None), deleted)

        result = await trash.purge_expired(db.pool, root, now=_NOW)

        assert (result, _gone(db, [purged_chat, kept_chat], [purged_file, kept_file])) == (
            2,
            [True, False, True, False],
        )

    async def test_trash_purge_job_purges_every_members_expired_items(
        self, trash: ModuleType, world: _World, root: Path
    ) -> None:
        """The job is org-wide: the expired items of every member of the org go."""
        db = world.db
        old = _NOW - _DAYS_30 - timedelta(days=1)
        chats = [_chat(db, world.user_a, old), _chat(db, world.colleague_a, old)]
        files = [
            _file(db, _chat(db, world.user_a, None), old),
            _file(db, _chat(db, world.colleague_a, None), old),
        ]

        result = await trash.purge_expired(db.pool, root, now=_NOW)

        assert (result, _gone(db, chats, files)) == (4, [True] * 4)

    async def test_trash_purge_job_now_defaults_to_the_current_time(
        self, trash: ModuleType, world: _World, root: Path
    ) -> None:
        """Without ``now``: a chat deleted 31 days ago goes, one deleted 29 days ago stays."""
        db = world.db
        current = datetime.now(UTC)
        old = db.add_chat(
            world.user_a, created_at=_CREATED, deleted_at=current - timedelta(days=31)
        )
        young = db.add_chat(
            world.user_a, created_at=_CREATED, deleted_at=current - timedelta(days=29)
        )

        await trash.purge_expired(db.pool, root)

        assert (db.chat_row(old), db.chat_row(young) is not None) == (None, True)


# ---------------------------------------------------------------------------
# 3. What a purged chat takes with it; files of their own after the chats
# ---------------------------------------------------------------------------


class TestCascade:
    async def test_trash_purge_job_chat_goes_with_messages_and_every_file_of_the_chat(
        self, trash: ModuleType, world: _World, root: Path
    ) -> None:
        """An expired chat goes with its messages, the file of its group and two files of
        their own (deleted before the chat: one expired by itself, one not): one
        chat.purge with file_count 3 and no file.purge (the chats go before J4)."""
        db = world.db
        chat = _chat(db, world.user_a, _NOW - timedelta(days=31), messages=3)
        group_file = _file(db, chat, _NOW - timedelta(days=31))
        own_file = _file(db, chat, _NOW - timedelta(days=40), own_group=True)
        younger_own_file = _file(db, chat, _NOW - timedelta(days=2), own_group=True)

        result = await trash.purge_expired(db.pool, root, now=_NOW)

        assert (result, _gone(db, [chat], [group_file, own_file, younger_own_file])) == (
            1,
            [True, True, True, True],
        )
        assert _purges(db) == [_chat_purge(ORG_ID, chat, 3)]

    async def test_trash_purge_job_group_file_is_not_purged_on_its_own(
        self, trash: ModuleType, world: _World, root: Path
    ) -> None:
        """A file of a trashed chat's group whose own stamp is expired (0031's backfill can
        give one) stays with its chat while the chat isn't expired: J4 selects only a file
        that is its own group."""
        db = world.db
        chat = _chat(db, world.user_a, _NOW - timedelta(days=10))
        group_file = _file(db, chat, _NOW - timedelta(days=40))
        files = _on_disk(root, ORG_ID, group_file)

        result = await trash.purge_expired(db.pool, root, now=_NOW)

        assert (result, db.attachment_row(group_file) is not None, files <= _tree(root)) == (
            0,
            True,
            True,
        )
        assert _purges(db) == []


# ---------------------------------------------------------------------------
# 4. Files on disk
# ---------------------------------------------------------------------------


class TestFilesOnDisk:
    async def test_trash_purge_job_removes_exactly_the_purged_files(
        self, trash: ModuleType, world: _World, root: Path
    ) -> None:
        """``<id>``, ``<id>.part`` and ``<id>.d/`` of every purged attachment go (a purged
        chat's files and an expired file of its own); the kept items' files, a stray, the
        same id under another org's directory and the other org's files stay."""
        db = world.db
        old = _NOW - timedelta(days=31)
        live_chat = _chat(db, world.user_a, None)
        chat = _chat(db, world.colleague_a, old)
        chat_files = [_file(db, chat, old), _file(db, chat, old - _SECOND, own_group=True)]
        own_file = _file(db, live_chat, old)
        kept_file = _file(db, live_chat, _NOW - timedelta(days=3))
        live_file = _file(db, live_chat, None)
        other_file = _file(db, _chat(db, world.user_b, None), _NOW - timedelta(days=3))
        purged = set().union(*(_on_disk(root, ORG_ID, item) for item in [*chat_files, own_file]))
        for item in (kept_file, live_file):
            _on_disk(root, ORG_ID, item)
        _on_disk(root, OTHER_ORG_ID, other_file)
        _on_disk(root, OTHER_ORG_ID, own_file)
        (root / str(ORG_ID) / "notes.txt").write_bytes(b"not an attachment")
        before = _tree(root)

        await trash.purge_expired(db.pool, root, now=_NOW)

        assert _tree(root) == before - purged

    async def test_trash_purge_job_files_go_after_each_commit_before_the_next_item(
        self,
        trash: ModuleType,
        world: _World,
        root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """While an item's audit row is written (inside its transaction) its files are still
        there; by the next item's lock (J3 / J5) they are gone."""
        db = world.db
        old = _NOW - timedelta(days=31)
        first = _chat(db, world.user_a, old - _SECOND)
        second = _chat(db, world.user_a, old)
        own_file = _file(db, _chat(db, world.user_a, None), old)
        first_file = _file(db, first, old - _SECOND)
        second_file = _file(db, second, old)
        paths = {
            item: root / str(ORG_ID) / str(item) for item in (first_file, second_file, own_file)
        }
        for item in paths:
            _on_disk(root, ORG_ID, item)
        seen: list[tuple[str, list[bool]]] = []

        def before(sql: str, _args: tuple[Any, ...]) -> None:
            label = "audit" if sql.startswith(_AUDIT_INSERT) else _FORMS.get(sql)
            if label in {"audit", "J3", "J5"}:
                seen.append((label, [path.exists() for path in paths.values()]))

        _hook(monkeypatch, db, before=before)

        await trash.purge_expired(db.pool, root, now=_NOW)

        assert seen == [
            ("J3", [True, True, True]),
            ("audit", [True, True, True]),
            ("J3", [False, True, True]),
            ("audit", [False, True, True]),
            ("J5", [False, False, True]),
            ("audit", [False, False, True]),
        ]


# ---------------------------------------------------------------------------
# 5. Transactions, audit rows and failures of one item
# ---------------------------------------------------------------------------


class TestItemsAndAudit:
    async def test_trash_purge_job_audits_each_item_as_the_system(
        self, trash: ModuleType, world: _World, root: Path
    ) -> None:
        """chat.purge: system, no user, no IP, the chat, {"file_count": n} (n = its
        attachment rows, 0 included); file.purge: system, the file, no metadata. Each
        org's chats first, then its files; the orgs in J1's order."""
        db = world.db
        old = _NOW - timedelta(days=31)
        chat_a = _chat(db, world.user_a, old, title=_LEAK_TITLE)
        _file(db, chat_a, old, filename=_LEAK_NAME)
        _file(db, chat_a, old)
        empty_chat_b = _chat(db, world.user_b, old)
        file_a = _file(db, _chat(db, world.user_a, None), old - timedelta(days=5))
        file_b = _file(db, _chat(db, world.user_b, None), old)

        result = await trash.purge_expired(db.pool, root, now=_NOW)

        assert result == 4
        assert _purges(db) == [
            _chat_purge(ORG_ID, chat_a, 2),
            _file_purge(ORG_ID, file_a),
            _chat_purge(OTHER_ORG_ID, empty_chat_b, 0),
            _file_purge(OTHER_ORG_ID, file_b),
        ]

    async def test_trash_purge_job_each_item_in_its_own_transaction(
        self, trash: ModuleType, world: _World, root: Path
    ) -> None:
        """J3, T8, T9 and the chat's audit insert share one transaction; J5 and the file's
        audit insert another; every item has its own."""
        db = world.db
        old = _NOW - timedelta(days=31)
        for _ in range(2):
            _file(db, _chat(db, world.user_a, old), old)
        for _ in range(2):
            _file(db, _chat(db, world.user_a, None), old)
        db.calls.clear()

        await trash.purge_expired(db.pool, root, now=_NOW)

        steps = [
            ("audit" if call.normalized.startswith(_AUDIT_INSERT) else _FORMS.get(call.normalized))
            for call in db.calls
        ]
        item_calls = [
            (step, call.tx, call.via)
            for step, call in zip(steps, db.calls, strict=True)
            if step in {"J3", "T8", "T9", "J5", "audit"}
        ]
        groups = [item_calls[0:4], item_calls[4:8], item_calls[8:10], item_calls[10:12]]
        assert [[step for step, _, _ in group] for group in groups] == [
            ["J3", "T8", "T9", "audit"],
            ["J3", "T8", "T9", "audit"],
            ["J5", "audit"],
            ["J5", "audit"],
        ]
        transactions = [{(tx, via) for _, tx, via in group} for group in groups]
        assert all(len(group) == 1 and None not in next(iter(group)) for group in transactions)
        assert len(set().union(*transactions)) == 4

    async def test_trash_purge_job_audit_failure_rolls_back_only_that_item(
        self,
        trash: ModuleType,
        world: _World,
        root: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A refused audit write rolls its item back: the chat with its messages and files
        (rows and disk), the file (row and disk) stay; the other chat and file still go.
        Each failure is logged with the item's id and the class name."""
        caplog.set_level(logging.DEBUG)
        db = world.db
        old = _NOW - timedelta(days=31)
        refused_chat = _chat(db, world.user_a, old - _SECOND, messages=2)
        refused_chat_file = _file(db, refused_chat, old - _SECOND)
        purged_chat = _chat(db, world.user_a, old)
        live_chat = _chat(db, world.user_a, None)
        refused_file = _file(db, live_chat, old - _SECOND)
        purged_file = _file(db, live_chat, old)
        kept = _on_disk(root, ORG_ID, refused_chat_file) | _on_disk(root, ORG_ID, refused_file)
        refused = {str(refused_chat), str(refused_file)}
        db.fail_audit_when = lambda row: row["target_ids"][0] in refused

        result = await trash.purge_expired(db.pool, root, now=_NOW)

        assert (result, _gone(db, [purged_chat], [purged_file])) == (2, [True, True])
        assert _gone(db, [refused_chat], [refused_chat_file, refused_file]) == [False] * 3
        assert (len(db.messages_of(refused_chat)), kept <= _tree(root)) == (2, True)
        assert _purges(db) == [
            _chat_purge(ORG_ID, purged_chat, 0),
            _file_purge(ORG_ID, purged_file),
        ]
        assert _warnings_naming(caplog, str(refused_chat), "AuditRecordError")
        assert _warnings_naming(caplog, str(refused_file), "AuditRecordError")

    async def test_trash_purge_job_chat_restored_before_its_lock_is_skipped(
        self,
        trash: ModuleType,
        world: _World,
        root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A chat restored between J2 and its J3 (no row) is skipped: not counted, no
        event, its rows and files stay; the next chat is still purged."""
        db = world.db
        old = _NOW - timedelta(days=31)
        restored = _chat(db, world.user_a, old - _SECOND)
        restored_file = _file(db, restored, old - _SECOND)
        purged = _chat(db, world.user_a, old)
        files = _on_disk(root, ORG_ID, restored_file)

        def after(sql: str, _args: tuple[Any, ...]) -> None:
            if sql == _J2:
                for row in (db.chats[restored], db.attachments[restored_file]):
                    row["deleted_at"] = None
                    row["trash_group_id"] = None

        _hook(monkeypatch, db, after=after)

        result = await trash.purge_expired(db.pool, root, now=_NOW)

        assert (result, _gone(db, [restored, purged], [restored_file])) == (
            1,
            [False, True, False],
        )
        assert (files <= _tree(root), _purges(db)) == (True, [_chat_purge(ORG_ID, purged, 0)])

    async def test_trash_purge_job_file_restored_before_its_lock_is_skipped(
        self,
        trash: ModuleType,
        world: _World,
        root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A file restored between J4 and its J5 (no row) is skipped: not counted, no event,
        its row and files stay; the next file is still purged."""
        db = world.db
        old = _NOW - timedelta(days=31)
        live_chat = _chat(db, world.user_a, None)
        restored = _file(db, live_chat, old - _SECOND)
        purged = _file(db, live_chat, old)
        files = _on_disk(root, ORG_ID, restored)

        def after(sql: str, _args: tuple[Any, ...]) -> None:
            if sql == _J4:
                db.attachments[restored]["deleted_at"] = None
                db.attachments[restored]["trash_group_id"] = None

        _hook(monkeypatch, db, after=after)

        result = await trash.purge_expired(db.pool, root, now=_NOW)

        assert (result, _gone(db, [], [restored, purged])) == (1, [False, True])
        assert (files <= _tree(root), _purges(db)) == (True, [_file_purge(ORG_ID, purged)])


# ---------------------------------------------------------------------------
# 6. Statements, org failures and logs
# ---------------------------------------------------------------------------


class TestStatementsAndFailures:
    async def test_trash_purge_job_statement_order(
        self, trash: ModuleType, world: _World, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """J1, then per org (J1's order): R1, the platform read (cold cache: once),
        J2 with the org's cutoff, J3 / T8 / T9 / audit per chat, J4, J5 / audit per file.
        Every statement binds the org it acts on."""
        db = world.db
        db.add_platform_settings()
        monkeypatch.setattr(scoped_settings, "_platform_cache", None)
        db.add_org_settings(OTHER_ORG_ID, trash_retention_days=7)
        old = _NOW - timedelta(days=31)
        chat_a = _chat(db, world.user_a, old)
        file_a = _file(db, _chat(db, world.user_a, None), old)
        chat_b = _chat(db, world.user_b, _NOW - timedelta(days=8))
        cut_a = _NOW - _DAYS_30
        cut_b = _NOW - timedelta(days=7)
        db.calls.clear()

        await trash.purge_expired(db.pool, root, now=_NOW)

        steps = [
            (
                "audit"
                if call.normalized.startswith(_AUDIT_INSERT)
                else "platform"
                if call.normalized.startswith(_PLATFORM_READ)
                else _FORMS.get(call.normalized, call.normalized),
                ()
                if call.normalized.startswith((_AUDIT_INSERT, _PLATFORM_READ))
                else tuple(_canonical(arg) for arg in call.args),
            )
            for call in db.calls
        ]
        assert steps == [
            ("J1", ()),
            ("R1", (ORG_ID,)),
            ("platform", ()),
            ("J2", (ORG_ID, cut_a)),
            ("J3", (chat_a, ORG_ID, cut_a)),
            ("T8", (chat_a, ORG_ID)),
            ("T9", (chat_a, ORG_ID)),
            ("audit", ()),
            ("J4", (ORG_ID, cut_a)),
            ("J5", (file_a, ORG_ID, cut_a)),
            ("audit", ()),
            ("R1", (OTHER_ORG_ID,)),
            ("J2", (OTHER_ORG_ID, cut_b)),
            ("J3", (chat_b, OTHER_ORG_ID, cut_b)),
            ("T8", (chat_b, OTHER_ORG_ID)),
            ("T9", (chat_b, OTHER_ORG_ID)),
            ("audit", ()),
            ("J4", (OTHER_ORG_ID, cut_b)),
        ]

    async def test_trash_purge_job_without_trash_reads_nothing_more(
        self, trash: ModuleType, world: _World, root: Path
    ) -> None:
        """No trashed row anywhere: J1 answers no org, nothing else runs, 0 purged."""
        db = world.db
        _file(db, _chat(db, world.user_a, None), None)
        db.calls.clear()

        result = await trash.purge_expired(db.pool, root, now=_NOW)

        assert (result, [call.normalized for call in db.calls]) == (0, [_J1])

    @pytest.mark.parametrize("failing", ["R1", "J2", "J4"])
    async def test_trash_purge_job_failing_org_is_logged_and_the_next_org_purged(
        self,
        trash: ModuleType,
        world: _World,
        root: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        failing: str,
    ) -> None:
        """Org A (first in J1's order) fails at its retention read, J2 or J4: a warning
        names the org and the class; org A is left for the next run from the failing
        step on (what it purged before stays purged and counted) and org B is purged."""
        caplog.set_level(logging.DEBUG)
        db = world.db
        old = _NOW - timedelta(days=31)
        chat_a = _chat(db, world.user_a, old)
        file_a = _file(db, _chat(db, world.user_a, None), old)
        chat_b = _chat(db, world.user_b, old)
        file_b = _file(db, _chat(db, world.user_b, None), old)

        def before(sql: str, args: tuple[Any, ...]) -> None:
            if _FORMS.get(sql) == failing and args[0] == ORG_ID:
                raise _probe_error()

        _hook(monkeypatch, db, before=before)

        result = await trash.purge_expired(db.pool, root, now=_NOW)

        chat_a_purged = failing == "J4"
        assert (result, _gone(db, [chat_a, chat_b], [file_a, file_b])) == (
            3 if chat_a_purged else 2,
            [chat_a_purged, True, False, True],
        )
        assert _warnings_naming(caplog, str(ORG_ID), _PurgeProbeError.__name__)

    async def test_trash_purge_job_j1_failure_propagates(
        self, trash: ModuleType, world: _World, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failing J1 (which orgs have trash) is the run's failure: it propagates."""
        db = world.db
        _chat(db, world.user_a, _NOW - timedelta(days=31))

        def before(sql: str, _args: tuple[Any, ...]) -> None:
            if sql == _J1:
                raise _probe_error()

        _hook(monkeypatch, db, before=before)

        with pytest.raises(_PurgeProbeError):
            await trash.purge_expired(db.pool, root, now=_NOW)

    async def test_trash_purge_job_logs_carry_no_title_name_path_or_message(
        self,
        trash: ModuleType,
        world: _World,
        root: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Items titled and named like real documents are purged, one item's audit write
        fails and org B's retention read fails with a message naming a title, a file and
        a path: the logs name the failures, never a title, a file name, the root or the
        error's message (tracebacks included)."""
        caplog.set_level(logging.DEBUG)
        db = world.db
        old = _NOW - timedelta(days=31)
        chat = _chat(db, world.user_a, old, title=_LEAK_TITLE)
        _on_disk(root, ORG_ID, _file(db, chat, old, filename=_LEAK_NAME))
        refused = _chat(db, world.user_a, old - _SECOND, title=_LEAK_TITLE)
        _file(db, refused, old - _SECOND, filename=_LEAK_NAME)
        _file(db, _chat(db, world.user_a, None, title=_LEAK_TITLE), old, filename=_LEAK_NAME)
        _chat(db, world.user_b, old, title=_LEAK_TITLE)
        db.fail_audit_when = lambda row: row["target_ids"] == [str(refused)]

        def before(sql: str, args: tuple[Any, ...]) -> None:
            if sql == _R1 and args[0] == OTHER_ORG_ID:
                raise _probe_error()

        _hook(monkeypatch, db, before=before)

        await trash.purge_expired(db.pool, root, now=_NOW)

        text = _log_text(caplog)
        assert _warnings_naming(caplog, _PurgeProbeError.__name__)
        assert _warnings_naming(caplog, "AuditRecordError")
        assert [marker in text for marker in (_LEAK_TITLE, _LEAK_NAME, _LEAK_DIR, str(root))] == [
            False
        ] * 4


# ---------------------------------------------------------------------------
# 7. run_purge_job
# ---------------------------------------------------------------------------


class _PurgeRecorder:
    """Replaces purge_expired: records the pool and root of each run."""

    def __init__(self, events: list[str], labels: dict[Path, str]) -> None:
        self.events = events
        self.labels = labels
        self.pools: list[Any] = []
        self.failures: list[BaseException] = []

    async def __call__(self, pool: Any, root: Path, *, now: datetime | None = None) -> int:
        self.pools.append(pool)
        self.events.append(f"purge {self.labels.get(root, str(root))}")
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


class TestRunPurgeJob:
    async def test_trash_purge_job_runs_now_then_hourly(
        self, trash: ModuleType, monkeypatch: pytest.MonkeyPatch, job_roots: tuple[Path, Path]
    ) -> None:
        """purge_expired(pool, attachments_root()) at once, then after each 3600 s sleep."""
        events: list[str] = []
        recorder = _PurgeRecorder(events, {job_roots[0]: "root-1"})
        pool = object()
        monkeypatch.setattr(trash, "purge_expired", recorder)
        monkeypatch.setattr(asyncio, "sleep", _sleep_recorder(events, stop_at=2))

        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(trash.run_purge_job(pool), _WAIT_S)

        assert events == ["purge root-1", "sleep 3600.0", "purge root-1", "sleep 3600.0"]
        assert recorder.pools == [pool, pool]

    async def test_trash_purge_job_reads_the_root_at_each_run(
        self, trash: ModuleType, monkeypatch: pytest.MonkeyPatch, job_roots: tuple[Path, Path]
    ) -> None:
        """organizations.ATTACHMENTS_ROOT changed during a sleep: the next run uses it."""
        events: list[str] = []
        first, second = job_roots

        def move_root(call: int) -> None:
            if call == 1:
                monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", second)

        monkeypatch.setattr(
            trash, "purge_expired", _PurgeRecorder(events, {first: "root-1", second: "root-2"})
        )
        monkeypatch.setattr(asyncio, "sleep", _sleep_recorder(events, stop_at=2, on_call=move_root))

        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(trash.run_purge_job(object(), interval_seconds=5.0), _WAIT_S)

        assert events == ["purge root-1", "sleep 5.0", "purge root-2", "sleep 5.0"]

    async def test_trash_purge_job_failed_run_is_logged_and_job_continues(
        self,
        trash: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        job_roots: tuple[Path, Path],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A failing run is logged by class name (never its message) and the next runs."""
        caplog.set_level(logging.DEBUG)
        events: list[str] = []
        recorder = _PurgeRecorder(events, {job_roots[0]: "root-1"})
        recorder.failures.append(_probe_error())
        monkeypatch.setattr(trash, "purge_expired", recorder)
        monkeypatch.setattr(asyncio, "sleep", _sleep_recorder(events, stop_at=2))

        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(trash.run_purge_job(object(), interval_seconds=5.0), _WAIT_S)

        text = _log_text(caplog)
        assert events == ["purge root-1", "sleep 5.0", "purge root-1", "sleep 5.0"]
        assert _warnings_naming(caplog, _PurgeProbeError.__name__)
        assert [marker in text for marker in (_LEAK_TITLE, _LEAK_NAME, _LEAK_DIR)] == [False] * 3

    async def test_trash_purge_job_cancelled_run_ends_the_job(
        self, trash: ModuleType, monkeypatch: pytest.MonkeyPatch, job_roots: tuple[Path, Path]
    ) -> None:
        """A cancellation during a run isn't a failed run: it propagates, no sleep follows."""
        events: list[str] = []
        recorder = _PurgeRecorder(events, {job_roots[0]: "root-1"})
        recorder.failures.append(asyncio.CancelledError())
        monkeypatch.setattr(trash, "purge_expired", recorder)
        monkeypatch.setattr(asyncio, "sleep", _sleep_recorder(events, stop_at=3))

        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(trash.run_purge_job(object()), _WAIT_S)

        assert events == ["purge root-1"]

    async def test_trash_purge_job_task_cancel_stops_it(
        self, trash: ModuleType, monkeypatch: pytest.MonkeyPatch, job_roots: tuple[Path, Path]
    ) -> None:
        """Cancelling the job's task while it sleeps ends it."""
        sleeping = asyncio.Event()

        async def blocking_sleep(delay: float, *_args: Any, **_kwargs: Any) -> None:
            sleeping.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(trash, "purge_expired", _PurgeRecorder([], {}))
        monkeypatch.setattr(asyncio, "sleep", blocking_sleep)
        task = asyncio.create_task(trash.run_purge_job(object()))
        await asyncio.wait_for(sleeping.wait(), _WAIT_S)

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, _WAIT_S)

        assert task.cancelled()

    async def test_trash_purge_job_purges_under_the_attachments_root(
        self,
        trash: ModuleType,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
        job_roots: tuple[Path, Path],
    ) -> None:
        """End to end on the fake: the first run, before any sleep, purges an expired chat
        and its files under organizations.ATTACHMENTS_ROOT."""
        db = world.db
        current = datetime.now(UTC)
        chat = db.add_chat(
            world.user_a, created_at=_CREATED, deleted_at=current - timedelta(days=31)
        )
        attachment = _file(db, chat, current - timedelta(days=31))
        files = _on_disk(job_roots[0], ORG_ID, attachment)
        monkeypatch.setattr(asyncio, "sleep", _sleep_recorder([], stop_at=1))

        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(trash.run_purge_job(db.pool), _WAIT_S)

        assert (db.chat_row(chat), db.attachment_row(attachment)) == (None, None)
        assert files & _tree(job_roots[0]) == set()
