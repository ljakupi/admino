"""Tests for ``admino.attachment_processing`` under GH-190: the upload rejection (Decision 7).

Issue #190, "Uploads": a new attachment that pushes the chat over the limit is
rejected right after its token count is known, before it becomes ``ready``.
Contract C7: ``process_attachment(..., budget=BudgetSettings(...))`` sums the
estimates of the chat's other live, ``ready``, active attachments (P6, sent or
not; a NULL estimate counts 0) after the page check and before the quota
transaction; when ``others + (processed.token_estimate or 0)`` is above
``available_attachment_tokens(budget_limit(<the platform's max_input_tokens>,
margin), reserved)``, P3'' stores ``failed`` / ``context_overflow`` with the
estimate, the derived files are removed, nothing counts toward the quota and one
log line carries the id and the code only. ``budget=None`` (the default) is
exactly today's behaviour. ``ProcessingPool(budget=...)`` passes it to every job.
Runs against tests/db_fakes.py (P6 and P3'' as PostgreSQL answers them; the
excluded-file case needs migration 0030, which the fake models once it ships).

The budget used throughout: the platform's ``max_input_tokens`` 10 001, a margin of
10 % and 1 000 reserved output tokens give ``budget_limit = 10 001 - ceil(1 000.1) =
9 000`` (a floor would give 9 001) and 8 000 tokens for the attachments.

What these tests pin down:
- ``process_attachment``'s and ``ProcessingPool``'s ``budget`` are keyword-only,
  default None.
- Under (others 5 000 + 2 999), exactly at (+ 3 000) and one over (+ 3 001): ready,
  ready, failed. Counted: a ready active file of the same chat, unsent and sent
  alike. Not counted: an excluded, a failed, an uploaded, a processing or a
  trashed file, another chat's and another org's. NULL estimates (another
  file's, the processed file's) count 0.
- Over: status ``failed``, reason ``context_overflow``, ``token_estimate`` the
  processed estimate, ``derived_bytes`` NULL, no ``<id>.d`` left, the original
  kept, the result ``failed``; exactly P1', P7, P6, P3'' (no P2'', no quota
  statement, even under a zero quota); P6 and P3'' in the contract's forms and binds.
- Order: a page-count failure comes first (no P6); P6 runs before the quota
  transaction (an under-budget file of a full org is still
  ``storage_quota_exceeded`` after P6).
- The platform's ``max_input_tokens`` is the stored one, read once (a larger
  platform model accepts the same file).
- ``budget=None``: an estimate far above any budget is ``ready`` with today's
  statements (no P6).
- The pool: with a budget every job is checked, without one none is.
- Logs: the over-budget line names the id and ``context_overflow``; no file name.
- GH-294 (Decision 8): right before P6 the processor reads the file's own
  ``active`` flag (P7, contract form, binds the id and the org id). An exclusion
  made before the claim or during the conversion skips P6 and the rejection: the
  file is ``ready`` with the converter's estimate (even one over the attachments'
  share on its own), its derived files kept, still excluded. An active file and
  one included again before the check are checked as before (``context_overflow``).
  A row gone during the conversion (P7 finds none) gets P6 as today, then owns
  nothing. No budget: no P7; a page-count failure: no P7.

Imports of the module under test and of ``admino.context_budget`` are lazy.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import scoped_settings
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, plain

if TYPE_CHECKING:
    import uuid
    from collections.abc import Callable
    from pathlib import Path
    from types import ModuleType

    from tests.db_fakes import Call

NAME_CANARY: Final = "NAME-CANARY-190p board salaries.pdf"
_PLATFORM_MAX_INPUT: Final = 10_001
_MARGIN: Final = 10
_RESERVED: Final = 1_000
# budget_limit(10_001, 10) = 10_001 - ceil(1_000.1) = 9_000; minus 1_000 reserved.
_AVAILABLE: Final = 8_000
_OTHERS: Final = 5_000
_WAIT_S: Final = 30.0

_T0: Final = datetime(2026, 10, 9, 11, 0, 0, tzinfo=UTC)

# Contract forms (GH-187/188 P1', P2'', P3, A3, A4'; GH-190 C7 P6, P3''; GH-294 P7).
P1: Final = """
    UPDATE attachments SET status = 'processing', updated_at = now()
    WHERE id = $1 AND org_id = $2 AND status = 'uploaded'
    RETURNING kind, filename
"""
P2: Final = """
    UPDATE attachments SET status = 'ready', page_count = $3, token_estimate = $4,
        derived_bytes = $5, updated_at = now()
    WHERE id = $1 AND org_id = $2 AND status = 'processing'
"""
P3: Final = """
    UPDATE attachments SET status = 'failed', failure_reason = $3, updated_at = now()
    WHERE id = $1 AND org_id = $2 AND status = 'processing'
"""
A3: Final = "SELECT storage_quota_bytes FROM organizations WHERE id = $1 FOR NO KEY UPDATE"
A4: Final = (
    "SELECT coalesce(sum(size_bytes + coalesce(derived_bytes, 0)), 0) "
    "FROM attachments WHERE org_id = $1"
)
P6: Final = """
    SELECT coalesce(sum(o.token_estimate), 0)
    FROM attachments a
    JOIN attachments o ON o.chat_id = a.chat_id AND o.org_id = a.org_id
        AND o.owner_user_id = a.owner_user_id
    WHERE a.id = $1 AND a.org_id = $2 AND o.id <> a.id
      AND o.status = 'ready' AND o.active AND o.deleted_at IS NULL
"""
P3_SECOND: Final = """
    UPDATE attachments SET status = 'failed', failure_reason = $3, token_estimate = $4,
        updated_at = now()
    WHERE id = $1 AND org_id = $2 AND status = 'processing'
"""
# GH-294 Decision 8: the processed file's own active flag, right before P6.
P7: Final = "SELECT active FROM attachments WHERE id = $1 AND org_id = $2"


def _canon(sql: str) -> str:
    """Lowercased, whitespace collapsed and dropped around ( ) , = (tokens kept)."""
    text = re.sub(r"\s+", " ", sql.strip().lower()).rstrip(";").strip()
    return re.sub(r"\s*([(),=])\s*", r"\1", text)


_FORMS: Final = {
    "P1'": _canon(P1),
    "P2''": _canon(P2),
    "P3": _canon(P3),
    "P3''": _canon(P3_SECOND),
    "P6": _canon(P6),
    "P7": _canon(P7),
    "A3": _canon(A3),
    "A4'": _canon(A4),
}


def _form(call: Call) -> str:
    text = _canon(call.sql)
    return next((label for label, form in _FORMS.items() if form == text), call.normalized)


def _outcome_forms(db: FakeDb) -> list[str]:
    """The forms of every statement naming attachments or organizations, in order."""
    return [
        _form(call)
        for call in db.calls
        if re.search(r"\b(attachments|organizations)\b", call.normalized)
    ]


def _calls_of(db: FakeDb, label: str) -> list[Call]:
    return [call for call in db.calls if _form(call) == label]


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def ap() -> ModuleType:
    import admino.attachment_processing as module

    return module


def _budget() -> Any:
    """The test budget (``admino.context_budget`` looked up when a test runs)."""
    from admino import context_budget

    return context_budget.BudgetSettings(
        reserved_output_tokens=_RESERVED,
        safety_margin_percent=_MARGIN,
        max_turn_bytes=64 * 1_048_576,
        max_tool_result_tokens=8000,
    )


@dataclass(frozen=True)
class _World:
    db: FakeDb
    root: Path
    chat: uuid.UUID
    message: uuid.UUID  # a user message of ``chat``
    other_chat: uuid.UUID  # the same member's other chat
    foreign_chat: uuid.UUID  # another org's chat


def _platform(
    db: FakeDb, monkeypatch: pytest.MonkeyPatch, max_input_tokens: int, **columns: Any
) -> None:
    """Store the platform row with this model input limit; empty the cache so it is read."""
    db.add_platform_settings(max_input_tokens=max_input_tokens, **columns)
    monkeypatch.setattr(scoped_settings, "_platform_cache", None)


@pytest.fixture()
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _World:
    db = FakeDb()
    db.add_org(ORG_ID, storage_quota_bytes=10**9)
    db.add_org(OTHER_ORG_ID, storage_quota_bytes=10**9)
    member = db.add_account(org_id=ORG_ID)
    outsider = db.add_account(org_id=OTHER_ORG_ID)
    chat = db.add_chat(member)
    message = db.add_chat_message(chat, "user", "Earlier, with a file")
    root = tmp_path / "attachments"
    root.mkdir()
    _platform(db, monkeypatch, _PLATFORM_MAX_INPUT)
    return _World(
        db=db,
        root=root,
        chat=chat,
        message=message,
        other_chat=db.add_chat(member),
        foreign_chat=db.add_chat(outsider),
    )


def _org_of(world: _World, attachment_id: uuid.UUID) -> uuid.UUID:
    row = world.db.attachment_row(attachment_id)
    assert row is not None
    return plain(row["org_id"])


def _original(world: _World, attachment_id: uuid.UUID) -> Path:
    return world.root / str(_org_of(world, attachment_id)) / str(attachment_id)


def _derived_dir(world: _World, attachment_id: uuid.UUID) -> Path:
    return _original(world, attachment_id).with_name(f"{attachment_id}.d")


def _upload(world: _World, chat_id: uuid.UUID | None = None, *, active: bool = True) -> uuid.UUID:
    """An uploaded row (named with the canary) and its stored original; ``active`` False:
    the member excluded it before the processor claimed it."""
    attachment_id = world.db.add_attachment(
        world.chat if chat_id is None else chat_id,
        filename=NAME_CANARY,
        kind="pdf",
        size_bytes=8,
        created_at=_T0 + timedelta(minutes=1),
        active=active,
    )
    path = _original(world, attachment_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"%PDF-1.7")
    return attachment_id


def _other(world: _World, chat_id: uuid.UUID | None = None, **values: Any) -> uuid.UUID:
    """Another attachment that may or may not count toward the budget."""
    values.setdefault("status", "ready")
    if values["status"] == "failed":
        values.setdefault("failure_reason", "context_overflow")
    return world.db.add_attachment(
        world.chat if chat_id is None else chat_id, created_at=_T0, **values
    )


class _Processor:
    """A sync processor: writes ``<id>.d`` (as a conversion does) and returns ``result``;
    ``during`` runs before it returns (what the member does while the file converts)."""

    def __init__(self, result: Any, during: Callable[[], None] | None = None) -> None:
        self.result = result
        self.during = during
        self.calls = 0

    def __call__(self, path: Path, kind: str, job: Any) -> Any:
        self.calls += 1
        derived = path.with_name(path.name + ".d")
        derived.mkdir()
        (derived / "part-0001.txt").write_text("converted", encoding="utf-8")
        (derived / "manifest.json").write_text("{}", encoding="utf-8")
        if self.during is not None:
            self.during()
        return self.result


def _processed(
    ap: ModuleType,
    estimate: int | None,
    *,
    page_count: int | None = 2,
    derived_bytes: int | None = 120,
) -> Any:
    return ap.ProcessedFile(
        page_count=page_count, token_estimate=estimate, derived_bytes=derived_bytes
    )


async def _process(
    ap: ModuleType, world: _World, attachment_id: uuid.UUID, processed: Any, budget: Any
) -> Any:
    return await ap.process_attachment(
        world.db.pool,
        world.root,
        attachment_id,
        _org_of(world, attachment_id),
        processor=_Processor(processed),
        budget=budget,
    )


def _state(world: _World, attachment_id: uuid.UUID) -> tuple[Any, Any, Any, Any]:
    """(status, failure_reason, token_estimate, derived_bytes) of the stored row."""
    row = world.db.attachment_row(attachment_id)
    assert row is not None
    return row["status"], row["failure_reason"], row["token_estimate"], row["derived_bytes"]


def _seed_others(world: _World) -> None:
    """The chat's other counted files: a ready unsent one (3 000) and a sent one (2 000)."""
    _other(world, token_estimate=3_000)
    _other(world, token_estimate=2_000, message_id=world.message)


# ---------------------------------------------------------------------------
# 1. Signatures
# ---------------------------------------------------------------------------


def test_attachment_processing_budget_is_keyword_only_and_none_by_default(
    ap: ModuleType,
) -> None:
    process = inspect.signature(ap.process_attachment).parameters["budget"]
    pool = inspect.signature(ap.ProcessingPool).parameters["budget"]

    assert (process.kind, process.default, pool.kind, pool.default) == (
        inspect.Parameter.KEYWORD_ONLY,
        None,
        inspect.Parameter.KEYWORD_ONLY,
        None,
    )


# ---------------------------------------------------------------------------
# 2. Under, at and over the budget
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("estimate", "expected"),
    [(2_999, "ready"), (3_000, "ready"), (3_001, "failed")],
    ids=["under", "at", "one-over"],
)
async def test_attachment_processing_budget_boundary(
    ap: ModuleType, world: _World, estimate: int, expected: str
) -> None:
    _seed_others(world)
    attachment_id = _upload(world)

    result = await _process(ap, world, attachment_id, _processed(ap, estimate), _budget())

    status, reason, stored, _ = _state(world, attachment_id)
    assert (result, status, stored) == (expected, expected, estimate)
    assert reason == (None if expected == "ready" else "context_overflow")


async def test_attachment_processing_budget_over_fails_without_storing_the_derived_files(
    ap: ModuleType, world: _World
) -> None:
    """failed / context_overflow with the estimate; no derived bytes, no <id>.d, the
    original kept; exactly P1', P7, P6, P3'' (no P2'', nothing counted in the quota)."""
    _seed_others(world)
    attachment_id = _upload(world)
    world.db.calls.clear()

    result = await _process(ap, world, attachment_id, _processed(ap, 3_001), _budget())

    assert (result, _state(world, attachment_id)) == (
        "failed",
        ("failed", "context_overflow", 3_001, None),
    )
    assert not _derived_dir(world, attachment_id).exists()
    assert _original(world, attachment_id).read_bytes() == b"%PDF-1.7"
    assert _outcome_forms(world.db) == ["P1'", "P7", "P6", "P3''"]
    (p6,) = _calls_of(world.db, "P6")
    (p3,) = _calls_of(world.db, "P3''")
    assert [plain(arg) for arg in p6.args] == [attachment_id, ORG_ID]
    assert (plain(p3.args[0]), plain(p3.args[1]), p3.args[2], p3.args[3]) == (
        attachment_id,
        ORG_ID,
        "context_overflow",
        3_001,
    )


async def test_attachment_processing_budget_under_runs_p6_then_the_quota_transaction(
    ap: ModuleType, world: _World
) -> None:
    _seed_others(world)
    attachment_id = _upload(world)
    world.db.calls.clear()

    result = await _process(ap, world, attachment_id, _processed(ap, 3_000), _budget())

    assert (result, _state(world, attachment_id)) == ("ready", ("ready", None, 3_000, 120))
    assert _outcome_forms(world.db) == ["P1'", "P7", "P6", "A3", "A4'", "P2''"]
    assert _derived_dir(world, attachment_id).is_dir()


# ---------------------------------------------------------------------------
# 3. Which other files count
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sent", [False, True], ids=["unsent", "sent"])
async def test_attachment_processing_budget_counts_the_chats_ready_active_files(
    ap: ModuleType, world: _World, sent: bool
) -> None:
    """Sent or not, a ready active file of the same chat counts: 5 000 + 3 001 > 8 000."""
    _other(world, token_estimate=_OTHERS, message_id=world.message if sent else None)
    attachment_id = _upload(world)

    result = await _process(ap, world, attachment_id, _processed(ap, 3_001), _budget())

    assert (result, _state(world, attachment_id)[:2]) == (
        "failed",
        ("failed", "context_overflow"),
    )


_NOT_COUNTED: Final[dict[str, dict[str, Any]]] = {
    "excluded": {"active": False},
    "failed": {"status": "failed"},
    "uploaded": {"status": "uploaded"},
    "processing": {"status": "processing"},
    "trashed": {"deleted_at": _T0},
    "other-chat": {"chat": "other_chat"},
    "other-org": {"chat": "foreign_chat"},
}


@pytest.mark.parametrize("case", list(_NOT_COUNTED))
async def test_attachment_processing_budget_does_not_count_other_files(
    ap: ModuleType, world: _World, case: str
) -> None:
    """Exactly at the budget with the counted files; a big estimate on a file that
    doesn't count changes nothing."""
    _seed_others(world)
    values = dict(_NOT_COUNTED[case])
    chat_id = getattr(world, values.pop("chat")) if "chat" in values else None
    _other(world, chat_id, token_estimate=100_000, **values)
    attachment_id = _upload(world)

    result = await _process(ap, world, attachment_id, _processed(ap, 3_000), _budget())

    assert (result, _state(world, attachment_id)[:2]) == ("ready", ("ready", None))


async def test_attachment_processing_budget_null_estimates_count_zero(
    ap: ModuleType, world: _World
) -> None:
    """Another ready file without an estimate counts 0; so does a processed file without
    one, even with the others exactly at the budget."""
    _other(world, token_estimate=_AVAILABLE)
    _other(world, token_estimate=None)
    attachment_id = _upload(world)

    result = await _process(ap, world, attachment_id, _processed(ap, None), _budget())

    assert (result, _state(world, attachment_id)) == ("ready", ("ready", None, None, 120))


# ---------------------------------------------------------------------------
# 4. Where the check runs
# ---------------------------------------------------------------------------


async def test_attachment_processing_budget_page_check_comes_first(
    ap: ModuleType, world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Too many pages AND over the budget: too_many_pages, and P6 never runs."""
    world.db.platform_settings.clear()
    _platform(world.db, monkeypatch, _PLATFORM_MAX_INPUT, max_pages_per_file=2)
    _seed_others(world)
    attachment_id = _upload(world)
    world.db.calls.clear()

    result = await _process(
        ap, world, attachment_id, _processed(ap, 3_001, page_count=3), _budget()
    )

    assert (result, _state(world, attachment_id)[:2]) == ("failed", ("failed", "too_many_pages"))
    assert _outcome_forms(world.db) == ["P1'", "P3"]


async def test_attachment_processing_budget_over_never_reaches_the_quota(
    ap: ModuleType, world: _World
) -> None:
    """A full org: the over-budget file is context_overflow, not storage_quota_exceeded."""
    world.db.add_org(ORG_ID, storage_quota_bytes=0)
    _seed_others(world)
    attachment_id = _upload(world)
    world.db.calls.clear()

    result = await _process(ap, world, attachment_id, _processed(ap, 3_001), _budget())

    assert (result, _state(world, attachment_id)[:2]) == (
        "failed",
        ("failed", "context_overflow"),
    )
    assert "A3" not in _outcome_forms(world.db)


async def test_attachment_processing_budget_under_still_meets_the_quota(
    ap: ModuleType, world: _World
) -> None:
    """Under the budget in a full org: P7, P6, then the quota refuses the derived files."""
    world.db.add_org(ORG_ID, storage_quota_bytes=0)
    attachment_id = _upload(world)
    world.db.calls.clear()

    result = await _process(ap, world, attachment_id, _processed(ap, 10), _budget())

    assert (result, _state(world, attachment_id)[:2]) == (
        "failed",
        ("failed", "storage_quota_exceeded"),
    )
    assert _outcome_forms(world.db) == ["P1'", "P7", "P6", "A3", "A4'", "P3"]


@pytest.mark.parametrize(
    ("max_input_tokens", "expected"),
    [(_PLATFORM_MAX_INPUT, "failed"), (20_001, "ready")],
    ids=["small-model", "large-model"],
)
async def test_attachment_processing_budget_uses_the_stored_platform_max_input_tokens(
    ap: ModuleType,
    world: _World,
    monkeypatch: pytest.MonkeyPatch,
    max_input_tokens: int,
    expected: str,
) -> None:
    """8 001 tokens: over 8 000, under 20 001 - 2 001 - 1 000 = 17 000. The platform
    settings are still read once."""
    world.db.platform_settings.clear()
    _platform(world.db, monkeypatch, max_input_tokens)
    reads: list[int] = []
    original = scoped_settings.current_platform_settings

    async def counted(executor: Any) -> Any:
        reads.append(1)
        return await original(executor)

    monkeypatch.setattr(scoped_settings, "current_platform_settings", counted)
    attachment_id = _upload(world)

    result = await _process(ap, world, attachment_id, _processed(ap, 8_001), _budget())

    assert (result, len(reads)) == (expected, 1)


async def test_attachment_processing_budget_none_is_todays_behaviour(
    ap: ModuleType, world: _World
) -> None:
    """No budget: an estimate far above any budget is ready, with no P6."""
    _seed_others(world)
    attachment_id = _upload(world)
    world.db.calls.clear()

    result = await _process(ap, world, attachment_id, _processed(ap, 1_000_000), None)

    assert (result, _state(world, attachment_id)) == ("ready", ("ready", None, 1_000_000, 120))
    assert _outcome_forms(world.db) == ["P1'", "A3", "A4'", "P2''"]


async def test_attachment_processing_budget_default_is_no_budget(
    ap: ModuleType, world: _World
) -> None:
    """Called without ``budget``: no P6 runs (the keyword exists and defaults to None)."""
    assert "budget" in inspect.signature(ap.process_attachment).parameters
    _seed_others(world)
    attachment_id = _upload(world)
    world.db.calls.clear()

    result = await ap.process_attachment(
        world.db.pool,
        world.root,
        attachment_id,
        ORG_ID,
        processor=_Processor(_processed(ap, 1_000_000)),
    )

    assert result == "ready"
    assert "P6" not in _outcome_forms(world.db)


# ---------------------------------------------------------------------------
# 5. The pool
# ---------------------------------------------------------------------------


async def test_attachment_processing_budget_pool_passes_the_budget_to_every_job(
    ap: ModuleType, world: _World
) -> None:
    """Over-budget files of two chats (the member's and another org's): a pool with the
    budget fails both jobs, a pool without one makes both ready."""
    processor = _Processor(_processed(ap, _AVAILABLE + 1))
    checked = (_upload(world), _upload(world, world.foreign_chat))
    unchecked = (_upload(world, world.other_chat), _upload(world, world.foreign_chat))

    for pool, attachment_ids in (
        (ap.ProcessingPool(processor=processor, budget=_budget()), checked),
        (ap.ProcessingPool(processor=processor), unchecked),
    ):
        for attachment_id in attachment_ids:
            pool.submit(world.db.pool, world.root, attachment_id, _org_of(world, attachment_id))
        await asyncio.wait_for(pool.join(), _WAIT_S)

    assert [_state(world, item)[:2] for item in (*checked, *unchecked)] == [
        ("failed", "context_overflow"),
        ("failed", "context_overflow"),
        ("ready", None),
        ("ready", None),
    ]
    assert processor.calls == 4


# ---------------------------------------------------------------------------
# 6. Logs
# ---------------------------------------------------------------------------


async def test_attachment_processing_budget_logs_the_id_and_the_code_only(
    ap: ModuleType, world: _World, caplog: pytest.LogCaptureFixture
) -> None:
    _seed_others(world)
    attachment_id = _upload(world)
    caplog.set_level(logging.DEBUG)

    await _process(ap, world, attachment_id, _processed(ap, 3_001), _budget())

    lines = [
        record.getMessage()
        for record in caplog.records
        if "context_overflow" in record.getMessage()
    ]
    assert len(lines) == 1
    assert str(attachment_id) in lines[0]
    assert all(NAME_CANARY not in record.getMessage() for record in caplog.records)
    assert all(str(world.root) not in record.getMessage() for record in caplog.records)


# ---------------------------------------------------------------------------
# 7. The file's own active flag (GH-294, Decision 8)
# ---------------------------------------------------------------------------

# Over the attachments' share (8 000) on its own, and so with the chat's 5 000 too.
_OVER_ALONE: Final = _AVAILABLE + 1
_CHECKED: Final = ["P1'", "P7", "P6", "P3''"]
_UNCHECKED: Final = ["P1'", "P7", "A3", "A4'", "P2''"]


def _set_active(world: _World, attachment_id: uuid.UUID, active: bool) -> Callable[[], None]:
    """Set the stored row's flag, as ``PATCH /api/attachments/{id}`` does (it accepts a
    file that is still processing)."""

    def flip() -> None:
        world.db.attachments[attachment_id]["active"] = active

    return flip


@pytest.mark.parametrize(
    ("seeded", "during", "expected"),
    [
        (True, None, "failed"),
        (False, None, "ready"),
        (True, False, "ready"),
        (False, True, "failed"),
    ],
    ids=[
        "active",
        "excluded-before-the-claim",
        "excluded-during-the-conversion",
        "included-again-during-the-conversion",
    ],
)
async def test_attachment_processing_budget_own_active_flag_decides_the_check(
    ap: ModuleType, world: _World, seeded: bool, during: bool | None, expected: str
) -> None:
    """P7 reads the flag after the conversion, right before P6. Excluded then: no P6, no
    rejection; ready with the converter's estimate (over the share even alone), the
    derived files kept, still excluded. Active then (or included again): checked as
    before, context_overflow."""
    _seed_others(world)
    attachment_id = _upload(world, active=seeded)
    flip = None if during is None else _set_active(world, attachment_id, during)
    world.db.calls.clear()

    result = await ap.process_attachment(
        world.db.pool,
        world.root,
        attachment_id,
        ORG_ID,
        processor=_Processor(_processed(ap, _OVER_ALONE), during=flip),
        budget=_budget(),
    )

    row = world.db.attachment_row(attachment_id)
    assert row is not None
    ready = expected == "ready"
    assert (result, _state(world, attachment_id), row["active"]) == (
        expected,
        ("ready", None, _OVER_ALONE, 120)
        if ready
        else ("failed", "context_overflow", _OVER_ALONE, None),
        seeded if during is None else during,
    )
    assert _derived_dir(world, attachment_id).is_dir() is ready
    assert (
        _outcome_forms(world.db),
        [[plain(arg) for arg in call.args] for call in _calls_of(world.db, "P7")],
    ) == (_UNCHECKED if ready else _CHECKED, [[attachment_id, ORG_ID]])


async def test_attachment_processing_budget_row_gone_during_the_conversion_gets_p6(
    ap: ModuleType, world: _World
) -> None:
    """The row is deleted while the file converts: P7 finds no row and P6 runs as today
    (nothing counts through a gone row, so the file fits); the ready outcome matches no
    row and the derived files are removed; the original is left to its deleter."""
    _seed_others(world)
    attachment_id = _upload(world)
    original = _original(world, attachment_id)
    derived = _derived_dir(world, attachment_id)

    def delete() -> None:
        del world.db.attachments[attachment_id]

    world.db.calls.clear()

    await ap.process_attachment(
        world.db.pool,
        world.root,
        attachment_id,
        ORG_ID,
        processor=_Processor(_processed(ap, 3_000), during=delete),
        budget=_budget(),
    )

    assert (
        _outcome_forms(world.db),
        world.db.attachment_row(attachment_id),
        derived.exists(),
        original.exists(),
    ) == (["P1'", "P7", "P6", "A3", "A4'", "P2''"], None, False, True)
