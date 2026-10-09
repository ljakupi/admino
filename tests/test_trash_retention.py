"""Tests for scoped_settings.trash_retention_days: the org's effective trash retention (GH-194).

Issue #194 Decision 4 and contract sections 4 and 5 (R1): the effective
retention is the org's stored ``org_settings.trash_retention_days`` (30 when
the org has no row: migration 0023's default, ``_ORG_SETTINGS_DEFAULTS``)
clamped into the platform's trash bounds exactly as the org settings page
shows it (``min(max(stored, trash_min_days), trash_max_days)``). The list,
the restores, the deletes with retention 0 and the purge job all read it.

What these tests pin down: no row reads as 30 (clamped too); stored values
come back within the bounds; a stored value below the minimum or above the
maximum is clamped; R1 (exactly the contract's form, bound to the org) runs
before the platform settings are read; the function only reads (no write, no
event) and needs no principal (an executor and an org id); another org's row
never counts.

Harness: tests/db_fakes.py's FakeDb (org_settings and platform_settings) and
the platform settings cache that tests/conftest.py primes; a test narrows the
bounds by replacing the cache, or empties it to make the read run.

Security notes: an internal read for the member's own trash routes and the
system job; it binds one org id and reads nothing else of the org.
"""

from __future__ import annotations

import inspect
import uuid
from typing import Final

import pytest

from admino import scoped_settings
from admino.models import PlatformRetention
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, norm, plain

_R1: Final = norm("SELECT trash_retention_days FROM org_settings WHERE org_id = $1")


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database with orgs A and B (no org_settings rows)."""
    database = FakeDb()
    database.add_org(ORG_ID)
    database.add_org(OTHER_ORG_ID)
    return database


def _bounds(monkeypatch: pytest.MonkeyPatch, low: int, high: int) -> None:
    """Narrow the platform's trash bounds (the cached platform settings)."""
    current = scoped_settings._platform_cache
    assert current is not None
    narrowed = current.model_copy(
        update={"retention": PlatformRetention(trash_min_days=low, trash_max_days=high)}
    )
    monkeypatch.setattr(scoped_settings, "_platform_cache", narrowed)


class TestTrashRetentionDays:
    """The stored retention (30 without a row), clamped into the platform's bounds."""

    async def test_trash_retention_without_an_org_settings_row_is_30(self, db: FakeDb) -> None:
        """No org_settings row: 30 days (migration 0023's default)."""
        assert await scoped_settings.trash_retention_days(db.pool, ORG_ID) == 30

    @pytest.mark.parametrize("stored", [0, 1, 7, 30, 89, 90])
    async def test_trash_retention_returns_the_stored_value_within_the_bounds(
        self, db: FakeDb, stored: int
    ) -> None:
        """The platform's default bounds (0 to 90) keep every stored value."""
        db.add_org_settings(ORG_ID, trash_retention_days=stored)

        assert await scoped_settings.trash_retention_days(db.pool, ORG_ID) == stored

    @pytest.mark.parametrize(
        ("stored", "low", "high", "effective"),
        [
            (60, 0, 45, 45),
            (90, 10, 20, 20),
            (3, 10, 90, 10),
            (0, 1, 90, 1),
            (15, 10, 20, 15),
            (None, 40, 60, 40),
            (None, 0, 14, 14),
        ],
        ids=[
            "above-max",
            "max-narrowed",
            "below-min",
            "zero-below-min",
            "within",
            "no-row-below-min",
            "no-row-above-max",
        ],
    )
    async def test_trash_retention_is_clamped_into_the_platform_bounds(
        self,
        db: FakeDb,
        monkeypatch: pytest.MonkeyPatch,
        stored: int | None,
        low: int,
        high: int,
        effective: int,
    ) -> None:
        """A stored value (or the default 30 without a row) outside narrowed platform
        bounds reads as the nearest bound."""
        if stored is not None:
            db.add_org_settings(ORG_ID, trash_retention_days=stored)
        _bounds(monkeypatch, low, high)

        assert await scoped_settings.trash_retention_days(db.pool, ORG_ID) == effective

    async def test_trash_retention_reads_r1_first_then_the_platform_settings(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With an empty platform cache: exactly R1 bound to the org, then the platform
        row (whose bounds clamp the stored 75 to 50); nothing else runs."""
        db.add_org_settings(ORG_ID, trash_retention_days=75)
        db.add_platform_settings(trash_min_days=5, trash_max_days=50)
        monkeypatch.setattr(scoped_settings, "_platform_cache", None)
        db.calls.clear()

        days = await scoped_settings.trash_retention_days(db.pool, ORG_ID)

        assert days == 50
        assert [call.normalized for call in db.calls][:1] == [_R1]
        assert [plain(arg) for arg in db.calls[0].args] == [ORG_ID]
        assert [bool(call.normalized.startswith("select")) for call in db.calls] == [True, True]
        assert "platform_settings" in db.calls[1].normalized

    async def test_trash_retention_only_reads(self, db: FakeDb) -> None:
        """One statement (R1; the platform settings come from the cache), no write and
        no audit event."""
        db.add_org_settings(ORG_ID, trash_retention_days=12)
        before = db.snapshot()
        db.calls.clear()

        days = await scoped_settings.trash_retention_days(db.pool, ORG_ID)

        assert days == 12
        assert [call.normalized for call in db.calls] == [_R1]
        assert db.snapshot() == before

    def test_trash_retention_takes_an_executor_and_an_org_id_only(self) -> None:
        """No principal, no capability: ``(executor, org_id)``, a coroutine function."""
        function = scoped_settings.trash_retention_days

        assert inspect.iscoroutinefunction(function)
        assert list(inspect.signature(function).parameters) == ["executor", "org_id"]

    @pytest.mark.parametrize(
        ("org_id", "effective"),
        [(ORG_ID, 30), (OTHER_ORG_ID, 7), (uuid.UUID(int=194), 30)],
        ids=["org-without-row", "org-with-row", "unknown-org"],
    )
    async def test_trash_retention_reads_only_its_own_orgs_row(
        self, db: FakeDb, org_id: uuid.UUID, effective: int
    ) -> None:
        """Org B's stored 7 never counts for org A (30 without a row) or an unknown org;
        R1 binds the asked org."""
        db.add_org_settings(OTHER_ORG_ID, trash_retention_days=7)
        db.calls.clear()

        days = await scoped_settings.trash_retention_days(db.pool, org_id)

        assert days == effective
        (call,) = db.calls
        assert [plain(arg) for arg in call.args] == [org_id]
