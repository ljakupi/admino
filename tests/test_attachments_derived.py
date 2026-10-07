"""Tests for the derived-artifact helpers of ``admino.attachments`` (GH-188 contract §7).

Issue #188, "Token estimate & storage": derived artifacts are stored next to the
original. Decision 3: they live in ``<attachments_root>/<org_id>/<id>.d/`` and are
removed with the original, on a failed conversion and when the row was deleted
during the conversion (``attachment_processing`` calls ``remove_derived`` then).

What these tests pin down:

- ``derived_path(root, org_id, attachment_id) == root / str(org_id) /
  f"{attachment_id}.d"``.
- ``async remove_derived(root, org_id, attachment_id) -> None``:
  - removes a ``<id>.d`` directory tree (a symlink inside it is removed, its
    target outside is left alone);
  - a symlink named ``<id>.d`` is unlinked, never followed (a linked directory's
    files and a linked file survive);
  - a plain file named ``<id>.d`` is unlinked;
  - a missing ``<id>.d`` (or a missing org directory) is fine: no error, nothing
    logged at WARNING or above;
  - never touches the original ``<id>``, its ``<id>.part``, another id's
    ``<id>.d`` or the same id's ``.d`` under another org;
  - an ``OSError`` (a PermissionError whose message holds the path) is never
    raised: one record at WARNING or above names the class and the attachment
    id; no record holds the path or a traceback;
  - the file work runs off the event loop's thread.

``admino.attachments`` exists already (GH-187); the new names are looked up inside
each test, so every test fails on its own before GH-188. Everything happens in
``tmp_path``; no fault injection needs root (the OSError comes from patched
``os``/``shutil`` functions that raise only for this test's ``<id>.d``).
"""

from __future__ import annotations

import errno
import inspect
import logging
import os
import shutil
import threading
import uuid
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import attachments

if TYPE_CHECKING:
    from pathlib import Path

ORG: Final = uuid.UUID("0b8a6f8e-5d1c-4e0a-9a51-3f3c2b7d9e01")
OTHER_ORG: Final = uuid.UUID("7c2e9d40-1a3b-4c5d-8e6f-0a1b2c3d4e5f")
ATTACHMENT: Final = uuid.UUID("5f0c3a2e-8b7d-4f61-a9e2-6d4c1b0a9f87")
OTHER_ATTACHMENT: Final = uuid.UUID("c4d3e2f1-0a9b-4c8d-b7e6-f5a4b3c2d1e0")


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    path = tmp_path / "attachments"
    (path / str(ORG)).mkdir(parents=True)
    return path


def _entry(root: Path, org_id: uuid.UUID = ORG, name: str = f"{ATTACHMENT}.d") -> Path:
    return root / str(org_id) / name


def _gone(path: Path) -> bool:
    """True when nothing (no file, directory or symlink) is left at ``path``."""
    return not path.exists() and not path.is_symlink()


def _tree(directory: Path) -> None:
    """A derived-artifacts tree: parts, a manifest and a nested directory."""
    directory.mkdir()
    (directory / "part-0001.txt").write_text("text", encoding="utf-8")
    (directory / "part-0002.jpg").write_bytes(b"\xff\xd8\xff\xd9")
    (directory / "manifest.json").write_text("{}", encoding="utf-8")
    (directory / "nested").mkdir()
    (directory / "nested" / "deep.txt").write_text("deep", encoding="utf-8")


def _outside(tmp_path: Path) -> Path:
    """A directory outside the attachments root holding one file."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep", encoding="utf-8")
    return outside


def _log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured record, formatted with its traceback (exc_info) if any."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(formatter.format(record) for record in caplog.records)


# ---------------------------------------------------------------------------
# derived_path
# ---------------------------------------------------------------------------


def test_attachments_derived_path_is_the_ids_d_entry_in_the_org_dir(tmp_path: Path) -> None:
    assert attachments.derived_path(tmp_path, ORG, ATTACHMENT) == (
        tmp_path / str(ORG) / f"{ATTACHMENT}.d"
    )


# ---------------------------------------------------------------------------
# remove_derived: what it removes
# ---------------------------------------------------------------------------


async def test_attachments_remove_derived_removes_the_tree(root: Path, tmp_path: Path) -> None:
    """The whole <id>.d tree goes; a symlink inside it is removed without following."""
    outside = _outside(tmp_path)
    derived = _entry(root)
    _tree(derived)
    (derived / "nested" / "escape").symlink_to(outside, target_is_directory=True)

    result = await attachments.remove_derived(root, ORG, ATTACHMENT)

    assert (result, _gone(derived), (outside / "keep.txt").read_text(encoding="utf-8")) == (
        None,
        True,
        "keep",
    )


@pytest.mark.parametrize("target", ["directory", "file"])
async def test_attachments_remove_derived_unlinks_a_symlink_without_touching_its_target(
    root: Path, tmp_path: Path, target: str
) -> None:
    outside = _outside(tmp_path)
    link_target = outside if target == "directory" else outside / "keep.txt"
    derived = _entry(root)
    derived.symlink_to(link_target, target_is_directory=target == "directory")

    await attachments.remove_derived(root, ORG, ATTACHMENT)

    assert (_gone(derived), sorted(os.listdir(outside)), link_target.exists()) == (
        True,
        ["keep.txt"],
        True,
    )


async def test_attachments_remove_derived_unlinks_a_plain_file(root: Path) -> None:
    derived = _entry(root)
    derived.write_bytes(b"not a directory")

    await attachments.remove_derived(root, ORG, ATTACHMENT)

    assert _gone(derived)


@pytest.mark.parametrize("org_dir", ["present", "missing"])
async def test_attachments_remove_derived_missing_entry_is_fine(
    root: Path, caplog: pytest.LogCaptureFixture, org_dir: str
) -> None:
    caplog.set_level(logging.DEBUG)
    org_id = ORG if org_dir == "present" else OTHER_ORG

    result = await attachments.remove_derived(root, org_id, ATTACHMENT)

    assert (result, [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]) == (
        None,
        [],
    )


async def test_attachments_remove_derived_never_touches_the_original_or_other_entries(
    root: Path,
) -> None:
    """Only this org's <id>.d goes: <id>, <id>.part, another id's files and the same
    id's .d under another org stay."""
    _tree(_entry(root))
    kept = [
        _entry(root, name=str(ATTACHMENT)),
        _entry(root, name=f"{ATTACHMENT}.part"),
        _entry(root, name=str(OTHER_ATTACHMENT)),
        _entry(root, name=f"{OTHER_ATTACHMENT}.d"),
        _entry(root, org_id=OTHER_ORG),
    ]
    (root / str(OTHER_ORG)).mkdir()
    for path in kept:
        if path.name.endswith(".d"):
            _tree(path)
        else:
            path.write_bytes(b"original bytes")

    await attachments.remove_derived(root, ORG, ATTACHMENT)

    assert (_gone(_entry(root)), [path.exists() for path in kept]) == (True, [True] * 5)
    assert [path.read_bytes() for path in kept if not path.name.endswith(".d")] == [
        b"original bytes"
    ] * 3


# ---------------------------------------------------------------------------
# remove_derived: failures and the thread
# ---------------------------------------------------------------------------


def _refuse_removal(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """Make every way to remove the entry called ``name`` raise a PermissionError whose
    message holds its full path (shutil.rmtree, os.rmdir, os.unlink, os.remove);
    any other entry is removed normally."""

    def refused(path: Any) -> PermissionError:
        return PermissionError(errno.EACCES, "Permission denied", os.fspath(path))

    def guard(original: Any) -> Any:
        def wrapper(path: Any, *args: Any, **kwargs: Any) -> Any:
            if os.path.basename(os.fspath(path)) == name:
                raise refused(path)
            return original(path, *args, **kwargs)

        return wrapper

    for module, attribute in ((shutil, "rmtree"), (os, "rmdir"), (os, "unlink"), (os, "remove")):
        monkeypatch.setattr(module, attribute, guard(getattr(module, attribute)))


@pytest.mark.parametrize("entry", ["directory", "file"])
async def test_attachments_remove_derived_oserror_is_logged_by_class_and_id_only(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    entry: str,
) -> None:
    caplog.set_level(logging.DEBUG)
    derived = _entry(root)
    if entry == "directory":
        _tree(derived)
    else:
        derived.write_bytes(b"x")
    _refuse_removal(monkeypatch, derived.name)

    result = await attachments.remove_derived(root, ORG, ATTACHMENT)

    named = [
        record
        for record in caplog.records
        if record.levelno >= logging.WARNING
        and "PermissionError" in record.getMessage()
        and str(ATTACHMENT) in record.getMessage()
    ]
    text = _log_text(caplog)
    assert (result, len(named), derived.exists()) == (None, 1, True)
    assert (
        str(root) in text,
        str(derived) in text,
        "Permission denied" in text,
        [record.exc_info for record in caplog.records if record.exc_info],
    ) == (False, False, False, [])


async def test_attachments_remove_derived_runs_off_the_event_loop_thread(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The removal of the tree (its last step, the rmdir of <id>.d itself) runs in a
    worker thread; remove_derived is a coroutine function."""
    derived = _entry(root)
    _tree(derived)
    threads: list[int] = []
    original_rmdir = os.rmdir

    def recording_rmdir(path: Any, *args: Any, **kwargs: Any) -> None:
        if os.path.basename(os.fspath(path)) == derived.name:
            threads.append(threading.get_ident())
        original_rmdir(path, *args, **kwargs)

    monkeypatch.setattr(os, "rmdir", recording_rmdir)

    await attachments.remove_derived(root, ORG, ATTACHMENT)

    loop_thread = threading.get_ident()
    assert (
        inspect.iscoroutinefunction(attachments.remove_derived),
        _gone(derived),
        len(threads),
        loop_thread in threads,
    ) == (True, True, 1, False)
