"""Tests for ``admino.converters.ooxml.check_archive`` (GH-188 contract section 4.6).

The zip-bomb guard every DOCX and XLSX passes before python-docx or openpyxl
opens it (issue: "Zip-bomb guard for OOXML formats"; Decision 9). What these
tests pin down:

- Each limit, read at call time as ``common.<NAME>`` and judged from the
  central directory's declared sizes, with its boundary: ``MAX_OOXML_ENTRIES``
  (entries == limit pass, one more is refused), ``MAX_OOXML_ENTRY_BYTES`` (one
  entry declaring exactly the limit passes, one byte more is refused, also
  when it isn't the first entry) and ``MAX_OOXML_TOTAL_BYTES`` (all entries
  together: == passes, +1 refused) -> ``archive_too_large``.
- Real bombs at the default limits: one 300 MiB entry of zeros, and five
  60 MiB entries (each under the per-entry limit, together over the total),
  both well under 1 MiB on disk, are refused.
- Nothing is decompressed: while the guard runs, ``ZipFile.open`` in read mode
  (which ``read``, ``testzip`` and ``extract`` go through) and zipfile's
  decompressor factory fail the test when called, for every archive here,
  the accepted ones included.
- A ZIP64 entry (``0xFFFFFFFF`` in the 32-bit size fields, the real sizes in
  the ZIP64 extra field) is judged by its real declared size: 5 bytes pass,
  5 GiB are refused.
- An encrypted entry or an entry with an unknown compression method doesn't
  crash the guard: it decompresses nothing, so the archive passes.
- Not a readable ZIP (empty, garbage after a local-header signature, a
  truncated archive) -> ``corrupted_file``; the error's message is the code
  only.
- A real DOCX (python-docx) and XLSX (openpyxl) pass at the default limits.

The guard is imported inside the helpers, so this file collects before the
module exists. Archives are built in ``tmp_path`` with zipfile/struct.
"""

from __future__ import annotations

import struct
import zipfile
import zlib
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from pathlib import Path

_MIB = 1024 * 1024
_ZIP64_LIMIT_32 = 0xFFFFFFFF


class _DecompressedError(BaseException):
    """Raised by the guards below; a BaseException so a broad ``except
    Exception`` in the code under test can't swallow it."""


@contextmanager
def _no_decompression() -> Iterator[None]:
    """Fail when anything opens an entry for reading or builds a decompressor."""
    calls: list[str] = []
    real_open = zipfile.ZipFile.open

    def guarded_open(
        self: zipfile.ZipFile, name: Any, mode: str = "r", *args: Any, **kwargs: Any
    ) -> Any:
        if mode == "r":
            calls.append(f"open:{name}")
            raise _DecompressedError(name)
        return real_open(self, name, mode, *args, **kwargs)

    def guarded_decompressor(*args: Any) -> Any:
        calls.append("decompressor")
        raise _DecompressedError("decompressor")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(zipfile.ZipFile, "open", guarded_open)
        patch.setattr(zipfile, "_get_decompressor", guarded_decompressor)
        try:
            yield
        finally:
            assert calls == [], f"the guard decompressed: {calls}"


def _outcome(path: Path) -> str | None:
    """The guard's verdict: None when the archive passes, else the reason code."""
    from admino.converters import ooxml
    from admino.converters.common import ConversionError

    with _no_decompression():
        try:
            ooxml.check_archive(path)
        except ConversionError as exc:
            return exc.reason
    return None


def _limits(
    monkeypatch: pytest.MonkeyPatch, *, entries: int, entry_bytes: int, total_bytes: int
) -> None:
    from admino.converters import common

    monkeypatch.setattr(common, "MAX_OOXML_ENTRIES", entries)
    monkeypatch.setattr(common, "MAX_OOXML_ENTRY_BYTES", entry_bytes)
    monkeypatch.setattr(common, "MAX_OOXML_TOTAL_BYTES", total_bytes)


def _archive(path: Path, sizes: Sequence[int]) -> Path:
    """A CRC-consistent archive whose entries hold ``sizes`` bytes of zeros."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for index, size in enumerate(sizes):
            archive.writestr(f"word/part{index}.xml", bytes(size))
    return path


def _bomb(path: Path, entry_mib: Sequence[int]) -> Path:
    """A real bomb: entries of zeros streamed in 1 MiB chunks (fast, tiny on disk)."""
    chunk = bytes(_MIB)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        for index, mib in enumerate(entry_mib):
            with archive.open(f"word/media/blob{index}.xml", "w") as entry:
                for _ in range(mib):
                    entry.write(chunk)
    return path


def _zip64_archive(path: Path, declared: int) -> Path:
    """One stored entry written ZIP64-style: 0xFFFFFFFF in both 32-bit size
    fields, the sizes in the ZIP64 extra field; the central directory declares
    ``declared`` uncompressed bytes."""
    name = b"word/document.xml"
    data = b"<w:document/>"
    crc = zlib.crc32(data)
    local_extra = struct.pack("<HHQQ", 0x0001, 16, len(data), len(data))
    local = (
        struct.pack(
            "<4s2B4HL2L2H",
            b"PK\x03\x04",
            45,
            0,
            0,
            0,
            0,
            0,
            crc,
            _ZIP64_LIMIT_32,
            _ZIP64_LIMIT_32,
            len(name),
            len(local_extra),
        )
        + name
        + local_extra
        + data
    )
    central_extra = struct.pack("<HHQQ", 0x0001, 16, declared, len(data))
    central = (
        struct.pack(
            "<4s4B4HL2L5H2L",
            b"PK\x01\x02",
            45,
            3,
            45,
            0,
            0,
            0,
            0,
            0,
            crc,
            _ZIP64_LIMIT_32,
            _ZIP64_LIMIT_32,
            len(name),
            len(central_extra),
            0,
            0,
            0,
            0,
            0,
        )
        + name
        + central_extra
    )
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0)
    path.write_bytes(local + central + end)
    return path


# --- each limit with its boundary (monkeypatched small limits) ------------------------


@pytest.mark.parametrize(
    ("count", "expected"), [(5, None), (6, "archive_too_large")], ids=["at-limit", "one-over"]
)
def test_ooxml_entry_count_over_limit_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, count: int, expected: str | None
) -> None:
    _limits(monkeypatch, entries=5, entry_bytes=10_000, total_bytes=100_000)
    path = _archive(tmp_path / "count.docx", [10] * count)

    assert _outcome(path) == expected


@pytest.mark.parametrize(
    ("sizes", "expected"),
    [([10, 1000, 10], None), ([10, 1001, 10], "archive_too_large")],
    ids=["at-limit", "one-over-in-the-middle"],
)
def test_ooxml_entry_declared_size_over_limit_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sizes: list[int], expected: str | None
) -> None:
    _limits(monkeypatch, entries=100, entry_bytes=1000, total_bytes=100_000)
    path = _archive(tmp_path / "entry.docx", sizes)

    assert _outcome(path) == expected


@pytest.mark.parametrize(
    ("sizes", "expected"),
    [([1000, 1000, 500], None), ([1000, 1000, 501], "archive_too_large")],
    ids=["at-limit", "one-over"],
)
def test_ooxml_total_declared_size_over_limit_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sizes: list[int], expected: str | None
) -> None:
    _limits(monkeypatch, entries=100, entry_bytes=1000, total_bytes=2500)
    path = _archive(tmp_path / "total.xlsx", sizes)

    assert _outcome(path) == expected


# --- real bombs at the default limits -------------------------------------------------


@pytest.mark.parametrize(
    "entry_mib", [[300], [60] * 5], ids=["one-300MiB-entry", "five-60MiB-entries"]
)
def test_ooxml_real_zip_bomb_refused_without_decompressing(
    tmp_path: Path, entry_mib: list[int]
) -> None:
    path = _bomb(tmp_path / "bomb.docx", entry_mib)
    assert path.stat().st_size < _MIB  # the fixture really is a bomb

    assert _outcome(path) == "archive_too_large"


# --- ZIP64, odd entries ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("declared", "expected"),
    [(13, None), (5 * 1024**3, "archive_too_large")],
    ids=["small", "5GiB"],
)
def test_ooxml_zip64_entry_judged_by_its_real_declared_size(
    tmp_path: Path, declared: int, expected: str | None
) -> None:
    path = _zip64_archive(tmp_path / "zip64.docx", declared)

    assert _outcome(path) == expected


def _encrypted_entry(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", b"<w:document/>")
        # zipfile resets flag_bits while writing: set the encryption bit afterwards,
        # so the central directory written at close() carries it.
        archive.getinfo("word/document.xml").flag_bits |= 0x1
    return path


def _unknown_method_entry(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", b"<w:document/>", compress_type=zipfile.ZIP_DEFLATED)
        archive.getinfo("word/document.xml").compress_type = 99
    return path


@pytest.mark.parametrize(
    "build", [_encrypted_entry, _unknown_method_entry], ids=["encrypted", "unknown-method"]
)
def test_ooxml_odd_entry_passes_without_crashing(tmp_path: Path, build: Any) -> None:
    path = build(tmp_path / "odd.docx")

    assert _outcome(path) is None


# --- not a ZIP ------------------------------------------------------------------------


def _library_docx(path: Path) -> Path:
    import docx

    document = docx.Document()
    document.add_paragraph("Quarterly figures")
    document.save(str(path))
    return path


def _library_xlsx(path: Path) -> Path:
    import openpyxl

    workbook = openpyxl.Workbook()
    sheet = workbook.active
    assert sheet is not None
    sheet["A1"] = "Quarter"
    sheet["B1"] = 3
    workbook.save(path)
    return path


def _truncated(path: Path) -> Path:
    whole = _library_docx(path).read_bytes()
    path.write_bytes(whole[: len(whole) // 2])
    return path


def _garbage(path: Path) -> Path:
    path.write_bytes(b"PK\x03\x04" + b"not really a zip archive" * 10)
    return path


def _empty(path: Path) -> Path:
    path.write_bytes(b"")
    return path


@pytest.mark.parametrize(
    "build", [_empty, _garbage, _truncated], ids=["empty", "garbage", "truncated"]
)
def test_ooxml_unreadable_zip_is_corrupted_file(tmp_path: Path, build: Any) -> None:
    from admino.converters import ooxml
    from admino.converters.common import ConversionError

    path = build(tmp_path / "secret-name.docx")

    with _no_decompression(), pytest.raises(ConversionError) as caught:
        ooxml.check_archive(path)

    assert (caught.value.reason, str(caught.value)) == ("corrupted_file", "corrupted_file")


# --- library-built documents pass -----------------------------------------------------


@pytest.mark.parametrize(
    ("build", "name"),
    [(_library_docx, "report.docx"), (_library_xlsx, "book.xlsx")],
    ids=["docx", "xlsx"],
)
def test_ooxml_library_built_document_passes(tmp_path: Path, build: Any, name: str) -> None:
    path = build(tmp_path / name)

    assert _outcome(path) is None
