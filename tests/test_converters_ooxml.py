"""Tests for ``admino.converters.ooxml.check_archive`` (GH-188 contract sections 4.6, 12.1).

The zip-bomb guard every DOCX and XLSX passes before python-docx or openpyxl
opens it (issue: "Zip-bomb guard for OOXML formats"; Decisions 9 and 15:
"only stored and deflate entries are accepted (others ``corrupted_file``,
encrypted ``password_protected``), and every entry's real inflated size is
counted with bounded reads against the same limits before parsing"). What
these tests pin down:

- The directory checks first, each limit read at call time as
  ``common.<NAME>`` and judged from the central directory's declared sizes,
  with its boundary: ``MAX_OOXML_ENTRIES`` (entries == limit pass, one more is
  refused), ``MAX_OOXML_ENTRY_BYTES`` (one entry declaring exactly the limit
  passes, one byte more is refused, also when it isn't the first entry) and
  ``MAX_OOXML_TOTAL_BYTES`` (all entries together: == passes, +1 refused) ->
  ``archive_too_large``. When they refuse, nothing is decompressed: while the
  guard runs, ``ZipFile.open`` in read mode and zipfile's decompressor factory
  fail the test (real bombs of 300 MiB and 5 x 60 MiB, a ZIP64 entry declaring
  5 GiB, an archive that also holds a BZIP2/LZMA/unknown-method entry).
- Compression methods (PM-1): an entry that is neither stored (0) nor deflate
  (8) -> ``corrupted_file``: BZIP2, LZMA and an unknown method 99; the
  auditor's bomb (a ~500-byte DOCX whose BZIP2 ``word/document.xml`` declares
  its 30-byte XML but inflates to 256 MiB) is refused fast, its entry never
  read, with no memory growth. An encrypted entry (flag bit 0x1) ->
  ``password_protected``.
- Real sizes: every entry is inflated once with bounded reads (each read asks
  for 1..64 KiB, never ``read()`` whole; never more than
  ``MAX_OOXML_ENTRY_BYTES + 1`` bytes per entry; tracemalloc peak under
  4 MiB). A real size over ``MAX_OOXML_ENTRY_BYTES`` (an entry declaring 30
  bytes, really 8 MiB under a 1 MiB cap, prefix- or full-stream CRC; the
  auditor's DEFLATE bomb of 128 MiB at the default limits) or a running real
  total over ``MAX_OOXML_TOTAL_BYTES`` (crossed in the middle of a lying entry)
  -> ``archive_too_large``. A real size different from the declared one (a
  longer stream with the prefix's CRC or the full stream's CRC, a shorter
  stream), a CRC failure (same size, tampered bytes) or a zlib error (a broken
  deflate stream) -> ``corrupted_file``.
- Honest archives pass and are fully inflated once in bounded chunks: a
  python-docx DOCX, an openpyxl XLSX, a 32 MiB entry of zeros (memory stays
  flat); the limits' boundaries hold for the real sizes too (an entry of
  exactly ``MAX_OOXML_ENTRY_BYTES``, a real total of exactly
  ``MAX_OOXML_TOTAL_BYTES``), and a ZIP64 stored entry is read with its real
  sizes.
- Not a readable ZIP (empty, garbage after a local-header signature, a
  truncated archive) -> ``corrupted_file``; the error's message is the code
  only.

The guard is imported inside the helpers, so this file collects before the
module exists. Archives are built in ``tmp_path`` with zipfile/struct; lying
entries are written honestly and their central-directory size/CRC changed
before the archive is closed (zipfile reads sizes and CRC from the central
directory).
"""

from __future__ import annotations

import struct
import time
import tracemalloc
import zipfile
import zlib
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence
    from pathlib import Path

_KIB = 1024
_MIB = 1024 * 1024
_CHUNK = 64 * _KIB
_ZIP64_LIMIT_32 = 0xFFFFFFFF
_PEAK_LIMIT = 4 * _MIB
_XML = b'<?xml version="1.0"?><w:document><w:body/></w:document>'


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


def _verdict(path: Path) -> str | None:
    """None when the archive passes, else the refusal's reason code."""
    from admino.converters import ooxml
    from admino.converters.common import ConversionError

    try:
        ooxml.check_archive(path)
    except ConversionError as exc:
        return exc.reason
    return None


def _outcome(path: Path, *, opens_entries: bool) -> str | None:
    """The guard's verdict; with ``opens_entries=False`` the directory checks must
    decide alone (opening an entry or building a decompressor fails the test)."""
    with nullcontext() if opens_entries else _no_decompression():
        return _verdict(path)


@dataclass(frozen=True)
class _Run:
    """What one guard call did."""

    verdict: str | None
    inflated: dict[str, int]  # bytes the entry's reads returned, per entry name
    requests: list[object]  # every size a read was asked for
    peak: int  # tracemalloc peak during the call, in bytes
    seconds: float


def _run(path: Path) -> _Run:
    """Run the guard while recording every read of an entry, the memory peak and the time."""
    returned: dict[str, int] = {}
    requests: list[object] = []

    def recorded(real: Callable[..., bytes]) -> Callable[..., bytes]:
        def read(self: zipfile.ZipExtFile, n: Any = -1) -> bytes:
            requests.append(n)
            data = real(self, n)
            returned[self.name] = returned.get(self.name, 0) + len(data)
            return data

        return read

    _verdict(_archive(path.with_name("warm-up.docx"), [10]))  # imports and caches first
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(zipfile.ZipExtFile, "read", recorded(zipfile.ZipExtFile.read))
        patch.setattr(zipfile.ZipExtFile, "read1", recorded(zipfile.ZipExtFile.read1))
        tracemalloc.start()
        try:
            before = tracemalloc.get_traced_memory()[0]
            start = time.perf_counter()
            verdict = _verdict(path)
            seconds = time.perf_counter() - start
            peak = tracemalloc.get_traced_memory()[1] - before
        finally:
            tracemalloc.stop()
    return _Run(verdict, returned, requests, peak, seconds)


def _bounded(run: _Run) -> bool:
    """Every read asked for 1..64 KiB (never a whole entry)."""
    return all(type(n) is int and 1 <= n <= _CHUNK for n in run.requests)


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


def _lying(
    path: Path,
    *,
    method: int,
    padding: int,
    declared: bytes = _XML,
    crc_of: str = "declared",
    first: tuple[str, int] | None = None,
) -> Path:
    """An archive whose ``word/document.xml`` really holds ``declared`` plus
    ``padding`` zero bytes (streamed in 1 MiB chunks) while its central-directory
    entry declares ``declared`` only; its CRC is the declared prefix's
    (``crc_of="declared"``) or the whole real stream's (``"real"``). ``first``
    adds an honest entry of that many zero bytes in front of it."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        if first is not None:
            archive.writestr(first[0], bytes(first[1]))
        else:
            archive.writestr("[Content_Types].xml", b"<Types/>")
        info = zipfile.ZipInfo("word/document.xml")
        info.compress_type = method
        crc = zlib.crc32(declared)
        with archive.open(info, "w") as entry:
            entry.write(declared)
            left = padding
            while left:
                piece = bytes(min(left, _MIB))
                entry.write(piece)
                crc = zlib.crc32(piece, crc)
                left -= len(piece)
        written = archive.getinfo("word/document.xml")
        written.file_size = len(declared)
        written.CRC = zlib.crc32(declared) if crc_of == "declared" else crc
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


# --- directory checks: each limit with its boundary (monkeypatched small limits) ------


@pytest.mark.parametrize(
    ("count", "expected"), [(5, None), (6, "archive_too_large")], ids=["at-limit", "one-over"]
)
def test_ooxml_entry_count_over_limit_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, count: int, expected: str | None
) -> None:
    _limits(monkeypatch, entries=5, entry_bytes=10_000, total_bytes=100_000)
    path = _archive(tmp_path / "count.docx", [10] * count)

    assert _outcome(path, opens_entries=expected is None) == expected


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

    assert _outcome(path, opens_entries=expected is None) == expected


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

    assert _outcome(path, opens_entries=expected is None) == expected


# --- real bombs at the default limits, refused from the directory ---------------------


@pytest.mark.parametrize(
    "entry_mib", [[300], [60] * 5], ids=["one-300MiB-entry", "five-60MiB-entries"]
)
def test_ooxml_real_zip_bomb_refused_without_decompressing(
    tmp_path: Path, entry_mib: list[int]
) -> None:
    path = _bomb(tmp_path / "bomb.docx", entry_mib)
    assert path.stat().st_size < _MIB  # the fixture really is a bomb

    assert _outcome(path, opens_entries=False) == "archive_too_large"


# --- ZIP64 ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("declared", "expected"),
    [(13, None), (5 * 1024**3, "archive_too_large")],
    ids=["small", "5GiB"],
)
def test_ooxml_zip64_entry_judged_by_its_real_declared_size(
    tmp_path: Path, declared: int, expected: str | None
) -> None:
    path = _zip64_archive(tmp_path / "zip64.docx", declared)

    assert _outcome(path, opens_entries=expected is None) == expected


# --- compression methods and encryption -----------------------------------------------


def _method_entry(path: Path, method: int) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", _XML, compress_type=method)
    return path


def _bzip2_entry(path: Path) -> Path:
    return _method_entry(path, zipfile.ZIP_BZIP2)


def _lzma_entry(path: Path) -> Path:
    return _method_entry(path, zipfile.ZIP_LZMA)


def _unknown_method_entry(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", _XML, compress_type=zipfile.ZIP_DEFLATED)
        archive.getinfo("word/document.xml").compress_type = 99
    return path


@pytest.mark.parametrize(
    "build",
    [_bzip2_entry, _lzma_entry, _unknown_method_entry],
    ids=["bzip2", "lzma", "unknown-method"],
)
def test_ooxml_entry_with_another_compression_method_is_corrupted_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, build: Callable[[Path], Path]
) -> None:
    from admino.converters import common

    path = build(tmp_path / "method.docx")
    verdict = _verdict(path)
    # The directory checks still come first: the same archive over the entry
    # limit is refused as too large, and nothing is opened.
    monkeypatch.setattr(common, "MAX_OOXML_ENTRIES", 1)

    assert (verdict, _outcome(path, opens_entries=False)) == (
        "corrupted_file",
        "archive_too_large",
    )


def test_ooxml_encrypted_entry_is_password_protected(tmp_path: Path) -> None:
    path = tmp_path / "encrypted.docx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", _XML)
        # zipfile resets flag_bits while writing: set the encryption bit afterwards,
        # so the central directory written at close() carries it.
        archive.getinfo("word/document.xml").flag_bits |= 0x1

    assert _verdict(path) == "password_protected"


def test_ooxml_bzip2_bomb_refused_fast_without_inflating_it(tmp_path: Path) -> None:
    # The auditor's PM-1 probe: the entry declares its real XML (size and CRC),
    # and the BZIP2 stream goes on for 256 MiB of padding. Any read of it inflates
    # everything in one decompress call.
    path = _lying(tmp_path / "bomb.docx", method=zipfile.ZIP_BZIP2, padding=256 * _MIB)
    assert path.stat().st_size < 4 * _KIB  # the fixture really is a tiny bomb

    run = _run(path)

    assert (
        run.verdict,
        "word/document.xml" in run.inflated,
        run.peak < _PEAK_LIMIT,
        run.seconds < 1.0,
    ) == ("corrupted_file", False, True, True)


# --- real sizes against the declared ones ---------------------------------------------


def _longer_with_prefix_crc(path: Path) -> Path:
    return _lying(path, method=zipfile.ZIP_DEFLATED, padding=512 * _KIB)


def _longer_with_full_crc(path: Path) -> Path:
    return _lying(path, method=zipfile.ZIP_DEFLATED, padding=512 * _KIB, crc_of="real")


def _shorter_than_declared(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", _XML)
        archive.getinfo("word/document.xml").file_size = len(_XML) + 100
    return path


def _stored_entry_with_tampered_bytes(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", _XML)
    data = path.read_bytes()
    at = data.index(b"<w:body/>")
    path.write_bytes(data[:at] + b"<w:BODY/>" + data[at + 9 :])  # same size, wrong CRC
    return path


def _broken_deflate_stream(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", _XML * 20)
        info = archive.getinfo("word/document.xml")
    data = bytearray(path.read_bytes())
    start = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
    data[start : start + info.compress_size] = b"\xff" * info.compress_size
    path.write_bytes(bytes(data))
    return path


@pytest.mark.parametrize(
    "build",
    [
        _longer_with_prefix_crc,
        _longer_with_full_crc,
        _shorter_than_declared,
        _stored_entry_with_tampered_bytes,
        _broken_deflate_stream,
    ],
    ids=[
        "longer-stream-prefix-crc",
        "longer-stream-full-crc",
        "shorter-stream",
        "crc-mismatch-same-size",
        "broken-deflate-stream",
    ],
)
def test_ooxml_entry_whose_real_stream_differs_from_its_declaration_is_corrupted_file(
    tmp_path: Path, build: Callable[[Path], Path]
) -> None:
    path = build(tmp_path / "lying.docx")

    assert _verdict(path) == "corrupted_file"


@pytest.mark.parametrize(
    ("entry_cap", "padding", "crc_of"),
    [
        (_MIB, 8 * _MIB, "declared"),
        (_MIB, 8 * _MIB, "real"),
        (None, 128 * _MIB, "declared"),
    ],
    ids=["1MiB-cap-prefix-crc", "1MiB-cap-full-crc", "default-cap-128MiB-deflate-bomb"],
)
def test_ooxml_real_size_over_the_entry_cap_refused_with_bounded_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entry_cap: int | None,
    padding: int,
    crc_of: str,
) -> None:
    from admino.converters import common

    if entry_cap is not None:
        monkeypatch.setattr(common, "MAX_OOXML_ENTRY_BYTES", entry_cap)
    cap = common.MAX_OOXML_ENTRY_BYTES
    path = _lying(
        tmp_path / "lying.docx", method=zipfile.ZIP_DEFLATED, padding=padding, crc_of=crc_of
    )

    run = _run(path)

    assert (
        run.verdict,
        run.inflated.get("word/document.xml", 0) <= cap + 1,
        _bounded(run),
        run.peak < _PEAK_LIMIT,
    ) == ("archive_too_large", True, True, True)


def test_ooxml_running_real_total_over_the_cap_is_archive_too_large(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Declared: 1 MiB + 55 bytes, within the 1.5 MiB total. Real: the second entry
    # inflates to 768 KiB, so the running total passes the cap halfway through it.
    _limits(monkeypatch, entries=100, entry_bytes=_MIB, total_bytes=_MIB + _MIB // 2)
    path = _lying(
        tmp_path / "total.xlsx",
        method=zipfile.ZIP_DEFLATED,
        padding=768 * _KIB,
        crc_of="real",
        first=("a/honest.xml", _MIB),
    )

    assert _verdict(path) == "archive_too_large"


# --- honest archives pass, fully inflated once in bounded chunks ----------------------


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


def _large_honest_entry(path: Path) -> Path:
    return _bomb(path, [32])


@pytest.mark.parametrize(
    ("build", "name"),
    [
        (_library_docx, "report.docx"),
        (_library_xlsx, "book.xlsx"),
        (_large_honest_entry, "large.docx"),
    ],
    ids=["docx", "xlsx", "32MiB-entry"],
)
def test_ooxml_honest_archive_passes_fully_inflated_once_in_bounded_chunks(
    tmp_path: Path, build: Callable[[Path], Path], name: str
) -> None:
    path = build(tmp_path / name)
    with zipfile.ZipFile(path) as archive:
        declared = {info.filename: info.file_size for info in archive.infolist()}

    run = _run(path)

    assert (
        run.verdict,
        {entry: size for entry, size in run.inflated.items() if size},
        _bounded(run),
        run.peak < _PEAK_LIMIT,
    ) == (None, {entry: size for entry, size in declared.items() if size}, True, True)


# --- not a ZIP ------------------------------------------------------------------------


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
