"""Zip-bomb guard for OOXML uploads (DOCX, XLSX) before a parser opens them (GH-188).

Inputs: the path of a stored DOCX or XLSX upload.
Outputs: nothing when the archive is within the limits; else ``ConversionError``
with ``archive_too_large``, ``corrupted_file`` or ``password_protected``.

Security notes:
- The central directory is judged first, from the declared sizes only (ZIP64
  sizes included) and without decompressing anything: too many entries, an
  entry or all entries together declaring too much -> ``archive_too_large``.
- Declared sizes alone bound nothing: zipfile cuts what it *returns* at an
  entry's declared size, but BZIP2/LZMA inflate a read without any output
  limit and DEFLATE ``read()`` inflates up to 1 GiB before cutting. So only
  stored and deflate entries are accepted (the only methods ECMA-376 allows;
  others are ``corrupted_file``), an encrypted entry is
  ``password_protected``, and every entry is then inflated once in chunks of
  at most 64 KiB, its REAL size counted against the same limits (stopping one
  byte past the entry limit) and compared with the declared one. After this,
  each entry is known to inflate to exactly its declared size, so the later
  reads by python-docx and openpyxl are bounded by the declared sizes.
- No more than one chunk of an entry is held in memory.
- The limits (``common.MAX_OOXML_ENTRIES``, ``MAX_OOXML_ENTRY_BYTES``,
  ``MAX_OOXML_TOTAL_BYTES``) are read at call time.
- zipfile's and zlib's own errors are dropped (``from None``): their text may
  hold input and never reaches a log or the database.
"""

from __future__ import annotations

import copy
import zipfile
from typing import TYPE_CHECKING, Final

from admino.converters import common
from admino.converters.common import ConversionError

if TYPE_CHECKING:
    from pathlib import Path

_CHUNK_BYTES: Final = 64 * 1024
_ALLOWED_METHODS: Final = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})
_ENCRYPTED_FLAG: Final = 0x1


def check_archive(path: Path) -> None:
    """Refuse an OOXML archive that is unreadable, encrypted or holds too much content.

    Raises:
        ConversionError: ``archive_too_large`` for more than
            ``MAX_OOXML_ENTRIES`` entries, an entry declaring or really
            inflating to more than ``MAX_OOXML_ENTRY_BYTES``, or all entries
            together declaring or really inflating to more than
            ``MAX_OOXML_TOTAL_BYTES``; ``corrupted_file`` when ``path`` isn't a
            readable ZIP, an entry is neither stored nor deflated, or an entry's
            real content doesn't match its declared size and CRC;
            ``password_protected`` for an encrypted entry.
    """
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            _check_directory(entries)
            _check_real_sizes(archive, entries)
    except (ConversionError, MemoryError):
        raise
    except Exception:
        # zipfile's error surface isn't closed (BadZipFile for a CRC or header
        # mismatch, zlib.error, EOFError, struct errors, NotImplementedError ...).
        raise ConversionError("corrupted_file") from None


def _check_directory(entries: list[zipfile.ZipInfo]) -> None:
    """The checks that need no decompression: declared sizes, methods, encryption."""
    if len(entries) > common.MAX_OOXML_ENTRIES:
        raise ConversionError("archive_too_large")
    if any(entry.file_size > common.MAX_OOXML_ENTRY_BYTES for entry in entries):
        raise ConversionError("archive_too_large")
    if sum(entry.file_size for entry in entries) > common.MAX_OOXML_TOTAL_BYTES:
        raise ConversionError("archive_too_large")
    # Every entry's method before any entry is inflated: one BZIP2 or LZMA read
    # inflates its whole stream at once.
    for entry in entries:
        if entry.compress_type not in _ALLOWED_METHODS:
            raise ConversionError("corrupted_file")
        if entry.flag_bits & _ENCRYPTED_FLAG:
            raise ConversionError("password_protected")


def _check_real_sizes(archive: zipfile.ZipFile, entries: list[zipfile.ZipInfo]) -> None:
    """Inflate every entry once in bounded chunks and hold its real size to the limits."""
    entry_limit = common.MAX_OOXML_ENTRY_BYTES
    total_limit = common.MAX_OOXML_TOTAL_BYTES
    total = 0
    for entry in entries:
        # zipfile ends an entry (and compares its CRC) once the declared size is
        # read: the probe declares more than is ever read here, so a lying
        # entry is cut by the limits below, not by a CRC error at the cut.
        probe = copy.copy(entry)
        probe.file_size = entry_limit + 1 + 2 * _CHUNK_BYTES
        real = 0
        with archive.open(probe) as stream:
            while chunk := stream.read(min(_CHUNK_BYTES, entry_limit + 1 - real)):
                real += len(chunk)
                total += len(chunk)
                if real > entry_limit or total > total_limit:
                    raise ConversionError("archive_too_large")
        if real != entry.file_size:
            raise ConversionError("corrupted_file")
