"""Zip-bomb guard for OOXML uploads (DOCX, XLSX) before a parser opens them (GH-188).

Inputs: the path of a stored DOCX or XLSX upload.
Outputs: nothing when the archive is within the limits; else ``ConversionError``
with ``archive_too_large`` or ``corrupted_file``.

Security notes:
- Judged from the central directory's declared sizes only (ZIP64 sizes
  included): nothing is decompressed. zipfile never yields more than an
  entry's declared size (and fails its CRC otherwise), so the declared sizes
  bound what python-docx or openpyxl can inflate afterwards.
- The limits (``common.MAX_OOXML_ENTRIES``, ``MAX_OOXML_ENTRY_BYTES``,
  ``MAX_OOXML_TOTAL_BYTES``) are read at call time.
- zipfile's own errors are dropped (``from None``): their text may hold
  input and never reaches a log or the database.
"""

from __future__ import annotations

import zipfile
from typing import TYPE_CHECKING

from admino.converters import common
from admino.converters.common import ConversionError

if TYPE_CHECKING:
    from pathlib import Path


def check_archive(path: Path) -> None:
    """Refuse an OOXML archive that is unreadable or declares too much content.

    Raises:
        ConversionError: ``corrupted_file`` when ``path`` isn't a readable ZIP;
            ``archive_too_large`` for more than ``MAX_OOXML_ENTRIES`` entries,
            an entry declaring more than ``MAX_OOXML_ENTRY_BYTES`` or all
            entries together declaring more than ``MAX_OOXML_TOTAL_BYTES``.
    """
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
    except MemoryError:
        raise
    except Exception:
        # zipfile's error surface isn't closed (BadZipFile, EOFError, struct
        # errors, NotImplementedError for an unsupported version, ...).
        raise ConversionError("corrupted_file") from None
    if len(entries) > common.MAX_OOXML_ENTRIES:
        raise ConversionError("archive_too_large")
    if any(entry.file_size > common.MAX_OOXML_ENTRY_BYTES for entry in entries):
        raise ConversionError("archive_too_large")
    if sum(entry.file_size for entry in entries) > common.MAX_OOXML_TOTAL_BYTES:
        raise ConversionError("archive_too_large")
