"""Attachment input boundary: file-name sanitizing and content-based type detection.

Every uploaded file and every ``X-Attachment-Name`` header passes through this
module before anything is stored (GH-187).

Inputs:
- ``sanitize_filename``: the raw ``X-Attachment-Name`` header (percent-encoded
  ASCII, or ``None`` when missing).
- ``detect_kind``: the path of the stored upload and its sanitized name.
- ``download_name`` / ``content_disposition``: a stored name and its kind.

Outputs: a clean file name, an ``AttachmentKind``, the download name and the
``Content-Disposition`` header value, or an ``AttachmentRefusedError`` whose
``reason`` is a fixed code and whose text is fixed English.

Security notes:
- The kind comes from the file's bytes only. The name merely chooses among the
  text kinds (csv, md, txt); a declared Content-Type is never an input.
- The whole file is scanned where it matters (a PDF's ``/Encrypt``, an OLE
  file's ``EncryptedPackage``, the text check), in chunks that overlap, so a
  harmless prefix can't carry a binary payload.
- ZIP files are read through their central directory only: nothing is
  decompressed here (the zip-bomb guard is #188's converter work). zipfile
  reads the archive through a wrapper that refuses any read past
  ``MAX_ZIP_DIRECTORY_BYTES``, so a huge directory is refused before it is
  read or parsed (its memory and CPU cost stay bounded); whatever zipfile
  raises while listing, ``MemoryError`` aside, is ``corrupted_file``.
- A refusal never carries the name, the path or any byte of the file, and
  every lower-level exception is dropped (``from None``) so its message, which
  may hold input, can't reach a log or a response.
- Pure: no database, no network, no logging, no async. Callers run
  ``detect_kind`` in a worker thread because it reads the whole file.
"""

from __future__ import annotations

import codecs
import os
import re
import unicodedata
import urllib.parse
import zipfile
from types import MappingProxyType
from typing import TYPE_CHECKING, BinaryIO, Final, Literal

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping
    from pathlib import Path

    from admino.models import AttachmentKind

KINDS: Final[tuple[AttachmentKind, ...]] = (
    "pdf",
    "docx",
    "xlsx",
    "csv",
    "txt",
    "md",
    "png",
    "jpeg",
    "webp",
)

MEDIA_TYPES: Final[Mapping[AttachmentKind, str]] = MappingProxyType(
    {
        "pdf": "application/pdf",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "csv": "text/csv; charset=utf-8",
        "txt": "text/plain; charset=utf-8",
        "md": "text/markdown; charset=utf-8",
        "png": "image/png",
        "jpeg": "image/jpeg",
        "webp": "image/webp",
    }
)

# The first extension of each kind is the canonical one (``download_name``).
EXTENSIONS: Final[Mapping[AttachmentKind, tuple[str, ...]]] = MappingProxyType(
    {
        "pdf": (".pdf",),
        "docx": (".docx",),
        "xlsx": (".xlsx",),
        "csv": (".csv",),
        "txt": (".txt",),
        "md": (".md", ".markdown"),
        "png": (".png",),
        "jpeg": (".jpg", ".jpeg"),
        "webp": (".webp",),
    }
)

RefusalReason = Literal[
    "invalid_filename",
    "content_length_required",
    "empty_file",
    "content_length_mismatch",
    "file_too_large",
    "storage_quota_exceeded",
    "unsupported_type",
    "legacy_office",
    "password_protected",
    "corrupted_file",
    "storage_unavailable",
]

REFUSAL_DETAILS: Final[Mapping[RefusalReason, str]] = MappingProxyType(
    {
        "invalid_filename": "Invalid attachment name",
        "content_length_required": "Content-Length is required",
        "empty_file": "The file is empty",
        "content_length_mismatch": "The body doesn't match Content-Length",
        "file_too_large": "The file is too large",
        "storage_quota_exceeded": "The organization's storage quota is full",
        "unsupported_type": "This file type isn't supported",
        "legacy_office": "Legacy Office files aren't supported: save as .docx or .xlsx",
        "password_protected": "The file is password-protected",
        "corrupted_file": "The file is corrupted",
        "storage_unavailable": "Attachment storage is unavailable",
    }
)


class AttachmentRefusedError(Exception):
    """An upload refused for ``reason``; the text is the fixed English detail, never input."""

    def __init__(self, reason: RefusalReason) -> None:
        super().__init__(REFUSAL_DETAILS[reason])
        self.reason: RefusalReason = reason


# --- File names --------------------------------------------------------------

_MAX_RAW_NAME_LENGTH: Final = 4096
_MAX_NAME_LENGTH: Final = 255
_MAX_KEPT_EXTENSION_LENGTH: Final = 16
# The header must be percent-encoded ASCII: printable characters only.
_RAW_NAME_RE: Final = re.compile(r"[\x20-\x7e]*")
_SEPARATORS_RE: Final = re.compile(r"[/\\]")
# Controls, format (bidi overrides, zero-width, BOM), surrogates, private use,
# unassigned, line and paragraph separators.
_REMOVED_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def sanitize_filename(raw: str | None) -> str:
    """Return the display name for the ``X-Attachment-Name`` header ``raw``.

    Steps: percent-decode once (strict UTF-8), NFC, keep the last ``/`` or
    ``\\`` segment, remove control/format/separator/unassigned characters,
    trim spaces then dots then spaces, cut to 255 characters keeping an
    extension of 1 to 16 characters.

    Raises:
        AttachmentRefusedError: ``invalid_filename`` when ``raw`` is missing,
            longer than 4096 characters, holds a character outside
            U+0020..U+007E, doesn't decode as UTF-8, or nothing is left.
    """
    if raw is None or len(raw) > _MAX_RAW_NAME_LENGTH or not _RAW_NAME_RE.fullmatch(raw):
        raise AttachmentRefusedError("invalid_filename")
    try:
        decoded = urllib.parse.unquote(raw, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        raise AttachmentRefusedError("invalid_filename") from None
    name = _SEPARATORS_RE.split(unicodedata.normalize("NFC", decoded))[-1]
    name = "".join(char for char in name if unicodedata.category(char) not in _REMOVED_CATEGORIES)
    name = name.strip().strip(".").strip()
    if not name:
        raise AttachmentRefusedError("invalid_filename")
    return _cut(name)


def _cut(name: str) -> str:
    """Cut ``name`` to 255 characters, keeping a short extension when there is one."""
    if len(name) <= _MAX_NAME_LENGTH:
        return name
    stem, dot, extension = name.rpartition(".")
    if dot and stem and 1 <= len(extension) <= _MAX_KEPT_EXTENSION_LENGTH:
        return stem[: _MAX_NAME_LENGTH - len(extension) - 1] + "." + extension
    return name[:_MAX_NAME_LENGTH]


def _extension(filename: str) -> str:
    """The lower-cased last extension of ``filename`` with its dot, or ``""``."""
    _, dot, extension = filename.rpartition(".")
    return "." + extension.lower() if dot else ""


# --- Type detection ----------------------------------------------------------

_HEAD_SIZE: Final = 16
_CHUNK_SIZE: Final = 1 << 20
_PDF_MAGIC: Final = b"%PDF-"
_PDF_EOF: Final = b"%%EOF"
_PDF_TAIL_SIZE: Final = 1024
# An /Encrypt entry: an indirect reference or an inline dictionary (not a
# longer name such as /EncryptMetadata).
_PDF_ENCRYPT_RE: Final = re.compile(rb"/Encrypt\s*(?:\d+\s+\d+\s+R|<<)")
# Longer than any /Encrypt entry a real PDF writes, so one spanning two
# chunks is still seen whole.
_PDF_ENCRYPT_OVERLAP: Final = 4096
_PNG_MAGIC: Final = b"\x89PNG\r\n\x1a\n"
_PNG_MIN_SIZE: Final = 33
_JPEG_MAGIC: Final = b"\xff\xd8\xff"
_ZIP_MAGIC: Final = b"PK\x03\x04"
# zipfile reads the whole central directory in one read and builds an object
# per entry: a larger directory is refused before any of it is read.
MAX_ZIP_DIRECTORY_BYTES: Final = 2 * 1024 * 1024
_ZIP_ENCRYPTED_FLAG: Final = 0x1
_OOXML_CONTENT_TYPES: Final = "[Content_Types].xml"
_CFB_MAGIC: Final = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_CFB_ENCRYPTED_PACKAGE: Final = "EncryptedPackage".encode("utf-16-le")
_UTF8_BOM: Final = b"\xef\xbb\xbf"
_TEXT_CONTROL_RE: Final = re.compile(r"[\x00-\x08\x0b\x0e-\x1f\x7f]")


def detect_kind(path: Path, filename: str) -> AttachmentKind:
    """Return the kind of the file at ``path`` from its bytes.

    ``filename`` (already sanitized) only chooses among the text kinds by its
    lower-cased extension: ``.csv`` csv, ``.md``/``.markdown`` md, else txt.
    Synchronous and reads the whole file: run it in a worker thread.

    Raises:
        AttachmentRefusedError: ``unsupported_type``, ``legacy_office``,
            ``password_protected`` or ``corrupted_file``.
        OSError: the file can't be read.
    """
    with path.open("rb") as file:
        size = os.fstat(file.fileno()).st_size
        head = file.read(_HEAD_SIZE)
        if head[:5] == _PDF_MAGIC:
            return _check_pdf(file, size)
        if head[:8] == _PNG_MAGIC:
            if size < _PNG_MIN_SIZE or head[12:16] != b"IHDR":
                raise AttachmentRefusedError("corrupted_file")
            return "png"
        if head[:3] == _JPEG_MAGIC:
            return "jpeg"
        if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
            if int.from_bytes(head[4:8], "little") + 8 > size:
                raise AttachmentRefusedError("corrupted_file")
            return "webp"
        if head[:4] == _ZIP_MAGIC:
            return _check_ooxml(_CappedReader(file, size))
        if head[:8] == _CFB_MAGIC:
            file.seek(0)
            if _contains(file, _CFB_ENCRYPTED_PACKAGE):
                raise AttachmentRefusedError("password_protected")
            raise AttachmentRefusedError("legacy_office")
        file.seek(0)
        _check_text(file)
    return _text_kind(filename)


def _chunks(file: BinaryIO) -> Iterator[bytes]:
    """Yield ``file`` from its current position in chunks of ``_CHUNK_SIZE``."""
    while chunk := file.read(_CHUNK_SIZE):
        yield chunk


def _contains(file: BinaryIO, needle: bytes) -> bool:
    """Whether ``needle`` occurs anywhere in ``file`` (also across a chunk boundary)."""
    carry = b""
    for chunk in _chunks(file):
        window = carry + chunk
        if needle in window:
            return True
        carry = window[-(len(needle) - 1) :]
    return False


def _check_pdf(file: BinaryIO, size: int) -> AttachmentKind:
    """A PDF must end with ``%%EOF`` (last 1024 bytes) and hold no ``/Encrypt`` entry."""
    file.seek(max(0, size - _PDF_TAIL_SIZE))
    if _PDF_EOF not in file.read(_PDF_TAIL_SIZE):
        raise AttachmentRefusedError("corrupted_file")
    file.seek(0)
    carry = b""
    for chunk in _chunks(file):
        # The window is a contiguous slice of the file, so a match in it is a
        # match in the file; the carried overlap finds an entry split by a read.
        window = carry + chunk
        if _PDF_ENCRYPT_RE.search(window):
            raise AttachmentRefusedError("password_protected")
        carry = window[-_PDF_ENCRYPT_OVERLAP:]
    return "pdf"


class _CappedReader:
    """A read-only view of an open file whose reads never exceed ``MAX_ZIP_DIRECTORY_BYTES``.

    A read asking for more, or an unsized read that would return more, raises
    instead of returning fewer bytes: zipfile lists a directory cut short
    inside its last entry's name or comment without noticing.
    """

    def __init__(self, file: BinaryIO, size: int) -> None:
        self._file = file
        self._size = size

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Move to ``offset`` (relative to ``whence``) in the file."""
        return self._file.seek(offset, whence)

    def tell(self) -> int:
        """The current position in the file."""
        return self._file.tell()

    def read(self, size: int | None = -1) -> bytes:
        """Return ``size`` bytes (all that are left when unsized), refusing more than the cap.

        Raises:
            zipfile.BadZipFile: The read would hand out more than
                ``MAX_ZIP_DIRECTORY_BYTES``.
        """
        if size is None or size < 0:
            size = max(0, self._size - self._file.tell())
        if size > MAX_ZIP_DIRECTORY_BYTES:
            raise zipfile.BadZipFile("Central directory too large")
        return self._file.read(size)


def _check_ooxml(file: _CappedReader) -> AttachmentKind:
    """Classify a ZIP by its central directory alone: DOCX, XLSX or refused."""
    try:
        with zipfile.ZipFile(file) as archive:
            entries = archive.infolist()
    except MemoryError:
        raise
    except Exception:
        # zipfile's error surface isn't closed (NotImplementedError for an
        # unsupported "version needed to extract", among others).
        raise AttachmentRefusedError("corrupted_file") from None
    if any(entry.flag_bits & _ZIP_ENCRYPTED_FLAG for entry in entries):
        raise AttachmentRefusedError("password_protected")
    names = [entry.filename for entry in entries]
    if _OOXML_CONTENT_TYPES in names:
        if any(name.startswith("word/") for name in names):
            return "docx"
        if any(name.startswith("xl/") for name in names):
            return "xlsx"
    raise AttachmentRefusedError("unsupported_type")


def _check_text(file: BinaryIO) -> None:
    """Refuse a file that isn't strict UTF-8 text without control characters.

    TAB, LF, FF and CR are allowed; an optional leading BOM is skipped.
    """
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    if file.read(len(_UTF8_BOM)) != _UTF8_BOM:
        file.seek(0)
    try:
        for chunk in _chunks(file):
            if _TEXT_CONTROL_RE.search(decoder.decode(chunk)):
                raise AttachmentRefusedError("unsupported_type")
        # final=True: a sequence cut at the end of the file is an error.
        decoder.decode(b"", final=True)
    except UnicodeDecodeError:
        raise AttachmentRefusedError("unsupported_type") from None


def _text_kind(filename: str) -> AttachmentKind:
    """The text kind ``filename``'s extension names: csv, md or txt."""
    extension = _extension(filename)
    if extension in EXTENSIONS["csv"]:
        return "csv"
    if extension in EXTENSIONS["md"]:
        return "md"
    return "txt"


# --- Download headers --------------------------------------------------------


def download_name(filename: str, kind: AttachmentKind) -> str:
    """The name a download carries: ``filename`` plus the kind's extension unless it has one.

    The result may exceed 255 characters; it is never stored.
    """
    if _extension(filename) in EXTENSIONS[kind]:
        return filename
    return filename + EXTENSIONS[kind][0]


def content_disposition(name: str) -> str:
    """The ``Content-Disposition`` value for ``name`` (RFC 5987, nothing left unencoded)."""
    return "attachment; filename*=UTF-8''" + urllib.parse.quote(name, safe="")
