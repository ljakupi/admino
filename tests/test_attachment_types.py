"""Tests for ``admino.attachment_types`` (GH-187 contract section 3.2): the input boundary.

Every uploaded file and every ``X-Attachment-Name`` header passes through this
pure module before anything is stored. What these tests pin down:

- Constants: ``KINDS`` is ``models.AttachmentKind``'s members in order;
  ``MEDIA_TYPES`` (the download ``Content-Type`` per kind, text kinds with
  ``charset=utf-8``), ``EXTENSIONS`` (canonical extension first) and
  ``REFUSAL_DETAILS`` (fixed English per ``RefusalReason``) are exactly the
  contract's.
- ``AttachmentRefusedError(reason)``: ``reason`` is kept, ``str()`` is
  ``REFUSAL_DETAILS[reason]``; a refusal never carries the name, the path or
  any byte of the file.
- ``sanitize_filename(raw)``: refused (``invalid_filename``) when missing,
  longer than 4096 raw characters, holding a raw character outside
  U+0020..U+007E, not strict UTF-8 after percent-decoding, or empty after the
  steps. The steps, in order: percent-decode once (``%ZZ`` stays literal),
  NFC (not NFKC), the last ``/`` or ``\\`` segment (also when the separator was
  percent-encoded), every Cc/Cf/Cs/Co/Cn/Zl/Zp character removed (NUL, CR/LF,
  C1, bidi overrides, zero-width, BOM, line and paragraph separators, private
  use, unassigned), spaces then dots then spaces trimmed (after the removal),
  then a cut to 255 characters (code points) that keeps an extension of 1 to
  16 characters.
- ``detect_kind(path, filename)``: the kind comes from the bytes; the name only
  picks among the text kinds (``.csv`` csv, ``.md``/``.markdown`` md, any
  other txt, case-insensitive) and no Content-Type is taken at all. Each rule
  of the contract's list with its boundary: PDF ``%%EOF`` within the last 1024
  bytes (1019 trailing bytes pass, 1020 don't), ``/Encrypt`` as a reference or
  an inline dictionary anywhere in the file (also split across a 4 MiB read
  boundary, far from both ends) but not ``/EncryptMetadata``, corrupted before
  protected; PNG of at least 33 bytes with ``IHDR`` at 12..16; JPEG on its magic
  bytes alone; WEBP whose RIFF size fits the file (RIFF of another format is
  not WEBP); ZIP read from its central directory only (an entry's bad CRC is
  not looked at), unreadable -> corrupted, an encrypted entry -> protected,
  DOCX/XLSX by ``[Content_Types].xml`` + ``word/``/``xl/``, any other ZIP
  (plain, PPTX) unsupported; OLE/CFB with a UTF-16LE ``EncryptedPackage``
  stream -> protected, else ``legacy_office``; text as strict UTF-8 over the
  whole file (a BOM allowed, a multi-byte character across a read boundary
  fine, a truncated sequence at EOF refused) without U+0000..U+0008, U+000B,
  U+000E..U+001F or U+007F (TAB, LF, FF, CR allowed).
- Spoofs: content wins over the name (PNG named ``.pdf`` is png), an
  executable named ``.pdf``/``.txt``/``.png`` is unsupported, HTML and SVG are
  plain text.
- ``download_name``: the stored name when its last extension fits the kind,
  else the kind's canonical extension appended (never truncated).
- ``content_disposition``: exactly ``attachment; filename*=UTF-8''`` plus the
  name percent-encoded with nothing safe, so quotes, semicolons, separators
  and CR/LF can't split or extend the header.
- Purity: no import of server, agent, llm*, tools, database or asyncpg, and no
  async code (callers run ``detect_kind`` in a worker thread).

The module is imported inside the ``at`` fixture, so this file collects before
it exists and every test fails on its own. Fixture files are built in
``tmp_path`` with stdlib only (struct, zlib, zipfile): no binary in the repo.
"""

from __future__ import annotations

import ast
import inspect
import struct
import typing
import zipfile
import zlib
from typing import TYPE_CHECKING, Any

import pytest

import admino.models as models_module

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path
    from types import ModuleType

_MARKER = "ZZ-SENTINEL-187"
# Every power-of-two read chunk up to 4 MiB has a boundary here.
_BOUNDARY = 1 << 22

_KINDS = ("pdf", "docx", "xlsx", "csv", "txt", "md", "png", "jpeg", "webp")
_MEDIA_TYPES = {
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
_EXTENSIONS = {
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
_REFUSAL_DETAILS = {
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
_BANNED_IMPORT_PREFIXES = (
    "admino.server",
    "admino.agent",
    "admino.llm",
    "admino.tools",
    "admino.database",
    "asyncpg",
)

# Characters built with chr() so they survive editing tools verbatim.
_E_ACUTE = chr(0xE9)
_U_UMLAUT = chr(0xFC)
_FI_LIGATURE = chr(0xFB01)  # NFKC would turn it into "fi"; NFC keeps it
_NIHON = chr(0x65E5) + chr(0x672C)
_ROCKET = chr(0x1F680)

# --- Fixture bytes -----------------------------------------------------------

_PDF_HEAD = (
    b"%PDF-1.7\n%"
    + bytes([0xE2, 0xE3, 0xCF, 0xD3])
    + b"\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
)
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_JPEG_HEAD = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
_CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
# A Windows executable's first bytes (DOS header with NULs, then the PE signature).
_EXE = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + bytes(44) + b"PE\x00\x00"
_HTML = b"<!DOCTYPE html><html><body><script>alert(1)</script></body></html>\n"
_SVG = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect/></svg>\n'
_CSV = b"name,amount\nAlpha,12\nBeta,7\n"
_DOCX_NAMES = ("[Content_Types].xml", "_rels/.rels", "word/document.xml")
_XLSX_NAMES = ("[Content_Types].xml", "_rels/.rels", "xl/workbook.xml", "xl/worksheets/s1.xml")
_PPTX_NAMES = ("[Content_Types].xml", "_rels/.rels", "ppt/presentation.xml")


def _pdf(trailer: bytes = b"/Root 1 0 R", *, after_eof: bytes = b"\n") -> bytes:
    """A small PDF; ``after_eof`` is what follows the final ``%%EOF``."""
    return _PDF_HEAD + b"trailer\n<< " + trailer + b" >>\nstartxref\n9\n%%EOF" + after_eof


def _png_ihdr(chunk_type: bytes = b"IHDR") -> bytes:
    """The PNG signature plus one 13-byte header chunk with its CRC: 33 bytes."""
    data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    crc = struct.pack(">I", zlib.crc32(chunk_type + data))
    return _PNG_SIGNATURE + struct.pack(">I", len(data)) + chunk_type + data + crc


def _png() -> bytes:
    iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND"))
    return _png_ihdr() + iend


def _webp(*, overrun: int = 0) -> bytes:
    """A RIFF/WEBP file whose RIFF size claims ``overrun`` bytes more than it has."""
    body = b"WEBP" + b"VP8L" + struct.pack("<I", 6) + b"\x2f\x00\x00\x00\x00\x00"
    return b"RIFF" + struct.pack("<I", len(body) + overrun) + body


def _wav() -> bytes:
    fmt = struct.pack("<IHHIIHH", 16, 1, 1, 8000, 8000, 1, 8)
    return b"RIFF" + struct.pack("<I", 36) + b"WAVEfmt " + fmt + b"data" + struct.pack("<I", 0)


def _cfb(*names: str) -> bytes:
    """An OLE/CFB file: header sector, then one directory sector with ``names``."""
    header = (_CFB_MAGIC + bytes(16) + b"\x3e\x00\x03\x00\xfe\xff\x09\x00").ljust(512, b"\x00")
    entries = b"".join(name.encode("utf-16-le").ljust(64, b"\x00") + bytes(64) for name in names)
    return header + entries.ljust(1024, b"\x00")


def _zip_bytes(
    tmp_path: Path,
    names: Sequence[str],
    *,
    encrypted: str | None = None,
    stored: bool = False,
) -> bytes:
    """A ZIP of ``names``; ``encrypted`` gets flag bit 0 in the central directory."""
    path = tmp_path / "built.zip"
    method = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(path, "w", method) as archive:
        for name in names:
            archive.writestr(name, "<x>" + name + "</x>")
        if encrypted is not None:
            # zipfile resets flag_bits while writing an entry; the central
            # directory is written at close() from the ZipInfo, so set it here.
            archive.getinfo(encrypted).flag_bits |= 0x1
    data = path.read_bytes()
    path.unlink()
    return data


def _write(tmp_path: Path, data: bytes) -> Path:
    """The upload as it lies on disk: a ``.part`` file named by an id, not by the user."""
    path = tmp_path / "upload.part"
    path.write_bytes(data)
    return path


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def at() -> ModuleType:
    """``admino.attachment_types``, imported per test (fails each test until it exists)."""
    from admino import attachment_types

    return attachment_types


def _detect(at: ModuleType, path: Path, filename: str) -> str:
    """The detected kind, or the refusal reason (whose text must be the fixed detail)."""
    try:
        kind = at.detect_kind(path, filename)
    except at.AttachmentRefusedError as exc:
        assert str(exc) == _REFUSAL_DETAILS[exc.reason]
        return str(exc.reason)
    return str(kind)


def _sanitized(at: ModuleType, raw: str | None) -> str:
    """The sanitized name, or ``refused:<reason>``."""
    try:
        return str(at.sanitize_filename(raw))
    except at.AttachmentRefusedError as exc:
        return f"refused:{exc.reason}"


def _imported_modules(tree: ast.AST) -> list[str]:
    """Every module an import statement of ``tree`` names (relative ones as admino.*)."""
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                module = f"admino.{module}" if module else "admino"
            if module == "admino":
                names.extend(f"admino.{alias.name}" for alias in node.names)
            else:
                names.append(module)
    return names


# ---------------------------------------------------------------------------
# 1. Constants and the refusal error
# ---------------------------------------------------------------------------


class TestConstants:
    """KINDS, MEDIA_TYPES, EXTENSIONS, RefusalReason and REFUSAL_DETAILS."""

    def test_attachment_types_kinds_are_the_attachment_kind_literal_in_order(
        self, at: ModuleType
    ) -> None:
        kind = getattr(models_module, "AttachmentKind", None)

        assert tuple(at.KINDS) == _KINDS
        assert kind is not None
        assert typing.get_args(kind) == tuple(at.KINDS)

    def test_attachment_types_media_types_are_exactly_the_contract(self, at: ModuleType) -> None:
        assert dict(at.MEDIA_TYPES) == _MEDIA_TYPES

    def test_attachment_types_extensions_are_exactly_the_contract(self, at: ModuleType) -> None:
        assert dict(at.EXTENSIONS) == _EXTENSIONS

    def test_attachment_types_refusal_details_cover_every_reason(self, at: ModuleType) -> None:
        reasons = frozenset(typing.get_args(at.RefusalReason))

        assert dict(at.REFUSAL_DETAILS) == _REFUSAL_DETAILS
        assert reasons == frozenset(_REFUSAL_DETAILS)

    def test_attachment_types_refused_error_text_is_the_fixed_detail(self, at: ModuleType) -> None:
        """Every reason: ``reason`` kept, ``str()`` the fixed English text."""
        seen = {}
        for reason in _REFUSAL_DETAILS:
            error = at.AttachmentRefusedError(reason)
            assert isinstance(error, Exception)
            seen[reason] = (error.reason, str(error))

        assert seen == {reason: (reason, text) for reason, text in _REFUSAL_DETAILS.items()}


# ---------------------------------------------------------------------------
# 2. sanitize_filename
# ---------------------------------------------------------------------------

_SANITIZED: tuple[tuple[str, str, str], ...] = (
    ("plain", "report.pdf", "report.pdf"),
    ("inner-spaces-and-punctuation", "Q3 report (final).pdf", "Q3 report (final).pdf"),
    ("percent-encoded-utf8", "Offerte%20M%C3%BCller.pdf", "Offerte M" + _U_UMLAUT + "ller.pdf"),
    ("nfc", "Cafe%CC%81.txt", "Caf" + _E_ACUTE + ".txt"),
    ("nfc-not-nfkc", "%EF%AC%81le.txt", _FI_LIGATURE + "le.txt"),
    ("unicode-kept", "%E6%97%A5%E6%9C%AC%20%F0%9F%9A%80.txt", _NIHON + " " + _ROCKET + ".txt"),
    ("invalid-escape-literal", "50%ZZoff.txt", "50%ZZoff.txt"),
    ("decoded-once", "a%252Fb.txt", "a%2Fb.txt"),
    ("unix-traversal", "../../etc/passwd", "passwd"),
    ("windows-path", "C:\\Users\\x\\a.pdf", "a.pdf"),
    ("encoded-slash-traversal", "..%2F..%2Fetc%2Fpasswd", "passwd"),
    ("encoded-backslash-traversal", "..%5C..%5Cboot.ini", "boot.ini"),
    ("nul", "evil.exe%00.pdf", "evil.exe.pdf"),
    ("crlf", "a%0D%0Ab.txt", "ab.txt"),
    ("c1-nel", "a%C2%85b.txt", "ab.txt"),
    ("bidi-override-u202e", "invoice%E2%80%AEfdp.exe", "invoicefdp.exe"),
    ("zero-width-space", "pay%E2%80%8Bment.pdf", "payment.pdf"),
    ("bom", "%EF%BB%BFnotes.txt", "notes.txt"),
    ("line-separator-zl", "a%E2%80%A8b.txt", "ab.txt"),
    ("paragraph-separator-zp", "a%E2%80%A9b.txt", "ab.txt"),
    ("private-use-co", "a%EE%80%80b.txt", "ab.txt"),
    ("unassigned-cn", "a%CD%B8b.txt", "ab.txt"),
    ("trim-spaces", "   report.pdf   ", "report.pdf"),
    ("trim-dots", "...report.pdf...", "report.pdf"),
    ("dotfile", ".env", "env"),
    ("spaces-trimmed-before-dots", " .env. ", "env"),
    ("spaces-trimmed-after-dots", ". report.pdf .", "report.pdf"),
    ("removal-before-trim", "%E2%80%8B .report.pdf", "report.pdf"),
)

_REFUSED_NAMES: tuple[tuple[str, str | None], ...] = (
    ("missing", None),
    ("empty", ""),
    ("raw-over-4096", "%41" * 1365 + "aa"),
    ("raw-non-ascii", "caf" + _E_ACUTE + ".pdf"),
    ("raw-tab", "a" + chr(0x09) + "b.pdf"),
    ("raw-del", "a" + chr(0x7F) + "b.pdf"),
    ("invalid-utf8", "%FF.pdf"),
    ("truncated-utf8", "caf%C3.pdf"),
    ("encoded-surrogate", "%ED%A0%80.pdf"),
    ("overlong-slash", "..%C0%AF..%C0%AFetc%C0%AFpasswd"),
    ("trailing-slash", "docs/"),
    ("encoded-dotdot-segment", "x%2F.."),
    ("dot", "."),
    ("dotdot", ".."),
    ("three-dots", "..."),
    ("spaces", "   "),
    ("controls-only", "%00%0D%0A"),
    ("dots-between-zero-width", "%E2%80%8B..%E2%80%8B"),
)

_LENGTHS: tuple[tuple[str, str, str], ...] = (
    ("exactly-255-kept", "a" * 251 + ".pdf", "a" * 251 + ".pdf"),
    ("256-keeps-the-extension", "a" * 252 + ".pdf", "a" * 251 + ".pdf"),
    ("16-char-extension-kept", "a" * 300 + "." + "b" * 16, "a" * 238 + "." + "b" * 16),
    ("17-char-extension-cut-plainly", "a" * 300 + "." + "b" * 17, "a" * 255),
    ("no-extension-cut-plainly", "a" * 300, "a" * 255),
    ("counts-characters-not-bytes", "%C3%A9" * 300 + ".pdf", _E_ACUTE * 251 + ".pdf"),
    ("raw-of-exactly-4096", "%41" * 1365 + "a", "A" * 255),
)


class TestSanitizeFilename:
    """The X-Attachment-Name header: decoded, normalized, cleaned, trimmed, cut."""

    @pytest.mark.parametrize(
        ("label", "raw", "expected"), _SANITIZED, ids=[case[0] for case in _SANITIZED]
    )
    def test_attachment_types_sanitize_filename_cleans_the_name(
        self, at: ModuleType, label: str, raw: str, expected: str
    ) -> None:
        assert _sanitized(at, raw) == expected, label

    @pytest.mark.parametrize(("label", "raw"), _REFUSED_NAMES, ids=[c[0] for c in _REFUSED_NAMES])
    def test_attachment_types_sanitize_filename_refuses_invalid_names(
        self, at: ModuleType, label: str, raw: str | None
    ) -> None:
        assert _sanitized(at, raw) == "refused:invalid_filename", label

    @pytest.mark.parametrize(("label", "raw", "expected"), _LENGTHS, ids=[c[0] for c in _LENGTHS])
    def test_attachment_types_sanitize_filename_cuts_to_255_characters(
        self, at: ModuleType, label: str, raw: str, expected: str
    ) -> None:
        result = _sanitized(at, raw)

        assert result == expected, label
        assert len(result) <= 255

    @pytest.mark.parametrize(
        "raw",
        [_MARKER + "%FF.pdf", _MARKER + _E_ACUTE + ".pdf", _MARKER + "x" * 4096, _MARKER + "/"],
        ids=["undecodable", "raw-non-ascii", "too-long", "empty-after-steps"],
    )
    def test_attachment_types_sanitize_filename_refusal_never_echoes_the_name(
        self, at: ModuleType, raw: str
    ) -> None:
        with pytest.raises(at.AttachmentRefusedError) as exc_info:
            at.sanitize_filename(raw)

        error = exc_info.value
        assert error.reason == "invalid_filename"
        assert str(error) == "Invalid attachment name"
        assert _MARKER not in repr(error)
        assert _MARKER not in repr(error.args)


# ---------------------------------------------------------------------------
# 3. detect_kind: every supported kind, spoofs, the text kinds
# ---------------------------------------------------------------------------

_SPOOFS: tuple[tuple[str, bytes, str, str], ...] = (
    ("png-named-pdf", _png(), "scan.pdf", "png"),
    ("png-named-csv", _png(), "data.csv", "png"),
    ("pdf-named-png", _pdf(), "photo.png", "pdf"),
    ("exe-named-pdf", _EXE, "invoice.pdf", "unsupported_type"),
    ("exe-named-txt", _EXE, "notes.txt", "unsupported_type"),
    ("exe-named-png", _EXE, "photo.png", "unsupported_type"),
    ("text-named-pdf", b"Not really a PDF\n", "report.pdf", "txt"),
    ("html-is-text", _HTML, "page.html", "txt"),
    ("svg-is-text", _SVG, "logo.svg", "txt"),
    ("svg-named-png", _SVG, "logo.png", "txt"),
    ("riff-wave-is-not-webp", _wav(), "sound.webp", "unsupported_type"),
)


class TestDetectKindSupported:
    """Each supported kind is recognised from its bytes."""

    def test_attachment_types_detect_kind_takes_only_the_path_and_the_name(
        self, at: ModuleType
    ) -> None:
        """No Content-Type parameter: the declared type can't influence detection."""
        assert list(inspect.signature(at.detect_kind).parameters) == ["path", "filename"]

    def test_attachment_types_detect_kind_recognises_every_supported_kind(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        samples: dict[str, tuple[bytes, str]] = {
            "pdf": (_pdf(), "report.pdf"),
            "docx": (_zip_bytes(tmp_path, _DOCX_NAMES), "letter.docx"),
            "xlsx": (_zip_bytes(tmp_path, _XLSX_NAMES), "budget.xlsx"),
            "csv": (_CSV, "amounts.csv"),
            "txt": (b"Meeting notes\n- item one\n", "notes.txt"),
            "md": (b"# Title\n\nSome *text*.\n", "readme.md"),
            "png": (_png(), "chart.png"),
            "jpeg": (_JPEG_HEAD + b"\x00" * 32 + b"\xff\xd9", "photo.jpg"),
            "webp": (_webp(), "image.webp"),
        }
        detected = {
            kind: _detect(at, _write(tmp_path, data), name)
            for kind, (data, name) in samples.items()
        }

        assert detected == {kind: kind for kind in _KINDS}

    @pytest.mark.parametrize(
        ("label", "data", "filename", "expected"), _SPOOFS, ids=[case[0] for case in _SPOOFS]
    )
    def test_attachment_types_detect_kind_trusts_content_not_the_name(
        self, tmp_path: Path, at: ModuleType, label: str, data: bytes, filename: str, expected: str
    ) -> None:
        assert _detect(at, _write(tmp_path, data), filename) == expected, label

    def test_attachment_types_detect_kind_docx_named_xlsx_is_docx(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        path = _write(tmp_path, _zip_bytes(tmp_path, _DOCX_NAMES))

        assert _detect(at, path, "budget.xlsx") == "docx"

    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            ("data.csv", "csv"),
            ("DATA.CSV", "csv"),
            ("notes.md.csv", "csv"),
            ("notes.md", "md"),
            ("README.MD", "md"),
            ("guide.markdown", "md"),
            ("notes.txt", "txt"),
            ("table.csv.txt", "txt"),
            ("server.log", "txt"),
            ("README", "txt"),
        ],
    )
    def test_attachment_types_detect_kind_text_kind_follows_the_extension(
        self, tmp_path: Path, at: ModuleType, filename: str, expected: str
    ) -> None:
        assert _detect(at, _write(tmp_path, _CSV), filename) == expected

    def test_attachment_types_detect_kind_text_with_bom_is_text(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        path = _write(tmp_path, b"\xef\xbb\xbf" + _CSV)

        assert _detect(at, path, "amounts.csv") == "csv"
        assert _detect(at, path, "amounts.txt") == "txt"


# ---------------------------------------------------------------------------
# 4. detect_kind: PDF
# ---------------------------------------------------------------------------


class TestDetectKindPdf:
    """%%EOF in the last 1024 bytes; /Encrypt anywhere means password-protected."""

    @pytest.mark.parametrize(
        ("trailing", "expected"),
        [(1019, "pdf"), (1020, "corrupted_file")],
        ids=["eof-starts-1024-from-the-end", "eof-starts-1025-from-the-end"],
    )
    def test_attachment_types_detect_kind_pdf_eof_must_be_in_the_last_1024_bytes(
        self, tmp_path: Path, at: ModuleType, trailing: int, expected: str
    ) -> None:
        path = _write(tmp_path, _pdf(after_eof=b"\n" * trailing))

        assert _detect(at, path, "report.pdf") == expected

    def test_attachment_types_detect_kind_pdf_without_eof_is_corrupted(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        truncated = _pdf()[: -len(b"%%EOF\n")]

        assert _detect(at, _write(tmp_path, truncated), "report.pdf") == "corrupted_file"

    @pytest.mark.parametrize(
        "trailer",
        [
            b"/Root 1 0 R /Encrypt 5 0 R",
            b"/Root 1 0 R /Encrypt<</Filter /Standard /V 2>>",
            b"/Root 1 0 R /Encrypt <</Filter /Standard /V 2>>",
        ],
        ids=["indirect-reference", "inline-dictionary", "inline-dictionary-after-space"],
    )
    def test_attachment_types_detect_kind_pdf_with_encrypt_is_password_protected(
        self, tmp_path: Path, at: ModuleType, trailer: bytes
    ) -> None:
        assert _detect(at, _write(tmp_path, _pdf(trailer)), "report.pdf") == "password_protected"

    def test_attachment_types_detect_kind_pdf_encrypt_metadata_alone_is_a_pdf(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        """Only an /Encrypt entry (reference or dictionary) counts, not a longer name."""
        path = _write(tmp_path, _pdf(b"/Root 1 0 R /EncryptMetadata false"))

        assert _detect(at, path, "report.pdf") == "pdf"

    def test_attachment_types_detect_kind_truncated_encrypted_pdf_is_corrupted(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        """The %%EOF check comes first."""
        truncated = _pdf(b"/Root 1 0 R /Encrypt 5 0 R")[: -len(b"%%EOF\n")]

        assert _detect(at, _write(tmp_path, truncated), "report.pdf") == "corrupted_file"

    def test_attachment_types_detect_kind_pdf_encrypt_split_across_a_read_chunk_is_found(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        """A 4 MiB+ PDF whose /Encrypt reference spans the 4 MiB offset, far from both ends.

        Only the final ``R`` lies past the boundary, so a scan without enough
        overlap between chunks misses it; 70000 bytes follow it, so a scan of the
        tail alone misses it too.
        """
        token = b"/Encrypt 5 0 R"
        start = _BOUNDARY - (len(token) - 1)
        prefix = _PDF_HEAD + b"trailer\n<< /Root 1 0 R "
        data = prefix.ljust(start, b" ") + token + b" >>\n" + b"\n" * 70000 + b"%%EOF\n"
        assert data.index(token) == start

        assert _detect(at, _write(tmp_path, data), "report.pdf") == "password_protected"


# ---------------------------------------------------------------------------
# 5. detect_kind: images
# ---------------------------------------------------------------------------


class TestDetectKindImages:
    """PNG needs IHDR in 33+ bytes; JPEG its magic bytes; WEBP a RIFF size that fits."""

    def test_attachment_types_detect_kind_png_of_33_bytes_with_ihdr_is_a_png(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        data = _png_ihdr()
        assert len(data) == 33

        assert _detect(at, _write(tmp_path, data), "chart.png") == "png"

    @pytest.mark.parametrize(
        "data",
        [_png_ihdr()[:32], _png_ihdr(b"IDAT"), _PNG_SIGNATURE],
        ids=["32-bytes", "no-ihdr", "signature-only"],
    )
    def test_attachment_types_detect_kind_broken_png_is_corrupted(
        self, tmp_path: Path, at: ModuleType, data: bytes
    ) -> None:
        assert _detect(at, _write(tmp_path, data), "chart.png") == "corrupted_file"

    def test_attachment_types_detect_kind_jpeg_with_trailing_data_is_a_jpeg(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        """No structural check (Pillow re-validates in #188): no end marker, junk after."""
        data = _JPEG_HEAD + b"\x00\x01\x02" + b"trailing data, no end-of-image marker"

        assert _detect(at, _write(tmp_path, data), "photo.jpeg") == "jpeg"

    @pytest.mark.parametrize(
        ("overrun", "expected"),
        [(0, "webp"), (1, "corrupted_file")],
        ids=["riff-size-fits", "riff-size-one-past-the-end"],
    )
    def test_attachment_types_detect_kind_webp_riff_size_must_fit_the_file(
        self, tmp_path: Path, at: ModuleType, overrun: int, expected: str
    ) -> None:
        assert _detect(at, _write(tmp_path, _webp(overrun=overrun)), "image.webp") == expected


# ---------------------------------------------------------------------------
# 6. detect_kind: ZIP and OLE/CFB
# ---------------------------------------------------------------------------


class TestDetectKindContainers:
    """OOXML by structure; encrypted and unreadable containers refused."""

    @pytest.mark.parametrize(
        "names",
        [
            ("a.txt", "b/c.csv"),
            _PPTX_NAMES,
            ("_rels/.rels", "word/document.xml"),
        ],
        ids=["plain-zip", "pptx", "word-without-content-types"],
    )
    def test_attachment_types_detect_kind_other_zip_is_unsupported(
        self, tmp_path: Path, at: ModuleType, names: tuple[str, ...]
    ) -> None:
        path = _write(tmp_path, _zip_bytes(tmp_path, names))

        assert _detect(at, path, "file.docx") == "unsupported_type"

    @pytest.mark.parametrize(
        ("names", "encrypted"),
        [(_DOCX_NAMES, "word/document.xml"), (_XLSX_NAMES, "xl/workbook.xml")],
        ids=["docx", "xlsx"],
    )
    def test_attachment_types_detect_kind_zip_with_an_encrypted_entry_is_password_protected(
        self, tmp_path: Path, at: ModuleType, names: tuple[str, ...], encrypted: str
    ) -> None:
        data = _zip_bytes(tmp_path, names, encrypted=encrypted)

        assert _detect(at, _write(tmp_path, data), "file.docx") == "password_protected"

    def test_attachment_types_detect_kind_truncated_zip_is_corrupted(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        data = _zip_bytes(tmp_path, _DOCX_NAMES)

        assert _detect(at, _write(tmp_path, data[: len(data) // 2]), "x.docx") == "corrupted_file"

    def test_attachment_types_detect_kind_garbage_after_zip_magic_is_corrupted(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        data = b"PK\x03\x04" + bytes(range(256)) * 4

        assert _detect(at, _write(tmp_path, data), "x.xlsx") == "corrupted_file"

    def test_attachment_types_detect_kind_zip_entries_are_never_decompressed(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        """A DOCX whose entry data fails its CRC is still a DOCX: only the directory is read."""
        data = _zip_bytes(tmp_path, _DOCX_NAMES, stored=True)
        original = b"<x>word/document.xml</x>"
        assert data.count(original) == 1
        tampered = data.replace(original, b"<x>word/TAMPERED.xml</x>")
        archive = tmp_path / "check.zip"
        archive.write_bytes(tampered)
        with zipfile.ZipFile(archive) as opened:
            assert opened.testzip() == "word/document.xml"

        assert _detect(at, _write(tmp_path, tampered), "letter.docx") == "docx"

    def test_attachment_types_detect_kind_cfb_with_encrypted_package_is_password_protected(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        """An encrypted .docx/.xlsx is an OLE file holding an EncryptedPackage stream."""
        data = _cfb("Root Entry", "EncryptionInfo", "EncryptedPackage")

        assert _detect(at, _write(tmp_path, data), "secret.docx") == "password_protected"

    def test_attachment_types_detect_kind_other_cfb_is_legacy_office(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        data = _cfb("Root Entry", "WordDocument", "1Table")

        assert _detect(at, _write(tmp_path, data), "letter.doc") == "legacy_office"


# ---------------------------------------------------------------------------
# 7. detect_kind: text
# ---------------------------------------------------------------------------


class TestDetectKindText:
    """Strict UTF-8 over the whole file, no control characters but TAB/LF/FF/CR."""

    @pytest.mark.parametrize(
        "code", [0x00, 0x08, 0x0B, 0x0E, 0x1F, 0x7F], ids=lambda code: f"u{code:04x}"
    )
    def test_attachment_types_detect_kind_text_with_a_control_character_is_unsupported(
        self, tmp_path: Path, at: ModuleType, code: int
    ) -> None:
        data = b"name,amount\nAlpha," + bytes([code]) + b"12\n"

        assert _detect(at, _write(tmp_path, data), "amounts.csv") == "unsupported_type"

    def test_attachment_types_detect_kind_text_allows_tab_lf_ff_and_cr(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        data = b"name\tamount\r\nAlpha\t12\r\n\x0cBeta\t7\n"

        assert _detect(at, _write(tmp_path, data), "amounts.csv") == "csv"

    @pytest.mark.parametrize(
        "data",
        [
            b"caf\xe9 au lait\n",
            b"slash \xc0\xaf overlong\n",
            b"surrogate \xed\xa0\x80 half\n",
            b"cut at the end \xf0\x9f\x9a",
        ],
        ids=["latin-1", "overlong", "encoded-surrogate", "truncated-at-eof"],
    )
    def test_attachment_types_detect_kind_invalid_utf8_is_unsupported(
        self, tmp_path: Path, at: ModuleType, data: bytes
    ) -> None:
        assert _detect(at, _write(tmp_path, data), "notes.txt") == "unsupported_type"

    def test_attachment_types_detect_kind_multibyte_character_across_a_read_chunk_is_text(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        """A 4-byte character split 2/2 by the 4 MiB offset still decodes."""
        rocket = _ROCKET.encode("utf-8")
        data = b"a" * (_BOUNDARY - 2) + rocket + b"\nend\n"
        assert data[_BOUNDARY - 2 : _BOUNDARY + 2] == rocket

        assert _detect(at, _write(tmp_path, data), "notes.md") == "md"

    def test_attachment_types_detect_kind_nul_after_the_first_4_mib_is_unsupported(
        self, tmp_path: Path, at: ModuleType
    ) -> None:
        """The whole file is checked, not a head sample: a text prefix can't carry a binary."""
        data = b"a" * (_BOUNDARY + 10) + b"\x00" + b"tail\n"

        assert _detect(at, _write(tmp_path, data), "notes.txt") == "unsupported_type"


# ---------------------------------------------------------------------------
# 8. Refusals never carry the name or the path
# ---------------------------------------------------------------------------


class TestDetectKindRefusal:
    """A detection refusal is the reason plus the fixed text, nothing of the upload."""

    @pytest.mark.parametrize(
        ("data", "reason"),
        [
            (_EXE, "unsupported_type"),
            (_PNG_SIGNATURE, "corrupted_file"),
            (_pdf(b"/Root 1 0 R /Encrypt 5 0 R"), "password_protected"),
            (_cfb("Root Entry", "WordDocument"), "legacy_office"),
        ],
        ids=["unsupported", "corrupted", "password-protected", "legacy-office"],
    )
    def test_attachment_types_detect_kind_refusal_never_echoes_the_name_or_path(
        self, tmp_path: Path, at: ModuleType, data: bytes, reason: str
    ) -> None:
        folder = tmp_path / _MARKER
        folder.mkdir()
        path = folder / (_MARKER + ".part")
        path.write_bytes(data)

        with pytest.raises(at.AttachmentRefusedError) as exc_info:
            at.detect_kind(path, _MARKER + ".pdf")

        error = exc_info.value
        assert error.reason == reason
        assert str(error) == _REFUSAL_DETAILS[reason]
        assert _MARKER not in repr(error)
        assert _MARKER not in repr(error.args)


# ---------------------------------------------------------------------------
# 9. download_name and content_disposition
# ---------------------------------------------------------------------------


_DOWNLOAD_NAMES: tuple[tuple[str, str, str, str], ...] = (
    ("html-stored-as-text", "page.html", "txt", "page.html.txt"),
    ("pdf-name-holding-a-png", "scan.pdf", "png", "scan.pdf.png"),
    ("upper-case-extension-kept", "report.PDF", "pdf", "report.PDF"),
    ("jpg-kept", "photo.jpg", "jpeg", "photo.jpg"),
    ("jpeg-upper-case-kept", "photo.JPEG", "jpeg", "photo.JPEG"),
    ("markdown-kept", "guide.markdown", "md", "guide.markdown"),
    ("md-kept", "readme.md", "md", "readme.md"),
    ("no-extension", "data", "csv", "data.csv"),
    ("doc-holding-a-docx", "letter.doc", "docx", "letter.doc.docx"),
    ("last-extension-decides", "holiday.jpg.exe", "jpeg", "holiday.jpg.exe.jpg"),
    ("may-exceed-255", "a" * 255, "txt", "a" * 255 + ".txt"),
)


class TestDownloadHeaders:
    """The download name gets the kind's extension; the header is RFC 5987 encoded."""

    @pytest.mark.parametrize(
        ("label", "filename", "kind", "expected"),
        _DOWNLOAD_NAMES,
        ids=[case[0] for case in _DOWNLOAD_NAMES],
    )
    def test_attachment_types_download_name_appends_the_kind_extension(
        self, at: ModuleType, label: str, filename: str, kind: str, expected: str
    ) -> None:
        assert at.download_name(filename, kind) == expected, label

    @pytest.mark.parametrize(
        ("name", "encoded"),
        [
            ("Q3-report_v2.pdf", "Q3-report_v2.pdf"),
            ('it\'s "a";b c.pdf', "it%27s%20%22a%22%3Bb%20c.pdf"),
            ("M" + _U_UMLAUT + "ller r" + _E_ACUTE + ".pdf", "M%C3%BCller%20r%C3%A9.pdf"),
            (_NIHON + _ROCKET + ".txt", "%E6%97%A5%E6%9C%AC%F0%9F%9A%80.txt"),
            ("a/b\\c.txt", "a%2Fb%5Cc.txt"),
            ("100%.txt", "100%25.txt"),
            ("x\r\nSet-Cookie: a=b.txt", "x%0D%0ASet-Cookie%3A%20a%3Db.txt"),
        ],
        ids=[
            "plain",
            "quotes-semicolon-space",
            "latin",
            "cjk-emoji",
            "separators",
            "percent",
            "crlf",
        ],
    )
    def test_attachment_types_content_disposition_is_exact_and_percent_encoded(
        self, at: ModuleType, name: str, encoded: str
    ) -> None:
        assert at.content_disposition(name) == "attachment; filename*=UTF-8''" + encoded


# ---------------------------------------------------------------------------
# 10. Purity
# ---------------------------------------------------------------------------


class TestPurity:
    """No DB, no LLM, no server, no tools, no async."""

    def test_attachment_types_imports_no_server_agent_llm_tools_or_database(
        self, at: ModuleType
    ) -> None:
        tree = ast.parse(inspect.getsource(at))
        imported = _imported_modules(tree)

        assert imported, "the module's imports were not read"
        assert [m for m in imported if m.startswith(_BANNED_IMPORT_PREFIXES)] == []

    def test_attachment_types_has_no_async_code(self, at: ModuleType) -> None:
        tree = ast.parse(inspect.getsource(at))
        async_nodes: list[Any] = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.AsyncFunctionDef | ast.Await | ast.AsyncFor | ast.AsyncWith)
        ]

        assert async_nodes == []
