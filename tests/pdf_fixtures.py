"""Programmatic PDF fixtures for the GH-188 PDF converter tests (no binary in the repo).

``build_pdf`` writes a small, well-formed PDF by hand (objects, xref table, trailer):
pages of any size in points with text lines in the standard Helvetica font
(WinAnsiEncoding, not embedded), an optional dark image XObject in the middle of
the page (a "scanned" page), an optional ``/Rotate``, and an optional
``/ToUnicode`` map so a test can make pdfium's text layer yield chosen code points
(control characters, C1, BOM, noncharacters). ``encrypt=`` writes a genuine
Standard security handler (revision 3, 128-bit RC4) with a user password: every
stream is encrypted, so pdfium opens the file only with that password.
``security_filter=`` writes an ``/Encrypt`` dictionary for a handler pdfium
doesn't support. ``missing_kids=`` adds page references to objects that don't
exist, so pdfium counts those pages but can't load them.

Stdlib only; the tests import pypdfium2 and Pillow themselves.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

A4 = (595.276, 841.89)
LETTER_LANDSCAPE = (792.0, 612.0)

_PAD = bytes.fromhex("28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A")
_FILE_ID = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
_PERMISSIONS = -4


@dataclass(frozen=True)
class Page:
    """One page: size in points, Helvetica text lines from the top, an optional image."""

    width: float = A4[0]
    height: float = A4[1]
    # str lines are WinAnsi (cp1252) text; bytes lines are raw one-byte character codes.
    lines: tuple[str | bytes, ...] = ()
    image: bool = False
    rotate: int = 0
    # Character code (one byte) -> code point, for a /ToUnicode map on the page font.
    to_unicode: dict[int, int] = field(default_factory=dict)


def text_page(*lines: str, width: float = A4[0], height: float = A4[1]) -> Page:
    """A page whose text layer is ``lines`` (one PDF text line each)."""
    return Page(width=width, height=height, lines=tuple(lines))


def scanned_page(*, width: float = A4[0], height: float = A4[1], rotate: int = 0) -> Page:
    """An image-only page: a black square image in the middle, no text layer."""
    return Page(width=width, height=height, image=True, rotate=rotate)


def blank_page(*, width: float = A4[0], height: float = A4[1]) -> Page:
    """A page without any content."""
    return Page(width=width, height=height)


def _rc4(key: bytes, data: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) % 256
        state[i], state[j] = state[j], state[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        out.append(byte ^ state[(state[i] + state[j]) % 256])
    return bytes(out)


def _rc4_rounds(key: bytes, data: bytes) -> bytes:
    """RC4 with ``key``, then 19 more times with each key byte XOR the round (R3)."""
    data = _rc4(key, data)
    for round_ in range(1, 20):
        data = _rc4(bytes(b ^ round_ for b in key), data)
    return data


def _padded(password: str) -> bytes:
    return (password.encode("latin-1") + _PAD)[:32]


def _standard_security(user: str, owner: str) -> tuple[bytes, bytes, bytes]:
    """(O, U, file key) of the Standard handler, revision 3, 128-bit (PDF 1.7 7.6.3)."""
    digest = hashlib.md5(_padded(owner), usedforsecurity=False).digest()
    for _ in range(50):
        digest = hashlib.md5(digest, usedforsecurity=False).digest()
    o_value = _rc4_rounds(digest[:16], _padded(user))
    key_hash = hashlib.md5(usedforsecurity=False)
    key_hash.update(_padded(user))
    key_hash.update(o_value)
    key_hash.update(struct.pack("<i", _PERMISSIONS))
    key_hash.update(_FILE_ID)
    digest = key_hash.digest()
    for _ in range(50):
        digest = hashlib.md5(digest[:16], usedforsecurity=False).digest()
    file_key = digest[:16]
    u_hash = hashlib.md5(_PAD + _FILE_ID, usedforsecurity=False).digest()
    u_value = _rc4_rounds(file_key, u_hash) + bytes(16)
    return o_value, u_value, file_key


def _object_key(file_key: bytes, number: int) -> bytes:
    material = file_key + struct.pack("<i", number)[:3] + b"\x00\x00"
    return hashlib.md5(material, usedforsecurity=False).digest()[:16]


def _pdf_string(text: str | bytes) -> bytes:
    raw = text if isinstance(text, bytes) else text.encode("cp1252")
    out = bytearray(b"(")
    for byte in raw:
        if byte in b"()\\" or byte < 0x20 or byte > 0x7E:
            out += b"\\%03o" % byte
        else:
            out.append(byte)
    return bytes(out + b")")


def _number(value: float) -> bytes:
    return (b"%.3f" % value).rstrip(b"0").rstrip(b".")


def _content(page: Page) -> bytes:
    parts: list[bytes] = []
    if page.image:
        side = min(page.width, page.height) / 2
        left = (page.width - side) / 2
        bottom = (page.height - side) / 2
        parts.append(
            b"q %s 0 0 %s %s %s cm /Im1 Do Q"
            % (_number(side), _number(side), _number(left), _number(bottom))
        )
    if page.lines:
        top = page.height - 72 if page.height > 100 else page.height - 14
        parts.append(b"BT /F1 12 Tf 14 TL %s %s Td" % (_number(36), _number(top)))
        for index, line in enumerate(page.lines):
            if index:
                parts.append(b"T*")
            parts.append(_pdf_string(line) + b" Tj")
        parts.append(b"ET")
    return b"\n".join(parts)


def _to_unicode_cmap(mapping: dict[int, int]) -> bytes:
    entries = b"\n".join(
        b"<%02X> <%04X>" % (code, point) for code, point in sorted(mapping.items())
    )
    return (
        b"/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n"
        b"/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n"
        b"/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n"
        b"1 begincodespacerange\n<00> <FF>\nendcodespacerange\n"
        b"%d beginbfchar\n%s\nendbfchar\n"
        b"endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend"
        % (len(mapping), entries)
    )


class _Writer:
    def __init__(self, file_key: bytes | None) -> None:
        self.objects: list[bytes] = []
        self.file_key = file_key

    def reserve(self) -> int:
        self.objects.append(b"")
        return len(self.objects)

    def set(self, number: int, body: bytes) -> None:
        self.objects[number - 1] = body

    def add(self, body: bytes) -> int:
        number = self.reserve()
        self.set(number, body)
        return number

    def add_stream(self, dictionary: bytes, data: bytes) -> int:
        number = self.reserve()
        if self.file_key is not None:
            data = _rc4(_object_key(self.file_key, number), data)
        self.set(
            number,
            b"<< %s /Length %d >>\nstream\n%s\nendstream" % (dictionary, len(data), data),
        )
        return number


def build_pdf(
    pages: list[Page],
    *,
    encrypt: tuple[str, str] | None = None,
    security_filter: str | None = None,
    missing_kids: int = 0,
) -> bytes:
    """The PDF file's bytes; ``encrypt`` = (user password, owner password).

    ``missing_kids`` appends that many page references to objects that don't exist
    (the page tree counts them), so loading those pages fails.
    """
    security = _standard_security(*encrypt) if encrypt is not None else None
    writer = _Writer(security[2] if security is not None else None)
    catalog = writer.reserve()
    pages_number = writer.reserve()
    font = writer.add(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
    )
    kids: list[int] = []
    for page in pages:
        resources = b"/Font << /F1 %d 0 R >>" % font
        if page.to_unicode:
            cmap = writer.add_stream(b"", _to_unicode_cmap(page.to_unicode))
            own_font = writer.add(
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                b"/Encoding /WinAnsiEncoding /ToUnicode %d 0 R >>" % cmap
            )
            resources = b"/Font << /F1 %d 0 R >>" % own_font
        if page.image:
            image = writer.add_stream(
                b"/Type /XObject /Subtype /Image /Width 2 /Height 2 "
                b"/ColorSpace /DeviceGray /BitsPerComponent 8",
                bytes(4),
            )
            resources += b" /XObject << /Im1 %d 0 R >>" % image
        content = writer.add_stream(b"", _content(page))
        rotate = b" /Rotate %d" % page.rotate if page.rotate else b""
        kids.append(
            writer.add(
                b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %s %s] "
                b"/Resources << %s >> /Contents %d 0 R%s >>"
                % (
                    pages_number,
                    _number(page.width),
                    _number(page.height),
                    resources,
                    content,
                    rotate,
                )
            )
        )
    writer.set(catalog, b"<< /Type /Catalog /Pages %d 0 R >>" % pages_number)
    kids += [len(writer.objects) + 1000 + index for index in range(missing_kids)]
    writer.set(
        pages_number,
        b"<< /Type /Pages /Kids [%s] /Count %d >>"
        % (b" ".join(b"%d 0 R" % kid for kid in kids), len(kids)),
    )
    trailer_extra = b""
    if security is not None:
        o_value, u_value, _ = security
        encrypt_dict = writer.add(
            b"<< /Filter /Standard /V 2 /R 3 /Length 128 /P %d /O <%s> /U <%s> >>"
            % (_PERMISSIONS, o_value.hex().encode(), u_value.hex().encode())
        )
        trailer_extra = b" /Encrypt %d 0 R" % encrypt_dict
    elif security_filter is not None:
        encrypt_dict = writer.add(
            b"<< /Filter /%s /V 4 /R 4 /Length 128 >>" % security_filter.encode()
        )
        trailer_extra = b" /Encrypt %d 0 R" % encrypt_dict
    file_id = _FILE_ID.hex().upper().encode()
    trailer_extra += b" /ID [<%s> <%s>]" % (file_id, file_id)
    return _serialize(writer.objects, catalog, trailer_extra)


def _serialize(objects: list[bytes], root: int, trailer_extra: bytes) -> bytes:
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (number, body)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root %d 0 R%s >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        root,
        trailer_extra,
        xref,
    )
    return bytes(out)
