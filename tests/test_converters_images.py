"""Tests for the image converter (GH-188 contract section 4.5).

Uploaded PNG, JPEG and WEBP files (issue: "Images (Pillow): orientation
corrected, converted to a supported format, downscaled to a fixed
longest-edge maximum of 2048 px, metadata stripped"; "Pillow pixel limit";
Decision 8). Fixtures are built with Pillow in memory; each test converts
through ``dispatch.convert(path, kind, out_dir, options)`` (the contract
gives ``convert_image`` no kind parameter, the dispatcher has it) and reads
the stored part back. What these tests pin down:

- One image part per file: ``part-0001.jpg`` (``image/jpeg``) from JPEG,
  ``part-0001.png`` (``image/png``) from PNG and WEBP; page and label None;
  width/height are the stored file's; tokens == ``estimate_image_tokens(w,
  h)``; the manifest's page count is None (the converter returns None).
- EXIF orientation 3, 6 and 8 applied (JPEG, and the PNG/WEBP EXIF chunk):
  dimensions swap for 6/8 and the quadrant colours land where the rotation
  puts them.
- Orientations 5 to 8 (GH-286 Decision 7): the output size is fitted on the
  oriented size (width and height swapped), the size ``Image.thumbnail`` gives
  the turned image. A PNG stored 21847x400 becomes 37x2048 for each of them
  (fitting the stored size, then turning, gives 38x2048), with the quadrants
  where ``ImageOps.exif_transpose`` puts them.
- Longest edge > 2048 -> downscaled to fit 2048 x 2048, aspect kept within
  1 px (4000x1000 -> 2048x512, portrait, 2049x1537); exactly 2048 and small
  images untouched (never upscaled).
- Modes: RGBA (alpha values kept) when the PNG/WEBP has an alpha channel or
  transparency (RGBA, LA, palette with a transparent index, RGB with tRNS);
  RGB otherwise (L, I;16, palette, CMYK JPEG, grayscale JPEG).
- Animated PNG/WEBP -> the first frame, as a single-frame PNG. A JPEG with a
  multi-picture (MPF) segment, as phone cameras write, is a JPEG: its first
  picture converts (resolved gap: Pillow reports such files as ``MPO``).
- Metadata stripped: EXIF (with GPS), ICC profile, XMP, JPEG comment,
  Photoshop APP13, PNG tEXt/zTXt/iTXt: the stored file has none of the info
  keys, an empty ``getexif()``, no metadata segment/chunk and none of the
  marker strings.
- The detected format must be the recorded kind (PNG recorded as jpeg, JPEG
  as png, WEBP as png, GIF as png, PNG as webp) -> ``corrupted_file``;
  truncated or garbage images -> ``corrupted_file``; nothing written. A PNG
  whose IDAT holds a corrupt (not truncated) zlib stream with valid CRCs is
  ``corrupted_file`` too (GH-286 Decision 7): Pillow raises on its first pixel
  load only, so only the load before the EXIF guard refuses it.
- Pixel limit: a header declaring more than ``MAX_IMAGE_PIXELS`` ->
  ``image_too_large`` without decoding: 8000 x 8500 (over 64 M, under the
  ~89 M where Pillow starts to warn, so only our check sees it), 10000 x
  10000 (Pillow warns) and 30000 x 30000 (Pillow raises its own
  ``DecompressionBombError``); boundary with a monkeypatched limit read at
  call time.
- JPEG output is re-encoded at ``JPEG_QUALITY`` (its quantization tables are
  quality 85's), never the uploaded bytes copied.
- Malformed EXIF (GH-281 Decision 2, contract I1): a JPEG whose hand-built EXIF
  block carries a readable orientation 6 plus one tag Pillow can't write back
  (Make as RATIONAL -> AttributeError, InteropIFD as BYTE -> struct.error, XMP
  as ASCII -> TypeError, each raised by ``ImageOps.exif_transpose``) converts
  as stored: no orientation correction (stored size, quadrants in place), no
  metadata in the output (info keys, APP1/APP2/APP13/COM segments, the EXIF
  marker string), RGB at ``JPEG_QUALITY``. The same
  block in a truncated JPEG is still ``corrupted_file``, and over the pixel
  limit still ``image_too_large``.
- Draft mode (GH-281 Decision 3, contract I3), observed through a spy wrapping
  ``JpegImageFile.draft`` (requested size, whether it took effect, i.e. ran
  before any pixel was loaded, and the size after): a JPEG larger than its
  target (the stored size fitted into 2048 x 2048 as ``Image.thumbnail``
  computes it) is drafted once with exactly that target (8192x4096 -> 2048x1024
  decoded at 1/4; 4100x4100 -> 2050x2050 at 1/2; 2049x4110 -> 1025x2055 at
  1/2). The output equals the non-draft path's (draft replaced by a no-op
  returning None) in size and content: 2049x4110 -> 1021x2048 (a naive
  thumbnail of the drafted image gives 1022x2048), 4100x2051 -> 2048x1024 (naive
  2048x1025) and the same with orientation 6 -> 1024x2048, rotated. A JPEG
  within 2048 x 2048 is not reduced; PNG and WEBP sources are never drafted.

The converter modules are imported inside the helpers, so this file collects
before they exist.
"""

from __future__ import annotations

import io
import struct
import zlib
from typing import TYPE_CHECKING, Any

import pytest
from PIL import ExifTags, Image, ImageCms, ImageFile, ImageOps, JpegImagePlugin, PngImagePlugin

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_FORMAT = {"jpeg": "JPEG", "png": "PNG", "webp": "WEBP"}
_RED = (220, 20, 20)
_GREEN = (20, 200, 20)
_BLUE = (20, 20, 220)
_YELLOW = (230, 230, 20)
_COLOURS = {"red": _RED, "green": _GREEN, "blue": _BLUE, "yellow": _YELLOW}
_ORIENTATION = 0x0112
_IMAGE_DESCRIPTION = 0x010E
_MARKERS = (
    "EXIF-MARK-188",
    "COMMENT-MARK-188",
    "XMP-MARK-188",
    "PS-MARK-188",
    "TEXT-MARK-188",
    "ITXT-MARK-188",
)
_METADATA_INFO_KEYS = frozenset(
    {"exif", "icc_profile", "xmp", "XML:com.adobe.xmp", "comment", "photoshop"}
)
_METADATA_PNG_CHUNKS = frozenset({b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"iCCP"})
# APP1 (EXIF/XMP), APP2 (ICC), APP13 (Photoshop), COM.
_METADATA_JPEG_MARKERS = frozenset({0xE1, 0xE2, 0xED, 0xFE})


class _DecodedError(BaseException):
    """Raised when pixel data is decoded where it may not be (not an Exception,
    so the converter's error mapping can't swallow it)."""


@pytest.fixture(autouse=True)
def _restore_pillow_globals(monkeypatch: pytest.MonkeyPatch) -> None:
    """Whatever the converter does to Pillow's process-wide limits stays in the test."""
    monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", Image.MAX_IMAGE_PIXELS)
    monkeypatch.setattr(ImageFile, "LOAD_TRUNCATED_IMAGES", ImageFile.LOAD_TRUNCATED_IMAGES)


# --- fixture builders -----------------------------------------------------------------


def _encode(image: Image.Image, fmt: str, **params: Any) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, fmt, **params)
    return buffer.getvalue()


def _quadrants(width: int = 64, height: int = 32) -> Image.Image:
    """Top-left red, top-right green, bottom-left blue, bottom-right yellow."""
    image = Image.new("RGB", (width, height))
    half_w, half_h = width // 2, height // 2
    image.paste(_RED, (0, 0, half_w, half_h))
    image.paste(_GREEN, (half_w, 0, width, half_h))
    image.paste(_BLUE, (0, half_h, half_w, height))
    image.paste(_YELLOW, (half_w, half_h, width, height))
    return image


def _nearest(pixel: tuple[int, ...]) -> str:
    return min(
        _COLOURS,
        key=lambda name: sum((a - b) ** 2 for a, b in zip(pixel[:3], _COLOURS[name], strict=True)),
    )


def _quadrant_colours(image: Image.Image) -> tuple[str, str, str, str]:
    rgb = image.convert("RGB")
    w, h = rgb.size
    points = (
        (w // 4, h // 4),
        (3 * w // 4, h // 4),
        (w // 4, 3 * h // 4),
        (3 * w // 4, 3 * h // 4),
    )
    tl, tr, bl, br = (_nearest(rgb.getpixel(point)) for point in points)
    return tl, tr, bl, br


def _png_chunk(kind: bytes, body: bytes) -> bytes:
    """One PNG chunk: length, type, body and a valid CRC over type and body."""
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def _png_header_only(width: int, height: int) -> bytes:
    """A PNG declaring ``width`` x ``height`` with no pixel data to decode."""
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", header)
        + _png_chunk(b"IDAT", zlib.compress(b""))
        + _png_chunk(b"IEND", b"")
    )


def _png_with_corrupt_idat(garbage: bytes) -> bytes:
    """A 64 x 64 RGB PNG whose IDAT holds a whole zlib stream with ``garbage``
    written over it after its first eight bytes: a data error, not a truncation
    (the stream keeps its length), and every chunk CRC is valid (PR #285 review)."""
    header = struct.pack(">IIBBBBB", 64, 64, 8, 2, 0, 0, 0)
    good = zlib.compress(b"".join(b"\0" + bytes(range(192)) for _ in range(64)))
    idat = good[:8] + garbage + good[8 + len(garbage) :]
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", header)
        + _png_chunk(b"IDAT", idat)
        + _png_chunk(b"IEND", b"")
    )


def _photoshop_segment(text: str) -> bytes:
    """An APP13 'Photoshop 3.0' segment with one 8BIM caption resource."""
    data = text.encode()
    if len(data) % 2:
        data += b"\0"
    resource = b"8BIM" + struct.pack(">H", 0x0404) + b"\0\0" + struct.pack(">I", len(data)) + data
    body = b"Photoshop 3.0\0" + resource
    return b"\xff\xed" + struct.pack(">H", len(body) + 2) + body


def _exif_with_gps() -> Image.Exif:
    exif = Image.Exif()
    exif[_IMAGE_DESCRIPTION] = "EXIF-MARK-188"
    exif[0x010F] = "PhoneMaker"
    gps = exif.get_ifd(ExifTags.IFD.GPSInfo)
    gps[1] = "N"
    gps[2] = (47.0, 22.0, 30.0)
    gps[3] = "E"
    gps[4] = (8.0, 32.0, 10.0)
    return exif


def _srgb_profile() -> bytes:
    return ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()


def _jpeg_with_metadata() -> bytes:
    data = _encode(
        _quadrants(),
        "JPEG",
        exif=_exif_with_gps(),
        icc_profile=_srgb_profile(),
        comment=b"COMMENT-MARK-188",
        xmp=b"<x:xmpmeta xmlns:x='adobe:ns:meta/'>XMP-MARK-188</x:xmpmeta>",
    )
    return data[:2] + _photoshop_segment("PS-MARK-188") + data[2:]


def _png_with_metadata() -> bytes:
    info = PngImagePlugin.PngInfo()
    info.add_text("Author", "TEXT-MARK-188")
    info.add_text("Location", "ZTXT-MARK-188 " * 20, zip=True)
    info.add_itxt("Comment", "ITXT-MARK-188", lang="de", tkey="Kommentar")
    info.add_itxt("XML:com.adobe.xmp", "<x:xmpmeta>XMP-MARK-188</x:xmpmeta>")
    return _encode(
        _quadrants(), "PNG", pnginfo=info, exif=_exif_with_gps(), icc_profile=_srgb_profile()
    )


def _webp_with_metadata() -> bytes:
    return _encode(
        _quadrants(),
        "WEBP",
        lossless=True,
        exif=_exif_with_gps(),
        icc_profile=_srgb_profile(),
        xmp=b"<x:xmpmeta>XMP-MARK-188</x:xmpmeta>",
    )


# --- conversion helpers ---------------------------------------------------------------


def _convert(tmp_path: Path, data: bytes, kind: str) -> tuple[Any, Path]:
    """Store ``data``, convert it as ``kind``; returns (manifest, out_dir)."""
    from admino.converters import common, dispatch

    source = tmp_path / "0b7f1c52-stored"
    source.write_bytes(data)
    out_dir = tmp_path / "0b7f1c52-stored.d"
    out_dir.mkdir()
    options = common.ConversionOptions(
        filename=f"Ferien Foto.{kind}", render_dpi=150, max_pages=100
    )
    return dispatch.convert(source, kind, out_dir, options), out_dir


def _single_image(tmp_path: Path, data: bytes, kind: str) -> tuple[Any, Image.Image, bytes]:
    """(the one image part, the stored image loaded, the stored bytes)."""
    manifest, out_dir = _convert(tmp_path, data, kind)
    assert (manifest.page_count, len(manifest.parts)) == (None, 1)
    part = manifest.parts[0]
    stored_bytes = (out_dir / part.file).read_bytes()
    stored = Image.open(io.BytesIO(stored_bytes))
    stored.load()
    return part, stored, stored_bytes


def _refusal(tmp_path: Path, data: bytes, kind: str) -> tuple[str, list[str]]:
    """(reason, files left in out_dir) for a refused image."""
    from admino.converters.common import ConversionError

    with pytest.raises(ConversionError) as caught:
        _convert(tmp_path, data, kind)
    return caught.value.reason, sorted(
        entry.name for entry in (tmp_path / "0b7f1c52-stored.d").iterdir()
    )


# --- output format and part fields ----------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "media_type", "file", "stored_format"),
    [
        ("jpeg", "image/jpeg", "part-0001.jpg", "JPEG"),
        ("png", "image/png", "part-0001.png", "PNG"),
        ("webp", "image/png", "part-0001.png", "PNG"),
    ],
)
def test_images_each_kind_becomes_one_image_part(
    tmp_path: Path, kind: str, media_type: str, file: str, stored_format: str
) -> None:
    from admino.converters.common import ImagePart
    from admino.tokens import estimate_image_tokens

    manifest, out_dir = _convert(tmp_path, _encode(_quadrants(64, 32), _FORMAT[kind]), kind)

    tokens = estimate_image_tokens(64, 32)
    expected_part = ImagePart(
        type="image",
        file=file,
        page=None,
        label=None,
        media_type=media_type,
        width=64,
        height=32,
        tokens=tokens,
    )
    stored = Image.open(out_dir / file)
    assert (
        manifest.page_count,
        manifest.parts,
        manifest.token_estimate,
        stored.format,
        stored.size,
    ) == (
        None,
        [expected_part],
        tokens,
        stored_format,
        (64, 32),
    )


# --- orientation ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "orientation", "size", "colours"),
    [
        ("jpeg", 3, (64, 32), ("yellow", "blue", "green", "red")),
        ("jpeg", 6, (32, 64), ("blue", "red", "yellow", "green")),
        ("jpeg", 8, (32, 64), ("green", "yellow", "red", "blue")),
        ("png", 6, (32, 64), ("blue", "red", "yellow", "green")),
        ("webp", 8, (32, 64), ("green", "yellow", "red", "blue")),
    ],
)
def test_images_exif_orientation_applied(
    tmp_path: Path, kind: str, orientation: int, size: tuple[int, int], colours: tuple[str, ...]
) -> None:
    exif = Image.Exif()
    exif[_ORIENTATION] = orientation
    params: dict[str, Any] = {"exif": exif}
    if kind == "webp":
        params["lossless"] = True
    data = _encode(_quadrants(64, 32), _FORMAT[kind], **params)

    part, stored, _ = _single_image(tmp_path, data, kind)

    assert ((part.width, part.height), stored.size, _quadrant_colours(stored)) == (
        size,
        size,
        colours,
    )


@pytest.mark.parametrize(
    ("orientation", "colours"),
    [
        (5, ("red", "blue", "green", "yellow")),
        (6, ("blue", "red", "yellow", "green")),
        (7, ("yellow", "green", "blue", "red")),
        (8, ("green", "yellow", "red", "blue")),
    ],
    ids=["orientation-5", "orientation-6", "orientation-7", "orientation-8"],
)
def test_images_orientations_5_to_8_fit_the_oriented_size(
    tmp_path: Path, orientation: int, colours: tuple[str, ...]
) -> None:
    # Stored 21847x400 (PR #285 review): the turned image (400x21847) thumbnails
    # to 37x2048, the stored one to 2048x38, i.e. 38x2048 once turned. Pillow
    # rounds the shorter side to the ratio closest to width/height, which isn't
    # symmetric in the two sides. A PNG (EXIF chunk before its pixels) is never
    # drafted, so only the orientation explains the size.
    exif = Image.Exif()
    exif[_ORIENTATION] = orientation
    data = _encode(_quadrants(21847, 400), "PNG", exif=exif)
    turned = ImageOps.exif_transpose(Image.open(io.BytesIO(data)))
    turned.thumbnail((2048, 2048))
    fitted_first = Image.open(io.BytesIO(data))
    fitted_first.thumbnail((2048, 2048))
    # The fixture: Pillow's own sizes, and the size discriminates.
    assert (turned.size, ImageOps.exif_transpose(fitted_first).size) == ((37, 2048), (38, 2048))

    part, stored, _ = _single_image(tmp_path, data, "png")

    assert (
        (part.width, part.height),
        stored.size,
        _quadrant_colours(stored),
        _quadrant_colours(turned),
    ) == (turned.size, turned.size, colours, colours)


# --- malformed EXIF (GH-281 Decision 2) -----------------------------------------------

_BYTE, _ASCII, _SHORT, _RATIONAL = 1, 2, 3, 5
_MAKE = 0x010F
_XMP = 0x02BC
_INTEROP_IFD = 0xA005
_ExifEntry = tuple[int, int, int, bytes]
# One tag Pillow reads but can't write back (what ImageOps.exif_transpose raises).
_MALFORMED_EXIF: dict[str, tuple[_ExifEntry, type[Exception]]] = {
    "make-as-rational": ((_MAKE, _RATIONAL, 1, struct.pack("<II", 1, 1)), AttributeError),
    "interop-ifd-as-byte": ((_INTEROP_IFD, _BYTE, 1, b"\x07"), struct.error),
    "xmp-as-ascii": ((_XMP, _ASCII, 1, b"\0"), TypeError),
}


def _exif_block(entries: list[_ExifEntry]) -> bytes:
    """A hand-built EXIF block (``Exif\\0\\0`` + a little-endian TIFF with one IFD) of
    ``(tag, type, count, value bytes)`` entries; values over 4 bytes follow the IFD."""
    entries = sorted(entries)
    data_offset = 8 + 2 + 12 * len(entries) + 4
    ifd = struct.pack("<H", len(entries))
    data = b""
    for tag, kind, count, value in entries:
        if len(value) <= 4:
            field = value.ljust(4, b"\0")
        else:
            field = struct.pack("<I", data_offset + len(data))
            data += value + b"\0" * (len(value) % 2)
        ifd += struct.pack("<HHI", tag, kind, count) + field
    ifd += struct.pack("<I", 0)
    return b"Exif\0\0II*\0" + struct.pack("<I", 8) + ifd + data


def _malformed_exif(case: str) -> bytes:
    """Orientation 6 (readable), the marker as ImageDescription and the case's bad tag."""
    description = b"EXIF-MARK-188\0"
    return _exif_block(
        [
            (_IMAGE_DESCRIPTION, _ASCII, len(description), description),
            (_ORIENTATION, _SHORT, 1, struct.pack("<H", 6)),
            _MALFORMED_EXIF[case][0],
        ]
    )


def _jpeg_with_malformed_exif(case: str, image: Image.Image) -> bytes:
    data = _encode(image, "JPEG", exif=_malformed_exif(case))
    # The fixture: Pillow reads orientation 6, but can't write the EXIF back without it.
    source = Image.open(io.BytesIO(data))
    assert source.getexif()[_ORIENTATION] == 6
    with pytest.raises(_MALFORMED_EXIF[case][1]):
        ImageOps.exif_transpose(source)
    return data


@pytest.mark.parametrize("case", list(_MALFORMED_EXIF))
def test_images_malformed_exif_converts_as_stored_with_metadata_stripped(
    tmp_path: Path, case: str
) -> None:
    from admino.converters import common

    data = _jpeg_with_malformed_exif(case, _quadrants(64, 32))
    reference = Image.open(io.BytesIO(_encode(_quadrants(), "JPEG", quality=common.JPEG_QUALITY)))

    part, stored, stored_bytes = _single_image(tmp_path, data, "jpeg")

    # Not rotated: the orientation of a malformed EXIF block isn't trusted.
    assert (
        (part.width, part.height),
        stored.size,
        _quadrant_colours(stored),
        (stored.format, stored.mode, stored.quantization),
        _metadata_left(stored, stored_bytes),
    ) == (
        (64, 32),
        (64, 32),
        ("red", "green", "blue", "yellow"),
        ("JPEG", "RGB", reference.quantization),
        {"info": [], "exif": [], "containers": [], "markers": []},
    )


@pytest.mark.parametrize("case", list(_MALFORMED_EXIF))
def test_images_malformed_exif_keeps_decode_errors_and_the_pixel_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    from admino.converters import common
    from admino.converters.common import ConversionError

    data = _jpeg_with_malformed_exif(case, Image.effect_noise((64, 64), 60).convert("RGB"))

    def outcome(name: str, upload: bytes) -> str:
        directory = tmp_path / name
        directory.mkdir()
        try:
            _convert(directory, upload, "jpeg")
        except ConversionError as exc:
            return exc.reason
        return "converted"

    outcomes = {
        "intact": outcome("intact", data),
        "truncated": outcome("truncated", data[: len(data) // 2]),
    }
    monkeypatch.setattr(common, "MAX_IMAGE_PIXELS", 64 * 64 - 1)
    outcomes["over-the-pixel-limit"] = outcome("over-the-pixel-limit", data)

    assert outcomes == {
        "intact": "converted",
        "truncated": "corrupted_file",
        "over-the-pixel-limit": "image_too_large",
    }


# --- downscaling ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "size", "expected", "tolerance"),
    [
        ("jpeg", (4000, 1000), (2048, 512), 1),
        ("png", (1000, 4000), (512, 2048), 1),
        ("jpeg", (2049, 1537), (2048, 1536), 1),
        ("webp", (2048, 1000), (2048, 1000), 0),
        ("png", (100, 50), (100, 50), 0),
    ],
    ids=["landscape", "portrait", "just-over", "exactly-2048-untouched", "small-not-upscaled"],
)
def test_images_longest_edge_fits_2048_never_upscaled(
    tmp_path: Path, kind: str, size: tuple[int, int], expected: tuple[int, int], tolerance: int
) -> None:
    from admino.tokens import estimate_image_tokens

    data = _encode(Image.new("RGB", size, (90, 120, 150)), _FORMAT[kind])

    part, stored, _ = _single_image(tmp_path, data, kind)

    assert (
        abs(part.width - expected[0]) <= tolerance,
        abs(part.height - expected[1]) <= tolerance,
        max(part.width, part.height) <= 2048,
        stored.size,
        part.tokens,
    ) == (
        True,
        True,
        True,
        (part.width, part.height),
        estimate_image_tokens(part.width, part.height),
    )


# --- JPEG draft mode (GH-281 Decision 3) ----------------------------------------------

_DraftCall = tuple[tuple[int, int] | None, bool, tuple[int, int]]


def _spy_jpeg_draft(monkeypatch: pytest.MonkeyPatch, *, effective: bool = True) -> list[_DraftCall]:
    """Record every ``JpegImageFile.draft`` call: (requested size, whether it took
    effect, the image's size after it). Pillow's draft returns None, changing nothing,
    once the pixels are loaded (or on a second call), so "took effect" means it ran
    before the load. ``effective=False`` makes draft a no-op returning None: the
    non-draft path."""
    real = JpegImagePlugin.JpegImageFile.draft
    calls: list[_DraftCall] = []

    def draft(
        self: JpegImagePlugin.JpegImageFile, mode: str | None, size: tuple[int, int] | None
    ) -> Any:
        result = real(self, mode, size) if effective else None
        requested = None if size is None else (int(size[0]), int(size[1]))
        calls.append((requested, result is not None, self.size))
        return result

    monkeypatch.setattr(JpegImagePlugin.JpegImageFile, "draft", draft)
    return calls


def _spy_file_draft(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record the class of every opened image file (not a JPEG, which has its own
    draft) whose ``draft`` is called; a plain in-memory image is not recorded."""
    real = Image.Image.draft
    files: list[str] = []

    def draft(self: Image.Image, mode: str | None, size: tuple[int, int] | None) -> Any:
        if isinstance(self, ImageFile.ImageFile):
            files.append(type(self).__name__)
        return real(self, mode, size)

    monkeypatch.setattr(Image.Image, "draft", draft)
    return files


@pytest.mark.parametrize(
    ("size", "target", "decoded"),
    [
        ((8192, 4096), (2048, 1024), (2048, 1024)),
        ((4100, 4100), (2048, 2048), (2050, 2050)),
        ((2049, 4110), (1021, 2048), (1025, 2055)),
    ],
    ids=["quarter-scale", "half-scale-square", "half-scale-portrait"],
)
def test_images_large_jpeg_is_drafted_once_to_the_target_before_loading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    size: tuple[int, int],
    target: tuple[int, int],
    decoded: tuple[int, int],
) -> None:
    data = _encode(Image.new("RGB", size, (90, 120, 150)), "JPEG")
    calls = _spy_jpeg_draft(monkeypatch)

    part, stored, _ = _single_image(tmp_path, data, "jpeg")

    assert (calls, (part.width, part.height), stored.size) == (
        [(target, True, decoded)],
        target,
        target,
    )


@pytest.mark.parametrize(
    ("size", "orientation", "expected", "colours"),
    [
        ((2049, 4110), None, (1021, 2048), ("red", "green", "blue", "yellow")),
        ((4100, 2051), None, (2048, 1024), ("red", "green", "blue", "yellow")),
        ((4100, 2051), 6, (1024, 2048), ("blue", "red", "yellow", "green")),
    ],
    ids=["portrait", "landscape", "orientation-6"],
)
def test_images_drafted_jpeg_matches_the_non_draft_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    size: tuple[int, int],
    orientation: int | None,
    expected: tuple[int, int],
    colours: tuple[str, ...],
) -> None:
    # A naive thumbnail of the drafted image is one pixel off for these sizes
    # (2049x4110 drafted to 1025x2055 gives 1022x2048; 4100x2051 drafted to
    # 2050x1026 gives 2048x1025): the output must be the non-draft path's.
    params: dict[str, Any] = {}
    if orientation is not None:
        exif = Image.Exif()
        exif[_ORIENTATION] = orientation
        params["exif"] = exif
    data = _encode(_quadrants(*size), "JPEG", **params)
    observed = {}
    for name, effective in (("draft", True), ("non-draft", False)):
        directory = tmp_path / name
        directory.mkdir()
        calls = _spy_jpeg_draft(monkeypatch, effective=effective)
        part, stored, _ = _single_image(directory, data, "jpeg")
        observed[name] = (
            [took_effect for _, took_effect, _ in calls] if effective else "no-op",
            (part.width, part.height),
            stored.size,
            _quadrant_colours(stored),
        )

    assert observed == {
        "draft": ([True], expected, expected, colours),
        "non-draft": ("no-op", expected, expected, colours),
    }


def test_images_only_a_jpeg_larger_than_its_target_is_drafted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    jpeg_calls = _spy_jpeg_draft(monkeypatch)
    other_files = _spy_file_draft(monkeypatch)
    cases = {
        "jpeg-over": ("jpeg", (4100, 1000)),
        "jpeg-at-2048": ("jpeg", (2048, 1000)),
        "jpeg-small": ("jpeg", (64, 32)),
        "png-over": ("png", (4100, 1000)),
        "webp-over": ("webp", (4100, 1000)),
    }
    observed = {}
    for name, (kind, size) in cases.items():
        directory = tmp_path / name
        directory.mkdir()
        seen_jpeg, seen_other = len(jpeg_calls), len(other_files)
        data = _encode(Image.new("RGB", size, (90, 120, 150)), _FORMAT[kind])
        part, _, _ = _single_image(directory, data, kind)
        observed[name] = (
            any(after != size for _, _, after in jpeg_calls[seen_jpeg:]),  # decoded smaller
            other_files[seen_other:],
            (part.width, part.height),
        )

    assert observed == {
        "jpeg-over": (True, [], (2048, 500)),
        "jpeg-at-2048": (False, [], (2048, 1000)),
        "jpeg-small": (False, [], (64, 32)),
        "png-over": (False, [], (2048, 500)),
        "webp-over": (False, [], (2048, 500)),
    }


# --- modes ----------------------------------------------------------------------------


def _palette(transparent: bool) -> bytes:
    image = Image.new("P", (8, 8), 0 if transparent else 1)
    image.putpalette([255, 0, 0, 0, 255, 0])
    return _encode(image, "PNG", **({"transparency": 0} if transparent else {}))


_MODE_CASES: dict[str, tuple[str, Callable[[], bytes], str, str, tuple[int, ...] | None]] = {
    "png-rgba": (
        "png",
        lambda: _encode(Image.new("RGBA", (8, 8), (10, 20, 30, 128)), "PNG"),
        "PNG",
        "RGBA",
        (10, 20, 30, 128),
    ),
    "webp-rgba": (
        "webp",
        lambda: _encode(
            Image.new("RGBA", (8, 8), (10, 20, 30, 128)), "WEBP", lossless=True, exact=True
        ),
        "PNG",
        "RGBA",
        (10, 20, 30, 128),
    ),
    "png-palette-transparent": (
        "png",
        lambda: _palette(transparent=True),
        "PNG",
        "RGBA",
        (255, 0, 0, 0),
    ),
    "png-la": (
        "png",
        lambda: _encode(Image.new("LA", (8, 8), (100, 50)), "PNG"),
        "PNG",
        "RGBA",
        (100, 100, 100, 50),
    ),
    "png-rgb-trns": (
        "png",
        lambda: _encode(Image.new("RGB", (8, 8), (1, 2, 3)), "PNG", transparency=(1, 2, 3)),
        "PNG",
        "RGBA",
        (1, 2, 3, 0),
    ),
    "png-rgb": (
        "png",
        lambda: _encode(Image.new("RGB", (8, 8), (10, 20, 30)), "PNG"),
        "PNG",
        "RGB",
        (10, 20, 30),
    ),
    "webp-rgb": (
        "webp",
        lambda: _encode(Image.new("RGB", (8, 8), (10, 20, 30)), "WEBP", lossless=True),
        "PNG",
        "RGB",
        (10, 20, 30),
    ),
    "png-l": (
        "png",
        lambda: _encode(Image.new("L", (8, 8), 77), "PNG"),
        "PNG",
        "RGB",
        (77, 77, 77),
    ),
    "png-i16": (
        "png",
        lambda: _encode(Image.new("I;16", (8, 8), 40000), "PNG"),
        "PNG",
        "RGB",
        None,
    ),
    "png-palette": ("png", lambda: _palette(transparent=False), "PNG", "RGB", (0, 255, 0)),
    "jpeg-cmyk": (
        "jpeg",
        lambda: _encode(Image.new("CMYK", (8, 8), (0, 255, 255, 0)), "JPEG"),
        "JPEG",
        "RGB",
        None,
    ),
    "jpeg-grey": ("jpeg", lambda: _encode(Image.new("L", (8, 8), 77), "JPEG"), "JPEG", "RGB", None),
}


@pytest.mark.parametrize("case", list(_MODE_CASES))
def test_images_mode_rgba_only_when_transparent_else_rgb(tmp_path: Path, case: str) -> None:
    kind, build, stored_format, mode, pixel = _MODE_CASES[case]

    _, stored, _ = _single_image(tmp_path, build(), kind)

    observed_pixel = stored.getpixel((3, 3)) if pixel is not None else None
    assert (stored.format, stored.mode, observed_pixel) == (stored_format, mode, pixel)


# --- animation and multi-picture JPEG -------------------------------------------------


@pytest.mark.parametrize("kind", ["png", "webp"])
def test_images_animated_file_keeps_first_frame_only(tmp_path: Path, kind: str) -> None:
    first = Image.new("RGB", (16, 8), (255, 0, 0))
    second = Image.new("RGB", (16, 8), (0, 0, 255))
    params: dict[str, Any] = {
        "save_all": True,
        "append_images": [second],
        "duration": 100,
        "loop": 0,
    }
    if kind == "webp":
        params["lossless"] = True
    data = _encode(first, _FORMAT[kind], **params)
    assert getattr(Image.open(io.BytesIO(data)), "n_frames", 1) == 2  # the fixture is animated

    _, stored, _ = _single_image(tmp_path, data, kind)

    assert (
        stored.format,
        getattr(stored, "n_frames", 1),
        stored.convert("RGB").getpixel((4, 4)),
    ) == (
        "PNG",
        1,
        (255, 0, 0),
    )


def test_images_multi_picture_jpeg_converts_its_first_picture(tmp_path: Path) -> None:
    data = _encode(
        _quadrants(), "MPO", save_all=True, append_images=[Image.new("RGB", (64, 32), _BLUE)]
    )
    assert (
        Image.open(io.BytesIO(data)).format == "MPO"
    )  # what Pillow calls a JPEG with an MPF segment

    part, stored, _ = _single_image(tmp_path, data, "jpeg")

    assert (
        part.media_type,
        stored.format,
        getattr(stored, "n_frames", 1),
        _quadrant_colours(stored),
    ) == (
        "image/jpeg",
        "JPEG",
        1,
        ("red", "green", "blue", "yellow"),
    )


# --- metadata -------------------------------------------------------------------------


def _png_chunk_types(data: bytes) -> list[bytes]:
    kinds, offset = [], 8
    while offset + 8 <= len(data):
        (length,) = struct.unpack(">I", data[offset : offset + 4])
        kinds.append(data[offset + 4 : offset + 8])
        offset += 12 + length
    return kinds


def _jpeg_segment_markers(data: bytes) -> list[int]:
    markers, offset = [], 2
    while offset + 4 <= len(data) and data[offset] == 0xFF:
        marker = data[offset + 1]
        if marker == 0xDA:  # start of scan: no metadata segment after it
            break
        markers.append(marker)
        (length,) = struct.unpack(">H", data[offset + 2 : offset + 4])
        offset += 2 + length
    return markers


def _metadata_left(stored: Image.Image, stored_bytes: bytes) -> dict[str, list[Any]]:
    if stored.format == "PNG":
        containers = [
            kind.decode() for kind in _png_chunk_types(stored_bytes) if kind in _METADATA_PNG_CHUNKS
        ]
    else:
        containers = [
            f"{m:#04x}" for m in _jpeg_segment_markers(stored_bytes) if m in _METADATA_JPEG_MARKERS
        ]
    return {
        "info": sorted(_METADATA_INFO_KEYS & set(stored.info)),
        "exif": sorted(stored.getexif().items()),
        "containers": containers,
        "markers": [marker for marker in _MARKERS if marker.encode() in stored_bytes],
    }


@pytest.mark.parametrize(
    ("kind", "build"),
    [("jpeg", _jpeg_with_metadata), ("png", _png_with_metadata), ("webp", _webp_with_metadata)],
)
def test_images_metadata_stripped(tmp_path: Path, kind: str, build: Callable[[], bytes]) -> None:
    data = build()
    source = Image.open(io.BytesIO(data))
    source.load()
    assert len(source.getexif().get_ifd(ExifTags.IFD.GPSInfo)) == 4  # the fixture carries GPS

    _, stored, stored_bytes = _single_image(tmp_path, data, kind)

    assert _metadata_left(stored, stored_bytes) == {
        "info": [],
        "exif": [],
        "containers": [],
        "markers": [],
    }


# --- refusals -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("recorded", "build"),
    [
        ("jpeg", lambda: _encode(_quadrants(), "PNG")),
        ("png", lambda: _encode(_quadrants(), "JPEG")),
        ("png", lambda: _encode(_quadrants(), "WEBP")),
        ("png", lambda: _encode(_quadrants(), "GIF")),
        ("webp", lambda: _encode(_quadrants(), "PNG")),
    ],
    ids=["png-as-jpeg", "jpeg-as-png", "webp-as-png", "gif-as-png", "png-as-webp"],
)
def test_images_format_other_than_recorded_kind_is_corrupted_file(
    tmp_path: Path, recorded: str, build: Callable[[], bytes]
) -> None:
    assert _refusal(tmp_path, build(), recorded) == ("corrupted_file", [])


def _cut_in_half(fmt: str) -> bytes:
    data = _encode(Image.effect_noise((64, 64), 60).convert("RGB"), fmt)
    return data[: len(data) // 2]


@pytest.mark.parametrize(
    ("kind", "build"),
    [
        ("png", lambda: _cut_in_half("PNG")),
        ("jpeg", lambda: _cut_in_half("JPEG")),
        ("webp", lambda: _cut_in_half("WEBP")),
        ("png", lambda: b"\x89PNG\r\n\x1a\n" + b"garbage, not a chunk" * 4),
    ],
    ids=["truncated-png", "truncated-jpeg", "truncated-webp", "garbage-png"],
)
def test_images_truncated_or_garbage_image_is_corrupted_file(
    tmp_path: Path, kind: str, build: Callable[[], bytes]
) -> None:
    assert _refusal(tmp_path, build(), kind) == ("corrupted_file", [])


@pytest.mark.parametrize("garbage", [b"\xff" * 40, b"\x00\x01" * 30], ids=["ff", "0001"])
def test_images_png_with_corrupt_pixel_data_is_corrupted_file(
    tmp_path: Path, garbage: bytes
) -> None:
    """A corrupt (not truncated) IDAT stream is refused, with nothing written.

    Unlike a truncated PNG, whose error Pillow raises on every load, a zlib data
    error is raised on the first load only: a later load returns the partly
    decoded pixels. A PNG without an EXIF chunk before its pixels loads them in
    ``getexif()``, inside the EXIF guard that swallows errors, so only the load
    before that guard turns this file into ``corrupted_file``.
    """
    data = _png_with_corrupt_idat(garbage)
    # The fixture: the header opens, the pixels don't decode.
    source = Image.open(io.BytesIO(data))
    with pytest.raises(OSError):
        source.load()

    assert _refusal(tmp_path, data, "png") == ("corrupted_file", [])


@pytest.mark.parametrize(
    "size",
    [(8_000, 8_500), (10_000, 10_000), (30_000, 30_000)],
    ids=["over-ours-under-pillows-warning", "over-pillows-warning", "over-pillows-error"],
)
def test_images_declared_pixels_over_limit_refused_without_decoding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, size: tuple[int, int]
) -> None:
    decoded: list[str] = []

    def no_load(self: Image.Image) -> Any:
        decoded.append(type(self).__name__)
        raise _DecodedError

    monkeypatch.setattr(ImageFile.ImageFile, "load", no_load)
    monkeypatch.setattr(Image.Image, "load", no_load)

    assert (_refusal(tmp_path, _png_header_only(*size), "png"), decoded) == (
        ("image_too_large", []),
        [],
    )


@pytest.mark.parametrize(
    ("size", "expected"),
    [((10, 10), "converted"), ((101, 1), "image_too_large")],
    ids=["at-limit", "one-over"],
)
def test_images_pixel_limit_read_at_call_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, size: tuple[int, int], expected: str
) -> None:
    from admino.converters import common
    from admino.converters.common import ConversionError

    monkeypatch.setattr(common, "MAX_IMAGE_PIXELS", 100)
    data = _encode(Image.new("RGB", size, (1, 2, 3)), "PNG")

    try:
        manifest, _ = _convert(tmp_path, data, "png")
    except ConversionError as exc:
        outcome = exc.reason
    else:
        outcome = (
            "converted"
            if (manifest.parts[0].width, manifest.parts[0].height) == size
            else "resized"
        )
    assert outcome == expected


# --- JPEG quality ---------------------------------------------------------------------


def test_images_jpeg_reencoded_at_jpeg_quality(tmp_path: Path) -> None:
    from admino.converters import common

    original = Image.effect_noise((64, 64), 60).convert("RGB")
    data = _encode(original, "JPEG", quality=100)
    reference = Image.open(io.BytesIO(_encode(original, "JPEG", quality=common.JPEG_QUALITY)))

    _, stored, stored_bytes = _single_image(tmp_path, data, "jpeg")

    assert (stored_bytes != data, stored.quantization) == (True, reference.quantization)
