"""Tests for ``admino.converters.pdf.convert_pdf`` (GH-188 contract sections 3, 4.1, 4.7).

A PDF is converted page by page, in-process here (the worker boundary is tested
elsewhere), with ``convert_pdf(path, PartWriter(out_dir), ConversionOptions(...))``.
What these tests pin down:

- A page whose cleaned text layer has at least ``MIN_PAGE_TEXT_CHARS`` (20)
  non-whitespace characters is one text part, exactly
  ``"[<file> — page N]\\n<cleaned page text>"`` (U+2014 with one space each side,
  ``N`` 1-based), ``page`` = N, written as ``part-NNNN.txt`` (UTF-8, no BOM). The file
  name is ``options.filename`` verbatim (brackets, quotes, Markdown characters,
  non-ASCII), never the stored file's name. 19 vs 20 characters is the boundary;
  spaces, line breaks and removed control characters don't count.
- The text layer goes through ``clean_text``: CRLF (pdfium's line break) becomes
  LF, C0/C1 controls, DEL, BOM and the U+FFFE noncharacter are removed, VT and FF
  become line breaks, spaces at line ends are stripped.
- Any other page (scanned, blank) is rendered on white with its rotation applied,
  at ``render_dpi / 72`` (each edge within 1 px of ``points * dpi / 72``; checked for
  three sizes and dpi values) and saved as a real metadata-free RGB JPEG (no EXIF,
  ICC, XMP, comment or Photoshop block; only the JFIF APP0 segment): an image part
  ``part-NNNN.jpg``, ``media_type`` image/jpeg, label ``[<file> — page N]``, width and
  height those of the JPEG. The page content is really rendered.
- The render bound: a page that would exceed ``common.MAX_RENDER_PIXELS`` (read at
  call time) is rendered at ``sqrt(MAX_RENDER_PIXELS / (w_pt * h_pt))``: its pixel
  count never exceeds the bound and each edge stays within 1 px of that scale (so
  the aspect ratio holds), for a 14,400 pt square and a 2:1 page at 300 dpi.
- Mixed documents: text, image, text, in page order, part names numbered in order,
  nothing else written by the converter. The page count is returned.
- ``too_many_pages`` when the document has more pages than ``max_pages``, before
  any part is written (out_dir stays empty); exactly ``max_pages`` converts.
- ``password_protected`` for a genuinely encrypted file (Standard handler, a user
  password; the fixture opens with it) and for an unsupported security handler;
  ``corrupted_file`` for garbage after ``%PDF-``, a truncated file, a page that
  fails to load, and a document without pages (pdfium 156 writes one but refuses to
  load it, so the contract's ``n == 0`` branch can't be reached from a file and the
  load-error rule applies). The error's text is the reason code only.
- Tokens: a text part = one per ASCII digit plus one per 4 other UTF-8 bytes of the
  part text (marker included); an image part = ``ceil(w * h / 750)`` plus its label's
  text tokens (a scanned A4 page at 150 dpi lands in 2,500..3,300).
- ``text_too_large`` when the parts of all pages together exceed
  ``common.MAX_TEXT_CHARS`` (monkeypatched small) although each page fits.
- Through ``dispatch.convert(path, "pdf", out_dir, options)``: the manifest's
  version, kind, page count, parts (type, file, page, label) and
  ``token_estimate == sum(part tokens)``; ``manifest.json`` on disk equals the
  returned model.

The new modules are imported inside the helpers, so this file collects before they
exist and every test fails on its own. PDFs are built in ``tmp_path`` by
``tests/pdf_fixtures.py`` (hand-written PDF bytes, stdlib only).
"""

from __future__ import annotations

import io
import json
import math
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import pypdfium2 as pdfium
import pytest
from PIL import Image

from tests.pdf_fixtures import (
    A4,
    LETTER_LANDSCAPE,
    Page,
    blank_page,
    build_pdf,
    scanned_page,
    text_page,
)

if TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

EM_DASH = chr(0x2014)
# The stored original has no extension (``<attachments_root>/<org>/<id>``).
STORED_NAME = "3f1c2a9e-7b1d-4c55-9a43-1d2e3f4a5b6c"
METADATA_KEYS = frozenset(
    {"exif", "icc_profile", "xmp", "XML:com.adobe.xmp", "comment", "photoshop"}
)


def _marker(filename: str, page: int) -> str:
    return f"[{filename} {EM_DASH} page {page}]"


def _text_tokens(text: str) -> int:
    """The contract's text estimate, computed independently of ``admino.tokens``."""
    digits = sum(char in "0123456789" for char in text)
    return digits + math.ceil((len(text.encode("utf-8")) - digits) / 4)


@dataclass(frozen=True)
class _Result:
    page_count: int | None
    parts: list[dict[str, Any]]
    out_dir: Path


@pytest.fixture
def common() -> ModuleType:
    import admino.converters.common as module

    return module


def _paths(tmp_path: Path, data: bytes) -> tuple[Path, Path]:
    source = tmp_path / STORED_NAME
    source.write_bytes(data)
    out_dir = tmp_path / f"{STORED_NAME}.d"
    out_dir.mkdir()
    return source, out_dir


def _options(filename: str, render_dpi: int, max_pages: int) -> Any:
    from admino.converters.common import ConversionOptions

    return ConversionOptions(filename=filename, render_dpi=render_dpi, max_pages=max_pages)


def _convert(
    tmp_path: Path,
    data: bytes,
    *,
    filename: str = "report.pdf",
    render_dpi: int = 150,
    max_pages: int = 100,
) -> _Result:
    from admino.converters.common import PartWriter
    from admino.converters.pdf import convert_pdf

    source, out_dir = _paths(tmp_path, data)
    writer = PartWriter(out_dir)
    page_count = convert_pdf(source, writer, _options(filename, render_dpi, max_pages))
    return _Result(page_count, [part.model_dump() for part in writer.parts], out_dir)


def _failure(tmp_path: Path, data: bytes, *, max_pages: int = 100) -> tuple[str, str, list[str]]:
    """(reason, str(error), files left in out_dir) of a failing conversion."""
    from admino.converters.common import ConversionError, PartWriter
    from admino.converters.pdf import convert_pdf

    source, out_dir = _paths(tmp_path, data)
    with pytest.raises(ConversionError) as excinfo:
        convert_pdf(source, PartWriter(out_dir), _options("report.pdf", 150, max_pages))
    return excinfo.value.reason, str(excinfo.value), sorted(os.listdir(out_dir))


def _jpeg(result: _Result, part: dict[str, Any]) -> Image.Image:
    image = Image.open(result.out_dir / part["file"])
    image.load()
    return image


def _within_one_pixel(actual: int, exact: float) -> bool:
    return abs(actual - exact) <= 1


# --- text pages ------------------------------------------------------------------


def test_pdf_text_page_is_marker_line_then_cleaned_text(tmp_path: Path) -> None:
    city = "Z" + chr(0xFC) + "rich"
    data = build_pdf([text_page(f"Quarterly report 2026 for {city}", "Revenue grew 12 %.")])

    result = _convert(tmp_path, data)

    expected = f"{_marker('report.pdf', 1)}\nQuarterly report 2026 for {city}\nRevenue grew 12 %."
    assert (
        result.page_count,
        result.parts,
        (result.out_dir / "part-0001.txt").read_bytes(),
    ) == (
        1,
        [{"type": "text", "file": "part-0001.txt", "page": 1, "tokens": _text_tokens(expected)}],
        expected.encode("utf-8"),
    )


def test_pdf_text_pages_become_one_part_per_page_in_order(tmp_path: Path) -> None:
    lines = [
        "First page carries enough text here",
        "Second page carries enough text too",
        "Third page closes the whole document",
    ]
    data = build_pdf([text_page(line) for line in lines])

    result = _convert(tmp_path, data)

    texts = [f"{_marker('report.pdf', n)}\n{line}" for n, line in enumerate(lines, start=1)]
    assert (
        result.page_count,
        [(part["file"], part["page"]) for part in result.parts],
        [(result.out_dir / part["file"]).read_text(encoding="utf-8") for part in result.parts],
        sorted(os.listdir(result.out_dir)),
    ) == (
        3,
        [("part-0001.txt", 1), ("part-0002.txt", 2), ("part-0003.txt", 3)],
        texts,
        ["part-0001.txt", "part-0002.txt", "part-0003.txt"],
    )


@pytest.mark.parametrize(
    "filename",
    ['Q3 [draft] *v2* "final".pdf', "Bericht " + chr(0xC4) + ".pdf"],
    ids=["markdown-characters", "non-ascii"],
)
def test_pdf_marker_keeps_the_file_name_verbatim(tmp_path: Path, filename: str) -> None:
    data = build_pdf([text_page("This page has a usable text layer.")])

    result = _convert(tmp_path, data, filename=filename)

    text = (result.out_dir / "part-0001.txt").read_text(encoding="utf-8")
    assert text == f"{_marker(filename, 1)}\nThis page has a usable text layer."


@pytest.mark.parametrize(
    ("line", "kind"),
    [
        (" ".join("abcdefghijklmnopqrs"), "image"),
        (" ".join("abcdefghijklmnopqrst"), "text"),
        (b"abcdefghij\x01\x02\x03\x04\x05\x06klmnopqrs", "image"),
    ],
    ids=["19-spaced-letters", "20-spaced-letters", "19-letters-and-6-controls"],
)
def test_pdf_usable_text_needs_twenty_non_whitespace_characters(
    tmp_path: Path, line: str | bytes, kind: str
) -> None:
    data = build_pdf([Page(lines=(line,))])

    result = _convert(tmp_path, data, render_dpi=72)

    assert [(part["type"], part["page"]) for part in result.parts] == [(kind, 1)]


def test_pdf_text_layer_controls_and_line_breaks_are_cleaned(tmp_path: Path) -> None:
    page = Page(
        lines=(
            b"Invoice\x01 total\x07 due\x1f today",
            b"Second\x80line\x81with\x82odd\x83marks\x84inside\x85it\x86.",
            b"Trailing spaces   ",
        ),
        # C1 NEL, BOM, the U+FFFE noncharacter, VT, FF, DEL, C1 APC.
        to_unicode={
            0x80: 0x85,
            0x81: 0xFEFF,
            0x82: 0xFFFE,
            0x83: 0x0B,
            0x84: 0x0C,
            0x85: 0x7F,
            0x86: 0x9F,
        },
    )

    result = _convert(tmp_path, build_pdf([page]))

    text = (result.out_dir / "part-0001.txt").read_text(encoding="utf-8")
    assert text == (
        f"{_marker('report.pdf', 1)}\n"
        "Invoice total due today\n"
        "Secondlinewithodd\nmarks\ninsideit.\n"
        "Trailing spaces"
    )


# --- rendered pages -----------------------------------------------------------------


def test_pdf_scanned_page_is_a_labeled_metadata_free_rgb_jpeg(tmp_path: Path) -> None:
    result = _convert(tmp_path, build_pdf([scanned_page()]), filename="scan.pdf")

    (part,) = result.parts
    image = _jpeg(result, part)
    middle = image.getpixel((image.width // 2, image.height // 2))
    corner = image.getpixel((5, 5))
    assert (
        result.page_count,
        {key: part[key] for key in ("type", "file", "page", "label", "media_type")},
        (image.format, image.mode, image.size),
        sorted(METADATA_KEYS & set(image.info)),
        len(image.getexif()),
        sorted({marker for marker, _ in image.applist}),
        max(middle) < 64 and min(corner) > 240,
        sorted(os.listdir(result.out_dir)),
    ) == (
        1,
        {
            "type": "image",
            "file": "part-0001.jpg",
            "page": 1,
            "label": _marker("scan.pdf", 1),
            "media_type": "image/jpeg",
        },
        ("JPEG", "RGB", (part["width"], part["height"])),
        [],
        0,
        ["APP0"],
        True,
        ["part-0001.jpg"],
    )


@pytest.mark.parametrize(
    ("size", "dpi"),
    [(A4, 72), (LETTER_LANDSCAPE, 150), ((200.0, 100.0), 300)],
    ids=["a4-72dpi", "letter-landscape-150dpi", "small-300dpi"],
)
def test_pdf_rendered_page_size_follows_render_dpi(
    tmp_path: Path, size: tuple[float, float], dpi: int
) -> None:
    width_pt, height_pt = size
    data = build_pdf([scanned_page(width=width_pt, height=height_pt)])

    result = _convert(tmp_path, data, render_dpi=dpi)

    (part,) = result.parts
    assert (
        _within_one_pixel(part["width"], width_pt * dpi / 72),
        _within_one_pixel(part["height"], height_pt * dpi / 72),
        _jpeg(result, part).size,
    ) == (True, True, (part["width"], part["height"]))


@pytest.mark.parametrize(
    ("size", "bound"),
    [((14400.0, 14400.0), 50_000), ((14400.0, 7200.0), 30_000)],
    ids=["square-14400pt", "two-to-one-14400pt"],
)
def test_pdf_render_bound_caps_pixels_and_keeps_the_aspect_ratio(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    common: ModuleType,
    size: tuple[float, float],
    bound: int,
) -> None:
    monkeypatch.setattr(common, "MAX_RENDER_PIXELS", bound)
    width_pt, height_pt = size
    data = build_pdf([scanned_page(width=width_pt, height=height_pt)])

    result = _convert(tmp_path, data, render_dpi=300)

    (part,) = result.parts
    scale = math.sqrt(bound / (width_pt * height_pt))
    assert (
        part["width"] * part["height"] <= bound,
        _within_one_pixel(part["width"], width_pt * scale),
        _within_one_pixel(part["height"], height_pt * scale),
        _jpeg(result, part).size,
    ) == (True, True, True, (part["width"], part["height"]))


def test_pdf_rotated_page_is_rendered_with_its_rotation(tmp_path: Path) -> None:
    data = build_pdf([scanned_page(width=400.0, height=200.0, rotate=90)])

    result = _convert(tmp_path, data, render_dpi=72)

    (part,) = result.parts
    assert (
        _within_one_pixel(part["width"], 200),
        _within_one_pixel(part["height"], 400),
        _jpeg(result, part).size,
    ) == (True, True, (part["width"], part["height"]))


def test_pdf_blank_page_is_rendered_on_white(tmp_path: Path) -> None:
    result = _convert(tmp_path, build_pdf([blank_page()]), render_dpi=72)

    (part,) = result.parts
    image = _jpeg(result, part)
    assert (
        part["type"],
        part["label"],
        image.mode,
        min(low for low, _ in image.getextrema()) >= 250,
    ) == ("image", _marker("report.pdf", 1), "RGB", True)


def test_pdf_mixed_document_is_converted_page_by_page_in_order(tmp_path: Path) -> None:
    filename = 'Q3 [draft] *v2* "final".pdf'
    data = build_pdf(
        [
            text_page("The first page is a typed cover letter."),
            scanned_page(),
            text_page("The third page is typed text again here."),
        ]
    )

    result = _convert(tmp_path, data, filename=filename)

    assert (
        result.page_count,
        [(p["type"], p["file"], p["page"], p.get("label")) for p in result.parts],
        (result.out_dir / "part-0003.txt").read_text(encoding="utf-8"),
        sorted(os.listdir(result.out_dir)),
    ) == (
        3,
        [
            ("text", "part-0001.txt", 1, None),
            ("image", "part-0002.jpg", 2, _marker(filename, 2)),
            ("text", "part-0003.txt", 3, None),
        ],
        f"{_marker(filename, 3)}\nThe third page is typed text again here.",
        ["part-0001.txt", "part-0002.jpg", "part-0003.txt"],
    )


# --- page limit -----------------------------------------------------------------------


def test_pdf_more_pages_than_max_pages_fails_before_any_part(tmp_path: Path) -> None:
    data = build_pdf([text_page(f"Page {n} has plenty of usable text.") for n in (1, 2, 3)])

    assert _failure(tmp_path, data, max_pages=2) == ("too_many_pages", "too_many_pages", [])


def test_pdf_page_count_equal_to_max_pages_is_converted(tmp_path: Path) -> None:
    data = build_pdf([text_page(f"Page {n} has plenty of usable text.") for n in (1, 2, 3)])

    result = _convert(tmp_path, data, max_pages=3)

    assert (result.page_count, [part["page"] for part in result.parts]) == (3, [1, 2, 3])


# --- protected and unreadable files -----------------------------------------------------


def test_pdf_encrypted_file_is_password_protected(tmp_path: Path) -> None:
    data = build_pdf([text_page("Confidential text behind a password.")], encrypt=("user", "own"))
    fixture = tmp_path / "fixture.pdf"
    fixture.write_bytes(data)
    with pdfium.PdfDocument(fixture, password="user") as opened:
        readable = opened[0].get_textpage().get_text_range()
    assert readable == "Confidential text behind a password."

    assert _failure(tmp_path, data) == ("password_protected", "password_protected", [])


def test_pdf_unsupported_security_handler_is_password_protected(tmp_path: Path) -> None:
    data = build_pdf(
        [text_page("Text behind a handler pdfium lacks.")], security_filter="Adobe.PubSec"
    )

    assert _failure(tmp_path, data) == ("password_protected", "password_protected", [])


def _garbage() -> bytes:
    return b"%PDF-1.7\n" + bytes(range(256)) * 8


def _truncated() -> bytes:
    full = build_pdf([text_page("Page one of two, cut short."), text_page("Page two of two.")])
    return full[: len(full) // 2]


def _missing_page() -> bytes:
    return build_pdf([text_page("The first page loads without trouble.")], missing_kids=1)


def _without_pages() -> bytes:
    buffer = io.BytesIO()
    document = pdfium.PdfDocument.new()
    document.save(buffer)
    document.close()
    return buffer.getvalue()


@pytest.mark.parametrize(
    "build",
    [_garbage, _truncated, _missing_page, _without_pages],
    ids=["garbage-after-header", "truncated", "page-fails-to-load", "no-pages"],
)
def test_pdf_unreadable_file_is_corrupted(tmp_path: Path, build: Any) -> None:
    reason, message, _ = _failure(tmp_path, build())

    assert (reason, message) == ("corrupted_file", "corrupted_file")


# --- token estimate and text cap --------------------------------------------------------


def test_pdf_scanned_a4_page_tokens_are_pixels_plus_label(tmp_path: Path) -> None:
    result = _convert(tmp_path, build_pdf([scanned_page()]), render_dpi=150)

    (part,) = result.parts
    expected = math.ceil(part["width"] * part["height"] / 750) + _text_tokens(
        _marker("report.pdf", 1)
    )
    assert (part["tokens"], 2500 <= part["tokens"] <= 3300) == (expected, True)


def test_pdf_text_of_all_pages_over_the_cap_is_text_too_large(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, common: ModuleType
) -> None:
    lines = [f"Page {n} carries this much usable text." for n in (1, 2, 3)]
    texts = [f"{_marker('report.pdf', n)}\n{line}" for n, line in enumerate(lines, start=1)]
    monkeypatch.setattr(common, "MAX_TEXT_CHARS", len(texts[0]) + len(texts[1]) + 1)

    reason, message, _ = _failure(tmp_path, build_pdf([text_page(line) for line in lines]))

    assert (reason, message) == ("text_too_large", "text_too_large")


# --- through the dispatcher -----------------------------------------------------------


def test_pdf_dispatch_manifest_lists_the_pages_and_matches_the_disk(tmp_path: Path) -> None:
    from admino.converters import dispatch
    from admino.converters.common import Manifest

    data = build_pdf([text_page("A typed first page with enough text."), scanned_page()])
    source, out_dir = _paths(tmp_path, data)

    manifest = dispatch.convert(source, "pdf", out_dir, _options("scan.pdf", 150, 10))

    on_disk = (out_dir / "manifest.json").read_text(encoding="utf-8")
    assert (
        (manifest.version, manifest.kind, manifest.page_count),
        [(p.type, p.file, p.page, getattr(p, "label", None)) for p in manifest.parts],
        manifest.token_estimate == sum(p.tokens for p in manifest.parts) > 0,
        Manifest.model_validate_json(on_disk) == manifest,
        json.loads(on_disk) == manifest.model_dump(mode="json"),
        sorted(os.listdir(out_dir)),
    ) == (
        (1, "pdf", 2),
        [
            ("text", "part-0001.txt", 1, None),
            ("image", "part-0002.jpg", 2, _marker("scan.pdf", 2)),
        ],
        True,
        True,
        True,
        ["manifest.json", "part-0001.txt", "part-0002.jpg"],
    )
