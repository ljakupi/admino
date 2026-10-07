"""PDF converter (GH-188): every page becomes a text part or a rendered JPEG part.

Runs only in the conversion worker child; the server never imports pypdfium2 or
Pillow. pdfium is not thread-safe: the worker converts one file on one thread.

Inputs: the stored PDF's path, the ``PartWriter`` of its derived directory, and the
``ConversionOptions`` (the display name for page markers, the render resolution,
the page limit).
Outputs: one part per page, in page order. A page whose text layer has at least
``MIN_PAGE_TEXT_CHARS`` non-whitespace characters is the text
``"[<file> — page N]\\n<cleaned page text>"``; any other page (scanned, blank) is
rendered on white, its rotation applied, at ``render_dpi`` and stored as an RGB JPEG
labelled ``[<file> — page N]``. Returns the page count.

Security notes:
- The page count is checked against ``max_pages`` before any page is converted.
- A rendered page never has more than ``MAX_RENDER_PIXELS`` pixels: a bigger page is
  rendered at the scale that fits, each edge rounded down; a page box so thin that
  even that can't fit (or wider than a JPEG can be) is refused as ``corrupted_file``.
- No form environment is set up, so no form field is drawn and no document
  JavaScript runs: pdfium only extracts text and renders.
- The rendered JPEG is encoded from a fresh image: no metadata segment but JFIF.
- Failures are reason codes only (``password_protected``, ``corrupted_file``,
  ``too_many_pages``, ``text_too_large``); pdfium's messages never propagate.
"""

from __future__ import annotations

import io
import math
import re
from typing import TYPE_CHECKING, Final

import pypdfium2 as pdfium
import pypdfium2.raw as pdfium_raw

from admino.converters import common
from admino.converters.common import ConversionError, clean_text

if TYPE_CHECKING:
    from pathlib import Path

    from admino.converters.common import ConversionOptions, PartWriter

_EM_DASH: Final = chr(0x2014)
_POINTS_PER_INCH: Final = 72
# The largest edge Pillow's JPEG encoder accepts.
_MAX_JPEG_EDGE: Final = 65_500
_WHITESPACE: Final = re.compile(r"\s")
_WHITE: Final = (255, 255, 255, 255)
# A wrong or missing password, or a security handler pdfium doesn't implement.
_LOCKED_ERRORS: Final = frozenset({pdfium_raw.FPDF_ERR_PASSWORD, pdfium_raw.FPDF_ERR_SECURITY})


def convert_pdf(path: Path, writer: PartWriter, options: ConversionOptions) -> int:
    """Convert the PDF at ``path`` page by page into ``writer``; returns its page count.

    Raises:
        ConversionError: ``password_protected`` (a password is needed, or the
            security handler is unsupported), ``corrupted_file`` (the document,
            a page, its text or its rendering fails; a document without pages),
            ``too_many_pages`` (more than ``options.max_pages``, before any part
            is written) or ``text_too_large`` (from the writer).
    """
    document = _open(path)
    try:
        page_count = len(document)
        if page_count < 1:
            raise ConversionError("corrupted_file")
        if page_count > options.max_pages:
            raise ConversionError("too_many_pages")
        for number in range(1, page_count + 1):
            try:
                _convert_page(document, number, writer, options)
            except pdfium.PdfiumError:
                raise ConversionError("corrupted_file") from None
    finally:
        document.close()
    return page_count


def _open(path: Path) -> pdfium.PdfDocument:
    """Load the document at ``path``; a failed load is a ``ConversionError``."""
    # The raw load, not ``PdfDocument(path)``: pypdfium2's loader also refuses a
    # document without pages but then reports pdfium's last error, which can be
    # left over from an earlier file (a stale password error).
    handle = pdfium_raw.FPDF_LoadDocument(bytes(path) + b"\0", None)
    if not handle:
        locked = pdfium_raw.FPDF_GetLastError() in _LOCKED_ERRORS
        raise ConversionError("password_protected" if locked else "corrupted_file")
    return pdfium.PdfDocument(handle)


def _convert_page(
    document: pdfium.PdfDocument, number: int, writer: PartWriter, options: ConversionOptions
) -> None:
    """Write page ``number`` (1-based) as a text part, or as a rendered image part."""
    marker = f"[{options.filename} {_EM_DASH} page {number}]"
    page = document[number - 1]
    try:
        text = _page_text(page)
        if len(_WHITESPACE.sub("", text)) >= common.MIN_PAGE_TEXT_CHARS:
            writer.add_text(f"{marker}\n{text}", page=number)
            return
        data, width, height = _render_jpeg(page, options.render_dpi)
        writer.add_image(
            data, media_type="image/jpeg", width=width, height=height, page=number, label=marker
        )
    finally:
        page.close()


def _page_text(page: pdfium.PdfPage) -> str:
    """The page's text layer, cleaned (``clean_text``)."""
    textpage = page.get_textpage()
    try:
        return clean_text(textpage.get_text_range())
    finally:
        textpage.close()


def _render_jpeg(page: pdfium.PdfPage, render_dpi: int) -> tuple[bytes, int, int]:
    """Render ``page`` on white, its rotation applied; returns (JPEG bytes, width, height)."""
    width, height = _render_size(page.get_width(), page.get_height(), render_dpi)
    bitmap = pdfium.PdfBitmap.new_native(width, height, pdfium_raw.FPDFBitmap_BGR)
    try:
        bitmap.fill_rect(_WHITE, 0, 0, width, height)
        # pdfium scales the page into exactly width x height pixels (PdfPage.render
        # would round each edge up, past the render bound).
        pdfium_raw.FPDF_RenderPageBitmap(
            bitmap, page, 0, 0, width, height, 0, pdfium_raw.FPDF_ANNOT
        )
        image = bitmap.to_pil()
    finally:
        bitmap.close()
    buffer = io.BytesIO()
    with image:
        image.save(buffer, "JPEG", quality=common.JPEG_QUALITY)
    return buffer.getvalue(), width, height


def _render_size(width_pt: float, height_pt: float, render_dpi: int) -> tuple[int, int]:
    """The rendered size in pixels of a ``width_pt`` x ``height_pt`` page.

    The scale is ``render_dpi / 72``, or ``sqrt(MAX_RENDER_PIXELS / area)`` when
    that would exceed ``MAX_RENDER_PIXELS``. Each edge is rounded down, so the
    pixel count never exceeds the bound.

    Raises:
        ConversionError: ``corrupted_file`` for a degenerate page box (an edge far
            below one pixel, so even one row passes the bound; or an edge longer
            than a JPEG can store).
    """
    limit = common.MAX_RENDER_PIXELS
    scale = render_dpi / _POINTS_PER_INCH
    area = width_pt * height_pt
    if area * scale * scale > limit:
        scale = math.sqrt(limit / area)
    width = max(1, math.floor(width_pt * scale))
    height = max(1, math.floor(height_pt * scale))
    if width * height > limit or max(width, height) > _MAX_JPEG_EDGE:
        raise ConversionError("corrupted_file")
    return width, height
