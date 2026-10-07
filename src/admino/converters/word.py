"""DOCX converter (GH-188): Markdown-like text with headings, lists and tables.

Inputs: the path of a stored ``docx`` upload, the part writer and the
conversion options (unused: a DOCX has no pages to label).
Outputs: one text part (none for a document without text); returns no page
count. Top-level body blocks in document order: ``Title``/``Heading N``
paragraphs become ``#`` headings, list styles and numbered paragraphs ``- ``/
``1. `` items indented by level, tables Markdown tables (the shared rules of
``sheets.table_text``), any other paragraph its cleaned text. Headers, footers,
footnotes, comments and text boxes aren't converted.

Security notes:
- The OOXML zip-bomb guard runs before python-docx opens the archive.
- python-docx parses XML with entity resolution off: no external entity is
  fetched and no entity is expanded.
- A list level comes from the document (a style name's number, ``w:ilvl``):
  it is capped at Word's nine levels, so a hostile number can't size the
  indentation.
- Table rows are built from their ``w:tc`` elements, never python-docx's
  ``row.cells`` (which repeats a cell once per spanned grid column, for any
  ``w:gridSpan`` the document declares): each cell's text is computed once
  and repeated for its span only up to ``MAX_TABLE_COLUMNS + 1`` cells per
  row, so a huge span costs no time or memory. A vertically merged
  continuation cell is empty (the merged text appears once).
- Tables stop being built at the text cap (``sheets.table_text``), and so
  does the document (``text_too_large``) before its text is joined.
- Any python-docx, XML or ZIP error is ``corrupted_file``; the library's
  message (which may hold the path) is dropped (``from None``).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

import docx
from docx.text.paragraph import Paragraph

from admino.converters import common
from admino.converters.common import ConversionError, clean_text
from admino.converters.ooxml import check_archive
from admino.converters.sheets import table_text

if TYPE_CHECKING:
    from pathlib import Path
    from typing import BinaryIO

    from docx.oxml.table import CT_Row, CT_Tc
    from docx.table import Table

    from admino.converters.common import ConversionOptions, PartWriter

_HEADING_STYLE: Final = re.compile(r"Heading ([1-9])")
_MAX_HEADING_LEVEL: Final = 6
_MAX_LIST_LEVEL: Final = 9
_BULLET: Final = "- "
_NUMBERED: Final = "1. "


def convert_docx(path: Path, writer: PartWriter, options: ConversionOptions) -> int | None:
    """Write the document's body as Markdown-like text in one text part.

    Returns:
        None: the page count of a DOCX isn't known without rendering it.

    Raises:
        ConversionError: ``archive_too_large`` or ``password_protected``
            (zip-bomb guard), ``corrupted_file`` (unreadable document),
            ``text_too_large`` (more than ``MAX_TEXT_CHARS`` characters).
    """
    check_archive(path)
    with path.open("rb") as file:
        try:
            text = _document_text(file)
        except (ConversionError, MemoryError):
            raise
        except Exception:
            # python-docx's error surface isn't closed (zipfile, lxml, KeyError
            # for a missing part, ValueError for another package type).
            raise ConversionError("corrupted_file") from None
    writer.add_text(text)
    return None


def _document_text(file: BinaryIO) -> str:
    """The body blocks joined: list items by one newline, everything else by a blank line.

    Raises:
        ConversionError: ``text_too_large`` as soon as the blocks hold more
            than ``MAX_TEXT_CHARS`` characters.
    """
    pieces: list[str] = []
    length = 0
    previous_item = False
    for block in docx.Document(file).iter_inner_content():
        if isinstance(block, Paragraph):
            text, item = _paragraph(block)
        else:
            text = table_text(_row_cells(row._tr, block) for row in block.rows)
            item = False
        if not text:
            continue
        separator = ("\n" if previous_item and item else "\n\n") if pieces else ""
        # Each table is capped on its own; many of them (a span repeats its
        # cell's text up to 51 times) must not pile up far past the cap either.
        length += len(separator) + len(text)
        if length > common.MAX_TEXT_CHARS:
            raise ConversionError("text_too_large")
        pieces.extend((separator, text))
        previous_item = item
    return "".join(pieces)


def _row_cells(row: CT_Row, table: Table) -> list[str]:
    """A table row's cell texts, each repeated for its ``w:gridSpan``.

    At most ``MAX_TABLE_COLUMNS + 1`` cells: one past the cap is enough for
    ``table_text`` to add its columns note.
    """
    limit = common.MAX_TABLE_COLUMNS + 1
    cells: list[str] = []
    for tc in row.tc_lst:
        if len(cells) == limit:
            break
        # A continuation of a vertical merge: its text is shown once, in the
        # merge's first cell.
        if tc.vMerge is not None and tc.vMerge != "restart":
            text = ""
        else:
            text = "\n".join(Paragraph(p, table).text for p in tc.p_lst)
        cells.extend([text] * min(_grid_span(tc), limit - len(cells)))
    return cells


def _grid_span(tc: CT_Tc) -> int:
    """The grid columns ``tc`` spans; a missing, non-numeric, zero or negative span is 1."""
    values: list[str] = tc.xpath("./w:tcPr/w:gridSpan/@w:val")
    try:
        span = int(values[0]) if values else 1
    except ValueError:
        return 1
    return max(span, 1)


def _paragraph(paragraph: Paragraph) -> tuple[str, bool]:
    """A paragraph's Markdown text and whether it is a list item (``""`` when empty)."""
    text = clean_text(paragraph.text)
    if not text:
        return "", False
    style = paragraph.style
    name = (style.name if style is not None else None) or ""
    if name == "Title":
        return "# " + text, False
    if heading := _HEADING_STYLE.fullmatch(name):
        return "#" * min(int(heading[1]), _MAX_HEADING_LEVEL) + " " + text, False
    if name.startswith("List Bullet"):
        return _item(_BULLET, _style_level(name), text), True
    if name.startswith("List Number"):
        return _item(_NUMBERED, _style_level(name), text), True
    # Numbering applied directly (Word's own list buttons) rather than by a list style.
    if paragraph._p.xpath("./w:pPr/w:numPr"):
        ilvl = paragraph._p.xpath("./w:pPr/w:numPr/w:ilvl/@w:val")
        return _item(_BULLET, int(ilvl[0]) + 1 if ilvl else 1, text), True
    return text, False


def _style_level(name: str) -> int:
    """The trailing number of a list style's name (``List Bullet 2`` -> 2), else 1."""
    digits = name[len(name.rstrip("0123456789")) :]
    return int(digits) if digits else 1


def _item(marker: str, level: int, text: str) -> str:
    """A list item at ``level`` (two spaces of indentation per level above 1)."""
    return "  " * (min(level, _MAX_LIST_LEVEL) - 1) + marker + text
