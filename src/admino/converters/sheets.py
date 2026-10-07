"""XLSX and CSV converters (GH-188): one Markdown table per worksheet, with caps.

Also home of the table rules every converter shares (``table_text``: XLSX
sheets, CSV files, DOCX tables) and of ``format_cell``.

Inputs: the path of a stored ``xlsx`` or ``csv`` upload, the part writer and the
conversion options (unused: sheets have no pages or labels).
Outputs: one text part (none when there is no content); returns no page count.
XLSX: ``## <sheet name>`` and its table (or ``(empty sheet)``) per worksheet in
workbook order, chartsheets skipped. CSV: one table, no heading.

Security notes:
- The OOXML zip-bomb guard runs before openpyxl opens a workbook; openpyxl
  reads it read-only with cached values (no formula is evaluated).
- Caps read at call time from ``common``: ``MAX_SHEETS``, ``MAX_TABLE_ROWS``,
  ``MAX_TABLE_COLUMNS``, ``MAX_CELL_CHARS`` (via ``clean_cell``); a cut is
  stated in a note. Sheets stop being built once their text passes
  ``MAX_TEXT_CHARS`` (``text_too_large``), so shared strings repeated across
  many cells can't inflate memory without bound.
- The worksheet's declared dimension is ignored: rows are as wide as their
  cells, so a lying ``<dimension>`` neither pads every row to 16,384 columns
  nor cuts real cells off.
- Any openpyxl, XML, ZIP or CSV error (while loading or while reading rows)
  is ``corrupted_file``; the library's message is dropped (``from None``).
"""

from __future__ import annotations

import csv
import datetime as dt
from typing import TYPE_CHECKING, Final

import openpyxl

from admino.converters import common
from admino.converters.common import ConversionError, clean_cell, markdown_table
from admino.converters.ooxml import check_archive

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path
    from typing import BinaryIO

    from admino.converters.common import ConversionOptions, PartWriter

_CSV_SAMPLE_CHARS: Final = 64 * 1024
_CSV_DELIMITERS: Final = ",;\t|"
_EMPTY_SHEET: Final = "(empty sheet)"
_SECTION_SEPARATOR: Final = "\n\n"
# Below this magnitude a float's integral value prints exactly as an int.
_EXACT_INTEGRAL_FLOAT: Final = 1e15


def format_cell(value: object) -> str:
    """Format one cell value as text (before ``clean_cell``).

    None is empty; bools are ``TRUE``/``FALSE``; integral floats under 1e15
    print as ints, other floats as ``repr``; a datetime at midnight is its
    date, any other datetime is ISO with a space; dates and times are ISO;
    everything else (timedelta and str included) is ``str()``.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, float):
        if value.is_integer() and abs(value) < _EXACT_INTEGRAL_FLOAT:
            return str(int(value))
        return repr(value)
    if isinstance(value, dt.datetime):
        if value.time() == dt.time():
            return value.date().isoformat()
        return value.isoformat(sep=" ")
    if isinstance(value, dt.date | dt.time):
        return value.isoformat()
    return str(value)


def table_text(rows: Iterable[Iterable[object]]) -> str:
    """Build a capped Markdown table from raw rows, with its notes; ``""`` when empty.

    Cells are formatted (``format_cell``) and cleaned (``clean_cell``); rows whose
    cells are all empty are dropped; the first ``MAX_TABLE_ROWS`` non-empty rows
    are kept, each cut to ``MAX_TABLE_COLUMNS`` cells, then the table is trimmed
    to its rightmost non-empty column. Notes follow after a blank line, one per
    line: the rows note when another non-empty row follows the kept ones, the
    columns note when a kept row has content beyond the column cap.
    """
    max_rows = common.MAX_TABLE_ROWS
    max_columns = common.MAX_TABLE_COLUMNS
    kept: list[list[str]] = []
    rows_cut = columns_cut = False
    for row in rows:
        cells = [clean_cell(format_cell(value)) for value in row]
        if not any(cells):
            continue
        if len(kept) == max_rows:
            # Stop at the first non-empty row past the cap: the rest is never read.
            rows_cut = True
            break
        columns_cut = columns_cut or any(cells[max_columns:])
        kept.append(cells[:max_columns])
    if not kept:
        return ""
    width = max(_used_width(row) for row in kept)
    table = markdown_table([row[:width] for row in kept])
    notes = []
    if rows_cut:
        notes.append(f"[Only the first {max_rows} rows are included.]")
    if columns_cut:
        notes.append(f"[Only the first {max_columns} columns are included.]")
    return table + "\n\n" + "\n".join(notes) if notes else table


def _used_width(cells: list[str]) -> int:
    """The number of cells up to and including the last non-empty one."""
    return max((index + 1 for index, cell in enumerate(cells) if cell), default=0)


def convert_xlsx(path: Path, writer: PartWriter, options: ConversionOptions) -> int | None:
    """Write the workbook's worksheets as Markdown tables in one text part.

    Returns:
        None: workbooks have no pages.

    Raises:
        ConversionError: ``archive_too_large`` (zip-bomb guard),
            ``corrupted_file`` (unreadable workbook or sheet),
            ``text_too_large`` (more than ``MAX_TEXT_CHARS`` characters).
    """
    check_archive(path)
    # openpyxl refuses a path without an xlsx extension (stored uploads have
    # none), so it gets the open file; the file is closed whatever happens.
    with path.open("rb") as file:
        try:
            text = _workbook_text(file)
        except (ConversionError, MemoryError):
            raise
        except Exception:
            # openpyxl's error surface isn't closed (zipfile, XML parser,
            # KeyError for a missing part, value errors), and read-only mode
            # parses each sheet lazily while its rows are read.
            raise ConversionError("corrupted_file") from None
    writer.add_text(text)
    return None


def _workbook_text(file: BinaryIO) -> str:
    """The sections of every worksheet (at most ``MAX_SHEETS``) joined by a blank line."""
    workbook = openpyxl.load_workbook(file, read_only=True, data_only=True)
    try:
        worksheets = workbook.worksheets
        max_sheets = common.MAX_SHEETS
        sections: list[str] = []
        length = -len(_SECTION_SEPARATOR)
        for sheet in worksheets[:max_sheets]:
            sheet.reset_dimensions()
            table = table_text(sheet.iter_rows(values_only=True))
            section = f"## {clean_cell(sheet.title)}\n\n{table or _EMPTY_SHEET}"
            length += len(_SECTION_SEPARATOR) + len(section)
            if length > common.MAX_TEXT_CHARS:
                raise ConversionError("text_too_large")
            sections.append(section)
        if len(worksheets) > max_sheets:
            sections.append(f"[Only the first {max_sheets} sheets are included.]")
        return _SECTION_SEPARATOR.join(sections)
    finally:
        workbook.close()


def convert_csv(path: Path, writer: PartWriter, options: ConversionOptions) -> int | None:
    """Write the CSV file as one Markdown table in one text part.

    The delimiter is sniffed among ``,`` ``;`` tab ``|`` from the first 64 KiB
    (``csv.excel`` when sniffing fails).

    Returns:
        None: CSV files have no pages.

    Raises:
        ConversionError: ``corrupted_file`` for bytes that aren't UTF-8 or a
            CSV error (a field over the csv module's limit);
            ``text_too_large`` for more than ``MAX_TEXT_CHARS`` characters.
    """
    with path.open(encoding="utf-8-sig", newline="") as file:
        try:
            sample = file.read(_CSV_SAMPLE_CHARS)
            # Seeking to 0 resets the decoder, so the BOM is skipped again.
            file.seek(0)
            dialect: type[csv.Dialect]
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=_CSV_DELIMITERS)
            except csv.Error:
                dialect = csv.excel
            text = table_text(csv.reader(file, dialect))
        except (csv.Error, UnicodeDecodeError):
            raise ConversionError("corrupted_file") from None
    writer.add_text(text)
    return None
