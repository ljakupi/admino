"""Shared base of the document converters (GH-188): limits, failure codes, parts, manifest.

Every converter writes its output through a ``PartWriter`` into the
attachment's derived directory (``<id>.d/``): numbered text and image parts
that the manifest (``Manifest``) lists in order with their token estimates.

Inputs: converter text (PDF page text, DOCX paragraphs and cells, sheet cells),
image bytes with their size and label, the conversion options.
Outputs: cleaned text, Markdown tables, part files (``part-NNNN.txt/.jpg/.png``)
and the ``TextPart``/``ImagePart``/``Manifest`` models; ``ConversionError`` with
one of the ``CONVERSION_FAILURES`` codes.

Security notes:
- The limits are module constants that callers read at call time as
  ``common.<NAME>``; they bound the work a hostile file can cause (pixels,
  rendered pages, text, tables, OOXML archive sizes, derived bytes).
- ``PartWriter`` counts the bytes of every part it writes (text as UTF-8):
  a part that would take one file's parts past ``MAX_DERIVED_BYTES`` is
  refused (``output_too_large``) before anything of it is written.
- ``ConversionError``'s message is its reason code only: never a path, a name
  or a library's text.
- Part files are created exclusively with mode 0600 and ``O_NOFOLLOW``: an
  existing file or a planted symlink at the next part name is refused, never
  followed or overwritten.
- Shared by the server and the worker: this module never imports a parsing
  library (PIL, pypdfium2, docx, openpyxl), so importing it loads none.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Final, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field

from admino.models import (
    AttachmentKind,  # noqa: TC001 — Pydantic resolves field annotations at runtime
)
from admino.tokens import estimate_image_tokens, estimate_text_tokens

if TYPE_CHECKING:
    from pathlib import Path

MAX_IMAGE_EDGE: Final = 2048
MAX_IMAGE_PIXELS: Final = 64_000_000
MAX_RENDER_PIXELS: Final = 25_000_000
JPEG_QUALITY: Final = 85
MIN_PAGE_TEXT_CHARS: Final = 20
MAX_TEXT_CHARS: Final = 10_000_000
MAX_SHEETS: Final = 50
MAX_TABLE_ROWS: Final = 1000
MAX_TABLE_COLUMNS: Final = 50
MAX_CELL_CHARS: Final = 1000
MAX_OOXML_ENTRIES: Final = 10_000
MAX_OOXML_ENTRY_BYTES: Final = 64 * 1024 * 1024
MAX_OOXML_TOTAL_BYTES: Final = 256 * 1024 * 1024
MANIFEST_NAME: Final = "manifest.json"
MAX_DERIVED_BYTES: Final = 256 * 1024 * 1024

ConversionFailure = Literal[
    "corrupted_file",
    "password_protected",
    "too_many_pages",
    "archive_too_large",
    "image_too_large",
    "text_too_large",
    "output_too_large",
    "conversion_timeout",
    "processing_error",
]
CONVERSION_FAILURES: Final[frozenset[str]] = frozenset(get_args(ConversionFailure))

# C0 controls except TAB, LF, VT, FF, CR; DEL and the C1 block; the BOM and the
# two noncharacters U+FFFE/U+FFFF. Code points, not escapes, keep the source ASCII.
_REMOVED: Final = (
    *range(0x00, 0x09),
    *range(0x0E, 0x20),
    *range(0x7F, 0xA0),
    0xFEFF,
    0xFFFE,
    0xFFFF,
)
_TEXT_TABLE: Final[dict[int, str | None]] = {
    **dict.fromkeys(_REMOVED),
    **dict.fromkeys((0x0B, 0x0C, 0x0D), "\n"),
}
_CELL_TABLE: Final[dict[int, str | None]] = {
    **dict.fromkeys(_REMOVED),
    **dict.fromkeys((0x09, 0x0A, 0x0B, 0x0C, 0x0D), " "),
}
_ELLIPSIS: Final = chr(0x2026)

_PART_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_PART_MODE: Final = 0o600


class ConversionError(Exception):
    """A file that can't be converted; ``reason`` is one of ``CONVERSION_FAILURES``."""

    def __init__(self, reason: ConversionFailure) -> None:
        # The message is the code only, so no path, name or library text can
        # reach a log line or the database through it.
        super().__init__(reason)
        self.reason: ConversionFailure = reason


@dataclass(frozen=True)
class ConversionOptions:
    """Per-file conversion settings: the display name for page labels and the PDF limits."""

    filename: str
    render_dpi: int
    max_pages: int


class TextPart(BaseModel):
    """A text part of a converted file (``part-NNNN.txt``, UTF-8)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["text"]
    # The part's name inside ``<id>.d/``: never a path.
    file: str = Field(pattern=r"^part-[0-9]{4,}\.txt$")
    page: int | None
    tokens: int = Field(ge=0)


class ImagePart(BaseModel):
    """An image part of a converted file (``part-NNNN.jpg`` or ``.png``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["image"]
    # The part's name inside ``<id>.d/``: never a path.
    file: str = Field(pattern=r"^part-[0-9]{4,}\.(?:jpg|png)$")
    page: int | None
    label: str | None
    media_type: Literal["image/jpeg", "image/png"]
    width: int = Field(ge=1)
    height: int = Field(ge=1)
    tokens: int = Field(ge=0)


class Manifest(BaseModel):
    """``manifest.json`` of a converted file: its parts in order and their token sum."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1]
    kind: AttachmentKind
    page_count: int | None
    token_estimate: int = Field(ge=0)
    parts: list[Annotated[TextPart | ImagePart, Field(discriminator="type")]]


def clean_text(text: str) -> str:
    """Normalize converter text (PDF page text, DOCX paragraph and cell text).

    CRLF, CR, VT and FF become LF; C0 controls (but TAB and LF), DEL, C1, U+FEFF,
    U+FFFE and U+FFFF are removed; spaces and tabs at each line end are
    stripped, then the whole text. Tabs inside a line are kept.
    """
    unified = text.replace("\r\n", "\n").translate(_TEXT_TABLE)
    # rstrip per line, not a regex: "[ \t]+$" is quadratic on a long run of
    # spaces that doesn't end a line.
    return "\n".join(line.rstrip(" \t") for line in unified.split("\n")).strip()


def clean_cell(value: str) -> str:
    """Make ``value`` one Markdown table cell.

    Controls are removed as in ``clean_text``; CRLF, CR, LF, TAB, VT and FF each
    become one space; the result is stripped, cut to ``MAX_CELL_CHARS``
    characters plus an ellipsis, and only then are ``|`` escaped (so escaping
    never counts toward the limit).
    """
    cell = value.replace("\r\n", " ").translate(_CELL_TABLE).strip()
    if len(cell) > MAX_CELL_CHARS:
        cell = cell[:MAX_CELL_CHARS] + _ELLIPSIS
    return cell.replace("|", "\\|")


def markdown_table(rows: list[list[str]]) -> str:
    """A Markdown table of already cleaned cells; the first row is the header.

    Every row is padded with empty cells to the longest row's length; no rows
    give ``""``.
    """
    if not rows:
        return ""
    width = max(len(row) for row in rows)
    lines = [_table_row(rows[0], width), _table_row(["---"] * width, width)]
    lines.extend(_table_row(row, width) for row in rows[1:])
    return "\n".join(lines)


def _table_row(cells: list[str], width: int) -> str:
    return "| " + " | ".join([*cells, *[""] * (width - len(cells))]) + " |"


class PartWriter:
    """Writes the numbered parts of one converted file into an existing ``out_dir``.

    Parts are named ``part-NNNN.<ext>`` with ``NNNN`` the 1-based index in
    order of addition; each is created exclusively (mode 0600, never through
    a symlink). ``parts`` lists them in order, ``token_estimate`` is their sum.
    All parts together hold at most ``MAX_DERIVED_BYTES`` bytes.
    """

    def __init__(self, out_dir: Path) -> None:
        self._out_dir = out_dir
        self._parts: list[TextPart | ImagePart] = []
        self._chars = 0
        self._bytes = 0

    @property
    def parts(self) -> list[TextPart | ImagePart]:
        """The parts written so far, in order."""
        return list(self._parts)

    @property
    def token_estimate(self) -> int:
        """The sum of the parts' token estimates."""
        return sum(part.tokens for part in self._parts)

    def add_text(self, text: str, *, page: int | None = None) -> None:
        """Write ``text`` as the next text part (``""`` writes nothing).

        Raises:
            ConversionError: ``text_too_large`` when the characters written so
                far plus ``text`` would pass ``MAX_TEXT_CHARS``;
                ``output_too_large`` when its UTF-8 bytes would take the parts
                past ``MAX_DERIVED_BYTES`` (nothing written either way).
            OSError: The part file exists already (or can't be written).
        """
        if not text:
            return
        if self._chars + len(text) > MAX_TEXT_CHARS:
            raise ConversionError("text_too_large")
        name = self._write("txt", text.encode("utf-8"))
        self._chars += len(text)
        self._parts.append(
            TextPart(type="text", file=name, page=page, tokens=estimate_text_tokens(text))
        )

    def add_image(
        self,
        data: bytes,
        *,
        media_type: Literal["image/jpeg", "image/png"],
        width: int,
        height: int,
        page: int | None = None,
        label: str | None = None,
    ) -> None:
        """Write ``data`` (an encoded JPEG or PNG) as the next image part.

        Its tokens are the image's estimate plus the label's text estimate.

        Raises:
            ConversionError: ``output_too_large`` when ``data`` would take the
                parts past ``MAX_DERIVED_BYTES`` (nothing written).
            OSError: The part file exists already (or can't be written).
        """
        name = self._write("jpg" if media_type == "image/jpeg" else "png", data)
        tokens = estimate_image_tokens(width, height)
        if label:
            tokens += estimate_text_tokens(label)
        self._parts.append(
            ImagePart(
                type="image",
                file=name,
                page=page,
                label=label,
                media_type=media_type,
                width=width,
                height=height,
                tokens=tokens,
            )
        )

    def _write(self, extension: str, data: bytes) -> str:
        """Create the next part file exclusively and write ``data``; returns its name.

        Raises:
            ConversionError: ``output_too_large`` when ``data`` would take the
                parts past ``MAX_DERIVED_BYTES`` (no file created).
        """
        if self._bytes + len(data) > MAX_DERIVED_BYTES:
            raise ConversionError("output_too_large")
        name = f"part-{len(self._parts) + 1:04d}.{extension}"
        with os.fdopen(os.open(self._out_dir / name, _PART_FLAGS, _PART_MODE), "wb") as file:
            file.write(data)
        self._bytes += len(data)
        return name
