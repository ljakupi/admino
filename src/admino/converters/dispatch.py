"""Dispatch one stored attachment to its converter and write the manifest (GH-188, worker side).

Runs in the conversion worker child only (it loads every parser through the
converters).

Inputs: the stored file, its kind, the existing derived directory and the
``ConversionOptions``.
Outputs: the parts the converter wrote into the directory, its
``manifest.json`` (UTF-8 JSON, mode 0600, written once the converter
returned) and the returned ``Manifest``.
Errors: whatever the converter raises (``ConversionError`` with its code, or
an unexpected exception the worker turns into ``processing_error``); no
manifest is written then.

Security notes:
- The manifest holds the part file names, pages, labels, sizes and token
  counts; it lives next to the parts, inside the 0700 derived directory, and
  is created exclusively, never through a symlink.
- Nothing here logs.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Final, assert_never

from admino.converters import common, images, pdf, sheets, text, word
from admino.converters.common import Manifest, PartWriter

if TYPE_CHECKING:
    from pathlib import Path

    from admino.converters.common import ConversionOptions
    from admino.models import AttachmentKind

_FILE_MODE: Final = 0o600
# Exclusive creation that never follows a symlink planted at the name.
_CREATE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


def convert(
    path: Path, kind: AttachmentKind, out_dir: Path, options: ConversionOptions
) -> Manifest:
    """Convert ``path`` with its kind's converter into ``out_dir`` and write the manifest.

    Args:
        path: The stored file.
        kind: Its recorded kind (picks the converter).
        out_dir: The existing, empty derived directory.
        options: The file name and the platform's render and page settings.

    Returns:
        The manifest: version 1, the kind, the converter's page count, the
        parts in order and their token sum.

    Raises:
        ConversionError: The converter's failure code; no manifest is written.
    """
    writer = PartWriter(out_dir)
    page_count = _run_converter(path, kind, writer, options)
    manifest = Manifest(
        version=1,
        kind=kind,
        page_count=page_count,
        token_estimate=writer.token_estimate,
        parts=writer.parts,
    )
    descriptor = os.open(out_dir / common.MANIFEST_NAME, _CREATE_FLAGS, _FILE_MODE)
    with os.fdopen(descriptor, "wb") as file:
        file.write(manifest.model_dump_json().encode("utf-8"))
    return manifest


def _run_converter(
    path: Path, kind: AttachmentKind, writer: PartWriter, options: ConversionOptions
) -> int | None:
    """Run the kind's converter; return its page count (None for kinds without pages)."""
    match kind:
        case "pdf":
            return pdf.convert_pdf(path, writer, options)
        case "docx":
            return word.convert_docx(path, writer, options)
        case "xlsx":
            return sheets.convert_xlsx(path, writer, options)
        case "csv":
            return sheets.convert_csv(path, writer, options)
        case "txt" | "md":
            return text.convert_text(path, writer, options)
        case "png" | "jpeg" | "webp":
            # An image has no pages.
            images.convert_image(path, writer, options, kind=kind)
            return None
        case _:
            assert_never(kind)
