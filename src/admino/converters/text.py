"""TXT and MD converter (GH-188): the text as is, without its BOM.

Inputs: the path of a stored ``txt`` or ``md`` upload, the part writer and the
conversion options (unused: plain text has no pages or labels).
Outputs: one text part (none for an empty file); returns no page count.

Security notes:
- Strict UTF-8 (a leading BOM removed): anything else is ``corrupted_file``,
  without the codec's message.
- The size is checked from the open file before it is read: more bytes than
  ``MAX_TEXT_CHARS`` four-byte characters plus a BOM can only be
  ``text_too_large``, so a huge file is never loaded. The character limit
  itself is the part writer's (``common.MAX_TEXT_CHARS``, read at call time).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from admino.converters import common
from admino.converters.common import ConversionError

if TYPE_CHECKING:
    from pathlib import Path

    from admino.converters.common import ConversionOptions, PartWriter

# A UTF-8 character has at most 4 bytes; the BOM adds 3.
_MAX_BYTES_PER_CHAR = 4
_BOM_BYTES = 3


def convert_text(path: Path, writer: PartWriter, options: ConversionOptions) -> int | None:
    """Write the UTF-8 text of ``path`` unchanged (BOM removed) as one text part.

    Returns:
        None: text has no pages.

    Raises:
        ConversionError: ``corrupted_file`` for bytes that aren't UTF-8;
            ``text_too_large`` for more than ``MAX_TEXT_CHARS`` characters.
    """
    with path.open("rb") as file:
        limit = _MAX_BYTES_PER_CHAR * common.MAX_TEXT_CHARS + _BOM_BYTES
        if os.fstat(file.fileno()).st_size > limit:
            raise ConversionError("text_too_large")
        data = file.read()
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ConversionError("corrupted_file") from None
    writer.add_text(text)
    return None
