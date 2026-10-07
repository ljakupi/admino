"""Image converter (GH-188): an uploaded PNG, JPEG or WEBP becomes one clean image part.

Runs only in the conversion worker child; the server never imports Pillow.

Inputs: the stored image's path, its recorded kind (``png``, ``jpeg``, ``webp``) and
the ``PartWriter`` of its derived directory.
Outputs: one image part (page and label None): the first frame, its EXIF
orientation applied, RGBA when the image has an alpha channel or transparency
(else RGB), downscaled to fit ``MAX_IMAGE_EDGE`` x ``MAX_IMAGE_EDGE`` (never
upscaled), saved as JPEG (quality ``JPEG_QUALITY``) from a JPEG and as PNG from a
PNG or WEBP. Returns None (no pages).

Security notes:
- Only the recorded kind's Pillow plugin may open the file, so the detected format
  is the kind's (a JPEG with a multi-picture segment opens as ``MPO``: a JPEG).
- Pillow's own pixel limit (``Image.MAX_IMAGE_PIXELS``) is set to
  ``MAX_IMAGE_PIXELS`` and its warning raised as an error: an image whose header
  declares more pixels fails as ``image_too_large`` when it is opened, before any
  pixel is decoded, and no later decode can exceed the limit.
- The output is encoded from a new image holding only the pixels: no EXIF (GPS),
  ICC profile, XMP, comment, Photoshop block or PNG text chunk reaches the part.
- Pillow's errors and messages never propagate: ``corrupted_file`` or
  ``image_too_large``.
"""

from __future__ import annotations

import io
import struct
import warnings
from typing import TYPE_CHECKING, Final

from PIL import Image, ImageOps

from admino.converters import common
from admino.converters.common import ConversionError

if TYPE_CHECKING:
    from pathlib import Path

    from admino.converters.common import ConversionOptions, PartWriter
    from admino.models import AttachmentKind

# The only Pillow plugin that may open each image kind.
_PLUGINS: Final[dict[str, str]] = {"png": "PNG", "jpeg": "JPEG", "webp": "WEBP"}
# What Pillow raises for a file it can't identify or decode; TypeError comes from
# exif_transpose rewriting a malformed EXIF value after removing the orientation.
_PILLOW_ERRORS: Final = (OSError, SyntaxError, ValueError, TypeError, struct.error)
_PIXEL_LIMIT_ERRORS: Final = (Image.DecompressionBombError, Image.DecompressionBombWarning)


def convert_image(
    path: Path, writer: PartWriter, options: ConversionOptions, *, kind: AttachmentKind
) -> int | None:
    """Convert the image at ``path`` (recorded as ``kind``) into one image part.

    ``options`` is not used: an image has no page marker and no page limit (the
    parameter keeps the converters' common signature).

    Returns:
        None: an image has no pages.

    Raises:
        ConversionError: ``image_too_large`` (more than ``MAX_IMAGE_PIXELS``) or
            ``corrupted_file`` (another format than ``kind``, unreadable data).
    """
    try:
        data, width, height = _reencode(path, kind)
    except _PIXEL_LIMIT_ERRORS:
        raise ConversionError("image_too_large") from None
    except _PILLOW_ERRORS:
        raise ConversionError("corrupted_file") from None
    media_type: Final = "image/jpeg" if kind == "jpeg" else "image/png"
    writer.add_image(data, media_type=media_type, width=width, height=height)
    return None


def _reencode(path: Path, kind: AttachmentKind) -> tuple[bytes, int, int]:
    """Decode, orient, convert and downscale the image; returns (encoded bytes, width, height)."""
    # Read at call time: tests lower the limit. Pillow warns between its limit and
    # twice it (and raises above), so the warning is turned into an error here.
    Image.MAX_IMAGE_PIXELS = common.MAX_IMAGE_PIXELS
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        # Opening reads the header only (and checks the pixel limit); Pillow
        # starts at the first frame of an animated file.
        with (
            Image.open(path, formats=[_PLUGINS[kind]]) as source,
            ImageOps.exif_transpose(source) as oriented,
        ):
            image = oriented.convert("RGBA" if oriented.has_transparency_data else "RGB")
    with image:
        edge = common.MAX_IMAGE_EDGE
        image.thumbnail((edge, edge), Image.Resampling.LANCZOS)
        with Image.frombytes(image.mode, image.size, image.tobytes()) as pixels:
            buffer = io.BytesIO()
            if kind == "jpeg":
                pixels.save(buffer, "JPEG", quality=common.JPEG_QUALITY)
            else:
                pixels.save(buffer, "PNG")
            return buffer.getvalue(), pixels.width, pixels.height
