"""Image converter (GH-188): an uploaded PNG, JPEG or WEBP becomes one clean image part.

Runs only in the conversion worker child; the server never imports Pillow.

Inputs: the stored image's path, its recorded kind (``png``, ``jpeg``, ``webp``) and
the ``PartWriter`` of its derived directory.
Outputs: one image part (page and label None): the first frame, its EXIF
orientation applied, RGBA when the image has an alpha channel or transparency
(else RGB), downscaled to fit ``MAX_IMAGE_EDGE`` x ``MAX_IMAGE_EDGE`` (never
upscaled, the size ``Image.thumbnail`` gives the oriented image), saved as JPEG
(quality ``JPEG_QUALITY``) from a JPEG and as PNG from a PNG or WEBP. Returns
None (no pages).

A JPEG larger than its output size is drafted before any pixel is loaded:
libjpeg decodes it at 1/8, 1/4 or 1/2 scale, the smallest whose result still
covers the output size, and that is resized to exactly the output size. The
result has the size the full decode would give, from a fraction of the memory
and time.

Security notes:
- Only the recorded kind's Pillow plugin may open the file, so the detected format
  is the kind's (a JPEG with a multi-picture segment opens as ``MPO``: a JPEG).
- Pillow's own pixel limit (``Image.MAX_IMAGE_PIXELS``) is set to
  ``MAX_IMAGE_PIXELS`` and its warning raised as an error: an image whose header
  declares more pixels fails as ``image_too_large`` when it is opened, before any
  pixel is decoded, and no later decode can exceed the limit.
- The output is encoded from a new image holding only the pixels: no EXIF (GPS),
  ICC profile, XMP, comment, Photoshop block or PNG text chunk reaches the part.
- Malformed EXIF isn't trusted: when Pillow can't read the EXIF, or can't write
  it back without its orientation tag (what ``ImageOps.exif_transpose`` does),
  the image converts as stored, without orientation correction, instead of
  failing. Pixel decode errors are judged apart from it.
- Pillow's errors and messages never propagate: ``corrupted_file`` or
  ``image_too_large``.
"""

from __future__ import annotations

import io
import math
import struct
import warnings
from typing import TYPE_CHECKING, Final

from PIL import ExifTags, Image

from admino.converters import common
from admino.converters.common import ConversionError

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from admino.converters.common import ConversionOptions, PartWriter
    from admino.models import AttachmentKind

# The only Pillow plugin that may open each image kind.
_PLUGINS: Final[dict[str, str]] = {"png": "PNG", "jpeg": "JPEG", "webp": "WEBP"}
# What Pillow raises for a file it can't identify or decode (struct.error and
# TypeError: values its parsers can't unpack or use).
_PILLOW_ERRORS: Final = (OSError, SyntaxError, ValueError, TypeError, struct.error)
_PIXEL_LIMIT_ERRORS: Final = (Image.DecompressionBombError, Image.DecompressionBombWarning)
# EXIF orientation -> the transposition that shows the image upright
# (ImageOps.exif_transpose's table).
_TRANSPOSITIONS: Final[dict[int, Image.Transpose]] = {
    2: Image.Transpose.FLIP_LEFT_RIGHT,
    3: Image.Transpose.ROTATE_180,
    4: Image.Transpose.FLIP_TOP_BOTTOM,
    5: Image.Transpose.TRANSPOSE,
    6: Image.Transpose.ROTATE_270,
    7: Image.Transpose.TRANSVERSE,
    8: Image.Transpose.ROTATE_90,
}
# The transpositions that swap width and height (orientations 5 to 8).
_SWAPPING: Final = frozenset(
    {
        Image.Transpose.TRANSPOSE,
        Image.Transpose.ROTATE_270,
        Image.Transpose.TRANSVERSE,
        Image.Transpose.ROTATE_90,
    }
)
# Image.thumbnail's default: reduce by whole factors while the last resampling
# step still shrinks by at least 2.
_REDUCING_GAP: Final = 2.0


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
    """Decode, convert, downscale and orient the image; returns (encoded bytes, width, height)."""
    # Read at call time: tests lower the limit. Pillow warns between its limit and
    # twice it (and raises above), so the warning is turned into an error here.
    Image.MAX_IMAGE_PIXELS = common.MAX_IMAGE_PIXELS
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        # Opening reads the header only (and checks the pixel limit); Pillow
        # starts at the first frame of an animated file.
        with Image.open(path, formats=[_PLUGINS[kind]]) as source:
            if kind != "jpeg":
                # Only a JPEG is drafted, before its pixels load. The others
                # decode here, outside the EXIF guard: a PNG's getexif() decodes
                # the pixels when its EXIF chunk follows them.
                source.load()
            transposition = _transposition(source)
            target = _target(source.size, transposition)
            box = None
            if kind == "jpeg" and source.size != target:
                # No mode change; the box is the stored image's extent in the
                # decoded pixels (a partial last block), for the resize below.
                drafted = source.draft(None, target)
                box = None if drafted is None else drafted[1]
            image = source.convert("RGBA" if source.has_transparency_data else "RGB")
    if image.size != target:
        image = image.resize(target, Image.Resampling.LANCZOS, box=box, reducing_gap=_REDUCING_GAP)
    if transposition is not None:
        image = image.transpose(transposition)
    with image, Image.frombytes(image.mode, image.size, image.tobytes()) as pixels:
        buffer = io.BytesIO()
        if kind == "jpeg":
            pixels.save(buffer, "JPEG", quality=common.JPEG_QUALITY)
        else:
            pixels.save(buffer, "PNG")
        return buffer.getvalue(), pixels.width, pixels.height


def _transposition(source: Image.Image) -> Image.Transpose | None:
    """The transposition the image's EXIF orientation asks for; None for none.

    None too when the EXIF is malformed: Pillow can't read it, or can't write
    it back without the orientation tag (the steps ``ImageOps.exif_transpose``
    takes). Such metadata isn't trusted, so the image converts as stored. A
    JPEG's EXIF is in its header: nothing here decodes its pixels.
    """
    try:
        exif = source.getexif()
        transposition = _TRANSPOSITIONS.get(exif.get(ExifTags.Base.Orientation, 1))
        if transposition is not None:
            # The source's own EXIF never reaches the output (only its pixels do).
            del exif[ExifTags.Base.Orientation]
            exif.tobytes()
    except MemoryError:
        raise
    except Exception:
        # Pillow's EXIF code raises whatever a malformed value provokes
        # (AttributeError, TypeError, struct.error, ...): its error surface
        # isn't closed.
        return None
    return transposition


def _target(size: tuple[int, int], transposition: Image.Transpose | None) -> tuple[int, int]:
    """The output size, in the stored orientation: the oriented size fitted
    into ``MAX_IMAGE_EDGE`` x ``MAX_IMAGE_EDGE`` as ``Image.thumbnail`` fits it."""
    swapped = transposition in _SWAPPING
    width, height = (size[1], size[0]) if swapped else size
    edge = common.MAX_IMAGE_EDGE
    if width > edge or height > edge:
        width, height = _fit(width, height, edge)
    return (height, width) if swapped else (width, height)


def _fit(width: int, height: int, edge: int) -> tuple[int, int]:
    """``Image.thumbnail``'s size for an image larger than ``edge`` x ``edge``:
    the longer side becomes ``edge``, the other the whole number (at least 1)
    whose ratio is closest to the image's."""
    aspect = width / height
    if aspect <= 1:
        return _closest(edge * aspect, lambda n: abs(aspect - n / edge)), edge
    return edge, _closest(edge / aspect, lambda n: 0 if n == 0 else abs(aspect - edge / n))


def _closest(number: float, error: Callable[[int], float]) -> int:
    """Of ``number`` rounded down or up, the one with the smaller ``error``; at least 1."""
    return max(min(math.floor(number), math.ceil(number), key=error), 1)
