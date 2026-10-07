"""Token estimator shared by the conversion pipeline and the context budget (GH-188, #190).

A converted attachment's size in model tokens is estimated once, when it is
converted, and stored with the file; #190's budgeting reuses the same rules.

Inputs: a text, or an image's width and height in pixels.
Outputs: a non-negative token count.

Rules (deliberately conservative, without a tokenizer):
- Text: one token per ASCII digit ``0-9`` (Qwen splits numbers into single
  digits) plus one token per ``TEXT_BYTES_PER_TOKEN`` of the remaining UTF-8
  bytes, rounded up once over the whole text. Counting bytes rather than
  characters keeps German/French conservative and CJK near one token per
  character.
- Image: one token per ``IMAGE_PIXELS_PER_TOKEN`` pixels, rounded up.

Security notes: pure functions over the standard library only (no I/O, no
logging), so the server, the conversion worker and later #190 can share them.
"""

from __future__ import annotations

from typing import Final

TEXT_BYTES_PER_TOKEN: Final = 4
IMAGE_PIXELS_PER_TOKEN: Final = 750

_ASCII_DIGITS: Final = "0123456789"


def estimate_text_tokens(text: str) -> int:
    """Estimate the tokens of ``text``: ASCII digits count one each, other bytes 4 per token.

    Args:
        text: Any text (``""`` costs 0).

    Returns:
        ``digits + ceil(rest / TEXT_BYTES_PER_TOKEN)`` where ``rest`` is the
        UTF-8 byte length of ``text`` minus its ASCII digits.
    """
    digits = sum(map(text.count, _ASCII_DIGITS))
    # surrogatepass: a lone surrogate (possible in a str decoded from JSON) is
    # counted as the 3 bytes UTF-8 would give it instead of raising.
    rest = len(text.encode("utf-8", "surrogatepass")) - digits
    return digits + -(-rest // TEXT_BYTES_PER_TOKEN)


def estimate_image_tokens(width: int, height: int) -> int:
    """Estimate the tokens of a ``width`` x ``height`` image: one per 750 pixels, rounded up.

    Raises:
        ValueError: ``width`` or ``height`` is below 1.
    """
    if width < 1 or height < 1:
        raise ValueError("an image is at least 1 x 1 pixels")
    return -(-(width * height) // IMAGE_PIXELS_PER_TOKEN)
