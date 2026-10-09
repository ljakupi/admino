"""Test helper: an attachment's derived artifacts on disk, as GH-188 leaves them (GH-189).

A converted attachment lives under ``<root>/<org_id>/<attachment_id>.d/``: numbered
part files (``part-NNNN.txt`` / ``.jpg`` / ``.png``) and ``manifest.json``, a
``admino.converters.common.Manifest`` that lists them in order with their token
estimates (``admino.tokens``). GH-189's slot 4 reads them back (contract C6), so the
prompt, server and agent tests seed them with this helper instead of running a
converter.

Inputs: the attachments root, the org and attachment ids, the attachment kind,
its page count and the parts: ``("text", text, page)`` and ``("image",
data_bytes, media_type, page, label)`` tuples, in order.
Outputs: ``write_derived`` returns the ``<attachment_id>.d`` directory it wrote;
``png_bytes()`` / ``jpeg_bytes()`` return tiny valid images (Pillow).

Behaviour:
- The directories are created 0700 (missing parents too), every file 0600 and
  exclusively (never through a symlink), like the converter's ``PartWriter``
  and ``dispatch.convert``; the manifest is ``Manifest.model_dump_json()``.
- Text parts are written as UTF-8 exactly as given (an empty or whitespace-only
  text too, so a reader that skips them can be tested); their tokens are
  ``estimate_text_tokens(text)``.
- Image parts keep their bytes; width and height are read with Pillow (bytes
  Pillow can't read count as 1 x 1, so a test can seed a broken image); their
  tokens are ``estimate_image_tokens(width, height)`` plus the label's text
  estimate, as ``PartWriter.add_image`` computes them.
- Only this module and tests/db_fakes.py are the groundwork writer's: other
  test files import them, never edit them.

Security notes: test infrastructure only; files are written under the given
root (a pytest ``tmp_path``), nothing else is touched.
"""

from __future__ import annotations

import io
import os
from typing import TYPE_CHECKING, Any, Final, Literal

from admino.converters.common import ImagePart, Manifest, TextPart
from admino.tokens import estimate_image_tokens, estimate_text_tokens

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path
    from uuid import UUID

    from admino.models import AttachmentKind

_DIRECTORY_MODE: Final = 0o700
_FILE_MODE: Final = 0o600
_CREATE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_EXTENSIONS: Final[dict[str, str]] = {"image/jpeg": "jpg", "image/png": "png"}


def _write_file(path: Path, data: bytes) -> None:
    """Create ``path`` exclusively (0600, never through a symlink) and write ``data``."""
    with os.fdopen(os.open(path, _CREATE_FLAGS, _FILE_MODE), "wb") as file:
        file.write(data)


def _image_size(data: bytes) -> tuple[int, int]:
    """The image's (width, height) as Pillow reads it; (1, 1) when it can't."""
    from PIL import Image, UnidentifiedImageError

    try:
        with Image.open(io.BytesIO(data)) as image:
            width, height = image.size
    except (UnidentifiedImageError, OSError, ValueError):
        return 1, 1
    return max(width, 1), max(height, 1)


def write_derived(
    root: Path,
    org_id: UUID,
    attachment_id: UUID,
    *,
    kind: AttachmentKind,
    parts: Sequence[tuple[Any, ...]],
    page_count: int | None = None,
) -> Path:
    """Write an attachment's derived directory: its part files and ``manifest.json``.

    Args:
        root: The attachments root (a test's ``tmp_path``).
        org_id: The attachment's org.
        attachment_id: The attachment.
        kind: The manifest's kind (match the row's for a readable attachment).
        parts: In order, ``("text", text, page)`` and
            ``("image", data_bytes, media_type, page, label)`` tuples;
            ``media_type`` is ``image/jpeg`` or ``image/png``, ``page`` and
            ``label`` may be None.
        page_count: The manifest's page count (None for kinds without pages).

    Returns:
        The ``<root>/<org_id>/<attachment_id>.d`` directory.
    """
    out_dir = root / str(org_id) / f"{attachment_id}.d"
    out_dir.parent.mkdir(parents=True, exist_ok=True, mode=_DIRECTORY_MODE)
    out_dir.mkdir(mode=_DIRECTORY_MODE)
    listed: list[TextPart | ImagePart] = []
    for index, part in enumerate(parts, start=1):
        if part[0] == "text":
            _, text, page = part
            name = f"part-{index:04d}.txt"
            _write_file(out_dir / name, text.encode("utf-8"))
            listed.append(
                TextPart(type="text", file=name, page=page, tokens=estimate_text_tokens(text))
            )
            continue
        assert part[0] == "image", f"unknown part type {part[0]!r}"
        _, data, media_type, page, label = part
        name = f"part-{index:04d}.{_EXTENSIONS[media_type]}"
        _write_file(out_dir / name, data)
        width, height = _image_size(data)
        tokens = estimate_image_tokens(width, height)
        if label:
            tokens += estimate_text_tokens(label)
        listed.append(
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
    manifest = Manifest(
        version=1,
        kind=kind,
        page_count=page_count,
        token_estimate=sum(part.tokens for part in listed),
        parts=listed,
    )
    _write_file(out_dir / "manifest.json", manifest.model_dump_json().encode("utf-8"))
    return out_dir


def _encoded(image_format: Literal["PNG", "JPEG"]) -> bytes:
    """A tiny (4 x 3) RGB image in ``image_format``."""
    from PIL import Image

    buffer = io.BytesIO()
    Image.new("RGB", (4, 3), (200, 30, 30)).save(buffer, format=image_format)
    return buffer.getvalue()


def png_bytes() -> bytes:
    """A tiny valid PNG (4 x 3 pixels)."""
    return _encoded("PNG")


def jpeg_bytes() -> bytes:
    """A tiny valid JPEG (4 x 3 pixels)."""
    return _encoded("JPEG")
