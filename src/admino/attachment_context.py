"""Read an attachment's derived files into the content slot 4 shows (GH-189, Decision 8).

GH-188's conversion leaves each ready attachment's derived files in
``<root>/<org_id>/<attachment_id>.d/``: a ``manifest.json`` that lists the
text and image parts in order, and the part files. A run reads them back here,
once per active attachment, to build the ``AttachmentContent`` that
``prompt_assembly`` wraps into the attachment's block.

Inputs: the attachments root (``attachments.attachments_root()``), the
caller's org id and the chat's active attachments (``chats.ActiveAttachment``,
read from the caller's own rows).
Outputs: ``AttachmentContent``: the row's id, stored name, kind, page count
and token estimate (GH-190: the row's, NULL as 0; the manifest's never
replaces it, so the budget counts what the send rule checked), and the parts
in manifest order (a text part as ``TextContent``; an image part as
``TextContent(label)`` when it has a label, then ``ImageContent`` with the
image's standard base64).
Errors: ``AttachmentUnavailableError``, one error with a fixed text for every
failure: a missing or unreadable file, a symlink, a file that isn't a
regular one (a directory or a FIFO), an invalid manifest, a
manifest kind other than the row's, a text part that isn't strict UTF-8, or
more than ``converters.common.MAX_DERIVED_BYTES`` bytes for one attachment.

Security notes:
- Never follows a symlink: ``<id>.d`` is opened with ``O_DIRECTORY |
  O_NOFOLLOW`` and every file inside it relative to that directory's
  descriptor with ``O_NOFOLLOW``, so a link planted at the directory, the
  manifest or a part (to another org's files, say) is refused. A file must be
  a regular one (``O_NONBLOCK`` keeps a planted FIFO from blocking the open):
  its type is checked on the raw descriptor before any read, so a directory
  or a FIFO at the manifest's or a part's name is refused unread (GH-294,
  Decision 10).
- No descriptor leaks: every descriptor opened here (``<id>.d`` and each file
  in it) is closed on every path, a refusal included (GH-294, Decision 12),
  so repeated reads of a planted attachment can't exhaust the process's
  descriptors.
- Part names come from the validated manifest (``part-NNNN.<ext>``, never a
  path), so a manifest can't name a file outside ``<id>.d``.
- Tenancy: the path is built from the caller's org id and the id of a row the
  caller's ``TenantContext`` read; another org's directory is never opened.
- Bounded: an attachment reads at most ``common.MAX_DERIVED_BYTES`` bytes in
  all (the manifest included), read at call time; no file is read past what
  is left.
- The content is user-provided data: it is never logged, stored or returned
  by an API here. A failure is logged with the attachment id (``safe_log``)
  and the exception's class name only, never its message, a traceback, a
  path or a file name, and ``AttachmentUnavailableError`` hides its cause.
- Runs the disk work in a worker thread (``load_contents``). Imports nothing
  from the server, agent, LLM or tools layers, and no parsing library.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import stat
from typing import TYPE_CHECKING, Final

from admino.attachments import derived_path
from admino.converters import common
from admino.logs import safe_log
from admino.models import AttachmentContent, ImageContent, TextContent

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path
    from uuid import UUID

    from admino.chats import ActiveAttachment

logger = logging.getLogger(__name__)

_DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class AttachmentUnavailableError(Exception):
    """An attachment's derived files can't be read (one error for every failure)."""

    def __init__(self) -> None:
        super().__init__("Attachment content unavailable.")


def _read_file(directory: int, name: str, budget: int) -> bytes:
    """Read the regular file ``name`` of the open directory, at most ``budget`` bytes.

    The type is checked on the raw descriptor, before any file object exists
    and before any read, so a directory or a FIFO planted at ``name`` is
    refused unread (GH-294, Decision 10). The descriptor ``os.open`` returned
    is closed on every path, a refusal included (Decision 12): a file object
    made on a directory's descriptor raises without closing it, which leaked
    one descriptor per read.

    Raises:
        OSError: The file is missing, a symlink or can't be read.
        ValueError: It isn't a regular file or holds more than ``budget`` bytes.
    """
    fd = os.open(name, _FILE_FLAGS, dir_fd=directory)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            msg = "Not a regular file."
            raise ValueError(msg)
        # closefd=False: the finally below is the descriptor's only close, so a
        # file object that fails half-made can neither leak it nor close it twice.
        with os.fdopen(fd, "rb", closefd=False) as file:
            # One byte more than the budget tells a file that doesn't fit.
            data = file.read(budget + 1)
    finally:
        os.close(fd)
    if len(data) > budget:
        msg = "Derived files too large."
        raise ValueError(msg)
    return data


def _read_parts(directory: int, attachment: ActiveAttachment) -> list[TextContent | ImageContent]:
    """The attachment's parts from the open ``<id>.d`` directory, in manifest order.

    Raises:
        OSError: A file can't be read.
        ValueError: An invalid manifest (a ``ValidationError``), another kind
            than the row's, a text part that isn't UTF-8, or files past
            ``common.MAX_DERIVED_BYTES``.
    """
    budget = common.MAX_DERIVED_BYTES
    raw = _read_file(directory, common.MANIFEST_NAME, budget)
    budget -= len(raw)
    manifest = common.Manifest.model_validate_json(raw)
    if manifest.kind != attachment.kind:
        msg = "Manifest kind mismatch."
        raise ValueError(msg)
    parts: list[TextContent | ImageContent] = []
    for part in manifest.parts:
        data = _read_file(directory, part.file, budget)
        budget -= len(data)
        if isinstance(part, common.TextPart):
            text = data.decode("utf-8")
            # TextContent refuses a blank text: a whitespace-only part is left out.
            if text.strip():
                parts.append(TextContent(text=text))
            continue
        if part.label is not None:
            parts.append(TextContent(text=part.label))
        parts.append(
            ImageContent(media_type=part.media_type, data=base64.b64encode(data).decode("ascii"))
        )
    return parts


def read_content(root: Path, org_id: UUID, attachment: ActiveAttachment) -> AttachmentContent:
    """Read one attachment's derived files (synchronous: a worker thread's body).

    Args:
        root: The attachments root.
        org_id: The caller's org (the directory read is ``<root>/<org_id>``).
        attachment: One of the chat's active attachments.

    Returns:
        Its content: the row's id, name, kind, page count and token estimate
        (NULL as 0), and the parts in manifest order.

    Raises:
        AttachmentUnavailableError: On any failure (see the module docstring);
            its cause is hidden and only the id and the failure's class are
            logged.
    """
    try:
        directory = os.open(derived_path(root, org_id, attachment.id), _DIRECTORY_FLAGS)
        try:
            parts = _read_parts(directory, attachment)
        finally:
            os.close(directory)
        return AttachmentContent(
            id=attachment.id,
            filename=attachment.filename,
            kind=attachment.kind,
            page_count=attachment.page_count,
            parts=tuple(parts),
            token_estimate=attachment.token_estimate or 0,
        )
    except (OSError, ValueError) as exc:
        # The class name only: an OSError's message holds the path, a
        # ValidationError's the manifest or the row.
        logger.warning(
            "Attachment %s content unavailable (%s).",
            safe_log(attachment.id),
            type(exc).__name__,
        )
        raise AttachmentUnavailableError from None


async def load_contents(
    root: Path, org_id: UUID, attachments: Sequence[ActiveAttachment]
) -> list[AttachmentContent]:
    """Read every attachment's content in a worker thread, in the given order.

    Args:
        root: The attachments root.
        org_id: The caller's org.
        attachments: The chat's active attachments, in slot order.

    Returns:
        Their contents, in the same order.

    Raises:
        AttachmentUnavailableError: When any of them can't be read.
    """
    return [
        await asyncio.to_thread(read_content, root, org_id, attachment)
        for attachment in attachments
    ]
