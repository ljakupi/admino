"""The conversion worker: the child process that parses one attachment (GH-188).

``converters.runner`` starts ``python -P -s -m admino.converters.worker`` for
each file, with the job on stdin. This is the only process that loads the
parsers (pypdfium2, Pillow, python-docx, openpyxl, through ``dispatch``).

Inputs: one JSON job on stdin, ``{"path", "kind", "out_dir", "filename",
"render_dpi", "max_pages"}`` (validated, extra keys refused).
Outputs: the parts and the manifest in ``out_dir`` (``dispatch.convert``) and
one result line on stdout: ``{"ok": true, "page_count", "token_estimate"}`` or
``{"ok": false, "reason"}``. The exit status is 0 for both and 1, with
nothing on stdout, for a malformed job or an unexpected error.

Security notes:
- On Linux the child first makes itself the OOM killer's first choice, so a
  file that exhausts memory costs this child, never the server.
- Only fixed codes reach stdout: an exception's message (a path, a file name)
  never does. The runner discards stderr and kills the child after its
  timeout.
- The environment holds no secret (the runner passes ``PYTHONPATH`` only).
"""

from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path
from typing import BinaryIO, Final

from pydantic import BaseModel, ConfigDict, ValidationError

from admino.converters import dispatch
from admino.converters.common import ConversionError, ConversionOptions
from admino.models import AttachmentKind  # noqa: TC001 — Pydantic resolves it at runtime

OOM_SCORE_ADJ_PATH: Final = Path("/proc/self/oom_score_adj")

# The highest score: this child is killed first when memory runs out.
_OOM_SCORE: Final = "1000"


class _Job(BaseModel):
    """The job the runner writes on stdin (strict: JSON integers only for the numbers)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    path: str
    kind: AttachmentKind
    out_dir: str
    filename: str
    render_dpi: int
    max_pages: int


def main(stdin: BinaryIO, stdout: BinaryIO) -> int:
    """Run one conversion job: read it from ``stdin``, write its result line to ``stdout``.

    Args:
        stdin: The job, one JSON object.
        stdout: Receives the result line.

    Returns:
        0 when a result line was written (converted or refused with a code);
        1, with nothing written, for a malformed job or an unexpected error.
    """
    _raise_oom_score()
    try:
        job = _Job.model_validate_json(stdin.read())
    except ValidationError:
        return 1
    options = ConversionOptions(
        filename=job.filename, render_dpi=job.render_dpi, max_pages=job.max_pages
    )
    try:
        manifest = dispatch.convert(Path(job.path), job.kind, Path(job.out_dir), options)
    except ConversionError as exc:
        _write(stdout, {"ok": False, "reason": exc.reason})
        return 0
    except Exception:
        # MemoryError included: the runner turns exit status 1 into
        # processing_error; the message (a path, a file name) goes nowhere.
        return 1
    _write(
        stdout,
        {"ok": True, "page_count": manifest.page_count, "token_estimate": manifest.token_estimate},
    )
    return 0


def _raise_oom_score() -> None:
    """Make this process the OOM killer's first choice (Linux); elsewhere nothing happens.

    ``OOM_SCORE_ADJ_PATH`` is read at call time. A missing or unwritable file
    is ignored: the conversion runs anyway.
    """
    with contextlib.suppress(OSError):
        OOM_SCORE_ADJ_PATH.write_text(_OOM_SCORE, encoding="ascii")


def _write(stdout: BinaryIO, result: dict[str, object]) -> None:
    """Write one result object and its newline (the runner accepts exactly one line)."""
    stdout.write(json.dumps(result).encode("utf-8") + b"\n")


if __name__ == "__main__":
    sys.exit(main(sys.stdin.buffer, sys.stdout.buffer))
