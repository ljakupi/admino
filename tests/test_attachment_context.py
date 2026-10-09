"""Tests for ``admino.attachment_context`` (GH-189 contract C6, Decision 8).

Issue #189, Decision 8 ("Reading derived files"): one call reads an attachment's
``<id>.d/manifest.json`` and its parts in a worker thread, never through a symlink
(not at ``<id>.d``, the manifest or a part); the manifest must validate as
``converters.common.Manifest`` and its ``kind`` must match the row's; text parts are
strict UTF-8 and whitespace-only ones are skipped; image parts become base64; an
attachment reads at most ``converters.common.MAX_DERIVED_BYTES`` bytes; any failure
is one error, logged with the attachment id and the exception class only (tracker
#139 §5: no file name, path or content in a log line or an error message).

What these tests pin down:

- ``read_content(root, org_id, attachment)`` (synchronous) reads
  ``<root>/<org_id>/<attachment.id>.d`` and returns an ``AttachmentContent`` whose
  ``id``, ``filename``, ``kind`` and ``page_count`` are the ``ActiveAttachment``'s
  (the row's page count wins over the manifest's) and whose ``parts`` follow the
  manifest's order, not the part files' numbering: a text part is
  ``TextContent(text)``; an image part is ``TextContent(label)`` (only when the label
  isn't None) then ``ImageContent(media_type, <standard base64 of the exact bytes>)``;
  whitespace-only text parts (by ``str.strip``, so a no-break space too) are left out.
- Every failure raises ``AttachmentUnavailableError`` with the fixed message
  ``"Attachment content unavailable."`` and no chained exception a traceback would
  show (it would carry a path): a missing ``<id>.d``, manifest or part; ``<id>.d``,
  the manifest or a part being a symlink, even to a valid file; invalid JSON; a
  manifest that fails validation (an extra key; a part file ``"../x"`` naming a real
  file next to ``<id>.d``); a manifest kind other than the row's; a text part that
  isn't UTF-8; parts that together pass ``MAX_DERIVED_BYTES`` (read at call time,
  each part and the manifest alone under it). The same files read fine when the
  limit is their total size.
- Tenancy: the files of the same attachment id under another org's directory are
  never read; the call names the caller's org, so it raises.
- Logs: a failure's log records (formatted with any traceback) carry no file name,
  no part text, no label and no path; a record of the module names the attachment id.
- ``load_contents(root, org_id, attachments)`` returns each attachment's content in
  the given order, calls ``read_content`` for each off the event loop's thread, and
  raises ``AttachmentUnavailableError`` when one attachment is unreadable.

The module and the new names (``admino.models.TextContent``, ``ImageContent``,
``AttachmentContent``; ``admino.chats.ActiveAttachment``) are looked up in fixtures
that fail the test when they are missing, so this file collects before GH-189 is
implemented and every test fails on its own. The derived files are built here in
``tmp_path`` with the ``converters.common`` models (no shared helper).
"""

from __future__ import annotations

import base64
import dataclasses
import json
import logging
import shutil
import struct
import threading
import uuid
import zlib
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import chats, models
from admino.converters import common
from tests.db_fakes import ORG_ID, OTHER_ORG_ID

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path
    from types import ModuleType

_UNAVAILABLE: Final = "Attachment content unavailable."

# Canaries: none of them may reach a log record.
_NAME_CANARY: Final = "CANARY-name-5be1"
_TEXT_CANARY: Final = "CANARY-text-9d04"
_ROOT_CANARY: Final = "CANARY-root-77ac"

_EM_DASH: Final = chr(0x2014)


def _png() -> bytes:
    """A 1x1 PNG (signature plus IHDR, 33 bytes), then three bytes whose standard
    base64 is ``+/+/``: URL-safe base64 would give ``-_-_`` instead."""
    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    chunk = b"IHDR" + header
    return (
        b"\x89PNG\r\n\x1a\n"
        + struct.pack(">I", len(header))
        + chunk
        + struct.pack(">I", zlib.crc32(chunk))
        + b"\xfb\xff\xbf"
    )


# A JFIF head and the end marker (22 bytes: its base64 ends with "==").
_JPEG: Final = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# --- Building derived files -----------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _Text:
    """A text part; its file holds ``text`` (UTF-8 when a str, raw when bytes)."""

    text: str | bytes
    page: int | None = None


@dataclasses.dataclass(frozen=True)
class _Image:
    """An image part with its media type and optional label."""

    data: bytes
    media_type: str
    label: str | None = None
    page: int | None = None


_Part = _Text | _Image


def _derived_files(
    kind: str,
    parts: Sequence[_Part],
    *,
    page_count: int | None = None,
    reverse_names: bool = False,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    """A valid manifest (as a dict) listing ``parts`` in order, and the part files.

    Parts are numbered by position, or backwards with ``reverse_names`` (so the
    manifest's order differs from the files' name order).
    """
    entries: list[common.TextPart | common.ImagePart] = []
    files: dict[str, bytes] = {}
    for index, part in enumerate(parts):
        number = len(parts) - index if reverse_names else index + 1
        if isinstance(part, _Text):
            name = f"part-{number:04d}.txt"
            files[name] = part.text.encode("utf-8") if isinstance(part.text, str) else part.text
            entries.append(common.TextPart(type="text", file=name, page=part.page, tokens=1))
        else:
            extension = "jpg" if part.media_type == "image/jpeg" else "png"
            name = f"part-{number:04d}.{extension}"
            files[name] = part.data
            entries.append(
                common.ImagePart(
                    type="image",
                    file=name,
                    page=part.page,
                    label=part.label,
                    media_type=part.media_type,  # type: ignore[arg-type]
                    width=1,
                    height=1,
                    tokens=1,
                )
            )
    manifest = common.Manifest(
        version=1,
        kind=kind,  # type: ignore[arg-type]
        page_count=page_count,
        token_estimate=len(entries),
        parts=entries,
    )
    loaded: dict[str, Any] = json.loads(manifest.model_dump_json())
    return loaded, files


def _manifest_bytes(manifest: dict[str, Any]) -> bytes:
    return json.dumps(manifest).encode("utf-8")


def _write_derived(
    org_dir: Path,
    attachment_id: uuid.UUID,
    manifest: dict[str, Any] | bytes,
    files: dict[str, bytes],
) -> Path:
    """Write ``<org_dir>/<attachment_id>.d/`` with the part files and the manifest."""
    directory = org_dir / f"{attachment_id}.d"
    directory.mkdir(parents=True)
    for name, data in files.items():
        (directory / name).write_bytes(data)
    raw = manifest if isinstance(manifest, bytes) else _manifest_bytes(manifest)
    (directory / common.MANIFEST_NAME).write_bytes(raw)
    return directory


def _page1(name: str = "report.pdf", extra: str = "") -> str:
    return f"[{name} {_EM_DASH} page 1]\nRevenue rose by 4 %.{extra}"


def _label(name: str = "report.pdf") -> str:
    return f"[{name} {_EM_DASH} page 2]"


def _page3(name: str = "report.pdf") -> str:
    return f"[{name} {_EM_DASH} page 3]\nCosts fell."


def _baseline(name: str = "report.pdf", extra: str = "") -> tuple[dict[str, Any], dict[str, bytes]]:
    """A converted three-page PDF: a text page, a rendered page (JPEG with its label),
    a text page. Files part-0001.txt, part-0002.jpg, part-0003.txt."""
    return _derived_files(
        "pdf",
        [
            _Text(_page1(name, extra), 1),
            _Image(_JPEG, "image/jpeg", _label(name), 2),
            _Text(_page3(name), 3),
        ],
        page_count=3,
    )


# --- Fixtures -----------------------------------------------------------------------


@pytest.fixture()
def ac() -> ModuleType:
    """The module under test, imported lazily (it doesn't exist before GH-189)."""
    try:
        import admino.attachment_context as module
    except ImportError:
        pytest.fail("admino.attachment_context is missing (GH-189 contract C6)")
    return module


def _need(module: ModuleType, name: str) -> Any:
    value = getattr(module, name, None)
    if value is None:
        pytest.fail(f"{module.__name__}.{name} is missing (GH-189 contract C1/C4)")
    return value


@dataclasses.dataclass(frozen=True)
class _Names:
    """The new model classes, looked up at test time."""

    text: Any
    image: Any
    content: Any
    active: Any


@pytest.fixture()
def m() -> _Names:
    return _Names(
        text=_need(models, "TextContent"),
        image=_need(models, "ImageContent"),
        content=_need(models, "AttachmentContent"),
        active=_need(chats, "ActiveAttachment"),
    )


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    """The attachments root; its path carries a canary (a path must never be logged)."""
    path = tmp_path / _ROOT_CANARY / "attachments"
    path.mkdir(parents=True)
    return path


@pytest.fixture()
def org_dir(root: Path) -> Path:
    path = root / str(ORG_ID)
    path.mkdir()
    return path


@pytest.fixture()
def outside(tmp_path: Path) -> Path:
    """A directory outside the attachments root (symlink targets)."""
    path = tmp_path / "outside"
    path.mkdir()
    return path


def _active(
    m: _Names,
    *,
    kind: str = "pdf",
    filename: str = "report.pdf",
    page_count: int | None = None,
    attachment_id: uuid.UUID | None = None,
) -> Any:
    return m.active(
        id=attachment_id or uuid.uuid4(), filename=filename, kind=kind, page_count=page_count
    )


def _chain_hidden(exc: BaseException) -> bool:
    """True when a traceback of ``exc`` shows no chained exception (raised from None,
    or raised outside any except block)."""
    return exc.__cause__ is None and (exc.__context__ is None or exc.__suppress_context__)


def _log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured record, formatted with its traceback (exc_info) if any."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(formatter.format(record) for record in caplog.records)


# --- Breaking a derived directory -----------------------------------------------------


def _move_to_symlink(path: Path, target: Path) -> None:
    """Move ``path`` to ``target`` and leave a symlink to it at ``path``."""
    path.rename(target)
    path.symlink_to(target)


def _rewrite_manifest(directory: Path, change: Callable[[dict[str, Any]], None]) -> None:
    path = directory / common.MANIFEST_NAME
    manifest: dict[str, Any] = json.loads(path.read_bytes())
    change(manifest)
    path.write_bytes(_manifest_bytes(manifest))


def _missing_derived_dir(directory: Path, outside: Path) -> None:
    shutil.rmtree(directory)


def _missing_manifest(directory: Path, outside: Path) -> None:
    (directory / common.MANIFEST_NAME).unlink()


def _missing_part(directory: Path, outside: Path) -> None:
    (directory / "part-0002.jpg").unlink()


def _derived_dir_symlink(directory: Path, outside: Path) -> None:
    real = directory.with_name("real.d")
    directory.rename(real)
    directory.symlink_to(real, target_is_directory=True)


def _manifest_symlink(directory: Path, outside: Path) -> None:
    _move_to_symlink(directory / common.MANIFEST_NAME, outside / common.MANIFEST_NAME)


def _text_part_symlink(directory: Path, outside: Path) -> None:
    _move_to_symlink(directory / "part-0001.txt", outside / "part-0001.txt")


def _image_part_symlink(directory: Path, outside: Path) -> None:
    _move_to_symlink(directory / "part-0002.jpg", outside / "part-0002.jpg")


def _invalid_json(directory: Path, outside: Path) -> None:
    (directory / common.MANIFEST_NAME).write_bytes(b'{"version": 1, "kind": "pdf", "parts": [')


def _manifest_extra_key(directory: Path, outside: Path) -> None:
    _rewrite_manifest(directory, lambda manifest: manifest.update(extra="x"))


def _part_name_outside_pattern(directory: Path, outside: Path) -> None:
    """The first part names "../x", and a readable text file sits at <org_dir>/x."""
    (directory.parent / "x").write_bytes((directory / "part-0001.txt").read_bytes())
    _rewrite_manifest(directory, lambda manifest: manifest["parts"][0].update(file="../x"))


def _manifest_kind_mismatch(directory: Path, outside: Path) -> None:
    _rewrite_manifest(directory, lambda manifest: manifest.update(kind="docx"))


def _text_not_utf8(directory: Path, outside: Path) -> None:
    """The last part (read after the others) holds bytes that aren't UTF-8."""
    (directory / "part-0003.txt").write_bytes(b"Umsatz \xff\xfe gestiegen")


_BREAKERS: Final[dict[str, Callable[[Path, Path], None]]] = {
    "missing-derived-dir": _missing_derived_dir,
    "missing-manifest": _missing_manifest,
    "missing-part": _missing_part,
    "derived-dir-symlink": _derived_dir_symlink,
    "manifest-symlink": _manifest_symlink,
    "text-part-symlink": _text_part_symlink,
    "image-part-symlink": _image_part_symlink,
    "invalid-json": _invalid_json,
    "manifest-extra-key": _manifest_extra_key,
    "part-name-outside-pattern": _part_name_outside_pattern,
    "manifest-kind-mismatch": _manifest_kind_mismatch,
    "text-not-utf8": _text_not_utf8,
}

# The failures whose exception can carry the path (an OSError on <id>.d) or that happen
# after a name, a label or a text was within reach.
_LOGGED_BREAKERS: Final = (
    "missing-derived-dir",
    "missing-part",
    "text-part-symlink",
    "manifest-kind-mismatch",
    "text-not-utf8",
    "invalid-json",
)


# ---------------------------------------------------------------------------
# 1. read_content: what a readable attachment gives
# ---------------------------------------------------------------------------


class TestReadContent:
    def test_attachment_context_text_file_gives_text_parts_in_manifest_order(
        self, ac: ModuleType, m: _Names, root: Path, org_dir: Path
    ) -> None:
        """The manifest lists part-0003, part-0002, part-0001: that order is kept."""
        attachment = _active(m, kind="txt", filename="notes.txt")
        texts = ["First paragraph.", "Second paragraph.", "Third paragraph."]
        manifest, files = _derived_files("txt", [_Text(t) for t in texts], reverse_names=True)
        _write_derived(org_dir, attachment.id, manifest, files)

        content = ac.read_content(root, ORG_ID, attachment)

        assert content == m.content(
            id=attachment.id,
            filename="notes.txt",
            kind="txt",
            page_count=None,
            parts=tuple(m.text(text=text) for text in texts),
        )

    def test_attachment_context_pdf_gives_label_then_image_in_order(
        self, ac: ModuleType, m: _Names, root: Path, org_dir: Path
    ) -> None:
        """A rendered page is its label (a text part) followed by the JPEG as standard
        base64 of the exact bytes, between the text pages."""
        attachment = _active(m, kind="pdf", filename="report.pdf", page_count=3)
        manifest, files = _baseline()
        _write_derived(org_dir, attachment.id, manifest, files)

        content = ac.read_content(root, ORG_ID, attachment)

        assert content.parts == (
            m.text(text=_page1()),
            m.text(text=_label()),
            m.image(media_type="image/jpeg", data=_b64(_JPEG)),
            m.text(text=_page3()),
        )

    def test_attachment_context_image_without_label_adds_no_text_part(
        self, ac: ModuleType, m: _Names, root: Path, org_dir: Path
    ) -> None:
        """A label of None gives the image part alone; its data is standard base64
        (with "+" and "/", never URL-safe)."""
        attachment = _active(m, kind="png", filename="photo.png")
        manifest, files = _derived_files("png", [_Image(_png(), "image/png", None)])
        _write_derived(org_dir, attachment.id, manifest, files)

        content = ac.read_content(root, ORG_ID, attachment)

        assert content.parts == (m.image(media_type="image/png", data=_b64(_png())),)

    def test_attachment_context_whitespace_only_text_parts_are_skipped(
        self, ac: ModuleType, m: _Names, root: Path, org_dir: Path
    ) -> None:
        """Blank by str.strip(): spaces, tabs and newlines, and a no-break space with an
        ideographic space (TextContent refuses both kinds)."""
        attachment = _active(m, kind="md", filename="plan.md")
        manifest, files = _derived_files(
            "md",
            [
                _Text("# Plan"),
                _Text("  \n\t \n"),
                _Text("- step one"),
                _Text(chr(0xA0) + chr(0x3000)),
                _Text("- step two"),
            ],
        )
        _write_derived(org_dir, attachment.id, manifest, files)

        content = ac.read_content(root, ORG_ID, attachment)

        assert content.parts == (
            m.text(text="# Plan"),
            m.text(text="- step one"),
            m.text(text="- step two"),
        )

    def test_attachment_context_identity_and_page_count_come_from_the_row(
        self, ac: ModuleType, m: _Names, root: Path, org_dir: Path
    ) -> None:
        """id, filename, kind and page_count are the ActiveAttachment's: the manifest's
        page count (7 here) doesn't replace the row's (4)."""
        attachment = _active(m, kind="pdf", filename="Bilanz Q3 2026.pdf", page_count=4)
        manifest, files = _baseline()
        manifest["page_count"] = 7
        _write_derived(org_dir, attachment.id, manifest, files)

        content = ac.read_content(root, ORG_ID, attachment)

        assert (content.id, content.filename, content.kind, content.page_count) == (
            attachment.id,
            "Bilanz Q3 2026.pdf",
            "pdf",
            4,
        )


# ---------------------------------------------------------------------------
# 2. read_content: every failure is AttachmentUnavailableError
# ---------------------------------------------------------------------------


class TestUnavailable:
    @pytest.mark.parametrize("breaker", list(_BREAKERS))
    def test_attachment_context_unreadable_derived_files_raise_unavailable(
        self,
        ac: ModuleType,
        m: _Names,
        root: Path,
        org_dir: Path,
        outside: Path,
        breaker: str,
    ) -> None:
        """The baseline PDF reads (see the PDF test); each break makes it one error
        with the fixed message and no chained exception (it would name a path)."""
        attachment = _active(m, kind="pdf", filename="report.pdf", page_count=3)
        manifest, files = _baseline()
        directory = _write_derived(org_dir, attachment.id, manifest, files)
        _BREAKERS[breaker](directory, outside)

        with pytest.raises(ac.AttachmentUnavailableError) as caught:
            ac.read_content(root, ORG_ID, attachment)

        assert (str(caught.value), _chain_hidden(caught.value)) == (_UNAVAILABLE, True)

    def test_attachment_context_parts_over_max_derived_bytes_raise_unavailable(
        self,
        ac: ModuleType,
        m: _Names,
        root: Path,
        org_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two parts of 300 bytes under a limit of 450 (read at call time): each part and
        the manifest fit alone, the parts together don't."""
        attachment = _active(m, kind="pdf", filename="big.pdf", page_count=2)
        manifest, files = _derived_files(
            "pdf",
            [
                _Text("x" * 300, 1),
                _Image(_JPEG + b"\x00" * (300 - len(_JPEG)), "image/jpeg", None, 2),
            ],
            page_count=2,
        )
        assert len(_manifest_bytes(manifest)) < 450
        _write_derived(org_dir, attachment.id, manifest, files)
        monkeypatch.setattr(common, "MAX_DERIVED_BYTES", 450)

        with pytest.raises(ac.AttachmentUnavailableError) as caught:
            ac.read_content(root, ORG_ID, attachment)

        assert str(caught.value) == _UNAVAILABLE

    def test_attachment_context_files_within_max_derived_bytes_read(
        self,
        ac: ModuleType,
        m: _Names,
        root: Path,
        org_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The same kind of files under a limit equal to all their bytes (manifest
        included) read fine: the limit is a total, not a smaller cap."""
        attachment = _active(m, kind="pdf", filename="big.pdf", page_count=2)
        image = _JPEG + b"\x00" * (300 - len(_JPEG))
        manifest, files = _derived_files(
            "pdf",
            [_Text("x" * 300, 1), _Image(image, "image/jpeg", None, 2)],
            page_count=2,
        )
        _write_derived(org_dir, attachment.id, manifest, files)
        total = sum(len(data) for data in files.values()) + len(_manifest_bytes(manifest))
        monkeypatch.setattr(common, "MAX_DERIVED_BYTES", total)

        content = ac.read_content(root, ORG_ID, attachment)

        assert content.parts == (
            m.text(text="x" * 300),
            m.image(media_type="image/jpeg", data=_b64(image)),
        )

    def test_attachment_context_other_orgs_directory_is_never_read(
        self, ac: ModuleType, m: _Names, root: Path, org_dir: Path
    ) -> None:
        """The files sit under root/<other org>/<id>.d; the call names the caller's org."""
        attachment = _active(m, kind="pdf", filename="report.pdf", page_count=3)
        manifest, files = _baseline()
        _write_derived(root / str(OTHER_ORG_ID), attachment.id, manifest, files)

        with pytest.raises(ac.AttachmentUnavailableError) as caught:
            ac.read_content(root, ORG_ID, attachment)

        assert str(caught.value) == _UNAVAILABLE

    @pytest.mark.parametrize("breaker", _LOGGED_BREAKERS)
    def test_attachment_context_failure_logs_no_name_text_or_path(
        self,
        ac: ModuleType,
        m: _Names,
        root: Path,
        org_dir: Path,
        outside: Path,
        caplog: pytest.LogCaptureFixture,
        breaker: str,
    ) -> None:
        """The file name and the labels carry one canary, the first page's text another,
        the root path a third: no record (traceback included) holds any of them, and
        every record of the module names the attachment id."""
        caplog.set_level(logging.DEBUG)
        name = f"{_NAME_CANARY}.pdf"
        attachment = _active(m, kind="pdf", filename=name, page_count=3)
        manifest, files = _baseline(name, extra=f" {_TEXT_CANARY}")
        directory = _write_derived(org_dir, attachment.id, manifest, files)
        _BREAKERS[breaker](directory, outside)

        with pytest.raises(ac.AttachmentUnavailableError):
            ac.read_content(root, ORG_ID, attachment)

        text = _log_text(caplog)
        own = [
            record.getMessage()
            for record in caplog.records
            if record.name.startswith("admino.attachment_context")
        ]
        leaks = [canary for canary in (_NAME_CANARY, _TEXT_CANARY, _ROOT_CANARY) if canary in text]
        assert (leaks, [str(attachment.id) in message for message in own]) == (
            [],
            [True] * len(own),
        )


# ---------------------------------------------------------------------------
# 3. load_contents
# ---------------------------------------------------------------------------


def _three(m: _Names, org_dir: Path) -> tuple[list[Any], list[Any]]:
    """Three readable attachments (ids 3, 1, 2: not in sorted order) and their contents."""
    first = _active(m, kind="txt", filename="c.txt", attachment_id=uuid.UUID(int=3))
    second = _active(m, kind="png", filename="a.png", attachment_id=uuid.UUID(int=1))
    third = _active(m, kind="md", filename="b.md", attachment_id=uuid.UUID(int=2))
    _write_derived(org_dir, first.id, *_derived_files("txt", [_Text("Third file.")]))
    _write_derived(org_dir, second.id, *_derived_files("png", [_Image(_png(), "image/png")]))
    _write_derived(org_dir, third.id, *_derived_files("md", [_Text("# Second file")]))
    contents = [
        m.content(
            id=first.id,
            filename="c.txt",
            kind="txt",
            page_count=None,
            parts=(m.text(text="Third file."),),
        ),
        m.content(
            id=second.id,
            filename="a.png",
            kind="png",
            page_count=None,
            parts=(m.image(media_type="image/png", data=_b64(_png())),),
        ),
        m.content(
            id=third.id,
            filename="b.md",
            kind="md",
            page_count=None,
            parts=(m.text(text="# Second file"),),
        ),
    ]
    return [first, second, third], contents


class TestLoadContents:
    async def test_attachment_context_load_contents_keeps_the_order(
        self, ac: ModuleType, m: _Names, root: Path, org_dir: Path
    ) -> None:
        attachments, expected = _three(m, org_dir)

        result = await ac.load_contents(root, ORG_ID, attachments)

        assert list(result) == expected

    async def test_attachment_context_load_contents_reads_off_the_event_loop(
        self,
        ac: ModuleType,
        m: _Names,
        root: Path,
        org_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """read_content runs once per attachment, never on the event loop's thread."""
        attachments, expected = _three(m, org_dir)
        loop_thread = threading.get_ident()
        calls: list[tuple[int, uuid.UUID]] = []
        original = ac.read_content

        def recording(root: Path, org_id: uuid.UUID, attachment: Any) -> Any:
            calls.append((threading.get_ident(), attachment.id))
            return original(root, org_id, attachment)

        monkeypatch.setattr(ac, "read_content", recording)

        result = await ac.load_contents(root, ORG_ID, attachments)

        assert (
            sorted(attachment_id for _, attachment_id in calls),
            [thread != loop_thread for thread, _ in calls],
            list(result),
        ) == (sorted(a.id for a in attachments), [True] * 3, expected)

    async def test_attachment_context_load_contents_one_unreadable_attachment_raises(
        self, ac: ModuleType, m: _Names, root: Path, org_dir: Path
    ) -> None:
        """The second attachment has no derived files: no partial list, one error."""
        attachments, _ = _three(m, org_dir)
        shutil.rmtree(org_dir / f"{attachments[1].id}.d")

        with pytest.raises(ac.AttachmentUnavailableError) as caught:
            await ac.load_contents(root, ORG_ID, attachments)

        assert str(caught.value) == _UNAVAILABLE
