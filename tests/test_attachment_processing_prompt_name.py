"""Tests for the processing step's display name (GH-189 contract C7, Decision 6).

Issue #189, "File names in the prompt" and Decision 6: ``prompt_assembly.
prompt_filename(name)`` removes every ``Default_Ignorable_Code_Point`` and every
``Cf`` character, then strips outer whitespace; when nothing is left the name is
``attachment``. The conversion's display name (the PDF page markers
``[<name> — page N]`` and the image labels) uses that prompt name: processing
passes ``prompt_filename(<stored name>)`` to the converter, so a hidden character
in a stored name never reaches a converted part.

What these tests pin down:

- ``process_attachment`` builds the ``ProcessingJob`` with ``filename ==
  prompt_filename(<row filename>)``: a stored name carrying a Hangul filler
  (U+3164), a combining grapheme joiner (U+034F) and a variation selector (U+FE0F)
  reaches the processor without them; a name made of such characters and a space
  only reaches it as ``attachment``; an ordinary name (spaces, an em dash,
  parentheses, a decomposed accent whose combining mark is visible and kept)
  reaches it unchanged.
- With the default processor (``convert_stored_file``), the converter's
  ``ConversionOptions.filename`` is the prompt name too.

``prompt_assembly.prompt_filename`` is looked up in a fixture that fails the test
when it is missing, so this file collects before GH-189 is implemented and every
test fails on its own. ``runner.run_conversion`` is replaced by a recorder (no
worker process starts here).
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import prompt_assembly
from tests.db_fakes import ORG_ID, FakeDb

if TYPE_CHECKING:
    import uuid
    from collections.abc import Callable
    from pathlib import Path
    from types import ModuleType

_HANGUL_FILLER: Final = chr(0x3164)
_GRAPHEME_JOINER: Final = chr(0x034F)
_VARIATION_SELECTOR: Final = chr(0xFE0F)
_EM_DASH: Final = chr(0x2014)
_COMBINING_ACUTE: Final = chr(0x0301)

_HIDDEN_PDF: Final = f"Bericht{_HANGUL_FILLER} Q3{_GRAPHEME_JOINER} 2026{_VARIATION_SELECTOR}.pdf"
_HIDDEN_TXT: Final = f"Notizen{_HANGUL_FILLER} Q3{_GRAPHEME_JOINER} 2026{_VARIATION_SELECTOR}.txt"
_ONLY_HIDDEN: Final = f"{_HANGUL_FILLER}{_VARIATION_SELECTOR} {_GRAPHEME_JOINER}"
_ORDINARY: Final = f"Bilanz 2026 {_EM_DASH} Entwurf (v2) Rene{_COMBINING_ACUTE}.pdf"


@pytest.fixture()
def ap() -> ModuleType:
    import admino.attachment_processing as module

    return module


@pytest.fixture()
def prompt_filename() -> Callable[[str], str]:
    """``prompt_assembly.prompt_filename``, looked up at test time (new in GH-189)."""
    function = getattr(prompt_assembly, "prompt_filename", None)
    if function is None:
        pytest.fail("admino.prompt_assembly.prompt_filename is missing (GH-189 contract C3)")
    return function  # type: ignore[no-any-return]


@pytest.fixture()
def db() -> FakeDb:
    return FakeDb()


@pytest.fixture()
def chat_id(db: FakeDb) -> uuid.UUID:
    return db.add_chat(db.add_account(org_id=ORG_ID))


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    path = tmp_path / "attachments"
    path.mkdir()
    return path


def _store(
    db: FakeDb, root: Path, chat_id: uuid.UUID, *, filename: str, kind: str, data: bytes
) -> uuid.UUID:
    """An uploaded attachments row with its stored file at <root>/<org_id>/<id>."""
    attachment_id = db.add_attachment(chat_id, filename=filename, kind=kind, size_bytes=len(data))
    path = root / str(ORG_ID) / str(attachment_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return attachment_id


class _Processor:
    """A sync processor that records each job and returns ``result``."""

    def __init__(self, result: Any) -> None:
        self.result = result
        self.jobs: list[Any] = []
        self.threads: list[int] = []

    def __call__(self, path: Path, kind: str, job: Any) -> Any:
        self.jobs.append(job)
        self.threads.append(threading.get_ident())
        return self.result


class _RunConversion:
    """Stands in for ``runner.run_conversion(path, kind, out_dir, options)``."""

    def __init__(self, result: Any) -> None:
        self.result = result
        self.options: list[Any] = []

    def __call__(self, path: Path, kind: str, out_dir: Path, options: Any) -> Any:
        self.options.append(options)
        return self.result


class TestProcessingPromptName:
    @pytest.mark.parametrize(
        ("stored", "expected"),
        [
            pytest.param(_HIDDEN_PDF, "Bericht Q3 2026.pdf", id="hidden-characters-removed"),
            pytest.param(_ONLY_HIDDEN, "attachment", id="nothing-left-is-attachment"),
            pytest.param(_ORDINARY, _ORDINARY, id="ordinary-name-unchanged"),
        ],
    )
    async def test_attachment_processing_job_filename_is_the_prompt_name(
        self,
        ap: ModuleType,
        prompt_filename: Callable[[str], str],
        db: FakeDb,
        chat_id: uuid.UUID,
        root: Path,
        stored: str,
        expected: str,
    ) -> None:
        """The processor's job carries prompt_filename(<stored name>), not the stored name."""
        attachment_id = _store(db, root, chat_id, filename=stored, kind="pdf", data=b"%PDF-1.7\n")
        processor = _Processor(ap.ProcessedFile())

        await ap.process_attachment(db.pool, root, attachment_id, ORG_ID, processor=processor)

        assert ([job.filename for job in processor.jobs], prompt_filename(stored)) == (
            [expected],
            expected,
        )

    async def test_attachment_processing_converter_options_carry_the_prompt_name(
        self,
        ap: ModuleType,
        db: FakeDb,
        chat_id: uuid.UUID,
        root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The default processor (convert_stored_file) hands the converter the prompt
        name as its display name (the PDF page markers and image labels)."""
        from admino.converters import runner

        db.add_org(ORG_ID, storage_quota_bytes=10**6)
        recorder = _RunConversion(
            runner.ConversionResult(page_count=None, token_estimate=3, derived_bytes=16)
        )
        monkeypatch.setattr(runner, "run_conversion", recorder)
        attachment_id = _store(
            db, root, chat_id, filename=_HIDDEN_TXT, kind="txt", data=b"plain text, nothing else\n"
        )

        await ap.process_attachment(db.pool, root, attachment_id, ORG_ID)

        assert [options.filename for options in recorder.options] == ["Notizen Q3 2026.txt"]
