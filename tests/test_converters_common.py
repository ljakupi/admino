"""Tests for ``admino.converters.common`` (GH-188 contract section 3).

The shared base of every converter: limits, failure codes, text and cell
cleaning, the Markdown table builder, the part writer and the manifest models.
What these tests pin down:

- Constants: the contract table exactly (image edge 2048, 64 MP Pillow limit,
  25 MP render bound, JPEG quality 85, 20 usable text characters, 10 M text
  characters, 50 sheets, 1000 rows, 50 columns, 1000 characters per cell, the
  OOXML entry count and declared sizes, ``manifest.json``).
- ``CONVERSION_FAILURES`` is a frozenset of exactly the eight codes and equals
  the ``ConversionFailure`` literal; ``ConversionError(reason)`` keeps the
  reason and its message is the code only; ``ConversionOptions`` is a frozen
  dataclass of ``filename``, ``render_dpi``, ``max_pages``.
- ``clean_text``: CRLF and CR to LF, VT and FF to LF, C0 (but TAB/LF), DEL, C1
  (NEL included), U+FEFF, U+FFFE and U+FFFF removed, spaces and tabs stripped at
  each line end (also when a removed control sat after them), the whole text
  stripped; tabs, leading indentation and blank lines inside are kept; U+00A0
  and U+FFFD (just outside the removed ranges) are kept.
- ``clean_cell``: controls removed, CRLF/CR/LF/TAB/VT/FF each one space (no
  collapsing), stripped, then cut to ``MAX_CELL_CHARS`` characters plus U+2026,
  THEN ``|`` escaped (so 1001 pipes become 1000 escaped pipes plus the
  ellipsis, and 1000 pipes are not cut); the limit is read at call time.
- ``markdown_table``: the contract example byte for byte, padding to the
  longest row (also when the header is the short one), a single row (header
  and separator only), no rows -> ``""``, cells taken as given.
- ``PartWriter``: ``part-NNNN.txt/.jpg/.png`` in addition order, the exact
  bytes (UTF-8 without BOM, CRLF untouched), ``""`` writes nothing and takes
  no index, files mode 0600, an existing file or a symlink planted at the next
  part name refused without following it (the target is neither created nor
  changed), ``text_too_large`` when the running character total would pass
  ``MAX_TEXT_CHARS`` (equal passes, characters not bytes, limit read at call
  time, nothing written), per-part tokens (an image's label counts as text),
  ``parts`` and ``token_estimate``.
- Manifest models: extra keys refused, frozen, parts discriminated by
  ``type`` (an unknown tag is ``union_tag_invalid``), ``version`` 1 only, the
  JSON field names and a JSON round trip, negative tokens, a zero image edge,
  another media type or an unknown kind refused.
- Imports: the module imports only the standard library, pydantic,
  ``admino.tokens`` and ``admino.models``, and importing it in a fresh
  interpreter loads none of PIL, pypdfium2, docx or openpyxl.

The module is imported inside the ``common`` fixture, so this file collects
before it exists and every test fails on its own.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import json
import os
import stat
import subprocess
import sys
import typing
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import ValidationError

if TYPE_CHECKING:
    from types import ModuleType

_ELLIPSIS = chr(0x2026)
_BOM = chr(0xFEFF)
_NONCHAR_FFFE = chr(0xFFFE)
_NONCHAR_FFFF = chr(0xFFFF)
_NBSP = chr(0x00A0)
_REPLACEMENT = chr(0xFFFD)
_EM_DASH = chr(0x2014)

_CONSTANTS: dict[str, object] = {
    "MAX_IMAGE_EDGE": 2048,
    "MAX_IMAGE_PIXELS": 64_000_000,
    "MAX_RENDER_PIXELS": 25_000_000,
    "JPEG_QUALITY": 85,
    "MIN_PAGE_TEXT_CHARS": 20,
    "MAX_TEXT_CHARS": 10_000_000,
    "MAX_SHEETS": 50,
    "MAX_TABLE_ROWS": 1000,
    "MAX_TABLE_COLUMNS": 50,
    "MAX_CELL_CHARS": 1000,
    "MAX_OOXML_ENTRIES": 10_000,
    "MAX_OOXML_ENTRY_BYTES": 67_108_864,
    "MAX_OOXML_TOTAL_BYTES": 268_435_456,
    "MANIFEST_NAME": "manifest.json",
}
_FAILURES = frozenset(
    {
        "corrupted_file",
        "password_protected",
        "too_many_pages",
        "archive_too_large",
        "image_too_large",
        "text_too_large",
        "conversion_timeout",
        "processing_error",
    }
)
_PARSERS = ("PIL", "pypdfium2", "docx", "openpyxl")


@pytest.fixture
def common() -> ModuleType:
    """``admino.converters.common``, imported per test (fails each test until it exists)."""
    import admino.converters.common as module

    return module


@pytest.fixture
def out_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "attachment.d"
    directory.mkdir()
    return directory


def _files(directory: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(directory.iterdir())}


# --- constants and failure codes -------------------------------------------


def test_common_constants_have_the_contract_values(common: ModuleType) -> None:
    assert {name: getattr(common, name, None) for name in _CONSTANTS} == _CONSTANTS


def test_common_conversion_failures_are_exactly_the_eight_codes(common: ModuleType) -> None:
    literal = frozenset(typing.get_args(common.ConversionFailure))
    assert (type(common.CONVERSION_FAILURES), common.CONVERSION_FAILURES, literal) == (
        frozenset,
        _FAILURES,
        _FAILURES,
    )


@pytest.mark.parametrize("reason", ["corrupted_file", "conversion_timeout"])
def test_common_conversion_error_keeps_the_reason_and_says_only_the_code(
    common: ModuleType, reason: str
) -> None:
    exc = common.ConversionError(reason)
    assert (isinstance(exc, Exception), exc.reason, str(exc)) == (True, reason, reason)


def test_common_conversion_options_is_a_frozen_dataclass(common: ModuleType) -> None:
    options = common.ConversionOptions(filename="report.pdf", render_dpi=150, max_pages=100)
    with pytest.raises(dataclasses.FrozenInstanceError):
        options.max_pages = 5
    assert [f.name for f in dataclasses.fields(options)] == [
        "filename",
        "render_dpi",
        "max_pages",
    ]


# --- clean_text --------------------------------------------------------------

_C0_REMOVED = "".join(chr(c) for c in [*range(0x00, 0x09), *range(0x0E, 0x20)])


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a\r\nb\rc", "a\nb\nc"),
        ("a\x0bb\x0cc", "a\nb\nc"),
        ("a" + _C0_REMOVED + "b", "ab"),
        ("a\x7f\x80\x85\x9fb", "ab"),
        ("a" + _BOM + "b" + _NONCHAR_FFFE + "c" + _NONCHAR_FFFF + "d", "abcd"),
        ("one  \t\ntwo \nthree", "one\ntwo\nthree"),
        ("a \r\nb\t\rc", "a\nb\nc"),
        ("a \x00\nb", "a\nb"),
        ("head\n  indented\n\ttabbed\n\n\nlast", "head\n  indented\n\ttabbed\n\n\nlast"),
        ("a\tb\t c", "a\tb\t c"),
        ("\n\n \t Title line \t\n\n", "Title line"),
        ("a" + _NBSP + "b" + _REPLACEMENT + "c", "a" + _NBSP + "b" + _REPLACEMENT + "c"),
        ("\x00 \x0b\t\r\n", ""),
    ],
    ids=[
        "crlf-and-cr-to-lf",
        "vt-and-ff-to-lf",
        "c0-removed",
        "del-and-c1-removed",
        "bom-and-nonchars-removed",
        "line-end-spaces-and-tabs-stripped",
        "line-end-stripped-after-crlf",
        "line-end-stripped-after-removal",
        "indentation-and-blank-lines-kept",
        "tabs-inside-a-line-kept",
        "whole-text-stripped",
        "nbsp-and-replacement-kept",
        "nothing-left",
    ],
)
def test_common_clean_text_applies_each_rule(common: ModuleType, raw: str, expected: str) -> None:
    assert common.clean_text(raw) == expected


# --- clean_cell --------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a\x00b\x1bc\x7fd\x85e" + _BOM + "f", "abcdef"),
        ("a\r\nb", "a b"),
        ("a\rb\nc\td\x0be\x0cf", "a b c d e f"),
        ("a\n\nb", "a  b"),
        (" \t a b \n ", "a b"),
        ("a|b||c", "a\\|b\\|\\|c"),
        ("x" * 1000, "x" * 1000),
        ("x" * 1001, "x" * 1000 + _ELLIPSIS),
        ("|" * 1000, "\\|" * 1000),
        ("|" * 1001, "\\|" * 1000 + _ELLIPSIS),
        (" " + "x" * 1000 + " ", "x" * 1000),
        ("x" * 1000 + "\x00\x00", "x" * 1000),
    ],
    ids=[
        "controls-removed",
        "crlf-is-one-space",
        "each-break-is-one-space",
        "spaces-not-collapsed",
        "stripped",
        "pipes-escaped",
        "at-limit-kept",
        "over-limit-cut-with-ellipsis",
        "escaping-does-not-count-toward-the-limit",
        "cut-before-escaping",
        "stripped-before-the-cut",
        "removed-before-the-cut",
    ],
)
def test_common_clean_cell_applies_each_rule(common: ModuleType, raw: str, expected: str) -> None:
    assert common.clean_cell(raw) == expected


def test_common_clean_cell_reads_the_limit_at_call_time(
    common: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(common, "MAX_CELL_CHARS", 5)
    assert (common.clean_cell("abcde"), common.clean_cell("abcdefg")) == (
        "abcde",
        "abcde" + _ELLIPSIS,
    )


# --- markdown_table -----------------------------------------------------------


def test_common_markdown_table_matches_the_contract_example(common: ModuleType) -> None:
    assert common.markdown_table([["a", "b"], ["1"]]) == "| a | b |\n| --- | --- |\n| 1 |  |"


def test_common_markdown_table_pads_to_the_longest_row(common: ModuleType) -> None:
    assert common.markdown_table([["h"], ["1", "2", "3"], ["4", ""]]) == (
        "| h |  |  |\n| --- | --- | --- |\n| 1 | 2 | 3 |\n| 4 |  |  |"
    )


def test_common_markdown_table_single_row_is_header_and_separator(common: ModuleType) -> None:
    # Cells are taken as given: an already escaped pipe is not escaped again.
    assert common.markdown_table([["a\\|b", ""]]) == "| a\\|b |  |\n| --- | --- |"


def test_common_markdown_table_no_rows_is_empty(common: ModuleType) -> None:
    assert common.markdown_table([]) == ""


# --- PartWriter -----------------------------------------------------------------

_LABEL = f"[a.pdf {_EM_DASH} page 2]"


def _fill(writer: Any) -> None:
    writer.add_text("Grüße 2026\r\n\tzweite Zeile", page=1)
    writer.add_image(
        b"\xff\xd8\xff\xe0jpeg",
        media_type="image/jpeg",
        width=750,
        height=2,
        page=2,
        label=_LABEL,
    )
    writer.add_image(b"\x89PNG\r\n\x1a\npng", media_type="image/png", width=751, height=1)
    writer.add_text("last")


def test_common_part_writer_writes_numbered_parts_with_the_exact_bytes(
    common: ModuleType, out_dir: Path
) -> None:
    _fill(common.PartWriter(out_dir))
    assert _files(out_dir) == {
        "part-0001.txt": "Grüße 2026\r\n\tzweite Zeile".encode(),
        "part-0002.jpg": b"\xff\xd8\xff\xe0jpeg",
        "part-0003.png": b"\x89PNG\r\n\x1a\npng",
        "part-0004.txt": b"last",
    }


def test_common_part_writer_records_parts_and_tokens_in_order(
    common: ModuleType, out_dir: Path
) -> None:
    writer = common.PartWriter(out_dir)
    _fill(writer)
    # Text: 4 digits + ceil(23 other bytes / 4) = 10. Image: 1500 px = 2, plus
    # the label as text (1 digit + ceil(17 / 4) = 6) = 8. 751 px = 2. "last" = 1.
    assert (
        [type(p) for p in writer.parts],
        [p.model_dump() for p in writer.parts],
        writer.token_estimate,
    ) == (
        [common.TextPart, common.ImagePart, common.ImagePart, common.TextPart],
        [
            {"type": "text", "file": "part-0001.txt", "page": 1, "tokens": 10},
            {
                "type": "image",
                "file": "part-0002.jpg",
                "page": 2,
                "label": _LABEL,
                "media_type": "image/jpeg",
                "width": 750,
                "height": 2,
                "tokens": 8,
            },
            {
                "type": "image",
                "file": "part-0003.png",
                "page": None,
                "label": None,
                "media_type": "image/png",
                "width": 751,
                "height": 1,
                "tokens": 2,
            },
            {"type": "text", "file": "part-0004.txt", "page": None, "tokens": 1},
        ],
        21,
    )


def test_common_part_writer_empty_text_writes_nothing_and_takes_no_index(
    common: ModuleType, out_dir: Path
) -> None:
    writer = common.PartWriter(out_dir)
    writer.add_text("")
    before = (list(out_dir.iterdir()), writer.parts, writer.token_estimate)
    writer.add_text("x")
    assert (before, sorted(_files(out_dir)), [p.file for p in writer.parts]) == (
        ([], [], 0),
        ["part-0001.txt"],
        ["part-0001.txt"],
    )


def test_common_part_writer_files_are_mode_0600(common: ModuleType, out_dir: Path) -> None:
    _fill(common.PartWriter(out_dir))
    modes = {p.name: stat.S_IMODE(p.stat().st_mode) for p in out_dir.iterdir()}
    assert modes == dict.fromkeys(
        ["part-0001.txt", "part-0002.jpg", "part-0003.png", "part-0004.txt"], 0o600
    )


def test_common_part_writer_refuses_an_existing_file_at_the_next_name(
    common: ModuleType, out_dir: Path
) -> None:
    (out_dir / "part-0001.txt").write_bytes(b"planted")
    writer = common.PartWriter(out_dir)
    with pytest.raises((OSError, common.ConversionError)):
        writer.add_text("new text")
    assert (_files(out_dir), writer.parts) == ({"part-0001.txt": b"planted"}, [])


@pytest.mark.parametrize(
    ("planted", "target_exists"),
    [("part-0001.txt", False), ("part-0001.txt", True), ("part-0002.jpg", True)],
    ids=["text-dangling-link", "text-link-to-file", "image-link-to-file"],
)
def test_common_part_writer_never_follows_a_symlink_at_the_next_name(
    common: ModuleType, tmp_path: Path, out_dir: Path, planted: str, target_exists: bool
) -> None:
    target = tmp_path / "outside.bin"
    if target_exists:
        target.write_bytes(b"keep")
    writer = common.PartWriter(out_dir)
    if planted == "part-0002.jpg":
        writer.add_text("first")
    (out_dir / planted).symlink_to(target)
    with pytest.raises((OSError, common.ConversionError)):
        if planted.endswith(".txt"):
            writer.add_text("payload")
        else:
            writer.add_image(b"\xff\xd8jpeg", media_type="image/jpeg", width=1, height=1)
    assert (
        (out_dir / planted).is_symlink(),
        target.read_bytes() if target.exists() else None,
        len(writer.parts),
    ) == (True, b"keep" if target_exists else None, 1 if planted == "part-0002.jpg" else 0)


def test_common_part_writer_text_total_may_reach_the_limit_but_not_pass_it(
    common: ModuleType, monkeypatch: pytest.MonkeyPatch, out_dir: Path
) -> None:
    writer = common.PartWriter(out_dir)
    monkeypatch.setattr(common, "MAX_TEXT_CHARS", 10)
    writer.add_text("a" * 6)
    writer.add_text("é" * 4)  # 8 bytes, 4 characters: the total is exactly 10
    with pytest.raises(common.ConversionError) as caught:
        writer.add_text("z")
    assert (caught.value.reason, sorted(_files(out_dir)), len(writer.parts)) == (
        "text_too_large",
        ["part-0001.txt", "part-0002.txt"],
        2,
    )


def test_common_part_writer_text_over_the_limit_writes_nothing(
    common: ModuleType, monkeypatch: pytest.MonkeyPatch, out_dir: Path
) -> None:
    monkeypatch.setattr(common, "MAX_TEXT_CHARS", 5)
    writer = common.PartWriter(out_dir)
    with pytest.raises(common.ConversionError) as caught:
        writer.add_text("abcdef")
    assert (caught.value.reason, list(out_dir.iterdir()), writer.parts) == (
        "text_too_large",
        [],
        [],
    )


# --- manifest models -----------------------------------------------------------

_TEXT_PART = {"type": "text", "file": "part-0001.txt", "page": 1, "tokens": 12}
_IMAGE_PART = {
    "type": "image",
    "file": "part-0002.jpg",
    "page": 2,
    "label": f"[scan.pdf {_EM_DASH} page 2]",
    "media_type": "image/jpeg",
    "width": 1240,
    "height": 1754,
    "tokens": 2907,
}
_MANIFEST = {
    "version": 1,
    "kind": "pdf",
    "page_count": 2,
    "token_estimate": 2919,
    "parts": [_TEXT_PART, _IMAGE_PART],
}


def _model(common: ModuleType, name: str) -> Any:
    return getattr(common, name)


@pytest.mark.parametrize(
    ("name", "payload"),
    [("TextPart", _TEXT_PART), ("ImagePart", _IMAGE_PART), ("Manifest", _MANIFEST)],
    ids=["text-part", "image-part", "manifest"],
)
def test_common_manifest_models_refuse_extra_keys(
    common: ModuleType, name: str, payload: dict[str, object]
) -> None:
    model = _model(common, name)
    model.model_validate(payload)
    with pytest.raises(ValidationError) as caught:
        model.model_validate({**payload, "path": "/etc/passwd"})
    assert [e["type"] for e in caught.value.errors()] == ["extra_forbidden"]


def test_common_manifest_models_are_frozen(common: ModuleType) -> None:
    part = common.TextPart.model_validate(_TEXT_PART)
    with pytest.raises(ValidationError):
        part.tokens = 0


def test_common_manifest_parts_are_discriminated_by_type(common: ModuleType) -> None:
    manifest = common.Manifest.model_validate(_MANIFEST)
    with pytest.raises(ValidationError) as caught:
        common.Manifest.model_validate({**_MANIFEST, "parts": [{**_TEXT_PART, "type": "video"}]})
    assert (
        [type(p) for p in manifest.parts],
        [e["type"] for e in caught.value.errors()],
    ) == ([common.TextPart, common.ImagePart], ["union_tag_invalid"])


@pytest.mark.parametrize("version", [0, 2])
def test_common_manifest_version_other_than_1_is_refused(common: ModuleType, version: int) -> None:
    with pytest.raises(ValidationError):
        common.Manifest.model_validate({**_MANIFEST, "version": version})


def test_common_manifest_json_round_trip_keeps_every_field(common: ModuleType) -> None:
    manifest = common.Manifest.model_validate(_MANIFEST)
    dumped = manifest.model_dump_json()
    assert (json.loads(dumped), common.Manifest.model_validate_json(dumped)) == (
        _MANIFEST,
        manifest,
    )


@pytest.mark.parametrize(
    ("name", "payload", "field", "value"),
    [
        ("TextPart", _TEXT_PART, "tokens", -1),
        ("ImagePart", _IMAGE_PART, "tokens", -1),
        ("ImagePart", _IMAGE_PART, "width", 0),
        ("ImagePart", _IMAGE_PART, "height", 0),
        ("ImagePart", _IMAGE_PART, "media_type", "image/webp"),
        ("Manifest", _MANIFEST, "token_estimate", -1),
        ("Manifest", _MANIFEST, "kind", "exe"),
    ],
    ids=[
        "text-negative-tokens",
        "image-negative-tokens",
        "image-zero-width",
        "image-zero-height",
        "image-webp-media-type",
        "manifest-negative-estimate",
        "manifest-unknown-kind",
    ],
)
def test_common_manifest_models_refuse_out_of_range_values(
    common: ModuleType, name: str, payload: dict[str, object], field: str, value: object
) -> None:
    with pytest.raises(ValidationError) as caught:
        _model(common, name).model_validate({**payload, field: value})
    assert [e["loc"] for e in caught.value.errors()] == [(field,)]


# --- imports --------------------------------------------------------------------


def test_common_module_imports_only_stdlib_pydantic_tokens_and_models(
    common: ModuleType,
) -> None:
    tree = ast.parse(Path(inspect.getfile(common)).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            if module == "admino":
                imported.update(f"admino.{alias.name}" for alias in node.names)
            else:
                imported.add(module)
    allowed_roots = set(sys.stdlib_module_names) | {"__future__", "pydantic"}
    refused = sorted(
        name
        for name in imported
        if name.split(".")[0] not in allowed_roots
        and name not in {"admino.tokens", "admino.models"}
    )
    assert refused == []


def test_common_import_in_a_fresh_interpreter_loads_no_parsing_library(
    common: ModuleType,
) -> None:
    src = Path(inspect.getfile(common)).resolve().parents[2]
    pythonpath = os.pathsep.join(p for p in (str(src), os.environ.get("PYTHONPATH", "")) if p)
    code = (
        "import sys, admino.converters.common; "
        f"print(sorted(m for m in {_PARSERS!r} if m in sys.modules))"
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code],
        capture_output=True,
        env={**os.environ, "PYTHONPATH": pythonpath},
        check=False,
        timeout=120,
    )
    assert (result.returncode, result.stdout.decode().strip()) == (0, "[]")
