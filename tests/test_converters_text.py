"""Tests for ``admino.converters.text`` (GH-188 contract section 4.3): TXT and MD.

``convert_text(path, writer, options)`` is called in-process with a real
``PartWriter`` and the part file is read back as bytes. What these tests pin down:

- The text is kept as is: CRLF, a lone CR, a trailing newline, tabs, trailing
  spaces, blank lines, a form feed and Markdown syntax are written unchanged
  (no ``clean_text``), for a ``.txt`` and a ``.md`` upload alike.
- A leading UTF-8 BOM is removed; only that one (a BOM inside or a second
  leading one stays).
- Bytes that aren't strict UTF-8 (an invalid byte, a truncated sequence at the
  end, an encoded surrogate) -> ``corrupted_file``, nothing written.
- More than ``MAX_TEXT_CHARS`` characters -> ``text_too_large`` with nothing
  written; exactly the limit passes; characters are counted, not bytes, and a
  removed BOM doesn't count (limit monkeypatched small, read at call time).
- An empty file or a BOM alone -> no part; whitespace alone is text.
- One text part, ``page`` None, ``part-0001.txt``; its tokens equal
  ``estimate_text_tokens`` of the text; the converter returns None.

Stored uploads have no extension (``<root>/<org>/<id>``), so the fixture files
don't either. The modules are imported inside fixtures, so this file collects
before they exist and every test fails on its own.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

_UTF8_BOM = b"\xef\xbb\xbf"


@pytest.fixture
def common() -> ModuleType:
    import admino.converters.common as module

    return module


@pytest.fixture
def text_module() -> ModuleType:
    import admino.converters.text as module

    return module


@pytest.fixture
def out_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "out.d"
    directory.mkdir()
    return directory


def _upload(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / str(uuid.uuid4())
    path.write_bytes(data)
    return path


def _convert(
    common: ModuleType, text_module: ModuleType, path: Path, out_dir: Path, filename: str
) -> tuple[Any, Any]:
    writer = common.PartWriter(out_dir)
    options = common.ConversionOptions(filename=filename, render_dpi=150, max_pages=100)
    return text_module.convert_text(path, writer, options), writer


def _files(directory: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(directory.iterdir())}


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("notes.txt", "line one\r\nline two\rthree  \n\n\tindented\tcell \fnext page\n"),
        ("README.md", "# Title\n\n- item *one*  \n- item | two\n\n```\ncode\n```\n"),
    ],
    ids=["txt", "md"],
)
def test_text_convert_keeps_the_text_as_is(
    common: ModuleType,
    text_module: ModuleType,
    tmp_path: Path,
    out_dir: Path,
    filename: str,
    content: str,
) -> None:
    path = _upload(tmp_path, content.encode())
    result, _ = _convert(common, text_module, path, out_dir, filename)
    assert (result, _files(out_dir)) == (None, {"part-0001.txt": content.encode()})


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (_UTF8_BOM + "Grüezi".encode() + _UTF8_BOM + b"mitenand", "Grüezi".encode() + _UTF8_BOM),
        (_UTF8_BOM + _UTF8_BOM + b"mitenand", _UTF8_BOM),
    ],
    ids=["bom-inside-kept", "second-leading-bom-kept"],
)
def test_text_convert_removes_only_the_leading_bom(
    common: ModuleType,
    text_module: ModuleType,
    tmp_path: Path,
    out_dir: Path,
    data: bytes,
    expected: bytes,
) -> None:
    path = _upload(tmp_path, data)
    _convert(common, text_module, path, out_dir, "greeting.txt")
    assert _files(out_dir) == {"part-0001.txt": expected + b"mitenand"}


@pytest.mark.parametrize(
    "data",
    [b"caf\xe9 au lait", b"price: 5 \xe2\x82", b"a\xed\xa0\x80b"],
    ids=["latin-1-byte", "truncated-sequence-at-end", "encoded-surrogate"],
)
def test_text_convert_non_utf8_bytes_fail_as_corrupted(
    common: ModuleType, text_module: ModuleType, tmp_path: Path, out_dir: Path, data: bytes
) -> None:
    path = _upload(tmp_path, data)
    with pytest.raises(common.ConversionError) as caught:
        _convert(common, text_module, path, out_dir, "broken.txt")
    assert (caught.value.reason, list(out_dir.iterdir())) == ("corrupted_file", [])


@pytest.mark.parametrize(
    "data",
    ["a" * 10, "é" * 10, "ü" * 9 + "\n"],
    ids=["ten-ascii", "ten-two-byte-chars", "nine-two-byte-chars-and-newline"],
)
def test_text_convert_exactly_the_limit_passes(
    common: ModuleType,
    text_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    out_dir: Path,
    data: str,
) -> None:
    monkeypatch.setattr(common, "MAX_TEXT_CHARS", 10)
    path = _upload(tmp_path, _UTF8_BOM + data.encode())
    _convert(common, text_module, path, out_dir, "limit.txt")
    assert _files(out_dir) == {"part-0001.txt": data.encode()}


@pytest.mark.parametrize("data", ["a" * 11, "é" * 11], ids=["ascii", "two-byte-chars"])
def test_text_convert_over_the_limit_fails_as_text_too_large(
    common: ModuleType,
    text_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    out_dir: Path,
    data: str,
) -> None:
    monkeypatch.setattr(common, "MAX_TEXT_CHARS", 10)
    path = _upload(tmp_path, data.encode())
    with pytest.raises(common.ConversionError) as caught:
        _convert(common, text_module, path, out_dir, "big.txt")
    assert (caught.value.reason, str(caught.value), list(out_dir.iterdir())) == (
        "text_too_large",
        "text_too_large",
        [],
    )


@pytest.mark.parametrize("data", [b"", _UTF8_BOM], ids=["empty-file", "bom-only"])
def test_text_convert_empty_text_writes_no_part(
    common: ModuleType, text_module: ModuleType, tmp_path: Path, out_dir: Path, data: bytes
) -> None:
    path = _upload(tmp_path, data)
    result, writer = _convert(common, text_module, path, out_dir, "empty.md")
    assert (result, list(out_dir.iterdir()), writer.parts, writer.token_estimate) == (
        None,
        [],
        [],
        0,
    )


def test_text_convert_whitespace_only_is_still_one_part(
    common: ModuleType, text_module: ModuleType, tmp_path: Path, out_dir: Path
) -> None:
    path = _upload(tmp_path, b"\n \t\n")
    _convert(common, text_module, path, out_dir, "blank.txt")
    assert _files(out_dir) == {"part-0001.txt": b"\n \t\n"}


def test_text_convert_writes_one_text_part_with_the_text_token_estimate(
    common: ModuleType, text_module: ModuleType, tmp_path: Path, out_dir: Path
) -> None:
    from admino.tokens import estimate_text_tokens

    content = "Invoice 2026-10 for Zürich: 1,250.00 CHF\n"
    path = _upload(tmp_path, content.encode())
    result, writer = _convert(common, text_module, path, out_dir, "invoice.txt")
    # 12 digits + ceil(30 other bytes / 4) = 20.
    assert (
        result,
        [p.model_dump() for p in writer.parts],
        writer.token_estimate,
        estimate_text_tokens(content),
    ) == (
        None,
        [{"type": "text", "file": "part-0001.txt", "page": None, "tokens": 20}],
        20,
        20,
    )
