"""Dispatch of one stored file to its converter, and the manifest (GH-188, contract §4.7).

``admino.converters.dispatch.convert(path, kind, out_dir, options) -> Manifest`` runs in the
worker child. Pinned here:

- Routing: pdf -> ``pdf.convert_pdf``; docx -> ``word.convert_docx``; xlsx ->
  ``sheets.convert_xlsx``; csv -> ``sheets.convert_csv``; txt, md -> ``text.convert_text``;
  png, jpeg, webp -> ``images.convert_image``. Exactly one converter runs, with the stored
  path, a ``PartWriter`` that writes into ``out_dir`` and the options object unchanged.
- The ``Manifest`` is built from the writer: ``version`` 1, the requested kind, the
  converter's page count (``None`` for kinds without pages), the parts in order, and
  ``token_estimate`` equal to the sum of the parts' tokens.
- ``out_dir/manifest.json`` is written once the converter has returned (UTF-8 JSON, mode
  0600) and parses back to the returned model. A converter that raises leaves no manifest,
  and its exception (a ``ConversionError`` or anything else) propagates unchanged.
- One small real conversion per family that needs no parser fixture: a txt and a png.

The converters are replaced at every lookup site (their own module attribute, any name in
``dispatch`` bound to them, and any mapping in ``dispatch`` holding them), so the routing
check holds however dispatch looks a converter up. New modules are imported inside the
tests, so the file collects before GH-188 exists.
"""

from __future__ import annotations

import importlib
import io
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType, ModuleType
from typing import TYPE_CHECKING, Any, Final

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

# kind -> (converter module under admino.converters, function name), contract §4.7.
_ROUTES: Final[dict[str, tuple[str, str]]] = {
    "pdf": ("pdf", "convert_pdf"),
    "docx": ("word", "convert_docx"),
    "xlsx": ("sheets", "convert_xlsx"),
    "csv": ("sheets", "convert_csv"),
    "txt": ("text", "convert_text"),
    "md": ("text", "convert_text"),
    "png": ("images", "convert_image"),
    "jpeg": ("images", "convert_image"),
    "webp": ("images", "convert_image"),
}
_CONVERTERS: Final = tuple(sorted(set(_ROUTES.values())))

_FILENAME: Final = "Quartalsbericht Zürich [v2].pdf"
_TEXT_PART: Final = "[a.pdf — page 1]\nalpha beta 2026"
_IMAGE_LABEL: Final = "[a.pdf — page 2]"


def _module(name: str) -> ModuleType:
    return importlib.import_module(f"admino.converters.{name}")


def _common() -> ModuleType:
    return _module("common")


def _options() -> Any:
    return _common().ConversionOptions(filename=_FILENAME, render_dpi=150, max_pages=100)


def _replace_everywhere(
    monkeypatch: pytest.MonkeyPatch,
    module_name: str,
    function_name: str,
    replacement: Callable[..., int | None],
) -> None:
    """Replace a converter in its module and wherever ``dispatch`` holds a reference."""
    module = _module(module_name)
    dispatch = _module("dispatch")
    original = getattr(module, function_name)
    monkeypatch.setattr(module, function_name, replacement)
    for name, value in list(vars(dispatch).items()):
        if value is original:
            monkeypatch.setattr(dispatch, name, replacement)
        elif isinstance(value, Mapping) and any(item is original for item in value.values()):
            patched = {
                key: replacement if item is original else item for key, item in value.items()
            }
            monkeypatch.setattr(
                dispatch,
                name,
                MappingProxyType(patched) if isinstance(value, MappingProxyType) else patched,
            )


def _install_recorders(
    monkeypatch: pytest.MonkeyPatch,
    calls: list[tuple[str, tuple[object, ...], dict[str, object]]],
    *,
    page_count: int | None = None,
    write: Callable[[Any], None] | None = None,
) -> None:
    """Every converter becomes a recorder that writes through the writer it receives."""
    common = _common()

    for module_name, function_name in _CONVERTERS:
        label = f"{module_name}.{function_name}"

        def fake(*args: object, _label: str = label, **kwargs: object) -> int | None:
            calls.append((_label, args, kwargs))
            writers = [
                value for value in (*args, *kwargs.values()) if isinstance(value, common.PartWriter)
            ]
            assert len(writers) == 1
            if write is None:
                writers[0].add_text("routed")
            else:
                write(writers[0])
            return page_count

        _replace_everywhere(monkeypatch, module_name, function_name, fake)


def _two_parts(writer: Any) -> None:
    """A text part on page 1 and a labelled JPEG on page 2."""
    writer.add_text(_TEXT_PART, page=1)
    writer.add_image(
        b"\xff\xd8\xff\xe0 not decoded by dispatch",
        media_type="image/jpeg",
        width=30,
        height=50,
        page=2,
        label=_IMAGE_LABEL,
    )


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


@pytest.fixture
def stored(tmp_path: Path) -> Path:
    """A stored original (its bytes are never read by the recorders)."""
    path = tmp_path / "org" / "0d6a3f9e-2c1b-4f55-9a43-6b1f2a7c9e10"
    path.parent.mkdir()
    path.write_bytes(b"stored bytes")
    return path


@pytest.fixture
def out_dir(stored: Path) -> Path:
    """The existing ``<id>.d`` directory the runner created."""
    path = stored.with_name(stored.name + ".d")
    path.mkdir(mode=0o700)
    return path


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", list(_ROUTES))
def test_converters_dispatch_each_kind_routes_to_its_converter(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path, kind: str
) -> None:
    """Exactly the kind's converter runs, once, with the stored path, the options object
    and a PartWriter whose part lands in out_dir."""
    dispatch = _module("dispatch")
    calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []
    _install_recorders(monkeypatch, calls)
    options = _options()

    dispatch.convert(stored, kind, out_dir, options)

    module_name, function_name = _ROUTES[kind]
    assert [label for label, _, _ in calls] == [f"{module_name}.{function_name}"]
    _, args, kwargs = calls[0]
    values = (*args, *kwargs.values())
    assert [value for value in values if isinstance(value, Path)] == [stored]
    assert [value for value in values if value is options] == [options]
    assert (out_dir / "part-0001.txt").read_bytes() == b"routed"


# ---------------------------------------------------------------------------
# The manifest
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("kind", "page_count"), [("pdf", 2), ("md", None)])
def test_converters_dispatch_manifest_built_from_the_writer(
    monkeypatch: pytest.MonkeyPatch,
    stored: Path,
    out_dir: Path,
    kind: str,
    page_count: int | None,
) -> None:
    """version 1, the kind, the converter's page count, the parts in order and
    token_estimate == the sum of the parts' tokens."""
    common = _common()
    tokens = importlib.import_module("admino.tokens")
    _install_recorders(monkeypatch, [], page_count=page_count, write=_two_parts)

    manifest = _module("dispatch").convert(stored, kind, out_dir, _options())

    text_tokens = tokens.estimate_text_tokens(_TEXT_PART)
    image_tokens = tokens.estimate_image_tokens(30, 50) + tokens.estimate_text_tokens(_IMAGE_LABEL)
    assert manifest == common.Manifest(
        version=1,
        kind=kind,
        page_count=page_count,
        token_estimate=text_tokens + image_tokens,
        parts=[
            common.TextPart(type="text", file="part-0001.txt", page=1, tokens=text_tokens),
            common.ImagePart(
                type="image",
                file="part-0002.jpg",
                page=2,
                label=_IMAGE_LABEL,
                media_type="image/jpeg",
                width=30,
                height=50,
                tokens=image_tokens,
            ),
        ],
    )


def test_converters_dispatch_manifest_json_written_0600_and_parses_back(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path
) -> None:
    """manifest.json is UTF-8 JSON with mode 0600 that parses back to the returned model;
    out_dir holds the parts and the manifest, nothing else."""
    common = _common()
    _install_recorders(monkeypatch, [], page_count=2, write=_two_parts)

    manifest = _module("dispatch").convert(stored, "pdf", out_dir, _options())

    path = out_dir / "manifest.json"
    data = path.read_bytes()
    assert common.MANIFEST_NAME == "manifest.json"
    assert common.Manifest.model_validate_json(data.decode("utf-8")) == manifest
    assert _mode(path) == 0o600
    assert sorted(os.listdir(out_dir)) == ["manifest.json", "part-0001.txt", "part-0002.jpg"]


@pytest.mark.parametrize("error", ["conversion-error", "unexpected"])
def test_converters_dispatch_converter_that_raises_propagates_and_leaves_no_manifest(
    monkeypatch: pytest.MonkeyPatch, stored: Path, out_dir: Path, error: str
) -> None:
    """A converter that fails after writing a part: its exception object propagates
    unchanged and no manifest.json is written."""
    common = _common()
    raised: BaseException = (
        common.ConversionError("corrupted_file")
        if error == "conversion-error"
        else ValueError("parser state")
    )

    def failing(writer: Any) -> None:
        writer.add_text("a first page")
        raise raised

    _install_recorders(monkeypatch, [], write=failing)

    with pytest.raises(type(raised)) as excinfo:
        _module("dispatch").convert(stored, "pdf", out_dir, _options())

    assert excinfo.value is raised
    assert not os.path.lexists(out_dir / "manifest.json")


# ---------------------------------------------------------------------------
# Small real conversions
# ---------------------------------------------------------------------------


def test_converters_dispatch_real_txt_conversion(stored: Path, out_dir: Path) -> None:
    """A txt file converts in process: one text part with the text as is, page None."""
    common = _common()
    tokens = importlib.import_module("admino.tokens")
    text = "Meeting notes 2026\n- budget approved\n"
    stored.write_bytes(text.encode("utf-8"))

    manifest = _module("dispatch").convert(stored, "txt", out_dir, _options())

    estimate = tokens.estimate_text_tokens(text)
    assert manifest == common.Manifest(
        version=1,
        kind="txt",
        page_count=None,
        token_estimate=estimate,
        parts=[common.TextPart(type="text", file="part-0001.txt", page=None, tokens=estimate)],
    )
    assert (out_dir / "part-0001.txt").read_bytes() == text.encode("utf-8")
    assert common.Manifest.model_validate_json((out_dir / "manifest.json").read_bytes()) == manifest


def test_converters_dispatch_real_png_conversion(stored: Path, out_dir: Path) -> None:
    """A tiny png converts in process: one PNG image part with its size, no page or label."""
    from PIL import Image

    common = _common()
    buffer = io.BytesIO()
    Image.new("RGB", (3, 2), (200, 30, 30)).save(buffer, format="PNG")
    stored.write_bytes(buffer.getvalue())

    manifest = _module("dispatch").convert(stored, "png", out_dir, _options())

    assert manifest == common.Manifest(
        version=1,
        kind="png",
        page_count=None,
        token_estimate=1,
        parts=[
            common.ImagePart(
                type="image",
                file="part-0001.png",
                page=None,
                label=None,
                media_type="image/png",
                width=3,
                height=2,
                tokens=1,
            )
        ],
    )
    with Image.open(out_dir / "part-0001.png") as image:
        assert (image.format, image.size) == ("PNG", (3, 2))
