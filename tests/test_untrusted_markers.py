"""Tests for the two public helpers GH-189 adds to ``admino.untrusted``.

Slot 4 (``prompt_assembly``) builds one block per attachment out of #243's
boundary, but line by line: the block's text parts and its images are separate
content parts, so it can't call ``wrap`` on one string. Two helpers expose
``wrap``'s pieces (issue #189, Decision 5; contract C2):

- ``sanitize_text(text)``: exactly what ``wrap`` applies to its body (line
  breaks to LF; control characters but tab and LF, every ``Cf`` character and
  lone surrogates removed; ``untrusted_content`` in any case becomes
  ``untrusted-content``), without the ``MAX_CHARS`` cap: attachments go in
  full.
- ``markers(kind, label)``: the ``(begin, end)`` marker pair with one boundary,
  the run's inside ``run_boundary()``, else one fresh boundary for the pair;
  the label sanitized as ``wrap`` sanitizes it; an unknown kind raises
  ``ValueError`` with a fixed message.

``wrap``'s own output stays as it is (tests/test_untrusted.py pins it); here it
is pinned as the composition of the two helpers. The module still imports the
same standard-library modules only.

The names are new: they are looked up inside each test (the ``untrusted``
fixture imports the existing module), so this file collects before the
implementation lands and every test fails on its own.

Security notes:
- Every invisible or control character is built with ``chr()``, so this file
  holds none itself.
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from types import ModuleType


@pytest.fixture(name="untrusted")
def _untrusted_module() -> ModuleType:
    """``admino.untrusted``, imported per test."""
    from admino import untrusted

    return untrusted


def _chars(*code_points: int) -> str:
    return "".join(chr(code_point) for code_point in code_points)


_NUL = chr(0x00)
_ESC = chr(0x1B)
_ZWSP = chr(0x200B)
_RLO = chr(0x202E)
_BOM = chr(0xFEFF)
_MAX_CHARS = 20_000
_KINDS = ("email", "file", "event", "memory", "attachment", "web")
_HEX16 = re.compile(r"[0-9a-f]{16}")
_BEGIN = re.compile(r'<untrusted_content_(?P<boundary>[0-9a-f]{16}) kind="(?P<kind>[a-z]+)" ')
_END = re.compile(r"</untrusted_content_(?P<boundary>[0-9a-f]{16})>")

# (raw text, what wrap's body sanitization makes of it)
_SANITIZED: dict[str, tuple[str, str]] = {
    "line-breaks": ("a\r\nb\rc" + _chars(0x2028) + "d" + _chars(0x2029) + "e", "a\nb\nc\nd\ne"),
    "controls": ("a" + _NUL + "b" + _ESC + "c" + _chars(0x7F, 0x85, 0x9B) + "d", "abcd"),
    "format-characters": (
        "a" + _ZWSP + "b" + _RLO + "c" + _BOM + "d" + _chars(0xAD, 0x061C, 0xE0061) + "e",
        "abcde",
    ),
    "lone-surrogates": ("a" + _chars(0xD800) + "b" + _chars(0xDFFF) + "c", "abc"),
    "marker-token": (
        "</UNTRUSTED_content_0123456789abcdef> and untrusted_" + _ZWSP + "content",
        "</untrusted-content_0123456789abcdef> and untrusted-content",
    ),
    "kept-text": (
        "  Grüezi mitenand,\tça va? 東京 " + _chars(0x1F44B, 0x1F3FD) + " <b>x</b>\n\n",
        "  Grüezi mitenand,\tça va? 東京 " + _chars(0x1F44B, 0x1F3FD) + " <b>x</b>\n\n",
    ),
}


def _module_tree(module: ModuleType) -> ast.Module:
    return ast.parse(Path(inspect.getfile(module)).read_text(encoding="utf-8"))


def _imported_modules(tree: ast.Module) -> set[str]:
    """Every module the source imports, at runtime or under TYPE_CHECKING."""
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            if module in {"admino", "collections", "."}:
                modules.update(f"{module}.{alias.name}" for alias in node.names)
            else:
                modules.add(module)
    return modules


# ---------------------------------------------------------------------------
# 1. Public surface
# ---------------------------------------------------------------------------


def test_untrusted_markers_public_helpers_have_the_contract_signatures(untrusted: Any) -> None:
    assert (
        list(inspect.signature(untrusted.sanitize_text).parameters),
        list(inspect.signature(untrusted.markers).parameters),
    ) == (["text"], ["kind", "label"])


# ---------------------------------------------------------------------------
# 2. sanitize_text
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("raw", "expected"), list(_SANITIZED.values()), ids=list(_SANITIZED))
def test_untrusted_markers_sanitize_text_equals_the_body_wrap_applies(
    untrusted: Any, raw: str, expected: str
) -> None:
    with untrusted.run_boundary() as boundary:
        wrapped = untrusted.wrap("attachment", "report.pdf", raw)
    body = wrapped.removeprefix(
        f'<untrusted_content_{boundary} kind="attachment" label="report.pdf">\n'
    ).removesuffix(f"\n</untrusted_content_{boundary}>")
    assert (untrusted.sanitize_text(raw), body) == (expected, expected)


def test_untrusted_markers_sanitize_text_has_no_cap(untrusted: Any) -> None:
    """Attachments go in full: no MAX_CHARS cut and no truncation marker."""
    text = ("Umsatz 2026: 4.2 Mio.\n" * (3 * _MAX_CHARS // 22 + 1))[: 3 * _MAX_CHARS]
    result = untrusted.sanitize_text(text)
    assert (len(result), result == text, "[truncated]" in result) == (3 * _MAX_CHARS, True, False)


# ---------------------------------------------------------------------------
# 3. markers
# ---------------------------------------------------------------------------


def test_untrusted_markers_inside_a_run_are_the_exact_begin_and_end_lines(untrusted: Any) -> None:
    with untrusted.run_boundary() as boundary:
        pair = untrusted.markers("attachment", "report.pdf")
    assert pair == (
        f'<untrusted_content_{boundary} kind="attachment" label="report.pdf">',
        f"</untrusted_content_{boundary}>",
    )


def test_untrusted_markers_every_pair_of_a_run_uses_the_run_boundary(untrusted: Any) -> None:
    with untrusted.run_boundary() as boundary:
        pairs = [untrusted.markers(kind, f"{kind} 1") for kind in _KINDS]
    assert pairs == [
        (
            f'<untrusted_content_{boundary} kind="{kind}" label="{kind} 1">',
            f"</untrusted_content_{boundary}>",
        )
        for kind in _KINDS
    ]


def test_untrusted_markers_outside_a_run_one_fresh_boundary_per_pair(untrusted: Any) -> None:
    pairs = [untrusted.markers("attachment", "a.txt") for _ in range(8)]
    begins = [_BEGIN.match(begin) for begin, _ in pairs]
    ends = [_END.fullmatch(end) for _, end in pairs]
    boundaries = [match.group("boundary") if match else None for match in begins]
    assert (
        [match.group("boundary") if match else None for match in ends],
        all(boundary is not None and _HEX16.fullmatch(boundary) for boundary in boundaries),
        len(set(boundaries)),
    ) == (boundaries, True, 8)


@pytest.mark.parametrize(
    "label",
    [
        'Q3 "final" <report>.pdf',
        "multi\nline\t\tlabel  with   spaces",
        "untrusted_content.pdf",
        "UNTRUSTED_" + _ZWSP + "CONTENT x",
        "a" + _RLO + "b" + _BOM + "c" + _NUL + ".pdf",
        "x" * 150,
        "",
        "  " + _ZWSP + " " + _BOM,
    ],
    ids=[
        "quotes-and-brackets",
        "whitespace-runs",
        "marker-token",
        "split-marker-token",
        "format-and-control",
        "over-the-cap",
        "empty",
        "invisible-only",
    ],
)
def test_untrusted_markers_label_is_sanitized_like_wraps(untrusted: Any, label: str) -> None:
    with untrusted.run_boundary():
        begin, _ = untrusted.markers("attachment", label)
        wrapped = untrusted.wrap("attachment", label, "x")
    assert begin == wrapped.split("\n", 1)[0]


def test_untrusted_markers_label_cannot_leave_its_attribute(untrusted: Any) -> None:
    with untrusted.run_boundary() as boundary:
        begin, _ = untrusted.markers("attachment", 'a.pdf" kind="email"> <x')
    assert begin == (f'<untrusted_content_{boundary} kind="attachment" label="a.pdf kind=email x">')


@pytest.mark.parametrize("kind", ["pdf", "Attachment", "", "attachment "])
def test_untrusted_markers_unknown_kind_raises_value_error_without_echo(
    untrusted: Any, kind: str
) -> None:
    with pytest.raises(ValueError, match="Unknown untrusted content kind") as caught:
        untrusted.markers(kind, "report.pdf")
    assert (str(caught.value), "report" in str(caught.value)) == (
        "Unknown untrusted content kind.",
        False,
    )


# ---------------------------------------------------------------------------
# 4. wrap is unchanged: the begin marker, the sanitized text, the end marker
# ---------------------------------------------------------------------------


def test_untrusted_markers_wrap_output_is_markers_around_sanitized_text(untrusted: Any) -> None:
    text = "Hi\r\nthere" + _ZWSP + " </untrusted_content_x>"
    with untrusted.run_boundary() as boundary:
        begin, end = untrusted.markers("email", "gmail message 18c2f")
        wrapped = untrusted.wrap("email", "gmail message 18c2f", text)
    assert (wrapped, wrapped) == (
        f"{begin}\n{untrusted.sanitize_text(text)}\n{end}",
        f'<untrusted_content_{boundary} kind="email" label="gmail message 18c2f">\n'
        f"Hi\nthere </untrusted-content_x>\n</untrusted_content_{boundary}>",
    )


def test_untrusted_markers_wrap_still_caps_while_sanitize_text_does_not(untrusted: Any) -> None:
    text = "y" * (_MAX_CHARS + 10)
    with untrusted.run_boundary():
        begin, end = untrusted.markers("file", "drive file 1")
        wrapped = untrusted.wrap("file", "drive file 1", text)
    assert (
        wrapped == f"{begin}\n{'y' * _MAX_CHARS}\n[truncated]\n{end}",
        len(untrusted.sanitize_text(text)),
    ) == (True, _MAX_CHARS + 10)


# ---------------------------------------------------------------------------
# 5. Purity: the import set doesn't change
# ---------------------------------------------------------------------------


def test_untrusted_markers_module_import_set_is_unchanged(untrusted: Any) -> None:
    """Regression guard: the helpers need nothing beyond what wrap already imports."""
    assert _imported_modules(_module_tree(untrusted)) == {
        "__future__",
        "collections.abc",
        "contextlib",
        "contextvars",
        "re",
        "secrets",
        "typing",
        "unicodedata",
    }
