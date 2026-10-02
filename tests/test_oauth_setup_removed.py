"""The one-time OAuth consent CLI (``admino.oauth_setup``) is removed (GH-162).

Connections are per user now: each user connects their own Google and
Microsoft accounts from the Tools page (OAuth authorize -> callback, bound to
their session). The operator-run CLI wrote one install-wide token and has no
user to bind it to, so it goes, with its tests (decision of 2026-10-01).

What these tests pin down:
- ``importlib.import_module("admino.oauth_setup")`` raises
  ``ModuleNotFoundError`` for that module, and its source file is gone.
- No user-facing instructions still point at it: docs/*.md, README.md and the
  Makefile never mention ``oauth_setup``.
- docs/tools.md and docs/getting-started.md say accounts are connected from
  the Tools page: one paragraph (or list item) names the Tools page
  (``**Tools**``, "Tools page", "Tools tab" or "Tools ->") and "connect".

Doc checks are deliberately loose (case-insensitive, per paragraph) so the
wording stays free; they only fail when the instruction is missing.

Security notes:
- The CLI stored a token no session owned; removing it means every stored
  token was granted by, and is bound to, one signed-in user.
"""

from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

import pytest

import admino

_MODULE = "admino.oauth_setup"
_REPO_ROOT = Path(__file__).resolve().parent.parent
_DOCS = _REPO_ROOT / "docs"
_CONNECT_DOCS = ("tools.md", "getting-started.md")
_BLOCK_START = re.compile(r"^\s*(?:[-*+]\s|\d+[.)]\s|\||#)")
# "Tools -> Connect" style paths; the arrows are built with chr() so they survive
# editing tools verbatim.
_ARROWS = "|".join(re.escape(arrow) for arrow in ("->", chr(0x2192), chr(0x203A), ">"))
_TOOLS_PAGE = re.compile(
    rf"\*\*tools\*\*|\btools\s+(?:page|tab|view|screen)\b|\btools\s*(?:{_ARROWS})",
    re.IGNORECASE,
)
_CONNECT = re.compile(r"\bconnect", re.IGNORECASE)


def _blocks(text: str) -> list[str]:
    """The paragraphs of a Markdown text; every list item, table row and heading is
    its own block. Whitespace collapsed."""
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            if current:
                blocks.append(current)
                current = []
            continue
        if _BLOCK_START.match(line) and current:
            blocks.append(current)
            current = []
        current.append(line.strip())
    if current:
        blocks.append(current)
    return [re.sub(r"\s+", " ", " ".join(block)) for block in blocks]


def _user_facing_files() -> list[Path]:
    return [*sorted(_DOCS.glob("*.md")), _REPO_ROOT / "README.md", _REPO_ROOT / "Makefile"]


class TestOAuthSetupModuleRemoved:
    """The CLI module no longer exists."""

    def test_oauth_setup_import_raises_module_not_found(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delitem(sys.modules, _MODULE, raising=False)

        with pytest.raises(ModuleNotFoundError) as error:
            importlib.import_module(_MODULE)

        assert error.value.name == _MODULE

    def test_oauth_setup_source_file_is_gone(self) -> None:
        package = Path(admino.__file__).resolve().parent

        assert not (package / "oauth_setup.py").exists()
        assert not (package / "oauth_setup").exists()


class TestOAuthSetupNotDocumented:
    """No instruction still tells anyone to run the CLI."""

    def test_oauth_setup_docs_readme_and_makefile_do_not_mention_it(self) -> None:
        files = _user_facing_files()
        offenders = [
            path.relative_to(_REPO_ROOT).as_posix()
            for path in files
            if path.is_file() and "oauth_setup" in path.read_text(encoding="utf-8")
        ]

        assert all(path.is_file() for path in files[-2:])
        assert offenders == []

    @pytest.mark.parametrize("name", _CONNECT_DOCS)
    def test_oauth_setup_docs_point_at_the_tools_page_to_connect(self, name: str) -> None:
        """Accounts are connected from the Tools page ("my connections")."""
        blocks = _blocks((_DOCS / name).read_text(encoding="utf-8"))
        matching = [b for b in blocks if _TOOLS_PAGE.search(b) and _CONNECT.search(b)]

        assert matching, f"docs/{name} never says to connect from the Tools page"
