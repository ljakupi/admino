"""``make run`` stores uploads under the checkout (GH-281, Decision 9; contract A8).

Issue #281: "``make run`` sets ``ADMINO_ATTACHMENTS_ROOT`` to a writable directory
under the checkout (git-ignored), so uploads work natively". Decision 9:
``ADMINO_ATTACHMENTS_ROOT ?= $(CURDIR)/data/attachments``; the directory is created
with mode 0700 before the app starts, and an exported value wins. What this file
pins, from a dry run (``make -n run``) of a copy of the Makefile in ``tmp_path`` (so
``$(CURDIR)`` is that directory and nothing in the checkout is touched):

- the app command (``python -m admino.main``) still runs through ``env -u
  PG_PASSWORD`` and gets ``ADMINO_ATTACHMENTS_ROOT=<checkout>/data/attachments`` in
  its own environment; migrate's command is printed first (``run: migrate``);
- before the app command, the recipe creates that directory with mode 0700
  (``mkdir`` with ``-m 700``/``--mode``, ``install -d -m``, a later ``chmod 700``, or
  ``umask 077`` before the ``mkdir``);
- with ``ADMINO_ATTACHMENTS_ROOT`` exported, the app and the ``mkdir`` use that value;
- the dry run executes nothing (no ``data`` directory appears), and ``data/`` is
  git-ignored by the repository's .gitignore (checked in a throwaway repository
  holding only that file, with the global and system git configs switched off).

The recipe's printed lines are tokenized with ``shlex`` (backslash continuations
joined, ``;``/``&&``/``||``/``|`` separate commands).
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Final

_REPO: Final = Path(__file__).resolve().parents[1]
_APP_MODULE: Final = "admino.main"
_MIGRATE_MODULE: Final = "admino.migrate"
_VARIABLE: Final = "ADMINO_ATTACHMENTS_ROOT"
_MODES_0700: Final = frozenset({"700", "0700", "u=rwx,go=", "u=rwx,g=,o=", "u=rwx,go-rwx"})
_UMASKS_077: Final = frozenset({"077", "0077"})
_SEPARATORS: Final = frozenset({";", "&&", "||", "|", "&", "(", ")"})
# Make variables of an outer make (``make check`` runs pytest) must not reach the dry run.
_OUTER_MAKE_VARIABLES: Final = frozenset(
    {_VARIABLE, "MAKEFLAGS", "MFLAGS", "MAKELEVEL", "GNUMAKEFLAGS", "MAKEOVERRIDES"}
)
_ASSIGNMENT_RE: Final = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", re.DOTALL)


def _tool(name: str) -> str:
    path = shutil.which(name)
    assert path is not None, f"{name} is not installed"
    return path


def _checkout(tmp_path: Path) -> Path:
    """A directory holding a copy of the repository's Makefile (the dry run's CURDIR)."""
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    shutil.copyfile(_REPO / "Makefile", checkout / "Makefile")
    return checkout


def _dry_run(checkout: Path, exported_root: str | None = None) -> list[str]:
    """``make -n run`` in ``checkout``: the printed recipe, one logical line each."""
    env = {key: value for key, value in os.environ.items() if key not in _OUTER_MAKE_VARIABLES}
    if exported_root is not None:
        env[_VARIABLE] = exported_root
    completed = subprocess.run(  # noqa: S603
        [_tool("make"), "-n", "run"],
        cwd=checkout,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return _logical_lines(completed.stdout)


def _logical_lines(text: str) -> list[str]:
    lines: list[str] = []
    buffer = ""
    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        lines.append(buffer + line)
        buffer = ""
    if buffer:
        lines.append(buffer)
    return [line for line in lines if line.strip()]


def _commands(line: str) -> list[list[str]]:
    """The simple commands of one printed recipe line."""
    lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|()")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    commands: list[list[str]] = []
    current: list[str] = []
    for token in lexer:
        if token in _SEPARATORS:
            if current:
                commands.append(current)
            current = []
        else:
            current.append(token)
    if current:
        commands.append(current)
    return commands


def _module_index(words: list[str], module: str) -> int | None:
    """The index of ``-m <module>`` in a command, or None."""
    for index in range(1, len(words)):
        if words[index] == module and words[index - 1] == "-m":
            return index
    return None


def _app_start(lines: list[str]) -> tuple[int, list[str]]:
    """(line number, words) of the one command that starts ``python -m admino.main``."""
    found = [
        (number, words)
        for number, line in enumerate(lines)
        for words in _commands(line)
        if _module_index(words, _APP_MODULE) is not None
    ]
    assert len(found) == 1, lines
    return found[0]


def _app_environment(words: list[str]) -> dict[str, object]:
    """What the app command does to its environment: the ``VAR=value`` words before
    the interpreter (prefix assignments and ``env``'s operands), and whether ``env``
    unsets PG_PASSWORD."""
    module_at = _module_index(words, _APP_MODULE)
    assert module_at is not None
    before = words[: module_at - 2]
    assignments = [
        (match.group(1), match.group(2))
        for word in before
        if (match := _ASSIGNMENT_RE.fullmatch(word)) is not None
    ]
    unsets_owner_password = "env" in before and any(
        (word == "-u" and index + 1 < len(before) and before[index + 1] == "PG_PASSWORD")
        or word in ("-uPG_PASSWORD", "--unset=PG_PASSWORD")
        for index, word in enumerate(before)
    )
    return {
        "unsets_PG_PASSWORD": unsets_owner_password,
        "roots": [value for name, value in assignments if name == _VARIABLE],
    }


def _option_value(words: list[str], short: str, long: str) -> str | None:
    for index, word in enumerate(words):
        if word == short and index + 1 < len(words):
            return words[index + 1]
        if word.startswith(short) and len(word) > len(short) and not word.startswith("--"):
            return word[len(short) :]
        if word.startswith(f"{long}="):
            return word.split("=", 1)[1]
    return None


def _creates_private_directory(lines: list[str], root: str, before_line: int) -> bool:
    """Whether a printed command before ``before_line`` creates ``root`` with mode 0700."""
    created = mode = False
    for line in lines[:before_line]:
        umask_077 = False
        for words in _commands(line):
            command = words[0]
            operands = [word.rstrip("/") for word in words[1:] if not word.startswith("-")]
            if command == "umask" and operands[:1] and operands[0] in _UMASKS_077:
                umask_077 = True
            elif command == "mkdir" and root in operands:
                created = True
                mode = mode or umask_077 or _option_value(words, "-m", "--mode") in _MODES_0700
            elif command == "install" and "-d" in words and root in operands:
                created = True
                mode = mode or _option_value(words, "-m", "--mode") in _MODES_0700
            elif command == "chmod" and created and operands[:1] and operands[0] in _MODES_0700:
                mode = mode or root in operands[1:]
    return created and mode


# Recipe forms the checks must accept, and ones they must refuse (positive control: a
# check that parses nothing can't pass).
_SAMPLE_ROOT: Final = "/x/data/attachments"
_ACCEPTED_RECIPES: Final[tuple[str, ...]] = (
    f"mkdir -p -m 700 {_SAMPLE_ROOT}\n"
    f'env -u PG_PASSWORD ADMINO_ATTACHMENTS_ROOT="{_SAMPLE_ROOT}" python -m admino.main\n',
    f"mkdir -p {_SAMPLE_ROOT} && chmod 0700 {_SAMPLE_ROOT}\n"
    f"ADMINO_ATTACHMENTS_ROOT={_SAMPLE_ROOT} env -u PG_PASSWORD python -m admino.main\n",
    f"install -d -m 0700 {_SAMPLE_ROOT}\n"
    f"env --unset=PG_PASSWORD ADMINO_ATTACHMENTS_ROOT={_SAMPLE_ROOT} python -m admino.main\n",
    f"umask 077; mkdir -p {_SAMPLE_ROOT}\n"
    f"env -u PG_PASSWORD ADMINO_ATTACHMENTS_ROOT={_SAMPLE_ROOT} python3 -m admino.main\n",
)
_REFUSED_RECIPES: Final[tuple[str, ...]] = (
    # Mode 755.
    f"mkdir -p -m 755 {_SAMPLE_ROOT}\n"
    f"env -u PG_PASSWORD ADMINO_ATTACHMENTS_ROOT={_SAMPLE_ROOT} python -m admino.main\n",
    # Created after the app starts.
    f"env -u PG_PASSWORD ADMINO_ATTACHMENTS_ROOT={_SAMPLE_ROOT} python -m admino.main\n"
    f"mkdir -p -m 700 {_SAMPLE_ROOT}\n",
    # The root isn't in the app's environment.
    f"mkdir -p -m 700 {_SAMPLE_ROOT}\nenv -u PG_PASSWORD python -m admino.main\n",
    # PG_PASSWORD isn't removed.
    f"mkdir -p -m 700 {_SAMPLE_ROOT}\n"
    f"ADMINO_ATTACHMENTS_ROOT={_SAMPLE_ROOT} python -m admino.main\n",
)


def _recipe_ok(text: str, root: str) -> bool:
    lines = _logical_lines(text)
    app_line, app_words = _app_start(lines)
    environment = _app_environment(app_words)
    return environment == {
        "unsets_PG_PASSWORD": True,
        "roots": [root],
    } and _creates_private_directory(lines, root, app_line)


def _checker_misses() -> list[str]:
    misses = [text for text in _ACCEPTED_RECIPES if not _recipe_ok(text, _SAMPLE_ROOT)]
    misses.extend(text for text in _REFUSED_RECIPES if _recipe_ok(text, _SAMPLE_ROOT))
    return misses


def _git_ignored(relative: str, tmp_path: Path) -> bool:
    """Whether the repository's .gitignore ignores ``relative`` (a throwaway repository
    holding only that .gitignore; no global or system excludes)."""
    repository = tmp_path / "gitignore-probe"
    repository.mkdir()
    shutil.copyfile(_REPO / ".gitignore", repository / ".gitignore")
    git = _tool("git")
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    subprocess.run(  # noqa: S603
        [git, "init", "-q", str(repository)], env=env, check=True, capture_output=True
    )
    completed = subprocess.run(  # noqa: S603
        [git, "-C", str(repository), "-c", "core.excludesFile=", "check-ignore", "-q", relative],
        env=env,
        capture_output=True,
        check=False,
    )
    return completed.returncode == 0


def test_make_run_starts_the_app_with_the_checkout_attachments_root(tmp_path: Path) -> None:
    """Unset in the environment: the app gets ``<checkout>/data/attachments`` and still runs
    without PG_PASSWORD; migrate's command is printed first; the dry run runs nothing."""
    checkout = _checkout(tmp_path)
    expected = str(checkout.resolve() / "data" / "attachments")

    lines = _dry_run(checkout)
    app_line, app_words = _app_start(lines)
    migrate_lines = [
        number
        for number, line in enumerate(lines)
        for words in _commands(line)
        if _module_index(words, _MIGRATE_MODULE) is not None
    ]

    assert (
        _app_environment(app_words),
        migrate_lines[:1] == [0] and app_line > 0,
        (checkout / "data").exists(),
    ) == ({"unsets_PG_PASSWORD": True, "roots": [expected]}, True, False)


def test_make_run_creates_the_root_mode_0700_before_the_app_and_git_ignores_it(
    tmp_path: Path,
) -> None:
    """The directory is created with mode 0700 by a command printed before the app's;
    ``data/attachments`` in the checkout is git-ignored. The checks accept every contract
    form of the recipe and refuse a wrong mode, a late mkdir, a missing root or a kept
    PG_PASSWORD."""
    checkout = _checkout(tmp_path)
    expected = str(checkout.resolve() / "data" / "attachments")

    lines = _dry_run(checkout)
    app_line, _ = _app_start(lines)

    assert (
        _checker_misses(),
        _creates_private_directory(lines, expected, app_line),
        _git_ignored("data/attachments/0a1b2c3d/upload-281", tmp_path),
    ) == ([], True, True)


def test_make_run_an_exported_root_wins(tmp_path: Path) -> None:
    """``?=``: an ``ADMINO_ATTACHMENTS_ROOT`` exported in the shell is the one the recipe
    creates and passes to the app."""
    checkout = _checkout(tmp_path)
    exported = str(tmp_path / "exported-attachments")

    lines = _dry_run(checkout, exported)
    app_line, app_words = _app_start(lines)

    assert (
        _app_environment(app_words),
        _creates_private_directory(lines, exported, app_line),
        Path(exported).exists(),
    ) == ({"unsets_PG_PASSWORD": True, "roots": [exported]}, True, False)
