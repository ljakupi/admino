"""Root-owned code in the image and ``python -P`` (GH-188, security-audit fix M-2).

Issue #188, Decision 15: "the image's code and web files are root-owned and the
server starts with ``python -P``". The conversion child runs as the server's
user (admino); before the fix it could rewrite the served PWA in ``/app/static``
or plant ``/app/admino/`` (``/app`` was admino's and the working directory was
``sys.path[0]``). Contract §12.8 pins, for the Dockerfile's runtime stage (after
the last ``FROM``):

- ``src/`` and the ``static/`` built by frontend-builder are copied without a
  (non-root) ``--chown``: root-owned, files and directories alike; the installed
  package under ``/usr/local`` stays root's too;
- only ``/app/data`` is ``chown -R admino:admino``: ``/app`` itself and
  ``/app/config`` stay root's, ``/app/data`` and ``/app/data/attachments`` are
  admino's (the attachments mount point keeps working; tests/
  test_compose_attachments.py pins its creation and the entrypoint's
  ``install -d``);
- the entrypoint stays root-owned, mode 0555;
- ``CMD ["python", "-P", "-m", "admino.main"]`` (the working directory is never
  on the import path), behind the unchanged ``ENTRYPOINT ["/entrypoint.sh"]``, and
  no compose file overrides the agent's command or entrypoint.

Static checks, no Docker: the Dockerfile is split into instructions (comment lines
dropped, continuations joined) and the runtime stage is replayed as a small
ownership model: ``WORKDIR``/``USER``, ``COPY``/``ADD`` (``--chown``,
``--chmod``, JSON or plain form, relative destinations), and the ``mkdir``,
``install -d``, ``chown`` and ``chmod`` commands of ``RUN`` instructions
(``-R`` applies to the whole tree). Sample Dockerfiles folded into the first test
prove the model sees the vulnerable forms.
"""

from __future__ import annotations

import json
import posixpath
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import yaml

_REPO: Final = Path(__file__).resolve().parents[1]
_SEPARATORS: Final = frozenset({";", "&&", "||", "|", "&", "(", ")", ";;"})
_USERS: Final = {"admino": "admino", "1000": "admino", "root": "root", "0": "root"}

# What a compromised conversion child (uid admino) must not be able to rewrite.
_CODE_PATHS: Final = {
    "/app/src": "root",
    "/app/src/admino/main.py": "root",
    "/app/static": "root",
    "/app/static/index.html": "root",
    "/usr/local/lib/python3.12/site-packages/admino/main.py": "root",
}
# /app and /app/config root's; only /app/data (and the attachments mount point)
# admino's; the entrypoint root's.
_DIRECTORY_PATHS: Final = {
    "/app": "root",
    "/app/config": "root",
    "/app/data": "admino",
    "/app/data/attachments": "admino",
    "/entrypoint.sh": "root",
}


# ---------------------------------------------------------------------------
# Dockerfile instructions
# ---------------------------------------------------------------------------


def _instruction_lines(text: str) -> list[str]:
    """Logical instruction lines: comment lines dropped (Docker drops them even inside
    a continuation), blank lines skipped, backslash continuations joined."""
    lines: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        lines.append((buffer + stripped).strip())
        buffer = ""
    if buffer.strip():
        lines.append(buffer.strip())
    return lines


def _runtime_stage(text: str) -> list[tuple[str, str]]:
    """(KEYWORD, arguments) of every instruction after the last FROM."""
    instructions: list[tuple[str, str]] = []
    for line in _instruction_lines(text):
        keyword, _, rest = line.partition(" ")
        if keyword.upper() == "FROM":
            instructions = []
            continue
        instructions.append((keyword.upper(), rest.strip()))
    return instructions


def _shell_commands(script: str) -> list[list[str]]:
    """The simple commands of a RUN's shell text (split at ; && || | & ( ))."""
    lexer = shlex.shlex(script, posix=True, punctuation_chars=";&|()")
    lexer.whitespace_split = True
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


def _user(spec: str) -> str:
    """``admino:admino`` / ``1000:1000`` -> admino, ``root`` / ``0:0`` -> root."""
    name = spec.split(":", 1)[0]
    return _USERS.get(name, name)


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _ancestors(path: str) -> list[str]:
    """``/a/b/c`` -> ``["/a", "/a/b", "/a/b/c"]``."""
    parts = [part for part in path.split("/") if part]
    return ["/" + "/".join(parts[: index + 1]) for index in range(len(parts))]


def _option(words: list[str], short: str, long: str) -> str | None:
    """The value of ``-m 0700`` / ``-m0700`` / ``--mode=0700`` style options."""
    for index, word in enumerate(words):
        if word == short and index + 1 < len(words):
            return words[index + 1]
        if word.startswith(short) and len(word) > len(short) and not word.startswith("--"):
            return word[len(short) :]
        if word.startswith(f"{long}="):
            return word.split("=", 1)[1]
    return None


def _operands(words: list[str], valued: tuple[str, ...]) -> list[str]:
    """Non-option words, skipping the value of a separate ``-o owner`` style option."""
    operands: list[str] = []
    skip = False
    for word in words:
        if skip:
            skip = False
            continue
        if word in valued:
            skip = True
            continue
        if not word.startswith("-"):
            operands.append(word)
    return operands


@dataclass
class _Image:
    """The ownership/mode events of the runtime stage, in order.

    ``events``: ("create", path, owner, False) when a path comes into existence (a
    no-op when it already exists) and ("own", path, owner, recursive) when its owner
    is set; ``modes``: (path, mode, recursive)."""

    events: list[tuple[str, str, str, bool]] = field(default_factory=list)
    modes: list[tuple[str, str, bool]] = field(default_factory=list)

    def create(self, path: str, owner: str, *, parents: bool) -> None:
        for each in _ancestors(path) if parents else [path]:
            self.events.append(("create", each, owner, False))

    def own(self, path: str, owner: str, *, recursive: bool) -> None:
        self.events.append(("own", path, owner, recursive))

    def owner(self, path: str) -> str | None:
        owner: str | None = None
        for kind, target, who, recursive in self.events:
            if kind == "create":
                if target == path and owner is None:
                    owner = who
            elif target == path or (recursive and _under(path, target)):
                owner = who
        return owner

    def mode(self, path: str) -> int | str | None:
        mode: str | None = None
        for target, value, recursive in self.modes:
            if target == path or (recursive and _under(path, target)):
                mode = value
        if mode is None:
            return None
        try:
            return int(mode, 8)
        except ValueError:
            return mode


def _copy(image: _Image, arguments: str, workdir: str) -> None:
    """``COPY [--flags] <src>... <dest>`` (plain or JSON form after the flags)."""
    flags: list[str] = []
    rest = arguments
    while rest.startswith("--"):
        flag, _, rest = rest.partition(" ")
        flags.append(flag)
        rest = rest.strip()
    paths: list[str] = json.loads(rest) if rest.startswith("[") else shlex.split(rest)
    chown = next((flag.split("=", 1)[1] for flag in flags if flag.startswith("--chown=")), None)
    chmod = next((flag.split("=", 1)[1] for flag in flags if flag.startswith("--chmod=")), None)
    destination = posixpath.normpath(posixpath.join(workdir, paths[-1]))
    owner = _user(chown) if chown is not None else "root"
    image.create(posixpath.dirname(destination), owner, parents=True)
    image.own(destination, owner, recursive=True)
    if chmod is not None:
        image.modes.append((destination, chmod, True))


def _run(image: _Image, script: str, workdir: str, user: str) -> None:
    def resolve(path: str) -> str:
        return posixpath.normpath(posixpath.join(workdir, path))

    for words in _shell_commands(script):
        command, rest = words[0], words[1:]
        flags = [word for word in rest if word.startswith("-")]
        if command == "mkdir":
            parents = any(flag in ("-p", "--parents") for flag in flags)
            mode = _option(rest, "-m", "--mode")
            for path in _operands(rest, ("-m",)):
                image.create(resolve(path), user, parents=parents)
                if mode is not None:
                    image.modes.append((resolve(path), mode, False))
        elif command == "install" and any(flag in ("-d", "--directory") for flag in flags):
            owner_spec = _option(rest, "-o", "--owner")
            owner = _user(owner_spec) if owner_spec is not None else user
            mode = _option(rest, "-m", "--mode")
            for path in _operands(rest, ("-o", "-g", "-m")):
                image.create(resolve(path), user, parents=True)
                image.own(resolve(path), owner, recursive=False)
                if mode is not None:
                    image.modes.append((resolve(path), mode, False))
        elif command in ("chown", "chmod"):
            recursive = any(flag in ("-R", "--recursive") for flag in flags)
            operands = _operands(rest, ())
            if len(operands) < 2:
                continue
            for path in operands[1:]:
                if command == "chown":
                    image.own(resolve(path), _user(operands[0]), recursive=recursive)
                else:
                    image.modes.append((resolve(path), operands[0], recursive))


def _image(text: str) -> _Image:
    """Replay the runtime stage's ownership and mode changes."""
    image = _Image()
    workdir, user = "/", "root"
    for keyword, arguments in _runtime_stage(text):
        if keyword == "WORKDIR":
            workdir = posixpath.normpath(posixpath.join(workdir, arguments))
            image.create(workdir, user, parents=True)
        elif keyword == "USER":
            user = _user(arguments)
        elif keyword in ("COPY", "ADD"):
            _copy(image, arguments, workdir)
        elif keyword == "RUN":
            _run(image, arguments, workdir, user)
    return image


def _owners(text: str, paths: dict[str, str]) -> dict[str, str | None]:
    image = _image(text)
    return {path: image.owner(path) for path in paths}


def _dockerfile() -> str:
    return (_REPO / "Dockerfile").read_text(encoding="utf-8")


# Sample runtime stages and what the model must report for them (the vulnerable
# forms and a few parsing traps), so the checks below can't pass vacuously.
_SAMPLES: Final[tuple[tuple[str, str, dict[str, Any]], ...]] = (
    (
        "chown_copies_and_whole_app",
        "FROM python AS runtime\nWORKDIR /app\nCOPY --chown=admino:admino src/ src/\n"
        "COPY --from=frontend-builder --chown=admino:admino /build/static/ /app/static/\n"
        "RUN mkdir -p /app/config /app/data/attachments \\\n    && chown -R admino:admino /app\n",
        {
            "/app": "admino",
            "/app/src/admino/main.py": "admino",
            "/app/static/index.html": "admino",
            "/app/config": "admino",
        },
    ),
    (
        "root_copies_data_only",
        "FROM python AS runtime\nWORKDIR /app\nCOPY src/ src/\n"
        "COPY --from=frontend-builder /build/static/ /app/static/\n"
        "RUN mkdir -p /app/config /app/data/attachments \\\n"
        "    # a comment line inside the continuation\n"
        "    && chown -R admino:admino /app/data\n",
        {
            "/app": "root",
            "/app/src/admino/main.py": "root",
            "/app/static": "root",
            "/app/config": "root",
            "/app/data": "admino",
            "/app/data/attachments": "admino",
        },
    ),
    (
        "earlier_stage_and_json_form",
        "FROM node AS builder\nWORKDIR /app\nRUN chown -R admino /app\n"
        'FROM python\nWORKDIR /app\nCOPY --chown=1000:1000 ["src/", "src/"]\n',
        {"/app": "root", "/app/src": "admino", "/app/src/admino/main.py": "admino"},
    ),
    (
        "user_switch_and_shallow_chown",
        "FROM python\nUSER admino\nWORKDIR /app\nUSER root\nCOPY src/ src/\n"
        "RUN chown admino /app/src\n",
        {"/app": "admino", "/app/src": "admino", "/app/src/admino/main.py": "root"},
    ),
)


def _checker_misses() -> list[str]:
    return [
        name
        for name, text, expected in _SAMPLES
        if {path: _image(text).owner(path) for path in expected} != expected
    ]


# ---------------------------------------------------------------------------
# 1. Code and web files are root's
# ---------------------------------------------------------------------------


def test_dockerfile_hardening_code_and_web_files_are_root_owned() -> None:
    """``/app/src``, ``/app/static`` (directories and files) and the installed package
    are root's: no ``--chown`` on their COPY, no chown over them afterwards."""
    assert _checker_misses() == []
    assert _owners(_dockerfile(), _CODE_PATHS) == _CODE_PATHS


# ---------------------------------------------------------------------------
# 2. Only /app/data is admino's; the entrypoint stays root's 0555
# ---------------------------------------------------------------------------


def test_dockerfile_hardening_only_the_data_directory_is_admino_owned() -> None:
    """``/app`` and ``/app/config`` stay root's (no ``chown -R`` of ``/app``),
    ``/app/data`` and the attachments mount point are admino's, and the entrypoint is
    root's with mode 0555."""
    text = _dockerfile()

    owners = _owners(text, _DIRECTORY_PATHS)
    entrypoint_mode = _image(text).mode("/entrypoint.sh")

    assert (owners, entrypoint_mode) == (_DIRECTORY_PATHS, 0o555)


# ---------------------------------------------------------------------------
# 3. The server starts with python -P
# ---------------------------------------------------------------------------


def _exec_form(arguments: str) -> list[str]:
    if arguments.startswith("["):
        parsed: list[str] = json.loads(arguments)
        return parsed
    return ["/bin/sh", "-c", arguments]


def _agent_overrides() -> dict[str, Any]:
    """``file:key`` -> value for every compose file whose agent service sets its own
    ``command`` or ``entrypoint`` (either would drop the image's ``-P``)."""
    overrides: dict[str, Any] = {}
    for path in sorted(_REPO.glob("docker-compose*.yml")):
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        agent = (loaded.get("services") or {}).get("agent") or {}
        for key in ("command", "entrypoint"):
            if key in agent:
                overrides[f"{path.name}:{key}"] = agent[key]
    return overrides


def test_dockerfile_hardening_server_starts_with_python_safe_path() -> None:
    """The runtime CMD is exactly ``python -P -m admino.main`` behind the unchanged
    entrypoint, and no compose file replaces the agent's command or entrypoint."""
    stage = _runtime_stage(_dockerfile())
    commands = [_exec_form(arguments) for keyword, arguments in stage if keyword == "CMD"]
    entrypoints = [_exec_form(arguments) for keyword, arguments in stage if keyword == "ENTRYPOINT"]

    assert (commands[-1:], entrypoints[-1:], _agent_overrides()) == (
        [["python", "-P", "-m", "admino.main"]],
        [["/entrypoint.sh"]],
        {},
    )
