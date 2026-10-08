"""The attachments volume in compose, the image and the entrypoint (GH-187).

Issue #187, "DevOps & security": "A named volume ``admino-attachments`` in
compose, created by the entrypoint with ``admino`` ownership", and Decision 11:
originals live at ``<ATTACHMENTS_ROOT>/<org_id>/<attachment_id>`` with
``organizations.ATTACHMENTS_ROOT`` = ``/app/data/attachments``. GH-281 (Decision 8)
made the root configurable (``ADMINO_ATTACHMENTS_ROOT``, default
``/app/data/attachments``); in the container it stays on the volume. Contract §6 pins:

- docker-compose.yml declares the named volume ``attachments`` with
  ``name: admino-attachments`` and mounts it on the ``agent`` service at
  ``/app/data/attachments``, read-write (uploads write there);
- no other service of any compose file (postgres, migrate, vllm, the prod
  overlay's Caddy, ...) mounts it, and no overlay changes the agent's mount: only
  the app reads the files, and a proxy never serves them directly;
- GH-281 (contract A7): the agent's ``environment`` sets ``ADMINO_ATTACHMENTS_ROOT:
  /app/data/attachments``, the volume's mount point (``environment`` wins over the
  ``env_file``, so a ``.env`` value meant for native runs never moves the container's
  root off the volume), and no overlay sets it to anything else;
- the Dockerfile's runtime stage creates ``/app/data/attachments`` owned by
  admino (a fresh named volume copies the image directory's ownership);
- entrypoint.sh (root, before the ``gosu admino`` drop) creates the directory
  when missing and sets owner admino and mode 0700, so an existing volume of
  another owner or mode is fixed on every start. Whether that needs CHOWN/FOWNER
  in ``cap_add`` is devops' call (contract §6); this file only reads the files.

Static checks, no Docker: the compose files are read with PyYAML (already used
by the app and by tests/test_shipped_defaults.py); the shell files are tokenized
with ``shlex``. The entrypoint check follows simple variable assignments
(``DIR=/app/data/attachments``, ``${DIR:-...}``), commands inside functions (they
count where the function is called) and commands run through ``gosu admino``.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any, Final

import yaml

from admino import organizations

_REPO: Final = Path(__file__).resolve().parents[1]
_ROOT: Final = "/app/data/attachments"
_VOLUME_KEY: Final = "attachments"
_VOLUME_NAME: Final = "admino-attachments"
_OWNERS: Final = frozenset({"admino", "admino:admino", "admino:", "1000", "1000:1000"})
_MODES_0700: Final = frozenset({"700", "0700", "u=rwx,go=", "u=rwx,g=,o=", "u=rwx,go-rwx"})
_SEPARATORS: Final = frozenset({";", "&&", "||", "|", "&", "(", ")", ";;"})


# ---------------------------------------------------------------------------
# Compose
# ---------------------------------------------------------------------------


def _compose(name: str) -> dict[str, Any]:
    loaded = yaml.safe_load((_REPO / name).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict), name
    return loaded


def _compose_files() -> list[str]:
    return sorted(path.name for path in _REPO.glob("docker-compose*.yml"))


def _mounts(service: dict[str, Any]) -> list[tuple[str, str, bool]]:
    """(source, target, read_only) of each volume entry, short or long syntax."""
    mounts: list[tuple[str, str, bool]] = []
    for entry in service.get("volumes") or []:
        if isinstance(entry, str):
            parts = entry.split(":")
            source, target = (parts[0], parts[1]) if len(parts) > 1 else ("", parts[0])
            options = parts[2].split(",") if len(parts) > 2 else []
            mounts.append((source, target.rstrip("/"), "ro" in options))
        else:
            mounts.append(
                (
                    str(entry.get("source", "")),
                    str(entry.get("target", "")).rstrip("/"),
                    bool(entry.get("read_only", False)),
                )
            )
    return mounts


def _touches_attachments(source: str, target: str) -> bool:
    return source == _VOLUME_KEY or target == _ROOT or target.startswith(f"{_ROOT}/")


# ---------------------------------------------------------------------------
# Shell
# ---------------------------------------------------------------------------

_VARIABLE: Final = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)"
)
_ASSIGNMENT: Final = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", re.DOTALL)
_FUNCTION_START: Final = re.compile(r"\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{?\s*$")


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Lines with backslash continuations joined, each with its first line number."""
    lines: list[tuple[int, str]] = []
    buffer = ""
    start = 0
    for number, line in enumerate(text.splitlines(), 1):
        if not buffer:
            start = number
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        lines.append((start, buffer + line))
        buffer = ""
    if buffer:
        lines.append((start, buffer))
    return lines


def _simple_commands(text: str) -> list[tuple[int, list[str]]]:
    """Each simple command of a shell text: (line number, tokens). Lines shlex can't
    split (a multi-line quoted block) are skipped."""
    commands: list[tuple[int, list[str]]] = []
    for number, line in _logical_lines(text):
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|()")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        try:
            tokens = list(lexer)
        except ValueError:
            continue
        current: list[str] = []
        for token in tokens:
            if token in _SEPARATORS:
                if current:
                    commands.append((number, current))
                current = []
            else:
                current.append(token)
        if current:
            commands.append((number, current))
    return commands


def _expand(token: str, variables: dict[str, str]) -> str:
    def substitute(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(3)
        if name in variables:
            return variables[name]
        if match.group(2) is not None:
            return match.group(2)
        return match.group(0)

    return _VARIABLE.sub(substitute, token)


def _functions(text: str) -> dict[str, tuple[int, int]]:
    """Function name -> (first line, closing-brace line), for top-level ``name() {``
    definitions closed by a ``}`` at the start of a line."""
    functions: dict[str, tuple[int, int]] = {}
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = _FUNCTION_START.match(line)
        if match is None or line.startswith((" ", "\t")):
            continue
        for end in range(index + 1, len(lines)):
            if lines[end].rstrip() == "}":
                functions[match.group(1)] = (index + 1, end + 1)
                break
    return functions


def _effective_commands(text: str) -> list[tuple[float, list[str]]]:
    """Each command with variables expanded and its position in the run order: its
    own line at top level, the line of the first call of its function otherwise
    (infinity when the function is never called)."""
    functions = _functions(text)
    commands = _simple_commands(text)
    variables: dict[str, str] = {}
    expanded: list[tuple[int, list[str]]] = []
    for number, tokens in commands:
        words = [_expand(token, variables) for token in tokens]
        first = (
            1 if words[0] in ("local", "readonly", "export", "declare") and len(words) > 1 else 0
        )
        assignment = _ASSIGNMENT.fullmatch(words[first])
        if assignment is not None:
            variables[assignment.group(1)] = assignment.group(2)
        expanded.append((number, words))

    # A definition line (``name() {``) tokenizes like a call of ``name``: not a call.
    definition_lines = {first_line for first_line, _ in functions.values()}

    def owner(line: int) -> str | None:
        for name, (first_line, last_line) in functions.items():
            if first_line < line < last_line:
                return name
        return None

    def position(line: int, seen: frozenset[str] = frozenset()) -> float:
        function = owner(line)
        if function is None:
            return float(line)
        if function in seen:
            return float("inf")
        calls = [
            position(call_line, seen | {function})
            for call_line, words in expanded
            if words[0] == function
            and owner(call_line) != function
            and call_line not in definition_lines
        ]
        return min(calls, default=float("inf"))

    return [(position(number), words) for number, words in expanded]


def _without_gosu(words: list[str]) -> tuple[list[str], bool]:
    """Strip a leading ``gosu admino`` (or ``exec``); True when it ran as admino."""
    as_admino = False
    if words[:1] == ["exec"]:
        words = words[1:]
    if len(words) > 1 and words[0] == "gosu" and words[1] in _OWNERS:
        words = words[2:]
        as_admino = True
    return words, as_admino


def _names_root(words: list[str]) -> bool:
    return any(word.rstrip("/") == _ROOT for word in words)


def _option_value(words: list[str], short: str, long: str) -> str | None:
    """The value of ``-m 0700`` / ``-m0700`` / ``--mode=0700`` style options."""
    for index, word in enumerate(words):
        if word == short and index + 1 < len(words):
            return words[index + 1]
        if word.startswith(short) and len(word) > len(short) and not word.startswith("--"):
            return word[len(short) :]
        if word.startswith(f"{long}="):
            return word.split("=", 1)[1]
    return None


def _root_preparation(text: str) -> dict[str, bool]:
    """Whether the script creates the attachments root, makes admino its owner and sets
    mode 0700, each before the ``exec gosu admino`` privilege drop."""
    commands = _effective_commands(text)
    drops = [
        at
        for at, words in commands
        if words[:1] == ["exec"] and "gosu" in words and _without_gosu(words)[1]
    ]
    drop = min(drops, default=float("-inf"))
    created = owned = mode = False
    for at, raw_words in commands:
        if at >= drop:
            continue
        words, as_admino = _without_gosu(raw_words)
        if not words or not _names_root(words):
            continue
        command = words[0]
        flags = [word for word in words[1:] if word.startswith("-")]
        operands = [word for word in words[1:] if not word.startswith("-")]
        if command == "mkdir" or (command == "install" and "-d" in flags):
            created = True
            owned = owned or as_admino
            owner_option = _option_value(words, "-o", "--owner")
            owned = owned or (command == "install" and owner_option in _OWNERS)
            mode_option = _option_value(words, "-m", "--mode")
            mode = mode or (command == "install" and mode_option in _MODES_0700)
        elif command == "chown":
            owned = owned or (bool(operands) and operands[0] in _OWNERS)
        elif command == "chmod":
            mode = mode or (bool(operands) and operands[0] in _MODES_0700)
    return {"created": created, "owned_by_admino": owned, "mode_0700": mode}


_ALL_DONE: Final = {"created": True, "owned_by_admino": True, "mode_0700": True}

# Scripts the entrypoint check must accept, and ones it must refuse.
_ACCEPTED_SCRIPTS: Final[tuple[str, ...]] = (
    f'mkdir -p {_ROOT}\nchown admino:admino {_ROOT}\nchmod 0700 {_ROOT}\nexec gosu admino "$@"\n',
    "ATTACHMENTS_DIR=/app/data/attachments\n"
    "prepare_attachments() {\n"
    '    [ -d "${ATTACHMENTS_DIR}" ] || mkdir -p "${ATTACHMENTS_DIR}"\n'
    '    chown admino "${ATTACHMENTS_DIR}" && chmod 700 "${ATTACHMENTS_DIR}"\n'
    "}\n"
    "prepare_attachments\n"
    'if [ "$(id -u)" = "0" ]; then\n    exec gosu admino "$@"\nfi\n',
    f'install -d -o admino -g admino -m 0700 "{_ROOT}"\nexec gosu admino "$@"\n',
)
_REFUSED_SCRIPTS: Final[tuple[str, ...]] = (
    # After the drop: too late (and impossible as admino).
    f'exec gosu admino "$@"\nmkdir -p {_ROOT}\nchown admino {_ROOT}\nchmod 0700 {_ROOT}\n',
    # A function that is never called.
    f"prepare() {{\n    mkdir -p {_ROOT}\n    chown admino {_ROOT}\n    chmod 0700 {_ROOT}\n}}\n"
    'exec gosu admino "$@"\n',
    # Wrong owner and mode.
    f'mkdir -p {_ROOT}\nchown root:root {_ROOT}\nchmod 0755 {_ROOT}\nexec gosu admino "$@"\n',
)


def _checker_misses() -> list[str]:
    misses = [script for script in _ACCEPTED_SCRIPTS if _root_preparation(script) != _ALL_DONE]
    misses.extend(script for script in _REFUSED_SCRIPTS if _root_preparation(script) == _ALL_DONE)
    return misses


# ---------------------------------------------------------------------------
# Dockerfile
# ---------------------------------------------------------------------------


def _runtime_run_commands(text: str) -> list[list[str]]:
    """The simple commands of the RUN instructions after the last FROM, in order."""
    lines = _logical_lines(text)
    last_from = max(
        (
            index
            for index, (_, line) in enumerate(lines)
            if line.lstrip().upper().startswith("FROM ")
        ),
        default=-1,
    )
    commands: list[list[str]] = []
    for _, line in lines[last_from + 1 :]:
        stripped = line.strip()
        if not stripped.upper().startswith("RUN "):
            continue
        commands.extend(tokens for _, tokens in _simple_commands(stripped[4:]))
    return commands


def _image_creates_root_for_admino(text: str) -> dict[str, bool]:
    """Whether the runtime stage creates the root and then makes admino its owner
    (directly, or with ``chown -R`` on /app or /app/data)."""
    created = owned = False
    for words in _runtime_run_commands(text):
        if not words:
            continue
        command = words[0]
        flags = [word for word in words[1:] if word.startswith("-")]
        operands = [word.rstrip("/") for word in words[1:] if not word.startswith("-")]
        if command == "mkdir" or (command == "install" and "-d" in flags):
            if _ROOT in operands:
                created = True
                owner_option = _option_value(words, "-o", "--owner")
                owned = owned or (command == "install" and owner_option in _OWNERS)
        elif command == "chown" and created and operands and operands[0] in _OWNERS:
            recursive = any(flag in ("-R", "--recursive") for flag in flags)
            targets = operands[1:]
            owned = (
                owned
                or _ROOT in targets
                or (recursive and any(target in ("/app", "/app/data") for target in targets))
            )
    return {"created": created, "owned_by_admino": owned}


# ---------------------------------------------------------------------------
# 1. docker-compose.yml: the named volume and the agent's mount
# ---------------------------------------------------------------------------


def test_compose_attachments_declares_the_named_volume() -> None:
    """The top-level volume ``attachments`` is named ``admino-attachments`` (a local
    volume compose creates, not an external one)."""
    volumes = _compose("docker-compose.yml").get("volumes") or {}

    assert _VOLUME_KEY in volumes
    declared = volumes[_VOLUME_KEY] or {}
    assert (declared.get("name"), bool(declared.get("external", False))) == (_VOLUME_NAME, False)


def test_compose_attachments_mounts_the_volume_read_write_on_the_agent() -> None:
    """The agent mounts exactly that volume at the app's attachments root
    (organizations.ATTACHMENTS_ROOT, /app/data/attachments), not read-only."""
    agent = _compose("docker-compose.yml")["services"]["agent"]
    attachment_mounts = [
        mount for mount in _mounts(agent) if _touches_attachments(mount[0], mount[1])
    ]

    assert Path(_ROOT) == organizations.ATTACHMENTS_ROOT
    assert attachment_mounts == [(_VOLUME_KEY, str(organizations.ATTACHMENTS_ROOT), False)]


def test_compose_attachments_no_other_service_or_overlay_mounts_the_volume() -> None:
    """Across every compose file, only the base file's agent mounts the volume or
    anything at /app/data/attachments; no overlay remounts it (read-only or elsewhere)."""
    assert _VOLUME_KEY in (_compose("docker-compose.yml").get("volumes") or {})
    others = [
        f"{name}:{service_name}:{source}:{target}"
        for name in _compose_files()
        for service_name, service in (_compose(name).get("services") or {}).items()
        for source, target, _ in _mounts(service or {})
        if _touches_attachments(source, target)
        and not (name == "docker-compose.yml" and service_name == "agent")
    ]

    assert others == []


_ROOT_VARIABLE: Final = "ADMINO_ATTACHMENTS_ROOT"


def _environment(service: dict[str, Any]) -> dict[str, str | None]:
    """A service's ``environment``, mapping or ``KEY=value`` list syntax."""
    entries = service.get("environment") or {}
    if isinstance(entries, dict):
        return {str(key): None if value is None else str(value) for key, value in entries.items()}
    environment: dict[str, str | None] = {}
    for entry in entries:
        key, separator, value = str(entry).partition("=")
        environment[key] = value if separator else None
    return environment


def test_compose_attachments_agent_environment_pins_the_root_to_the_volume() -> None:
    """GH-281 (contract A7): the agent's environment sets ADMINO_ATTACHMENTS_ROOT to
    /app/data/attachments, the attachments volume's mount point, and no overlay's agent
    environment sets it to another value."""
    agent = _compose("docker-compose.yml")["services"]["agent"]
    volume_targets = [target for source, target, _ in _mounts(agent) if source == _VOLUME_KEY]
    overlay_values = {
        name: _environment(((_compose(name).get("services") or {}).get("agent")) or {}).get(
            _ROOT_VARIABLE, _ROOT
        )
        for name in _compose_files()
        if name != "docker-compose.yml"
    }

    assert (
        _environment(agent).get(_ROOT_VARIABLE),
        volume_targets,
        set(overlay_values.values()),
    ) == (
        _ROOT,
        [_ROOT],
        {_ROOT},
    )


# ---------------------------------------------------------------------------
# 2. Dockerfile: the image directory
# ---------------------------------------------------------------------------


def test_compose_attachments_dockerfile_creates_the_root_owned_by_admino() -> None:
    """The runtime stage creates /app/data/attachments and gives it to admino (a fresh
    named volume starts with the image directory's owner)."""
    text = (_REPO / "Dockerfile").read_text(encoding="utf-8")

    assert _image_creates_root_for_admino(text) == {"created": True, "owned_by_admino": True}


# ---------------------------------------------------------------------------
# 3. entrypoint.sh: created, owned by admino, mode 0700, before the gosu drop
# ---------------------------------------------------------------------------


def test_compose_attachments_entrypoint_prepares_the_root_before_dropping_root() -> None:
    """Before ``exec gosu admino``, the entrypoint creates /app/data/attachments when
    missing, makes admino its owner and sets mode 0700. The check itself must accept
    the plain, function/variable and ``install -d`` forms and refuse a preparation after
    the drop, in a function never called, or with another owner or mode."""
    text = (_REPO / "entrypoint.sh").read_text(encoding="utf-8")

    assert _checker_misses() == []
    assert _root_preparation(text) == _ALL_DONE
