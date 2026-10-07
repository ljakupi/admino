"""The parsers stay in the worker child, the converters out of the LLM's reach (GH-188).

Contract §1 and §5, issue Decision 2 ("the server process never loads the parsing
libraries"). Pinned:

1. A fresh interpreter that imports ``admino.server``, ``admino.attachment_processing``,
   ``admino.converters.runner`` or ``admino.converters.common`` has none of ``PIL``,
   ``pypdfium2``, ``docx`` and ``openpyxl`` in ``sys.modules`` (control: importing the four
   afterwards does show them, so the probe sees what it looks for).
2. Nothing on the LLM's tool path (``admino/tools/**``, ``agent.py``, every ``llm*.py``,
   ``permissions.py``, ``prompt_assembly.py``, ``untrusted.py``) imports
   ``admino.converters`` or ``admino.tokens`` in any form (plain, aliased, ``from``,
   relative, function-level, TYPE_CHECKING, ``__import__`` / ``import_module``).
3. No ``admino.converters`` module imports the server, agent, LLM, tools, database,
   asyncpg, fastapi/starlette, ``admino.attachments`` or ``admino.attachment_processing``.
4. Only the worker-side converter modules (``pdf``, ``images``, ``word``, ``sheets``,
   ``dispatch``, ``worker``) may load a parser: no other admino module imports
   ``PIL``/``pypdfium2``/``docx``/``openpyxl`` or one of those six modules, in any form
   (function-level and TYPE_CHECKING imports included), so no code path of the server
   process loads a parser later either.
5. The converters' logging calls pass no file name, path, page/cell text, label, title,
   job or options, and no exception object or message (class names only: never
   ``logger.exception`` or ``exc_info=``); ``runner.py`` has no logging call at all.
6. Among the converters (and ``tokens.py``), only ``runner.py`` imports ``subprocess``;
   no call passes ``shell=`` anything but ``False``, and nothing uses ``os.system``,
   ``os.popen``, ``os.exec*``, ``os.spawn*``, ``os.posix_spawn*``, ``pty.spawn`` or
   ``asyncio.create_subprocess_*``.

The scans read the source of the imported ``admino`` package (``admino.__file__``), so
they check whatever implementation is on the import path. Each scanner is first run on
known samples, so a scanner that silently finds nothing fails; each test also requires the
converter modules to exist, else it would prove nothing.
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Final

import pytest

import admino

_PACKAGE_DIR: Final = Path(admino.__file__).resolve().parent
_CONVERTERS_DIR: Final = _PACKAGE_DIR / "converters"
_SRC: Final = str(_PACKAGE_DIR.parent)

# Contract §1's module layout.
_CONVERTER_FILES: Final = (
    "__init__.py",
    "common.py",
    "ooxml.py",
    "text.py",
    "sheets.py",
    "word.py",
    "pdf.py",
    "images.py",
    "dispatch.py",
    "worker.py",
    "runner.py",
)
_PARSERS: Final = ("PIL", "docx", "openpyxl", "pypdfium2")
# The converter modules that load a parser (directly or through the converters).
_WORKER_SIDE: Final = ("pdf", "images", "word", "sheets", "dispatch", "worker")


def _missing_layout() -> list[str]:
    """The contract's converter files (and tokens.py) that don't exist on the import path."""
    missing = [name for name in _CONVERTER_FILES if not (_CONVERTERS_DIR / name).is_file()]
    if not (_PACKAGE_DIR / "tokens.py").is_file():
        missing.append("tokens.py")
    return missing


def _module_name(path: Path) -> str:
    """The dotted module name of a file inside the admino package."""
    parts = list(path.relative_to(_PACKAGE_DIR.parent).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _converter_sources() -> dict[str, str]:
    """module name -> source for every module under admino/converters/ and tokens.py."""
    files = [*sorted(_CONVERTERS_DIR.rglob("*.py")), _PACKAGE_DIR / "tokens.py"]
    return {_module_name(path): path.read_text(encoding="utf-8") for path in files}


# ---------------------------------------------------------------------------
# Import scanner
# ---------------------------------------------------------------------------


def _imported_names(source: str, module: str, *, is_package: bool = False) -> list[str]:
    """Every module (and ``from`` target) a source imports anywhere in it, relative
    imports resolved against ``module``; plus the string argument of ``__import__(...)`` /
    ``import_module(...)`` calls. (A bare string constant isn't an import: the runner names
    the worker module in its argv to run it in the child, never in the server.)"""
    tree = ast.parse(source)
    package = module if is_package else module.rpartition(".")[0]
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package.split(".")
                base_parts = parts[: len(parts) - (node.level - 1)]
                base = ".".join(base_parts + ([node.module] if node.module else []))
            else:
                base = node.module or ""
            names.append(base)
            names.extend(f"{base}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Call):
            func = node.func
            called = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            first = node.args[0] if node.args else None
            if (
                called in ("__import__", "import_module")
                and isinstance(first, ast.Constant)
                and isinstance(first.value, str)
            ):
                names.append(first.value)
    return names


def _hits(
    source: str, module: str, patterns: tuple[str, ...], *, is_package: bool = False
) -> list[str]:
    """The imported names that are (or live under) a forbidden module pattern."""
    compiled = [re.compile(rf"(?:{pattern})(?:\..+)?") for pattern in patterns]
    return sorted(
        {
            name
            for name in _imported_names(source, module, is_package=is_package)
            if any(regex.fullmatch(name) for regex in compiled)
        }
    )


def _scan(files: dict[str, tuple[str, bool]], patterns: tuple[str, ...]) -> dict[str, list[str]]:
    """module -> forbidden imports, for every module (source, is_package) with a hit."""
    return {
        module: found
        for module, (source, is_package) in files.items()
        if (found := _hits(source, module, patterns, is_package=is_package))
    }


def _sample_misses(
    samples: tuple[tuple[str, str], ...], clean: tuple[str, str], patterns: tuple[str, ...]
) -> list[str]:
    """The samples a scanner gets wrong: a forbidden sample it misses, or the clean sample
    it flags."""
    misses = [source for module, source in samples if _hits(source, module, patterns) == []]
    if _hits(clean[1], clean[0], patterns) != []:
        misses.append(clean[1])
    return misses


def _package_files(paths: list[Path]) -> dict[str, tuple[str, bool]]:
    return {
        _module_name(path): (path.read_text(encoding="utf-8"), path.name == "__init__.py")
        for path in paths
    }


# ---------------------------------------------------------------------------
# 1. Importing the server side loads no parser
# ---------------------------------------------------------------------------

_PROBE: Final = (
    "import importlib, json, sys\n"
    f"parsers = {_PARSERS!r}\n"
    "def loaded():\n"
    "    return sorted({name.split('.')[0] for name in sys.modules} & set(parsers))\n"
    "importlib.import_module(sys.argv[1])\n"
    "after_module = loaded()\n"
    "for name in parsers:\n"
    "    importlib.import_module(name)\n"
    "print(json.dumps({'after_module': after_module, 'control': loaded()}))\n"
)


@pytest.mark.parametrize(
    "module",
    [
        "admino.server",
        "admino.attachment_processing",
        "admino.converters.runner",
        "admino.converters.common",
    ],
)
def test_converters_isolation_server_side_import_loads_no_parser(module: str) -> None:
    """In a fresh interpreter, importing a server-side module leaves PIL, pypdfium2, docx
    and openpyxl out of sys.modules; importing the four afterwards shows all of them."""
    assert _missing_layout() == []

    # A fixed probe script run by this interpreter; the module name comes from the table.
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _PROBE, module],
        capture_output=True,
        env={**os.environ, "PYTHONPATH": _SRC},
        timeout=120,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")[-2000:]
    assert json.loads(completed.stdout) == {"after_module": [], "control": sorted(_PARSERS)}


# ---------------------------------------------------------------------------
# 2. Nothing on the LLM's tool path imports the converters or tokens
# ---------------------------------------------------------------------------

_CONVERSION_MODULES: Final = (r"admino\.converters", r"admino\.tokens")

_LLM_SAMPLES: Final[tuple[tuple[str, str], ...]] = (
    ("admino.tools.sample", "import admino.converters.runner"),
    ("admino.tools.sample", "import admino.tokens as tk"),
    ("admino.tools.sample", "from admino import tokens"),
    ("admino.tools.sample", "from admino import logs, converters"),
    ("admino.tools.sample", "from admino.converters.common import ConversionError"),
    ("admino.tools.sample", "from ..converters import dispatch"),
    ("admino.tools.sample", "from ..tokens import estimate_text_tokens"),
    ("admino.agent", "from . import tokens"),
    ("admino.agent", "from .converters.runner import run_conversion"),
    ("admino.tools.sample", "def load():\n    import admino.tokens\n"),
    (
        "admino.tools.sample",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n"
        "    from admino.converters.common import Manifest\n",
    ),
    ("admino.tools.sample", "module = __import__('admino.converters.pdf')"),
    ("admino.tools.sample", "import importlib\nmodule = importlib.import_module('admino.tokens')"),
)
_LLM_CLEAN: Final = (
    "admino.tools.sample",
    "from __future__ import annotations\nimport admino.chats\nfrom admino import logs\n"
    "from admino.tools.registry import register_tool\nfrom .. import organizations\n"
    "from admino.attachment_types import KINDS\nNOTE = 'counts admino tokens'\n",
)


def _llm_reachable_files() -> list[Path]:
    """admino/tools/**, agent.py, llm*.py, permissions.py, prompt_assembly.py, untrusted.py."""
    files = sorted((_PACKAGE_DIR / "tools").rglob("*.py"))
    files.append(_PACKAGE_DIR / "agent.py")
    files.extend(sorted(_PACKAGE_DIR.glob("llm*.py")))
    files.extend(
        _PACKAGE_DIR / name for name in ("permissions.py", "prompt_assembly.py", "untrusted.py")
    )
    return files


def test_converters_isolation_llm_reachable_modules_never_import_converters_or_tokens() -> None:
    """No module the LLM's tool calls run through imports admino.converters or
    admino.tokens, in any form."""
    assert _missing_layout() == []
    assert _sample_misses(_LLM_SAMPLES, _LLM_CLEAN, _CONVERSION_MODULES) == []
    files = _llm_reachable_files()
    assert {"registry.py", "agent.py", "llm.py", "permissions.py", "untrusted.py"} <= {
        path.name for path in files
    }

    assert _scan(_package_files(files), _CONVERSION_MODULES) == {}


# ---------------------------------------------------------------------------
# 3. The converters import no server-side layer
# ---------------------------------------------------------------------------

_SERVER_LAYERS: Final = (
    r"admino\.server",
    r"admino\.agent",
    r"admino\.llm\w*",
    r"admino\.tools",
    r"admino\.database",
    r"asyncpg",
    r"fastapi",
    r"starlette",
    r"admino\.attachments",
    r"admino\.attachment_processing",
)
_LAYER_SAMPLES: Final[tuple[tuple[str, str], ...]] = (
    ("admino.converters.pdf", "from admino import server"),
    ("admino.converters.pdf", "import admino.agent"),
    ("admino.converters.pdf", "from admino.llm_policy import guard"),
    ("admino.converters.pdf", "from ..tools import registry"),
    ("admino.converters.pdf", "import asyncpg"),
    ("admino.converters.pdf", "from fastapi import FastAPI"),
    ("admino.converters.pdf", "from admino.attachments import attachment_path"),
    ("admino.converters.pdf", "from .. import attachment_processing"),
    ("admino.converters.runner", "from admino import database"),
    ("admino.converters.runner", "def run():\n    from admino import server\n"),
)
_LAYER_CLEAN: Final = (
    "admino.converters.pdf",
    "from __future__ import annotations\nimport zipfile\nfrom PIL import Image\n"
    "import pypdfium2 as pdfium\nfrom admino import tokens\nfrom admino.models import "
    "AttachmentKind\nfrom admino.attachment_types import KINDS\nfrom admino.logs import "
    "safe_log\nfrom . import common\nfrom .common import PartWriter\n",
)


def test_converters_isolation_converters_import_no_server_side_layer() -> None:
    """No admino.converters module imports the server, agent, LLM, tools, database,
    asyncpg, fastapi/starlette, attachments or attachment_processing layers."""
    assert _missing_layout() == []
    assert _sample_misses(_LAYER_SAMPLES, _LAYER_CLEAN, _SERVER_LAYERS) == []

    files = _package_files(sorted(_CONVERTERS_DIR.rglob("*.py")))

    assert _scan(files, _SERVER_LAYERS) == {}


# ---------------------------------------------------------------------------
# 4. Only the worker-side converters load a parser
# ---------------------------------------------------------------------------

_PARSER_MODULES: Final = (
    r"PIL",
    r"pypdfium2",
    r"pypdfium2_raw",
    r"docx",
    r"openpyxl",
    r"admino\.converters\.(?:" + "|".join(_WORKER_SIDE) + ")",
)
_PARSER_SAMPLES: Final[tuple[tuple[str, str], ...]] = (
    ("admino.converters.runner", "import PIL"),
    ("admino.converters.runner", "from PIL import Image"),
    ("admino.converters.runner", "import pypdfium2 as pdfium"),
    ("admino.converters.common", "from docx import Document"),
    ("admino.converters.common", "import openpyxl"),
    ("admino.attachment_processing", "def convert():\n    import pypdfium2\n"),
    (
        "admino.attachment_processing",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from PIL.Image import Image\n",
    ),
    ("admino.attachment_processing", "from admino.converters import dispatch"),
    ("admino.attachment_processing", "from admino.converters.pdf import convert_pdf"),
    ("admino.attachment_processing", "from .converters import images"),
    ("admino.converters.runner", "from . import word"),
    ("admino.converters.runner", "from .worker import main"),
    ("admino.converters.runner", "module = __import__('PIL.Image')"),
    ("admino.server", "import importlib\nreader = importlib.import_module('openpyxl')"),
)
_PARSER_CLEAN: Final = (
    "admino.attachment_processing",
    "import zipfile\nfrom admino.converters import common, runner\n"
    "from admino.converters.runner import run_conversion\n"
    "from admino.converters.common import ConversionError\nimport admino.tokens\n"
    "from admino.attachment_types import detect_kind\nKINDS = ('pdf', 'docx', 'xlsx')\n",
)


def test_converters_isolation_only_worker_side_modules_load_a_parser() -> None:
    """Outside converters/{pdf,images,word,sheets,dispatch,worker}.py, no admino module
    imports PIL, pypdfium2, docx, openpyxl or one of those six modules, in any form."""
    assert _missing_layout() == []
    assert _sample_misses(_PARSER_SAMPLES, _PARSER_CLEAN, _PARSER_MODULES) == []
    worker_side = {_CONVERTERS_DIR / f"{name}.py" for name in _WORKER_SIDE}
    paths = [path for path in sorted(_PACKAGE_DIR.rglob("*.py")) if path not in worker_side]
    files = _package_files(paths)
    assert {"admino.server", "admino.converters.runner", "admino.converters.common"} <= set(files)

    assert _scan(files, _PARSER_MODULES) == {}


# ---------------------------------------------------------------------------
# 5. Logging carries no names, paths, content or exception text
# ---------------------------------------------------------------------------

_LOG_METHODS: Final = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "log"}
)
# Identifiers that name a file name, a path, file content or a job.
_LEAKY_IDENTIFIER: Final = re.compile(
    r"(?i)(?:.*file_?name.*|.*path.*|.*dir|.*header.*|raw|raw_.*|.*_raw|chunks?|body|"
    r"content|.*_content|head|text|.*_text|data|label|title|options|job|stdin|stdout|line|"
    r"value|cells?|rows?|.*name)"
)
# ``*name`` identifiers that hold a type, class or exception name, never input.
_SAFE_NAME: Final = re.compile(
    r"(?i).*(?:type|class|exc|exception|error|err|kind|module|func|function|logger|reason|"
    r"status)_?name"
)
# Exception attributes that carry its message (or a path).
_EXCEPTION_TEXT_ATTRIBUTES: Final = frozenset(
    {"args", "strerror", "filename", "filename2", "msg", "message"}
)


def _is_leaky(identifier: str) -> bool:
    if identifier.startswith("__") and identifier.endswith("__"):
        return False
    return bool(_LEAKY_IDENTIFIER.fullmatch(identifier)) and not _SAFE_NAME.fullmatch(identifier)


def _is_log_call(node: ast.AST) -> bool:
    """``<something named like a logger>.<level>(...)`` or ``logging.getLogger(...).<level>``."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    if node.func.attr not in _LOG_METHODS:
        return False
    receiver = node.func.value
    if isinstance(receiver, ast.Name):
        return "log" in receiver.id.lower()
    if isinstance(receiver, ast.Attribute):
        return "log" in receiver.attr.lower()
    if isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Attribute):
        return receiver.func.attr == "getLogger"
    return False


def _leaks_in(node: ast.AST, exception_names: frozenset[str]) -> list[str]:
    """The leaky identifiers a log-call argument mentions (``len(x)`` is a count: fine)."""
    found: list[str] = []

    def visit(current: ast.AST) -> None:
        if (
            isinstance(current, ast.Call)
            and isinstance(current.func, ast.Name)
            and current.func.id == "len"
        ):
            return
        if isinstance(current, ast.Attribute):
            if current.attr in ("__name__", "__qualname__"):
                return
            on_exception = isinstance(current.value, ast.Name) and (
                current.value.id in exception_names
            )
            if _is_leaky(current.attr) or (
                on_exception and current.attr in _EXCEPTION_TEXT_ATTRIBUTES
            ):
                found.append(current.attr)
            if not on_exception:
                visit(current.value)
            return
        if isinstance(current, ast.Name):
            if _is_leaky(current.id) or current.id in exception_names:
                found.append(current.id)
            return
        for child in ast.iter_child_nodes(current):
            visit(child)

    visit(node)
    return found


def _log_leaks(source: str) -> list[str]:
    """Every logging call of a source that may log input: ``line N: <what>``."""
    tree = ast.parse(source)
    exception_names = frozenset(
        node.name for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler) and node.name
    )
    leaks: list[str] = []
    for node in ast.walk(tree):
        if not _is_log_call(node):
            continue
        assert isinstance(node, ast.Call)
        assert isinstance(node.func, ast.Attribute)
        if node.func.attr == "exception":
            leaks.append(f"line {node.lineno}: logger.exception")
        for keyword in node.keywords:
            if keyword.arg == "exc_info" and not (
                isinstance(keyword.value, ast.Constant) and keyword.value.value in (None, False)
            ):
                leaks.append(f"line {node.lineno}: exc_info")
                continue
            leaks.extend(
                f"line {node.lineno}: {name}" for name in _leaks_in(keyword.value, exception_names)
            )
        for argument in node.args:
            leaks.extend(
                f"line {node.lineno}: {name}" for name in _leaks_in(argument, exception_names)
            )
    return leaks


def _log_call_lines(source: str) -> list[int]:
    """The line of every logging call in a source."""
    return sorted(node.lineno for node in ast.walk(ast.parse(source)) if _is_log_call(node))


_LOG_LEAK_SAMPLES: Final[tuple[str, ...]] = (
    'logger.info("converting %s", options.filename)',
    'logger.info("converting %s", filename)',
    'logger.debug("reading %s", path)',
    'logger.debug("writing %s", out_dir)',
    'logger.warning(f"page text {page_text}")',
    'logger.debug("label %s", label)',
    'logger.info("job %s", job)',
    'logger.debug("sheet %s", sheet.title)',
    'logger.debug("cell %s", value)',
    'logging.getLogger(__name__).info("child said %s", stdout)',
    'try:\n    pass\nexcept OSError as exc:\n    logger.error("failed: %s", exc)\n',
    'try:\n    pass\nexcept ValueError as error:\n    logger.error("failed: %s", str(error))\n',
    'try:\n    pass\nexcept OSError as exc:\n    logger.warning("failed: %r", exc.args)\n',
    'logger.exception("conversion failed")',
    'logger.warning("conversion failed", exc_info=True)',
)
_CLEAN_LOG_SAMPLE: Final = (
    "try:\n    pass\nexcept OSError as exc:\n"
    '    logger.warning("Conversion failed (%s).", type(exc).__name__)\n'
    "except ConversionError as failure:\n"
    '    logger.info("Conversion refused: %s", failure.reason)\n'
    'logger.info("Converted %d pages (%d tokens, %s)", page_count, token_estimate, kind)\n'
    'logger.info("Converted %d characters", len(text))\n'
    'logger.debug("status %s", status, exc_info=False)\n'
)


def _log_scanner_misses() -> list[str]:
    misses = [source for source in _LOG_LEAK_SAMPLES if _log_leaks(source) == []]
    if _log_leaks(_CLEAN_LOG_SAMPLE) != []:
        misses.append(_CLEAN_LOG_SAMPLE)
    if _log_call_lines(
        'log.info("a")\nlogging.warning("b")\nlogging.getLogger(n).debug("c")\n'
    ) != [
        1,
        2,
        3,
    ]:
        misses.append("log call finder")
    return misses


def test_converters_isolation_converter_logging_carries_no_names_paths_or_exception_text() -> None:
    """No logging call in admino.converters or tokens.py passes a file name, path, content,
    label, title, job or an exception's message; runner.py has no logging call."""
    assert _missing_layout() == []
    assert _log_scanner_misses() == []
    sources = _converter_sources()

    leaks = {module: found for module, source in sources.items() if (found := _log_leaks(source))}

    assert leaks == {}
    assert _log_call_lines(sources["admino.converters.runner"]) == []


# ---------------------------------------------------------------------------
# 6. Child processes: only the runner, never through a shell
# ---------------------------------------------------------------------------

_PROCESS_CALLS: Final = re.compile(
    r"os\.(?:system|popen|exec\w*|spawn\w*|posix_spawn\w*|fork\w*)|pty\.spawn|"
    r"asyncio\.create_subprocess_\w+"
)
_OS_PROCESS_NAMES: Final = re.compile(r"system|popen|exec\w*|spawn\w*|posix_spawn\w*|fork\w*")


def _imports_subprocess(source: str, module: str) -> bool:
    return any(
        name == "subprocess" or name.startswith("subprocess.")
        for name in _imported_names(source, module)
    )


def _process_hazards(source: str) -> list[str]:
    """Calls that pass a shell, or start a process outside subprocess.run: ``line N: what``."""
    hazards: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == "shell" and not (
                    isinstance(keyword.value, ast.Constant) and keyword.value.value is False
                ):
                    hazards.append(f"line {node.lineno}: shell")
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and _PROCESS_CALLS.fullmatch(f"{func.value.id}.{func.attr}")
            ):
                hazards.append(f"line {node.lineno}: {func.value.id}.{func.attr}")
        elif isinstance(node, ast.ImportFrom) and node.module in ("os", "pty", "asyncio"):
            hazards.extend(
                f"line {node.lineno}: {node.module}.{alias.name}"
                for alias in node.names
                if _OS_PROCESS_NAMES.fullmatch(alias.name)
                or alias.name.startswith("create_subprocess")
            )
    return hazards


_HAZARD_SAMPLES: Final[tuple[str, ...]] = (
    "subprocess.run(argv, shell=True)",
    "subprocess.run(argv, shell=flag)",
    "os.system('convert x')",
    "os.popen('convert x')",
    "os.execv(path, argv)",
    "os.spawnlp(0, 'x', 'x')",
    "os.posix_spawn(path, argv, env)",
    "asyncio.create_subprocess_shell('convert x')",
    "from os import system",
)
_CLEAN_HAZARD_SAMPLE: Final = (
    "subprocess.run(list(WORKER_ARGV), input=job, shell=False)\n"
    "subprocess.run(argv, check=False)\nos.replace(a, b)\nos.open(p, flags, 0o600)\n"
    "from os import fspath\n"
)


def test_converters_isolation_only_the_runner_starts_processes_and_never_via_a_shell() -> None:
    """Among the converters and tokens.py, only runner.py imports subprocess; no shell=
    other than False, no os.system/popen/exec/spawn, pty or asyncio subprocesses."""
    assert _missing_layout() == []
    assert [sample for sample in _HAZARD_SAMPLES if _process_hazards(sample) == []] == []
    assert _process_hazards(_CLEAN_HAZARD_SAMPLE) == []
    assert _imports_subprocess("from subprocess import run", "admino.converters.pdf")
    sources = _converter_sources()

    importers = sorted(
        module for module, source in sources.items() if _imports_subprocess(source, module)
    )
    hazards = {
        module: found for module, source in sources.items() if (found := _process_hazards(source))
    }

    assert importers == ["admino.converters.runner"]
    assert hazards == {}
