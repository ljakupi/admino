"""No LLM tool can reach attachments, and attachment logs carry no names (GH-187).

Issue #187, "DevOps & security": "Logs carry IDs, sizes and types only. No LLM
tool can reach attachments." Contract §6 pins how:

- The four attachment modules exist: ``admino.attachments`` (repository,
  storage, upload service), ``admino.attachment_types`` (pure detection and
  filename rules), ``admino.attachment_processing`` (the bounded processing
  pool) and ``admino.attachment_gc`` (the orphan GC).
- Nothing the LLM's tool calls run through imports them, in any form (``import
  x``, ``import x as y``, ``from admino import x``, ``from admino.x import y``,
  relative imports, a function-level or TYPE_CHECKING import, a dynamic
  ``__import__("admino.x")``): every module under ``admino/tools/``,
  ``agent.py``, every ``llm*.py``, ``permissions.py``, ``prompt_assembly.py``
  and ``untrusted.py``. ``permissions.py`` keeps exactly its pinned import set
  (``__future__``, ``logging``, ``re``, ``typing``, ``pydantic``,
  ``admino.logs``).
- No tool the real tool modules register has a name containing "attachment",
  and no ``register_tool(...)`` call anywhere in the package names one
  (attachments get no tool before #192 decides how).
- The four modules' logging calls pass no file name, raw header value or file
  bytes: no argument mentions an identifier named like ``filename``,
  ``name``/``*_name`` (except type/class/exception names), ``raw``/``raw_*``,
  anything with ``header``, or ``chunk``/``body``/``content``/``head``. An
  exception is logged by its class name only (``type(exc).__name__``): never
  the exception object, ``str(exc)``, ``exc.args``, ``logger.exception`` or
  ``exc_info=`` (an error message can carry a path, a zip member's name or a
  database row). ``exc.<attribute>`` such as a refusal's ``reason`` code stays
  allowed. The HTTP tests capture the runtime log lines; this is the static
  guard over the code paths they don't reach.

The scans read the source of the imported ``admino`` package (``admino.__file__``),
so they check whatever implementation is on the import path. Each scanner is
first run on known samples, so a scanner that silently finds nothing fails.
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

import admino

if TYPE_CHECKING:
    import pytest

_PACKAGE_DIR: Final = Path(admino.__file__).resolve().parent

_ATTACHMENT_MODULES: Final = (
    "admino.attachments",
    "admino.attachment_types",
    "admino.attachment_processing",
    "admino.attachment_gc",
)

# permissions.py's import set (CLAUDE.md, tests/test_permissions.py): unchanged by #187.
_PERMISSIONS_IMPORTS: Final = frozenset(
    {"__future__", "logging", "re", "typing", "pydantic", "admino.logs"}
)


# ---------------------------------------------------------------------------
# Import scanner
# ---------------------------------------------------------------------------


def _module_name(path: Path) -> str:
    """The dotted module name of a file inside the admino package."""
    relative = path.relative_to(_PACKAGE_DIR.parent).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _imported_names(source: str, module: str, *, is_package: bool = False) -> list[str]:
    """Every module (and ``from`` target) a source imports, relative imports resolved
    against ``module``, plus string constants naming an attachment module (a dynamic
    ``__import__``)."""
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
        elif isinstance(node, ast.Constant) and node.value in _ATTACHMENT_MODULES:
            names.append(str(node.value))
    return names


def _attachment_imports(source: str, module: str, *, is_package: bool = False) -> list[str]:
    """The attachment modules (or their members) a source imports."""
    return sorted(
        {
            name
            for name in _imported_names(source, module, is_package=is_package)
            if any(
                name == target or name.startswith(f"{target}.") for target in _ATTACHMENT_MODULES
            )
        }
    )


def _llm_reachable_files() -> list[Path]:
    """The modules an LLM tool call runs through: admino/tools/**, agent.py, llm*.py,
    permissions.py, prompt_assembly.py, untrusted.py."""
    files = sorted((_PACKAGE_DIR / "tools").rglob("*.py"))
    files.append(_PACKAGE_DIR / "agent.py")
    files.extend(sorted(_PACKAGE_DIR.glob("llm*.py")))
    files.extend(
        _PACKAGE_DIR / name for name in ("permissions.py", "prompt_assembly.py", "untrusted.py")
    )
    return files


# Each sample, as module admino.tools.sample (or admino.agent), imports an
# attachment module; the scanner must find it.
_IMPORT_SAMPLES: Final[tuple[tuple[str, str], ...]] = (
    ("admino.tools.sample", "import admino.attachments"),
    ("admino.tools.sample", "import admino.attachment_types as kinds"),
    ("admino.tools.sample", "from admino import attachment_processing"),
    ("admino.tools.sample", "from admino import logs, attachment_gc as gc"),
    ("admino.tools.sample", "from admino.attachments import upload_attachment"),
    ("admino.tools.sample", "from .. import attachments"),
    ("admino.tools.sample", "from ..attachment_types import detect_kind"),
    ("admino.agent", "from . import attachments"),
    ("admino.agent", "from .attachment_gc import collect_garbage"),
    ("admino.tools.sample", "def load():\n    import admino.attachments\n"),
    (
        "admino.tools.sample",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n"
        "    from admino.attachments import AttachmentRecord\n",
    ),
    ("admino.tools.sample", "module = __import__('admino.attachment_gc')"),
)
# Imports the scanner must NOT flag.
_CLEAN_IMPORT_SAMPLE: Final = (
    "from __future__ import annotations\nimport admino.chats\nfrom admino import logs\n"
    "from admino.tools.registry import register_tool\nfrom .. import organizations\n"
)


def _scanner_misses() -> list[str]:
    """The samples the import scanner gets wrong (empty when it works)."""
    misses = [
        source for module, source in _IMPORT_SAMPLES if _attachment_imports(source, module) == []
    ]
    if _attachment_imports(_CLEAN_IMPORT_SAMPLE, "admino.tools.sample") != []:
        misses.append(_CLEAN_IMPORT_SAMPLE)
    return misses


def _top_level_imports(path: Path) -> set[str]:
    """The modules a file imports (``from x import y`` counts as ``x``)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.add("." * node.level + (node.module or ""))
    return modules


# ---------------------------------------------------------------------------
# Log scanner
# ---------------------------------------------------------------------------

_LOG_METHODS: Final = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "log"}
)
# Identifiers that name a file name, a raw header value or file bytes.
_LEAKY_IDENTIFIER: Final = re.compile(
    r"(?i)(?:.*file_?name.*|.*header.*|raw|raw_.*|.*_raw|chunks?|body|content|head|.*name)"
)
# ``*name`` identifiers that hold a type, class or exception name, never input.
_SAFE_NAME: Final = re.compile(
    r"(?i).*(?:type|class|exc|exception|error|err|kind|module|func|function|logger|reason|"
    r"status|column|table|key)_?name"
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
    """The leaky identifiers a log-call argument mentions."""
    found: list[str] = []

    def visit(current: ast.AST) -> None:
        if isinstance(current, ast.Attribute):
            if current.attr in ("__name__", "__qualname__"):
                return  # a class or function name, e.g. type(exc).__name__
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


# Each sample logs something it must not; the scanner must flag it.
_LOG_LEAK_SAMPLES: Final[tuple[str, ...]] = (
    'logger.info("stored %s", filename)',
    'logger.warning("stored %s", record.filename)',
    'logger.info(f"stored {original_name}")',
    'logger.info("stored %s", name)',
    'logger.debug("got %s", raw)',
    'logger.debug("got %s", request.headers)',
    'logger.debug("got %s", header_value)',
    'logger.log(logging.INFO, "read %s", chunk)',
    'logging.getLogger(__name__).info("stored %s", safe_filename)',
    'try:\n    pass\nexcept OSError as exc:\n    logger.error("failed: %s", exc)\n',
    'try:\n    pass\nexcept OSError as exc:\n    logger.error("failed: %s", str(exc))\n',
    'try:\n    pass\nexcept OSError as error:\n    logger.error("failed: %r", error.args)\n',
    'try:\n    pass\nexcept OSError as exc:\n    log.warning(f"failed: {exc!r}")\n',
    'logger.exception("processing failed")',
    'logger.warning("processing failed", exc_info=True)',
)
# Content-free logging the scanner must NOT flag.
_CLEAN_LOG_SAMPLE: Final = (
    "try:\n    pass\nexcept OSError as exc:\n"
    '    logger.warning("Attachment removal failed (%s).", type(exc).__name__)\n'
    '    logger.warning("failed (%s)", exc.__class__.__name__)\n'
    "except AttachmentRefusedError as refused:\n"
    '    logger.info("Upload refused: %s", refused.reason)\n'
    'logger.info("Stored attachment %s of org %s (%d bytes, %s)", attachment_id, org_id, '
    "size_bytes, kind)\n"
    'logger.info("Removed %d entries", removed)\n'
    'logger.warning("Processing %s failed (%s)", record.id, error_name)\n'
    'logger.debug("status %s", status, exc_info=False)\n'
)


def _log_scanner_misses() -> list[str]:
    """The samples the log scanner gets wrong (empty when it works)."""
    misses = [source for source in _LOG_LEAK_SAMPLES if _log_leaks(source) == []]
    if _log_leaks(_CLEAN_LOG_SAMPLE) != []:
        misses.append(_CLEAN_LOG_SAMPLE)
    return misses


def _module_file(name: str) -> Path | None:
    """The source file of a module on the import path, or None when it doesn't exist."""
    spec = importlib.util.find_spec(name)
    if spec is None or spec.origin is None:
        return None
    return Path(spec.origin)


# ---------------------------------------------------------------------------
# 1. The four modules exist
# ---------------------------------------------------------------------------


def test_attachments_isolation_the_four_modules_exist() -> None:
    """attachments, attachment_types, attachment_processing and attachment_gc import."""
    missing = [name for name in _ATTACHMENT_MODULES if _module_file(name) is None]
    assert missing == []
    for name in _ATTACHMENT_MODULES:
        importlib.import_module(name)


# ---------------------------------------------------------------------------
# 2. Nothing on the LLM's tool path imports them
# ---------------------------------------------------------------------------


def test_attachments_isolation_no_llm_reachable_module_imports_them() -> None:
    """No module under tools/, agent.py, llm*.py, permissions.py, prompt_assembly.py or
    untrusted.py imports an attachment module, in any form. The four modules must exist
    (else the scan proves nothing) and the scanner must catch every sample form."""
    files = _llm_reachable_files()
    names = {path.name for path in files}

    assert [name for name in _ATTACHMENT_MODULES if _module_file(name) is None] == []
    assert _scanner_misses() == []
    assert {
        "registry.py",
        "memory.py",
        "agent.py",
        "llm.py",
        "llm_policy.py",
        "permissions.py",
        "prompt_assembly.py",
        "untrusted.py",
    } <= names
    hits = {
        _module_name(path): found
        for path in files
        if (
            found := _attachment_imports(
                path.read_text(encoding="utf-8"),
                _module_name(path),
                is_package=path.name == "__init__.py",
            )
        )
    }
    assert hits == {}


def test_attachments_isolation_permissions_keeps_its_import_set() -> None:
    """permissions.py imports exactly its pinned set, next to the four attachment modules
    (#187 adds nothing to the engine)."""
    assert [name for name in _ATTACHMENT_MODULES if _module_file(name) is None] == []
    assert _top_level_imports(_PACKAGE_DIR / "permissions.py") == _PERMISSIONS_IMPORTS


# ---------------------------------------------------------------------------
# 3. No tool is named after attachments
# ---------------------------------------------------------------------------


def _register_calls_naming_attachments() -> list[str]:
    """``register_tool(...)`` calls anywhere in the package with a string argument that
    contains "attachment": ``module:line``."""
    hits: list[str] = []
    for path in sorted(_PACKAGE_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            called = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if called != "register_tool":
                continue
            texts = [
                argument.value
                for argument in [*node.args, *(keyword.value for keyword in node.keywords)]
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str)
            ]
            if any("attachment" in text.lower() for text in texts):
                hits.append(f"{_module_name(path)}:{node.lineno}")
    return hits


def test_attachments_isolation_no_registered_tool_is_named_after_attachments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the four modules imported, the real tool modules (main's import list,
    re-registered into a clean registry) register no tool or action whose name contains
    "attachment", and no register_tool call in the package names one."""
    from admino.main import _import_tool_modules
    from admino.tools import registry

    for name in _ATTACHMENT_MODULES:
        importlib.import_module(name)
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)
    _import_tool_modules()
    # A first import above registers into the clean registry already: start over, then
    # re-run every loaded tool module's decorators.
    registry.clear_registry()
    for name in sorted(sys.modules):
        if name.startswith("admino.tools.") and name != "admino.tools.registry":
            importlib.reload(sys.modules[name])
    keys = set(registry._REGISTRY)

    assert ("memory", "store") in keys
    assert (
        sorted(
            f"{tool}.{action}"
            for tool, action in keys
            if "attachment" in f"{tool}.{action}".lower()
        )
        == []
    )
    assert _register_calls_naming_attachments() == []


# ---------------------------------------------------------------------------
# 4. The attachment modules log IDs, sizes and types only
# ---------------------------------------------------------------------------


def test_attachments_isolation_attachment_modules_log_no_names_or_content() -> None:
    """No logging call of the four modules passes a file name, a raw header value, file
    bytes or an exception's message (class names only). The scanner must catch every
    sample leak and pass the content-free sample."""
    assert _log_scanner_misses() == []
    files = {name: _module_file(name) for name in _ATTACHMENT_MODULES}
    assert [name for name, path in files.items() if path is None] == []

    leaks = {
        name: found
        for name, path in files.items()
        if path is not None and (found := _log_leaks(path.read_text(encoding="utf-8")))
    }

    assert leaks == {}
