"""The configurable attachments root (GH-281, Decision 8; contract A1 to A3, A5, A6).

Issue #281, "Attachments root": "``ADMINO_ATTACHMENTS_ROOT`` sets the attachments
root (default ``/app/data/attachments``). The upload store, the conversion worker,
the downloads and the org purge (#154) all read the same setting. An unset or empty
value means the default; a relative path is refused at startup with a clear
message." Testing: "the root setting read by every consumer, including the purge,
and a relative path refused". What this file pins (``main()``'s part, A4, is in
tests/test_main.py):

- A1/A2: ``organizations.DEFAULT_ATTACHMENTS_ROOT == Path("/app/data/attachments")``
  and the process setting ``organizations.ATTACHMENTS_ROOT`` starts at it.
- A3: ``organizations.resolve_attachments_root(value)``: ``None`` and ``""`` give the
  default; an absolute path gives ``Path(value)``; anything else (``.``,
  ``data/attachments``, whitespace only, ``~/...``: no home expansion) raises a
  ``ValueError`` whose text is exactly ``ADMINO_ATTACHMENTS_ROOT must be an absolute
  path.``, never the value.
- A5: ``purge_due_orgs(pool)`` without ``attachments_root`` removes the due org's
  directory under the setting read at call time (today the default is bound at
  import, so a changed setting is ignored), and the same call agrees with
  ``attachments.attachments_root()``, the other consumers' accessor.
  ``run_org_purge_job(pool)`` reads it at every run: a root changed between two
  runs is used by the second one (the job's own sleep is a recorder).
- A6: no import-time binding of the root anywhere in ``src/admino``: no function
  parameter defaults to it (a ``*root*`` parameter defaults to ``None`` or nothing),
  no module- or class-level name is assigned from it (except organizations' own two
  constants), no module does ``from admino.organizations import ATTACHMENTS_ROOT``.
  The checker is run against binding and call-time samples first, so it can't pass
  by seeing nothing. And no module other than organizations holds the
  ``/app/data/attachments`` literal (docstrings aside).

Inputs: tests/db_fakes.FakeDb (a due org and an active one), files under
``tmp_path`` only; ``organizations.ATTACHMENTS_ROOT`` is changed with
``monkeypatch`` (restored after each test).
"""

from __future__ import annotations

import ast
import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import attachments, organizations
from tests.db_fakes import OTHER_ORG_ID, FakeDb

if TYPE_CHECKING:
    import uuid
    from collections.abc import Callable, Iterator

_REPO: Final = Path(__file__).resolve().parents[1]
_SRC: Final = _REPO / "src" / "admino"
_DEFAULT_TEXT: Final = "/app/data/attachments"
_DEFAULT: Final = Path(_DEFAULT_TEXT)
_MESSAGE: Final = "ADMINO_ATTACHMENTS_ROOT must be an absolute path."
_REAL_SLEEP: Final = asyncio.sleep
_WAIT_S: Final = 5.0
_MISSING: Final = object()


def _resolve(value: str | None) -> Path:
    """``organizations.resolve_attachments_root`` (looked up at call time: new in GH-281)."""
    resolved: Path = organizations.resolve_attachments_root(value)
    return resolved


# ---------------------------------------------------------------------------
# 1. The default and the resolver (A1 to A3)
# ---------------------------------------------------------------------------


def test_attachments_root_default_is_app_data_attachments() -> None:
    """The default is a Path at /app/data/attachments, and the process setting starts
    there (nothing has set it in a test process)."""
    default = getattr(organizations, "DEFAULT_ATTACHMENTS_ROOT", _MISSING)

    assert (isinstance(default, Path), default, organizations.ATTACHMENTS_ROOT) == (
        True,
        _DEFAULT,
        _DEFAULT,
    )


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_attachments_root_resolve_unset_or_empty_is_the_default(value: str | None) -> None:
    assert _resolve(value) == _DEFAULT


@pytest.mark.parametrize(
    "value",
    ["/srv/admino/attachments", "/Users/dev/admino/data/attachments"],
    ids=["srv", "checkout"],
)
def test_attachments_root_resolve_absolute_path_is_used(value: str) -> None:
    resolved = _resolve(value)

    assert (isinstance(resolved, Path), resolved) == (True, Path(value))


@pytest.mark.parametrize(
    "value",
    [".", "data/attachments", "zq281-relative/attachments", "   ", "~/attachments"],
    ids=["dot", "data-attachments", "relative-marker", "whitespace", "home-tilde"],
)
def test_attachments_root_resolve_refuses_a_non_absolute_path(value: str) -> None:
    """A ValueError whose text is the fixed message: the value is never echoed."""
    with pytest.raises(ValueError) as excinfo:
        _resolve(value)

    assert (str(excinfo.value), excinfo.value.args) == (_MESSAGE, (_MESSAGE,))


# ---------------------------------------------------------------------------
# 2. The org purge reads the setting at call time (A5)
# ---------------------------------------------------------------------------


def _due_org(db: FakeDb) -> uuid.UUID:
    """A pending_deletion org whose grace period ended a minute ago."""
    now = datetime.now(UTC)
    return db.add_org(
        status="pending_deletion",
        deletion_requested_at=now - timedelta(days=30, minutes=1),
        purge_after=now - timedelta(minutes=1),
    )


def _org_files(root: Path, org_id: uuid.UUID, name: str) -> Path:
    """``<root>/<org_id>/<name>`` and a derived artifact under ``<name>.d/``; returns the
    org's directory."""
    directory = root / str(org_id)
    (directory / f"{name}.d").mkdir(parents=True)
    (directory / name).write_bytes(b"original 281")
    (directory / f"{name}.d" / "text.md").write_bytes(b"derived 281")
    return directory


@pytest.fixture()
def setting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """``organizations.ATTACHMENTS_ROOT`` pointed at an empty ``tmp_path`` directory."""
    root = tmp_path / "setting-root"
    root.mkdir()
    monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", root)
    return root


async def test_attachments_root_purge_without_a_root_uses_the_setting_at_call_time(
    setting: Path,
) -> None:
    """``purge_due_orgs(pool)``: the due org's directory under the current setting is
    gone, an active org's stays, and ``attachments.attachments_root()`` names the same
    root (every consumer reads one setting)."""
    db = FakeDb()
    due = _due_org(db)
    kept_org = db.add_org(OTHER_ORG_ID)
    due_dir = _org_files(setting, due, "a1b2c3d4-0000-4000-8000-000000000281")
    kept_dir = _org_files(setting, kept_org, "a1b2c3d4-0000-4000-8000-000000000282")

    purged = await organizations.purge_due_orgs(db.pool)

    assert (purged, due_dir.exists(), kept_dir.exists(), attachments.attachments_root()) == (
        1,
        False,
        True,
        setting,
    )


def _switching_sleep(on_first: Callable[[], None], events: list[str]) -> Any:
    """A fake asyncio.sleep: the first call runs ``on_first`` (between the job's first
    and second run), the second raises CancelledError (ends the job)."""
    calls = {"n": 0}

    async def fake_sleep(delay: float, *_args: Any, **_kwargs: Any) -> None:
        calls["n"] += 1
        events.append(f"sleep {calls['n']}")
        if calls["n"] == 1:
            on_first()
        if calls["n"] >= 2:
            raise asyncio.CancelledError
        await _REAL_SLEEP(0)

    return fake_sleep


@pytest.fixture()
def two_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Path, Path]]:
    """Two roots; ``organizations.ATTACHMENTS_ROOT`` starts at the first."""
    first = tmp_path / "root-1"
    second = tmp_path / "root-2"
    first.mkdir()
    second.mkdir()
    monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", first)
    yield first, second


async def test_attachments_root_purge_job_reads_the_setting_at_every_run(
    monkeypatch: pytest.MonkeyPatch, two_roots: tuple[Path, Path]
) -> None:
    """``run_org_purge_job(pool)``: run 1 purges org 1 under root 1; between the runs the
    setting moves to root 2 and org 2 becomes due; run 2 purges org 2 under root 2. The
    decoys (org 1 under root 2, org 2 under root 1) stay: each run used its own root."""
    first, second = two_roots
    db = FakeDb()
    org_1 = _due_org(db)
    org_2 = db.add_org()
    org_1_dir = _org_files(first, org_1, "b1b2c3d4-0000-4000-8000-000000000281")
    org_2_dir = _org_files(second, org_2, "b1b2c3d4-0000-4000-8000-000000000282")
    decoy_1 = _org_files(second, org_1, "b1b2c3d4-0000-4000-8000-000000000283")
    decoy_2 = _org_files(first, org_2, "b1b2c3d4-0000-4000-8000-000000000284")
    events: list[str] = []

    def between_runs() -> None:
        now = datetime.now(UTC)
        db.add_org(
            org_2,
            status="pending_deletion",
            deletion_requested_at=now - timedelta(days=30, minutes=1),
            purge_after=now - timedelta(minutes=1),
        )
        monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", second)

    monkeypatch.setattr(asyncio, "sleep", _switching_sleep(between_runs, events))

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(organizations.run_org_purge_job(db.pool), _WAIT_S)

    assert (
        events,
        sorted(db.orgs),
        [org_1_dir.exists(), org_2_dir.exists()],
        [decoy_1.exists(), decoy_2.exists()],
    ) == (["sleep 1", "sleep 2"], [], [False, False], [True, True])


# ---------------------------------------------------------------------------
# 3. No import-time binding of the root, one literal (A6)
# ---------------------------------------------------------------------------

_ROOT_NAMES: Final = frozenset({"ATTACHMENTS_ROOT", "DEFAULT_ATTACHMENTS_ROOT"})
# organizations' own definitions of the two constants.
_ORGANIZATIONS_OWN: Final = frozenset({"ATTACHMENTS_ROOT", "DEFAULT_ATTACHMENTS_ROOT"})


def _names_root(node: ast.AST) -> bool:
    """Whether an expression reads the root: a root constant, a call of
    ``attachments_root()``, or the default path literal."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in _ROOT_NAMES:
            return True
        if isinstance(child, ast.Attribute) and child.attr in _ROOT_NAMES:
            return True
        if isinstance(child, ast.Call):
            func = child.func
            name = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute)
                else None
            )
            if name == "attachments_root":
                return True
        if (
            isinstance(child, ast.Constant)
            and isinstance(child.value, str)
            and _DEFAULT_TEXT in child.value
        ):
            return True
    return False


def _parameter_defaults(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
) -> list[tuple[str, ast.expr]]:
    arguments = node.args
    positional = [*arguments.posonlyargs, *arguments.args]
    pairs = list(
        zip(
            positional[len(positional) - len(arguments.defaults) :], arguments.defaults, strict=True
        )
    )
    pairs.extend(
        (argument, default)
        for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True)
        if default is not None
    )
    return [(argument.arg, default) for argument, default in pairs]


def _is_none(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _import_time_statements(body: list[ast.stmt]) -> Iterator[ast.stmt]:
    """The statements that run at import: module and class bodies, and the blocks of an
    ``if``/``try``/``with`` there; never a function body."""
    for statement in body:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        yield statement
        for field in ("body", "orelse", "finalbody"):
            inner = getattr(statement, field, None)
            if isinstance(inner, list):
                yield from _import_time_statements(inner)
        for handler in getattr(statement, "handlers", None) or []:
            yield from _import_time_statements(handler.body)


def _assigned_names(statement: ast.Assign | ast.AnnAssign | ast.AugAssign) -> set[str]:
    targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    return {
        node.id for target in targets for node in ast.walk(target) if isinstance(node, ast.Name)
    }


def _import_time_bindings(source: str, *, organizations_module: bool = False) -> list[str]:
    """Every place a source binds the attachments root before any call: a parameter
    default (any default naming the root, or a non-None default of a ``*root*``
    parameter), a module- or class-level assignment from the root, or ``from
    admino.organizations import ATTACHMENTS_ROOT``."""
    tree = ast.parse(source)
    findings: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            name = getattr(node, "name", "<lambda>")
            for parameter, default in _parameter_defaults(node):
                is_root = "root" in parameter.lower() and not _is_none(default)
                if is_root or _names_root(default):
                    findings.append(f"{node.lineno}:default:{name}({parameter})")
    for statement in _import_time_statements(tree.body):
        if isinstance(statement, ast.Assign | ast.AnnAssign | ast.AugAssign):
            if statement.value is None or not _names_root(statement.value):
                continue
            names = _assigned_names(statement)
            if organizations_module and names <= _ORGANIZATIONS_OWN:
                continue
            findings.append(f"{statement.lineno}:assign:{','.join(sorted(names))}")
        elif isinstance(statement, ast.ImportFrom) and (statement.module or "").endswith(
            "organizations"
        ):
            findings.extend(
                f"{statement.lineno}:import:{alias.name}"
                for alias in statement.names
                if alias.name == "ATTACHMENTS_ROOT"
            )
    return findings


# Sources the checker must flag (each binds the root at import), and ones it must not.
_BINDING_SAMPLES: Final[tuple[str, ...]] = (
    "def f(root=organizations.ATTACHMENTS_ROOT):\n    return root\n",
    "async def f(pool, *, attachments_root: Path = ATTACHMENTS_ROOT) -> None:\n    pass\n",
    "def f(*, root: Path = Path('/srv/attachments')) -> Path:\n    return root\n",
    "def f(target=attachments.attachments_root()):\n    return target\n",
    "_ROOT = organizations.ATTACHMENTS_ROOT\n",
    "class Store:\n    base: Path = attachments.attachments_root()\n",
    "try:\n    _ROOT: Path = organizations.DEFAULT_ATTACHMENTS_ROOT\nexcept Exception:\n    pass\n",
    "from admino.organizations import ATTACHMENTS_ROOT\n",
    "_FALLBACK = Path('/app/data/attachments') / 'x'\n",
)
_CALL_TIME_SAMPLES: Final[tuple[str, ...]] = (
    "def f(*, attachments_root: Path | None = None) -> Path:\n"
    "    if attachments_root is None:\n"
    "        attachments_root = organizations.ATTACHMENTS_ROOT\n"
    "    return attachments_root\n",
    "def f() -> Path:\n    root = attachments.attachments_root()\n    return root\n",
    "_ROOT_OF = attachments.attachments_root\n",
    "def f(pool, *, interval_seconds: float = 3600.0) -> None:\n    pass\n",
)


def _checker_misses() -> list[str]:
    misses = [sample for sample in _BINDING_SAMPLES if not _import_time_bindings(sample)]
    misses.extend(sample for sample in _CALL_TIME_SAMPLES if _import_time_bindings(sample))
    return misses


def _modules() -> list[Path]:
    return sorted(_SRC.rglob("*.py"))


def test_attachments_root_no_function_or_module_binds_the_root_at_import() -> None:
    """Every consumer reads the setting when it runs: no parameter default, module- or
    class-level alias or ``from ... import ATTACHMENTS_ROOT`` in src/admino holds it
    (organizations' own two constants aside)."""
    findings = [
        f"{path.relative_to(_SRC)}:{finding}"
        for path in _modules()
        for finding in _import_time_bindings(
            path.read_text(encoding="utf-8"),
            organizations_module=path == _SRC / "organizations.py",
        )
    ]

    assert (_checker_misses(), findings) == ([], [])


def _docstring_ids(tree: ast.Module) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            first = node.body[0] if node.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def _default_literals(path: Path) -> list[int]:
    """Lines of the string constants (docstrings aside) holding /app/data/attachments."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = _docstring_ids(tree)
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and _DEFAULT_TEXT in node.value
        and id(node) not in docstrings
    ]


def test_attachments_root_only_organizations_holds_the_default_path() -> None:
    """The default lives in ``organizations.DEFAULT_ATTACHMENTS_ROOT`` and no other module
    of src/admino spells /app/data/attachments."""
    elsewhere = {
        str(path.relative_to(_SRC)): lines
        for path in _modules()
        if path != _SRC / "organizations.py" and (lines := _default_literals(path))
    }

    assert (getattr(organizations, "DEFAULT_ATTACHMENTS_ROOT", _MISSING), elsewhere) == (
        _DEFAULT,
        {},
    )
