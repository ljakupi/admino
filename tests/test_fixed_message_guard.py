"""Admino's own 422 messages can't be built from the input (GH-304 criterion 3).

Issue #304 Decision 3 and contract C4. ``FixedMessageError`` (``admino.models``) is the
opt-in error whose text the 422 handlers answer as ``msg``, so its message must be fixed in
the source. Pinned:

1. Every ``FixedMessageError(...)`` call under ``src/admino`` (callee the name
   ``FixedMessageError`` or an attribute ``.FixedMessageError``) takes exactly one positional
   argument and no keyword, and that argument is a string literal (implicit concatenation of
   literals included) or a name bound once to one: a module-level constant
   (``Assign``/``AnnAssign``, e.g. ``_MODEL_NAME_ERROR: Final = "..."``) or a single local
   assignment in the enclosing function (``msg = "..."; raise FixedMessageError(msg)``).
   An f-string, ``%``, ``+``, ``.format`` or any other expression fails, and so does a
   parameter, a name bound twice (each message gets its own binding or is passed as the
   literal), a name bound to anything but a string literal, and a name declared ``global`` or
   ``nonlocal``. The name resolves through the call's real scope chain, comprehensions
   included: a name bound to a literal but rebound in an inner scope between that binding and
   the call (a comprehension's loop variable, a lambda parameter, a nested function's
   parameter or local) fails, because at runtime the call sees the inner binding.
2. Nothing under ``src/admino`` raises the bare class, subclasses it, or imports or assigns
   it under another name (each would evade the call scan).
3. The real scan is not vacuous: in ``src/admino/models.py`` it finds the 20 call sites of
   contract C3 in their 18 request-model validator functions, each with its fixed text.
4. The scanner is proven on sample sources: each failing form is reported at its line, and
   each passing form is accepted and found (with its resolved text).

The scan parses ``src/admino`` next to this test file (not the installed package), so it
checks the tree it runs in, and imports nothing from admino. A violation reads
``path:line: reason``, so a failure tells the developer what to fix.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parent.parent
_SRC_DIR: Final = _REPO_ROOT / "src" / "admino"
_MODELS_PATH: Final = "src/admino/models.py"

_CLASS_NAME: Final = "FixedMessageError"
_FUNCTION_SCOPES: Final = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_SCOPES: Final = (*_FUNCTION_SCOPES, ast.ClassDef)
# Python 3 comprehensions run in their own scope: their loop variables are local to them.
_COMPREHENSIONS: Final = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
# Nodes that bind their ``name`` attribute (a def, class, ``except ... as``, match capture).
_NAMED_BINDERS: Final = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.ExceptHandler,
    ast.MatchAs,
    ast.MatchStar,
)
_SNIPPET_LENGTH: Final = 80

# Contract C3: the request-model validators that raise FixedMessageError, by qualified
# function name, with the fixed text of each call site (two sites in two of them).
_C3_SITES: Final[dict[str, tuple[str, ...]]] = {
    "ConfirmRequest._check_one_chat_reference": ("Give exactly one of chat_id and session_id.",),
    "SettingsPatchLLM.validate_model_name": ("Model name contains invalid characters.",),
    "UserSettingsPatch._check_something_given": ("Give at least one setting to change.",),
    "PlatformSettingsPatch._check_something_given": ("Give at least one setting to change.",),
    "_check_invite_email": (
        "The email must look like name@example.com.",
        "The email must not contain whitespace, control or invisible characters.",
    ),
    "InvitationAcceptRequest._check_name": (
        "The name must not contain control or formatting characters.",
    ),
    "_check_org_name": ("The name must not contain control or formatting characters.",),
    "OrgLimitsPatch._check_something_given": ("Give at least one limit to change.",),
    "OrgUserPatch._check_name": ("The name must not contain control or formatting characters.",),
    "OrgUserPatch._check_something_given": ("Give a role, a name or an email to change.",),
    "MyAccountPatch._check_name": ("The name must not contain control or formatting characters.",),
    "MyAccountPatch._check_timezone": ("Unknown timezone.",),
    "MyAccountPatch._check_personal_instructions": (
        "The personal instructions must not contain control or formatting characters.",
    ),
    "MyAccountPatch._check_given_fields": (
        "Give at least one field to change.",
        "Only response_language can be null.",
    ),
    "OrgSettingsPatch._check_instructions": (
        "The instructions must not contain control or formatting characters.",
    ),
    "OrgSettingsPatch._check_something_given": ("Give at least one setting to change.",),
    "_check_chat_title": ("The title must not contain control or formatting characters.",),
    "ChatMessageCreate._refuse_duplicates": ("Each attachment can be sent only once per message.",),
}


# --- the scanner ----------------------------------------------------------------------------


@dataclass(frozen=True)
class _Site:
    """One accepted ``FixedMessageError`` call: its enclosing function and its fixed text."""

    qualname: str
    message: str


@dataclass(frozen=True)
class _ScanResult:
    """Accepted call sites in source order, and the violations (``path:line: reason``)."""

    sites: tuple[_Site, ...]
    violations: tuple[str, ...]


def _is_class_ref(node: ast.AST) -> bool:
    """True for the name ``FixedMessageError`` or any attribute ``.FixedMessageError``."""
    return (isinstance(node, ast.Name) and node.id == _CLASS_NAME) or (
        isinstance(node, ast.Attribute) and node.attr == _CLASS_NAME
    )


def _is_str_constant(node: ast.AST | None) -> bool:
    """True for a string literal (implicit concatenation of literals is one constant)."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _snippet(node: ast.AST) -> str:
    """The node's source, cut to a readable length for the violation text."""
    text = ast.unparse(node).strip()
    return text if len(text) <= _SNIPPET_LENGTH else text[: _SNIPPET_LENGTH - 3] + "..."


def _parameters(scope: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> dict[str, ast.arg]:
    """Every parameter of a function or lambda, by name."""
    args = scope.args
    every = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    every.extend(arg for arg in (args.vararg, args.kwarg) if arg is not None)
    return {arg.arg: arg for arg in every}


def _scope_roots(scope: ast.AST) -> list[ast.AST]:
    """The nodes evaluated in the scope's own namespace (its body)."""
    if isinstance(scope, ast.Lambda):
        return [scope.body]
    if isinstance(scope, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return list(scope.body)
    return []


def _binds(node: ast.AST, name: str) -> bool:
    """True when the node binds ``name`` in the namespace it is evaluated in."""
    if isinstance(node, ast.Name):
        return node.id == name and isinstance(node.ctx, ast.Store)
    if isinstance(node, _NAMED_BINDERS):
        return node.name == name
    if isinstance(node, ast.MatchMapping):
        return node.rest == name
    if isinstance(node, ast.alias):
        return (node.asname or node.name.partition(".")[0]) == name
    return False


def _bindings(scope: ast.AST, name: str) -> list[tuple[ast.AST, ast.AST]]:
    """Every binding of ``name`` in the scope's own namespace, as (binder, its parent).

    Nested functions, lambdas and classes are their own scopes (only their name binds
    here), and a comprehension's loop variable is local to the comprehension (see
    ``_target_bindings``); an assignment expression inside a comprehension does bind here.
    """
    found: list[tuple[ast.AST, ast.AST]] = []
    stack: list[tuple[ast.AST, ast.AST]] = [(root, scope) for root in _scope_roots(scope)]
    while stack:
        node, parent = stack.pop()
        if _binds(node, name):
            found.append((node, parent))
        if isinstance(node, _SCOPES):
            continue
        for child in ast.iter_child_nodes(node):
            if isinstance(node, ast.comprehension) and child is node.target:
                continue
            stack.append((child, node))
    return sorted(found, key=lambda pair: getattr(pair[0], "lineno", 0))


def _literal_binding(binder: ast.AST, parent: ast.AST) -> str | None:
    """The string a ``name = "..."`` (or annotated) assignment binds, else None."""
    if (
        isinstance(parent, ast.Assign)
        and any(target is binder for target in parent.targets)
        and isinstance(parent.value, ast.Constant)
        and isinstance(parent.value.value, str)
    ):
        return parent.value.value
    if (
        isinstance(parent, ast.AnnAssign)
        and parent.target is binder
        and isinstance(parent.value, ast.Constant)
        and isinstance(parent.value.value, str)
    ):
        return parent.value.value
    return None


def _target_bindings(
    comprehension: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp, name: str
) -> list[tuple[ast.AST, ast.AST]]:
    """Every loop variable ``name`` of a comprehension, as (binder, its ``for`` clause)."""
    return [
        (node, clause)
        for clause in comprehension.generators
        for node in ast.walk(clause.target)
        if _binds(node, name)
    ]


@dataclass(frozen=True)
class _Binder:
    """A scope on a call's scope chain that binds the message name: its parameter, if the
    name is one, and its bindings of the name (as (binder, its parent))."""

    scope: ast.AST
    parameter: ast.arg | None
    bindings: tuple[tuple[ast.AST, ast.AST], ...]

    def literal_line(self) -> int | None:
        """The line where this scope binds the name to a string literal, if it does."""
        for binder, parent in self.bindings:
            if _literal_binding(binder, parent) is not None:
                return getattr(binder, "lineno", 0)
        return None

    def describe(self) -> str:
        """What binds the name here, for a violation text."""
        scope, parameter = self.scope, self.parameter
        if isinstance(scope, ast.Lambda):
            kind = "a lambda parameter" if parameter else "a name bound in a lambda"
        elif isinstance(scope, ast.FunctionDef | ast.AsyncFunctionDef):
            kind = f"a parameter of {scope.name}" if parameter else f"a local of {scope.name}"
        elif isinstance(scope, ast.ClassDef):
            kind = f"a name in the body of class {scope.name}"
        else:
            kind = "a comprehension's loop variable"
        node = parameter if parameter is not None else self.bindings[0][0]
        return f"{kind}, line {getattr(node, 'lineno', '?')}"


def _binders(scopes: tuple[ast.AST, ...], name: str) -> list[_Binder]:
    """The scopes a call can see (``scopes``, outermost first) that bind ``name``, innermost
    first. A class body is visible only to code directly in it, not to its methods or its
    comprehensions."""
    found: list[_Binder] = []
    innermost = scopes[-1]
    for scope in reversed(scopes):
        if scope is not innermost and isinstance(scope, ast.ClassDef):
            continue
        parameter = None
        if isinstance(scope, _FUNCTION_SCOPES):
            parameter = _parameters(scope).get(name)
        if isinstance(scope, _COMPREHENSIONS):
            bindings = _target_bindings(scope, name)
        else:
            bindings = _bindings(scope, name)
        if parameter is not None or bindings:
            found.append(_Binder(scope, parameter, tuple(bindings)))
    return found


class _Scanner:
    """AST scan of one module for the C4 rules."""

    def __init__(self, source: str, path: str) -> None:
        self._path = path
        self._module = ast.parse(source)
        self._sites: list[_Site] = []
        self._violations: list[tuple[int, str]] = []
        self._declared_global = {
            name
            for node in ast.walk(self._module)
            if isinstance(node, ast.Global | ast.Nonlocal)
            for name in node.names
        }

    def run(self) -> _ScanResult:
        self._visit(self._module, (), (self._module,))
        ordered = sorted(self._violations, key=lambda item: item[0])
        return _ScanResult(tuple(self._sites), tuple(text for _, text in ordered))

    def _report(self, line: int, reason: str) -> None:
        self._violations.append((line, f"{self._path}:{line}: {reason}"))

    def _visit(self, node: ast.AST, qual: tuple[str, ...], scopes: tuple[ast.AST, ...]) -> None:
        for child in ast.iter_child_nodes(node):
            self._walk(child, qual, scopes)

    def _walk(self, node: ast.AST, qual: tuple[str, ...], scopes: tuple[ast.AST, ...]) -> None:
        """Check ``node`` and everything under it; ``scopes`` is its scope chain."""
        self._check(node, qual, scopes)
        if isinstance(node, _SCOPES):
            name = node.name if not isinstance(node, ast.Lambda) else "<lambda>"
            self._visit(node, (*qual, name), (*scopes, node))
        elif isinstance(node, _COMPREHENSIONS):
            # Its own scope (not part of the qualified name), except for the first iterable,
            # which runs in the enclosing scope.
            inner = (*scopes, node)
            first = node.generators[0]
            for child in ast.iter_child_nodes(node):
                if child is first:
                    self._walk(first.target, qual, inner)
                    self._walk(first.iter, qual, scopes)
                    for condition in first.ifs:
                        self._walk(condition, qual, inner)
                else:
                    self._walk(child, qual, inner)
        else:
            self._visit(node, qual, scopes)

    def _check(self, node: ast.AST, qual: tuple[str, ...], scopes: tuple[ast.AST, ...]) -> None:
        if isinstance(node, ast.Call) and _is_class_ref(node.func):
            self._check_call(node, qual, scopes)
        elif isinstance(node, ast.Raise) and node.exc is not None and _is_class_ref(node.exc):
            self._report(
                node.lineno,
                'raises the bare class; raise FixedMessageError("...") with its fixed message',
            )
        elif isinstance(node, ast.ClassDef) and any(_is_class_ref(base) for base in node.bases):
            self._report(
                node.lineno,
                f"class {node.name} subclasses FixedMessageError; raise FixedMessageError itself",
            )
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == _CLASS_NAME and alias.asname not in (None, _CLASS_NAME):
                    self._report(
                        alias.lineno,
                        f"imports FixedMessageError as {alias.asname}; import it under its "
                        "own name so the guard sees every call",
                    )
        elif (
            isinstance(node, ast.Assign | ast.AnnAssign | ast.NamedExpr)
            and node.value is not None
            and _is_class_ref(node.value)
        ):
            self._report(
                node.lineno,
                "binds FixedMessageError to another name; call it by its own name so the "
                "guard sees every call",
            )

    def _check_call(
        self, call: ast.Call, qual: tuple[str, ...], scopes: tuple[ast.AST, ...]
    ) -> None:
        if call.keywords:
            self._report(
                call.lineno,
                "FixedMessageError takes no keyword argument; pass the fixed message positionally",
            )
            return
        if len(call.args) != 1:
            self._report(
                call.lineno,
                "FixedMessageError takes exactly one positional argument (the fixed message), "
                f"got {len(call.args)}",
            )
            return
        message = self._resolve(call, call.args[0], scopes)
        if message is not None:
            self._sites.append(_Site(".".join(qual) or "<module>", message))

    def _resolve(self, call: ast.Call, arg: ast.expr, scopes: tuple[ast.AST, ...]) -> str | None:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
        if not isinstance(arg, ast.Name):
            self._report(
                call.lineno,
                f"the message `{_snippet(arg)}` must be a string literal or a name bound once "
                "to one (no f-string, %, +, .format or other expression)",
            )
            return None
        name = arg.id
        if name in self._declared_global:
            self._report(
                call.lineno,
                f"the message `{name}` is declared global or nonlocal in this module; use a "
                "string literal or a name bound once to one",
            )
            return None
        binders = _binders(scopes, name)
        if not binders:
            self._report(
                call.lineno,
                f"the message `{name}` is not bound to a string literal in this module",
            )
            return None
        # At runtime the call sees the innermost binding. When that one isn't a literal but
        # an outer scope binds the name to one, the inner scope hides the literal.
        inner = binders[0]
        outer_line = next(
            (line for binder in binders[1:] if (line := binder.literal_line()) is not None), None
        )
        if inner.literal_line() is None and outer_line is not None:
            self._report(
                call.lineno,
                f"the message `{name}` is rebound in an inner scope ({inner.describe()}), "
                f"which hides its string literal at line {outer_line}; don't rebind the "
                "message's name between its binding and the call",
            )
            return None
        if inner.parameter is not None:
            self._report(
                call.lineno,
                f"the message `{name}` is a parameter; use a string literal or a name "
                "bound once to one",
            )
            return None
        return self._single_literal(call, name, list(inner.bindings))

    def _single_literal(
        self, call: ast.Call, name: str, bindings: list[tuple[ast.AST, ast.AST]]
    ) -> str | None:
        lines = ", ".join(str(getattr(binder, "lineno", "?")) for binder, _ in bindings)
        if len(bindings) != 1:
            self._report(
                call.lineno,
                f"the message `{name}` is bound {len(bindings)} times (lines {lines}); bind "
                "each fixed message once (its own name, or pass the literal itself)",
            )
            return None
        binder, parent = bindings[0]
        message = _literal_binding(binder, parent)
        if message is None:
            self._report(
                call.lineno,
                f"the message `{name}` is bound to `{_snippet(parent)}` (line {lines}), not "
                "to a string literal",
            )
        return message


def _scan(source: str, path: str) -> _ScanResult:
    """Scan one module's source; ``path`` prefixes every violation."""
    return _Scanner(source, path).run()


@pytest.fixture(scope="module")
def src_scan() -> dict[str, _ScanResult]:
    """The scan of every module under src/admino, keyed by its repository-relative path."""
    paths = sorted(_SRC_DIR.rglob("*.py"))
    assert _SRC_DIR / "models.py" in paths, f"no admino sources under {_SRC_DIR}"
    results: dict[str, _ScanResult] = {}
    for path in paths:
        relative = path.relative_to(_REPO_ROOT).as_posix()
        results[relative] = _scan(path.read_text(encoding="utf-8"), relative)
    return results


# --- the real scan --------------------------------------------------------------------------


def test_fixed_message_guard_src_tree_has_no_violation(
    src_scan: dict[str, _ScanResult],
) -> None:
    violations = [violation for result in src_scan.values() for violation in result.violations]

    assert violations == []


def test_fixed_message_guard_src_tree_finds_every_request_model_site(
    src_scan: dict[str, _ScanResult],
) -> None:
    sites = src_scan[_MODELS_PATH].sites
    found = {
        qualname: tuple(sorted(site.message for site in sites if site.qualname == qualname))
        for qualname in _C3_SITES
    }

    assert found == {qualname: tuple(sorted(texts)) for qualname, texts in _C3_SITES.items()}


# --- the scanner on samples -----------------------------------------------------------------

_SAMPLE_PATH: Final = "sample.py"
_FLAG: Final = "# flagged"
_HEADER: Final = """\
from typing import Final

from pydantic import BaseModel, field_validator

from admino import models
from admino.models import FixedMessageError

"""


def _validator(*body: str, prefix: str = "") -> str:
    """A sample module: a request model whose name validator runs ``body``."""
    lines = [
        "class Sample(BaseModel):",
        "    name: str",
        "",
        '    @field_validator("name")',
        "    @classmethod",
        "    def _check_name(cls, value: str) -> str:",
        *(f"        {line}" for line in body),
        "        return value",
    ]
    return _HEADER + prefix + "\n".join(lines) + "\n"


def _module(*lines: str) -> str:
    """A sample module made of the header and ``lines``."""
    return _HEADER + "\n".join(lines) + "\n"


def _flagged_lines(source: str) -> list[int]:
    """The 1-based lines a sample marks with ``# flagged``."""
    return [number for number, line in enumerate(source.splitlines(), 1) if _FLAG in line]


_FAILING_FORMS: Final = [
    pytest.param(
        _validator('raise FixedMessageError(f"The name {value} is not printable.")  # flagged'),
        "must be a string literal",
        id="f_string",
    ),
    pytest.param(
        _validator('raise FixedMessageError("The name %s is not printable." % value)  # flagged'),
        "must be a string literal",
        id="percent",
    ),
    pytest.param(
        _validator(
            'raise FixedMessageError("The name {} is not printable.".format(value))  # flagged'
        ),
        "must be a string literal",
        id="format",
    ),
    pytest.param(
        _validator('raise FixedMessageError("Not printable: " + value)  # flagged'),
        "must be a string literal",
        id="plus",
    ),
    pytest.param(
        _validator('raise models.FixedMessageError(f"The name {value} is bad.")  # flagged'),
        "must be a string literal",
        id="attribute_callee_f_string",
    ),
    pytest.param(
        _module(
            "def _refuse(message: str) -> None:",
            "    raise FixedMessageError(message)  # flagged",
        ),
        "is a parameter",
        id="parameter",
    ),
    pytest.param(
        _validator(
            'msg = f"The name {value} is not printable."',
            "raise FixedMessageError(msg)  # flagged",
        ),
        "is bound to",
        id="name_from_f_string",
    ),
    pytest.param(
        _validator(
            "if not value:",
            '    msg = "Give a name."',
            "    raise FixedMessageError(msg)  # flagged",
            "if not value.isprintable():",
            '    msg = "The name is not printable."',
            "    raise FixedMessageError(msg)  # flagged",
        ),
        "is bound 2 times",
        id="name_assigned_twice",
    ),
    pytest.param(
        _validator(
            'msg = "The name is not printable: "',
            "msg += value",
            "raise FixedMessageError(msg)  # flagged",
        ),
        "is bound 2 times",
        id="name_augmented",
    ),
    pytest.param(
        _validator(
            "raise FixedMessageError(_NAME_ERROR)  # flagged",
            prefix='_NAME_ERROR: Final = " ".join(("The name", "is not printable."))\n\n\n',
        ),
        "is bound to",
        id="module_name_from_expression",
    ),
    pytest.param(
        _module(
            "def _check(value: str) -> None:",
            '    msg = "The name is not printable."',
            "",
            "    def _remember(text: str) -> None:",
            "        nonlocal msg",
            "        msg = text",
            "",
            "    _remember(value)",
            "    raise FixedMessageError(msg)  # flagged",
        ),
        "global or nonlocal",
        id="nonlocal_rebinding",
    ),
    pytest.param(
        _validator('raise FixedMessageError(message="The name is not printable.")  # flagged'),
        "no keyword argument",
        id="keyword_argument",
    ),
    pytest.param(
        _validator('raise FixedMessageError("The name is not printable.", value)  # flagged'),
        "exactly one positional argument",
        id="two_arguments",
    ),
    pytest.param(
        _validator("raise FixedMessageError()  # flagged"),
        "exactly one positional argument",
        id="no_argument",
    ),
    pytest.param(
        _validator("raise FixedMessageError  # flagged"),
        "bare class",
        id="bare_class_raise",
    ),
    pytest.param(
        _module(
            "class EchoError(FixedMessageError):  # flagged",
            '    """Says what was sent."""',
        ),
        "subclasses FixedMessageError",
        id="subclass",
    ),
    pytest.param(
        _validator(
            'raise Refusal(f"The name {value} is not printable.")',
            prefix="from admino.models import FixedMessageError as Refusal  # flagged\n\n\n",
        ),
        "imports FixedMessageError as Refusal",
        id="aliased_import",
    ),
    pytest.param(
        _validator(
            'raise Refusal(f"The name {value} is not printable.")',
            prefix="Refusal = FixedMessageError  # flagged\n\n\n",
        ),
        "binds FixedMessageError to another name",
        id="assigned_alias",
    ),
    # A name the function binds to a literal, rebound in a scope between it and the call:
    # at runtime the call sees the inner binding (Python 3 comprehensions have their own scope).
    pytest.param(
        _validator(
            'msg = "The name is not printable."',
            "errors = [FixedMessageError(msg) for msg in value.split()]  # flagged",
            "if errors:",
            "    raise errors[0]",
        ),
        "rebound in an inner scope",
        id="list_comprehension_target",
    ),
    pytest.param(
        _validator(
            'msg = "The name is not printable."',
            "if not value.isprintable():",
            "    raise next(FixedMessageError(msg) for msg in value.split())  # flagged",
        ),
        "rebound in an inner scope",
        id="generator_expression_target",
    ),
    pytest.param(
        _validator(
            'msg = "The name is not printable."',
            "errors = {i: FixedMessageError(msg) for i, msg in enumerate(value)}  # flagged",
            "if errors:",
            "    raise errors[0]",
        ),
        "rebound in an inner scope",
        id="dict_comprehension_tuple_target",
    ),
    pytest.param(
        _module(
            "def _check(names: list[str]) -> None:",
            '    msg = "The name is not printable."',
            "    errors = [[FixedMessageError(msg) for _ in range(2)] for msg in names]  # flagged",
            "    if errors:",
            "        raise errors[0][0]",
        ),
        "rebound in an inner scope",
        id="nested_comprehension_outer_target",
    ),
    pytest.param(
        _validator(
            'msg = "The name is not printable."',
            "refuse = lambda msg: FixedMessageError(msg)  # flagged",
            "if not value.isprintable():",
            "    raise refuse(value)",
        ),
        "rebound in an inner scope",
        id="lambda_parameter",
    ),
    pytest.param(
        _module(
            "def _check(value: str) -> None:",
            '    msg = "The name is not printable."',
            "",
            "    def _refuse(text: str) -> None:",
            "        msg = text",
            "        raise FixedMessageError(msg)  # flagged",
            "",
            "    if not value.isprintable():",
            "        _refuse(value)",
        ),
        "rebound in an inner scope",
        id="nested_function_local",
    ),
]


@pytest.mark.parametrize(("source", "reason"), _FAILING_FORMS)
def test_fixed_message_guard_sample_failing_form_is_reported(source: str, reason: str) -> None:
    violations = _scan(source, _SAMPLE_PATH).violations
    expected_lines = _flagged_lines(source)

    assert [violation.split(": ", 1)[0] for violation in violations] == [
        f"{_SAMPLE_PATH}:{line}" for line in expected_lines
    ], violations
    assert all(reason in violation for violation in violations), violations


_TEXT: Final = "The name is not printable."

_PASSING_FORMS: Final = [
    pytest.param(
        _validator("if not value.isprintable():", f'    raise FixedMessageError("{_TEXT}")'),
        (_Site("Sample._check_name", _TEXT),),
        id="literal",
    ),
    pytest.param(
        _validator(
            "if not value.isprintable():",
            "    raise FixedMessageError(",
            '        "The name is "',
            '        "not printable."',
            "    )",
        ),
        (_Site("Sample._check_name", _TEXT),),
        id="implicit_literal_concatenation",
    ),
    pytest.param(
        _validator(
            "if not value.isprintable():",
            "    raise FixedMessageError(_NAME_ERROR)",
            prefix=f'_NAME_ERROR: Final = "{_TEXT}"\n\n\n',
        ),
        (_Site("Sample._check_name", _TEXT),),
        id="module_final_constant",
    ),
    pytest.param(
        _validator(
            "if not value.isprintable():",
            "    raise FixedMessageError(_NAME_ERROR)",
            prefix=f'_NAME_ERROR = "{_TEXT}"\n\n\n',
        ),
        (_Site("Sample._check_name", _TEXT),),
        id="module_plain_constant",
    ),
    pytest.param(
        _validator(
            "if not value.isprintable():",
            f'    msg = "{_TEXT}"',
            "    raise FixedMessageError(msg)",
        ),
        (_Site("Sample._check_name", _TEXT),),
        id="single_local_assignment",
    ),
    pytest.param(
        _module(
            "def _check_first(value: str) -> str:",
            "    if not value:",
            '        msg = "Give a name."',
            "        raise FixedMessageError(msg)",
            "    return value",
            "",
            "",
            "def _check_second(value: str) -> str:",
            "    if not value.isprintable():",
            f'        msg = "{_TEXT}"',
            "        raise FixedMessageError(msg)",
            "    return value",
        ),
        (_Site("_check_first", "Give a name."), _Site("_check_second", _TEXT)),
        id="same_local_name_in_two_functions",
    ),
    pytest.param(
        _validator("if not value.isprintable():", f'    raise models.FixedMessageError("{_TEXT}")'),
        (_Site("Sample._check_name", _TEXT),),
        id="attribute_callee",
    ),
    pytest.param(
        _module(
            "def _check_names(names: list[str]) -> None:",
            f'    msg = "{_TEXT}"',
            "    errors = [FixedMessageError(msg) for name in names if not name.isprintable()]",
            "    if errors:",
            "        raise errors[0]",
        ),
        (_Site("_check_names", _TEXT),),
        id="comprehension_target_with_other_name",
    ),
    pytest.param(
        _module(
            "class FixedMessageError(ValueError):",
            "    def __init__(self, message: str) -> None:",
            "        super().__init__(message)",
            "",
            "",
            "def _is_fixed(error: Exception) -> bool:",
            "    try:",
            "        raise error",
            "    except FixedMessageError:",
            "        return True",
            "    except ValueError:",
            "        return isinstance(error, models.FixedMessageError)",
        ),
        (),
        id="class_definition_except_and_isinstance",
    ),
]


@pytest.mark.parametrize(("source", "sites"), _PASSING_FORMS)
def test_fixed_message_guard_sample_passing_form_is_accepted(
    source: str, sites: tuple[_Site, ...]
) -> None:
    assert _scan(source, _SAMPLE_PATH) == _ScanResult(sites=sites, violations=())
