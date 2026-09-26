"""Tests for admino.tenancy — the TenantContext scoping rule (GH-145).

Every repository function for org content requires a TenantContext and filters
by its org_id. A TenantContext can only be built for a member (Org Admin,
Editor or Viewer): Super Admins never carry an org context, so they can't reach
content repositories at all.

(The cross-org isolation suite from #163 owns tests/test_tenancy.py; this file
covers the TenantContext type itself.)

Security notes:
- Tenant isolation: org_id, user_id and role are required and never nullable,
  so no content query can run without an org scope.
- Operator blindness: a Super Admin principal can't produce a TenantContext.
- No content in errors: the NoTenantContextError message carries no identifiers.
- Isolation: tenancy.py is pure and imports only admino.access within admino.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

import admino.database as database_mod
import admino.tenancy as tenancy_mod
from admino.access import Principal
from admino.tenancy import NoTenantContextError, TenantContext

if TYPE_CHECKING:
    from collections.abc import Callable

_MEMBER_ROLES: tuple[str, ...] = ("org_admin", "editor", "viewer")


def _valid_kwargs() -> dict[str, Any]:
    """Return a complete, valid set of TenantContext fields."""
    return {"org_id": uuid4(), "user_id": uuid4(), "role": "editor"}


# ---------------------------------------------------------------------------
# 1. TenantContext validation
# ---------------------------------------------------------------------------


class TestTenantContextModel:
    """TenantContext(org_id, user_id, role): all required, none nullable, frozen."""

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    def test_tenant_context_valid_member_context_builds(self, role: str) -> None:
        """A context with an org_id, a user_id and a member role is valid."""
        org_id = uuid4()
        user_id = uuid4()

        context = TenantContext(org_id=org_id, user_id=user_id, role=role)

        assert (context.org_id, context.user_id, context.role) == (org_id, user_id, role)

    @pytest.mark.parametrize("field", ["org_id", "user_id", "role"])
    def test_tenant_context_missing_field_rejected(self, field: str) -> None:
        """org_id, user_id and role are all required."""
        kwargs = _valid_kwargs()
        del kwargs[field]

        with pytest.raises(ValidationError):
            TenantContext(**kwargs)

    @pytest.mark.parametrize("field", ["org_id", "user_id", "role"])
    def test_tenant_context_none_field_rejected(self, field: str) -> None:
        """No field is nullable: an org context without an org (org_id=None) can't exist."""
        kwargs = _valid_kwargs()
        kwargs[field] = None

        with pytest.raises(ValidationError):
            TenantContext(**kwargs)

    @pytest.mark.parametrize("role", ["super_admin", "owner", "admin", "ORG_ADMIN", ""])
    def test_tenant_context_non_member_role_rejected(self, role: str) -> None:
        """role accepts only member roles: 'super_admin' (or anything else) is rejected."""
        kwargs = _valid_kwargs()
        kwargs["role"] = role

        with pytest.raises(ValidationError):
            TenantContext(**kwargs)

    @pytest.mark.parametrize("field", ["org_id", "user_id"])
    def test_tenant_context_invalid_uuid_rejected(self, field: str) -> None:
        """org_id and user_id must be UUIDs."""
        kwargs = _valid_kwargs()
        kwargs[field] = "not-a-uuid"

        with pytest.raises(ValidationError):
            TenantContext(**kwargs)

    def test_tenant_context_extra_field_rejected(self) -> None:
        """extra='forbid': unknown fields (e.g. kind) are rejected."""
        kwargs = _valid_kwargs()
        kwargs["kind"] = "member"

        with pytest.raises(ValidationError):
            TenantContext(**kwargs)

    @pytest.mark.parametrize(
        ("field", "value"),
        [("org_id", uuid4()), ("user_id", uuid4()), ("role", "org_admin")],
    )
    def test_tenant_context_is_frozen(self, field: str, value: object) -> None:
        """A context can't be re-pointed at another org, user or role after it is built."""
        context = TenantContext(**_valid_kwargs())

        with pytest.raises(ValidationError):
            setattr(context, field, value)


# ---------------------------------------------------------------------------
# 2. TenantContext.from_principal
# ---------------------------------------------------------------------------


class TestTenantContextFromPrincipal:
    """Members get a context; Super Admins never do."""

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    def test_tenant_context_from_member_principal_copies_org_user_and_role(self, role: str) -> None:
        """A member principal yields a context with its own org_id, user_id and role."""
        principal = Principal(user_id=uuid4(), kind="member", org_id=uuid4(), role=role)

        context = TenantContext.from_principal(principal)

        assert isinstance(context, TenantContext)
        assert (context.org_id, context.user_id, context.role) == (
            principal.org_id,
            principal.user_id,
            role,
        )

    def test_tenant_context_from_super_admin_raises(self) -> None:
        """A Super Admin principal never carries an org context, so none can be built."""
        principal = Principal(user_id=uuid4(), kind="super_admin")

        with pytest.raises(NoTenantContextError):
            TenantContext.from_principal(principal)

    def test_tenant_context_super_admin_error_carries_no_identifier(self) -> None:
        """No content in errors: the message does not contain the Super Admin's user_id."""
        principal = Principal(user_id=uuid4(), kind="super_admin")

        with pytest.raises(NoTenantContextError) as exc_info:
            TenantContext.from_principal(principal)

        message = str(exc_info.value)
        assert str(principal.user_id) not in message
        assert principal.user_id.hex not in message

    def test_tenant_context_no_tenant_context_error_is_not_a_validation_error(self) -> None:
        """The SA refusal is its own error type, so routes can't mistake it for bad input."""
        assert issubclass(NoTenantContextError, Exception)
        assert not issubclass(NoTenantContextError, ValidationError)


def _forge(principal: Principal, **fields: object) -> Principal:
    """Overwrite fields of a validated Principal without validation (any bypass's result)."""
    for name, value in fields.items():
        object.__setattr__(principal, name, value)
    return principal


def _member(role: str = "editor") -> Principal:
    """A valid member principal."""
    return Principal(user_id=uuid4(), kind="member", org_id=uuid4(), role=role)


class _PrincipalLookalike:
    """Duck-typed object with a member's attributes, not a Principal."""

    def __init__(self) -> None:
        self.user_id = uuid4()
        self.kind = "member"
        self.org_id = uuid4()
        self.role = "org_admin"


_FORGED_PRINCIPALS: list[Any] = [
    pytest.param(
        lambda: _forge(_member("org_admin"), kind="super_admin"),
        id="super_admin-kind-with-org-and-role",
    ),
    pytest.param(
        lambda: _forge(Principal(user_id=uuid4(), kind="super_admin"), org_id=uuid4()),
        id="super_admin-given-an-org",
    ),
    pytest.param(lambda: _forge(_member(), role="super_admin"), id="member-role-super_admin"),
    pytest.param(lambda: _forge(_member(), role=None), id="member-without-role"),
    pytest.param(lambda: _forge(_member(), org_id=None), id="member-without-org"),
    pytest.param(lambda: _forge(_member(), kind="root"), id="unknown-kind"),
    pytest.param(_PrincipalLookalike, id="lookalike-object"),
]


class TestTenantContextFromForgedPrincipal:
    """from_principal fails closed: only a well-formed member Principal gets an org scope.

    The worst case is a forged Super Admin that still carries an org_id and so
    reaches that org's content.
    """

    @pytest.mark.parametrize("forged", _FORGED_PRINCIPALS)
    def test_tenant_context_forged_principal_gets_no_context(
        self, forged: Callable[[], Any]
    ) -> None:
        """An inconsistent or non-Principal object raises NoTenantContextError."""
        with pytest.raises(NoTenantContextError):
            TenantContext.from_principal(forged())


class TestTenantContextBypassesBlocked:
    """The Pydantic APIs that skip validation are disabled on TenantContext."""

    def test_tenant_context_model_construct_is_disabled(self) -> None:
        """TenantContext.model_construct() raises instead of building an unscoped context."""
        with pytest.raises(TypeError):
            TenantContext.model_construct(org_id=None, user_id=uuid4(), role="super_admin")

    def test_tenant_context_model_copy_with_update_is_disabled(self) -> None:
        """model_copy(update=...) raises: it would re-point the context at another org."""
        context = TenantContext.from_principal(_member())

        with pytest.raises(TypeError):
            context.model_copy(update={"org_id": uuid4()})

    def test_tenant_context_plain_copy_still_works(self) -> None:
        """model_copy() without changes returns an equal context."""
        context = TenantContext.from_principal(_member())

        assert context.model_copy() == context
        assert context.model_copy(deep=True) == context


def _context_builders(path: Path) -> list[str]:
    """Return the TenantContext constructions/validations in a source file."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "TenantContext":
            found.append(f"{path.name}:{node.lineno} TenantContext(...)")
        elif (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "TenantContext"
            and func.attr.startswith(("model_validate", "model_construct"))
        ):
            found.append(f"{path.name}:{node.lineno} TenantContext.{func.attr}(...)")
    return found


class TestTenantContextConstructionSites:
    """A TenantContext only ever comes from TenantContext.from_principal."""

    def test_tenant_context_is_built_only_by_from_principal(self) -> None:
        """No src module builds a TenantContext directly (e.g. from a request's org_id)."""
        src_dir = Path(tenancy_mod.__file__).resolve().parent
        offenders = [
            site for path in sorted(src_dir.rglob("*.py")) for site in _context_builders(path)
        ]

        assert offenders == []


# ---------------------------------------------------------------------------
# 3. The scoping rule is documented in the module docstrings
# ---------------------------------------------------------------------------


class TestScopingRuleDocumented:
    """The issue requires the scoping rule to be written down in the module docstrings."""

    def test_tenant_context_tenancy_docstring_names_the_type(self) -> None:
        """admino.tenancy documents TenantContext."""
        assert "TenantContext" in (tenancy_mod.__doc__ or "")

    def test_tenant_context_tenancy_docstring_states_org_id_filter(self) -> None:
        """admino.tenancy documents that org content is filtered by org_id."""
        assert "org_id" in (tenancy_mod.__doc__ or "")

    def test_tenant_context_database_docstring_requires_tenant_context(self) -> None:
        """admino.database documents that org-content repositories take a TenantContext."""
        assert "TenantContext" in (database_mod.__doc__ or "")


# ---------------------------------------------------------------------------
# 4. Architectural isolation (AST)
# ---------------------------------------------------------------------------

_TENANCY_PATH = Path(__file__).resolve().parent.parent / "src" / "admino" / "tenancy.py"

_FORBIDDEN_MODULES: frozenset[str] = frozenset(
    {
        "admino.server",
        "admino.agent",
        "admino.database",
        "admino.audit",
        "admino.main",
        "asyncpg",
        "httpx",
        "socket",
        "subprocess",
        "os",
        "pathlib",
        "logging",
        "importlib",
        "shutil",
    }
)
_FORBIDDEN_PREFIXES: tuple[str, ...] = (
    "admino.llm",
    "admino.tools",
    "admino.oauth",
    "urllib",
    "http",
)
_FORBIDDEN_CALLS: frozenset[str] = frozenset({"open", "__import__", "eval", "exec", "compile"})


def _imported_modules(path: Path) -> list[str]:
    """Return every module a source file imports, with relative imports resolved under admino."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                base = f"admino.{base}" if base else "admino"
            if base == "admino":
                modules.extend(f"admino.{alias.name}" for alias in node.names)
            else:
                modules.append(base)
    return modules


class TestTenancyIsolation:
    """tenancy.py is pure and depends only on the access policy within admino."""

    def test_tenant_context_module_imports_only_access_from_admino(self) -> None:
        """Within admino, tenancy.py imports nothing but admino.access."""
        admino_imports = {
            m for m in _imported_modules(_TENANCY_PATH) if m == "admino" or m.startswith("admino.")
        }

        assert admino_imports <= {"admino.access"}, f"Unexpected imports: {admino_imports}"

    def test_tenant_context_module_imports_no_forbidden_modules(self) -> None:
        """No imports from server, agent, LLM, database, tools, OAuth, audit or I/O modules."""
        violations = [
            m
            for m in _imported_modules(_TENANCY_PATH)
            if m.startswith(_FORBIDDEN_PREFIXES)
            or any(m == f or m.startswith(f"{f}.") for f in _FORBIDDEN_MODULES)
        ]

        assert violations == [], f"Forbidden imports in tenancy.py: {violations}"

    def test_tenant_context_module_makes_no_io_or_dynamic_import_calls(self) -> None:
        """No open(), __import__(), eval(), exec() or compile() calls in tenancy.py."""
        tree = ast.parse(_TENANCY_PATH.read_text(encoding="utf-8"))
        calls = [
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in _FORBIDDEN_CALLS
        ]

        assert calls == []
