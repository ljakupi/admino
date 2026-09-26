"""Tests for admino.access — the pure role-matrix access policy (GH-145).

The expected matrix below is written independently from the tracker's role
matrix (#139 §2.1), row by row, so the implementation cannot drift from the
spec: every (capability, role) pair is checked, the Capability enum must hold
exactly these values, and anything outside the matrix is denied by default.

Security notes:
- Default-deny: unknown capabilities are refused for every role, including the
  Super Admin (the Super Admin is not a wildcard).
- Operator blindness: the Super Admin gets no content capability (chat, files,
  projects, exports, account connections, templates).
- Least privilege: a Viewer is read-only, and member roles never get a
  platform-level capability.
- Principal mirrors the users-table CHECKs: kind == super_admin iff org_id is
  NULL iff role is NULL.
- Isolation: access.py is pure (no I/O) and imports nothing from the server,
  agent, LLM, database, tools, OAuth or audit modules. The tool permission
  engine (permissions.py) stays a separate layer and imports nothing from admino.
"""

from __future__ import annotations

import ast
import inspect
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from admino.access import Capability, Principal, can

# ---------------------------------------------------------------------------
# Expected role matrix (#139 §2.1), written independently of the implementation
# ---------------------------------------------------------------------------

_SA = "super_admin"
_OA = "org_admin"
_ED = "editor"
_VI = "viewer"

_ROLES: tuple[str, ...] = (_SA, _OA, _ED, _VI)
_MEMBER_ROLES: tuple[str, ...] = (_OA, _ED, _VI)

_SA_ONLY: frozenset[str] = frozenset({_SA})
_ORG_ADMIN_ONLY: frozenset[str] = frozenset({_OA})
_ORG_ADMIN_AND_EDITOR: frozenset[str] = frozenset({_OA, _ED})
_ALL_MEMBERS: frozenset[str] = frozenset({_OA, _ED, _VI})
_EVERYONE: frozenset[str] = frozenset(_ROLES)

_EXPECTED_MATRIX: dict[str, frozenset[str]] = {
    # Row 1 — Create orgs; set plan limits; deactivate, delete; residency policy
    "org.create": _SA_ONLY,
    "org.limits.manage": _SA_ONLY,
    "org.lifecycle.manage": _SA_ONLY,
    "org.residency.manage": _SA_ONLY,
    # Row 2 — Model registry and platform defaults
    "platform.registry.manage": _SA_ONLY,
    "platform.defaults.manage": _SA_ONLY,
    # Row 3 — Platform usage (per-org totals only)
    "usage.view.platform": _SA_ONLY,
    # Row 4 — Platform audit log
    "audit.view.platform": _SA_ONLY,
    # Row 5 — Manage users and invitations in own org
    "org.users.view": _ORG_ADMIN_ONLY,
    "org.users.invite": _ORG_ADMIN_ONLY,
    "org.users.role_change": _ORG_ADMIN_ONLY,
    "org.users.manage": _ORG_ADMIN_ONLY,
    # Row 6 — Org settings, instructions, tool permissions, allowed models,
    # org templates, letterhead
    "org.settings.manage": _ORG_ADMIN_ONLY,
    "org.instructions.manage": _ORG_ADMIN_ONLY,
    "org.permissions.manage": _ORG_ADMIN_ONLY,
    "org.models.manage": _ORG_ADMIN_ONLY,
    "template.org.manage": _ORG_ADMIN_ONLY,
    "org.letterhead.manage": _ORG_ADMIN_ONLY,
    # Row 7 — Org usage (per user) and org audit log
    "usage.view.org": _ORG_ADMIN_ONLY,
    "audit.view.org": _ORG_ADMIN_ONLY,
    # Row 8 — Open any project or chat in own org (audit-logged)
    "project.open_any": _ORG_ADMIN_ONLY,
    # Row 9 — Create projects; personal default project
    "project.create": _ORG_ADMIN_AND_EDITOR,
    "project.personal_default": _ORG_ADMIN_AND_EDITOR,
    # Row 10 — Send messages, upload files
    "chat.send": _ORG_ADMIN_AND_EDITOR,
    "file.upload": _ORG_ADMIN_AND_EDITOR,
    # Row 11 — Connect own Google/Microsoft accounts
    "oauth.connect": _ORG_ADMIN_AND_EDITOR,
    # Row 12 — Personal templates
    "template.personal.manage": _ORG_ADMIN_AND_EDITOR,
    # Row 13 — Read projects shared with them
    "project.read_shared": _ALL_MEMBERS,
    # Row 14 — Export what they can read
    "export.create": _ALL_MEMBERS,
    # Row 15 — Own usage
    "usage.view.own": _ALL_MEMBERS,
    # Row 16 — Own account, password, sessions
    "account.manage": _EVERYONE,
}

_MATRIX_CASES = [
    pytest.param(capability, role, id=f"{capability}-{role}")
    for capability in _EXPECTED_MATRIX
    for role in _ROLES
]

# The capability names the issue (#145) lists as examples.
_ISSUE_EXAMPLES: tuple[str, ...] = (
    "org.create",
    "platform.registry.manage",
    "org.users.invite",
    "org.users.role_change",
    "org.settings.manage",
    "usage.view.org",
    "audit.view.org",
    "project.create",
    "chat.send",
    "file.upload",
    "oauth.connect",
    "template.personal.manage",
    "export.create",
)

# Capabilities that touch org content: the Super Admin never gets any of them.
_CONTENT_CAPABILITIES: tuple[str, ...] = (
    "chat.send",
    "file.upload",
    "project.create",
    "project.personal_default",
    "project.open_any",
    "project.read_shared",
    "export.create",
    "oauth.connect",
    "template.personal.manage",
    "template.org.manage",
)
_CONTENT_PREFIXES: frozenset[str] = frozenset(
    {"chat", "file", "project", "export", "oauth", "template"}
)

# Everything a Viewer (read-only member) must not do.
_VIEWER_WRITE_CAPABILITIES: tuple[str, ...] = (
    "chat.send",
    "file.upload",
    "project.create",
    "project.personal_default",
    "oauth.connect",
    "template.personal.manage",
)

# Platform-level capabilities: no member role ever gets any of them.
_PLATFORM_CAPABILITIES: tuple[str, ...] = (
    "org.create",
    "org.limits.manage",
    "org.lifecycle.manage",
    "org.residency.manage",
    "platform.registry.manage",
    "platform.defaults.manage",
    "usage.view.platform",
    "audit.view.platform",
)

# Strings that are not capability values: denied for every role, never raising.
_UNKNOWN_CAPABILITIES: tuple[str, ...] = (
    "org.delete_everything",
    "",
    "*",
    "platform.*",
    "CHAT.SEND",
    "chat.send.all",
    "admin",
)


def _principal(role: str) -> Principal:
    """Build a valid Principal for one of the matrix's role keys."""
    if role == _SA:
        return Principal(user_id=uuid4(), kind="super_admin")
    return Principal(user_id=uuid4(), kind="member", org_id=uuid4(), role=role)


# ---------------------------------------------------------------------------
# 1. Exhaustive role matrix
# ---------------------------------------------------------------------------


class TestRoleMatrix:
    """can() matches #139 §2.1 for every (capability, role) pair."""

    @pytest.mark.parametrize(("capability", "role"), _MATRIX_CASES)
    def test_access_can_matches_role_matrix(self, capability: str, role: str) -> None:
        """can(principal, capability) is True exactly when the matrix grants the role."""
        expected = role in _EXPECTED_MATRIX[capability]

        assert can(_principal(role), Capability(capability)) is expected

    def test_access_can_is_synchronous(self) -> None:
        """can() is a plain function, not a coroutine: the policy never does I/O."""
        assert inspect.iscoroutinefunction(can) is False

    def test_access_can_ignores_which_org_a_member_belongs_to(self) -> None:
        """The role matrix depends on the role only: two editors of different orgs agree."""
        first = Principal(user_id=uuid4(), kind="member", org_id=uuid4(), role="editor")
        second = Principal(user_id=uuid4(), kind="member", org_id=uuid4(), role="editor")

        assert [can(first, c) for c in Capability] == [can(second, c) for c in Capability]


# ---------------------------------------------------------------------------
# 2. Capability enum completeness
# ---------------------------------------------------------------------------


class TestCapabilityEnum:
    """Capability holds exactly one member per matrix capability, no more, no less."""

    def test_access_capability_is_a_str_enum(self) -> None:
        """Capability is a StrEnum, so members compare and serialize as their dotted value."""
        assert issubclass(Capability, StrEnum)

    def test_access_capability_values_match_spec_exactly(self) -> None:
        """Adding or dropping a capability without updating this spec fails."""
        assert {c.value for c in Capability} == set(_EXPECTED_MATRIX)

    @pytest.mark.parametrize("value", list(_EXPECTED_MATRIX))
    def test_access_capability_member_name_mirrors_value(self, value: str) -> None:
        """Member names mirror values: upper-cased, dots as underscores (chat.send → CHAT_SEND)."""
        name = value.upper().replace(".", "_")

        assert Capability[name] == value

    @pytest.mark.parametrize("value", _ISSUE_EXAMPLES)
    def test_access_capability_includes_issue_example(self, value: str) -> None:
        """Every capability the issue names as an example exists."""
        assert value in {c.value for c in Capability}


# ---------------------------------------------------------------------------
# 3. Role-level invariants
# ---------------------------------------------------------------------------


class TestRoleInvariants:
    """Cross-row properties of the matrix: operator blindness and least privilege."""

    @pytest.mark.parametrize("capability", _CONTENT_CAPABILITIES)
    def test_access_super_admin_cannot_touch_content(self, capability: str) -> None:
        """Operator blindness: the Super Admin gets no chat, file, project, export,
        account-connection or template capability."""
        assert can(_principal(_SA), Capability(capability)) is False

    def test_access_super_admin_denied_every_content_prefixed_capability(self) -> None:
        """Any capability in a content namespace (present or future) is denied to the SA."""
        sa = _principal(_SA)
        granted = [
            c.value for c in Capability if c.value.split(".")[0] in _CONTENT_PREFIXES and can(sa, c)
        ]

        assert granted == []

    @pytest.mark.parametrize("capability", _VIEWER_WRITE_CAPABILITIES)
    def test_access_viewer_is_read_only(self, capability: str) -> None:
        """A Viewer can't write: no messages, uploads, projects, personal default
        project, account connections or personal templates."""
        assert can(_principal(_VI), Capability(capability)) is False

    @pytest.mark.parametrize(
        ("capability", "role"),
        [
            pytest.param(capability, role, id=f"{capability}-{role}")
            for capability in _PLATFORM_CAPABILITIES
            for role in _MEMBER_ROLES
        ],
    )
    def test_access_member_never_gets_platform_capability(self, capability: str, role: str) -> None:
        """Org Admins, Editors and Viewers never get a platform-level capability."""
        assert can(_principal(role), Capability(capability)) is False

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    def test_access_member_denied_every_platform_namespaced_capability(self, role: str) -> None:
        """Any platform-namespaced capability (present or future) is denied to members."""
        member = _principal(role)
        granted = [
            c.value
            for c in Capability
            if (c.value.startswith("platform.") or c.value.endswith(".platform")) and can(member, c)
        ]

        assert granted == []


# ---------------------------------------------------------------------------
# 4. Default-deny
# ---------------------------------------------------------------------------


class TestDefaultDeny:
    """Anything outside the matrix is refused, for every role, without raising."""

    @pytest.mark.parametrize(
        ("capability", "role"),
        [
            pytest.param(capability, role, id=f"{capability or '<empty>'}-{role}")
            for capability in _UNKNOWN_CAPABILITIES
            for role in _ROLES
        ],
    )
    def test_access_unknown_capability_is_denied(self, capability: str, role: str) -> None:
        """A string that is not a Capability value returns False (never raises)."""
        assert can(_principal(role), capability) is False  # type: ignore[arg-type]


class TestForgedPrincipal:
    """can() re-checks the member role instead of trusting Principal's validator.

    model_construct() skips validation. Production code never calls it
    (test_models.py enforces that), but can() must not turn a forged role into a grant.
    """

    @pytest.mark.parametrize("capability", list(Capability), ids=lambda c: str(c))
    def test_access_member_with_forged_super_admin_role_is_denied(
        self, capability: Capability
    ) -> None:
        """kind='member' with role='super_admin' gets nothing, not the Super Admin's grants."""
        forged = Principal.model_construct(
            user_id=uuid4(), kind="member", org_id=uuid4(), role="super_admin"
        )

        assert can(forged, capability) is False

    @pytest.mark.parametrize("capability", list(Capability), ids=lambda c: str(c))
    def test_access_member_without_role_is_denied(self, capability: Capability) -> None:
        """A member built without a role gets nothing."""
        forged = Principal.model_construct(user_id=uuid4(), kind="member", org_id=uuid4())

        assert can(forged, capability) is False

    @pytest.mark.parametrize("capability", list(Capability), ids=lambda c: str(c))
    def test_access_unknown_kind_is_denied(self, capability: Capability) -> None:
        """An unknown kind gets nothing, even with a real member role."""
        forged = Principal.model_construct(
            user_id=uuid4(), kind="root", org_id=uuid4(), role="org_admin"
        )

        assert can(forged, capability) is False

    @pytest.mark.parametrize("capability", list(Capability), ids=lambda c: str(c))
    def test_access_super_admin_with_forged_org_role_stays_a_super_admin(
        self, capability: Capability
    ) -> None:
        """A Super Admin with a forged org and role still gets only the Super Admin's grants."""
        forged = Principal.model_construct(
            user_id=uuid4(), kind="super_admin", org_id=uuid4(), role="org_admin"
        )

        assert can(forged, capability) is (_SA in _EXPECTED_MATRIX[capability.value])


# ---------------------------------------------------------------------------
# 5. Principal validation (mirrors the users-table CHECKs)
# ---------------------------------------------------------------------------


class TestPrincipal:
    """Principal enforces kind == super_admin iff org_id is None iff role is None."""

    def test_access_principal_super_admin_has_no_org_and_no_role(self) -> None:
        """A Super Admin principal is valid without org_id and role, both default to None."""
        principal = Principal(user_id=uuid4(), kind="super_admin")

        assert (principal.kind, principal.org_id, principal.role) == ("super_admin", None, None)

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    def test_access_principal_member_with_org_and_role_is_valid(self, role: str) -> None:
        """A member principal carries its org_id and member role."""
        user_id = uuid4()
        org_id = uuid4()

        principal = Principal(user_id=user_id, kind="member", org_id=org_id, role=role)

        assert (principal.user_id, principal.org_id, principal.role) == (user_id, org_id, role)

    def test_access_principal_super_admin_with_org_rejected(self) -> None:
        """A Super Admin belongs to no org: an org_id is rejected."""
        with pytest.raises(ValidationError):
            Principal(user_id=uuid4(), kind="super_admin", org_id=uuid4())

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    def test_access_principal_super_admin_with_role_rejected(self, role: str) -> None:
        """A Super Admin has no member role: any role is rejected."""
        with pytest.raises(ValidationError):
            Principal(user_id=uuid4(), kind="super_admin", role=role)

    def test_access_principal_super_admin_with_org_and_role_rejected(self) -> None:
        """A Super Admin with both an org_id and a role is rejected."""
        with pytest.raises(ValidationError):
            Principal(user_id=uuid4(), kind="super_admin", org_id=uuid4(), role="org_admin")

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    def test_access_principal_member_without_org_rejected(self, role: str) -> None:
        """A member always belongs to exactly one org: a missing org_id is rejected."""
        with pytest.raises(ValidationError):
            Principal(user_id=uuid4(), kind="member", role=role)

    def test_access_principal_member_without_role_rejected(self) -> None:
        """A member always has a role: a missing role is rejected."""
        with pytest.raises(ValidationError):
            Principal(user_id=uuid4(), kind="member", org_id=uuid4())

    def test_access_principal_member_without_org_and_role_rejected(self) -> None:
        """A member with neither org_id nor role is rejected."""
        with pytest.raises(ValidationError):
            Principal(user_id=uuid4(), kind="member")

    @pytest.mark.parametrize("kind", ["admin", "root", "", "SUPER_ADMIN", "org_admin", "owner"])
    def test_access_principal_unknown_kind_rejected(self, kind: str) -> None:
        """kind accepts only 'super_admin' or 'member'."""
        with pytest.raises(ValidationError):
            Principal(user_id=uuid4(), kind=kind, org_id=uuid4(), role="editor")

    @pytest.mark.parametrize("role", ["owner", "admin", "super_admin", "ORG_ADMIN", ""])
    def test_access_principal_unknown_role_rejected(self, role: str) -> None:
        """role accepts only 'org_admin', 'editor' or 'viewer'."""
        with pytest.raises(ValidationError):
            Principal(user_id=uuid4(), kind="member", org_id=uuid4(), role=role)

    def test_access_principal_missing_user_id_rejected(self) -> None:
        """user_id is required."""
        with pytest.raises(ValidationError):
            Principal(kind="super_admin")  # type: ignore[call-arg]

    def test_access_principal_invalid_user_id_rejected(self) -> None:
        """user_id must be a UUID."""
        with pytest.raises(ValidationError):
            Principal(user_id="not-a-uuid", kind="super_admin")

    def test_access_principal_extra_field_rejected(self) -> None:
        """extra='forbid': unknown fields (e.g. an email) are rejected."""
        with pytest.raises(ValidationError):
            Principal(  # type: ignore[call-arg]
                user_id=uuid4(),
                kind="member",
                org_id=uuid4(),
                role="editor",
                email="someone@example.com",
            )

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("role", "org_admin"),
            ("kind", "super_admin"),
            ("org_id", None),
            ("user_id", None),
        ],
    )
    def test_access_principal_is_frozen(self, field: str, value: object) -> None:
        """A principal can't be mutated after it is built (e.g. escalating its role)."""
        principal = Principal(user_id=uuid4(), kind="member", org_id=uuid4(), role="viewer")

        with pytest.raises(ValidationError):
            setattr(principal, field, value)


# ---------------------------------------------------------------------------
# 6. Architectural isolation (AST)
# ---------------------------------------------------------------------------

_SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "admino"

_FORBIDDEN_MODULES: frozenset[str] = frozenset(
    {
        "admino.server",
        "admino.agent",
        "admino.database",
        "admino.audit",
        "admino.main",
        "admino.permissions",
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


def _is_forbidden(module: str) -> bool:
    """True when a module is (or lives under) a forbidden module or prefix."""
    if module.startswith(_FORBIDDEN_PREFIXES):
        return True
    return any(module == f or module.startswith(f"{f}.") for f in _FORBIDDEN_MODULES)


def _forbidden_calls(path: Path) -> list[str]:
    """Return the names of forbidden builtin calls (open, __import__, eval, ...) in a file."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _FORBIDDEN_CALLS
    ]


class TestAccessIsolation:
    """access.py is a pure, isolated policy module; permissions.py stays separate."""

    def test_access_module_imports_no_forbidden_modules(self) -> None:
        """No imports from server, agent, LLM, database, tools, OAuth, audit or I/O modules."""
        violations = [m for m in _imported_modules(_SRC_DIR / "access.py") if _is_forbidden(m)]

        assert violations == [], f"Forbidden imports in access.py: {violations}"

    def test_access_module_makes_no_io_or_dynamic_import_calls(self) -> None:
        """No open(), __import__(), eval(), exec() or compile() calls in access.py."""
        assert _forbidden_calls(_SRC_DIR / "access.py") == []

    def test_access_permission_engine_imports_nothing_from_admino(self) -> None:
        """Permission engine untouched: permissions.py gains no admino import (access,
        tenancy, accounts or anything else), so the two authorization layers stay apart."""
        admino_imports = [
            m
            for m in _imported_modules(_SRC_DIR / "permissions.py")
            if m == "admino" or m.startswith("admino.")
        ]

        assert admino_imports == []
