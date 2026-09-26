"""Pure access policy: who may do what, per the role matrix (#139 §2.1, GH-145).

Inputs: a ``Principal`` (who is acting: a Super Admin, or a member of exactly
one organization with a member role) and a ``Capability`` (what they want to
do). Output: ``can(principal, capability)`` returns True or False.

The policy depends on the role only, never on which organization a member
belongs to; scoping data to the member's own organization is the job of
``admino.tenancy.TenantContext``.

Security notes:
- Default-deny: a capability outside the matrix (including an unknown string)
  is refused for every role and never raises. The Super Admin is not a wildcard.
- Operator blindness: the Super Admin gets no content capability (chat, files,
  projects, exports, account connections, templates).
- Least privilege: a Viewer is read-only; member roles never get a
  platform-level capability.
- ``Principal`` mirrors the users-table CHECKs: kind is 'super_admin' iff
  org_id is None iff role is None. It is frozen, so a role can't be escalated
  after it is built. Never build one with ``model_construct()`` (it skips the
  validator; test_models.py forbids it in src/). ``can()`` re-checks kind and
  role anyway, so a forged role grants nothing.
- Pure and isolated: no I/O, no logging, and no imports from the server,
  agent, LLM, database, tools, OAuth, audit or permissions modules. The tool
  permission engine (permissions.py) is a separate layer.
"""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import Final, Literal
from uuid import UUID  # noqa: TC003 — Pydantic resolves field annotations at runtime

from pydantic import BaseModel, ConfigDict, model_validator

UserKind = Literal["super_admin", "member"]
MemberRole = Literal["org_admin", "editor", "viewer"]


class Principal(BaseModel):
    """The authenticated account an access decision is made for.

    A Super Admin belongs to no organization and has no member role; a member
    always belongs to exactly one organization and has exactly one role.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    user_id: UUID
    kind: UserKind
    org_id: UUID | None = None
    role: MemberRole | None = None

    @model_validator(mode="after")
    def _check_kind_matches_org_and_role(self) -> Principal:
        """Enforce kind == 'super_admin' iff org_id is None iff role is None."""
        is_super_admin = self.kind == "super_admin"
        if is_super_admin != (self.org_id is None) or is_super_admin != (self.role is None):
            msg = "A Super Admin has no org_id and no role; a member has both."
            raise ValueError(msg)
        return self


class Capability(StrEnum):
    """Every action the role matrix governs (#139 §2.1)."""

    ORG_CREATE = "org.create"
    ORG_LIMITS_MANAGE = "org.limits.manage"
    ORG_LIFECYCLE_MANAGE = "org.lifecycle.manage"
    ORG_RESIDENCY_MANAGE = "org.residency.manage"
    PLATFORM_REGISTRY_MANAGE = "platform.registry.manage"
    PLATFORM_DEFAULTS_MANAGE = "platform.defaults.manage"
    USAGE_VIEW_PLATFORM = "usage.view.platform"
    AUDIT_VIEW_PLATFORM = "audit.view.platform"
    ORG_USERS_VIEW = "org.users.view"
    ORG_USERS_INVITE = "org.users.invite"
    ORG_USERS_ROLE_CHANGE = "org.users.role_change"
    ORG_USERS_MANAGE = "org.users.manage"
    ORG_SETTINGS_MANAGE = "org.settings.manage"
    ORG_INSTRUCTIONS_MANAGE = "org.instructions.manage"
    ORG_PERMISSIONS_MANAGE = "org.permissions.manage"
    ORG_MODELS_MANAGE = "org.models.manage"
    TEMPLATE_ORG_MANAGE = "template.org.manage"
    ORG_LETTERHEAD_MANAGE = "org.letterhead.manage"
    USAGE_VIEW_ORG = "usage.view.org"
    AUDIT_VIEW_ORG = "audit.view.org"
    PROJECT_OPEN_ANY = "project.open_any"
    PROJECT_CREATE = "project.create"
    PROJECT_PERSONAL_DEFAULT = "project.personal_default"
    CHAT_SEND = "chat.send"
    FILE_UPLOAD = "file.upload"
    OAUTH_CONNECT = "oauth.connect"
    TEMPLATE_PERSONAL_MANAGE = "template.personal.manage"
    PROJECT_READ_SHARED = "project.read_shared"
    EXPORT_CREATE = "export.create"
    USAGE_VIEW_OWN = "usage.view.own"
    ACCOUNT_MANAGE = "account.manage"


# Role keys: "super_admin" for a Super Admin, otherwise the member role.
_SUPER_ADMIN_ONLY: Final = frozenset({"super_admin"})
_ORG_ADMIN_ONLY: Final = frozenset({"org_admin"})
_ORG_ADMIN_AND_EDITOR: Final = frozenset({"org_admin", "editor"})
_ALL_MEMBERS: Final = frozenset({"org_admin", "editor", "viewer"})
_EVERYONE: Final = frozenset({"super_admin", "org_admin", "editor", "viewer"})

_MATRIX: Final[MappingProxyType[Capability, frozenset[str]]] = MappingProxyType(
    {
        # Create orgs; set plan limits; deactivate, delete; residency policy
        Capability.ORG_CREATE: _SUPER_ADMIN_ONLY,
        Capability.ORG_LIMITS_MANAGE: _SUPER_ADMIN_ONLY,
        Capability.ORG_LIFECYCLE_MANAGE: _SUPER_ADMIN_ONLY,
        Capability.ORG_RESIDENCY_MANAGE: _SUPER_ADMIN_ONLY,
        # Model registry and platform defaults
        Capability.PLATFORM_REGISTRY_MANAGE: _SUPER_ADMIN_ONLY,
        Capability.PLATFORM_DEFAULTS_MANAGE: _SUPER_ADMIN_ONLY,
        # Platform usage (per-org totals only)
        Capability.USAGE_VIEW_PLATFORM: _SUPER_ADMIN_ONLY,
        # Platform audit log
        Capability.AUDIT_VIEW_PLATFORM: _SUPER_ADMIN_ONLY,
        # Manage users and invitations in own org
        Capability.ORG_USERS_VIEW: _ORG_ADMIN_ONLY,
        Capability.ORG_USERS_INVITE: _ORG_ADMIN_ONLY,
        Capability.ORG_USERS_ROLE_CHANGE: _ORG_ADMIN_ONLY,
        Capability.ORG_USERS_MANAGE: _ORG_ADMIN_ONLY,
        # Org settings, instructions, tool permissions, allowed models,
        # org templates, letterhead
        Capability.ORG_SETTINGS_MANAGE: _ORG_ADMIN_ONLY,
        Capability.ORG_INSTRUCTIONS_MANAGE: _ORG_ADMIN_ONLY,
        Capability.ORG_PERMISSIONS_MANAGE: _ORG_ADMIN_ONLY,
        Capability.ORG_MODELS_MANAGE: _ORG_ADMIN_ONLY,
        Capability.TEMPLATE_ORG_MANAGE: _ORG_ADMIN_ONLY,
        Capability.ORG_LETTERHEAD_MANAGE: _ORG_ADMIN_ONLY,
        # Org usage (per user) and org audit log
        Capability.USAGE_VIEW_ORG: _ORG_ADMIN_ONLY,
        Capability.AUDIT_VIEW_ORG: _ORG_ADMIN_ONLY,
        # Open any project or chat in own org (audit-logged)
        Capability.PROJECT_OPEN_ANY: _ORG_ADMIN_ONLY,
        # Create projects; personal default project
        Capability.PROJECT_CREATE: _ORG_ADMIN_AND_EDITOR,
        Capability.PROJECT_PERSONAL_DEFAULT: _ORG_ADMIN_AND_EDITOR,
        # Send messages, upload files
        Capability.CHAT_SEND: _ORG_ADMIN_AND_EDITOR,
        Capability.FILE_UPLOAD: _ORG_ADMIN_AND_EDITOR,
        # Connect own Google/Microsoft accounts
        Capability.OAUTH_CONNECT: _ORG_ADMIN_AND_EDITOR,
        # Personal templates
        Capability.TEMPLATE_PERSONAL_MANAGE: _ORG_ADMIN_AND_EDITOR,
        # Read projects shared with them
        Capability.PROJECT_READ_SHARED: _ALL_MEMBERS,
        # Export what they can read
        Capability.EXPORT_CREATE: _ALL_MEMBERS,
        # Own usage
        Capability.USAGE_VIEW_OWN: _ALL_MEMBERS,
        # Own account, password, sessions
        Capability.ACCOUNT_MANAGE: _EVERYONE,
    }
)


def can(principal: Principal, capability: Capability) -> bool:
    """Return True when the principal's role is granted the capability.

    Default-deny: a capability missing from the matrix (such as an unknown
    string) returns False, and so does a principal whose kind or member role
    isn't a real one (e.g. built with ``model_construct()``).

    Args:
        principal: The account the decision is made for.
        capability: The action being attempted.

    Returns:
        True if the role matrix grants the capability to the principal's role.
    """
    if principal.kind == "super_admin":
        role = "super_admin"
    elif principal.kind == "member" and principal.role in _ALL_MEMBERS:
        role = principal.role
    else:
        return False
    return role in _MATRIX.get(capability, frozenset())
