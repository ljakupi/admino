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
  org_id is None iff role is None. It is a ``SealedModel``: frozen, and
  ``model_construct()`` / ``model_copy(update=...)`` (which skip validation)
  raise, so a role can't be forged or escalated through Pydantic.
- Fail closed: ``can()`` doesn't trust that validation ran. ``principal_role``
  grants a role only to an exact ``Principal`` that is a well-formed Super
  Admin (no org, no role) or member (a UUID org and a member role). Anything a
  low-level bypass could leave behind, e.g. kind 'super_admin' with an org,
  gets nothing.
- UUID subclasses are normalized: ``user_id`` and ``org_id`` become a plain
  ``uuid.UUID`` during validation (asyncpg returns its own subclass), so a
  Principal built from a users row passes ``principal_role``'s exact type
  check. A value forced onto a Principal after validation is not normalized
  and still fails closed.
- A well-formed Principal passes every check, so only trusted server-side
  code may build one: ``admino.sessions`` is the one builder, from the
  session's users row re-read on every request, never from request data.
  tests/test_access.py allowlists the modules that build one.
- ``Operator`` is the platform operator at the server's terminal (the admin
  CLI, GH-154): no account, no session, no fields. It is not a Principal, so
  ``can()`` grants it nothing; the one service that accepts it
  (``organizations.create_org``) checks for it explicitly. Only
  ``admino.admin_cli`` builds one (tests/test_access.py enforces it): building
  one anywhere reachable over HTTP would let a request act with the CLI's
  rights.
- Pure and isolated: no I/O, no logging, and no imports from the server,
  agent, LLM, database, tools, OAuth, audit or permissions modules. The tool
  permission engine (permissions.py) is a separate layer.
"""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, Any, Final, Literal, NoReturn, Self
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, model_validator

if TYPE_CHECKING:
    from collections.abc import Mapping

UserKind = Literal["super_admin", "member"]
MemberRole = Literal["org_admin", "editor", "viewer"]


def _plain_uuid(value: UUID) -> UUID:
    """Return ``value`` as a plain ``uuid.UUID`` with the same 128 bits.

    asyncpg returns ``asyncpg.pgproto.pgproto.UUID`` (a subclass) and Pydantic
    keeps a subclass instance as it is; rebuilding it drops the subclass.
    """
    return value if type(value) is UUID else UUID(int=value.int)


# A UUID field that never holds a UUID subclass after validation.
PlainUUID = Annotated[UUID, AfterValidator(_plain_uuid)]


class SealedModel(BaseModel):
    """A frozen model that only validation can create or change.

    ``model_construct()`` and ``model_copy(update=...)`` skip validation, so
    both are disabled: every instance went through its validators.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    @classmethod
    def model_construct(cls, _fields_set: set[str] | None = None, **values: Any) -> NoReturn:
        """Refuse to build an instance without validation."""
        msg = f"{cls.__name__} can only be built through validation."
        raise TypeError(msg)

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """Copy the instance unchanged; changing fields on the way (update=...) is refused."""
        if update is not None:
            msg = f"{type(self).__name__} fields can't change; build a new instance."
            raise TypeError(msg)
        return super().model_copy(deep=deep)


class Principal(SealedModel):
    """The authenticated account an access decision is made for.

    A Super Admin belongs to no organization and has no member role; a member
    always belongs to exactly one organization and has exactly one role.
    """

    user_id: PlainUUID
    kind: UserKind
    org_id: PlainUUID | None = None
    role: MemberRole | None = None

    @model_validator(mode="after")
    def _check_kind_matches_org_and_role(self) -> Principal:
        """Enforce kind == 'super_admin' iff org_id is None iff role is None."""
        is_super_admin = self.kind == "super_admin"
        if is_super_admin != (self.org_id is None) or is_super_admin != (self.role is None):
            msg = "A Super Admin has no org_id and no role; a member has both."
            raise ValueError(msg)
        return self


class Operator(SealedModel):
    """The platform operator at the server's terminal: the admin CLI's actor.

    Has no account, no session and no fields. Audited as actor kind
    'operator' with no user id. Never a Principal: ``can()`` refuses it every
    capability.
    """


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
    PLATFORM_DIAGNOSTICS_VIEW = "platform.diagnostics.view"
    PLATFORM_ORG_METADATA_VIEW = "platform.org_metadata.view"
    PLATFORM_USERS_MANAGE = "platform.users.manage"
    ORG_USERS_VIEW = "org.users.view"
    ORG_USERS_INVITE = "org.users.invite"
    ORG_USERS_ROLE_CHANGE = "org.users.role_change"
    ORG_USERS_MANAGE = "org.users.manage"
    ORG_SETTINGS_MANAGE = "org.settings.manage"
    ORG_INSTRUCTIONS_MANAGE = "org.instructions.manage"
    ORG_PERMISSIONS_MANAGE = "org.permissions.manage"
    ORG_PERMISSIONS_VIEW = "org.permissions.view"
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
        # Platform diagnostics: LLM provider, model and reachability (GH-158)
        Capability.PLATFORM_DIAGNOSTICS_VIEW: _SUPER_ADMIN_ONLY,
        # Super Admin user administration and org metadata (GH-167): an org's
        # users list, seats and counts; deactivate, reactivate, password reset
        # and re-invite of its users
        Capability.PLATFORM_ORG_METADATA_VIEW: _SUPER_ADMIN_ONLY,
        Capability.PLATFORM_USERS_MANAGE: _SUPER_ADMIN_ONLY,
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
        # Read the summary of their org's tool permissions (GH-161)
        Capability.ORG_PERMISSIONS_VIEW: _ALL_MEMBERS,
        # Export what they can read
        Capability.EXPORT_CREATE: _ALL_MEMBERS,
        # Own usage
        Capability.USAGE_VIEW_OWN: _ALL_MEMBERS,
        # Own account, password, sessions
        Capability.ACCOUNT_MANAGE: _EVERYONE,
    }
)


def principal_role(principal: object) -> str | None:
    """Return the matrix role of a well-formed Principal, or None to deny.

    Doesn't trust that validation ran: only an exact ``Principal`` (not a
    subclass or lookalike) that is a Super Admin with no org and no role, or a
    member with a UUID org and a member role, gets a role. Anything else, such
    as kind 'super_admin' left next to an org or role, gets None.

    Args:
        principal: The object to classify.

    Returns:
        "super_admin", "org_admin", "editor" or "viewer"; None for anything else.
    """
    if type(principal) is not Principal:
        return None
    kind = getattr(principal, "kind", None)
    org_id = getattr(principal, "org_id", None)
    role = getattr(principal, "role", None)
    if type(kind) is not str:
        return None
    if kind == "super_admin" and org_id is None and role is None:
        return "super_admin"
    if kind == "member" and type(org_id) is UUID and type(role) is str and role in _ALL_MEMBERS:
        return role
    return None


def can(principal: Principal, capability: Capability) -> bool:
    """Return True when the principal's role is granted the capability.

    Default-deny, and never raises: only a ``Capability`` member can be granted
    (a plain string gets False), and only to a well-formed Principal (see
    ``principal_role``).

    Args:
        principal: The account the decision is made for.
        capability: The action being attempted.

    Returns:
        True if the role matrix grants the capability to the principal's role.
    """
    if not isinstance(capability, Capability):
        return False
    role = principal_role(principal)
    return role is not None and role in _MATRIX.get(capability, frozenset())
