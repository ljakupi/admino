"""Tenant scoping for org content: the TenantContext type (GH-145).

Inputs: a member ``Principal`` (see ``admino.access``). Output: a frozen
``TenantContext`` carrying the member's org_id, user_id and role.

Scoping rule: every repository function for org content takes a
``TenantContext`` as its first argument and filters by its ``org_id``. There
is no unscoped content query path. Super Admin principals never get a
``TenantContext`` (``from_principal`` raises ``NoTenantContextError``), so
they can't reach content repositories; they only reach account metadata and
counts via the platform routes.

Security notes:
- Tenant isolation: org_id, user_id and role are required and never nullable,
  so no content query can run without an org scope. The context is frozen, so
  it can't be re-pointed at another org after it is built.
- Operator blindness: a Super Admin can't produce a TenantContext.
- No content in errors: the NoTenantContextError message carries no identifiers.
- Pure: no I/O; within admino it imports only admino.access.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID  # noqa: TC003 — Pydantic resolves field annotations at runtime

from pydantic import BaseModel, ConfigDict

from admino.access import MemberRole  # noqa: TC001 — Pydantic resolves field annotations at runtime

if TYPE_CHECKING:
    from admino.access import Principal


class NoTenantContextError(Exception):
    """Raised when a principal without an organization (a Super Admin) asks for org scope."""


class TenantContext(BaseModel):
    """The org scope every org-content repository function requires."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    org_id: UUID
    user_id: UUID
    role: MemberRole

    @classmethod
    def from_principal(cls, principal: Principal) -> TenantContext:
        """Build the context for a member principal.

        Args:
            principal: The authenticated account.

        Returns:
            The member's TenantContext.

        Raises:
            NoTenantContextError: If the principal is a Super Admin (no org, no role).
        """
        # Principal's validator guarantees org_id and role are None exactly for
        # a Super Admin.
        if principal.org_id is None or principal.role is None:
            msg = "A Super Admin has no organization context."
            raise NoTenantContextError(msg)
        return cls(org_id=principal.org_id, user_id=principal.user_id, role=principal.role)
