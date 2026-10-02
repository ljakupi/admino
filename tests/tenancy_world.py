"""Shared world and route catalog of the tenant isolation suite (GH-163).

The suite (``tests/test_tenancy.py``, ``tests/test_tenancy_cross_org.py`` and
``tests/test_tenancy_memory.py``) runs the FastAPI app from ``create_app()``
against the in-memory database of tests/db_fakes.py, with real session cookies
resolved by the real ``server.require_session``.

Inputs: a ``FakeDb``. Outputs:
- ``build_world(db)``: two active organizations (A = ``ORG_ID``, B =
  ``OTHER_ORG_ID``), each with an Org Admin, an Editor and a Viewer, plus a
  Super Admin; every account has a live session and the password
  ``PASSWORD``. Both orgs have data residency off, the default tool
  permission matrix and an org_settings row; the platform settings row exists.
- ``make_app(agent)`` / ``make_client(app)``: the app and a TestClient.
- The catalog: ``ROUTES`` (every registered API route, classified),
  ``ROLE_MATRIX`` (#139 §2.1, written from the tracker, never from
  ``access.py``), ``PENDING_CAPABILITIES`` (capabilities without a route yet,
  with the issue that adds it) and ``PROJECT_ROLES`` (#139 §2.2, pending
  until project routes exist).

Adding a route: give it a ``RouteSpec`` row in ``ROUTES`` and its cases in the
suite. The completeness tests in tests/test_tenancy.py fail for a registered
route without a row, and for a capability that is neither routed nor pending.

Security notes:
- Passwords, tokens and emails here are fixed fake values, never secrets.
- The expected role matrix is spelled out here on purpose: deriving it from
  ``access.can`` would make the HTTP role tests agree with any mistake there.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Literal
from unittest.mock import AsyncMock, MagicMock

from fastapi.testclient import TestClient

from admino import server
from admino.access import Capability
from admino.config import AppConfig
from admino.models import AgentResult, LLMMessage
from admino.server import create_app
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, PUBLIC_URL, FakeDb, fake_hash

if TYPE_CHECKING:
    import uuid

    import pytest
    from fastapi import FastAPI

# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------

Role = Literal["super_admin", "org_admin", "editor", "viewer"]
MemberRole = Literal["org_admin", "editor", "viewer"]

ROLES: Final[tuple[Role, ...]] = ("super_admin", "org_admin", "editor", "viewer")
MEMBER_ROLES: Final[tuple[MemberRole, ...]] = ("org_admin", "editor", "viewer")

SESSION_COOKIE: Final = "admino_session"
PASSWORD: Final = "tenancy-Suite-163-quartz"
CLIENT_IP: Final = "203.0.113.163"
FORBIDDEN: Final = {"detail": "Forbidden"}
UNAUTHORIZED: Final = {"detail": "Unauthorized"}


@dataclass(frozen=True)
class Account:
    """One account of the world: its ids, role, email and live session token."""

    user_id: uuid.UUID
    org_id: uuid.UUID | None
    role: Role
    email: str
    token: str

    @property
    def cookie(self) -> dict[str, str]:
        """Request headers carrying this account's session cookie."""
        return {"Cookie": f"{SESSION_COOKIE}={self.token}"}


@dataclass(frozen=True)
class World:
    """Two organizations with one account per member role, plus a Super Admin."""

    db: FakeDb
    org_a: uuid.UUID
    org_b: uuid.UUID
    super_admin: Account
    a: MappingProxyType[MemberRole, Account]
    b: MappingProxyType[MemberRole, Account]

    def by_role(self, role: Role) -> Account:
        """The Super Admin, or org A's account with ``role``."""
        return self.super_admin if role == "super_admin" else self.a[role]

    def everyone(self) -> list[Account]:
        """All seven accounts: the Super Admin, then org A's and org B's members."""
        return [self.super_admin, *self.a.values(), *self.b.values()]


def _account(db: FakeDb, role: Role, org_id: uuid.UUID | None, label: str) -> Account:
    """Add an account that logs in with ``PASSWORD`` and open a live session for it."""
    email = f"{label}-{role.replace('_', '-')}@example.ch"
    if role == "super_admin":
        user_id = db.add_account(
            kind="super_admin", role=None, email=email, password_hash=fake_hash(PASSWORD)
        )
    else:
        assert org_id is not None
        user_id = db.add_account(
            role=role, org_id=org_id, email=email, password_hash=fake_hash(PASSWORD)
        )
    return Account(
        user_id=user_id,
        org_id=org_id,
        role=role,
        email=email,
        token=db.open_session(user_id),
    )


def build_world(db: FakeDb) -> World:
    """Populate ``db`` with orgs A and B (residency off), their members and a Super Admin."""
    for org_id in (ORG_ID, OTHER_ORG_ID):
        db.add_org(org_id, data_residency=False)
        db.add_permissions(org_id)
        db.add_org_settings(org_id)
    db.add_platform_settings()
    a = {role: _account(db, role, ORG_ID, "org-a") for role in MEMBER_ROLES}
    b = {role: _account(db, role, OTHER_ORG_ID, "org-b") for role in MEMBER_ROLES}
    return World(
        db=db,
        org_a=ORG_ID,
        org_b=OTHER_ORG_ID,
        super_admin=_account(db, "super_admin", None, "platform"),
        a=MappingProxyType(a),
        b=MappingProxyType(b),
    )


# ---------------------------------------------------------------------------
# App and client
# ---------------------------------------------------------------------------


def make_config() -> AppConfig:
    """A real config: localhost server with the fake public URL."""
    return AppConfig.model_validate(
        {
            "server": {"host": "127.0.0.1", "port": 8000, "public_url": PUBLIC_URL},
            "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
        }
    )


def final_result(reply: str = "Done.") -> AgentResult:
    """A finished agent run that answered ``reply``."""
    return AgentResult(
        status="final",
        response=reply,
        history=[
            LLMMessage(role="user", content="hi"),
            LLMMessage(role="assistant", content=reply),
        ],
        tool_calls=[],
        pending_confirmation=None,
    )


def stub_agent() -> MagicMock:
    """An agent whose ``run`` answers ``final_result()`` (an AsyncMock to inspect)."""
    agent = MagicMock(name="agent")
    agent.run = AsyncMock(return_value=final_result())
    return agent


def make_app(agent: MagicMock | None = None) -> FastAPI:
    """create_app with ``agent`` (a stub by default); no lifespan runs under TestClient."""
    return create_app(agent=agent or stub_agent(), config=make_config())


def make_client(app: FastAPI, *, raise_server_exceptions: bool = True) -> TestClient:
    """A client at ``CLIENT_IP`` that doesn't follow redirects."""
    return TestClient(
        app,
        client=(CLIENT_IP, 50000),
        follow_redirects=False,
        raise_server_exceptions=raise_server_exceptions,
    )


def use_fake_database(monkeypatch: pytest.MonkeyPatch, db: FakeDb) -> None:
    """Make ``admino.database.get_pool()`` return ``db``'s pool."""
    monkeypatch.setattr("admino.database.get_pool", lambda: db.pool)


def use_fast_passwords(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace Argon2 with ``fake_hash`` (real hashing is covered by test_passwords)."""
    monkeypatch.setattr(
        "admino.passwords.verify_password", lambda password, encoded: encoded == fake_hash(password)
    )
    monkeypatch.setattr("admino.passwords.needs_rehash", lambda _encoded: False)
    monkeypatch.setattr("admino.passwords.hash_password", fake_hash)


def use_roomy_rate_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Functional cases aren't about rate limits: every bucket gets 1000 req/s, burst 1000."""
    for key in list(server._RATE_LIMITS):
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))
    monkeypatch.setattr(server, "_DEFAULT_RATE_LIMIT", (1000.0, 1000))


# ---------------------------------------------------------------------------
# The role matrix (#139 §2.1), spelled out from the tracker
# ---------------------------------------------------------------------------

_SA: Final[frozenset[Role]] = frozenset({"super_admin"})
_OA: Final[frozenset[Role]] = frozenset({"org_admin"})
_OA_ED: Final[frozenset[Role]] = frozenset({"org_admin", "editor"})
_MEMBERS: Final[frozenset[Role]] = frozenset({"org_admin", "editor", "viewer"})
_ALL: Final[frozenset[Role]] = frozenset(ROLES)

ROLE_MATRIX: Final[MappingProxyType[Capability, frozenset[Role]]] = MappingProxyType(
    {
        # Create orgs; set plan limits; deactivate, delete; residency policy
        Capability.ORG_CREATE: _SA,
        Capability.ORG_LIMITS_MANAGE: _SA,
        Capability.ORG_LIFECYCLE_MANAGE: _SA,
        Capability.ORG_RESIDENCY_MANAGE: _SA,
        # Model registry and platform defaults
        Capability.PLATFORM_REGISTRY_MANAGE: _SA,
        Capability.PLATFORM_DEFAULTS_MANAGE: _SA,
        # Platform usage (per-org totals only); platform audit log
        Capability.USAGE_VIEW_PLATFORM: _SA,
        Capability.AUDIT_VIEW_PLATFORM: _SA,
        # Platform diagnostics (GH-158): provider, model, reachability
        Capability.PLATFORM_DIAGNOSTICS_VIEW: _SA,
        # Manage users and invitations in own org
        Capability.ORG_USERS_VIEW: _OA,
        Capability.ORG_USERS_INVITE: _OA,
        Capability.ORG_USERS_ROLE_CHANGE: _OA,
        Capability.ORG_USERS_MANAGE: _OA,
        # Org settings, instructions, tool permissions, allowed models, org
        # templates, letterhead
        Capability.ORG_SETTINGS_MANAGE: _OA,
        Capability.ORG_INSTRUCTIONS_MANAGE: _OA,
        Capability.ORG_PERMISSIONS_MANAGE: _OA,
        Capability.ORG_MODELS_MANAGE: _OA,
        Capability.TEMPLATE_ORG_MANAGE: _OA,
        Capability.ORG_LETTERHEAD_MANAGE: _OA,
        # Org usage (per user) and org audit log
        Capability.USAGE_VIEW_ORG: _OA,
        Capability.AUDIT_VIEW_ORG: _OA,
        # Open any project or chat in own org
        Capability.PROJECT_OPEN_ANY: _OA,
        # Create projects; personal default project
        Capability.PROJECT_CREATE: _OA_ED,
        Capability.PROJECT_PERSONAL_DEFAULT: _OA_ED,
        # Send messages, upload files
        Capability.CHAT_SEND: _OA_ED,
        Capability.FILE_UPLOAD: _OA_ED,
        # Connect own Google/Microsoft accounts
        Capability.OAUTH_CONNECT: _OA_ED,
        # Personal templates
        Capability.TEMPLATE_PERSONAL_MANAGE: _OA_ED,
        # Read projects shared with them; read the org's tool permissions (GH-161)
        Capability.PROJECT_READ_SHARED: _MEMBERS,
        Capability.ORG_PERMISSIONS_VIEW: _MEMBERS,
        # Export what they can read; own usage
        Capability.EXPORT_CREATE: _MEMBERS,
        Capability.USAGE_VIEW_OWN: _MEMBERS,
        # Own account, password, sessions
        Capability.ACCOUNT_MANAGE: _ALL,
    }
)

# Capabilities whose routes don't exist yet, and the issue that adds them. That
# issue moves its capability from here into a ROUTES row with HTTP cases.
PENDING_CAPABILITIES: Final[MappingProxyType[Capability, str]] = MappingProxyType(
    {
        Capability.PLATFORM_REGISTRY_MANAGE: "#173",
        Capability.USAGE_VIEW_PLATFORM: "#183",
        Capability.AUDIT_VIEW_PLATFORM: "#171",
        Capability.ORG_USERS_ROLE_CHANGE: "#164",
        Capability.ORG_INSTRUCTIONS_MANAGE: "#169",
        Capability.ORG_MODELS_MANAGE: "#173",
        Capability.TEMPLATE_ORG_MANAGE: "#205",
        Capability.ORG_LETTERHEAD_MANAGE: "#207",
        Capability.USAGE_VIEW_ORG: "#183",
        Capability.AUDIT_VIEW_ORG: "#171",
        Capability.PROJECT_OPEN_ANY: "#185",
        Capability.PROJECT_CREATE: "#185",
        Capability.PROJECT_PERSONAL_DEFAULT: "#185",
        Capability.FILE_UPLOAD: "#187",
        Capability.TEMPLATE_PERSONAL_MANAGE: "#205",
        Capability.PROJECT_READ_SHARED: "#197",
        Capability.EXPORT_CREATE: "#206",
        Capability.USAGE_VIEW_OWN: "#183",
    }
)

# #139 §2.2 project roles: (capability, roles that have it). No project route
# exists yet; #185 (projects) and #197 (sharing) add them with their HTTP cases.
ProjectRole = Literal["owner", "project_editor", "project_viewer"]
PROJECT_ROLES: Final[tuple[tuple[str, frozenset[ProjectRole]], ...]] = (
    ("Read all chats in the project", frozenset({"owner", "project_editor", "project_viewer"})),
    ("Create chats and send messages in their own chats", frozenset({"owner", "project_editor"})),
    ("Upload files", frozenset({"owner", "project_editor"})),
    ("Edit the project's instructions", frozenset({"owner", "project_editor"})),
    ("Share, change member roles, transfer, delete", frozenset({"owner"})),
)
PROJECT_ROLES_PENDING: Final = "#185, #197"

# ---------------------------------------------------------------------------
# The route catalog
# ---------------------------------------------------------------------------

# Who a route serves:
# - "public": no session (login, reset, invitation links, OAuth callback, health);
# - "account": any logged-in principal, the Super Admin included (own account);
# - "member": a member of an organization; holds or changes org or user
#   content, so the Super Admin is refused (operator blindness);
# - "platform": the Super Admin's platform operations.
Audience = Literal["public", "account", "member", "platform"]

# How the cross-org case reaches the route:
# - "path_id": the path names a resource; another org's id answers 404 with the
#   same body as an unknown id, and changes nothing;
# - "own_org": acts on the caller's own organization only (no id in the path);
# - "own_user": acts on the caller's own data only (no id in the path);
# - "none": public and platform routes (no tenant content).
Isolation = Literal["path_id", "own_org", "own_user", "none"]


@dataclass(frozen=True)
class RouteSpec:
    """One registered API route and what the suite expects of it.

    ``capability`` is the §2.1 capability that gates the route (None: any
    logged-in principal, or public). Allowed roles are
    ``ROLE_MATRIX[capability]`` (every role when None); the others get 403.
    """

    method: str
    path: str
    audience: Audience
    capability: Capability | None
    isolation: Isolation


ROUTES: Final[tuple[RouteSpec, ...]] = (
    # --- public ---
    RouteSpec("GET", "/health", "public", None, "none"),
    RouteSpec("POST", "/api/auth/login", "public", None, "none"),
    RouteSpec("POST", "/api/auth/password-reset", "public", None, "none"),
    RouteSpec("POST", "/api/auth/password-reset/confirm", "public", None, "none"),
    RouteSpec("GET", "/api/auth/invitations/{token}", "public", None, "none"),
    RouteSpec("POST", "/api/auth/invitations/{token}/accept", "public", None, "none"),
    RouteSpec("GET", "/api/oauth/callback", "public", None, "none"),
    # --- own account (every logged-in principal) ---
    RouteSpec("POST", "/api/auth/logout", "account", None, "own_user"),
    RouteSpec("GET", "/api/auth/me", "account", None, "own_user"),
    RouteSpec("GET", "/api/me/sessions", "account", Capability.ACCOUNT_MANAGE, "own_user"),
    RouteSpec(
        "DELETE", "/api/me/sessions/{session_id}", "account", Capability.ACCOUNT_MANAGE, "path_id"
    ),
    RouteSpec("GET", "/api/me/settings", "account", Capability.ACCOUNT_MANAGE, "own_user"),
    RouteSpec("PATCH", "/api/me/settings", "account", Capability.ACCOUNT_MANAGE, "own_user"),
    RouteSpec("POST", "/api/me/settings/reset", "account", Capability.ACCOUNT_MANAGE, "own_user"),
    # --- org users and invitations ---
    RouteSpec(
        "POST",
        "/api/org/users/{user_id}/logout",
        "member",
        Capability.ORG_USERS_MANAGE,
        "path_id",
    ),
    RouteSpec("POST", "/api/org/invitations", "member", Capability.ORG_USERS_INVITE, "own_org"),
    RouteSpec("GET", "/api/org/invitations", "member", Capability.ORG_USERS_VIEW, "own_org"),
    RouteSpec(
        "DELETE",
        "/api/org/invitations/{invitation_id}",
        "member",
        Capability.ORG_USERS_INVITE,
        "path_id",
    ),
    RouteSpec(
        "POST",
        "/api/org/invitations/{invitation_id}/resend",
        "member",
        Capability.ORG_USERS_INVITE,
        "path_id",
    ),
    # --- org settings and tool permissions ---
    RouteSpec("GET", "/api/org/settings", "member", Capability.ORG_SETTINGS_MANAGE, "own_org"),
    RouteSpec("PATCH", "/api/org/settings", "member", Capability.ORG_SETTINGS_MANAGE, "own_org"),
    RouteSpec(
        "GET", "/api/org/permissions", "member", Capability.ORG_PERMISSIONS_MANAGE, "own_org"
    ),
    RouteSpec(
        "PATCH", "/api/org/permissions", "member", Capability.ORG_PERMISSIONS_MANAGE, "own_org"
    ),
    RouteSpec(
        "GET",
        "/api/org/critical-permissions",
        "member",
        Capability.ORG_PERMISSIONS_MANAGE,
        "own_org",
    ),
    RouteSpec(
        "PATCH",
        "/api/org/critical-permissions/{tool}/{action}",
        "member",
        Capability.ORG_PERMISSIONS_MANAGE,
        "own_org",
    ),
    RouteSpec(
        "DELETE",
        "/api/org/critical-permissions/{tool}/{action}/pending",
        "member",
        Capability.ORG_PERMISSIONS_MANAGE,
        "own_org",
    ),
    RouteSpec(
        "GET", "/api/permissions/summary", "member", Capability.ORG_PERMISSIONS_VIEW, "own_org"
    ),
    # --- chat ---
    RouteSpec("POST", "/api/message", "member", Capability.CHAT_SEND, "own_user"),
    RouteSpec("GET", "/api/events", "member", Capability.CHAT_SEND, "own_user"),
    RouteSpec("POST", "/api/confirm/{confirmation_id}", "member", Capability.CHAT_SEND, "path_id"),
    # --- own Google/Microsoft connections ---
    RouteSpec("GET", "/api/oauth/google/authorize", "member", Capability.OAUTH_CONNECT, "own_user"),
    RouteSpec(
        "GET", "/api/oauth/microsoft/authorize", "member", Capability.OAUTH_CONNECT, "own_user"
    ),
    RouteSpec("GET", "/api/oauth/google/status", "member", Capability.OAUTH_CONNECT, "own_user"),
    RouteSpec("GET", "/api/oauth/microsoft/status", "member", Capability.OAUTH_CONNECT, "own_user"),
    RouteSpec("DELETE", "/api/oauth/google", "member", Capability.OAUTH_CONNECT, "own_user"),
    RouteSpec("DELETE", "/api/oauth/microsoft", "member", Capability.OAUTH_CONNECT, "own_user"),
    # --- platform (Super Admin) ---
    RouteSpec("GET", "/api/platform/orgs", "platform", Capability.ORG_LIFECYCLE_MANAGE, "none"),
    RouteSpec("POST", "/api/platform/orgs", "platform", Capability.ORG_CREATE, "none"),
    RouteSpec(
        "PATCH",
        "/api/platform/orgs/{org_id}/limits",
        "platform",
        Capability.ORG_LIMITS_MANAGE,
        "none",
    ),
    RouteSpec(
        "POST",
        "/api/platform/orgs/{org_id}/deactivate",
        "platform",
        Capability.ORG_LIFECYCLE_MANAGE,
        "none",
    ),
    RouteSpec(
        "POST",
        "/api/platform/orgs/{org_id}/reactivate",
        "platform",
        Capability.ORG_LIFECYCLE_MANAGE,
        "none",
    ),
    RouteSpec(
        "POST",
        "/api/platform/orgs/{org_id}/deletion",
        "platform",
        Capability.ORG_LIFECYCLE_MANAGE,
        "none",
    ),
    RouteSpec(
        "DELETE",
        "/api/platform/orgs/{org_id}/deletion",
        "platform",
        Capability.ORG_LIFECYCLE_MANAGE,
        "none",
    ),
    RouteSpec(
        "PATCH",
        "/api/platform/orgs/{org_id}/residency",
        "platform",
        Capability.ORG_RESIDENCY_MANAGE,
        "none",
    ),
    RouteSpec(
        "GET",
        "/api/platform/diagnostics",
        "platform",
        Capability.PLATFORM_DIAGNOSTICS_VIEW,
        "none",
    ),
    RouteSpec(
        "GET", "/api/platform/settings", "platform", Capability.PLATFORM_DEFAULTS_MANAGE, "none"
    ),
    RouteSpec(
        "PATCH", "/api/platform/settings", "platform", Capability.PLATFORM_DEFAULTS_MANAGE, "none"
    ),
)


def allowed_roles(spec: RouteSpec) -> frozenset[Role]:
    """The roles that may use ``spec`` (every role for an ungated route)."""
    return _ALL if spec.capability is None else ROLE_MATRIX[spec.capability]


def route_id(spec: RouteSpec) -> str:
    """A readable pytest id: ``"GET /api/org/settings"``."""
    return f"{spec.method} {spec.path}"
